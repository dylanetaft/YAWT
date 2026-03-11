#include "quic_connection.h"
#include "quic.h"
#include <stdio.h>
#include <uthash/uthash.h>
#include <allocnbuffer/fifoslab.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include "logger.h"
#include <arpa/inet.h>
#include <time.h>

YAWT_Q_Connection_t *_hash_cid = NULL; // Hash table of connections by CID
YAWT_Q_Connection_t *_hash_addr = NULL; // Hash table of connections by peer addr

YAWT_Q_Connection_t *YAWT_q_con_create(YAWT_Q_Con_Create_Info_t *info) {
  if (info == NULL) return NULL;
  YAWT_Q_Connection_t *con = malloc(sizeof(YAWT_Q_Connection_t));
  if (!con) return NULL;
  con->cid.len = 20;
  gnutls_rnd(GNUTLS_RND_NONCE, con->cid.id, con->cid.len);
  YAWT_q_cid_set(&con->peer_cid, info->peer_cid.id, info->peer_cid.len);
  con->version = 0;
  con->recv_buffer = ANB_fifoslab_create(4096);
  con->tx_buffer = ANB_fifoslab_create(4096);
  YAWT_q_crypto_init(&con->crypto, info->is_server, info->cred);
  HASH_ADD(hh_cid, _hash_cid, cid.id, con->cid.len, con);
  YAWT_LOG(YAWT_LOG_INFO, "Created connection: CID=%s",
            YAWT_q_cid_to_hex(&con->cid));

  return con;
}

void YAWT_q_con_free(YAWT_Q_Connection_t **con) {
  if (con == NULL || *con == NULL) return;
  YAWT_Q_Connection_t *c = *con;
  HASH_DELETE(hh_cid, _hash_cid, c);
  HASH_DELETE(hh_addr, _hash_addr, c);
  YAWT_q_crypto_free(&c->crypto);
  ANB_fifoslab_destroy(c->recv_buffer);
  ANB_fifoslab_destroy(c->tx_buffer);
  free(c);
  *con = NULL;
}

void YAWT_q_con_set_state(YAWT_Q_Connection_t *con, YAWT_Q_Connection_State_t new_state) {
  if (con == NULL) return;
  con->state = new_state;
}

YAWT_Q_Connection_State_t YAWT_q_con_get_state(YAWT_Q_Connection_t *con) {
  if (con == NULL) return YAWT_Q_STATE_CLOSED;
  return con->state;
}

static const char *_pkt_type_name(YAWT_Q_Packet_Type_t type) {
  switch (type) {
    case YAWT_Q_PKT_TYPE_INITIAL:  return "Initial";
    case YAWT_Q_PKT_TYPE_0RTT:    return "0-RTT";
    case YAWT_Q_PKT_TYPE_HANDSHAKE: return "Handshake";
    case YAWT_Q_PKT_TYPE_RETRY:   return "Retry";
    case YAWT_Q_PKT_TYPE_1RTT:    return "1-RTT";
    default:                       return "Unknown";
  }
}

// Map long header packet type bits to encryption level
static YAWT_Q_Encryption_Level_t _pkt_type_to_level(YAWT_Q_Packet_Type_t type) {
  switch (type) {
    case YAWT_Q_PKT_TYPE_INITIAL:   return YAWT_Q_LEVEL_INITIAL;
    case YAWT_Q_PKT_TYPE_0RTT:      return YAWT_Q_LEVEL_EARLY;
    case YAWT_Q_PKT_TYPE_HANDSHAKE: return YAWT_Q_LEVEL_HANDSHAKE;
    default:                         return YAWT_Q_LEVEL_APPLICATION;
  }
}

YAWT_Q_Connection_t *YAWT_q_con_find_by_cid(const YAWT_Q_Cid_t *cid) {
  YAWT_Q_Connection_t *con = NULL;
  HASH_FIND(hh_cid, _hash_cid, cid->id, cid->len, con);
  return con;
}

// --- Frame handler ---

typedef struct {
  YAWT_Q_Connection_t *con;
  YAWT_Q_Encryption_Level_t level;
} _Frame_Ctx_t;

// Push outbound CRYPTO frames from crypto->out_buf into tx_buffer
static void _push_crypto_frames(YAWT_Q_Connection_t *con) {
  YAWT_Q_Crypto_t *crypto = &con->crypto;
  for (int lvl = 0; lvl < 4; lvl++) {
    if (crypto->out_len[lvl] == 0) continue;

    // Encode CRYPTO frame into a temp buffer
    uint8_t frame_buf[4096];
    int frame_len = YAWT_q_encode_frame_crypto(frame_buf, sizeof(frame_buf),
                                                 0, crypto->out_buf[lvl],
                                                 crypto->out_len[lvl]);
    if (frame_len < 0) {
      printf("  error: encode CRYPTO frame failed for level %d\n", lvl);
      continue;
    }

    // Build YAWT_Q_Frame_t + inline data contiguously
    size_t total = sizeof(YAWT_Q_Frame_t) + frame_len;
    uint8_t blob[sizeof(YAWT_Q_Frame_t) + 4096];
    if (total > sizeof(blob)) {
      printf("  error: CRYPTO frame too large for level %d (%d bytes)\n", lvl, frame_len);
      continue;
    }

    YAWT_Q_Frame_t *f = (YAWT_Q_Frame_t *)blob;
    memset(f, 0, sizeof(*f));
    f->type = YAWT_Q_FRAME_CRYPTO;
    f->level = (uint8_t)lvl;
    f->packet_num = 0;
    f->last_sent = 0;
    f->data_len = frame_len;
    f->f.crypto.offset = 0;
    f->f.crypto.len = crypto->out_len[lvl];
    f->f.crypto.data = NULL; // will be resolved relative to blob on peek

    // Copy serialized frame data after the struct
    memcpy(blob + sizeof(YAWT_Q_Frame_t), frame_buf, frame_len);

    ANB_fifoslab_push_item(con->tx_buffer, blob, total);
    printf("  queued CRYPTO frame: level=%d, %zu bytes of TLS data\n",
           lvl, crypto->out_len[lvl]);

    // Consume the out_buf
    free(crypto->out_buf[lvl]);
    crypto->out_buf[lvl] = NULL;
    crypto->out_len[lvl] = 0;
  }
}

static int _on_frame(uint64_t frame_type, const void *frame, void *ctx) {
  _Frame_Ctx_t *fctx = (_Frame_Ctx_t *)ctx;
  YAWT_Q_Connection_t *con = fctx->con;

  switch (frame_type) {
    case YAWT_Q_FRAME_PADDING:
    case YAWT_Q_FRAME_PING:
      // Ignore
      break;

    case YAWT_Q_FRAME_ACK: {
      const YAWT_Q_Frame_ACK_t *ack = (const YAWT_Q_Frame_ACK_t *)frame;
      printf("  ACK: largest=%lu, delay=%lu, ranges=%lu, first_range=%lu\n",
             ack->largest_ack, ack->ack_delay, ack->ack_range_count, ack->first_ack_range);
      break;
    }

    case YAWT_Q_FRAME_CRYPTO: {
      const YAWT_Q_Frame_Crypto_t *crypto_frame = (const YAWT_Q_Frame_Crypto_t *)frame;
      printf("  CRYPTO: offset=%lu, len=%lu at level %d\n",
             crypto_frame->offset, crypto_frame->len, fctx->level);

      // Feed to GnuTLS
      gnutls_record_encryption_level_t gtls_level = (gnutls_record_encryption_level_t)fctx->level;
      int ret = YAWT_q_crypto_feed(&con->crypto, gtls_level,
                                    crypto_frame->data, crypto_frame->len);
      if (ret < 0) {
        printf("  error: crypto_feed failed: %d\n", ret);
        return ret;
      }

      // Check for outbound handshake data
      _push_crypto_frames(con);
      break;
    }

    case YAWT_Q_FRAME_HANDSHAKE_DONE:
      printf("  HANDSHAKE_DONE\n");
      con->crypto.handshake_complete = 1;
      break;

    case YAWT_Q_FRAME_CONNECTION_CLOSE: {
      const YAWT_Q_Frame_Connection_Close_t *cc = (const YAWT_Q_Frame_Connection_Close_t *)frame;
      printf("  CONNECTION_CLOSE: error=%lu, frame_type=%lu\n",
             cc->error_code, cc->frame_type);
      break;
    }

    case YAWT_Q_FRAME_NEW_CONNECTION_ID: {
      const YAWT_Q_Frame_New_Connection_ID_t *ncid = (const YAWT_Q_Frame_New_Connection_ID_t *)frame;
      printf("  NEW_CONNECTION_ID: seq=%lu, cid=%s\n",
             ncid->seq_num, YAWT_q_cid_to_hex(&ncid->cid));
      break;
    }

    default:
      printf("  unhandled frame type: 0x%02lx\n", frame_type);
      break;
  }

  return 0;
}

void YAWT_q_process_datagram(uint8_t *data, size_t len, YAWT_Q_Crypto_Cred_t *cred) {
  YAWT_Q_ReadCursor_t rc = { .data = data, .len = len, .cursor = 0, .err = YAWT_Q_OK };
  while (rc.cursor < rc.len && rc.err == YAWT_Q_OK) {
    size_t prev = rc.cursor;
    YAWT_Q_Packet_t pkt;
    YAWT_q_parse_packet(&rc, &pkt);
    if (rc.err != YAWT_Q_OK || rc.cursor == prev) break;

    printf("  packet: %s (consumed %zu bytes)\n", _pkt_type_name(pkt.type), rc.cursor - prev);

    // This feels wrong, but we actually index connections by DCID - which is our local CID, locally randomly generated
    // 1RTT packets, remote side does not know our CID yet, but we need to index before that
    YAWT_Q_Connection_t *con = YAWT_q_con_find_by_cid(&pkt.dest_cid);


    // Capture peer CID and version from first Initial
    if (!con && pkt.type == YAWT_Q_PKT_TYPE_INITIAL) {
      YAWT_Q_Con_Create_Info_t info;
      memset(&info, 0, sizeof(info));
      info.is_server = 0;
      info.cred = cred;
      YAWT_q_cid_set(&info.peer_cid, pkt.src_cid.id, pkt.src_cid.len); //still capture peer CID for future validation
      con = YAWT_q_con_create(&info);
      con->version = pkt.version;
      printf("  captured peer CID=%s, version=0x%08x\n",
             YAWT_q_cid_to_hex(&con->peer_cid), con->version);
    }

    if (!con) {
      YAWT_LOG(YAWT_LOG_ERROR, "Failed to create connection for CID=%s", YAWT_q_cid_to_hex(&pkt.dest_cid));
      continue;
    }

    YAWT_Q_Encryption_Level_t level = _pkt_type_to_level(pkt.type);

    // For Initial packets: derive keys from DCID if not done yet
    if (level == YAWT_Q_LEVEL_INITIAL &&
        !con->crypto.level_keys[YAWT_Q_LEVEL_INITIAL].available) {
      int ret = YAWT_q_crypto_derive_initial_keys(&con->crypto, &pkt.dest_cid);  //RFC 9001 §5.2 - the dest cid in initial packet is randomly generated by remote party
      if (ret < 0) {
        YAWT_LOG(YAWT_LOG_ERROR, "Failed to derive initial keys for CID=%s: %d",
                  YAWT_q_cid_to_hex(&pkt.dest_cid), ret);
        break;
      }
      YAWT_LOG(YAWT_LOG_INFO, "Derived initial keys for CID=%s from DCID (%u bytes)",
                YAWT_q_cid_to_hex(&pkt.dest_cid), pkt.dest_cid.len);
    }

    YAWT_Q_Level_Keys_t *keys = &con->crypto.level_keys[level];
    if (!keys->available) {
      printf("  no keys for level %d, skipping decrypt\n", level);
      continue;
    }

    int ret = YAWT_q_crypto_unprotect_packet(&pkt, keys);
    if (ret < 0) {
      printf("  error: unprotect/decrypt failed: %d\n", ret);
      continue;
    }

    // Parse frames from decrypted payload
    _Frame_Ctx_t fctx = { .con = con, .level = level };
    YAWT_Q_Error_t ferr = YAWT_q_parse_frames(pkt.payload, pkt.payload_len, _on_frame, &fctx);
    if (ferr != YAWT_Q_OK) {
      printf("  frame parse error: %d\n", ferr);
    }
  }
  if (rc.err != YAWT_Q_OK) {
    printf("  parse error: %d at cursor %zu\n", rc.err, rc.cursor);
  }
}

// --- Packet packer ---

// Map encryption level to packet type
static YAWT_Q_Packet_Type_t _level_to_pkt_type(uint8_t level) {
  switch (level) {
    case YAWT_Q_LEVEL_INITIAL:     return YAWT_Q_PKT_TYPE_INITIAL;
    case YAWT_Q_LEVEL_EARLY:       return YAWT_Q_PKT_TYPE_0RTT;
    case YAWT_Q_LEVEL_HANDSHAKE:   return YAWT_Q_PKT_TYPE_HANDSHAKE;
    default:                        return YAWT_Q_PKT_TYPE_1RTT;
  }
}

// Get next packet number for a given level
static uint32_t _next_pn(YAWT_Q_Connection_t *con, uint8_t level) {
  switch (level) {
    case YAWT_Q_LEVEL_INITIAL:     return (uint32_t)con->pkt_num_tx_initial++;
    case YAWT_Q_LEVEL_HANDSHAKE:   return (uint32_t)con->pkt_num_tx_handshake++;
    default:                        return (uint32_t)con->pkt_num_tx_app++;
  }
}

void YAWT_q_con_flush_send(YAWT_Q_Connection_t *con,
                            YAWT_Q_Send_Func_t send_func,
                            void *send_ctx) {
  if (!con || !send_func) return;

  // Iterate tx_buffer looking for unsent frames (last_sent == 0)
  // Group by level, build one packet per level
  // For simplicity: scan and send one packet per level per flush call

  for (int lvl = 0; lvl < 4; lvl++) {
    // Collect frame data for this level
    uint8_t payload[1200];
    size_t payload_len = 0;
    int found = 0;

    ANB_FifoSlabIter_t iter = {0};
    size_t item_size;
    uint8_t *item;
    size_t item_idx = 0;

    while ((item = ANB_fifoslab_peek_item_iter(con->tx_buffer, &iter, &item_size)) != NULL) {
      if (item_size < sizeof(YAWT_Q_Frame_t)) { item_idx++; continue; }
      YAWT_Q_Frame_t *f = (YAWT_Q_Frame_t *)item;

      if (f->level != lvl || f->last_sent != 0) { item_idx++; continue; }

      // Get the serialized frame data (stored after the struct)
      size_t frame_data_len = f->data_len;
      uint8_t *frame_data = item + sizeof(YAWT_Q_Frame_t);

      if (payload_len + frame_data_len > sizeof(payload)) break; // packet full

      memcpy(payload + payload_len, frame_data, frame_data_len);
      payload_len += frame_data_len;
      found = 1;
      item_idx++;
    }

    if (!found) continue;

    // Build packet
    YAWT_Q_Packet_Type_t pkt_type = _level_to_pkt_type(lvl);
    uint32_t pn = _next_pn(con, lvl);

    YAWT_Q_Packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.type = pkt_type;
    pkt.version = con->version;
    pkt.dest_cid = con->peer_cid;
    pkt.src_cid = con->cid;
    pkt.packet_num = pn;
    pkt.packet_number_length = 4; // always use 4-byte PN for simplicity
    pkt.reserved = 0;
    pkt.payload = payload;
    pkt.payload_len = payload_len;

    if (pkt_type == YAWT_Q_PKT_TYPE_INITIAL) {
      pkt.extra.initial.token_len = 0;
      pkt.extra.initial.token = NULL;
    }

    // Encode packet
    uint8_t wire_buf[1500];
    size_t wire_len;
    YAWT_Q_Error_t err = YAWT_q_encode_packet(&pkt, wire_buf, sizeof(wire_buf), &wire_len);
    if (err != YAWT_Q_OK) {
      printf("  error: encode packet failed: %d\n", err);
      continue;
    }

    // Compute pn_offset: for encoded packet, find where PN starts
    // For long headers: after byte0(1) + version(4) + dcid_len(1) + dcid + scid_len(1) + scid
    // + token_len varint + token (Initial only) + length varint
    // Simpler: scan for PN position from the encoded packet
    size_t pn_offset;
    if (pkt_type == YAWT_Q_PKT_TYPE_1RTT) {
      pn_offset = 1 + pkt.dest_cid.len;
    } else {
      // Long header: 1 + 4 + 1 + dcid + 1 + scid = 7 + dcid_len + scid_len
      pn_offset = 7 + pkt.dest_cid.len + pkt.src_cid.len;
      if (pkt_type == YAWT_Q_PKT_TYPE_INITIAL) {
        // + token_len varint + token + length varint
        // token_len=0 encodes as 1 byte (0x00)
        pn_offset += 1; // token_len varint (0 = 1 byte)
        // length varint: pn_len + payload_len + 16 (AEAD tag)
        uint64_t length_val = pkt.packet_number_length + payload_len + 16;
        if (length_val <= 0x3f) pn_offset += 1;
        else if (length_val <= 0x3fff) pn_offset += 2;
        else pn_offset += 4;
      } else {
        // Handshake/0-RTT: + length varint
        uint64_t length_val = pkt.packet_number_length + payload_len + 16;
        if (length_val <= 0x3f) pn_offset += 1;
        else if (length_val <= 0x3fff) pn_offset += 2;
        else pn_offset += 4;
      }
    }

    // We need to re-encode with the correct payload length that includes the AEAD tag
    // Actually the encode function already wrote the payload as-is. We need to:
    // 1. The "Length" field in the encoded packet already accounts for pn_len + payload_len
    //    but after encryption, payload becomes payload + 16 bytes (AEAD tag).
    // So we need to account for the AEAD expansion in the Length field BEFORE encoding.
    // Let's re-encode with payload_len + 16 in the Length field but only payload_len of actual data.
    // The simplest approach: adjust payload_len to include space for the tag.

    // Re-encode with space for AEAD tag
    pkt.payload_len = payload_len + 16; // reserve space for AEAD tag

    // Need a buffer where payload points to enough space
    uint8_t payload_with_tag[1200 + 16];
    memcpy(payload_with_tag, payload, payload_len);
    memset(payload_with_tag + payload_len, 0, 16); // tag space
    pkt.payload = payload_with_tag;

    err = YAWT_q_encode_packet(&pkt, wire_buf, sizeof(wire_buf), &wire_len);
    if (err != YAWT_Q_OK) {
      printf("  error: re-encode packet failed: %d\n", err);
      continue;
    }

    // Recalculate pn_offset on the encoded buffer
    if (pkt_type == YAWT_Q_PKT_TYPE_1RTT) {
      pn_offset = 1 + pkt.dest_cid.len;
    } else {
      pn_offset = 7 + pkt.dest_cid.len + pkt.src_cid.len;
      if (pkt_type == YAWT_Q_PKT_TYPE_INITIAL) {
        pn_offset += 1; // token_len = 0
      }
      // Length varint
      uint64_t length_val = pkt.packet_number_length + payload_len + 16;
      if (length_val <= 0x3f) pn_offset += 1;
      else if (length_val <= 0x3fff) pn_offset += 2;
      else pn_offset += 4;
    }

    // Encrypt
    YAWT_Q_Level_Keys_t *keys = &con->crypto.level_keys[lvl];
    if (!keys->available) {
      printf("  no write keys for level %d, skipping send\n", lvl);
      continue;
    }

    int ret = YAWT_q_crypto_protect_packet(wire_buf, wire_len,
                                            pn_offset, pkt.packet_number_length,
                                            pn, keys);
    if (ret < 0) {
      printf("  error: protect packet failed: %d\n", ret);
      continue;
    }

    // Pad Initial packets to 1200 bytes (RFC 9000 §14.1)
    size_t send_len = wire_len;
    uint8_t padded_buf[1200];
    if (pkt_type == YAWT_Q_PKT_TYPE_INITIAL && wire_len < 1200) {
      memcpy(padded_buf, wire_buf, wire_len);
      memset(padded_buf + wire_len, 0, 1200 - wire_len); // PADDING frames (0x00)
      send_len = 1200;
      send_func(padded_buf, send_len, send_ctx);
    } else {
      send_func(wire_buf, send_len, send_ctx);
    }

    printf("  sent %s packet: PN=%u, %zu bytes on wire\n",
           _pkt_type_name(pkt_type), pn, send_len);

    // Mark frames as sent
    // Re-iterate to update last_sent timestamps
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    ANB_FifoSlabIter_t iter2 = {0};
    while ((item = ANB_fifoslab_peek_item_iter(con->tx_buffer, &iter2, &item_size)) != NULL) {
      if (item_size < sizeof(YAWT_Q_Frame_t)) continue;
      YAWT_Q_Frame_t *f = (YAWT_Q_Frame_t *)item;
      if (f->level == lvl && f->last_sent == 0) {
        f->last_sent = now;
        f->packet_num = pn;
      }
    }
  }
}
