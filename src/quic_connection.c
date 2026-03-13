#include "quic_connection.h"
#include "quic.h"
#include <stdio.h>
#include <uthash/uthash.h>
#include <allocnbuffer/fifoslab.h>
#include "logger.h"
#include <arpa/inet.h>
#include <time.h>

YAWT_Q_Connection_t *_hash_cid = NULL;   // Hash table by our CID
YAWT_Q_Connection_t *_hash_addr = NULL;  // Hash table by peer addr
YAWT_Q_Connection_t *_hash_odcid = NULL; // Hash table by original DCID (temporary, pre-handshake)

YAWT_Q_Connection_t *YAWT_q_con_create(YAWT_Q_Con_Create_Info_t *info) {
  if (info == NULL) return NULL;
  YAWT_Q_Connection_t *con = calloc(1, sizeof(YAWT_Q_Connection_t));
  if (!con) return NULL;
  con->cid.len = 20;
  YAWT_q_crypto_random_nonce(con->cid.id, con->cid.len);
  YAWT_q_cid_set(&con->peer_cid, info->peer_cid.id, info->peer_cid.len);
  con->version = 0;
  con->recv_buffer = ANB_fifoslab_create(4096);
  con->tx_buffer = ANB_fifoslab_create(4096);
  con->peer_addr = info->peer_addr;
  YAWT_q_crypto_init(&con->crypto, info->is_server, info->cred);
  // Set CIDs for transport parameters (RFC 9000 §18.2)
  YAWT_q_cid_set(&con->crypto.original_dcid, info->original_dcid.id, info->original_dcid.len);
  YAWT_q_cid_set(&con->crypto.our_cid, con->cid.id, con->cid.len);
  HASH_ADD(hh_cid, _hash_cid, cid.id, con->cid.len, con);

  // Temporary index by original DCID (removed once client uses our real CID)
  YAWT_q_cid_set(&con->original_dcid, info->original_dcid.id, info->original_dcid.len);
  if (con->original_dcid.len > 0) {
    HASH_ADD(hh_odcid, _hash_odcid, original_dcid.id, con->original_dcid.len, con);
  }

  YAWT_LOG(YAWT_LOG_INFO, "Created connection: CID=%s",
            YAWT_q_cid_to_hex(&con->cid));

  return con;
}

void YAWT_q_con_free(YAWT_Q_Connection_t **con) {
  if (con == NULL || *con == NULL) return;
  YAWT_Q_Connection_t *c = *con;
  HASH_DELETE(hh_cid, _hash_cid, c);
  YAWT_q_con_clear_odcid(c);
  HASH_DELETE(hh_addr, _hash_addr, c);
  YAWT_q_crypto_free(&c->crypto);
  ANB_fifoslab_destroy(c->recv_buffer);
  ANB_fifoslab_destroy(c->tx_buffer);
  free(c);
  *con = NULL;
}

void YAWT_q_con_clear_odcid(YAWT_Q_Connection_t *con) {
  if (!con || con->original_dcid.len == 0) return;
  HASH_DELETE(hh_odcid, _hash_odcid, con);
  con->original_dcid.len = 0;
  YAWT_LOG(YAWT_LOG_INFO, "Retired odcid index for CID=%s", YAWT_q_cid_to_hex(&con->cid));
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
  if (!cid || cid->len == 0) return NULL;
  YAWT_Q_Connection_t *con = NULL;
  HASH_FIND(hh_cid, _hash_cid, cid->id, cid->len, con);
  if (!con) {
    HASH_FIND(hh_odcid, _hash_odcid, cid->id, cid->len, con);
  }
  return con;
}


// Push outbound CRYPTO frames from crypto->out_buf into tx_buffer
static void _push_crypto_frames(YAWT_Q_Connection_t *con) {
  YAWT_Q_Crypto_t *crypto = &con->crypto;
  for (int lvl = 0; lvl < 4; lvl++) {
    if (crypto->out_len[lvl] == 0) continue;

    YAWT_Q_Frame_Crypto_t cf = {
      .offset = 0,
      .len = crypto->out_len[lvl],
      .data = crypto->out_buf[lvl],
    };
    int frame_len = YAWT_q_enqueue_frame_crypto(con->tx_buffer, lvl, &cf);
    if (frame_len < 0) {
      printf("  error: encode CRYPTO frame failed for level %d\n", lvl);
      continue;
    }

    printf("  queued CRYPTO frame: level=%d, %zu bytes of TLS data\n",
           lvl, crypto->out_len[lvl]);

    free(crypto->out_buf[lvl]);
    crypto->out_buf[lvl] = NULL;
    crypto->out_len[lvl] = 0;
  }
}

static void _handle_frames(YAWT_Q_Connection_t *con, YAWT_Q_Encryption_Level_t level,
                            const uint8_t *payload, size_t payload_len) {
  YAWT_Q_ReadCursor_t frc = { .data = (uint8_t *)payload, .len = payload_len, .cursor = 0, .err = YAWT_Q_OK };

  while (frc.cursor < frc.len && frc.err == YAWT_Q_OK) {
    YAWT_Q_ParsedFrame_t frame;
    YAWT_q_parse_frame(&frc, &frame);
    if (frc.err != YAWT_Q_OK) break;

    switch (frame.type) {
      case YAWT_Q_FRAME_PADDING:
      case YAWT_Q_FRAME_PING:
        break;

      case YAWT_Q_FRAME_ACK:
        printf("  ACK: largest=%lu, delay=%lu, ranges=%lu, first_range=%lu\n",
               frame.ack.largest_ack, frame.ack.ack_delay,
               frame.ack.ack_range_count, frame.ack.first_ack_range);
        break;

      case YAWT_Q_FRAME_CRYPTO: {
        YAWT_LOG(YAWT_LOG_INFO, "Received CRYPTO frame at level %d: offset=%lu, len=%lu",
                  level, frame.crypto.offset, frame.crypto.len);

        int ret = YAWT_q_crypto_feed(&con->crypto, level,
                                      frame.crypto.data, frame.crypto.len);
        if (ret < 0) {
          YAWT_LOG(YAWT_LOG_ERROR, "crypto_feed failed: %d", ret);
          return;
        }

        _push_crypto_frames(con);

        if (con->crypto.handshake_complete) {
          YAWT_q_con_clear_odcid(con);
        }
        break;
      }

      case YAWT_Q_FRAME_HANDSHAKE_DONE:
        YAWT_LOG(YAWT_LOG_INFO, "Received HANDSHAKE_DONE frame");
        con->crypto.handshake_complete = 1;
        break;

      case YAWT_Q_FRAME_CONNECTION_CLOSE:
        printf("  CONNECTION_CLOSE: error=%lu, frame_type=%lu\n",
               frame.connection_close.error_code, frame.connection_close.frame_type);
        break;

      case YAWT_Q_FRAME_NEW_CONNECTION_ID:
        printf("  NEW_CONNECTION_ID: seq=%lu, cid=%s\n",
               frame.new_connection_id.seq_num,
               YAWT_q_cid_to_hex(&frame.new_connection_id.cid));
        break;

      default:
        printf("  unhandled frame type: 0x%02lx\n", (uint64_t)frame.type);
        break;
    }
  }

  if (frc.err != YAWT_Q_OK) {
    YAWT_LOG(YAWT_LOG_ERROR, "Frame parse error: %s (%d)", YAWT_q_err_str(frc.err), frc.err);
  }
}

void YAWT_q_process_datagram(uint8_t *data, size_t len, YAWT_Q_Crypto_Cred_t *cred,
                              const YAWT_Q_PeerAddr_t *peer_addr) {
  YAWT_Q_ReadCursor_t rc = { .data = data, .len = len, .cursor = 0, .err = YAWT_Q_OK };
  while (rc.cursor < rc.len && rc.err == YAWT_Q_OK) {
    size_t prev = rc.cursor;
    YAWT_Q_Packet_t pkt;
    YAWT_q_parse_packet(&rc, &pkt);
    if (rc.err != YAWT_Q_OK || rc.cursor == prev) break;

    printf("  packet: %s (consumed %zu bytes)\n", _pkt_type_name(pkt.type), rc.cursor - prev);

    YAWT_Q_Connection_t *con = YAWT_q_con_find_by_cid(&pkt.dest_cid);

    // First Initial from a new client — create connection
    if (!con && pkt.type == YAWT_Q_PKT_TYPE_INITIAL) {
      YAWT_Q_Con_Create_Info_t info;
      memset(&info, 0, sizeof(info));
      info.is_server = 1;
      info.cred = cred;
      YAWT_q_cid_set(&info.peer_cid, pkt.src_cid.id, pkt.src_cid.len);
      YAWT_q_cid_set(&info.original_dcid, pkt.dest_cid.id, pkt.dest_cid.len);
      info.peer_addr = *peer_addr;
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
      YAWT_LOG(YAWT_LOG_WARN, "no keys for level %d, skipping decrypt", level);
      continue;
    }

    int ret = YAWT_q_crypto_unprotect_packet(&pkt, keys);
    if (ret < 0) {
      printf("  error: unprotect/decrypt failed: %d\n", ret);
      continue;
    }

    // Parse frames from decrypted payload
    YAWT_LOG(YAWT_LOG_DEBUG, "Decrypted payload first bytes: %02x %02x %02x %02x %02x %02x %02x %02x",
             pkt.payload[0], pkt.payload[1], pkt.payload[2], pkt.payload[3],
             pkt.payload[4], pkt.payload[5], pkt.payload[6], pkt.payload[7]);
    _handle_frames(con, level, pkt.payload, pkt.payload_len);
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

static void _flush_connection(YAWT_Q_Connection_t *con,
                               YAWT_Q_Send_Func_t send_func,
                               void *send_ctx) {
  for (int lvl = 0; lvl < 4; lvl++) {
    uint8_t payload[YAWT_Q_MAX_PKT_SIZE];
    size_t payload_len = 0;
    int found = 0;

    ANB_FifoSlabIter_t iter = {0};
    size_t item_size;
    uint8_t *item;

    while ((item = ANB_fifoslab_peek_item_iter(con->tx_buffer, &iter, &item_size)) != NULL) {
      if (item_size < sizeof(YAWT_Q_Frame_t)) continue;
      YAWT_Q_Frame_t *f = (YAWT_Q_Frame_t *)item;

      if (f->level != lvl || f->last_sent != 0) continue;

      if (payload_len + f->wire_len > sizeof(payload)) break;

      memcpy(payload + payload_len, f->wire_data, f->wire_len);
      payload_len += f->wire_len;
      found = 1;
    }

    if (!found) continue;

    YAWT_Q_Level_Keys_t *keys = &con->crypto.level_keys[lvl];
    if (!keys->available) {
      printf("  no write keys for level %d, skipping send\n", lvl);
      continue;
    }

    YAWT_Q_Packet_Type_t pkt_type = _level_to_pkt_type(lvl);
    uint32_t pn = _next_pn(con, lvl);

    YAWT_Q_Packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.type = pkt_type;
    pkt.version = con->version;
    pkt.dest_cid = con->peer_cid;
    pkt.src_cid = con->cid;
    pkt.packet_num = pn;
    pkt.packet_number_length = 4;
    pkt.reserved = 0;
    pkt.payload = payload;
    pkt.payload_len = payload_len;

    if (pkt_type == YAWT_Q_PKT_TYPE_INITIAL) {
      pkt.extra.initial.token_len = 0;
      pkt.extra.initial.token = NULL;
    }

    const uint8_t *wire_data;
    int wire_len = YAWT_q_encode_packet(&pkt, con->crypto.level_keys, &wire_data);
    if (wire_len < 0) {
      printf("  error: encode packet failed: %d\n", wire_len);
      continue;
    }

    size_t send_size = (size_t)wire_len;
    send_func(wire_data, send_size, &con->peer_addr, send_ctx);

    YAWT_LOG(YAWT_LOG_DEBUG, "sent %s packet: PN=%u, %zu bytes, first 20: "
             "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
             "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
             _pkt_type_name(pkt_type), pn, send_size,
             wire_data[0], wire_data[1], wire_data[2], wire_data[3],
             wire_data[4], wire_data[5], wire_data[6], wire_data[7],
             wire_data[8], wire_data[9], wire_data[10], wire_data[11],
             wire_data[12], wire_data[13], wire_data[14], wire_data[15],
             wire_data[16], wire_data[17], wire_data[18], wire_data[19]);

    // Mark frames as sent
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

void YAWT_q_con_flush_send(YAWT_Q_Send_Func_t send_func, void *send_ctx) {
  if (!send_func) return;

  YAWT_Q_Connection_t *con, *tmp;
  HASH_ITER(hh_cid, _hash_cid, con, tmp) {
    if (ANB_fifoslab_item_count(con->tx_buffer) > 0) {
      _flush_connection(con, send_func, send_ctx);
    }
  }
}
