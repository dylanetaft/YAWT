#include "quic_connection.h"
#include "quic.h"
#include <stdio.h>
#include <uthash/uthash.h>
#include <allocnbuffer/fifoslab.h>
#include "logger.h"
#include "security.h"
#include <arpa/inet.h>
#include <float.h>

// Forward declarations
static void _drain_tx(YAWT_Q_Connection_t *con, YAWT_Q_Send_Func_t send_func,
                       void *send_ctx, double now);

// RFC 9000 Appendix A: reconstruct full PN from truncated value
static uint64_t _reconstruct_pn(uint64_t largest_pn, uint32_t truncated_pn, uint8_t pn_bytelen) {
  uint64_t expected_pn = largest_pn + 1;
  uint8_t pn_nbits = pn_bytelen * 8;
  uint64_t pn_win = 1ULL << pn_nbits;   // size of the PN encoding window (e.g. 256 for 1-byte)
  uint64_t pn_hwin = pn_win / 2;        // half-window: how far candidate can drift from expected
  uint64_t pn_mask = pn_win - 1;        // bitmask for the truncated portion of the PN
  uint64_t candidate = (expected_pn & ~pn_mask) | truncated_pn;
  if (candidate + pn_hwin <= expected_pn && candidate + pn_win < (1ULL << 62)) {
    return candidate + pn_win;
  }
  if (candidate > expected_pn + pn_hwin && candidate >= pn_win) {
    return candidate - pn_win;
  }
  return candidate;
}

// Check if a packet number falls within any range acknowledged by an ACK frame.
// Walks the first range then the gap/range pairs from ack->ranges.
static int _pn_is_acked(uint32_t pn, const YAWT_Q_Frame_ACK_t *ack) {
  uint64_t hi = ack->largest_ack;
  uint64_t lo = hi - ack->first_ack_range;
  if (pn >= lo && pn <= hi) return 1;

  if (ack->ack_range_count == 0 || !ack->ranges) return 0;

  // Walk additional ranges: each is a gap/range varint pair
  // RFC 9000 §19.3.1: smallest = lo - gap - 2, then range gives count below that
  YAWT_Q_ReadCursor_t rc = { .data = ack->ranges, .len = (size_t)-1, .cursor = 0, .err = YAWT_Q_OK };
  for (uint64_t i = 0; i < ack->ack_range_count; i++) {
    uint64_t gap, range;
    YAWT_q_varint_decode(&rc, &gap);
    YAWT_q_varint_decode(&rc, &range);
    if (rc.err != YAWT_Q_OK) break;
    hi = lo - gap - 2;
    lo = hi - range;
    if (pn >= lo && pn <= hi) return 1;
  }
  return 0;
}

// Remove ACK'd frames from tx_buffer
static void _process_ack(YAWT_Q_Connection_t *con, uint8_t level,
                          const YAWT_Q_Frame_ACK_t *ack) {
  ANB_SlabIter_t iter = {0};
  size_t item_size;
  uint8_t *item;
  while ((item = ANB_slab_peek_item_iter(con->tx_buffer, &iter, &item_size)) != NULL) {
    if (item_size < sizeof(YAWT_Q_WireFrame_t)) continue;
    YAWT_Q_WireFrame_t *f = (YAWT_Q_WireFrame_t *)item;
    if (f->level != level) continue;
    if (f->last_sent == 0) continue;
    if (_pn_is_acked(f->packet_num, ack)) {
      ANB_slab_pop_item(con->tx_buffer, &iter);
    }
  }
}

YAWT_Q_Connection_t *_hash_cid = NULL;   // Hash table by our CID
YAWT_Q_Connection_t *_hash_odcid = NULL; // Hash table by original DCID (temporary, pre-handshake)

// Global default transport settings — used when create info doesn't provide local_fc
static YAWT_Q_FlowControl_t _default_local_fc = {
  .max_idle_timeout = 30000,
  .max_data = 1048576,
  .max_stream_data_bidi_local = 1048576,
  .max_stream_data_bidi_remote = 1048576,
  .max_stream_data_uni = 1048576,
  .max_streams_bidi = 16,
  .max_streams_uni = 16,
  .max_datagram_frame_size = YAWT_Q_MAX_PKT_SIZE,
};

YAWT_Q_Connection_t *YAWT_q_con_create(YAWT_Q_Con_Create_Info_t *info) {
  if (info == NULL) return NULL;
  YAWT_Q_Connection_t *con = calloc(1, sizeof(YAWT_Q_Connection_t));
  if (!con) return NULL;
  con->cid.len = YAWT_Q_CID_LEN;
  YAWT_q_crypto_random_nonce(con->cid.id, con->cid.len);
  YAWT_q_cid_set(&con->peer_cid, info->peer_cid.id, info->peer_cid.len);
  con->version = 0;
  con->recv_buffer = ANB_slab_create(4096);
  con->tx_buffer = ANB_slab_create(4096);
  con->stream_rx = ANB_slab_create(4096);
  con->stream_meta = ANB_slab_create(4096);
  con->peer_addr = info->peer_addr;
  con->local_fc = info->local_fc ? *info->local_fc : _default_local_fc;
  con->crypto = YAWT_q_crypto_init(info->is_server, info->cred,
                                    &info->original_dcid, &con->cid,
                                    &con->local_fc, &con->peer_fc, NULL);
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
  YAWT_q_crypto_free(c->crypto);
  ANB_slab_destroy(c->recv_buffer);
  ANB_slab_destroy(c->tx_buffer);
  ANB_slab_destroy(c->stream_rx);
  ANB_slab_destroy(c->stream_meta);
  YAWT_Q_CbNode_t *node, *tmp;
  LL_FOREACH_SAFE(c->cb_list, node, tmp) {
    LL_DELETE(c->cb_list, node);
    free(node);
  }
  free(c);
  *con = NULL;
}

void YAWT_q_con_close(YAWT_Q_Connection_t *con, uint64_t error_code) {
  if (!con || con->stats.closing_at != 0) return;

  YAWT_q_enqueue_frame_connection_close(con, YAWT_Q_LEVEL_APPLICATION,
                                         error_code, 0);
  con->stats.closing_at = DBL_MAX;
  YAWT_LOG(YAWT_LOG_INFO, "Closing connection: CID=%s, error=%lu",
            YAWT_q_cid_to_hex(&con->cid), error_code);
}

void YAWT_q_con_update_peer_cid(YAWT_Q_Connection_t *con, const YAWT_Q_Cid_t *new_cid) {
  if (!con || !new_cid || new_cid->len == 0) return;
  YAWT_q_cid_set(&con->peer_cid, new_cid->id, new_cid->len);
  YAWT_LOG(YAWT_LOG_INFO, "Peer CID updated: %s", YAWT_q_cid_to_hex(&con->peer_cid));
}

void YAWT_q_con_cb_add(YAWT_Q_Connection_t *con, const YAWT_Q_Callbacks_t *cb) {
  if (!con || !cb) return;
  YAWT_Q_CbNode_t *node = calloc(1, sizeof(YAWT_Q_CbNode_t));
  if (!node) return;
  node->cb = *cb;
  LL_APPEND(con->cb_list, node);
}

void YAWT_q_con_clear_odcid(YAWT_Q_Connection_t *con) {
  if (!con || con->original_dcid.len == 0) return;
  HASH_DELETE(hh_odcid, _hash_odcid, con);
  con->original_dcid.len = 0;
  YAWT_LOG(YAWT_LOG_INFO, "Retired odcid index for CID=%s", YAWT_q_cid_to_hex(&con->cid));
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


// Find stream metadata by stream_id. Returns NULL if not found.
static YAWT_Q_StreamMeta_t *_stream_meta_find(ANB_Slab_t *meta_slab, uint64_t stream_id) {
  ANB_SlabIter_t iter = {0};
  size_t item_size;
  uint8_t *item;
  while ((item = ANB_slab_peek_item_iter(meta_slab, &iter, &item_size)) != NULL) {
    YAWT_Q_StreamMeta_t *m = (YAWT_Q_StreamMeta_t *)item;
    if (m->stream_id == stream_id) return m;
  }
  return NULL;
}

// Create a new stream metadata entry in the slab.
static YAWT_Q_StreamMeta_t *_stream_meta_add(ANB_Slab_t *meta_slab, uint64_t stream_id) {
  YAWT_Q_StreamMeta_t *m = (YAWT_Q_StreamMeta_t *)ANB_slab_alloc_item(meta_slab, sizeof(YAWT_Q_StreamMeta_t));
  if (!m) return NULL;
  memset(m, 0, sizeof(*m));
  m->stream_id = stream_id;
  return m;
}

// Count open streams of a given type (low 2 bits of stream_id: 0x00=bidi_c, 0x01=bidi_s, 0x02=uni_c, 0x03=uni_s)
static uint64_t _stream_count_by_type(ANB_Slab_t *meta_slab, uint8_t stream_type) {
  ANB_SlabIter_t iter = {0};
  size_t item_size;
  uint8_t *item;
  uint64_t count = 0;
  while ((item = ANB_slab_peek_item_iter(meta_slab, &iter, &item_size)) != NULL) {
    YAWT_Q_StreamMeta_t *m = (YAWT_Q_StreamMeta_t *)item;
    if ((m->stream_id & 0x03) == stream_type) count++;
  }
  return count;
}

// Drain contiguous stream frames from rx buffer for a given stream
static void _drain_stream_rx(YAWT_Q_Connection_t *con, YAWT_Q_StreamMeta_t *meta) {
  ANB_SlabIter_t iter = {0};
  size_t item_size;
  uint8_t *item;
  while ((item = ANB_slab_peek_item_iter(con->stream_rx, &iter, &item_size)) != NULL) {
    YAWT_Q_Frame_Stream_t *f = (YAWT_Q_Frame_Stream_t *)item;
    if (f->stream_id != meta->stream_id) continue;
    if (f->offset == meta->rx_next_offset) {
      YAWT_LOG(YAWT_LOG_DEBUG, "Stream %lu: delivered %lu bytes at offset %lu",
                meta->stream_id, f->len, f->offset);
      meta->rx_next_offset += f->len;
      con->stats.rx_count_bytes += f->len;
      if (f->fin) {
        meta->rx_fin = 1;
        meta->rx_fin_offset = f->offset + f->len;
      }
      ANB_slab_pop_item(con->stream_rx, &iter);
    }
  }
}

// Push outbound CRYPTO frames into tx_buffer
static void _push_crypto_frames(YAWT_Q_Connection_t *con) {
  for (int lvl = 0; lvl < 4; lvl++) {
    size_t data_len;
    const uint8_t *data = YAWT_q_crypto_pop_tx(con->crypto, lvl, &data_len);
    if (!data) continue;

    YAWT_Q_Frame_Crypto_t cf = { .offset = 0, .len = data_len, .data = (uint8_t *)data };
    int frame_len = YAWT_q_enqueue_frame_crypto(con, lvl, &cf);
    if (frame_len < 0) {
      printf("  error: encode CRYPTO frame failed for level %d\n", lvl);
      continue;
    }

    printf("  queued CRYPTO frame: level=%d, %zu bytes of TLS data\n", lvl, data_len);
  }
}

static YAWT_Q_FrameHandler_Res_t _handle_frames(YAWT_Q_Connection_t *con,
                                                  YAWT_Q_Packet_t *pkt) {
  YAWT_Q_FrameHandler_Res_t res = { .err = YAWT_Q_OK, .requires_ack = 0 };
  YAWT_Q_ReadCursor_t frc = { .data = pkt->payload, .len = pkt->payload_len, .cursor = 0, .err = YAWT_Q_OK };

  while (frc.cursor < frc.len && frc.err == YAWT_Q_OK) {
    YAWT_Q_Frame_t frame;
    YAWT_q_parse_frame(&frc, pkt->type, &frame);
    if (frc.err != YAWT_Q_OK) break;

    // RFC 9000 §13.2: only ACK and PADDING are non-ack-eliciting
    if (frame.type != YAWT_Q_FRAME_ACK && frame.type != YAWT_Q_FRAME_PADDING) {
      res.requires_ack = 1;
    }

    switch (frame.type) {
      case YAWT_Q_FRAME_PADDING:
      case YAWT_Q_FRAME_PING:
        break;

      case YAWT_Q_FRAME_ACK:
        YAWT_LOG(YAWT_LOG_DEBUG, "ACK: largest=%lu, first_range=%lu",
                 frame.ack.largest_ack, frame.ack.first_ack_range);
        _process_ack(con, _pkt_type_to_level(pkt->type), &frame.ack);
        break;

      case YAWT_Q_FRAME_CRYPTO: {
        YAWT_LOG(YAWT_LOG_INFO, "Received CRYPTO frame (pkt=%d): offset=%lu, len=%lu",
                  pkt->type, frame.crypto.offset, frame.crypto.len);

        int ret = YAWT_q_crypto_feed(con->crypto, &frame);
        if (ret < 0) {
          YAWT_LOG(YAWT_LOG_ERROR, "crypto_feed failed: %d", ret);
          res.err = YAWT_Q_ERR_INVALID_PACKET;
          return res;
        }

        _push_crypto_frames(con);

        if (YAWT_q_crypto_is_handshake_complete(con->crypto)) {
          YAWT_q_con_clear_odcid(con);

          YAWT_LOG(YAWT_LOG_INFO, "Peer flow control: max_data=%lu, streams_bidi=%lu, streams_uni=%lu",
                    con->peer_fc.max_data, con->peer_fc.max_streams_bidi, con->peer_fc.max_streams_uni);
          // RFC 9000 §19.20: server MUST send HANDSHAKE_DONE in a 1-RTT packet
          YAWT_q_enqueue_frame_handshake_done(con);
        }
        break;
      }

      case YAWT_Q_FRAME_HANDSHAKE_DONE:
        YAWT_LOG(YAWT_LOG_INFO, "TODO: handshake done, drop handshake keys");
        break;

      case YAWT_Q_FRAME_CONNECTION_CLOSE:
        printf("  CONNECTION_CLOSE: error=%lu, frame_type=%lu\n",
               frame.connection_close.error_code, frame.connection_close.frame_type);
        break;

      case YAWT_Q_FRAME_STREAM: {
        YAWT_Q_StreamMeta_t *meta = _stream_meta_find(con->stream_meta, frame.stream.stream_id);
        if (!meta) {
          meta = _stream_meta_add(con->stream_meta, frame.stream.stream_id);
          if (!meta) break;
        }
        uint64_t end = frame.stream.offset + frame.stream.len;

        // Skip fully duplicate data
        if (end <= meta->rx_next_offset) break;

        if (frame.stream.offset == meta->rx_next_offset) {
          // In order — deliver directly from dataptr (still points into UDP buffer)
          // TODO: deliver frame.stream.dataptr / frame.stream.len to application
          YAWT_LOG(YAWT_LOG_DEBUG, "Stream %lu: delivered %lu bytes at offset %lu",
                    meta->stream_id, frame.stream.len, frame.stream.offset);
          meta->rx_next_offset = end;
          con->stats.rx_count_bytes += frame.stream.len;
          if (frame.stream.fin) {
            meta->rx_fin = 1;
            meta->rx_fin_offset = end;
          }
          _drain_stream_rx(con, meta);
        } else {
          // Out of order — alloc in slab, copy struct + data, single copy
          YAWT_LOG(YAWT_LOG_DEBUG, "Stream %lu: buffering %lu bytes at offset %lu (expected %lu)",
                    meta->stream_id, frame.stream.len, frame.stream.offset, meta->rx_next_offset);
          uint8_t *slot = ANB_slab_alloc_item(con->stream_rx, sizeof(YAWT_Q_Frame_Stream_t));
          if (slot) {
            YAWT_Q_Frame_Stream_t *buf = (YAWT_Q_Frame_Stream_t *)slot;
            *buf = frame.stream;
            memcpy(buf->data, frame.stream.dataptr, frame.stream.len);
            buf->dataptr = NULL;
          }
        }
        break;
      }

      case YAWT_Q_FRAME_MAX_DATA:
        if (frame.max_data.max_data > con->peer_fc.max_data) {
          con->peer_fc.max_data = frame.max_data.max_data;
          YAWT_LOG(YAWT_LOG_DEBUG, "MAX_DATA updated to %lu", con->peer_fc.max_data);
        }
        break;

      case YAWT_Q_FRAME_MAX_STREAM_DATA: {
        YAWT_Q_StreamMeta_t *meta = _stream_meta_find(con->stream_meta, frame.max_stream_data.stream_id);
        if (meta && frame.max_stream_data.max_stream_data > meta->tx_max_data) {
          meta->tx_max_data = frame.max_stream_data.max_stream_data;
          YAWT_LOG(YAWT_LOG_DEBUG, "MAX_STREAM_DATA stream %lu updated to %lu",
                    frame.max_stream_data.stream_id, meta->tx_max_data);
        }
        break;
      }

      case YAWT_Q_FRAME_MAX_STREAMS_BIDI:
        if (frame.max_streams.max_streams > con->peer_fc.max_streams_bidi) {
          con->peer_fc.max_streams_bidi = frame.max_streams.max_streams;
          YAWT_LOG(YAWT_LOG_DEBUG, "MAX_STREAMS_BIDI updated to %lu", con->peer_fc.max_streams_bidi);
        }
        break;

      case YAWT_Q_FRAME_MAX_STREAMS_UNI:
        if (frame.max_streams.max_streams > con->peer_fc.max_streams_uni) {
          con->peer_fc.max_streams_uni = frame.max_streams.max_streams;
          YAWT_LOG(YAWT_LOG_DEBUG, "MAX_STREAMS_UNI updated to %lu", con->peer_fc.max_streams_uni);
        }
        break;

      case YAWT_Q_FRAME_NEW_CONNECTION_ID:
        if (frame.new_connection_id.seq_num > con->stats.cid_seq_num) {
          con->stats.cid_seq_num = frame.new_connection_id.seq_num;
          YAWT_q_con_update_peer_cid(con, &frame.new_connection_id.cid);
        }
        break;

      case YAWT_Q_FRAME_PATH_CHALLENGE:
        YAWT_LOG(YAWT_LOG_DEBUG, "PATH_CHALLENGE received, echoing PATH_RESPONSE");
        YAWT_q_enqueue_frame_path_response(con, frame.path_challenge.data);
        break;

      case YAWT_Q_FRAME_PATH_RESPONSE:
        YAWT_LOG(YAWT_LOG_DEBUG, "PATH_RESPONSE received (ignored — no pending challenge)");
        break;

      case YAWT_Q_FRAME_DATAGRAM:
        YAWT_LOG(YAWT_LOG_DEBUG, "DATAGRAM received, len=%lu", frame.datagram.len);
        // TODO: deliver via on_datagram callback when wired
        break;

      default:
        printf("  unhandled frame type: 0x%02lx\n", (uint64_t)frame.type);
        break;
    }
  }

  if (frc.err != YAWT_Q_OK) {
    YAWT_LOG(YAWT_LOG_ERROR, "Frame parse error: %s (%d)", YAWT_q_err_str(frc.err), frc.err);
    res.err = frc.err;
  }
  return res;
}

void YAWT_q_con_rx(uint8_t *data, size_t len, YAWT_Q_Crypto_Cred_t *cred,
                              const YAWT_Q_PeerAddr_t *peer_addr, double now) {
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
    int lvl_key_avail = YAWT_q_crypto_key_level_available(con->crypto, level);

    // For Initial packets: derive keys from DCID if not done yet
    if (level == YAWT_Q_LEVEL_INITIAL && !lvl_key_avail) {
      int ret = YAWT_q_crypto_derive_initial_keys(con->crypto, &pkt.dest_cid);  //RFC 9001 §5.2 - the dest cid in initial packet is randomly generated by remote party
      if (ret < 0) {
        YAWT_LOG(YAWT_LOG_ERROR, "Failed to derive initial keys for CID=%s: %d",
                  YAWT_q_cid_to_hex(&pkt.dest_cid), ret);
        break;
      }
      YAWT_LOG(YAWT_LOG_INFO, "Derived initial keys for CID=%s from DCID (%u bytes)",
                YAWT_q_cid_to_hex(&pkt.dest_cid), pkt.dest_cid.len);

      lvl_key_avail = YAWT_q_crypto_key_level_available(con->crypto, level);
    }
    
    if (!lvl_key_avail) {
      YAWT_LOG(YAWT_LOG_WARN, "no keys for level %d, skipping decrypt", level);
      continue;
    }

    int ret = YAWT_q_crypto_unprotect_packet(&pkt, con->crypto);
    if (ret < 0) {
      printf("  error: unprotect/decrypt failed: %d\n", ret);
      continue;
    }

    con->stats.last_rx = now;

    // Reconstruct full packet number from truncated value
    uint64_t full_pn = _reconstruct_pn(con->stats.pkt_num_rx[level], pkt.packet_num, pkt.packet_number_length);
    pkt.packet_num = (uint32_t)full_pn;
    if (full_pn > con->stats.pkt_num_rx[level]) con->stats.pkt_num_rx[level] = full_pn;

    // Parse frames from decrypted payload
    YAWT_LOG(YAWT_LOG_DEBUG, "Decrypted payload first bytes: %02x %02x %02x %02x %02x %02x %02x %02x",
             pkt.payload[0], pkt.payload[1], pkt.payload[2], pkt.payload[3],
             pkt.payload[4], pkt.payload[5], pkt.payload[6], pkt.payload[7]);
    YAWT_Q_FrameHandler_Res_t res = _handle_frames(con, &pkt);

    // RFC 9000 §13.2: only ACK packets containing ack-eliciting frames
    if (res.requires_ack) {
      YAWT_q_enqueue_frame_ack(con, level, pkt.packet_num);
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
  return (uint32_t)con->stats.pkt_num_tx[level]++;
}

static void _drain_tx(YAWT_Q_Connection_t *con,
                               YAWT_Q_Send_Func_t send_func,
                               void *send_ctx, double now) {
  for (int lvl = 0; lvl < 4; lvl++) {
    uint8_t payload[YAWT_Q_MAX_PKT_SIZE];
    size_t payload_len = 0;
    int found = 0;

    ANB_SlabIter_t iter = {0};
    size_t item_size;
    uint8_t *item;

    while ((item = ANB_slab_peek_item_iter(con->tx_buffer, &iter, &item_size)) != NULL) {
      if (item_size < sizeof(YAWT_Q_WireFrame_t)) continue;
      YAWT_Q_WireFrame_t *f = (YAWT_Q_WireFrame_t *)item;

      if (f->level != lvl || f->last_sent != 0) continue;

      // RFC 9000 §4.1: flow control — hold STREAM frames until within limits.
      // Bytes are counted optimistically at enqueue time (in send_stream);
      // frames stay buffered here until MAX_DATA / MAX_STREAM_DATA raises limits.
      if (f->type == YAWT_Q_FRAME_STREAM) {
        if (con->stats.tx_count_bytes > con->peer_fc.max_data) continue;
        YAWT_Q_StreamMeta_t *meta = _stream_meta_find(con->stream_meta, f->stream_id);
        if (meta && meta->tx_next_offset > meta->tx_max_data) continue;
      }

      if (payload_len + f->wire_len > sizeof(payload)) break;

      memcpy(payload + payload_len, f->wire_data, f->wire_len);
      payload_len += f->wire_len;
      found = 1;
    }

    if (!found) continue;

    if (!YAWT_q_crypto_key_level_available(con->crypto, lvl)) {
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
    int wire_len = YAWT_q_encode_packet(&pkt, con->crypto, &wire_data);
    if (wire_len < 0) {
      printf("  error: encode packet failed: %d\n", wire_len);
      continue;
    }

    size_t send_size = (size_t)wire_len;
    send_func(wire_data, send_size, &con->peer_addr, send_ctx);
    con->stats.last_tx = now;

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
    ANB_SlabIter_t iter2 = {0};
    while ((item = ANB_slab_peek_item_iter(con->tx_buffer, &iter2, &item_size)) != NULL) {
      if (item_size < sizeof(YAWT_Q_WireFrame_t)) continue;
      YAWT_Q_WireFrame_t *f = (YAWT_Q_WireFrame_t *)item;
      if (f->level == lvl && f->last_sent == 0) {
        f->last_sent = now;
        f->packet_num = pn;
      }
    }
  }
}

void YAWT_q_con_tx(YAWT_Q_Send_Func_t send_func, void *send_ctx,
                            double now) {
  if (!send_func) return;

  YAWT_Q_Connection_t *con, *tmp;
  HASH_ITER(hh_cid, _hash_cid, con, tmp) {
    if (ANB_slab_item_count(con->tx_buffer) > 0) {
      _drain_tx(con, send_func, send_ctx, now);
    }
  }
}

// Max stream data per STREAM frame: packet size minus worst-case overhead
// (long header ~25 bytes + varint stream_id + varint offset + varint length)
#define YAWT_Q_STREAM_CHUNK_MAX 1325

int YAWT_q_con_send_stream(YAWT_Q_Connection_t *con, uint64_t stream_id,
                           const uint8_t *data, size_t data_len, int fin) {
  if (!con) return -1;

  YAWT_Q_StreamMeta_t *meta = _stream_meta_find(con->stream_meta, stream_id);
  if (!meta) {
    // New stream — check max_streams before creating
    uint8_t stype = stream_id & 0x03;
    int is_bidi = (stype == YAWT_Q_C_BIDI || stype == YAWT_Q_S_BIDI);
    uint64_t limit = is_bidi ? con->peer_fc.max_streams_bidi : con->peer_fc.max_streams_uni;
    uint64_t count = _stream_count_by_type(con->stream_meta, stype);
    if (count >= limit) {
      YAWT_LOG(YAWT_LOG_WARN, "max_streams exceeded: type=%u, count=%lu, limit=%lu",
                stype, count, limit);
      return -1;
    }
    meta = _stream_meta_add(con->stream_meta, stream_id);
    if (!meta) return -1;
  }
  if (meta->tx_fin_sent) return -1;

  // Handle empty FIN (close stream with no data)
  if (data_len == 0 && fin) {
    YAWT_Q_Frame_Stream_t sf;
    memset(&sf, 0, sizeof(sf));
    sf.stream_id = stream_id;
    sf.off = (meta->tx_next_offset > 0) ? 1 : 0;
    sf.offset = meta->tx_next_offset;
    sf.len_present = 1;
    sf.len = 0;
    sf.fin = 1;
    int ret = YAWT_q_enqueue_frame_stream(con, &sf);
    if (ret < 0) return -1;
    meta->tx_fin_sent = 1;
    return 0;
  }

  size_t total = 0;
  size_t remaining = data_len;
  const uint8_t *src = data;

  while (remaining > 0) {
    size_t chunk_len = remaining;
    if (chunk_len > YAWT_Q_STREAM_CHUNK_MAX) chunk_len = YAWT_Q_STREAM_CHUNK_MAX;

    YAWT_Q_Frame_Stream_t sf;
    memset(&sf, 0, sizeof(sf));
    sf.stream_id = stream_id;
    sf.off = (meta->tx_next_offset > 0) ? 1 : 0;
    sf.offset = meta->tx_next_offset;
    sf.len_present = 1;
    sf.len = chunk_len;
    sf.fin = (fin && remaining == chunk_len) ? 1 : 0;
    memcpy(sf.data, src, chunk_len);

    int ret = YAWT_q_enqueue_frame_stream(con, &sf);
    if (ret < 0) return -1;

    meta->tx_next_offset += chunk_len;
    // RFC 9000 §4.1: flow control is offset-based — count bytes once here when
    // the offset advances, not on retransmit. Retransmits don't consume budget.
    con->stats.tx_count_bytes += chunk_len;
    src += chunk_len;
    remaining -= chunk_len;
    total += chunk_len;
  }

  if (fin) meta->tx_fin_sent = 1;
  return (int)total;
}

// Global maintenance configuration
static YAWT_Q_MaintenanceConfig_t _maint_cfg = {
  .retransmit_initial = 0.5,
  .retransmit_backoff = 1.5,
  .retransmit_max = 10,
  .min_maint_interval = 0.25,
};

// Effective idle timeout for a connection (seconds). Returns 0 if no limit.
// Clamped to security policy min_idle_timeout_ms floor.
static double _effective_idle_timeout(YAWT_Q_Connection_t *con) {
  uint64_t local = con->local_fc.max_idle_timeout;
  uint64_t peer = con->peer_fc.max_idle_timeout;
  uint64_t ms = 0;
  if (local > 0 && peer > 0) ms = (local < peer) ? local : peer;
  else if (local > 0) ms = local;
  else ms = peer;

  uint64_t floor = YAWT_q_security_get()->min_idle_timeout_ms;
  if (ms > 0 && floor > 0 && ms < floor) ms = floor;

  return (double)ms / 1000.0;
}

const YAWT_Q_MaintenanceConfig_t *YAWT_q_con_get_maint_config(void) {
  return &_maint_cfg;
}

// Check if connection should be freed. Returns 1 if freed.
// Handles: closing state (DBL_MAX -> stamp -> free after 3x PTO) and idle timeout.
static int _maint_kill(YAWT_Q_Connection_t **con, double idle_sec, double now) {
  double closing = (*con)->stats.closing_at;

  // Closing state: DBL_MAX means close queued but not yet flushed — stamp it now
  if (closing == DBL_MAX) {
    (*con)->stats.closing_at = now;
    return 0;
  }

  // Closing state: real timestamp — free after 3x PTO
  if (closing > 0) {
    double pto = _maint_cfg.retransmit_initial * 3.0;
    if (now - closing > pto) {
      YAWT_LOG(YAWT_LOG_INFO, "Closing period expired: CID=%s",
                YAWT_q_cid_to_hex(&(*con)->cid));
      YAWT_q_con_free(con);
      return 1;
    }
    return 0;
  }

  // Idle timeout
  if (idle_sec <= 0 || (*con)->stats.last_rx == 0) return 0;
  if (now - (*con)->stats.last_rx > idle_sec) {
    YAWT_LOG(YAWT_LOG_INFO, "Idle timeout: CID=%s, %.1fs since last rx",
              YAWT_q_cid_to_hex(&(*con)->cid), now - (*con)->stats.last_rx);
    YAWT_q_con_free(con);
    return 1;
  }
  return 0;
}

// Send keepalive PING if approaching idle timeout.
static void _maint_ping(YAWT_Q_Connection_t *con, double idle_sec, double now) {
  if (idle_sec <= 0 || con->stats.last_rx == 0) return;
  if (ANB_slab_item_count(con->tx_buffer) > 0) return;
  double keepalive_threshold = idle_sec / 3.0;
  if (now - con->stats.last_tx > keepalive_threshold) {
    YAWT_LOG(YAWT_LOG_DEBUG, "Keepalive PING: CID=%s", YAWT_q_cid_to_hex(&con->cid));
    YAWT_q_enqueue_frame_ping(con);
  }
}

// Mark timed-out sent frames for retransmit on a single connection.
static void _maint_retransmit(YAWT_Q_Connection_t *con, double now) {
  ANB_SlabIter_t iter = {0};
  size_t item_size;
  uint8_t *item;

  while ((item = ANB_slab_peek_item_iter(con->tx_buffer, &iter, &item_size)) != NULL) {
    if (item_size < sizeof(YAWT_Q_WireFrame_t)) continue;
    YAWT_Q_WireFrame_t *f = (YAWT_Q_WireFrame_t *)item;
    if (f->last_sent == 0) continue;

    if (f->retransmit_count >= _maint_cfg.retransmit_max) {
      // TODO: give up — close connection
      continue;
    }

    double timeout = _maint_cfg.retransmit_initial;
    for (uint32_t i = 0; i < f->retransmit_count; i++) {
      timeout *= _maint_cfg.retransmit_backoff;
    }

    if (now - f->last_sent > timeout) {
      YAWT_LOG(YAWT_LOG_DEBUG, "Retransmit: level=%d, type=0x%02x, attempt=%u, timeout=%.3fs",
                f->level, f->type, f->retransmit_count + 1, timeout);
      f->last_sent = 0;
      f->retransmit_count++;
    }
  }
}


void YAWT_q_con_maintain(YAWT_Q_Send_Func_t send_func, void *send_ctx,
                          double now) {
  if (!send_func) return;

  YAWT_Q_Connection_t *con, *tmp;
  HASH_ITER(hh_cid, _hash_cid, con, tmp) {
    double idle_sec = _effective_idle_timeout(con);
    if (_maint_kill(&con, idle_sec, now)) continue;
    _maint_ping(con, idle_sec, now);
    _maint_retransmit(con, now);

    if (ANB_slab_item_count(con->tx_buffer) > 0) {
      _drain_tx(con, send_func, send_ctx, now);
    }
  }
}
