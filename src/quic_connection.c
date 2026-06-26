#include "quic_connection.h"
#include "quic.h"
#include "impl/quic_types.h"
#include <stdio.h>
#include <uthash/uthash.h>
#include <allocnbuffer/slab.h>
#include "logger.h"
#include "security.h"
#include <arpa/inet.h>
#include <float.h>

// Process-wide event handler — installed via YAWT_q_con_set_event_handler.
// Defaults to a no-op so dispatch sites never need to null-check.
static void _noop_event_handler(YAWT_Q_Connection_t *con,
                                 YAWT_Q_EventType_t event,
                                 YAWT_Q_EventParam_t param) {
  (void)con; (void)event; (void)param;
}
static YAWT_Q_EventHandler_t _event_handler = _noop_event_handler;

// Forward declarations
static void _drain_tx(YAWT_Q_Connection_t *con, double now);
static void _push_crypto_frames(YAWT_Q_Connection_t *con);

// Calculate new auto-increased flow control limit.
// Returns current_val * fc_auto_increase_factor (default 2x if factor is 0).
static uint64_t _get_new_auto_fc_limit(uint64_t fc_current_val) {
  uint64_t factor = YAWT_q_security_get()->fc_auto_increase_factor;
  if (factor == 0) factor = 2;
  return fc_current_val * factor;
}

// Auto-adjust stream RX limit if userspace didn't adjust after threshold event.
// Called both preemptively (threshold reached) and reactively (peer sent STREAM_DATA_BLOCKED).
static void _fc_auto_adjust_stream_rx(YAWT_Q_Connection_t *con, uint64_t stream_id, uint64_t current_limit) {
  if (current_limit == 0) return;
  uint64_t new_limit = _get_new_auto_fc_limit(current_limit);
  YAWT_LOG(YAWT_LOG_INFO, "Stream %lu: auto-increased RX FC limit -> %lu", stream_id, new_limit);
  YAWT_q_con_set_stream_rx_limit(con, stream_id, new_limit);
}

// Auto-adjust connection RX limit if userspace didn't adjust after threshold event.
// Called both preemptively (threshold reached) and reactively (peer sent DATA_BLOCKED).
static void _fc_auto_adjust_conn_rx(YAWT_Q_Connection_t *con, uint64_t current_limit) {
  if (current_limit == 0) return;
  uint64_t new_limit = _get_new_auto_fc_limit(current_limit);
  YAWT_LOG(YAWT_LOG_INFO, "Connection: auto-increased RX FC limit -> %lu", new_limit);
  YAWT_q_con_set_conn_rx_limit(con, new_limit);
}

// Check if connection is in any closing state (RFC 9000 §10.2)
static bool _is_closing(const YAWT_Q_Connection_t *con) {
  return (con->state & (YAWT_Q_STATE_SELF_CLOSE_CLOSING | YAWT_Q_STATE_PEER_CLOSE_DRAINING)) != 0;
}

// Record why a connection is closing. The actual EVT_CLOSE is emitted later,
// exactly once, by YAWT_q_con_free. reason is copied (bounded) so callers may
// pass transient buffers or string literals.
static void _record_close(YAWT_Q_Connection_t *con, uint64_t code,
                          const char *reason, size_t reason_len,
                          YAWT_Q_ConnState_t state) {
  con->close_code = code;
  if (reason && reason_len) {
    if (reason_len >= sizeof(con->close_reason)) reason_len = sizeof(con->close_reason) - 1;
    memcpy(con->close_reason, reason, reason_len);
    con->close_reason[reason_len] = '\0';
  } else {
    con->close_reason[0] = '\0';
  }
  con->state |= state;
  con->closing_rx_count = 0;
}

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
static int _pn_is_acked(uint64_t pn, const YAWT_Q_Frame_ACK_t *ack) {
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


/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Check if stream should transmit data.
 * If the stream is just blocked, we'll buffer
 * @note Returns true if TX is active (no FIN sent, no RESET sent, not stopped by peer).
 */

static inline bool _stream_state_allows_tx(const YAWT_Q_StreamMeta_t *m) {
  return !(m->state & (YAWT_Q_STREAM_FIN_SENT | YAWT_Q_STREAM_RESET_SENT | YAWT_Q_STREAM_STOPPED_RECEIVED));
}

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Check if stream should receive data.
 * @note Returns true if RX is active (no FIN received, no RESET received, not stopped by us).
 */
static inline bool _stream_should_rx(const YAWT_Q_StreamMeta_t *m) {
  return !(m->state & (YAWT_Q_STREAM_FIN_RECEIVED | YAWT_Q_STREAM_RESET_RECEIVED | YAWT_Q_STREAM_STOPPED_SENT));
}
// RFC 9000 §4.1: Connection-level flow control threshold check.
// This applies only to stream data and should NOT be added to DATAGRAM
// or other unreliable frame handlers, as they do not count towards
// connection flow control limits.

static void _preemptive_fc_conn_rx_limit_check(YAWT_Q_Connection_t *con)
{
  uint64_t pct = YAWT_q_security_get()->fc_threshold_percent;
  if (con->local_fc.max_data > 0 && pct > 0 && pct <= 100) {
    uint64_t conn_threshold = con->local_fc.max_data * pct / 100;
    if (con->stats.rx_count_bytes >= conn_threshold) {
      YAWT_Q_FlowControlInfo_t conn_info = {
        .type = YAWT_Q_FC_CONN_RX,
        .stream_id = 0,
        .current_limit = con->local_fc.max_data,
        .consumed = con->stats.rx_count_bytes
      };
      YAWT_Q_EventParam_t conn_param;
      conn_param.P_EVT_FLOW_CONTROL.info = &conn_info;
      _event_handler(con, YAWT_Q_EVT_FLOW_CONTROL, conn_param);

      _fc_auto_adjust_conn_rx(con, con->local_fc.max_data);
    }
  }
}

static void _preemptive_fc_stream_rx_limit_check(YAWT_Q_Connection_t *con, YAWT_Q_StreamMeta_t *meta)
{

  // The amount of data we have received on stream is close to FC limits
  // alert app space as a courtesy to avoid stalls
  uint64_t pct = YAWT_q_security_get()->fc_threshold_percent;
  if (meta->fc.rx_max_data > 0 && pct > 0 && pct <= 100) {
    uint64_t threshold = meta->fc.rx_max_data * pct / 100;
    if (meta->stats.rx_count_bytes >= threshold) {
      YAWT_Q_FlowControlInfo_t info = {
        .type = YAWT_Q_FC_STREAM_RX,
        .stream_id = meta->stream_id,
        .current_limit = meta->fc.rx_max_data,
        .consumed = meta->stats.rx_count_bytes
      };
      YAWT_Q_EventParam_t param;
      param.P_EVT_FLOW_CONTROL.info = &info;
      _event_handler(con, YAWT_Q_EVT_FLOW_CONTROL, param);

      _fc_auto_adjust_stream_rx(con, meta->stream_id, meta->fc.rx_max_data);
    }
  }
}

static void _preemptive_fc_conn_tx_limit_check(YAWT_Q_Connection_t *con)
{
  uint64_t pct = YAWT_q_security_get()->fc_threshold_percent;
  if (con->peer_fc.max_data > 0 && pct > 0 && pct <= 100) {
    uint64_t conn_threshold = con->peer_fc.max_data * pct / 100;
    if (con->stats.tx_count_bytes >= conn_threshold) {
      YAWT_Q_FlowControlInfo_t conn_info = {
        .type = YAWT_Q_FC_CONN_TX,
        .stream_id = 0,
        .current_limit = con->peer_fc.max_data,
        .consumed = con->stats.tx_count_bytes
      };
      YAWT_Q_EventParam_t conn_param;
      conn_param.P_EVT_FLOW_CONTROL.info = &conn_info;
      _event_handler(con, YAWT_Q_EVT_FLOW_CONTROL, conn_param);
    }
  }
}

static void _preemptive_fc_stream_tx_limit_check(YAWT_Q_Connection_t *con, YAWT_Q_StreamMeta_t *meta)
{
  uint64_t pct = YAWT_q_security_get()->fc_threshold_percent;
  if (meta->fc.tx_max_data > 0 && pct > 0 && pct <= 100) {
    uint64_t threshold = meta->fc.tx_max_data * pct / 100;
    if (meta->stats.tx_count_bytes >= threshold) {
      YAWT_Q_FlowControlInfo_t info = {
        .type = YAWT_Q_FC_STREAM_TX,
        .stream_id = meta->stream_id,
        .current_limit = meta->fc.tx_max_data,
        .consumed = meta->stats.tx_count_bytes
      };
      YAWT_Q_EventParam_t param;
      param.P_EVT_FLOW_CONTROL.info = &info;
      _event_handler(con, YAWT_Q_EVT_FLOW_CONTROL, param);
    }
  }
}

YAWT_Q_Connection_t *_hash_cid = NULL;   // Hash table by our CID
YAWT_Q_Connection_t *_hash_odcid = NULL; // Hash table by original DCID (temporary, pre-handshake)

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
  con->local_fc = info->local_fc ? *info->local_fc : *YAWT_q_security_get_default_fc();
  con->crypto = YAWT_q_crypto_init(info->is_server ? YAWT_Q_ROLE_SERVER : YAWT_Q_ROLE_CLIENT,
                                    info->cred,
                                    &info->original_dcid, &con->cid,
                                    &con->local_fc, &con->peer_fc, NULL);
  con->role = info->is_server ? YAWT_Q_ROLE_SERVER : YAWT_Q_ROLE_CLIENT;
  if (!info->is_server && info->hostname) {
    YAWT_q_crypto_set_hostname(con->crypto, info->hostname);
  }
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

YAWT_Q_Connection_t *YAWT_q_con_connect(YAWT_Q_Con_Create_Info_t *info, double now) {
  if (!info || info->is_server) return NULL;

  YAWT_Q_Cid_t dcid;
  dcid.len = YAWT_Q_CID_LEN;
  YAWT_q_crypto_random_nonce(dcid.id, dcid.len);
  YAWT_q_cid_set(&info->peer_cid, dcid.id, dcid.len);
  YAWT_q_cid_set(&info->original_dcid, dcid.id, dcid.len);

  YAWT_Q_Connection_t *con = YAWT_q_con_create(info);
  if (!con) return NULL;

  con->version = 0x00000001;

  if (YAWT_q_crypto_derive_initial_keys(con->crypto, &dcid) < 0) {
    YAWT_LOG(YAWT_LOG_ERROR, "Failed to derive initial keys for client DCID=%s",
              YAWT_q_cid_to_hex(&dcid));
    YAWT_q_con_free(&con);
    return NULL;
  }

  if (YAWT_q_crypto_start(con->crypto) < 0) {
    YAWT_LOG(YAWT_LOG_ERROR, "Failed to start TLS handshake");
    YAWT_q_con_free(&con);
    return NULL;
  }

  _push_crypto_frames(con);
  _drain_tx(con, now);

  YAWT_LOG(YAWT_LOG_INFO, "Client connection initiated: CID=%s, DCID=%s",
            YAWT_q_cid_to_hex(&con->cid), YAWT_q_cid_to_hex(&dcid));
  return con;
}

void YAWT_q_con_free(YAWT_Q_Connection_t **con) {
  if (con == NULL || *con == NULL) return;
  YAWT_Q_Connection_t *c = *con;

  // Single close chokepoint: every teardown path funnels through here, so
  // emitting EVT_CLOSE once guarantees the app sees exactly one close per
  // connection regardless of how it died (peer CC, idle, closing expired,
  // future paths). Close triggers record code/reason on the connection;
  // they do not emit themselves.
  YAWT_Q_EventParam_t param;
  param.P_EVT_CLOSE.error_code = c->close_code;
  param.P_EVT_CLOSE.reason = c->close_reason;
  _event_handler(c, YAWT_Q_EVT_CLOSE, param);

  HASH_DELETE(hh_cid, _hash_cid, c);
  YAWT_q_con_clear_odcid(c);
  YAWT_q_crypto_free(c->crypto);
  ANB_slab_destroy(c->recv_buffer);
  ANB_slab_destroy(c->tx_buffer);
  ANB_slab_destroy(c->stream_rx);
  ANB_slab_destroy(c->stream_meta);
  free(c);
  *con = NULL;
}

// RFC 9000 §10.2.3: CONNECTION_CLOSE level selection based on role and handshake state.
// Pre-handshake: server sends Initial + Handshake, client sends Handshake + 1-RTT.
// Post-handshake: send at Application level only.
static void _send_connection_close(YAWT_Q_Connection_t *con, uint64_t error_code, uint64_t frame_type) {
  int hs_complete = YAWT_q_crypto_is_handshake_complete(con->crypto);

  if (hs_complete) {
    YAWT_q_enqueue_frame_connection_close(con, YAWT_Q_LEVEL_APPLICATION, error_code, frame_type);
  } else {
    if (con->role == YAWT_Q_ROLE_SERVER) {
      // Server: Initial + Handshake
      if (YAWT_q_crypto_key_level_available(con->crypto, YAWT_Q_LEVEL_INITIAL)) {
        YAWT_q_enqueue_frame_connection_close(con, YAWT_Q_LEVEL_INITIAL, error_code, frame_type);
      }
      if (YAWT_q_crypto_key_level_available(con->crypto, YAWT_Q_LEVEL_HANDSHAKE)) {
        YAWT_q_enqueue_frame_connection_close(con, YAWT_Q_LEVEL_HANDSHAKE, error_code, frame_type);
      }
    } else {
      // Client: Handshake + 1-RTT
      if (YAWT_q_crypto_key_level_available(con->crypto, YAWT_Q_LEVEL_HANDSHAKE)) {
        YAWT_q_enqueue_frame_connection_close(con, YAWT_Q_LEVEL_HANDSHAKE, error_code, frame_type);
      }
      YAWT_q_enqueue_frame_connection_close(con, YAWT_Q_LEVEL_APPLICATION, error_code, frame_type);
    }
  }
}

void YAWT_q_con_close(YAWT_Q_Connection_t *con, uint64_t error_code) {
  if (!con || _is_closing(con)) return;

  _send_connection_close(con, error_code, 0);
  _record_close(con, error_code, "local close", sizeof("local close") - 1, YAWT_Q_STATE_SELF_CLOSE_CLOSING);
  YAWT_LOG(YAWT_LOG_INFO, "Closing connection: CID=%s, error=%lu",
            YAWT_q_cid_to_hex(&con->cid), error_code);
}

void YAWT_q_con_update_peer_cid(YAWT_Q_Connection_t *con, const YAWT_Q_Cid_t *new_cid) {
  if (!con || !new_cid || new_cid->len == 0) return;
  YAWT_q_cid_set(&con->peer_cid, new_cid->id, new_cid->len);
  YAWT_LOG(YAWT_LOG_INFO, "Peer CID updated: %s", YAWT_q_cid_to_hex(&con->peer_cid));
}

void YAWT_q_con_set_user_data(YAWT_Q_Connection_t *con, YAWT_Q_UserDataSlot_t slot, void *p) {
  if (con) con->user_data[slot] = p;
}

void *YAWT_q_con_get_user_data(YAWT_Q_Connection_t *con, YAWT_Q_UserDataSlot_t slot) {
  return con ? con->user_data[slot] : NULL;
}

void YAWT_q_con_set_event_handler(YAWT_Q_EventHandler_t handler) {
  _event_handler = handler ? handler : _noop_event_handler;
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
static YAWT_Q_StreamMeta_t *_stream_meta_add(YAWT_Q_Connection_t *con, uint64_t stream_id) {
  YAWT_Q_StreamMeta_t *m = (YAWT_Q_StreamMeta_t *)ANB_slab_alloc_item(con->stream_meta, sizeof(YAWT_Q_StreamMeta_t));
  if (!m) return NULL;
  memset(m, 0, sizeof(*m));
  m->stream_id = stream_id;
  
  // Set initial flow control limits based on stream type and role
  // RFC 9000 §18.2: bidi_local = limit on locally-initiated streams, bidi_remote = limit on peer-initiated streams
  uint8_t stype = stream_id & 0x03;
  bool is_bidi = (stype == 0x00 || stype == 0x01);
  bool client_initiated = (stype == 0x00 || stype == 0x02);
  bool we_initiated = (client_initiated && con->role == YAWT_Q_ROLE_CLIENT) ||
                      (!client_initiated && con->role == YAWT_Q_ROLE_SERVER);
  
  if (is_bidi) {
    if (we_initiated) {
      m->fc.tx_max_data = con->peer_fc.max_stream_data_bidi_remote;
      m->fc.rx_max_data = con->local_fc.max_stream_data_bidi_local;
    } else {
      m->fc.tx_max_data = con->peer_fc.max_stream_data_bidi_local;
      m->fc.rx_max_data = con->local_fc.max_stream_data_bidi_remote;
    }
  } else {
    // Unidirectional: only one direction is active
    if (we_initiated) {
      m->fc.tx_max_data = con->peer_fc.max_stream_data_uni;
      m->fc.rx_max_data = 0;
    } else {
      m->fc.tx_max_data = 0;
      m->fc.rx_max_data = con->local_fc.max_stream_data_uni;
    }
  }
  
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

// RFC 9000 §4.5: Validate stream data against known final size.
// Returns YAWT_Q_OK if data is within bounds, YAWT_Q_ERR_FINAL_SIZE_ERROR if violation.
// Updates rx_final_size if FIN is set and final size not yet known.
static YAWT_Err_t _check_final_size(YAWT_Q_StreamMeta_t *meta, uint64_t offset, uint64_t data_len, int fin) {
  uint64_t end = offset + data_len;
  bool fin_received = (meta->state & YAWT_Q_STREAM_FIN_RECEIVED) != 0;
  
  if (fin_received) {
    if (end > meta->rx_final_size) {
      YAWT_LOG(YAWT_LOG_ERROR, "FINAL_SIZE_ERROR: stream %lu data at offset %lu len %lu exceeds final size %lu",
               meta->stream_id, offset, data_len, meta->rx_final_size);
      return YAWT_Q_ERR_FINAL_SIZE_ERROR;
    }
  }
  
  if (fin) {
    if (fin_received && end != meta->rx_final_size) {
      YAWT_LOG(YAWT_LOG_ERROR, "FINAL_SIZE_ERROR: stream %lu conflicting final size %lu (expected %lu)",
               meta->stream_id, end, meta->rx_final_size);
      return YAWT_Q_ERR_FINAL_SIZE_ERROR;
    }
    meta->rx_final_size = end;
  }
  
  return YAWT_Q_OK;
}

// Drain contiguous stream frames from rx buffer for a given stream.
// RFC 9000 §2.2: endpoints MUST deliver stream data as an ordered byte stream,
// requiring buffering of out-of-order data up to the flow control limit.
// This function is the reassembly mechanism — it delivers buffered frames
// once the gap is filled and rx_next_offset is reached.
// Returns YAWT_Q_OK on success, or YAWT_Q_ERR_FINAL_SIZE_ERROR on violation
static YAWT_Err_t _drain_stream_rx(YAWT_Q_Connection_t *con, YAWT_Q_StreamMeta_t *meta) {
  ANB_SlabIter_t iter = {0};
  size_t item_size;
  uint8_t *item;
  while ((item = ANB_slab_peek_item_iter(con->stream_rx, &iter, &item_size)) != NULL) {
    YAWT_Q_Frame_BufferedStream_t *bf = (YAWT_Q_Frame_BufferedStream_t *)item;
    YAWT_Q_Frame_Stream_t *f = &bf->frame;
    if (f->stream_id != meta->stream_id) continue;
    if (f->offset == meta->rx_next_offset) {
      // RFC 9000 §4.5: Validate buffered data against known final size
      YAWT_Err_t fs_err = _check_final_size(meta, f->offset, f->data_len, f->fin);
      if (fs_err != YAWT_Q_OK) return fs_err;

      YAWT_LOG(YAWT_LOG_DEBUG, "Stream %lu: delivered %lu bytes at offset %lu",
                meta->stream_id, f->data_len, f->offset);
      meta->rx_next_offset += f->data_len;

      if (f->fin) {
        meta->state |= YAWT_Q_STREAM_FIN_RECEIVED;
        YAWT_LOG(YAWT_LOG_INFO, "Stream %lu: RX finalized (buffered FIN drained at offset %lu)",
                 meta->stream_id, f->offset + f->data_len);
      }

      YAWT_Q_EventParam_t param;
      param.P_EVT_STREAM.frame = f;
      f->data = bf->data; //points at slab copy
      _event_handler(con, YAWT_Q_EVT_STREAM, param);

      ANB_slab_pop_item(con->stream_rx, &iter);
    }
  }

  return YAWT_Q_OK;
}

// Push outbound CRYPTO frames into tx_buffer.
// Splits one batch of TLS data per level into packet-sized chunks at increasing offsets.
// Assumes each level produces a single batch over the connection's lifetime (no 0-RTT,
// session tickets disabled, no post-handshake client auth) — so per-call offsets
// starting at 0 are correct.
//
// Chunk size budget: long-header packet payload (1281) minus CRYPTO frame header overhead
// (1 type byte + up to 4-byte offset varint + up to 4-byte length varint = 9 worst case).
#define YAWT_Q_CRYPTO_FRAME_HDR_MAX 9
#define YAWT_Q_CRYPTO_CHUNK_MAX (YAWT_Q_MAX_FRAME_PAYLOAD_LONG - YAWT_Q_CRYPTO_FRAME_HDR_MAX)

static void _push_crypto_frames(YAWT_Q_Connection_t *con) {
  for (int lvl = 0; lvl < 4; lvl++) {
    size_t data_len;
    const uint8_t *data = YAWT_q_crypto_pop_tx(con->crypto, lvl, &data_len);
    if (!data) continue;

    uint64_t off = 0;
    while (off < data_len) {
      size_t chunk = data_len - off;
      if (chunk > YAWT_Q_CRYPTO_CHUNK_MAX) chunk = YAWT_Q_CRYPTO_CHUNK_MAX;

      YAWT_Q_Frame_Crypto_t cf = { .offset = off, .len = chunk, .data = (uint8_t *)data + off };
      YAWT_Err_t err = YAWT_q_enqueue_frame_crypto(con, lvl, &cf);
      if (err != YAWT_Q_OK) {
        YAWT_LOG(YAWT_LOG_ERROR, "encode CRYPTO frame failed for level %d at offset %lu: %s",
                 lvl, off, YAWT_err_str(err));
        break;
      }

      YAWT_LOG(YAWT_LOG_DEBUG, "queued CRYPTO frame: level=%d, offset=%lu, %zu bytes",
               lvl, off, chunk);
      off += chunk;
    }
  }
}

// RFC 9000 §12.4: frames allowed per packet type
static int _frame_allowed_in_packet(YAWT_Q_Frame_Type_t frame, YAWT_Q_Packet_Type_t pkt_type) {
  switch (pkt_type) {
    case YAWT_Q_PKT_TYPE_INITIAL:
      return frame == YAWT_Q_FRAME_PADDING || frame == YAWT_Q_FRAME_PING ||
             frame == YAWT_Q_FRAME_ACK || frame == YAWT_Q_FRAME_CRYPTO ||
             frame == YAWT_Q_FRAME_CONNECTION_CLOSE;
    case YAWT_Q_PKT_TYPE_HANDSHAKE:
      return frame == YAWT_Q_FRAME_PADDING || frame == YAWT_Q_FRAME_PING ||
             frame == YAWT_Q_FRAME_ACK || frame == YAWT_Q_FRAME_CRYPTO ||
             frame == YAWT_Q_FRAME_CONNECTION_CLOSE || frame == YAWT_Q_FRAME_HANDSHAKE_DONE;
    case YAWT_Q_PKT_TYPE_0RTT:
      return frame != YAWT_Q_FRAME_CRYPTO && frame != YAWT_Q_FRAME_CONNECTION_CLOSE &&
             frame != YAWT_Q_FRAME_CONNECTION_CLOSE_APP && frame != YAWT_Q_FRAME_HANDSHAKE_DONE &&
             frame != YAWT_Q_FRAME_NEW_TOKEN;
    case YAWT_Q_PKT_TYPE_1RTT:
      return 1; 
      break;
    default:
      return 1;
  }
}

// This function parses and dispatches rx quic frames
static YAWT_Q_FrameHandler_Res_t _handle_frames(YAWT_Q_Connection_t *con,
                                                  YAWT_Q_Packet_t *pkt) {
  YAWT_Q_FrameHandler_Res_t res = { .err = YAWT_Q_OK, .requires_ack = 0 };
  YAWT_Q_ReadCursor_t frc = { .data = pkt->payload, .len = pkt->payload_len, .cursor = 0, .err = YAWT_Q_OK };
  int frame_count = 0;

  while (frc.cursor < frc.len && frc.err == YAWT_Q_OK) {
    YAWT_Q_Frame_t frame;
    YAWT_q_parse_frame(&frc, pkt->type, &frame);
    if (frc.err != YAWT_Q_OK) break;
    YAWT_LOG(YAWT_LOG_DEBUG, "Parsed Frame: type=0x%02x, cursor=%zu, len=%zu",
             frame.type, frc.cursor, frc.len);
    frame_count++;

    // RFC 9000 §12.4: reject frames not allowed in this packet type
    if (!_frame_allowed_in_packet(frame.type, pkt->type)) {
      YAWT_LOG(YAWT_LOG_WARN, "PROTOCOL_VIOLATION: frame 0x%02x not allowed in %s",
               frame.type, _pkt_type_name(pkt->type));
      res.err = YAWT_Q_ERR_INVALID_PACKET;
      return res;
    }

    // RFC 9000 §13.2: only ACK and PADDING are non-ack-eliciting
    if (frame.type != YAWT_Q_FRAME_ACK && frame.type != YAWT_Q_FRAME_PADDING &&
        frame.type != YAWT_Q_FRAME_CONNECTION_CLOSE && frame.type != YAWT_Q_FRAME_CONNECTION_CLOSE_APP) {
      res.requires_ack = 1;
    }

    switch (frame.type) {
      case YAWT_Q_FRAME_PADDING:
      case YAWT_Q_FRAME_PING:
        break;

      case YAWT_Q_FRAME_ACK:
        YAWT_LOG(YAWT_LOG_DEBUG, "ACK: largest=%lu, first_range=%lu",
                 frame.ack.largest_ack, frame.ack.first_ack_range);
        _process_ack(con, YAWT_q_pkt_type_to_level(pkt->type), &frame.ack);
        break;

      case YAWT_Q_FRAME_CRYPTO: {
        YAWT_LOG(YAWT_LOG_INFO, "Received CRYPTO frame (pkt=%d): offset=%lu, len=%lu",
                  pkt->type, frame.crypto.offset, frame.crypto.len);

        YAWT_Err_t feed_err = YAWT_q_crypto_feed(con->crypto, &frame);
        if (feed_err == YAWT_Q_ERR_CRYPTO_BUFFER_EXCEEDED) {
          YAWT_LOG(YAWT_LOG_ERROR, "CRYPTO_BUFFER_EXCEEDED at level %d", YAWT_q_pkt_type_to_level(pkt->type));
          _send_connection_close(con, YAWT_Q_ERR_CRYPTO_BUFFER_EXCEEDED, YAWT_Q_FRAME_CRYPTO);
          _record_close(con, YAWT_Q_ERR_CRYPTO_BUFFER_EXCEEDED, "crypto buffer exceeded", sizeof("crypto buffer exceeded") - 1, YAWT_Q_STATE_SELF_CLOSE_CLOSING);
          res.err = feed_err;
          return res;
        }
        if (feed_err == YAWT_Q_ERR_TLS_ALERT) {
          uint8_t alert_code = YAWT_q_crypto_get_tls_alert(con->crypto);
          uint64_t crypto_error = 0x0100 + alert_code;
          YAWT_LOG(YAWT_LOG_ERROR, "TLS alert received: code=%d, sending CRYPTO_ERROR 0x%lx", alert_code, crypto_error);
          _send_connection_close(con, crypto_error, YAWT_Q_FRAME_CRYPTO);
          _record_close(con, crypto_error, "TLS alert", sizeof("TLS alert") - 1, YAWT_Q_STATE_SELF_CLOSE_CLOSING);
          res.err = feed_err;
          return res;
        }
        if (feed_err != YAWT_Q_OK) {
          YAWT_LOG(YAWT_LOG_ERROR, "crypto_feed failed: %s", YAWT_err_str(feed_err));
          res.err = feed_err;
          return res;
        }

        _push_crypto_frames(con);

        // Fire once: gated on original_dcid still being set, which clear_odcid()
        // tears down. Avoids re-enqueueing HANDSHAKE_DONE / re-firing on_connected
        // for every post-handshake CRYPTO frame (e.g. NewSessionTicket).
        if (YAWT_q_crypto_is_handshake_complete(con->crypto) && con->original_dcid.len > 0) {
          YAWT_q_con_clear_odcid(con);

          // RFC 9000 §8.1: address validated after successful handshake
          con->state |= YAWT_Q_STATE_ADDR_VALIDATED;
          con->stats.rx_count_bytes = 0;
          con->stats.tx_count_bytes = 0;

          YAWT_LOG(YAWT_LOG_INFO, "Peer flow control: max_data=%lu, streams_bidi=%lu, streams_uni=%lu",
                    con->peer_fc.max_data, con->peer_fc.max_streams_bidi, con->peer_fc.max_streams_uni);
          if (con->role == YAWT_Q_ROLE_SERVER) {
            YAWT_q_enqueue_frame_handshake_done(con);
          }

          YAWT_Q_EventParam_t param;
          memset(&param, 0, sizeof(param));
          _event_handler(con, YAWT_Q_EVT_CONNECTED, param);
        }
        break;
      }

      case YAWT_Q_FRAME_HANDSHAKE_DONE:
        YAWT_LOG(YAWT_LOG_INFO, "HANDSHAKE_DONE received");
        break;

      case YAWT_Q_FRAME_CONNECTION_CLOSE: {
        YAWT_LOG(YAWT_LOG_INFO, "CONNECTION_CLOSE: error=%lu, frame_type=%lu, reason=%.*s",
                 frame.connection_close.error_code, frame.connection_close.frame_type,
                 (int)frame.connection_close.reason_phrase_len,
                 frame.connection_close.reason_phrase);

        // Record the reason; EVT_CLOSE is emitted once by con_free. Enter the
        // closing state (RFC 9000 §10.2 draining) so _maint_kill reaps it —
        // do not emit here. reason_phrase points into the transient rx buffer;
        // _record_close copies it.
        _record_close(con, frame.connection_close.error_code,
                      (const char *)frame.connection_close.reason_phrase,
                      frame.connection_close.reason_phrase_len,
                      YAWT_Q_STATE_PEER_CLOSE_DRAINING);
        break;
      }

      case YAWT_Q_FRAME_CONNECTION_CLOSE_APP: {
        YAWT_LOG(YAWT_LOG_INFO, "CONNECTION_CLOSE (app): error=%lu",
                 frame.connection_close_app.error_code);

        _record_close(con, frame.connection_close_app.error_code,
                      (const char *)frame.connection_close_app.reason_phrase,
                      frame.connection_close_app.reason_phrase_len,
                      YAWT_Q_STATE_PEER_CLOSE_DRAINING);
        break;
      }

      case YAWT_Q_FRAME_STREAM: {
        YAWT_Q_StreamMeta_t *meta = _stream_meta_find(con->stream_meta, frame.stream.stream_id);
        if (!meta) {
          meta = _stream_meta_add(con, frame.stream.stream_id);
          YAWT_LOG(YAWT_LOG_INFO, "RX: Stream %lu: new stream metadata allocated", frame.stream.stream_id);
          if (!meta) {
            YAWT_LOG(YAWT_LOG_ERROR, "RX: Failed to allocate stream metadata for stream %lu", frame.stream.stream_id);
            break;
          }
        }
        uint64_t end = frame.stream.offset + frame.stream.data_len;

        // RFC 9000 §4.5: Validate data against known final size
        YAWT_Err_t fs_err = _check_final_size(meta, frame.stream.offset, frame.stream.data_len, frame.stream.fin);
        if (fs_err == YAWT_Q_ERR_FINAL_SIZE_ERROR) {
          _send_connection_close(con, YAWT_Q_ERR_FINAL_SIZE_ERROR, YAWT_Q_FRAME_STREAM);
          _record_close(con, YAWT_Q_ERR_FINAL_SIZE_ERROR, "final size error",
                        sizeof("final size error") - 1,
                        YAWT_Q_STATE_SELF_CLOSE_CLOSING);
          break;
        }

        // RFC 9000 §4.5: ignore data after stream RX is finalized (FIN/RESET_STREAM/STOP_SENDING).
        if (!_stream_should_rx(meta)) {
          if (end > meta->rx_next_offset) {
            YAWT_LOG(YAWT_LOG_WARN, "Stream %lu: ignoring %lu bytes at offset %lu after RX finalized (rx_next_offset=%lu)",
                     meta->stream_id, frame.stream.data_len, frame.stream.offset, meta->rx_next_offset);
          }
          break;
        }

        // Skip fully duplicate data
        if (end <= meta->rx_next_offset) break;
        //count all bytes towards FC regardless of order, per RFC 9000 §4.5
        con->stats.rx_count_bytes += frame.stream.data_len;
        meta->stats.rx_count_bytes += frame.stream.data_len;
        _preemptive_fc_stream_rx_limit_check(con, meta);
        _preemptive_fc_conn_rx_limit_check(con);

        // RFC 9000 §4.1: Hard enforcement - peer MUST NOT exceed advertised limits
        if (meta->stats.rx_count_bytes > meta->fc.rx_max_data) {
          YAWT_LOG(YAWT_LOG_ERROR, "FLOW_CONTROL_ERROR: stream %lu exceeded limit (%lu > %lu)",
                   meta->stream_id, meta->stats.rx_count_bytes, meta->fc.rx_max_data);
          _send_connection_close(con, YAWT_Q_ERR_FLOW_CONTROL_ERROR, YAWT_Q_FRAME_STREAM);
          _record_close(con, YAWT_Q_ERR_FLOW_CONTROL_ERROR, "stream flow control violation",
                        sizeof("stream flow control violation") - 1,
                        YAWT_Q_STATE_SELF_CLOSE_CLOSING);
          break;
        }

        if (con->stats.rx_count_bytes > con->local_fc.max_data) {
          YAWT_LOG(YAWT_LOG_ERROR, "FLOW_CONTROL_ERROR: connection exceeded limit (%lu > %lu)",
                   con->stats.rx_count_bytes, con->local_fc.max_data);
          _send_connection_close(con, YAWT_Q_ERR_FLOW_CONTROL_ERROR, YAWT_Q_FRAME_STREAM);
          _record_close(con, YAWT_Q_ERR_FLOW_CONTROL_ERROR, "connection flow control violation",
                        sizeof("connection flow control violation") - 1,
                        YAWT_Q_STATE_SELF_CLOSE_CLOSING);
          break;
        }

        if (frame.stream.offset == meta->rx_next_offset) {
          // RFC 9000 §2.2: in-order fast path — deliver directly from frame data (zero-copy into UDP buffer).
          YAWT_LOG(YAWT_LOG_DEBUG, "Stream %lu: delivered %lu bytes at offset %lu",
                    meta->stream_id, frame.stream.data_len, frame.stream.offset);
          meta->rx_next_offset = end;
          if (frame.stream.fin) {
            meta->state |= YAWT_Q_STREAM_FIN_RECEIVED;
            YAWT_LOG(YAWT_LOG_INFO, "Stream %lu: RX finalized (FIN received at offset %lu)",
                     meta->stream_id, end);
          }

          YAWT_Q_EventParam_t param;
          param.P_EVT_STREAM.frame = &frame.stream;
          _event_handler(con, YAWT_Q_EVT_STREAM, param);

          YAWT_Err_t drain_err = _drain_stream_rx(con, meta);
          if (drain_err == YAWT_Q_ERR_FINAL_SIZE_ERROR) {
            _send_connection_close(con, YAWT_Q_ERR_FINAL_SIZE_ERROR, YAWT_Q_FRAME_STREAM);
            _record_close(con, YAWT_Q_ERR_FINAL_SIZE_ERROR, "final size error in buffered data",
                          sizeof("final size error in buffered data") - 1,
                          YAWT_Q_STATE_SELF_CLOSE_CLOSING);
          }

        } else {
          // RFC 9000 §21.7: stream fragmentation attack mitigation.
          // We already ACKed these packets, so we cannot simply drop frames — the peer
          // will not retransmit. Terminate the connection when the reorder buffer exceeds
          // the configured cap. Legitimate QUIC implementations deliver in-order, so
          // hitting this limit indicates a misbehaving or malicious peer.
          uint64_t cap = YAWT_q_security_get()->max_stream_rx_buffer_bytes;
          if (cap > 0 && ANB_slab_size(con->stream_rx) + frame.stream.data_len > cap) {
            YAWT_LOG(YAWT_LOG_ERROR, "Stream %lu: RX reorder buffer exceeded (%zu + %lu > %lu), closing connection",
                     meta->stream_id, ANB_slab_size(con->stream_rx), frame.stream.data_len, cap);
            _send_connection_close(con, YAWT_Q_ERR_PROTOCOL_VIOLATION, YAWT_Q_FRAME_STREAM);
            _record_close(con, YAWT_Q_ERR_PROTOCOL_VIOLATION, "stream rx reorder buffer exceeded",
                          sizeof("stream rx reorder buffer exceeded") - 1,
                          YAWT_Q_STATE_SELF_CLOSE_CLOSING);
            res.err = YAWT_Q_ERR_INVALID_PACKET;
            return res;
          }

          // RFC 9000 §2.2: out-of-order data must be buffered to fulfill the ordered
          // byte stream contract. Copy into slab for later reassembly by _drain_stream_rx().
          YAWT_LOG(YAWT_LOG_INFO, "Stream %lu: buffering %lu bytes at offset %lu (expected %lu)",
                    meta->stream_id, frame.stream.data_len, frame.stream.offset, meta->rx_next_offset);

          uint8_t *slot = ANB_slab_alloc_item(con->stream_rx, sizeof(YAWT_Q_Frame_BufferedStream_t));
          if (slot) {
            YAWT_Q_Frame_BufferedStream_t *buf = (YAWT_Q_Frame_BufferedStream_t *)slot;

            buf->frame = frame.stream;
            memcpy(buf->data, frame.stream.data, frame.stream.data_len);
          }
        }
        break;
      }

      case YAWT_Q_FRAME_MAX_DATA:
        if (frame.max_data.max_data > con->peer_fc.max_data) {
          con->peer_fc.max_data = frame.max_data.max_data;
          con->data_blocked = false;
          YAWT_LOG(YAWT_LOG_INFO, "MAX_DATA updated to %lu", con->peer_fc.max_data);
        }
        break;
      case YAWT_Q_FRAME_MAX_STREAM_DATA: {
        YAWT_Q_StreamMeta_t *meta = _stream_meta_find(con->stream_meta, frame.max_stream_data.stream_id);
        if (meta && frame.max_stream_data.max_stream_data > meta->fc.tx_max_data) {
          meta->fc.tx_max_data = frame.max_stream_data.max_stream_data;
          meta->state &= ~YAWT_Q_STREAM_TX_BLOCKED_SENT;
          YAWT_LOG(YAWT_LOG_INFO, "MAX_STREAM_DATA stream %lu updated to %lu",
                    frame.max_stream_data.stream_id, meta->fc.tx_max_data);
        }
        break;
      }

      case YAWT_Q_FRAME_MAX_STREAMS_BIDI:
        if (frame.max_streams.max_streams > con->peer_fc.max_streams_bidi) {
          con->peer_fc.max_streams_bidi = frame.max_streams.max_streams;
          YAWT_LOG(YAWT_LOG_INFO, "MAX_STREAMS_BIDI updated to %lu", con->peer_fc.max_streams_bidi);
        }
        break;

      case YAWT_Q_FRAME_MAX_STREAMS_UNI:
        if (frame.max_streams.max_streams > con->peer_fc.max_streams_uni) {
          con->peer_fc.max_streams_uni = frame.max_streams.max_streams;
          YAWT_LOG(YAWT_LOG_INFO, "MAX_STREAMS_UNI updated to %lu", con->peer_fc.max_streams_uni);
        }
        break;

      case YAWT_Q_FRAME_NEW_CONNECTION_ID:
        // TODO connection migration: implement CID pool for migration support
        YAWT_LOG(YAWT_LOG_WARN, "NEW_CONNECTION_ID received but migration not supported");
        if (frame.new_connection_id.seq_num > con->stats.cid_seq_num) {
          con->stats.cid_seq_num = frame.new_connection_id.seq_num;
        }
        break;

      case YAWT_Q_FRAME_PATH_CHALLENGE:
        YAWT_LOG(YAWT_LOG_INFO, "PATH_CHALLENGE received, echoing PATH_RESPONSE");
        YAWT_q_enqueue_frame_path_response(con, frame.path_challenge.data);
        break;

      case YAWT_Q_FRAME_PATH_RESPONSE:
        YAWT_LOG(YAWT_LOG_INFO, "PATH_RESPONSE received (ignored — no pending challenge)");
        break;

      case YAWT_Q_FRAME_DATAGRAM: {
        YAWT_LOG(YAWT_LOG_DEBUG, "DATAGRAM received, len=%lu", frame.datagram.len);
        YAWT_Q_EventParam_t param;
        param.P_EVT_DATAGRAM.data = frame.datagram.dataptr;
        param.P_EVT_DATAGRAM.len = frame.datagram.len;
        _event_handler(con, YAWT_Q_EVT_DATAGRAM, param);
        break;
      }

      case YAWT_Q_FRAME_RESET_STREAM: {
        YAWT_LOG(YAWT_LOG_INFO, "RESET_STREAM received: stream=%lu, error=%lu, final_size=%lu",
                 frame.reset_stream.stream_id, frame.reset_stream.app_error_code,
                 frame.reset_stream.final_size);
        YAWT_Q_StreamMeta_t *meta = _stream_meta_find(con->stream_meta, frame.reset_stream.stream_id);
        if (meta) {
          if (!_stream_should_rx(meta)) {
            // RFC 9000 §4.5: already finalized, ignore duplicate RESET_STREAM
            YAWT_LOG(YAWT_LOG_INFO, "Stream %lu: ignoring duplicate RESET_STREAM (RX already finalized)",
                     meta->stream_id);
            break;
          }
          // TODO: RFC 9000 §4.5 — validate frame.reset_stream.final_size against meta->rx_final_size
          // if FIN_RECEIVED is set. If they differ, close with FINAL_SIZE_ERROR.
          // Deferred: RESET_STREAM handling needs more work (flow control accounting, etc.)
          meta->state |= YAWT_Q_STREAM_RESET_RECEIVED;
          YAWT_LOG(YAWT_LOG_INFO, "Stream %lu: RX finalized (RESET_STREAM received)",
                   meta->stream_id);
        }
        YAWT_Q_EventParam_t param;
        param.P_EVT_STREAM_RESET.stream_id = frame.reset_stream.stream_id;
        param.P_EVT_STREAM_RESET.app_error_code = frame.reset_stream.app_error_code;
        param.P_EVT_STREAM_RESET.final_size = frame.reset_stream.final_size;
        _event_handler(con, YAWT_Q_EVT_STREAM_RESET, param);
        break;
      }

      case YAWT_Q_FRAME_STOP_SENDING: {
        YAWT_LOG(YAWT_LOG_INFO, "STOP_SENDING received: stream=%lu, error=%lu",
                 frame.stop_sending.stream_id, frame.stop_sending.app_error_code);
        YAWT_Q_EventParam_t param;
        param.P_EVT_STREAM_STOP_SENDING.stream_id = frame.stop_sending.stream_id;
        param.P_EVT_STREAM_STOP_SENDING.app_error_code = frame.stop_sending.app_error_code;
        _event_handler(con, YAWT_Q_EVT_STREAM_STOP_SENDING, param);
        YAWT_q_con_reset_stream(con, frame.stop_sending.stream_id, 0);
        break;
      }

      case YAWT_Q_FRAME_DATA_BLOCKED:
        YAWT_LOG(YAWT_LOG_INFO, "DATA_BLOCKED received: max_data=%lu",
                 frame.data_blocked.max_data);
        {
          // Peer is blocked on our advertised limit. We shouldn't normally hit this
          // because we proactively update limits at threshold, but if we do, try
          // to auto-adjust to unblock the peer.
          YAWT_Q_FlowControlInfo_t info = {
            .type = YAWT_Q_FC_CONN_TX,
            .stream_id = 0,
            .current_limit = frame.data_blocked.max_data,
            .consumed = con->stats.tx_count_bytes
          };
          YAWT_Q_EventParam_t param;
          param.P_EVT_FLOW_CONTROL.info = &info;
          _event_handler(con, YAWT_Q_EVT_FLOW_CONTROL, param);

          _fc_auto_adjust_conn_rx(con, frame.data_blocked.max_data);
        }
        break;

      case YAWT_Q_FRAME_STREAM_DATA_BLOCKED: {
        uint8_t stype = frame.stream_data_blocked.stream_id & 0x03;
        int is_uni = (stype & 0x02) != 0;
        int peer_initiated = ((stype & 0x01) != 0) != (con->role == YAWT_Q_ROLE_SERVER);
        if (is_uni && !peer_initiated) {
          YAWT_LOG(YAWT_LOG_ERROR, "STREAM_DATA_BLOCKED on send-only stream %lu",
                   frame.stream_data_blocked.stream_id);
          _send_connection_close(con, YAWT_Q_ERR_STREAM_STATE_ERROR, YAWT_Q_FRAME_STREAM_DATA_BLOCKED);
          _record_close(con, YAWT_Q_ERR_STREAM_STATE_ERROR, "stream data blocked on send-only stream",
                        sizeof("stream data blocked on send-only stream") - 1,
                        YAWT_Q_STATE_SELF_CLOSE_CLOSING);
          break;
        }
        YAWT_LOG(YAWT_LOG_INFO, "STREAM_DATA_BLOCKED received: stream=%lu, max_stream_data=%lu",
                 frame.stream_data_blocked.stream_id, frame.stream_data_blocked.max_stream_data);
        YAWT_Q_StreamMeta_t *meta = _stream_meta_find(con->stream_meta, frame.stream_data_blocked.stream_id);
        uint64_t consumed = meta ? meta->stats.tx_count_bytes : 0;
        YAWT_Q_FlowControlInfo_t info = {
          .type = YAWT_Q_FC_STREAM_TX,
          .stream_id = frame.stream_data_blocked.stream_id,
          .current_limit = frame.stream_data_blocked.max_stream_data,
          .consumed = consumed
        };
        YAWT_Q_EventParam_t param;
        param.P_EVT_FLOW_CONTROL.info = &info;
        _event_handler(con, YAWT_Q_EVT_FLOW_CONTROL, param);

        // Peer is blocked on our advertised limit. We shouldn't normally hit this
        // because we proactively update limits at threshold, but if we do, try
        // to auto-adjust to unblock the peer.
        _fc_auto_adjust_stream_rx(con, frame.stream_data_blocked.stream_id, frame.stream_data_blocked.max_stream_data);
        break;
      }

      default:
        YAWT_LOG(YAWT_LOG_WARN, "Unhandled frame type: 0x%02lx", (uint64_t)frame.type);
        break;
    }
  }

  if (frc.err != YAWT_Q_OK) {
    YAWT_LOG(YAWT_LOG_ERROR, "Frame parse error: %s (%d)", YAWT_err_str(frc.err), frc.err);
    res.err = frc.err;
  }
  // RFC 9000 §12.4: packets with no frames are a protocol violation
  if (frame_count == 0 && res.err == YAWT_Q_OK) {
    YAWT_LOG(YAWT_LOG_WARN, "PROTOCOL_VIOLATION: empty packet (no frames)");
    res.err = YAWT_Q_ERR_INVALID_PACKET;
  }
  return res;
}

// Screaming into the void, padding frames belong in packets
// but some implementations set the len of initial frames to shorter
// than the UDP payload, and pad outside the packet
// I think they are not following spec so I am adding this for compatibility
static bool _rx_skip_padding(YAWT_Q_ReadCursor_t *rc) {
  bool has_padding = false;
  size_t prev = rc->cursor;
  //no valid packet starts with byte 0x00
  while (rc->cursor < rc->len && rc->data[rc->cursor] == 0x00) {
    rc->cursor++;
  }
  if (rc->cursor > prev) {
    has_padding = true;
    YAWT_LOG(YAWT_LOG_DEBUG, "Skipped %zu bytes of padding before packet start", rc->cursor - prev);
  }
  return has_padding;
}

void YAWT_q_con_rx(uint8_t *data, size_t len, YAWT_Q_Crypto_Cred_t *cred,
                              const YAWT_Q_PeerAddr_t *peer_addr, double now) {
  YAWT_Q_ReadCursor_t rc = { .data = data, .len = len, .cursor = 0, .err = YAWT_Q_OK };
  YAWT_LOG(YAWT_LOG_DEBUG, "Received datagram, processing");
  while (rc.cursor < rc.len && rc.err == YAWT_Q_OK) {
    YAWT_LOG(YAWT_LOG_DEBUG, "Cursor at %zu of %zu bytes pre pkt parse", rc.cursor, rc.len); 
    size_t prev = rc.cursor;

    if (_rx_skip_padding(&rc)) continue;

    YAWT_Q_Packet_t pkt;
    YAWT_q_parse_packet(&rc, &pkt);
    if (rc.err != YAWT_Q_OK || rc.cursor == prev) break;
    YAWT_LOG(YAWT_LOG_DEBUG, "Cursor at %zu of %zu bytes post pkt parse", rc.cursor, rc.len);

    // RFC 9000 §10.3: discard packets smaller than 21 bytes
    size_t pkt_len = rc.cursor - prev;
    if (pkt_len < 21) {
      YAWT_LOG(YAWT_LOG_WARN, "discarding packet < 21 bytes (%zu)", pkt_len);
      continue;
    }

    // RFC 9000 §14.1: server must discard Initial packets in datagrams < 1200 bytes
    if (pkt.type == YAWT_Q_PKT_TYPE_INITIAL && prev == 0 && len < 1200) {
      YAWT_LOG(YAWT_LOG_WARN, "discarding Initial in datagram < 1200 bytes (%zu)", len);
      break;
    }
    YAWT_LOG(YAWT_LOG_DEBUG, "packet %s (consumed %zu bytes)", _pkt_type_name(pkt.type), rc.cursor - prev);

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

    if (con->role == YAWT_Q_ROLE_CLIENT && pkt.type == YAWT_Q_PKT_TYPE_INITIAL
        && con->peer_cid.len > 0 && pkt.src_cid.len > 0
        && memcmp(con->peer_cid.id, pkt.src_cid.id, pkt.src_cid.len) != 0) {
      YAWT_q_cid_set(&con->peer_cid, pkt.src_cid.id, pkt.src_cid.len);
      YAWT_LOG(YAWT_LOG_INFO, "Client: updated peer CID to server SCID=%s",
                YAWT_q_cid_to_hex(&con->peer_cid));
    }

    // RFC 9000 §10.2: handle closing/draining states
    if (con->state & YAWT_Q_STATE_PEER_CLOSE_DRAINING) {
      YAWT_LOG(YAWT_LOG_INFO, "draining: dropping packet");
      continue;
    }
    if (con->state & YAWT_Q_STATE_SELF_CLOSE_CLOSING) {
      con->closing_rx_count++;
      // RFC 9000 §10.2.1: exponential backoff on closing-state responses.
      // Respond at packet counts that are powers of 2 (1, 2, 4, 8, 16, ...).
      if ((con->closing_rx_count & (con->closing_rx_count - 1)) != 0) {
        YAWT_LOG(YAWT_LOG_INFO, "closing: rate-limited, dropping packet");
        continue;
      }
      YAWT_LOG(YAWT_LOG_INFO, "closing: responding with CONNECTION_CLOSE");
      _send_connection_close(con, con->close_code, 0);
      _drain_tx(con, now);
      continue;
    }

    YAWT_Q_Encryption_Level_t level = YAWT_q_pkt_type_to_level(pkt.type);
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

    if (!pkt.reserved_zero) {
      YAWT_LOG(YAWT_LOG_WARN, "PROTOCOL_VIOLATION: non-zero reserved bits after unprotection");
      YAWT_q_con_close(con, YAWT_Q_ERR_PROTOCOL_VIOLATION);
      continue;
    }

    con->stats.last_rx = now;
    if (!(con->state & YAWT_Q_STATE_ADDR_VALIDATED)) {
      con->stats.rx_count_bytes += pkt.payload_len;
    }

    // Reconstruct full packet number from truncated value
    uint64_t largest_pn = con->stats.next_pkt_num_rx[level] > 0 ? con->stats.next_pkt_num_rx[level] - 1 : 0;
    uint64_t full_pn = _reconstruct_pn(largest_pn, pkt.packet_num, pkt.packet_number_length);
    pkt.packet_num = full_pn;
     

    // TODO reconsider this logic, quic frames are imdepotent by mandate
    // Not reprocessing old PNs is for extra security
    // It may be worth keeping a small buffer or bitmap of recent PNs allowing better efficiency for
    // packets arriving out of order - no need for remote side to resent
    // WARNING this would impact quic STREAM buffering that occurs as streams are delivered in order to the app layer
    // This can have implications for ACK too - we send largest frame ACK, see 13.2.3
    // Unsure what would happen if we allow for PNs out of order and acknowledge a higher PN yet a lower PN has not been
    // processd - the code currently mandates PNs are in order, if a PN is higher than expected it won't be processed
    // until lower PN received
    //
    // RFC 9000 §12.3: "A receiver MUST discard a newly unprotected packet unless it is
    // certain that it has not processed another packet with the same packet number."
    // We only track the high-water mark, so any full_pn < the next expected PN is
    // discarded.  Because we skip frame processing and ACK enqueuing below, the
    // sender's loss detector will not receive an ACK and will retransmit any
    // ack-eliciting frames (e.g. reliable stream data) in a new packet.
    if (full_pn < con->stats.next_pkt_num_rx[level]) {
      YAWT_LOG(YAWT_LOG_INFO, "discarding duplicate/old PN %lu < %lu at level %d",
               full_pn, con->stats.next_pkt_num_rx[level], level);
      continue;
    }
    
    con->stats.next_pkt_num_rx[level] = full_pn + 1;


   YAWT_LOG(YAWT_LOG_DEBUG, "pkt type: %u rx pkt payload: %s",pkt.type,
    YAWT_q_blob_to_hex(pkt.payload, pkt.payload_len));

    // Parse frames from decrypted payload
    YAWT_Q_FrameHandler_Res_t res = _handle_frames(con, &pkt);

    // RFC 9000 §12.4: PROTOCOL_VIOLATION for invalid frames or empty packets
    if (res.err != YAWT_Q_OK) {
      YAWT_q_con_close(con, YAWT_Q_ERR_PROTOCOL_VIOLATION);
      continue;
    }

    // RFC 9000 §13.2: only ACK packets containing ack-eliciting frames
    if (res.requires_ack) {
      YAWT_q_enqueue_frame_ack(con, level, pkt.packet_num);
    }

    // Flush queued frames immediately (handshake replies, ACKs, etc.)
    _drain_tx(con, now);
  }
  if (rc.err != YAWT_Q_OK) {
    YAWT_LOG(YAWT_LOG_ERROR, "Packet parse error: %s (%d) at cursor %zu",
             YAWT_err_str(rc.err), rc.err, rc.cursor);
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
static uint64_t _next_pn(YAWT_Q_Connection_t *con, uint8_t level) {
  return con->stats.next_pkt_num_tx[level]++;
}

static void _drain_tx(YAWT_Q_Connection_t *con, double now) {
  if (ANB_slab_item_count(con->tx_buffer) == 0) return;

  // RFC 9000 §8.1: anti-amplification — server MUST NOT send more than 3x bytes
  // received before address validation. Clients are not subject to this limit.
  if (con->role == YAWT_Q_ROLE_SERVER && !(con->state & YAWT_Q_STATE_ADDR_VALIDATED)) {
    if (con->stats.tx_count_bytes >= 3 * con->stats.rx_count_bytes) {
      YAWT_LOG(YAWT_LOG_INFO, "anti-amplification limit reached: tx=%lu, rx=%lu, limit=%lu",
               con->stats.tx_count_bytes, con->stats.rx_count_bytes, 3 * con->stats.rx_count_bytes);
      return;
    }
  }

  for (int lvl = 0; lvl < 4; lvl++) {
    size_t max_payload = (lvl <= YAWT_Q_LEVEL_HANDSHAKE)
        ? YAWT_Q_MAX_FRAME_PAYLOAD_LONG
        : YAWT_Q_MAX_FRAME_PAYLOAD_SHORT;
    uint8_t payload[YAWT_Q_MAX_PKT_SIZE];
    size_t payload_len = 0;
    int found = 0;

    ANB_SlabIter_t iter = {0};
    size_t item_size;
    uint8_t *item;

    while ((item = ANB_slab_peek_item_iter(con->tx_buffer, &iter, &item_size)) != NULL) {
      if (item_size != sizeof(YAWT_Q_WireFrame_t))  { //defensive check, should never happen
        YAWT_LOG(YAWT_LOG_ERROR, "invalid item in tx_buffer: size %zu (expected %zu), skipping",
                 item_size, sizeof(YAWT_Q_WireFrame_t));
        abort();
      }
      YAWT_Q_WireFrame_t *f = (YAWT_Q_WireFrame_t *)item;

      //see process_ack - this removes frames from tx_buffer
      if (f->level != lvl || f->last_sent != 0) continue; 

      // RFC 9000 §4.1: flow control — hold STREAM frames until within limits.
      // Bytes are counted optimistically at enqueue time (in send_stream);
      // frames stay buffered here until MAX_DATA / MAX_STREAM_DATA raises limits
      if (f->type == YAWT_Q_FRAME_STREAM) {
        if (con->stats.tx_count_bytes > con->peer_fc.max_data) {
          if (!con->data_blocked) {
            con->data_blocked = true;
            YAWT_q_enqueue_frame_data_blocked(con, con->peer_fc.max_data);
          }
          continue;
        }
        YAWT_Q_StreamMeta_t *meta = _stream_meta_find(con->stream_meta, f->stream_id);
        if (meta && meta->stats.tx_count_bytes >= meta->fc.tx_max_data) {
          if (_stream_state_allows_tx(meta) && !(meta->state & YAWT_Q_STREAM_TX_BLOCKED_SENT)) {
            meta->state |= YAWT_Q_STREAM_TX_BLOCKED_SENT;
            YAWT_q_enqueue_frame_stream_data_blocked(con, f->stream_id, meta->fc.tx_max_data);
          }
          continue;
        }
      }

      if (payload_len + f->wire_len > max_payload) break;

      memcpy(payload + payload_len, f->wire_data, f->wire_len);
      payload_len += f->wire_len;
      found = 1;
    }

    if (!found) continue;

    if (!YAWT_q_crypto_key_level_available(con->crypto, lvl)) {
      printf("  no write keys for level %d, skipping send\n", lvl);
      continue;
    }

    // RFC 9000 §12.3: If sending packet number reaches 2^62-1, sender MUST close
    // connection without CONNECTION_CLOSE or further packets.
    if (con->stats.next_pkt_num_tx[lvl] >= (1ULL << 62)) {
      YAWT_LOG(YAWT_LOG_ERROR, "packet number overflow: level %d reached 2^62-1, closing connection", lvl);
      _record_close(con, YAWT_Q_ERR_AEAD_LIMIT_REACHED, "packet number space exhausted",
                    sizeof("packet number space exhausted") - 1,
                    YAWT_Q_STATE_SELF_CLOSE_CLOSING);
      return;
    }

    YAWT_Q_Packet_Type_t pkt_type = _level_to_pkt_type(lvl);
    uint64_t pn = _next_pn(con, lvl);

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
    YAWT_Q_EventParam_t param;
    param.P_EVT_TX.buf = wire_data;
    param.P_EVT_TX.len = send_size;
    param.P_EVT_TX.peer = &con->peer_addr;
    _event_handler(con, YAWT_Q_EVT_TX, param);
    con->stats.last_tx = now;
    if (!(con->state & YAWT_Q_STATE_ADDR_VALIDATED)) {
      con->stats.tx_count_bytes += send_size;
    }

    // Mark frames as sent. ACK frames are one-shot — RFC 9000 §13.2.1 says ACK
    // info is regenerated from current rx state, never retransmitted — so pop
    // them now instead of leaving them to the retransmit timer.
    ANB_SlabIter_t iter2 = {0};
    while ((item = ANB_slab_peek_item_iter(con->tx_buffer, &iter2, &item_size)) != NULL) {
      if (item_size < sizeof(YAWT_Q_WireFrame_t)) continue;
      YAWT_Q_WireFrame_t *f = (YAWT_Q_WireFrame_t *)item;
      if (f->level == lvl && f->last_sent == 0) {
        f->last_sent = now;
        f->packet_num = pn;
        if (f->type == YAWT_Q_FRAME_ACK) {
          ANB_slab_pop_item(con->tx_buffer, &iter2);
        }
      }
    }
  }
}


// STREAM frame overhead: 1 type + 8 stream_id + 8 offset + 8 length = 25 bytes max
#define YAWT_Q_STREAM_FRAME_OVERHEAD 25
#define YAWT_Q_STREAM_CHUNK_MAX (YAWT_Q_MAX_FRAME_PAYLOAD_SHORT - YAWT_Q_STREAM_FRAME_OVERHEAD) // 1284

YAWT_Err_t YAWT_q_con_send_stream(YAWT_Q_Connection_t *con, uint64_t stream_id,
                                       const YAWT_Q_IoVec_t *iov, int iov_count, int fin) {
  if (!con) return YAWT_Q_ERR_INVALID_PARAM;
  if (iov_count < 0) return YAWT_Q_ERR_INVALID_PARAM;
  if (iov_count > 0 && !iov) return YAWT_Q_ERR_INVALID_PARAM;

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
      return YAWT_Q_ERR_INVALID_PARAM;
    }
    meta = _stream_meta_add(con, stream_id);
    YAWT_LOG(YAWT_LOG_INFO, "TX: Stream %lu: new stream metadata allocated", stream_id);
    if (!meta) {
      YAWT_LOG(YAWT_LOG_ERROR, "TX: Failed to allocate stream metadata for stream %lu", stream_id);
      return YAWT_Q_ERR_ALLOC;
    }

  }
  if (!_stream_state_allows_tx(meta)) return YAWT_Q_ERR_INVALID_PARAM;

  size_t total_len = 0;
  for (int i = 0; i < iov_count; i++) {
    if (iov[i].len > 0 && !iov[i].buf) return YAWT_Q_ERR_INVALID_PARAM;
    total_len += iov[i].len;
  }

  size_t iov_pos = 0;
  while (iov_pos < total_len || (total_len == 0 && fin)) {
    YAWT_Q_Frame_BufferedStream_t sf = {0};
    size_t new_iov_pos = 0;
    YAWT_Err_t err = YAWT_q_encode_frame_stream(iov, iov_count, iov_pos,
                                                       YAWT_Q_STREAM_CHUNK_MAX,
                                                       stream_id, meta->tx_next_offset,
                                                       fin, &sf, &new_iov_pos);
    if (err != YAWT_Q_OK) return err;

    err = YAWT_q_enqueue_frame_stream(con, &sf);
    if (err != YAWT_Q_OK) return err;

    size_t chunk = new_iov_pos - iov_pos;
    meta->tx_next_offset += chunk;
    con->stats.tx_count_bytes += chunk;
    meta->stats.tx_count_bytes += chunk;
    _preemptive_fc_stream_tx_limit_check(con, meta);
    _preemptive_fc_conn_tx_limit_check(con);
    iov_pos = new_iov_pos;

    if (total_len == 0 && fin) break;
  }

  if (fin) meta->state |= YAWT_Q_STREAM_FIN_SENT;
  return YAWT_Q_OK;
}

static void _reset_stream_unbuffer(YAWT_Q_Connection_t *con, uint64_t stream_id) {
  ANB_SlabIter_t iter = {0};
  size_t item_size;
  uint8_t *item;

  while ((item = ANB_slab_peek_item_iter(con->tx_buffer, &iter, &item_size)) != NULL) {
    if (item_size < sizeof(YAWT_Q_WireFrame_t)) continue;
    YAWT_Q_WireFrame_t *f = (YAWT_Q_WireFrame_t *)item;
    if (f->type == YAWT_Q_FRAME_STREAM && f->stream_id == stream_id) {
      ANB_slab_pop_item(con->tx_buffer, &iter);
    }
  }
}

YAWT_Err_t YAWT_q_con_reset_stream(YAWT_Q_Connection_t *con, uint64_t stream_id,
                                         uint64_t app_error_code) {
  if (!con) return YAWT_Q_ERR_INVALID_PARAM;

  YAWT_Q_StreamMeta_t *meta = _stream_meta_find(con->stream_meta, stream_id);
  if (!meta) return YAWT_Q_ERR_INVALID_PARAM;
  if (!_stream_state_allows_tx(meta)) return YAWT_Q_ERR_INVALID_PARAM;

  meta->state |= YAWT_Q_STREAM_RESET_SENT;
  YAWT_Err_t err = YAWT_q_enqueue_frame_reset_stream(con, stream_id, app_error_code, meta->tx_next_offset);
  if (err != YAWT_Q_OK) return err;

  _reset_stream_unbuffer(con, stream_id);
  return YAWT_Q_OK;
}

YAWT_Err_t YAWT_q_con_stop_sending(YAWT_Q_Connection_t *con, uint64_t stream_id,
                                          uint64_t app_error_code) {
  if (!con) return YAWT_Q_ERR_INVALID_PARAM;

  YAWT_Q_StreamMeta_t *meta = _stream_meta_find(con->stream_meta, stream_id);
  if (!meta) return YAWT_Q_ERR_INVALID_PARAM;
  if (!_stream_should_rx(meta)) return YAWT_Q_ERR_INVALID_PARAM;

  meta->state |= YAWT_Q_STREAM_STOPPED_SENT;
  return YAWT_q_enqueue_frame_stop_sending(con, stream_id, app_error_code);
}

void YAWT_q_con_set_stream_rx_limit(YAWT_Q_Connection_t *con, uint64_t stream_id, uint64_t new_limit) {
  if (!con) return;
  YAWT_Q_StreamMeta_t *meta = _stream_meta_find(con->stream_meta, stream_id);
  if (!meta) return;
  if (new_limit > meta->fc.rx_max_data) {
    meta->fc.rx_max_data = new_limit;
    YAWT_q_enqueue_frame_max_stream_data(con, stream_id, new_limit);
  }
}

void YAWT_q_con_set_conn_rx_limit(YAWT_Q_Connection_t *con, uint64_t new_limit) {
  if (!con) return;
  if (new_limit > con->local_fc.max_data) {
    con->local_fc.max_data = new_limit;
    YAWT_q_enqueue_frame_max_data(con, new_limit);
  }
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
// Handles: closing state (stamp -> free after 3x PTO) and idle timeout.
static int _maint_kill(YAWT_Q_Connection_t **con, double idle_sec, double now) {
  double closing = (*con)->stats.closing_at;

  // Close initiated but timestamp not yet stamped — stamp it now
  if (_is_closing(*con) && closing == 0) {
    (*con)->stats.closing_at = now;
    return 0;
  }

  // Closing state: real timestamp — free after 3x PTO
  if (closing > 0) {
    double pto = _maint_cfg.retransmit_initial * 3.0;
    if (now - closing > pto) {
      YAWT_LOG(YAWT_LOG_INFO, "Closing period expired: CID=%s",
                YAWT_q_cid_to_hex(&(*con)->cid));
      // close_code/reason already recorded by whoever initiated the close
      // (con_close or peer CONNECTION_CLOSE); con_free emits EVT_CLOSE.
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
    _record_close(*con, YAWT_Q_OK, "idle timeout", sizeof("idle timeout") - 1, YAWT_Q_STATE_SELF_CLOSE_CLOSING);
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
    YAWT_LOG(YAWT_LOG_INFO, "Keepalive PING: CID=%s", YAWT_q_cid_to_hex(&con->cid));
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
    if (f->last_sent == 0) continue; //only consider frames that have been sent at least once

   

   // RFC 9001 §4.9.2: After handshake completion, endpoints discard Handshake keys.
   // Any unacknowledged Handshake-level frames can never be ACKed, so purge them
   // to prevent infinite retransmit loops.
    if (f->level == YAWT_Q_LEVEL_HANDSHAKE && (con->state & YAWT_Q_STATE_ADDR_VALIDATED) != 0)
    {
      ANB_slab_pop_item(con->tx_buffer, &iter);
      YAWT_LOG(YAWT_LOG_INFO, "Dropping handshake frame after address validation: level=%d, type=0x%02x",
                f->level, f->type);
      continue;
    }

    if (f->retransmit_count >= _maint_cfg.retransmit_max) {
      // TODO: give up — close connection
      continue;
    }

    double timeout = _maint_cfg.retransmit_initial;
    for (uint32_t i = 0; i < f->retransmit_count; i++) {
      timeout *= _maint_cfg.retransmit_backoff;
    }

    if (now - f->last_sent > timeout) {
      YAWT_LOG(YAWT_LOG_INFO, "Retransmit: level=%d, type=0x%02x, attempt=%u, timeout=%.3fs",
                f->level, f->type, f->retransmit_count + 1, timeout);
      f->last_sent = 0;
      f->retransmit_count++;
    }
  }
}


void YAWT_q_con_maintain(double now) {
  YAWT_Q_Connection_t *con, *tmp;
  HASH_ITER(hh_cid, _hash_cid, con, tmp) {
    double idle_sec = _effective_idle_timeout(con);
    if (_maint_kill(&con, idle_sec, now)) continue;
    if (con->state & YAWT_Q_STATE_PEER_CLOSE_DRAINING) continue;
    _maint_ping(con, idle_sec, now);
    _maint_retransmit(con, now);

    _drain_tx(con, now);
  }
}
