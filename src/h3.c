#include "h3.h"
#include "quic.h"   // YAWT_q_varint_* + YAWT_Q_ReadCursor_t — H3 reuses the QUIC varint codec
#include "quic_connection.h"  // YAWT_Q_Connection_t, user_data, event types
#include "security.h"
#include "logger.h"
#include <allocnbuffer/slab.h>
#include <string.h>
#include <stdlib.h>

// Decode a varint from the H3 cursor by delegating to the QUIC codec (the two
// cursor layouts are identical aside from the error type). Returns 1 on
// success; 0 on truncation, in which case the cursor is left UNCHANGED
// (YAWT_q_varint_decode does not advance on SHORT_BUFFER) so the caller can
// retry the whole frame once more bytes arrive.
static int _h3_varint(YAWT_H3_ReadCursor_t *rc, uint64_t *out) {
  YAWT_Q_ReadCursor_t qc = {
    .data = (uint8_t *)rc->data,  // const cast: decode only reads
    .len = rc->len,
    .cursor = rc->cursor,
    .err = YAWT_Q_OK,
  };
  YAWT_q_varint_decode(&qc, out);
  if (qc.err != YAWT_Q_OK) return 0;
  rc->cursor = qc.cursor;
  return 1;
}

YAWT_H3_Error_t YAWT_h3_parse_frame(YAWT_H3_ReadCursor_t *rc,
                                     YAWT_H3_Frame_t *out) {
  memset(out, 0, sizeof(*out));
  if (!rc) return YAWT_H3_ERR_INVALID_PARAM;

  // Anything short of a complete Type + Length + full payload is INCOMPLETE.
  // Restore the cursor to the frame start on any shortfall so a later call
  // (with more stream bytes appended) re-parses from the same point.
  size_t start = rc->cursor;
  uint64_t type, len;

  if (!_h3_varint(rc, &type)) { rc->cursor = start; return YAWT_H3_ERR_INCOMPLETE; }
  if (!_h3_varint(rc, &len))  { rc->cursor = start; return YAWT_H3_ERR_INCOMPLETE; }

  if (len > rc->len - rc->cursor) { rc->cursor = start; return YAWT_H3_ERR_INCOMPLETE; }

  out->type = type;
  out->len = len;
  out->payload = (len > 0) ? rc->data + rc->cursor : NULL;
  rc->cursor += len;
  return YAWT_H3_OK;
}

YAWT_H3_Error_t YAWT_h3_encode_frame(uint64_t type,
                                      const uint8_t *payload, size_t payload_len,
                                      uint8_t *buf, size_t len, size_t *written) {
  if (!buf || !written || (payload_len > 0 && !payload)) {
    return YAWT_H3_ERR_INVALID_PARAM;
  }

  size_t off = 0;
  int n;

  if (YAWT_q_varint_encode(type, buf + off, len - off, &n) != YAWT_Q_OK) {
    return YAWT_H3_ERR_SHORT_BUFFER;
  }
  off += n;
  if (YAWT_q_varint_encode(payload_len, buf + off, len - off, &n) != YAWT_Q_OK) {
    return YAWT_H3_ERR_SHORT_BUFFER;
  }
  off += n;

  if (payload_len > len - off) return YAWT_H3_ERR_SHORT_BUFFER;
  if (payload_len > 0) {
    memcpy(buf + off, payload, payload_len);
    off += payload_len;
  }

  *written = off;
  return YAWT_H3_OK;
}

// ---------------------------------------------------------------------------
// H3 connection object — hung off the QUIC connection's user_data. Allocated on
// EVT_CONNECTED, freed on EVT_CLOSE (which con_free guarantees fires once).
// ---------------------------------------------------------------------------
typedef struct {
  YAWT_H3_Settings_t local_settings;
  YAWT_H3_Settings_t peer_settings;
  bool peer_settings_seen;
  ANB_Slab_t *rxbuf;                // stream_id-tagged buffered chunks
  size_t nstreams;                  // slot pool size (concurrent stream cap)
  YAWT_H3_StreamState_t *streams;   // preallocated slot pool, linear-scan by id
} YAWT_H3_Connection_t;

static YAWT_H3_Connection_t *_h3_conn_create(YAWT_Q_Connection_t *con) {
  YAWT_H3_Connection_t *h3 = calloc(1, sizeof(*h3));
  if (!h3) return NULL;

  // Settings we advertise: static-only QPACK + the WT-enabling trio.
  h3->local_settings.qpack_max_table_capacity = 0;
  h3->local_settings.qpack_blocked_streams = 0;
  h3->local_settings.enable_connect_protocol = 1;
  h3->local_settings.h3_datagram = 1;
  h3->local_settings.wt_enabled = 1;

  h3->rxbuf = ANB_slab_create(4096);
  h3->nstreams = con->local_fc.max_streams_bidi + con->local_fc.max_streams_uni;
  h3->streams = calloc(h3->nstreams, sizeof(*h3->streams));
  if (!h3->rxbuf || !h3->streams) {
    if (h3->rxbuf) ANB_slab_destroy(h3->rxbuf);
    free(h3->streams);
    free(h3);
    return NULL;
  }
  return h3;
}

static void _h3_conn_destroy(YAWT_H3_Connection_t *h3) {
  if (!h3) return;
  ANB_slab_destroy(h3->rxbuf);
  free(h3->streams);
  free(h3);
}

// Process-wide event handler for the H3 layer. The app installs this (directly,
// or by forwarding from its own handler) via YAWT_q_con_set_event_handler. TX is
// the app's concern (UDP write); H3 consumes the connection lifecycle + streams.
void YAWT_h3_on_event(YAWT_Q_Connection_t *con, YAWT_Q_EventType_t event,
                       YAWT_Q_EventParam_t param) {
  switch (event) {
    case YAWT_Q_EVT_CONNECTED: {
      YAWT_H3_Connection_t *h3 = _h3_conn_create(con);
      YAWT_q_con_set_user_data(con, h3);
      YAWT_LOG(YAWT_LOG_INFO, "h3: connection up, state allocated (%zu stream slots)",
               h3 ? h3->nstreams : 0);
      // TODO: open the server control stream and send our SETTINGS frame.
      break;
    }
    case YAWT_Q_EVT_STREAM: {
      YAWT_H3_Connection_t *h3 = YAWT_q_con_get_user_data(con);
      if (!h3) break;
      const YAWT_Q_Frame_Stream_t *f = param.P_EVT_STREAM.frame;
      // TODO: buffer the chunk in rxbuf (tagged by stream_id), then run the
      // per-stream feed/advance state machine (read type prefix, read frame
      // headers, deliver complete frames, renormalize the buffer).
      YAWT_LOG(YAWT_LOG_DEBUG, "h3: rx stream=%lu len=%lu fin=%d",
               f->stream_id, f->len, f->fin);
      break;
    }
    case YAWT_Q_EVT_CLOSE: {
      YAWT_H3_Connection_t *h3 = YAWT_q_con_get_user_data(con);
      if (h3) {
        _h3_conn_destroy(h3);
        YAWT_q_con_set_user_data(con, NULL);
      }
      break;
    }
    default:
      break;
  }
}

// ---------------------------------------------------------------------------
// TODO: SETTINGS codec — parked until the control-stream slice. Operates on a
// SETTINGS frame *body* (the payload that YAWT_h3_parse_frame delimits via the
// frame Length). decode loops to the cursor's len, which the frame layer will
// clamp to the payload boundary before calling. Preserved here so the work
// isn't lost; re-enable the declarations in h3.h when wiring it up.
// ---------------------------------------------------------------------------
#if 0
// Append one (identifier, value) varint pair. Error is sticky: a no-op if *err
// is already set; on failure sets *err and leaves *off unchanged. Lets the
// caller chain writes and check once at the end.
static void _put_setting(uint8_t *buf, size_t len, size_t *off,
                          uint64_t id, uint64_t value, YAWT_H3_Error_t *err) {
  if (*err != YAWT_H3_OK) return;

  int n;
  size_t pos = *off;
  if (YAWT_q_varint_encode(id, buf + pos, len - pos, &n) != YAWT_Q_OK) {
    *err = YAWT_H3_ERR_SHORT_BUFFER;
    return;
  }
  pos += n;
  if (YAWT_q_varint_encode(value, buf + pos, len - pos, &n) != YAWT_Q_OK) {
    *err = YAWT_H3_ERR_SHORT_BUFFER;
    return;
  }
  pos += n;
  *off = pos;
}

YAWT_H3_Error_t YAWT_h3_settings_encode(const YAWT_H3_Settings_t *s,
                                         uint8_t *buf, size_t len,
                                         size_t *written) {
  if (!s || !buf || !written) return YAWT_H3_ERR_INVALID_PARAM;

  size_t off = 0;
  YAWT_H3_Error_t err = YAWT_H3_OK;

  _put_setting(buf, len, &off, YAWT_H3_SETTING_QPACK_MAX_TABLE_CAPACITY,
               s->qpack_max_table_capacity, &err);
  _put_setting(buf, len, &off, YAWT_H3_SETTING_QPACK_BLOCKED_STREAMS,
               s->qpack_blocked_streams, &err);
  _put_setting(buf, len, &off, YAWT_H3_SETTING_ENABLE_CONNECT_PROTOCOL,
               s->enable_connect_protocol, &err);
  _put_setting(buf, len, &off, YAWT_H3_SETTING_H3_DATAGRAM,
               s->h3_datagram, &err);
  _put_setting(buf, len, &off, YAWT_H3_SETTING_WT_ENABLED,
               s->wt_enabled, &err);

  // 0 means "unlimited / unset" — omit rather than advertise a 0 cap.
  if (s->max_field_section_size != 0) {
    _put_setting(buf, len, &off, YAWT_H3_SETTING_MAX_FIELD_SECTION_SIZE,
                 s->max_field_section_size, &err);
  }

  if (err != YAWT_H3_OK) return err;
  *written = off;
  return YAWT_H3_OK;
}

YAWT_H3_Error_t YAWT_h3_settings_decode(YAWT_H3_ReadCursor_t *rc,
                                         YAWT_H3_Settings_t *out) {
  if (!rc || !out) return YAWT_H3_ERR_INVALID_PARAM;

  while (rc->cursor < rc->len) {
    uint64_t id, value;

    if (!_h3_varint(rc, &id)) return YAWT_H3_ERR_MALFORMED;
    // A valid SETTINGS body is whole (id, value) pairs — a dangling id is
    // malformed (RFC 9114 §7.2.4 treats a truncated frame as a frame error).
    if (!_h3_varint(rc, &value)) return YAWT_H3_ERR_MALFORMED;

    switch (id) {
      case YAWT_H3_SETTING_QPACK_MAX_TABLE_CAPACITY:
        out->qpack_max_table_capacity = value;
        break;
      case YAWT_H3_SETTING_QPACK_BLOCKED_STREAMS:
        out->qpack_blocked_streams = value;
        break;
      case YAWT_H3_SETTING_MAX_FIELD_SECTION_SIZE:
        out->max_field_section_size = value;
        break;
      case YAWT_H3_SETTING_ENABLE_CONNECT_PROTOCOL:
        out->enable_connect_protocol = (uint8_t)value;
        break;
      case YAWT_H3_SETTING_H3_DATAGRAM:
        out->h3_datagram = (uint8_t)value;
        break;
      case YAWT_H3_SETTING_WT_ENABLED:
        out->wt_enabled = (uint8_t)value;
        break;
      default:
        // Unknown identifier — skip (value already consumed). RFC 9114
        // forward-compatibility: reserved/greased settings are ignored.
        break;
    }
  }

  return YAWT_H3_OK;
}
#endif
