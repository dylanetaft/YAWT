#include "h3.h"
#include "quic.h"   // YAWT_q_varint_* + YAWT_Q_ReadCursor_t — H3 reuses the QUIC varint codec
#include "quic_connection.h"  // YAWT_Q_Connection_t, user_data, event types
#include "security.h"
#include "logger.h"
#include <allocnbuffer/slab.h>
#include <string.h>
#include <stdlib.h>



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
  uint64_t nstreams;                  // slot pool size (concurrent stream cap)
  YAWT_H3_StreamMeta_t *stream_meta;   // preallocated slot pool, linear-scan by id
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
  h3->stream_meta = calloc(h3->nstreams, sizeof(YAWT_H3_StreamMeta_t));

  if (!h3->rxbuf || !h3->stream_meta) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: failed to allocate connection state");
    abort();
  }
  return h3;
}

static void _h3_conn_destroy(YAWT_H3_Connection_t *h3) {
  if (!h3) return;
  ANB_slab_destroy(h3->rxbuf);
  free(h3->stream_meta);
  free(h3);
}

YAWT_H3_StreamMeta_t *_h3_stream_meta_find(
    YAWT_H3_Connection_t *h3, 
    uint64_t stream_id) {
  //locate assigned stream slot
  for (uint64_t i = 0; i < h3->nstreams; i++) {
    if (h3->stream_meta[i].in_use && h3->stream_meta[i].stream_id == stream_id) {
      return &h3->stream_meta[i];
    }
  }
  //else assign
  for (uint64_t i = 0; i < h3->nstreams; i++) {
    if (!h3->stream_meta[i].in_use) {
      h3->stream_meta[i].in_use = true;
      h3->stream_meta[i].stream_id = stream_id;
      return &h3->stream_meta[i];
    }
  }
  return NULL;
}

// Read the current H3 frame's header (Type + Length varints) for `meta`,
// accumulating across QUIC stream chunks. Stream bytes always land in
// meta->hdr first, then we decode from there — so a header split across two
// chunks is handled the same as one fully contained in a chunk.
//
// Returns true once both varints are decoded (meta->frame_type, payload_len,
// hdr_size are set). Returns false if more bytes are still needed (the partial
// header stays in meta->hdr; call again with the next chunk). hdr_size == 0
// means "header not yet read" — reset it to 0 when starting a new frame.
inline bool _gather_h3_frame_head (
    YAWT_H3_Connection_t *h3,
    YAWT_H3_StreamMeta_t *meta,
    const YAWT_Q_Frame_Stream_t *chunk
    ) {
  // Copy as much of this chunk as can still fit in the header scratch. Only
  // the leading header bytes matter here; any payload bytes that ride along in
  // this chunk are re-derived by the caller from hdr_size once we succeed.
  size_t take = chunk->data_len;
  if (take > H3_FRAME_MAX_HEADER_BYTES - meta->accumulated) {
    take = H3_FRAME_MAX_HEADER_BYTES - meta->accumulated;
  }
  memcpy(meta->hdr + meta->accumulated, chunk->data, take);
  meta->accumulated += take;

  YAWT_Q_ReadCursor_t rc = {0};
  rc.data = meta->hdr;
  rc.len = meta->accumulated;

  // SHORT_BUFFER just means the header isn't complete yet — not an error.
  YAWT_q_varint_decode(&rc, &meta->frame_type);
  if (rc.err != YAWT_Q_OK) goto need_more;
  YAWT_q_varint_decode(&rc, &meta->payload_len);
  if (rc.err != YAWT_Q_OK) goto need_more;

  meta->hdr_size = (uint8_t)rc.cursor;
  return true;

  need_more:
  // Scratch full and still won't decode: no legal Type+Length is this long, so
  // the header can never complete — malformed. (Truncation, i.e. the stream
  // ending mid-header, is the caller's concern via chunk->fin.)
  if (meta->accumulated == H3_FRAME_MAX_HEADER_BYTES) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: frame header exceeds max len, closing stream_id=%lu",
             meta->stream_id);
    //TODO close stream
  }
  return false;
}
                                 

void _handle_rx_stream_chunk(YAWT_Q_Connection_t *con,
   YAWT_Q_EventParam_t *param) {
  
  const YAWT_Q_Frame_Stream_t *f = param->P_EVT_STREAM.frame;
  YAWT_H3_Connection_t *h3 = YAWT_q_con_get_user_data(con);
  YAWT_H3_StreamMeta_t *meta = _h3_stream_meta_find(h3, f->stream_id);
  if (!meta) {
    //TODO we need to close the connection
    YAWT_LOG(YAWT_LOG_ERROR, "h3: no stream slots available for stream_id=%lu", f->stream_id);
    return;
  }

  if (meta->hdr_size == 0) { //we have not read header yet
    bool res = _gather_h3_frame_head(h3, meta, f);
  }



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
      _handle_rx_stream_chunk(con, &param);
      const YAWT_Q_Frame_Stream_t *f = param.P_EVT_STREAM.frame;
      // TODO: buffer the chunk in rxbuf (tagged by stream_id), then run the
      // per-stream feed/advance state machine (read type prefix, read frame
      // headers, deliver complete frames, renormalize the buffer).
      YAWT_LOG(YAWT_LOG_DEBUG, "h3: rx stream=%lu len=%lu fin=%d",
               f->stream_id, f->data_len, f->fin);
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
