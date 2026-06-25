#include "h3.h"
#include "h3_header.h"
#include "qpack.h"
#include "quic.h"   // YAWT_q_varint_* + YAWT_Q_ReadCursor_t — H3 reuses the QUIC varint codec
#include "quic_connection.h"  // YAWT_Q_Connection_t, user_data slots, event types
#include "impl/quic_types.h"  // YAWT_Q_Connection_t definition
#include "impl/h3_types.h"    // YAWT_H3_Connection_t and YAWT_H3_Stream_t definitions
#include "security.h"
#include "logger.h"
#include <allocnbuffer/slab.h>
#include <string.h>
#include <stdlib.h>


#define H3_MAX_FRAME_SIZE 16384
static uint8_t _h3_encode_buf[H3_MAX_FRAME_SIZE];


size_t YAWT_h3_encode_frame_header(uint64_t frame_type, size_t payload_len, uint8_t *buf) {
  if (!buf) return 0;

  size_t off = 0;
  uint64_t n;

  if (YAWT_q_varint_encode(frame_type, buf + off, H3_FRAME_MAX_HEADER_BYTES - off, &n) != YAWT_Q_OK)
    return 0;
  off += n;

  if (YAWT_q_varint_encode(payload_len, buf + off, H3_FRAME_MAX_HEADER_BYTES - off, &n) != YAWT_Q_OK)
    return 0;
  off += n;

  return off;
}

size_t YAWT_h3_frame_header_size(size_t payload_len) {
  return YAWT_q_varint_size(YAWT_H3_FRAME_HEADERS) + YAWT_q_varint_size(payload_len);
}

YAWT_H3_Error_t YAWT_h3_settings_encode(const YAWT_H3_Settings_t *settings,
                                          uint8_t *buf, size_t len,
                                          size_t *written) {
  if (!settings || !buf || !written) return YAWT_H3_ERR_INVALID_PARAM;

  size_t off = 0;
  uint64_t n;

  uint64_t ids[] = {
    YAWT_H3_SETTING_QPACK_MAX_TABLE_CAPACITY,
    YAWT_H3_SETTING_QPACK_BLOCKED_STREAMS,
    YAWT_H3_SETTING_MAX_FIELD_SECTION_SIZE,
    YAWT_H3_SETTING_ENABLE_CONNECT_PROTOCOL,
    YAWT_H3_SETTING_H3_DATAGRAM,
    YAWT_H3_SETTING_WT_ENABLED,
    YAWT_H3_SETTING_WT_MAX_SESSIONS,
    YAWT_H3_SETTING_WT_INITIAL_MAX_STREAMS_UNI,
    YAWT_H3_SETTING_WT_INITIAL_MAX_STREAMS_BIDI,
    YAWT_H3_SETTING_WT_INITIAL_MAX_DATA,
  };
  uint64_t vals[] = {
    settings->qpack_max_table_capacity,
    settings->qpack_blocked_streams,
    settings->max_field_section_size,
    settings->enable_connect_protocol,
    settings->h3_datagram,
    settings->wt_enabled,
    settings->wt_max_sessions,
    settings->wt_initial_max_streams_uni,
    settings->wt_initial_max_streams_bidi,
    settings->wt_initial_max_data,
  };

  for (size_t i = 0; i < sizeof(ids)/sizeof(ids[0]); i++) {
    if (YAWT_q_varint_encode(ids[i], buf + off, len - off, &n) != YAWT_Q_OK)
      return YAWT_H3_ERR_SHORT_BUFFER;
    off += n;
    if (YAWT_q_varint_encode(vals[i], buf + off, len - off, &n) != YAWT_Q_OK)
      return YAWT_H3_ERR_SHORT_BUFFER;
    off += n;
  }

  *written = off;
  return YAWT_H3_OK;
}

static YAWT_H3_Connection_t *_h3_conn_create(YAWT_Q_Connection_t *con) {
  YAWT_H3_Connection_t *h3 = calloc(1, sizeof(*h3));
  if (!h3) return NULL;

  h3->qcon = con;
  h3->nstreams = con->local_fc.max_streams_bidi + con->local_fc.max_streams_uni;
  h3->streams = calloc(h3->nstreams, sizeof(YAWT_H3_Stream_t));
  h3->control_stream_id = UINT64_MAX;

  if (!h3->streams) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: failed to allocate connection state");
    abort();
  }
  return h3;
}

static void _h3_conn_destroy(YAWT_H3_Connection_t *h3) {
  if (!h3) return;
  for (uint64_t i = 0; i < h3->nstreams; i++) {
    if (h3->streams[i].frame.payload_blob != NULL) {
      ANB_blob_destroy(h3->streams[i].frame.payload_blob);
    }
    if (h3->streams[i].request_headers) {
      YAWT_h3_header_fields_destroy(h3->streams[i].request_headers);
      h3->streams[i].request_headers = NULL;
    }
    if (h3->streams[i].response_headers) {
      YAWT_h3_header_fields_destroy(h3->streams[i].response_headers);
      h3->streams[i].response_headers = NULL;
    }
  }
  free(h3->streams);
  free(h3->local_settings);
  free(h3->peer_settings);
  free(h3);
}

YAWT_H3_Stream_t *_h3_stream_meta_find(
    YAWT_H3_Connection_t *h3,
    uint64_t stream_id) {
  for (uint64_t i = 0; i < h3->nstreams; i++) {
    if (h3->streams[i].in_use && h3->streams[i].id == stream_id) {
      return &h3->streams[i];
    }
  }
  for (uint64_t i = 0; i < h3->nstreams; i++) {
    if (!h3->streams[i].in_use) {
      h3->streams[i].in_use = true;
      h3->streams[i].id = stream_id;
      return &h3->streams[i];
    }
  }
  return NULL;
}

// Resolve a uni stream's role from its leading stream-type varint (RFC 9114
// §6.2, RFC 9204 §4.2), accumulating across chunks into stream->hdr. On success
// sets stream->type and reports via *consumed how many bytes of THIS chunk were
// the prefix — the rest is stream body the caller forwards on.
static inline YAWT_H3_Error_t _gather_h3_stream_type(
    YAWT_H3_Stream_t *stream,
    const YAWT_Q_Frame_Stream_t *chunk,
    size_t *consumed) {

  size_t accumulated_before = stream->accumulated;
  size_t take = chunk->data_len;
  if (take > H3_STREAM_TYPE_MAX_BYTES - accumulated_before) {
    take = H3_STREAM_TYPE_MAX_BYTES - accumulated_before;
  }
  memcpy(stream->hdr + accumulated_before, chunk->data, take);
  stream->accumulated += take;

  YAWT_LOG(YAWT_LOG_DEBUG, "h3: stream %lu accumulating %zu bytes for stream type (total %zu), chunk offset=%lu",
           stream->id, take, stream->accumulated, chunk->offset);
  for (size_t i = 0; i < stream->accumulated && i < 16; i++) {
    YAWT_LOG(YAWT_LOG_DEBUG, "  hdr[%zu] = 0x%02x", i, stream->hdr[i]);
  }

  YAWT_Q_ReadCursor_t rc = {0};
  rc.data = stream->hdr;
  rc.len = stream->accumulated;
  uint64_t wire = 0;
  YAWT_q_varint_decode(&rc, &wire);
  if (rc.err != YAWT_Q_OK) {
    *consumed = take;
    return YAWT_H3_ERR_INCOMPLETE;
  }
  *consumed = (size_t)rc.cursor - accumulated_before;

  switch (wire) {
    case YAWT_H3_STREAM_WIRE_CONTROL:
      stream->type = YAWT_H3_STREAM_CONTROL;
      return YAWT_H3_OK;
    case YAWT_H3_STREAM_WIRE_QPACK_ENCODER:
    case YAWT_H3_STREAM_WIRE_QPACK_DECODER:
      stream->type = YAWT_H3_STREAM_QPACK;
      return YAWT_H3_OK;
    case YAWT_H3_STREAM_WIRE_WEBTRANSPORT:
      stream->type = YAWT_H3_STREAM_WEBTRANSPORT;
      return YAWT_H3_OK;
    case YAWT_H3_STREAM_WIRE_PUSH:
      YAWT_LOG(YAWT_LOG_ERROR, "h3: client opened a push stream, stream_id=%lu",
               stream->id);
      return YAWT_H3_ERR_MALFORMED;
    default:
      YAWT_LOG(YAWT_LOG_DEBUG, "h3: unknown/GREASE uni stream type 0x%lx, stream_id=%lu (will drain)",
               wire, stream->id);
      stream->type = YAWT_H3_STREAM_UNKNOWN;
      return YAWT_H3_OK;
  }
}

// Read the current H3 frame's header (Type + Length varints) for `stream`,
// accumulating across QUIC stream chunks.
static inline bool _gather_h3_frame_head(
    YAWT_H3_Connection_t *h3,
    YAWT_H3_Stream_t *stream,
    YAWT_Q_ReadCursor_t *rc) {
  size_t accumulated_before = stream->frame.accumulated;
  size_t remaining = rc->len - rc->cursor;
  size_t take = remaining;
  if (take > H3_FRAME_MAX_HEADER_BYTES - accumulated_before) {
    take = H3_FRAME_MAX_HEADER_BYTES - accumulated_before;
  }
  memcpy(stream->frame.hdr + accumulated_before, rc->data + rc->cursor, take);
  stream->frame.accumulated += take;

  YAWT_Q_ReadCursor_t dec = {0};
  dec.data = stream->frame.hdr;
  dec.len = stream->frame.accumulated;

  YAWT_q_varint_decode(&dec, &stream->frame.type);
  if (dec.err != YAWT_Q_OK) goto need_more;
  YAWT_q_varint_decode(&dec, &stream->frame.payload_len);
  if (dec.err != YAWT_Q_OK) goto need_more;

  stream->frame.hdr_size = (uint8_t)dec.cursor;
  rc->cursor += (size_t)dec.cursor - accumulated_before;
  stream->frame.accumulated = 0;
  return true;

  need_more:
  rc->cursor += take;
  if (stream->frame.accumulated == H3_FRAME_MAX_HEADER_BYTES) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: frame header exceeds max len, stream_id=%lu",
             stream->id);
  }
  return false;
}

// Emit an H3-level event to the app handler if one is installed.
static void _h3_emit_event(YAWT_H3_Connection_t *con,
                            YAWT_H3_EventType_t event,
                            YAWT_H3_EventParam_t param) {
  if (con->app_handler) {
    con->app_handler(con, event, param);
  }
}

// Dispatch a completed buffered frame (SETTINGS, HEADERS) based on stream type.
// Returns true on success, false on protocol error (caller should close connection).
static bool _dispatch_buffered_frame(YAWT_H3_Connection_t *con,
                                      YAWT_H3_Stream_t *stream) {
  YAWT_H3_Frame_t *f = &stream->frame;

  switch (stream->type) {
    case YAWT_H3_STREAM_CONTROL:
      switch (f->type) {
        case YAWT_H3_FRAME_SETTINGS: {
          if (con->peer_settings) {
            YAWT_LOG(YAWT_LOG_ERROR, "h3: duplicate SETTINGS on control stream, stream_id=%lu",
                     stream->id);
            return false;
          }
          con->peer_settings = calloc(1, sizeof(YAWT_H3_Settings_t));
          if (!con->peer_settings) {
            YAWT_LOG(YAWT_LOG_ERROR, "h3: OOM allocating peer_settings");
            abort();
          }
          YAWT_Q_ReadCursor_t dec = {
            .data = ANB_blob_data(f->payload_blob),
            .len = (size_t)f->payload_len,
            .cursor = 0,
            .err = YAWT_Q_OK,
          };
          YAWT_H3_Error_t err = YAWT_h3_settings_decode(&dec, con->peer_settings);
          if (err != YAWT_H3_OK) {
            YAWT_LOG(YAWT_LOG_ERROR, "h3: SETTINGS decode failed: %s", YAWT_h3_err_str(err));
            return false;
          }
          YAWT_LOG(YAWT_LOG_INFO, "h3: peer settings decoded (qpack_cap=%lu, blocked=%lu, connect=%u, datagram=%u, wt_enabled=%u, wt_sessions=%lu, wt_uni=%lu, wt_bidi=%lu, wt_data=%lu)",
                   con->peer_settings->qpack_max_table_capacity,
                   con->peer_settings->qpack_blocked_streams,
                   con->peer_settings->enable_connect_protocol,
                   con->peer_settings->h3_datagram,
                   con->peer_settings->wt_enabled,
                   con->peer_settings->wt_max_sessions,
                   con->peer_settings->wt_initial_max_streams_uni,
                   con->peer_settings->wt_initial_max_streams_bidi,
                   con->peer_settings->wt_initial_max_data);
          _h3_emit_event(con, YAWT_H3_EVT_SETTINGS, (YAWT_H3_EventParam_t){
            .P_EVT_SETTINGS = { .stream_id = stream->id, .settings = con->peer_settings }
          });
          return true;
        }
        case YAWT_H3_FRAME_GOAWAY:
          // TODO: parse GOAWAY, emit event
          return true;
        default:
          YAWT_LOG(YAWT_LOG_ERROR, "h3: unexpected frame type 0x%lx on control stream, stream_id=%lu",
                   f->type, stream->id);
          return false;
      }

    case YAWT_H3_STREAM_FRAME:
      switch (f->type) {
        case YAWT_H3_FRAME_HEADERS: {
          if (!stream->request_headers) {
            stream->request_headers = YAWT_h3_header_fields_create();
          }
          YAWT_QPACK_Error_t qerr = YAWT_qpack_decode_header_block(
              ANB_blob_data(f->payload_blob), (size_t)f->payload_len, stream->request_headers);
          if (qerr != YAWT_QPACK_OK) {
            YAWT_LOG(YAWT_LOG_ERROR, "h3: QPACK decode failed on stream %lu: %d",
                     stream->id, qerr);
            YAWT_h3_header_fields_destroy(stream->request_headers);
            stream->request_headers = NULL;
            return false;
          }
          YAWT_LOG(YAWT_LOG_DEBUG, "h3: headers decoded on stream %lu", stream->id);
          _h3_emit_event(con, YAWT_H3_EVT_HEADERS, (YAWT_H3_EventParam_t){
            .P_EVT_HEADERS = { .stream_id = stream->id, .headers = stream->request_headers }
          });
          return true;
        }
        case YAWT_H3_FRAME_GOAWAY:
          // TODO: parse GOAWAY, emit event
          return true;
        default:
          YAWT_LOG(YAWT_LOG_ERROR, "h3: unexpected frame type 0x%lx on request/response stream, stream_id=%lu",
                   f->type, stream->id);
          return false;
      }

    default:
      return true;
  }
}

void _handle_rx_stream_frame(
    YAWT_H3_Connection_t *con,
    YAWT_Q_ReadCursor_t *rc,
    YAWT_H3_Stream_t *stream,
    int chunk_fin) {

  YAWT_H3_Frame_t *f = &stream->frame;

  while (rc->cursor < rc->len && rc->err == YAWT_Q_OK) {
    // Header phase: read Type + Length once per frame.
    // hdr_size == 0 means we haven't yet decoded both varints for this frame.
    if (f->hdr_size == 0) {
      if (!_gather_h3_frame_head(con, stream, rc)) {
        return; // header spans into the next chunk — resume when it arrives
      }

      // Allocation decision: only SETTINGS and HEADERS must be held whole
      // (decoded after full receipt). DATA frames stream through without
      // allocation. Unknown/ignored frame types also skip allocation.
      bool must_buffer = (f->type == YAWT_H3_FRAME_SETTINGS ||
                          f->type == YAWT_H3_FRAME_HEADERS);
      if (must_buffer && f->payload_len > 0) {
        const YAWT_H3_SecurityPolicy_t *sec = YAWT_h3_security_get();
        if (f->type == YAWT_H3_FRAME_HEADERS &&
            sec->max_field_section_size &&
            f->payload_len > sec->max_field_section_size) {
          YAWT_LOG(YAWT_LOG_ERROR,
                   "h3: HEADERS frame %lu exceeds max_field_section_size %lu, stream_id=%lu",
                   f->payload_len, sec->max_field_section_size, stream->id);
          YAWT_q_con_close(con->qcon, YAWT_ERR_H3_EXCESSIVE_LOAD);
          return;
        }
        if (sec->max_frame_buffer_bytes &&
            f->payload_len > sec->max_frame_buffer_bytes) {
          YAWT_LOG(YAWT_LOG_ERROR,
                   "h3: frame Length %lu exceeds buffer cap %lu, stream_id=%lu",
                   f->payload_len, sec->max_frame_buffer_bytes, stream->id);
          return;
        }
        // blob: owned by f->payload_blob, destroyed at frame completion below.
        f->payload_blob = ANB_blob_create(f->payload_len);
      }
    }

    // Payload phase: three paths depending on frame type.
    if (f->payload_blob) {
      // Buffered frame (SETTINGS/HEADERS): push payload bytes into the blob.
      uint64_t need = f->payload_len - f->accumulated;
      size_t avail = rc->len - rc->cursor;
      size_t n = (need < avail) ? (size_t)need : avail;
      ANB_blob_push(f->payload_blob, rc->data + rc->cursor, n);
      f->accumulated += n;
      rc->cursor += n;
    } else if (f->type == YAWT_H3_FRAME_DATA && f->payload_len > 0) {
      // DATA frame: stream through to app without buffering. The app receives
      // a borrowed pointer into rc->data — it must copy if it wants to retain.
      uint64_t need = f->payload_len - f->accumulated;
      size_t avail = rc->len - rc->cursor;
      size_t n = (need < avail) ? (size_t)need : avail;
      int is_last = (f->accumulated + n >= f->payload_len) && chunk_fin;
      _h3_emit_event(con, YAWT_H3_EVT_DATA, (YAWT_H3_EventParam_t){
        .P_EVT_DATA = { .stream_id = stream->id, .data = rc->data + rc->cursor, .len = n, .fin = is_last }
      });
      f->accumulated += n;
      rc->cursor += n;
    } else {
      // Unknown/ignored frame type: skip payload bytes without copying.
      YAWT_LOG(YAWT_LOG_DEBUG, "h3: skipping %lu bytes of unknown frame type 0x%lx on stream %lu",
               f->payload_len - f->accumulated, f->type, stream->id);
      uint64_t need = f->payload_len - f->accumulated;
      size_t avail = rc->len - rc->cursor;
      size_t n = (need < avail) ? (size_t)need : avail;
      f->accumulated += n;
      rc->cursor += n;
    }

    // Frame complete: all payload bytes received (or payload_len was 0).
    if (f->hdr_size && f->accumulated >= f->payload_len) {
      YAWT_LOG(YAWT_LOG_DEBUG, "h3: frame complete type=0x%lx len=%lu stream=%lu",
               f->type, f->payload_len, stream->id);

      if (f->payload_blob) {
        // Dispatch buffered frame.
        if (!_dispatch_buffered_frame(con, stream)) {
          YAWT_LOG(YAWT_LOG_ERROR, "h3: protocol error on stream %lu", stream->id);
        }
      }

      // Release the blob (NULL if DATA/unknown — ANB_blob_destroy(NULL) is safe).
      // memset: resets the frame struct for the next frame on this stream.
      ANB_blob_destroy(f->payload_blob);
      memset(f, 0, sizeof(YAWT_H3_Frame_t));
    }
  }
}



void _handle_rx_stream_chunk(YAWT_Q_Connection_t *con,
    YAWT_Q_EventParam_t *param) {

  const YAWT_Q_Frame_Stream_t *qf = param->P_EVT_STREAM.frame;
  YAWT_H3_Connection_t *h3con = YAWT_q_con_get_user_data(con, YAWT_UD_H3);
  if (!h3con->app_handler) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: stream event but no app handler installed");
    return;
  }
  YAWT_H3_Stream_t *stream = _h3_stream_meta_find(h3con, qf->stream_id);
  if (!stream) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: no stream slots available for stream_id=%lu", qf->stream_id);
    return;
  }

  YAWT_LOG(YAWT_LOG_DEBUG, "h3: stream %lu received chunk: offset=%lu, len=%zu, fin=%d",
           qf->stream_id, qf->offset, qf->data_len, qf->fin);

  YAWT_Q_ReadCursor_t rc = {
    .data = qf->data,
    .len = qf->data_len,
    .cursor = 0,
    .err = YAWT_Q_OK,
  };

  if (stream->type == YAWT_H3_STREAM_UNASSIGNED) {
    switch (qf->stream_type) {
      case YAWT_Q_C_BIDI:
      case YAWT_Q_S_BIDI:
        stream->type = YAWT_H3_STREAM_FRAME;
        break;
      case YAWT_Q_C_UNI:
      case YAWT_Q_S_UNI: {
        size_t consumed = 0;
        YAWT_H3_Error_t e = _gather_h3_stream_type(stream, qf, &consumed);
        if (e == YAWT_H3_ERR_INCOMPLETE) return;
        if (e != YAWT_H3_OK) {
          return;
        }
        rc.cursor += consumed;
        break;
      }
      default:
        YAWT_LOG(YAWT_LOG_ERROR, "h3: unknown stream type %d for stream_id=%lu",
                 qf->stream_type, qf->stream_id);
        return;
    }
  }

  switch (stream->type) {
    case YAWT_H3_STREAM_FRAME:
    case YAWT_H3_STREAM_CONTROL:
      _handle_rx_stream_frame(h3con, &rc, stream, qf->fin);
      break;
    case YAWT_H3_STREAM_QPACK:
    case YAWT_H3_STREAM_UNKNOWN:
      rc.cursor = rc.len;
      break;
    case YAWT_H3_STREAM_WEBTRANSPORT:
      _h3_emit_event(h3con, YAWT_H3_EVT_WT_UNI_STREAM, (YAWT_H3_EventParam_t){
        .P_EVT_WT_UNI_STREAM = {
          .stream_id = qf->stream_id,
          .data = rc.data + rc.cursor,
          .len = rc.len - rc.cursor,
        }
      });
      rc.cursor = rc.len;
      break;
    default:
      YAWT_LOG(YAWT_LOG_ERROR, "h3: unhandled stream type %d for stream_id=%lu",
               stream->type, qf->stream_id);
      break;
  }
}

YAWT_H3_Error_t YAWT_h3_on_event(YAWT_Q_Connection_t *con, YAWT_Q_EventType_t event,
                                   YAWT_Q_EventParam_t param) {
  switch (event) {
    case YAWT_Q_EVT_CONNECTED: {
      YAWT_H3_Connection_t *h3 = _h3_conn_create(con);
      h3->local_settings = calloc(1, sizeof(YAWT_H3_Settings_t));
      if (!h3->local_settings) {
        YAWT_LOG(YAWT_LOG_ERROR, "h3: OOM allocating local_settings");
        abort();
      }

      const YAWT_H3_SecurityPolicy_t *h3_pol = YAWT_h3_security_get();
      h3->local_settings->max_field_section_size = h3_pol->max_field_section_size;

      const YAWT_WT_SecurityPolicy_t *wt_pol = YAWT_wt_security_get();
      h3->local_settings->wt_enabled = (wt_pol->max_sessions > 0) ? 1 : 0;
      h3->local_settings->wt_max_sessions = wt_pol->max_sessions;
      h3->local_settings->wt_initial_max_streams_uni = wt_pol->initial_max_streams_uni;
      h3->local_settings->wt_initial_max_streams_bidi = wt_pol->initial_max_streams_bidi;
      h3->local_settings->wt_initial_max_data = wt_pol->initial_max_data;
      if (wt_pol->max_sessions > 0) {
        if (con->role == YAWT_Q_ROLE_SERVER)
          h3->local_settings->enable_connect_protocol = 1;
        h3->local_settings->h3_datagram = 1;
      }

      YAWT_q_con_set_user_data(con, YAWT_UD_H3, h3);
      YAWT_LOG(YAWT_LOG_INFO, "h3: connection up, state allocated (%zu stream slots)"
               " wt_enabled=%u wt_max_sessions=%lu",
               h3 ? h3->nstreams : 0,
               h3->local_settings->wt_enabled,
               h3->local_settings->wt_max_sessions);
      YAWT_h3_send_settings(h3);
      return YAWT_H3_OK;
    }
    case YAWT_Q_EVT_STREAM: {
      YAWT_H3_Connection_t *h3 = YAWT_q_con_get_user_data(con, YAWT_UD_H3);
      if (!h3 || !h3->app_handler) {
        return YAWT_H3_ERR_NO_APP_HANDLER;
      }
      _handle_rx_stream_chunk(con, &param);
      return YAWT_H3_OK;
    }
    case YAWT_Q_EVT_CLOSE: {
      YAWT_H3_Connection_t *h3 = YAWT_q_con_get_user_data(con, YAWT_UD_H3);
      if (h3) {
        if (h3->app_handler) {
          _h3_emit_event(h3, YAWT_H3_EVT_CLOSE, (YAWT_H3_EventParam_t){
            .P_EVT_CLOSE = { .error_code = 0, .reason = "connection closed" }
          });
        }
        _h3_conn_destroy(h3);
        YAWT_q_con_set_user_data(con, YAWT_UD_H3, NULL);
      }
      return YAWT_H3_OK;
    }
    case YAWT_Q_EVT_DATAGRAM: {
      YAWT_H3_Connection_t *h3 = YAWT_q_con_get_user_data(con, YAWT_UD_H3);
      if (h3 && h3->app_handler) {
        _h3_emit_event(h3, YAWT_H3_EVT_DATAGRAM, (YAWT_H3_EventParam_t){
          .P_EVT_DATAGRAM = {
            .data = param.P_EVT_DATAGRAM.data,
            .len = param.P_EVT_DATAGRAM.len,
          }
        });
        return YAWT_H3_OK;
      }
      return YAWT_H3_IGNORED;
    }
    default:
      return YAWT_H3_IGNORED;
  }
}

void YAWT_h3_set_event_handler(YAWT_H3_Connection_t *con,
                                YAWT_H3_EventHandler_t handler) {
  if (con) {
    con->app_handler = handler;
  }
}

YAWT_Q_Connection_t *YAWT_h3_get_qcon(const YAWT_H3_Connection_t *con) {
  return con ? con->qcon : NULL;
}

YAWT_H3_Error_t YAWT_h3_settings_decode(YAWT_Q_ReadCursor_t *rc,
                                          YAWT_H3_Settings_t *out) {
  if (!rc || !out) return YAWT_H3_ERR_INVALID_PARAM;

  while (rc->cursor < rc->len) {
    uint64_t id, value;

    YAWT_q_varint_decode(rc, &id);
    if (rc->err != YAWT_Q_OK) return YAWT_H3_ERR_MALFORMED;
    YAWT_q_varint_decode(rc, &value);
    if (rc->err != YAWT_Q_OK) return YAWT_H3_ERR_MALFORMED;

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
      case YAWT_H3_SETTING_WT_MAX_SESSIONS:
        out->wt_max_sessions = value;
        break;
      case YAWT_H3_SETTING_WT_INITIAL_MAX_STREAMS_UNI:
        out->wt_initial_max_streams_uni = value;
        break;
      case YAWT_H3_SETTING_WT_INITIAL_MAX_STREAMS_BIDI:
        out->wt_initial_max_streams_bidi = value;
        break;
      case YAWT_H3_SETTING_WT_INITIAL_MAX_DATA:
        out->wt_initial_max_data = value;
        break;
      default:
        break;
    }
  }

  return YAWT_H3_OK;
}

// ---------------------------------------------------------------------------
// TX helpers — open control stream, send SETTINGS/HEADERS/DATA frames.
// ---------------------------------------------------------------------------

YAWT_H3_Error_t YAWT_h3_send_settings(YAWT_H3_Connection_t *h3) {
  if (!h3 || !h3->qcon || !h3->local_settings) return YAWT_H3_ERR_INVALID_PARAM;

  uint8_t settings_payload[256];
  size_t payload_len = 0;
  YAWT_H3_Error_t err = YAWT_h3_settings_encode(
      h3->local_settings, settings_payload, sizeof(settings_payload), &payload_len);
  if (err != YAWT_H3_OK) return err;

  uint8_t stream_type_buf[8];
  size_t stream_type_len = 0;
  uint64_t n;
  if (YAWT_q_varint_encode(YAWT_H3_STREAM_WIRE_CONTROL, stream_type_buf, sizeof(stream_type_buf), &n) != YAWT_Q_OK)
    return YAWT_H3_ERR_SHORT_BUFFER;
  stream_type_len = n;

  uint8_t frame_hdr[H3_FRAME_MAX_HEADER_BYTES];
  size_t frame_hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_SETTINGS, payload_len, frame_hdr);
  if (frame_hdr_len == 0) return YAWT_H3_ERR_SHORT_BUFFER;

  uint64_t stream_id = (h3->qcon->role == YAWT_Q_ROLE_CLIENT) ? 2 : 3;
  YAWT_Q_IoVec_t iov[3] = {
    { stream_type_buf, stream_type_len },
    { frame_hdr, frame_hdr_len },
    { settings_payload, payload_len }
  };
  YAWT_Err_t qerr = YAWT_q_con_send_stream(h3->qcon, stream_id, iov, 3, 0);
  if (qerr != YAWT_Q_OK) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: failed to send SETTINGS on stream %lu: %d",
             stream_id, qerr);
    return YAWT_H3_ERR_INVALID_PARAM;
  }

  h3->control_stream_id = stream_id;
  YAWT_LOG(YAWT_LOG_INFO, "h3: sent SETTINGS on control stream %lu (%zu bytes)",
           stream_id, stream_type_len + frame_hdr_len + payload_len);
  return YAWT_H3_OK;
}

YAWT_H3_Error_t YAWT_h3_send_headers(YAWT_H3_Connection_t *h3,
                                       uint64_t stream_id,
                                       const YAWT_H3_HeaderFields_t *headers,
                                       int fin) {
  if (!h3 || !h3->qcon || !headers) return YAWT_H3_ERR_INVALID_PARAM;

  if (h3->peer_settings && h3->peer_settings->max_field_section_size) {
    size_t section_size = YAWT_h3_header_section_size(headers);
    if (section_size > h3->peer_settings->max_field_section_size) {
      YAWT_LOG(YAWT_LOG_ERROR,
               "h3: header section size %zu exceeds peer max_field_section_size %lu",
               section_size, h3->peer_settings->max_field_section_size);
      return YAWT_H3_ERR_TOO_LARGE;
    }
  }

  size_t block_len = 0;
  YAWT_QPACK_Error_t qerr = YAWT_qpack_encode_header_block(
      headers, _h3_encode_buf + H3_FRAME_MAX_HEADER_BYTES,
      sizeof(_h3_encode_buf) - H3_FRAME_MAX_HEADER_BYTES, &block_len);
  if (qerr != YAWT_QPACK_OK) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: QPACK encode failed: %d", qerr);
    return YAWT_H3_ERR_SHORT_BUFFER;
  }

  uint8_t hdr[H3_FRAME_MAX_HEADER_BYTES];
  size_t hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_HEADERS, block_len, hdr);
  if (hdr_len == 0) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: failed to encode HEADERS frame header");
    return YAWT_H3_ERR_SHORT_BUFFER;
  }

  YAWT_Q_IoVec_t iov[2] = {
    { hdr, hdr_len },
    { _h3_encode_buf + H3_FRAME_MAX_HEADER_BYTES, block_len }
  };
  YAWT_Err_t qe = YAWT_q_con_send_stream(h3->qcon, stream_id, iov, 2, fin);
  if (qe != YAWT_Q_OK) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: failed to send HEADERS on stream %lu: %d",
             stream_id, qe);
    return YAWT_H3_ERR_INVALID_PARAM;
  }

  YAWT_LOG(YAWT_LOG_DEBUG, "h3: sent HEADERS on stream %lu (%zu bytes, fin=%d)",
           stream_id, hdr_len + block_len, fin);
  return YAWT_H3_OK;
}

YAWT_H3_Error_t YAWT_h3_send_data(YAWT_H3_Connection_t *h3,
                                     uint64_t stream_id,
                                     const uint8_t *data, size_t data_len,
                                     int fin) {
  if (!h3 || !h3->qcon) return YAWT_H3_ERR_INVALID_PARAM;
  if (data_len > 0 && !data) return YAWT_H3_ERR_INVALID_PARAM;

  uint8_t frame_hdr[H3_FRAME_MAX_HEADER_BYTES];
  size_t frame_hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_DATA, data_len, frame_hdr);
  if (frame_hdr_len == 0) return YAWT_H3_ERR_SHORT_BUFFER;

  YAWT_Q_IoVec_t iov[2] = {
    { frame_hdr, frame_hdr_len },
    { data, data_len }
  };
  int iov_count = (data_len > 0) ? 2 : 1;

  YAWT_Err_t qe = YAWT_q_con_send_stream(h3->qcon, stream_id, iov, iov_count, fin);
  if (qe != YAWT_Q_OK) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: failed to send DATA on stream %lu: %d",
             stream_id, qe);
    return YAWT_H3_ERR_INVALID_PARAM;
  }

  YAWT_LOG(YAWT_LOG_DEBUG, "h3: sent DATA on stream %lu (%zu bytes, fin=%d)",
           stream_id, data_len, fin);
  return YAWT_H3_OK;
}
