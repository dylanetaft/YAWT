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

static const uint64_t _h3_setting_wire_ids[YAWT_H3_NUM_SETTINGS] = {
  [YAWT_H3_IDX_QPACK_MAX_TABLE_CAPACITY]  = 0x01,  /**< QPACK dynamic table capacity (RFC 9204) */
  [YAWT_H3_IDX_MAX_FIELD_SECTION_SIZE]    = 0x06,  /**< Maximum header field section size */
  [YAWT_H3_IDX_QPACK_BLOCKED_STREAMS]     = 0x07, /**< QPACK blocked streams limit (RFC 9204) */
  [YAWT_H3_IDX_ENABLE_CONNECT_PROTOCOL]   = 0x08, /**< Extended CONNECT protocol (RFC 9220) */
  [YAWT_H3_IDX_H3_DATAGRAM]              = 0x33, /**< HTTP datagrams (RFC 9297) */
  [YAWT_H3_IDX_WT_ENABLED]               = 0x2c7cf000, /**< WebTransport enabled (draft-15 §3.1) */
  [YAWT_H3_IDX_WT_MAX_SESSIONS]          = 0x14e9cd29,  /**< WebTransport session limit (draft-14 §3.1) */
  [YAWT_H3_IDX_WT_INITIAL_MAX_STREAMS_UNI]  = 0x2b64, /**< WT per-session uni stream limit (draft-15 §9.2) */
  [YAWT_H3_IDX_WT_INITIAL_MAX_STREAMS_BIDI] = 0x2b65, /**< WT per-session bidi stream limit (draft-15 §9.2) */
  [YAWT_H3_IDX_WT_INITIAL_MAX_DATA]         = 0x2b61, /**< WT per-session data limit (draft-15 §9.2) */
};

static int _h3_setting_wire_to_idx(uint64_t wire_id, YAWT_H3_SettingIdx_t *out) {
  for (int i = 0; i < YAWT_H3_NUM_SETTINGS; i++) {
    if (_h3_setting_wire_ids[i] == wire_id) {
      *out = (YAWT_H3_SettingIdx_t)i;
      return 0;
    }
  }
  return -1;
}

YAWT_H3_Error_t YAWT_h3_setting_set(YAWT_H3_Settings_t *s, YAWT_H3_SettingIdx_t idx, uint64_t val) {
  if (!s || idx < 0 || idx >= YAWT_H3_NUM_SETTINGS) return YAWT_H3_ERR_INVALID_PARAM;
  s->vals[idx] = val;
  s->val_set |= (1ULL << idx);
  return YAWT_H3_OK;
}

YAWT_H3_Error_t YAWT_h3_setting_get(const YAWT_H3_Settings_t *s, YAWT_H3_SettingIdx_t idx, uint64_t *out) {
  if (!s || !out || idx < 0 || idx >= YAWT_H3_NUM_SETTINGS) return YAWT_H3_ERR_INVALID_PARAM;
  if (!(s->val_set & (1ULL << idx))) return YAWT_H3_ERR_INVALID_PARAM;
  *out = s->vals[idx];
  return YAWT_H3_OK;
}

bool YAWT_h3_setting_isset(const YAWT_H3_Settings_t *s, YAWT_H3_SettingIdx_t idx) {
  if (!s || idx < 0 || idx >= YAWT_H3_NUM_SETTINGS) return false;
  return (s->val_set & (1ULL << idx)) != 0;
}

YAWT_H3_Error_t YAWT_h3_settings_encode(const YAWT_H3_Settings_t *settings,
                                          uint8_t *buf, size_t len,
                                          size_t *written) {
  if (!settings || !buf || !written) return YAWT_H3_ERR_INVALID_PARAM;

  size_t off = 0;
  uint64_t n;

  for (int i = 0; i < YAWT_H3_NUM_SETTINGS; i++) {
    if (!YAWT_h3_setting_isset(settings, (YAWT_H3_SettingIdx_t)i)) continue;
    if (YAWT_q_varint_encode(_h3_setting_wire_ids[i], buf + off, len - off, &n) != YAWT_Q_OK)
      return YAWT_H3_ERR_SHORT_BUFFER;
    off += n;
    if (YAWT_q_varint_encode(settings->vals[i], buf + off, len - off, &n) != YAWT_Q_OK)
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
      stream->type = YAWT_H3_STREAM_QPACK_ENCODER;
      return YAWT_H3_OK;
    case YAWT_H3_STREAM_WIRE_QPACK_DECODER:
      stream->type = YAWT_H3_STREAM_QPACK_DECODER;
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
          YAWT_LOG(YAWT_LOG_INFO, "h3: peer settings decoded (val_set=0x%lx)",
                   con->peer_settings->val_set);
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

YAWT_H3_Error_t YAWT_h3_parse_frame(YAWT_H3_Connection_t *h3con,
                                    const YAWT_Q_Frame_Stream_t *chunk,
                                    YAWT_H3_Stream_t **out_stream,
                                    size_t *cursor) {
  if (!h3con || !chunk || !out_stream || !cursor) {
    return YAWT_H3_ERR_INVALID_PARAM;
  }

  YAWT_H3_Stream_t *stream = _h3_stream_meta_find(h3con, chunk->stream_id);
  if (!stream) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: no stream slots available for stream_id=%lu", chunk->stream_id);
    return YAWT_H3_ERR_INVALID_PARAM;
  }
  *out_stream = stream;

  YAWT_LOG(YAWT_LOG_DEBUG, "h3: stream %lu received chunk: offset=%lu, len=%zu, fin=%d",
           chunk->stream_id, chunk->offset, chunk->data_len, chunk->fin);

  // Stream type resolution if not yet assigned
  if (stream->type == YAWT_H3_STREAM_UNASSIGNED) {
    switch (chunk->stream_type) {
      case YAWT_Q_C_BIDI:
      case YAWT_Q_S_BIDI:
        stream->type = YAWT_H3_STREAM_FRAME;
        break;
      case YAWT_Q_C_UNI:
       case YAWT_Q_S_UNI: {
         size_t consumed = 0;
         YAWT_H3_Error_t e = _gather_h3_stream_type(stream, chunk, &consumed);
         if (e == YAWT_H3_ERR_INCOMPLETE) {
           *cursor += consumed;
           return YAWT_H3_ERR_INCOMPLETE;
         }
         if (e != YAWT_H3_OK) {
           return e;
         }
         *cursor += consumed;
         /* If all chunk data was consumed by stream-type prefix, return OK now */
         if (*cursor >= chunk->data_len) {
           return YAWT_H3_OK;
         }
         break;
       }
      default:
        YAWT_LOG(YAWT_LOG_ERROR, "h3: unknown stream type %d for stream_id=%lu",
                 chunk->stream_type, chunk->stream_id);
        return YAWT_H3_ERR_MALFORMED;
    }

    // Duplicate detection and peer stream ID tracking for critical streams
    if (stream->type == YAWT_H3_STREAM_CONTROL) {
      YAWT_H3_Error_t err = YAWT_h3_core_stream_set(h3con, YAWT_H3_UNIQUE_STREAM_PEER_CONTROL, chunk->stream_id);
      if (err != YAWT_H3_OK) {
        YAWT_LOG(YAWT_LOG_ERROR, "h3: duplicate control stream, stream_id=%lu", chunk->stream_id);
        YAWT_q_con_close(h3con->qcon, YAWT_ERR_H3_STREAM_CREATION_ERROR);
        return YAWT_H3_ERR_MALFORMED;
      }
      YAWT_LOG(YAWT_LOG_INFO, "h3: peer control stream %lu", chunk->stream_id);
    } else if (stream->type == YAWT_H3_STREAM_QPACK_ENCODER) {
      YAWT_H3_Error_t err = YAWT_h3_core_stream_set(h3con, YAWT_H3_UNIQUE_STREAM_PEER_QPACK_ENCODER, chunk->stream_id);
      if (err != YAWT_H3_OK) {
        YAWT_LOG(YAWT_LOG_ERROR, "h3: duplicate QPACK encoder stream, stream_id=%lu", chunk->stream_id);
        YAWT_q_con_close(h3con->qcon, YAWT_ERR_H3_STREAM_CREATION_ERROR);
        return YAWT_H3_ERR_MALFORMED;
      }
      YAWT_LOG(YAWT_LOG_INFO, "h3: peer QPACK encoder stream %lu", chunk->stream_id);
    } else if (stream->type == YAWT_H3_STREAM_QPACK_DECODER) {
      YAWT_H3_Error_t err = YAWT_h3_core_stream_set(h3con, YAWT_H3_UNIQUE_STREAM_PEER_QPACK_DECODER, chunk->stream_id);
      if (err != YAWT_H3_OK) {
        YAWT_LOG(YAWT_LOG_ERROR, "h3: duplicate QPACK decoder stream, stream_id=%lu", chunk->stream_id);
        YAWT_q_con_close(h3con->qcon, YAWT_ERR_H3_STREAM_CREATION_ERROR);
        return YAWT_H3_ERR_MALFORMED;
      }
      YAWT_LOG(YAWT_LOG_INFO, "h3: peer QPACK decoder stream %lu", chunk->stream_id);
    }
  }

  // Dispatch by resolved stream type
  switch (stream->type) {
    case YAWT_H3_STREAM_FRAME:
    case YAWT_H3_STREAM_CONTROL: {
      // Parse frame header (Type + Length varints)
      YAWT_H3_Frame_t *f = &stream->frame;
      if (f->hdr_size == 0) {
        // Build a temporary ReadCursor for the remaining chunk data
        YAWT_Q_ReadCursor_t rc = {
          .data = chunk->data,
          .len = chunk->data_len,
          .cursor = *cursor,
          .err = YAWT_Q_OK,
        };
        if (!_gather_h3_frame_head(h3con, stream, &rc)) {
          *cursor = rc.cursor;
          return YAWT_H3_ERR_INCOMPLETE;
        }
        *cursor = rc.cursor;

        // Buffering decision: only SETTINGS and HEADERS must be held whole
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
            YAWT_q_con_close(h3con->qcon, YAWT_ERR_H3_EXCESSIVE_LOAD);
            return YAWT_H3_ERR_TOO_LARGE;
          }
          if (sec->max_frame_buffer_bytes &&
              f->payload_len > sec->max_frame_buffer_bytes) {
            YAWT_LOG(YAWT_LOG_ERROR,
                     "h3: frame Length %lu exceeds buffer cap %lu, stream_id=%lu",
                     f->payload_len, sec->max_frame_buffer_bytes, stream->id);
            return YAWT_H3_ERR_TOO_LARGE;
          }
          f->payload_blob = ANB_blob_create(f->payload_len);
        }
      }
      return YAWT_H3_OK;
    }

    case YAWT_H3_STREAM_QPACK_ENCODER:
    case YAWT_H3_STREAM_QPACK_DECODER:
    case YAWT_H3_STREAM_UNKNOWN:
      // Drain: advance cursor to end, no H3 frames on these streams
      *cursor = chunk->data_len;
      return YAWT_H3_IGNORED;

    case YAWT_H3_STREAM_WEBTRANSPORT:
      // Emit event with remaining data, then drain
      _h3_emit_event(h3con, YAWT_H3_EVT_WT_UNI_STREAM, (YAWT_H3_EventParam_t){
        .P_EVT_WT_UNI_STREAM = {
          .stream_id = chunk->stream_id,
          .data = chunk->data + *cursor,
          .len = chunk->data_len - *cursor,
        }
      });
      *cursor = chunk->data_len;
      return YAWT_H3_IGNORED;

    default:
      YAWT_LOG(YAWT_LOG_ERROR, "h3: unhandled stream type %d for stream_id=%lu",
               stream->type, chunk->stream_id);
      return YAWT_H3_ERR_MALFORMED;
  }
}

void _handle_rx_stream_frame(
    YAWT_H3_Connection_t *con,
    const YAWT_Q_Frame_Stream_t *chunk,
    YAWT_H3_Stream_t *stream,
    size_t *cursor,
    int chunk_fin) {

  YAWT_H3_Frame_t *f = &stream->frame;
  size_t avail = chunk->data_len - *cursor;

  if (avail == 0) return;

  // Payload phase: three paths depending on frame type.
  if (f->payload_blob) {
    // Buffered frame (SETTINGS/HEADERS): push payload bytes into the blob.
    uint64_t need = f->payload_len - f->accumulated;
    size_t n = (need < avail) ? (size_t)need : avail;
    ANB_blob_push(f->payload_blob, chunk->data + *cursor, n);
    f->accumulated += n;
    *cursor += n;
  } else if (f->type == YAWT_H3_FRAME_DATA && f->payload_len > 0) {
    // DATA frame: stream through to app without buffering.
    uint64_t need = f->payload_len - f->accumulated;
    size_t n = (need < avail) ? (size_t)need : avail;
    int is_last = (f->accumulated + n >= f->payload_len) && chunk_fin;
    _h3_emit_event(con, YAWT_H3_EVT_DATA, (YAWT_H3_EventParam_t){
      .P_EVT_DATA = { .stream_id = stream->id, .data = chunk->data + *cursor, .len = n, .fin = is_last }
    });
    f->accumulated += n;
    *cursor += n;
  } else {
    // Unknown/ignored frame type: skip payload bytes without copying.
    YAWT_LOG(YAWT_LOG_INFO, "h3: skipping %lu bytes of unknown frame type 0x%lx on stream %lu",
             f->payload_len - f->accumulated, f->type, stream->id);
    uint64_t need = f->payload_len - f->accumulated;
    size_t n = (need < avail) ? (size_t)need : avail;
    f->accumulated += n;
    *cursor += n;
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
      YAWT_h3_setting_set(h3->local_settings, YAWT_H3_IDX_MAX_FIELD_SECTION_SIZE, h3_pol->max_field_section_size);

      const YAWT_WT_SecurityPolicy_t *wt_pol = YAWT_wt_security_get();
      if (wt_pol->max_sessions > 0) {
        YAWT_h3_setting_set(h3->local_settings, YAWT_H3_IDX_WT_ENABLED, 1);
        YAWT_h3_setting_set(h3->local_settings, YAWT_H3_IDX_WT_MAX_SESSIONS, wt_pol->max_sessions);
        if (wt_pol->initial_max_streams_uni > 0)
          YAWT_h3_setting_set(h3->local_settings, YAWT_H3_IDX_WT_INITIAL_MAX_STREAMS_UNI, wt_pol->initial_max_streams_uni);
        if (wt_pol->initial_max_streams_bidi > 0)
          YAWT_h3_setting_set(h3->local_settings, YAWT_H3_IDX_WT_INITIAL_MAX_STREAMS_BIDI, wt_pol->initial_max_streams_bidi);
        if (wt_pol->initial_max_data > 0)
          YAWT_h3_setting_set(h3->local_settings, YAWT_H3_IDX_WT_INITIAL_MAX_DATA, wt_pol->initial_max_data);
        if (con->role == YAWT_Q_ROLE_SERVER)
          YAWT_h3_setting_set(h3->local_settings, YAWT_H3_IDX_ENABLE_CONNECT_PROTOCOL, 1);
        YAWT_h3_setting_set(h3->local_settings, YAWT_H3_IDX_H3_DATAGRAM, 1);
      }

      YAWT_h3_setting_set(h3->local_settings, YAWT_H3_IDX_QPACK_MAX_TABLE_CAPACITY, 0);
      YAWT_h3_setting_set(h3->local_settings, YAWT_H3_IDX_QPACK_BLOCKED_STREAMS, 0);
      YAWT_q_con_set_user_data(con, YAWT_UD_H3, h3);
      YAWT_h3_send_settings(h3);
      YAWT_h3_open_qpack_streams(h3);
      return YAWT_H3_OK;
    }
    case YAWT_Q_EVT_STREAM: {
      YAWT_H3_Connection_t *h3 = YAWT_q_con_get_user_data(con, YAWT_UD_H3);
      if (!h3 || !h3->app_handler) {
        return YAWT_H3_ERR_NO_APP_HANDLER;
      }
      const YAWT_Q_Frame_Stream_t *chunk = param.P_EVT_STREAM.frame;
      size_t cursor = 0;
      while (cursor < chunk->data_len) {
        YAWT_H3_Stream_t *stream = NULL;
        YAWT_H3_Error_t err = YAWT_h3_parse_frame(h3, chunk, &stream, &cursor);

        // Critical stream closure detection (RFC 9114 §6.2.1, RFC 9204 §4.2)
        // Must check FIN regardless of parse result for critical streams
        if (chunk->fin && stream) {
          bool is_core = false;
          for (int i = 0; i < YAWT_H3_UNIQUE_STREAM_COUNT; i++) {
            if (h3->core_stream_status[i].available && h3->core_stream_status[i].stream_id == chunk->stream_id) {
              is_core = true;
              break;
            }
          }
          if (is_core) {
            YAWT_LOG(YAWT_LOG_ERROR, "h3: critical stream %lu closed (type=%d)",
                     chunk->stream_id, stream->type);
            YAWT_q_con_close(h3->qcon, YAWT_ERR_H3_CLOSED_CRITICAL_STREAM);
            return YAWT_H3_ERR_MALFORMED;
          }
        }

        if (err == YAWT_H3_IGNORED) continue;
        if (err == YAWT_H3_ERR_INCOMPLETE) return YAWT_H3_OK;
        if (err != YAWT_H3_OK) {
          YAWT_LOG(YAWT_LOG_ERROR, "h3: parse error on stream %lu: %s",
                   chunk->stream_id, YAWT_h3_err_str(err));
          return err;
        }
        _handle_rx_stream_frame(h3, chunk, stream, &cursor, chunk->fin);
        if (stream->frame.hdr_size &&
            stream->frame.accumulated >= stream->frame.payload_len) {
          if (stream->frame.payload_blob) {
            if (!_dispatch_buffered_frame(h3, stream)) {
              YAWT_LOG(YAWT_LOG_ERROR, "h3: protocol error on stream %lu", stream->id);
            }
          }
          ANB_blob_destroy(stream->frame.payload_blob);
          memset(&stream->frame, 0, sizeof(YAWT_H3_Frame_t));
        }
      }

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

YAWT_H3_Error_t YAWT_h3_core_stream_set(YAWT_H3_Connection_t *h3,
                                         YAWT_H3_Unique_Stream_Type_t type,
                                         uint64_t stream_id) {
  if (!h3 || type < 0 || type >= YAWT_H3_UNIQUE_STREAM_COUNT) {
    return YAWT_H3_ERR_INVALID_PARAM;
  }

  YAWT_H3_Unique_Stream_Status_t *status = &h3->core_stream_status[type];
  if (status->available) {
    return YAWT_H3_ERR_INVALID_PARAM;  // duplicate
  }

  status->available = true;
  status->stream_id = stream_id;
  return YAWT_H3_OK;
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

    YAWT_H3_SettingIdx_t idx;
    if (_h3_setting_wire_to_idx(id, &idx) == 0) {
      YAWT_h3_setting_set(out, idx, value);
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

  YAWT_h3_core_stream_set(h3, YAWT_H3_UNIQUE_STREAM_LOCAL_CONTROL, stream_id);
  YAWT_LOG(YAWT_LOG_INFO, "h3: sent SETTINGS on control stream %lu (%zu bytes)",
           stream_id, stream_type_len + frame_hdr_len + payload_len);
  return YAWT_H3_OK;
}

YAWT_H3_Error_t YAWT_h3_open_qpack_streams(YAWT_H3_Connection_t *h3) {
  if (!h3 || !h3->qcon) return YAWT_H3_ERR_INVALID_PARAM;

  // QPACK streams are unidirectional. Client uses even IDs (2, 4, 6, ...),
  // server uses odd IDs (3, 5, 7, ...). Control stream is first (2 or 3),
  // so QPACK encoder is second (4 or 5), decoder is third (6 or 7).
  uint64_t encoder_stream_id = (h3->qcon->role == YAWT_Q_ROLE_CLIENT) ? 4 : 5;
  uint64_t decoder_stream_id = (h3->qcon->role == YAWT_Q_ROLE_CLIENT) ? 6 : 7;

  // Open QPACK encoder stream (type 0x02)
  uint8_t encoder_type_buf[8];
  uint64_t n;
  if (YAWT_q_varint_encode(YAWT_H3_STREAM_WIRE_QPACK_ENCODER, encoder_type_buf, sizeof(encoder_type_buf), &n) != YAWT_Q_OK)
    return YAWT_H3_ERR_SHORT_BUFFER;

  YAWT_Q_IoVec_t encoder_iov[1] = {
    { encoder_type_buf, n }
  };
  YAWT_Err_t qerr = YAWT_q_con_send_stream(h3->qcon, encoder_stream_id, encoder_iov, 1, 0);
  if (qerr != YAWT_Q_OK) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: failed to open QPACK encoder stream %lu: %d",
             encoder_stream_id, qerr);
    return YAWT_H3_ERR_INVALID_PARAM;
  }
  YAWT_h3_core_stream_set(h3, YAWT_H3_UNIQUE_STREAM_LOCAL_QPACK_ENCODER, encoder_stream_id);
  YAWT_LOG(YAWT_LOG_INFO, "h3: opened QPACK encoder stream %lu", encoder_stream_id);

  // Open QPACK decoder stream (type 0x03)
  uint8_t decoder_type_buf[8];
  if (YAWT_q_varint_encode(YAWT_H3_STREAM_WIRE_QPACK_DECODER, decoder_type_buf, sizeof(decoder_type_buf), &n) != YAWT_Q_OK)
    return YAWT_H3_ERR_SHORT_BUFFER;

  YAWT_Q_IoVec_t decoder_iov[1] = {
    { decoder_type_buf, n }
  };
  qerr = YAWT_q_con_send_stream(h3->qcon, decoder_stream_id, decoder_iov, 1, 0);
  if (qerr != YAWT_Q_OK) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: failed to open QPACK decoder stream %lu: %d",
             decoder_stream_id, qerr);
    return YAWT_H3_ERR_INVALID_PARAM;
  }
  YAWT_h3_core_stream_set(h3, YAWT_H3_UNIQUE_STREAM_LOCAL_QPACK_DECODER, decoder_stream_id);
  YAWT_LOG(YAWT_LOG_INFO, "h3: opened QPACK decoder stream %lu", decoder_stream_id);

  return YAWT_H3_OK;
}

YAWT_H3_Error_t YAWT_h3_send_headers(YAWT_H3_Connection_t *h3,
                                       uint64_t stream_id,
                                       const YAWT_H3_HeaderFields_t *headers,
                                       int fin) {
  if (!h3 || !h3->qcon || !headers) return YAWT_H3_ERR_INVALID_PARAM;

  if (h3->peer_settings && YAWT_h3_setting_isset(h3->peer_settings, YAWT_H3_IDX_MAX_FIELD_SECTION_SIZE)) {
    uint64_t max_fss = 0;
    YAWT_h3_setting_get(h3->peer_settings, YAWT_H3_IDX_MAX_FIELD_SECTION_SIZE, &max_fss);
    size_t section_size = YAWT_h3_header_section_size(headers);
    if (section_size > max_fss) {
      YAWT_LOG(YAWT_LOG_ERROR,
               "h3: header section size %zu exceeds peer max_field_section_size %lu",
               section_size, max_fss);
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

  YAWT_LOG(YAWT_LOG_INFO, "h3: sent HEADERS on stream %lu (%zu bytes, fin=%d)",
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
