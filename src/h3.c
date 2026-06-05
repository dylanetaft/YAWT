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

static YAWT_H3_Connection_t *_h3_conn_create(YAWT_Q_Connection_t *con) {
  YAWT_H3_Connection_t *h3 = calloc(1, sizeof(*h3));
  if (!h3) return NULL;

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
    // CAREFUL - the payload ptr may be pointed at
    // stream chunk data we don't own.
    // We have to NULL immediately after delivering to app.
    if (h3->streams[i].frame.payload != NULL) {
      free(h3->streams[i].frame.payload);
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
  // locate assigned stream slot
  for (uint64_t i = 0; i < h3->nstreams; i++) {
    if (h3->streams[i].in_use && h3->streams[i].id == stream_id) {
      return &h3->streams[i];
    }
  }
  // else assign
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
// the prefix — the rest is stream body the caller forwards on. Returns:
//   YAWT_H3_OK             — role resolved, stream->type set
//   YAWT_H3_ERR_INCOMPLETE — prefix split across chunks; call again with more
//   YAWT_H3_ERR_MALFORMED  — illegal role for our (server) side; close the stream
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

  YAWT_Q_ReadCursor_t rc = {0};
  rc.data = stream->hdr;
  rc.len = stream->accumulated;
  uint64_t wire = 0;
  YAWT_q_varint_decode(&rc, &wire);
  if (rc.err != YAWT_Q_OK) {
    *consumed = take;            // whole slice went into scratch; need more bytes
    return YAWT_H3_ERR_INCOMPLETE;
  }
  // Only rc.cursor of the scratch was the prefix; the rest still sits in the
  // chunk as stream body for the caller to forward.
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
      // Push streams flow server->client only; a server receiving one is a
      // protocol error (RFC 9114 §6.2.2, H3_STREAM_CREATION_ERROR).
      YAWT_LOG(YAWT_LOG_ERROR, "h3: client opened a push stream, stream_id=%lu",
               stream->id);
      return YAWT_H3_ERR_MALFORMED;
    default:
      // Unknown/greased uni stream type. RFC 9114 §6.2 says abort *reading* the
      // stream (not a connection error); we have no drain path yet, so treat as
      // a stream error for now. TODO: silently drain unknown stream types.
      YAWT_LOG(YAWT_LOG_ERROR, "h3: unknown uni stream type 0x%lx, stream_id=%lu",
               wire, stream->id);
      return YAWT_H3_ERR_MALFORMED;
  }
}

// Read the current H3 frame's header (Type + Length varints) for `meta`,
// accumulating across QUIC stream chunks. Stream bytes always land in
// meta->cur.hdr first, then we decode from there — so a header split across two
// chunks is handled the same as one fully contained in a chunk.
//
// Returns true once both varints are decoded (meta->cur.type, payload_len,
// hdr_size are set). Returns false if more bytes are still needed (the partial
// header stays in meta->cur.hdr; call again with the next chunk). hdr_size == 0
// means "header not yet read" — reset it to 0 when starting a new frame.
// Advances `rc->cursor` by the number of bytes consumed from the chunk.
static inline bool _gather_h3_frame_head (
    YAWT_H3_Connection_t *h3,
    YAWT_H3_Stream_t *stream,
    YAWT_Q_ReadCursor_t *rc
    ) {
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

  // SHORT_BUFFER just means the header isn't complete yet — not an error.
  YAWT_q_varint_decode(&dec, &stream->frame.type);
  if (dec.err != YAWT_Q_OK) goto need_more;
  YAWT_q_varint_decode(&dec, &stream->frame.payload_len);
  if (dec.err != YAWT_Q_OK) goto need_more;

  stream->frame.hdr_size = (uint8_t)dec.cursor;
  // Only dec.cursor of the scratch was the header; advance the input cursor
  // past those bytes. Anything past that is payload still in the chunk.
  rc->cursor += (size_t)dec.cursor - accumulated_before;
  // Done accumulating the header — repurpose `accumulated` to count payload bytes.
  stream->frame.accumulated = 0;
  return true;

  need_more:
  // The whole slice went into the header scratch; consume all remaining bytes.
  rc->cursor += take;
  // Scratch full and still won't decode: no legal Type+Length is this long, so
  // the header can never complete — malformed. (Truncation, i.e. the stream
  // ending mid-header, is the caller's concern via chunk->fin.)
  if (stream->frame.accumulated == H3_FRAME_MAX_HEADER_BYTES) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: frame header exceeds max len, closing stream_id=%lu",
             stream->id);
    // TODO close stream
  }
  return false;
}


void _handle_rx_stream_frame(
    YAWT_H3_Connection_t *con,
    YAWT_Q_ReadCursor_t *rc,
    YAWT_H3_Stream_t *stream) {

  YAWT_H3_Frame_t *f = &stream->frame;

  // Header phase: read Type + Length once. On success `rc->cursor` is advanced
  // past the header, so the payload starts at rc->data + rc->cursor.
  if (stream->frame.hdr_size == 0) {
    if (!_gather_h3_frame_head(con, stream, rc)) {
      return; // header spans into the next chunk — resume when it arrives
    }

    // Need a buffer? Frames we must hold whole (SETTINGS, HEADERS) get an owned
    // buffer sized to the declared Length, capped by security policy. DATA and
    // friends stream through (added later) and allocate nothing here.
    bool must_buffer = (f->type == YAWT_H3_FRAME_SETTINGS ||
                        f->type == YAWT_H3_FRAME_HEADERS);
    if (must_buffer && stream->frame.payload_len > 0) {
      const YAWT_H3_SecurityPolicy_t *sec = YAWT_h3_security_get();
      if (sec->max_frame_buffer_bytes &&
          f->payload_len > sec->max_frame_buffer_bytes) {
        YAWT_LOG(YAWT_LOG_ERROR,
                 "h3: frame Length %lu exceeds buffer cap %lu, stream_id=%lu",
                 f->payload_len, sec->max_frame_buffer_bytes, stream->id);
        return; // TODO close stream
      }
      f->payload = malloc(f->payload_len);
      if (!f->payload) {
        YAWT_LOG(YAWT_LOG_ERROR, "h3: OOM buffering %lu-byte frame", f->payload_len);
        abort();
      }
    }
  }

  // Payload phase: copy whatever remains in the cursor into the frame buffer.
  // Only buffered frames have a destination; `accumulated` counts payload bytes
  // now (the header phase reset it to 0).
  if (f->payload) {
    uint64_t need = f->payload_len - f->accumulated;
    size_t avail = rc->len - rc->cursor;
    size_t n = (need < avail) ? (size_t)need : avail;
    memcpy(f->payload + f->accumulated, rc->data + rc->cursor, n);
    f->accumulated += n;
    rc->cursor += n;
  }

  // Complete once the whole declared Length is buffered.
  if (f->hdr_size && f->accumulated >= f->payload_len) {
    YAWT_LOG(YAWT_LOG_DEBUG, "h3: frame complete type=0x%lx len=%lu stream=%lu",
             f->type, f->payload_len, stream->id);

    // Dispatch SETTINGS on the control stream with RFC 9114 §7.2.4 enforcement.
    if (stream->type == YAWT_H3_STREAM_CONTROL) {
      if (f->type == YAWT_H3_FRAME_SETTINGS) {
        if (con->peer_settings) {
          YAWT_LOG(YAWT_LOG_ERROR, "h3: duplicate SETTINGS frame on control stream, stream_id=%lu",
                   stream->id);
          // TODO: close connection with H3_SETTINGS_ERROR
        } else {
          con->peer_settings = calloc(1, sizeof(YAWT_H3_Settings_t));
          if (!con->peer_settings) {
            YAWT_LOG(YAWT_LOG_ERROR, "h3: OOM allocating peer_settings");
            abort();
          }
          YAWT_Q_ReadCursor_t dec = {
            .data = f->payload,
            .len = (size_t)f->payload_len,
            .cursor = 0,
            .err = YAWT_Q_OK,
          };
          YAWT_H3_Error_t err = YAWT_h3_settings_decode(&dec, con->peer_settings);
          if (err != YAWT_H3_OK) {
            YAWT_LOG(YAWT_LOG_ERROR, "h3: SETTINGS decode failed: %s", YAWT_h3_err_str(err));
            // TODO: close connection with H3_SETTINGS_ERROR
          } else {
            YAWT_LOG(YAWT_LOG_INFO, "h3: peer settings decoded (qpack_cap=%lu, blocked=%lu, connect=%u, datagram=%u, wt=%u)",
                     con->peer_settings->qpack_max_table_capacity,
                     con->peer_settings->qpack_blocked_streams,
                     con->peer_settings->enable_connect_protocol,
                     con->peer_settings->h3_datagram,
                     con->peer_settings->wt_enabled);
          }
        }
      } else if (!con->peer_settings) {
        YAWT_LOG(YAWT_LOG_ERROR, "h3: non-SETTINGS frame (type=0x%lx) before SETTINGS on control stream, stream_id=%lu",
                 f->type, stream->id);
        // TODO: close connection with H3_MISSING_SETTINGS
      }
    }

    free(f->payload);             // NULL or owned — safe
    memset(f, 0, sizeof(YAWT_H3_Frame_t)); // reset for the next frame
  }
}



void _handle_rx_stream_chunk(YAWT_Q_Connection_t *con,
    YAWT_Q_EventParam_t *param) {

  const YAWT_Q_Frame_Stream_t *qf = param->P_EVT_STREAM.frame;
  YAWT_H3_Connection_t *h3con = YAWT_q_con_get_user_data(con);
  YAWT_H3_Stream_t *stream = _h3_stream_meta_find(h3con, qf->stream_id);
  if (!stream) {
    // TODO we need to close the connection
    YAWT_LOG(YAWT_LOG_ERROR, "h3: no stream slots available for stream_id=%lu", qf->stream_id);
    return;
  }

  YAWT_Q_ReadCursor_t rc = {
    .data = qf->data,
    .len = qf->data_len,
    .cursor = 0,
    .err = YAWT_Q_OK,
  };

  if (stream->type == YAWT_H3_STREAM_UNASSIGNED) { // not yet resolved
    switch (qf->stream_type) {
      case YAWT_Q_C_BIDI:
      case YAWT_Q_S_BIDI:
        stream->type = YAWT_H3_STREAM_FRAME; // request stream — no prefix
        break;
      case YAWT_Q_C_UNI:
      case YAWT_Q_S_UNI: {
        size_t consumed = 0;
        YAWT_H3_Error_t e = _gather_h3_stream_type(stream, qf, &consumed);
        if (e == YAWT_H3_ERR_INCOMPLETE) return; // prefix spans chunks; resume later
        if (e != YAWT_H3_OK) {
          // TODO close stream/session
          return;
        }
        rc.cursor += consumed;
        break;
      }
      default:
        YAWT_LOG(YAWT_LOG_ERROR, "h3: unknown stream type %d for stream_id=%lu",
                 qf->stream_type, qf->stream_id);
        // TODO close stream
        return;
    }
  }

  switch (stream->type) {
    case YAWT_H3_STREAM_FRAME:   // request stream (bidi)
    case YAWT_H3_STREAM_CONTROL: // control stream (uni) — same H3 framing
      _handle_rx_stream_frame(h3con, &rc, stream);
      break;
    // TODO QPACK, WEBTRANSPORT
    default:
      YAWT_LOG(YAWT_LOG_ERROR, "h3: unhandled stream type %d for stream_id=%lu",
               stream->type, qf->stream_id);
       // TODO close stream
       break;

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
      h3->local_settings = calloc(1, sizeof(YAWT_H3_Settings_t));
      if (!h3->local_settings) {
        YAWT_LOG(YAWT_LOG_ERROR, "h3: OOM allocating local_settings");
        abort();
      }
      h3->local_settings->qpack_max_table_capacity = 0;
      h3->local_settings->qpack_blocked_streams = 0;
      h3->local_settings->enable_connect_protocol = 1;
      h3->local_settings->h3_datagram = 1;
      h3->local_settings->wt_enabled = 1;
      YAWT_q_con_set_user_data(con, h3);
      YAWT_LOG(YAWT_LOG_INFO, "h3: connection up, state allocated (%zu stream slots)",
               h3 ? h3->nstreams : 0);
      // TODO: open the server control stream and send our SETTINGS frame.
      break;
    }
    case YAWT_Q_EVT_STREAM: {
      YAWT_H3_Connection_t *h3 = YAWT_q_con_get_user_data(con);
      _handle_rx_stream_chunk(con, &param);
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

YAWT_H3_Error_t YAWT_h3_settings_decode(YAWT_Q_ReadCursor_t *rc,
                                         YAWT_H3_Settings_t *out) {
  if (!rc || !out) return YAWT_H3_ERR_INVALID_PARAM;

  while (rc->cursor < rc->len) {
    uint64_t id, value;

    YAWT_q_varint_decode(rc, &id);
    if (rc->err != YAWT_Q_OK) return YAWT_H3_ERR_MALFORMED;
    // A valid SETTINGS body is whole (id, value) pairs — a dangling id is
    // malformed (RFC 9114 §7.2.4 treats a truncated frame as a frame error).
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
      default:
        // Unknown identifier — skip (value already consumed). RFC 9114
        // forward-compatibility: reserved/greased settings are ignored.
        break;
    }
  }

  return YAWT_H3_OK;
}
