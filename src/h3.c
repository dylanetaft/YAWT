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

  // Settings we advertise: static-only QPACK + the WT-enabling trio.
  h3->local_settings.qpack_max_table_capacity = 0;
  h3->local_settings.qpack_blocked_streams = 0;
  h3->local_settings.enable_connect_protocol = 1;
  h3->local_settings.h3_datagram = 1;
  h3->local_settings.wt_enabled = 1;
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
    //CAREFUL - the payload ptr may be pointed at
    //steam chunk data we don't own
    //We have to NULL immediately after delivering to app
    if (h3->streams[i].frame.payload != NULL) {
      free(h3->streams[i].frame.payload);
    }
  }
  free(h3->streams);
  free(h3);
}

YAWT_H3_Stream_t *_h3_stream_meta_find(
    YAWT_H3_Connection_t *h3, 
    uint64_t stream_id) {
  //locate assigned stream slot
  for (uint64_t i = 0; i < h3->nstreams; i++) {
    if (h3->streams[i].in_use && h3->streams[i].id == stream_id) {
      return &h3->streams[i];
    }
  }
  //else assign
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
static inline bool _gather_h3_frame_head (
    YAWT_H3_Connection_t *h3,
    YAWT_H3_Stream_t *stream,
    const YAWT_Q_Frame_Stream_t *chunk,
    size_t *out_chunk_consumed
    ) {
  // Copy as much of this chunk as can still fit in the header scratch. Only
  // the leading header bytes matter here; any payload bytes that ride along in
  // this chunk are re-derived by the caller from hdr_size once we succeed.
  size_t accumulated_before = stream->frame.accumulated;
  size_t take = chunk->data_len;
  if (take > H3_FRAME_MAX_HEADER_BYTES - accumulated_before) {
    take = H3_FRAME_MAX_HEADER_BYTES - accumulated_before;
  }
  memcpy(stream->frame.hdr + accumulated_before, chunk->data, take);
  stream->frame.accumulated += take;

  YAWT_Q_ReadCursor_t rc = {0};
  rc.data = stream->frame.hdr;
  rc.len = stream->frame.accumulated;

  // SHORT_BUFFER just means the header isn't complete yet — not an error.
  YAWT_q_varint_decode(&rc, &stream->frame.type);
  if (rc.err != YAWT_Q_OK) goto need_more;
  YAWT_q_varint_decode(&rc, &stream->frame.payload_len);
  if (rc.err != YAWT_Q_OK) goto need_more;

  stream->frame.hdr_size = (uint8_t)rc.cursor;
  // How many bytes of THIS chunk were header. We greedily copied up to the
  // scratch, but only rc.cursor of it is the header; anything past that is
  // payload still sitting in the chunk, which the caller re-reads from here.
  if (out_chunk_consumed) *out_chunk_consumed = (size_t)rc.cursor - accumulated_before;
  // Done accumulating the header — repurpose `accumulated` to count payload bytes.
  stream->frame.accumulated = 0;
  return true;

  need_more:
  // The whole slice went into the header scratch; nothing left of this chunk.
  if (out_chunk_consumed) *out_chunk_consumed = take;
  // Scratch full and still won't decode: no legal Type+Length is this long, so
  // the header can never complete — malformed. (Truncation, i.e. the stream
  // ending mid-header, is the caller's concern via chunk->fin.)
  if (stream->frame.accumulated == H3_FRAME_MAX_HEADER_BYTES) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: frame header exceeds max len, closing stream_id=%lu",
             stream->id);
    //TODO close stream
  }
  return false;
}


void _handle_rx_stream_frame(
    YAWT_H3_Connection_t *con, 
    const YAWT_Q_Frame_Stream_t *qf,
    YAWT_H3_Stream_t *stream) {

  size_t chunkpos = 0;
  YAWT_H3_Frame_t *f = &stream->frame; // current frame being parsed on this stream
                                       //
  // Header phase: read Type + Length once. On success `consumed` is how many
  // bytes of THIS chunk were the header, so the payload starts at chunkpos.
  if (stream->frame.hdr_size == 0) {
    size_t consumed = 0;
    if (!_gather_h3_frame_head(con, stream, qf, &consumed)) {
      return; // header spans into the next chunk — resume when it arrives
    }
    chunkpos = consumed;

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

  // Payload phase: copy whatever this chunk carries into the frame buffer. Only
  // buffered frames have a destination; `accumulated` counts payload bytes now
  // (the header phase reset it to 0).
  if (f->payload) {
    uint64_t need = f->payload_len - f->accumulated;
    size_t avail = qf->data_len - chunkpos;
    size_t n = (need < avail) ? (size_t)need : avail;
    memcpy(f->payload + f->accumulated, qf->data + chunkpos, n);
    f->accumulated += n;
  }

  // Complete once the whole declared Length is buffered.
  if (f->hdr_size && f->accumulated >= f->payload_len) {
    YAWT_LOG(YAWT_LOG_DEBUG, "h3: frame complete type=0x%lx len=%lu stream=%lu",
             f->type, f->payload_len, stream->id);
    // TODO: dispatch the complete frame (e.g. decode SETTINGS) before freeing.
    free(f->payload);             // NULL or owned — safe
    memset(f, 0, sizeof(YAWT_H3_Frame_t)); // reset for the next frame
  }
}



void _handle_rx_stream_chunk(YAWT_Q_Connection_t *con,
   YAWT_Q_EventParam_t *param) {
  
  const YAWT_Q_Frame_Stream_t *qf = param->P_EVT_STREAM.frame; //quic frame
  YAWT_H3_Connection_t *h3con = YAWT_q_con_get_user_data(con);
  YAWT_H3_Stream_t *stream = _h3_stream_meta_find(h3con, qf->stream_id);
  if (!stream) {
    //TODO we need to close the connection
    YAWT_LOG(YAWT_LOG_ERROR, "h3: no stream slots available for stream_id=%lu", qf->stream_id);
    return;
  }
  // Body view forwarded to the per-type handler. For uni streams the leading
  // role-prefix bytes are stripped here, once, on first sight of the stream.
  YAWT_Q_Frame_Stream_t body = *qf;

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
          //TODO close stream/session
          return;
        }
        body.data += consumed;
        body.data_len -= consumed;
        break;
      }
      default:
        YAWT_LOG(YAWT_LOG_ERROR, "h3: unknown stream type %d for stream_id=%lu",
                 qf->stream_type, qf->stream_id);
        //TODO close stream
        return;
    }
  }

  switch (stream->type) {
    case YAWT_H3_STREAM_FRAME:   // request stream (bidi)
    case YAWT_H3_STREAM_CONTROL: // control stream (uni) — same H3 framing
      _handle_rx_stream_frame(h3con, &body, stream);
      break;
    //TODO QPACK, WEBTRANSPORT
    default:
      YAWT_LOG(YAWT_LOG_ERROR, "h3: unhandled stream type %d for stream_id=%lu",
               stream->type, qf->stream_id);
       //TODO close stream
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
