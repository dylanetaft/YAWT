/**
 * @file wt.c
 * @brief WebTransport layer implementation.
 * @note draft-ietf-webtrans-http3-15, RFC 9297 (capsules, HTTP datagrams).
 *
 * The WT layer sits parallel to H3, consuming QUIC events and looking up
 * H3 stream metadata to determine which streams are WT-owned. It processes
 * WT-owned streams (0x41 bidi, 0x54 uni, upgraded CONNECT) and emits
 * WT-specific events to the application.
 */

#include "wt.h"
#include "impl/wt_types.h"
#include "impl/h3_types.h"
#include "impl/quic_types.h"
#include "h3.h"
#include "quic.h"
#include "capsule.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>

//TODO base this off security module, move to Slab
#define WT_MAX_SESSIONS 16

// The address of this sentinel value is used to indicate that a stream slot is unused.
static const uint8_t _wt_sentinal_stream_unused = 0xff;

YAWT_WT_Context_t *_wt_conn_create(YAWT_Q_Context_t *qcon) {
  YAWT_WT_Context_t *ctx = calloc(1, sizeof(YAWT_WT_Context_t));
  if (!ctx) {
    YAWT_LOG(YAWT_LOG_ERROR, "wt: OOM allocating context");
    abort();
  }
  ctx->qcon = qcon;
  ctx->nsessions = WT_MAX_SESSIONS;
  ctx->sessions = calloc(ctx->nsessions, sizeof(YAWT_WT_Session_t));
  if (!ctx->sessions) {
    YAWT_LOG(YAWT_LOG_ERROR, "wt: OOM allocating session pool");
    abort();
  }
  YAWT_LOG(YAWT_LOG_INFO, "wt: context created");
  return ctx;
}

inline static bool _wt_stream_defined(YAWT_Q_StreamUserData_t *sud) {
  if (!sud) abort(); // should never be called with null, abort on bug
  return sud->user_data[YAWT_UD_WT] != NULL && sud->user_data[YAWT_UD_WT] != &_wt_sentinal_stream_unused;
}

inline static bool _wt_stream_unused(YAWT_Q_StreamUserData_t *sud) {
  if (!sud) abort(); // should never be called with null, abort on bug
  return sud->user_data[YAWT_UD_WT] == &_wt_sentinal_stream_unused;
}

//frees any memory we allocated for the stream metadata, and sets the slot to the sentinel value
static void _wt_sud_destroy(YAWT_Q_StreamUserData_t *sud) {
  if (!sud) return;
  YAWT_WT_Stream_t *wt_stream = sud->user_data[YAWT_UD_WT];
  if (_wt_stream_defined(sud)) {
    if (wt_stream->hdr_buffer != NULL) {
      ANB_blob_destroy(wt_stream->hdr_buffer);
      wt_stream->hdr_buffer = NULL;
    }
    free(wt_stream);
    // note, this function is also used if we're out of sessions 
    // so null the the ptr in conn_destroy if needed, not here
    // TODO might be a todo, there might be a max sessions we're supposed to close quic conn if too many opened
    sud->user_data[YAWT_UD_WT] = (void *)&_wt_sentinal_stream_unused; 
  }
}
static void _wt_conn_destroy(YAWT_WT_Context_t *ctx) {
  if (!ctx) return;
  YAWT_Q_Context_t *con = ctx->qcon;
  if (con) {
    YAWT_LOG(YAWT_LOG_INFO, "CID:%s wt: destroying context", YAWT_q_cid_to_hex(YAWT_q_con_get_cid(con)));
    ANB_Slab_t *slab = YAWT_q_con_get_stream_userdata_slab(con);
    if (slab) {
      ANB_SlabIter_t iter = {0};
      size_t item_size;
      uint8_t *item;
      while ((item = ANB_slab_peek_item_iter(slab, &iter, &item_size)) != NULL) {
        YAWT_Q_StreamUserData_t *sud = (YAWT_Q_StreamUserData_t *)item;
        if (_wt_stream_defined(sud)) { //free WT stream metadata we are responsible for
          free(sud->user_data[YAWT_UD_WT]);
        }
        sud->user_data[YAWT_UD_WT] = NULL; //null out any set to sentinal
      }
    }
  }
  for (uint64_t i = 0; i < ctx->nsessions; i++) {
    if (ctx->sessions[i].in_use) {
      YAWT_LOG(YAWT_LOG_INFO, "wt: terminating session %lu on context destroy",
               ctx->sessions[i].session_id);
      ctx->sessions[i].in_use = false;
    }
  }
  free(ctx->sessions);
  free(ctx);
  YAWT_q_con_set_user_data(con, YAWT_UD_WT, NULL);
  YAWT_LOG(YAWT_LOG_INFO, "wt: context destroyed");
}

void YAWT_wt_set_event_handler(YAWT_WT_Context_t *ctx, YAWT_WT_EventHandler_t handler) {
  if (ctx) {
    ctx->app_handler = handler;
  }
}

static YAWT_WT_Session_t *_wt_session_find(YAWT_WT_Context_t *ctx, uint64_t session_id) {
  if (!ctx) return NULL;
  for (uint64_t i = 0; i < ctx->nsessions; i++) {
    if (ctx->sessions[i].in_use && ctx->sessions[i].session_id == session_id) {
      return &ctx->sessions[i];
    }
  }
  return NULL;
}

static YAWT_WT_Session_t *_wt_session_find_or_create(YAWT_WT_Context_t *ctx, uint64_t session_id) {
  if (!ctx) return NULL;
  // Check if session already exists
  YAWT_WT_Session_t *existing = _wt_session_find(ctx, session_id);
  if (existing) return existing; 
  
  // Find free slot
  for (uint64_t i = 0; i < ctx->nsessions; i++) {
    if (!ctx->sessions[i].in_use) {
      ctx->sessions[i].in_use = true;
      ctx->sessions[i].session_id = session_id;
      ctx->sessions[i].connect_stream_id = session_id;
      YAWT_LOG(YAWT_LOG_INFO, "wt: created session %lu", session_id);
      return &ctx->sessions[i];
    }
  }
  YAWT_LOG(YAWT_LOG_ERROR, "wt: no free session slots");
  return NULL;
}

static void _wt_emit_event(YAWT_WT_Context_t *ctx, YAWT_WT_Session_t *session,
                            YAWT_WT_EventType_t event, YAWT_WT_EventParam_t param) {
  if (ctx && ctx->app_handler) {
    ctx->app_handler(ctx, session, event, param);
  }
}


static YAWT_Err_t _wt_gather_hdr(uint8_t *data, size_t len, uint64_t *o_signal, uint64_t *o_session, size_t *o_hdr_len) {

    YAWT_Q_ReadCursor_t rc = {
      .data = data,
      .len = len,
      .cursor = 0,
      .err = YAWT_Q_OK,
    };
    //the first varint is the signal
    uint64_t signal = 0;
    uint64_t session = 0;
    YAWT_q_varint_decode(&rc, &signal);
    if (rc.err != YAWT_Q_OK) return rc.err;
    if (signal != YAWT_WT_STREAM_WIRE_WT_UNI && signal != YAWT_WT_STREAM_WIRE_WT_BIDI) {
      YAWT_LOG(YAWT_LOG_INFO, "wt: stream header signal is not WT, signal=0x%lx", signal);
      return YAWT_Q_ERR_INVALID_PARAM; //not a WT stream
    }
    YAWT_q_varint_decode(&rc, &session);
    if (rc.err != YAWT_Q_OK) return rc.err;
    *o_hdr_len = rc.cursor;
    *o_signal = signal;
    *o_session = session;
    return YAWT_Q_OK;
}

// Never before seen stream
// parse the header and see if it is ours to process
// Happens in parallel to processing in H3
// It's a bit easier to do this way for unit testing and troubleshooting
// Less indirection, negligibly less performant
static YAWT_WT_Error_t _wt_gated_stream_create(YAWT_Q_Context_t *ctx, YAWT_Q_StreamUserData_t *sud, const YAWT_Q_Frame_Stream_t *chunk, size_t *out_offset) {
  if (out_offset == NULL) abort(); // should never be called with null, abort on bug
  if (ctx == NULL) abort(); // should never be called with null, abort on bug
  if (sud == NULL || chunk == NULL) abort(); // should never be called with null, abort on bug
  *out_offset = 0; // zero early so i dont forget
  YAWT_WT_Stream_t *wt_stream = sud->user_data[YAWT_UD_WT];
  if (wt_stream != NULL && wt_stream->hdr_complete) abort(); // should never be called with a complete stream, abort on bug
  YAWT_WT_Context_t *wt_ctx = YAWT_q_con_get_user_data(ctx, YAWT_UD_WT);
  if (!wt_ctx) abort(); //this is created in conn create, never null, abort on bug  
  // If the h3 parser already handled this, we can take some shortcuts for performance
  YAWT_H3_Stream_t *h3_stream = sud->user_data[YAWT_UD_H3];
  // we can only h3 fast path the ignore case
  // so we can deliver to the app offset
  if (h3_stream) { //fast h3 check
    YAWT_H3_StreamType_t h3_type = h3_stream->type;
    // If the stream is not a WT data stream, WT ignores it. The CONNECT stream
    // (WT_CONNECT) lands here too: H3 owns its HEADERS/DATA, and its capsules and
    // session lifecycle are driven from the H3-event pump (YAWT_wt_on_h3_event),
    // not this QUIC stream path.
    if (h3_type != YAWT_H3_STREAM_UNASSIGNED && h3_type != YAWT_H3_STREAM_WT) {
      YAWT_LOG(YAWT_LOG_DEBUG, "wt: stream %lu owned by h3, ignore", chunk->stream_id);
      sud->user_data[YAWT_UD_WT] = (void *)&_wt_sentinal_stream_unused; //mark as unused
      return YAWT_WT_OK; //not a WT stream, ignore
    }
  }

  //fast path                                           
  if (wt_stream == NULL) { //try to oneshot without buffering

    uint64_t signal = 0;
    uint64_t session = 0;
    size_t hdr_len = 0;
    YAWT_Err_t err = _wt_gather_hdr(chunk->data, chunk->data_len, &signal, &session, &hdr_len);
    if (err == YAWT_Q_ERR_SHORT_BUFFER) goto NEEDBUFFER; //need more data to complete header
    else if (err != YAWT_Q_OK) {
      YAWT_LOG(YAWT_LOG_INFO, "wt: stream %lu marking as unused", chunk->stream_id);
      sud->user_data[YAWT_UD_WT] = (void *)&_wt_sentinal_stream_unused; //mark as unused
      return YAWT_WT_OK; //not a WT stream, ignore
    } 

    wt_stream = calloc(1, sizeof(YAWT_WT_Stream_t));
    if (!wt_stream) abort(); //OOM, abort
    sud->user_data[YAWT_UD_WT] = wt_stream;
    wt_stream->type = (YAWT_WT_WireStreamType_t)signal;
    wt_stream->session_id = session;
    wt_stream->hdr_complete = true; //we have a complete header, no need to buffer
    YAWT_WT_Session_t *fast_session = _wt_session_find_or_create(wt_ctx, session);
    if (!fast_session) {
      _wt_sud_destroy(sud); //free the stream metadata and mark as unused
      YAWT_LOG(YAWT_LOG_ERROR, "wt: no free session slots for stream %lu session %lu, marking stream as unused",
               chunk->stream_id, session);
      return YAWT_WT_ERR_NO_SESSION;
    }
    wt_stream->session = fast_session; //draft-15 §2.2: session_id == CONNECT stream ID
    YAWT_LOG(YAWT_LOG_DEBUG, "wt: stream %lu header parsed in fast path, session %lu",
             chunk->stream_id, session);
    *out_offset = hdr_len; //return how many bytes we consumed from this chunk
    return YAWT_WT_OK;
  }
  NEEDBUFFER:
  //we need to buffer the stream data until we have a complete header
  if (wt_stream == NULL) {
    wt_stream = calloc(1, sizeof(YAWT_WT_Stream_t));
    if (!wt_stream) abort(); //OOM, abort
    sud->user_data[YAWT_UD_WT] = wt_stream;
    wt_stream->hdr_buffer = ANB_blob_create(16);
  }
  size_t gathered = ANB_blob_data_len(wt_stream->hdr_buffer);
  //8 bytes is the max varint wire size, we need to decode two varints (signal and session)
  size_t max_take = 16 - ANB_blob_data_len(wt_stream->hdr_buffer);
  size_t take = chunk->data_len < max_take ? chunk->data_len : max_take;
  ANB_blob_push(wt_stream->hdr_buffer, chunk->data, take);
  uint64_t signal = 0;
  uint64_t session = 0;
  size_t hdr_len = 0;
  YAWT_Err_t err = _wt_gather_hdr(ANB_blob_data(wt_stream->hdr_buffer), ANB_blob_data_len(wt_stream->hdr_buffer), &signal, &session, &hdr_len);
  if (err == YAWT_Q_ERR_SHORT_BUFFER) {
    YAWT_LOG(YAWT_LOG_DEBUG, "wt: stream %lu header incomplete, buffering", chunk->stream_id);
    return YAWT_WT_ERR_INCOMPLETE; //need more data to complete header
  }
  else if (err != YAWT_Q_OK) {
    YAWT_LOG(YAWT_LOG_INFO, "wt: stream %lu marking as unused", chunk->stream_id);
    _wt_sud_destroy(sud); //free the stream metadata and mark as unused
    return YAWT_WT_OK; //not a WT stream, ignore
  }
  wt_stream->type = (YAWT_WT_WireStreamType_t)signal;
  wt_stream->session_id = session;
  wt_stream->hdr_complete = true;
  *out_offset = hdr_len - gathered; //return how many bytes we consumed from this chunk
  YAWT_WT_Session_t *wt_session = _wt_session_find_or_create(wt_ctx, wt_stream->session_id);
  if (!wt_session) {
    YAWT_LOG(YAWT_LOG_ERROR, "wt: no free session slots for stream %lu session %lu, marking stream as unused",
             chunk->stream_id, wt_stream->session_id);
    _wt_sud_destroy(sud); //free the stream metadata and mark as unused
    return YAWT_WT_ERR_NO_SESSION;
  }
  wt_stream->session = wt_session; //draft-15 §2.2: session_id == CONNECT stream ID

  return YAWT_WT_OK;
}

YAWT_WT_Error_t YAWT_wt_on_h3_event(YAWT_H3_Context_t *h3con,
                                    YAWT_H3_EventType_t event,
                                    YAWT_H3_EventParam_t param) {
  if (!h3con) return YAWT_WT_ERR_INVALID_PARAM;
  YAWT_Q_Context_t *qcon = YAWT_h3_get_qcon(h3con);
  if (!qcon) return YAWT_WT_ERR_INVALID_PARAM;
  YAWT_WT_Context_t *ctx = YAWT_q_con_get_user_data(qcon, YAWT_UD_WT);
  if (!ctx) return YAWT_WT_OK;

  switch (event) {
    case YAWT_H3_EVT_WT_UPGRADE: {
      // A WT session is born when the CONNECT stream reaches WT_CONNECT. H3
      // fires WT_UPGRADE only post-upgrade, when the stream type is already
      // final, on both roles — client when the 2xx is processed, server from
      // YAWT_h3_webtrans_accept(). So this event can be pumped at the top of the
      // app's H3 handler regardless of role. On a client rejection the stream is
      // FRAME, so the type check below naturally skips it.
      // session_id == CONNECT stream ID (draft-15 §2.2).
      uint64_t sid = param.P_EVT_WT_UPGRADE.stream_id;
      if (YAWT_h3_stream_get_type(h3con, sid) == YAWT_H3_STREAM_WT_CONNECT &&
          _wt_session_find(ctx, sid) == NULL) {
        YAWT_WT_Session_t *session = _wt_session_find_or_create(ctx, sid);
        if (session) {
          _wt_emit_event(ctx, session, YAWT_WT_EVT_SESSION_ESTABLISHED,
              (YAWT_WT_EventParam_t){
                .P_EVT_SESSION_ESTABLISHED = { .session_id = sid }
              });
        }
      }
      break;
    }
    default:
      // Capsules (EVT_DATA on a WT_CONNECT stream) and HTTP datagrams
      // (EVT_DATAGRAM) are candidates to move here later; for now they are
      // handled by the app calling YAWT_wt_receive_capsule / the QUIC path.
      break;
  }
  return YAWT_WT_OK;
}

YAWT_WT_Error_t YAWT_wt_on_event(YAWT_Q_Context_t *con,
                                    YAWT_Q_EventType_t event,
                                    YAWT_Q_EventParam_t param) {
  if (!con) return YAWT_WT_ERR_INVALID_PARAM;

  if (event == YAWT_Q_EVT_CONNECTED) {
    YAWT_WT_Context_t *ctx = _wt_conn_create(con);
    YAWT_q_con_set_user_data(con, YAWT_UD_WT, ctx);
    return YAWT_WT_OK;
  }

  YAWT_WT_Context_t *ctx = YAWT_q_con_get_user_data(con, YAWT_UD_WT);

  if (event == YAWT_Q_EVT_CLOSE) {
    if (ctx) {
      _wt_conn_destroy(ctx);
    }
    return YAWT_WT_OK;
  }

  if (!ctx) return YAWT_WT_OK;

  switch (event) {
    case YAWT_Q_EVT_STREAM: {
      YAWT_Q_StreamUserData_t *sud = param.P_EVT_STREAM.stream_ud;
      const YAWT_Q_Frame_Stream_t *chunk = param.P_EVT_STREAM.frame;
      if (chunk == NULL || sud == NULL) abort(); //this would be a bug
      if (_wt_stream_unused(sud)) { //exit early if stream is marked unused, performance
        YAWT_LOG(YAWT_LOG_DEBUG, "wt: EVT_STREAM stream_id=%lu marked unused, ignoring", chunk->stream_id);
        return YAWT_WT_OK;
      }
      size_t read_offset = 0;
      YAWT_WT_Stream_t *wt_stream = sud->user_data[YAWT_UD_WT];
      if (wt_stream == NULL || !wt_stream->hdr_complete) {
        YAWT_WT_Error_t rc = _wt_gated_stream_create(con, sud, chunk, &read_offset);
        if (rc == YAWT_WT_ERR_INCOMPLETE) {
          YAWT_LOG(YAWT_LOG_DEBUG, "wt: stream %lu header incomplete, buffering", chunk->stream_id);
          return YAWT_WT_OK;
        }
        if (rc != YAWT_WT_OK) { //stream was marked unused by _wt_buffer_hdr
          return rc;
        }

      }
      //after reading headers, stream could be unused, early exit for performance
      if (_wt_stream_unused(sud)) { //exit early if stream is marked unused, performance
        YAWT_LOG(YAWT_LOG_DEBUG, "wt: EVT_STREAM stream_id=%lu marked unused after buffering, ignoring", chunk->stream_id);
        return YAWT_WT_OK;
      }
      //the above acts as a gate, no need for further checks
      wt_stream = sud->user_data[YAWT_UD_WT];
      _wt_emit_event(ctx, wt_stream->session, YAWT_WT_EVT_STREAM_DATA, (YAWT_WT_EventParam_t){
        .P_EVT_STREAM_DATA = {
          .session_id = wt_stream->session_id,
          .stream_id = chunk->stream_id,
          .data = chunk->data + read_offset,
          .len = chunk->data_len - read_offset,
          .fin = chunk->fin,
        }
        });
      return YAWT_WT_OK;
    }
    case YAWT_Q_EVT_DATAGRAM: {
      // QUIC DATAGRAM received directly from the QUIC layer (RFC 9297 §2.1).
      // Parse Quarter Stream ID and dispatch to the owning WT session.
      return YAWT_wt_on_datagram(ctx, param.P_EVT_DATAGRAM.data, param.P_EVT_DATAGRAM.len);
    }
    default:
      return YAWT_WT_OK;
  }
}


YAWT_WT_Error_t YAWT_wt_on_datagram(YAWT_WT_Context_t *ctx,
                                     const uint8_t *data, size_t len) {
  if (!ctx) return YAWT_WT_ERR_INVALID_PARAM;
  if (!data || len == 0) {
    YAWT_LOG(YAWT_LOG_WARN, "wt: empty datagram, dropping");
    return YAWT_WT_OK;
  }

  // RFC 9297 §2.1: HTTP/3 Datagram = [Quarter Stream ID (i)] [HTTP Datagram Payload (..)]
  // Decode the Quarter Stream ID varint
  YAWT_Q_ReadCursor_t rc = {
    .data = (uint8_t *)data,
    .len = len,
    .cursor = 0,
    .err = YAWT_Q_OK,
  };
  uint64_t quarter_stream_id = 0;
  YAWT_q_varint_decode(&rc, &quarter_stream_id);
  if (rc.err != YAWT_Q_OK) {
    YAWT_LOG(YAWT_LOG_WARN, "wt: datagram too short to parse Quarter Stream ID (%zu bytes), dropping", len);
    return YAWT_WT_OK;
  }

  // Validate: Quarter Stream ID must be <= 2^60-1
  if (quarter_stream_id > ((1ULL << 60) - 1)) {
    YAWT_LOG(YAWT_LOG_ERROR, "wt: Quarter Stream ID %lu exceeds 2^60-1", quarter_stream_id);
    // RFC 9297: connection error H3_DATAGRAM_ERROR (0x33) — but we just drop for now
    return YAWT_WT_ERR_INVALID_PARAM;
  }

  // Session ID = Quarter Stream ID * 4 (reverse of /4 in RFC 9297 §2.1)
  uint64_t session_id = quarter_stream_id * 4;

  // Look up session
  YAWT_WT_Session_t *session = _wt_session_find(ctx, session_id);
  if (!session) {
    // RFC 9297 §2.1: "drop that datagram silently or buffer it temporarily"
    YAWT_LOG(YAWT_LOG_DEBUG, "wt: datagram for unknown session %lu (quarter=%lu), dropping",
             session_id, quarter_stream_id);
    return YAWT_WT_OK;
  }

  // Emit datagram event with remaining payload (past the Quarter Stream ID varint)
  size_t varint_bytes = rc.cursor;
  _wt_emit_event(ctx, session, YAWT_WT_EVT_DATAGRAM, (YAWT_WT_EventParam_t){
    .P_EVT_DATAGRAM = {
      .session_id = session_id,
      .data = data + varint_bytes,
      .len = len - varint_bytes,
    }
  });

  return YAWT_WT_OK;
}

/**
 * Feed DATA payload from a WT_CONNECT stream into the per-session capsule
 * parser. The app calls this from its H3 EVT_DATA handler when it detects
 * the stream is WT_CONNECT — the capsule types (CLOSE_SESSION, DRAIN_SESSION,
 * MAX_STREAMS_*, STREAMS_BLOCKED_*, etc.) are defined by draft-15 §6 / RFC 9297.
 *
 * Returns YAWT_WT_OK when a capsule was fully parsed (event emitted),
 * YAWT_WT_ERR_INCOMPLETE if more bytes are needed, or another error.
 */
YAWT_WT_Error_t YAWT_wt_receive_capsule(YAWT_WT_Context_t *ctx,
                                         uint64_t session_id,
                                         const uint8_t *data, size_t len) {
  if (!ctx) return YAWT_WT_ERR_INVALID_PARAM;
  if (len > 0 && !data) return YAWT_WT_ERR_INVALID_PARAM;
  if (len == 0) return YAWT_WT_OK;

  YAWT_WT_Session_t *session = _wt_session_find(ctx, session_id);
  if (!session) {
    YAWT_LOG(YAWT_LOG_WARN, "wt: capsule data for unknown session %lu, dropping",
             session_id);
    return YAWT_WT_ERR_NO_SESSION;
  }

  YAWT_WT_CapsuleType_t type;
  YAWT_WT_Capsule_t capsule;
  int rc = YAWT_wt_parse_capsule(&session->capsule_parser, data, len, &type, &capsule);
  if (rc == YAWT_CAPSULE_OK) {
    _wt_emit_event(ctx, session, YAWT_WT_EVT_CAPSULE_RECEIVED, (YAWT_WT_EventParam_t){
      .P_EVT_CAPSULE_RECEIVED = {
        .session_id = session_id,
        .stream_id = session_id,  /* CONNECT stream IS the session per draft-15 §2.2 */
        .type = type,
        .capsule = capsule,
      }
    });
    return YAWT_WT_OK;
  }
  if (rc == YAWT_CAPSULE_INCOMPLETE) return YAWT_WT_ERR_INCOMPLETE;
  YAWT_LOG(YAWT_LOG_WARN, "wt: capsule parse error on session %lu", session_id);
  return YAWT_WT_ERR_MALFORMED;
}

YAWT_WT_Error_t YAWT_wt_send_datagram(YAWT_WT_Context_t *ctx,
                                        uint64_t session_id,
                                        const uint8_t *data, size_t len) {
  if (!ctx || !ctx->qcon) return YAWT_WT_ERR_INVALID_PARAM;

  YAWT_WT_Session_t *session = _wt_session_find(ctx, session_id);
  if (!session) return YAWT_WT_ERR_NO_SESSION;

  // Quarter Stream ID = connect_stream_id / 4
  uint64_t quarter_stream_id = session->connect_stream_id / 4;

  // Build buffer: [Quarter Stream ID varint] [payload]
  size_t varint_sz = YAWT_q_varint_size(quarter_stream_id);
  if (varint_sz == 0) {
    YAWT_LOG(YAWT_LOG_ERROR, "wt: varint size() returned 0 for quarter_stream_id %lu", quarter_stream_id);
    return YAWT_WT_ERR_INVALID_PARAM;
  }

  size_t total_len = varint_sz + len;
  uint8_t *buf = malloc(total_len);
  if (!buf) {
    YAWT_LOG(YAWT_LOG_ERROR, "wt: OOM allocating datagram buffer (%zu bytes)", total_len);
    return YAWT_WT_ERR_SHORT_BUFFER;
  }

  uint64_t written = 0;
  YAWT_Err_t rc = YAWT_q_varint_encode(quarter_stream_id, buf, varint_sz, &written);
  if (rc != YAWT_Q_OK) {
    free(buf);
    return YAWT_WT_ERR_SHORT_BUFFER;
  }

  if (len > 0) {
    memcpy(buf + varint_sz, data, len);
  }

  rc = YAWT_q_enqueue_frame_datagram(ctx->qcon, buf, total_len);
  free(buf);

  if (rc != YAWT_Q_OK) {
    YAWT_LOG(YAWT_LOG_WARN, "wt: enqueue_frame_datagram failed: %s", YAWT_err_str(rc));
    return YAWT_WT_ERR_SHORT_BUFFER;
  }

  YAWT_LOG(YAWT_LOG_DEBUG, "wt: sent datagram for session %lu (%zu + %zu bytes)",
           session_id, varint_sz, len);
  return YAWT_WT_OK;
}

YAWT_WT_Error_t YAWT_wt_open_stream(YAWT_WT_Context_t *ctx,
                                      uint64_t session_id,
                                      YAWT_WT_StreamDir_t dir,
                                      uint64_t *out_stream_id) {
  if (!ctx || !ctx->qcon || !out_stream_id) return YAWT_WT_ERR_INVALID_PARAM;

  YAWT_WT_Session_t *session = _wt_session_find(ctx, session_id);
  if (!session) return YAWT_WT_ERR_NO_SESSION;

  // Pick the local stream ID for this direction; the allocator derives the role
  // half of the stream type from con->role (RFC 9000 §2.1).
  YAWT_WT_WireStreamType_t wire = (dir == YAWT_WT_DIR_BIDI)
      ? YAWT_WT_STREAM_WIRE_WT_BIDI : YAWT_WT_STREAM_WIRE_WT_UNI;
  uint64_t stream_id = YAWT_q_con_next_stream_id(ctx->qcon, dir == YAWT_WT_DIR_BIDI);

  // Build the WT stream header: [type/signal varint][Session ID varint] (draft-15 §4.2/§4.3).
  uint64_t sid = session->connect_stream_id;
  size_t wire_sz = YAWT_q_varint_size(wire);
  size_t sid_sz = YAWT_q_varint_size(sid);
  if (wire_sz == 0 || sid_sz == 0) return YAWT_WT_ERR_INVALID_PARAM;
  uint8_t hdr[16];
  uint64_t written = 0;
  if (YAWT_q_varint_encode(wire, hdr, wire_sz, &written) != YAWT_Q_OK) return YAWT_WT_ERR_SHORT_BUFFER;
  if (YAWT_q_varint_encode(sid, hdr + wire_sz, sid_sz, &written) != YAWT_Q_OK) return YAWT_WT_ERR_SHORT_BUFFER;

  // send_stream runs the QUIC MAX_STREAMS check before creating the stream, so a
  // limit failure leaves no partial state. (WT-level WT_MAX_STREAMS is not enforced.)
  YAWT_Q_IoVec_t iov = { .buf = hdr, .len = wire_sz + sid_sz };
  if (YAWT_q_con_send_stream(ctx->qcon, stream_id, &iov, 1, 0) != YAWT_Q_OK) {
    YAWT_LOG(YAWT_LOG_WARN, "wt: open_stream: send_stream failed for stream %lu (max_streams?)", stream_id);
    return YAWT_WT_ERR_INVALID_PARAM;
  }

  // Record the WT stream so send_data() carries raw payload (header already sent).
  YAWT_Q_StreamUserData_t *sud = YAWT_q_con_get_stream_userdata(ctx->qcon, stream_id);
  if (!sud) return YAWT_WT_ERR_INVALID_PARAM;
  YAWT_WT_Stream_t *wt_stream = calloc(1, sizeof(*wt_stream));
  if (!wt_stream) return YAWT_WT_ERR_SHORT_BUFFER;
  wt_stream->type = wire;
  wt_stream->session_id = session_id;
  wt_stream->session = session;
  wt_stream->hdr_complete = true;
  sud->user_data[YAWT_UD_WT] = wt_stream;

  if (dir == YAWT_WT_DIR_BIDI) session->open_streams_bidi++;
  else session->open_streams_uni++;
  // TODO: enforce the WT session-level WT_MAX_STREAMS limit (draft-15 §5.3) once
  // flow-control negotiation lands; only QUIC's MAX_STREAMS is checked today.

  *out_stream_id = stream_id;
  YAWT_LOG(YAWT_LOG_INFO, "wt: opened %s stream %lu for session %lu",
           dir == YAWT_WT_DIR_BIDI ? "bidi" : "uni", stream_id, session_id);
  return YAWT_WT_OK;
}

YAWT_WT_Error_t YAWT_wt_send_data(YAWT_WT_Context_t *ctx,
                                    uint64_t session_id,
                                    uint64_t stream_id,
                                    const uint8_t *data, size_t len,
                                    int fin) {
  if (!ctx || !ctx->qcon) return YAWT_WT_ERR_INVALID_PARAM;

  YAWT_WT_Session_t *session = _wt_session_find(ctx, session_id);
  if (!session) return YAWT_WT_ERR_NO_SESSION;

  YAWT_Q_StreamUserData_t *sud = YAWT_q_con_get_stream_userdata(ctx->qcon, stream_id);
  if (!sud) return YAWT_WT_ERR_INVALID_PARAM;

  // WT data stream (uni/bidi): send raw payload. The WT header was written once —
  // by YAWT_wt_open_stream() on the initiator, or by the receive path for a
  // peer-initiated stream (both mark hdr_complete). No H3 metadata is involved.
  if (_wt_stream_defined(sud)) {
    YAWT_WT_Stream_t *wt_stream = sud->user_data[YAWT_UD_WT];
    if (wt_stream->type == YAWT_WT_STREAM_WIRE_WT_UNI ||
        wt_stream->type == YAWT_WT_STREAM_WIRE_WT_BIDI) {
      YAWT_Q_IoVec_t iov = { .buf = data, .len = len };
      if (YAWT_q_con_send_stream(ctx->qcon, stream_id, &iov, 1, fin) != YAWT_Q_OK)
        return YAWT_WT_ERR_SHORT_BUFFER;
      session->sent_data += len;
      return YAWT_WT_OK;
    }
  }

  // Otherwise this is the CONNECT stream — send as DATA frames via H3.
  YAWT_H3_Context_t *h3 = YAWT_q_con_get_user_data(ctx->qcon, YAWT_UD_H3);
  if (!h3) return YAWT_WT_ERR_INVALID_PARAM;
  YAWT_H3_Stream_t *h3_stream = sud->user_data[YAWT_UD_H3];
  if (!h3_stream) return YAWT_WT_ERR_INVALID_PARAM;
  if (h3_stream->type == YAWT_H3_STREAM_WT_CONNECT) {
    // TODO: proper capsule encoding
    return YAWT_h3_send_data(h3, stream_id, data, len, fin) == YAWT_H3_OK ?
           YAWT_WT_OK : YAWT_WT_ERR_SHORT_BUFFER;
  }
  return YAWT_WT_ERR_INVALID_PARAM;
}

YAWT_WT_Error_t YAWT_wt_send_capsule(YAWT_WT_Context_t *ctx,
                                       uint64_t session_id,
                                       uint64_t capsule_type,
                                       const uint8_t *value, size_t len) {
  if (!ctx || !ctx->qcon) return YAWT_WT_ERR_INVALID_PARAM;

  YAWT_WT_Session_t *session = _wt_session_find(ctx, session_id);
  if (!session) return YAWT_WT_ERR_NO_SESSION;

  // Encode capsule
  uint8_t capsule_buf[4096];
  size_t capsule_len = YAWT_capsule_encode(capsule_type, value, len, capsule_buf, sizeof(capsule_buf));
  if (capsule_len == 0) {
    YAWT_LOG(YAWT_LOG_ERROR, "wt: failed to encode capsule type 0x%lx", capsule_type);
    return YAWT_WT_ERR_SHORT_BUFFER;
  }

  // Send as DATA frame on CONNECT stream
  YAWT_H3_Context_t *h3 = YAWT_q_con_get_user_data(ctx->qcon, YAWT_UD_H3);
  if (!h3) return YAWT_WT_ERR_INVALID_PARAM;

  return YAWT_h3_send_data(h3, session->connect_stream_id, capsule_buf, capsule_len, 0) == YAWT_H3_OK ?
         YAWT_WT_OK : YAWT_WT_ERR_SHORT_BUFFER;
}

int YAWT_wt_parse_capsule(YAWT_Capsule_Parser_t *parser,
                          const uint8_t *data, size_t len,
                          YAWT_WT_CapsuleType_t *type_out,
                          YAWT_WT_Capsule_t *capsule_out) {
  if (!parser || !data || !type_out || !capsule_out) return YAWT_CAPSULE_ERROR;

  memset(capsule_out, 0, sizeof(*capsule_out));

  int rc = YAWT_capsule_parse_feed(parser, data, len);
  if (rc != YAWT_CAPSULE_OK) return rc;

  const uint8_t *payload;
  size_t payload_len;
  rc = YAWT_capsule_get_current(parser, (uint64_t *)type_out, &payload, &payload_len);
  if (rc != YAWT_CAPSULE_OK) return rc;

  YAWT_Q_ReadCursor_t cursor = {
    .data = (uint8_t *)payload,
    .len = payload_len,
    .cursor = 0,
    .err = YAWT_Q_OK,
  };

  switch (*type_out) {
    case YAWT_WT_CAPSULE_CLOSE_SESSION: {
      /* draft-ietf-webtrans-http3-15 §6: Application Error Code is fixed 32-bit BE, not a varint */
      if (payload_len < 4) return YAWT_CAPSULE_ERROR;
      capsule_out->close_session.app_error_code =
          ((uint32_t)payload[0] << 24) |
          ((uint32_t)payload[1] << 16) |
          ((uint32_t)payload[2] << 8)  |
          ((uint32_t)payload[3]);
      capsule_out->close_session.app_error_message = payload + 4;
      capsule_out->close_session.message_len = payload_len - 4;
      break;
    }

    case YAWT_WT_CAPSULE_DRAIN_SESSION:
      break;

    case YAWT_WT_CAPSULE_MAX_STREAMS_BIDI:
    case YAWT_WT_CAPSULE_MAX_STREAMS_UNI: {
      uint64_t max_streams;
      YAWT_q_varint_decode(&cursor, &max_streams);
      if (cursor.err != YAWT_Q_OK) return YAWT_CAPSULE_ERROR;
      capsule_out->max_streams.maximum_streams = max_streams;
      capsule_out->max_streams.is_bidi = (*type_out == YAWT_WT_CAPSULE_MAX_STREAMS_BIDI);
      break;
    }

    case YAWT_WT_CAPSULE_STREAMS_BLOCKED_BIDI:
    case YAWT_WT_CAPSULE_STREAMS_BLOCKED_UNI: {
      uint64_t max_streams;
      YAWT_q_varint_decode(&cursor, &max_streams);
      if (cursor.err != YAWT_Q_OK) return YAWT_CAPSULE_ERROR;
      capsule_out->streams_blocked.maximum_streams = max_streams;
      capsule_out->streams_blocked.is_bidi = (*type_out == YAWT_WT_CAPSULE_STREAMS_BLOCKED_BIDI);
      break;
    }

    case YAWT_WT_CAPSULE_MAX_DATA: {
      uint64_t max_data;
      YAWT_q_varint_decode(&cursor, &max_data);
      if (cursor.err != YAWT_Q_OK) return YAWT_CAPSULE_ERROR;
      capsule_out->max_data.maximum_data = max_data;
      break;
    }

    case YAWT_WT_CAPSULE_DATA_BLOCKED: {
      uint64_t max_data;
      YAWT_q_varint_decode(&cursor, &max_data);
      if (cursor.err != YAWT_Q_OK) return YAWT_CAPSULE_ERROR;
      capsule_out->data_blocked.maximum_data = max_data;
      break;
    }

    case YAWT_WT_CAPSULE_DATAGRAM:
      capsule_out->datagram.payload = payload;
      capsule_out->datagram.payload_len = payload_len;
      break;

    default:
      YAWT_LOG(YAWT_LOG_DEBUG, "wt: unknown capsule type 0x%u, skipping", *type_out);
      break;
  }

  return YAWT_CAPSULE_OK;
}
