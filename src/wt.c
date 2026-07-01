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
#include "capsule.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>

//TODO base this off security module, move to Slab
#define WT_MAX_SESSIONS 16

YAWT_WT_Context_t *_wt_conn_create(YAWT_Q_Context_t *qcon) {
  YAWT_WT_Context_t *ctx = calloc(1, sizeof(YAWT_WT_Context_t));
  if (!ctx) {
    YAWT_LOG(YAWT_LOG_ERROR, "wt: OOM allocating context");
    return NULL;
  }
  ctx->qcon = qcon;
  ctx->h3con = YAWT_q_con_get_user_data(qcon, YAWT_UD_H3);
  ctx->nsessions = WT_MAX_SESSIONS;
  ctx->sessions = calloc(ctx->nsessions, sizeof(YAWT_WT_Session_t));
  if (!ctx->sessions) {
    YAWT_LOG(YAWT_LOG_ERROR, "wt: OOM allocating session pool");
    free(ctx);
    return NULL;
  }
  YAWT_LOG(YAWT_LOG_INFO, "wt: context created");
  return ctx;
}

static void _wt_conn_destroy(YAWT_WT_Context_t *ctx) {
  if (!ctx) return;
  for (uint64_t i = 0; i < ctx->nsessions; i++) {
    if (ctx->sessions[i].in_use) {
      YAWT_LOG(YAWT_LOG_INFO, "wt: terminating session %lu on context destroy",
               ctx->sessions[i].session_id);
      ctx->sessions[i].in_use = false;
    }
  }
  free(ctx->sessions);
  free(ctx);
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

static YAWT_WT_Session_t *_wt_session_create(YAWT_WT_Context_t *ctx, uint64_t session_id) {
  if (!ctx) return NULL;
  // Check if session already exists
  YAWT_WT_Session_t *existing = _wt_session_find(ctx, session_id);
  if (existing) {
    YAWT_LOG(YAWT_LOG_WARN, "wt: session %lu already exists", session_id);
    return existing;
  }
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

static YAWT_WT_Stream_t *_wt_stream_get_or_create(
    YAWT_Q_StreamUserData_t *sud,
    uint64_t stream_id) {
  
  YAWT_WT_Stream_t *wt_stream = sud->user_data[YAWT_UD_WT];
  if (!wt_stream) {
    wt_stream = calloc(1, sizeof(YAWT_WT_Stream_t));
    if (!wt_stream) {
      YAWT_LOG(YAWT_LOG_ERROR, "wt: OOM allocating stream metadata");
      return NULL;
    }
    wt_stream->stream_id = stream_id;
    sud->user_data[YAWT_UD_WT] = wt_stream;
  }
  return wt_stream;
}

static YAWT_WT_Error_t _wt_buffer_session_id(
    YAWT_WT_Stream_t *wt_stream,
    const YAWT_Q_Frame_Stream_t *chunk,
    size_t *cursor) {
  
  size_t start = *cursor;
  
  // Skip signal byte on first chunk
  if (wt_stream->stream_offset == 0 && start < chunk->data_len) {
    start++;  // Skip 0x41 or 0x54
  }
  
  size_t avail = chunk->data_len - start;
  if (avail == 0) {
    *cursor = chunk->data_len;
    wt_stream->stream_offset += chunk->data_len;
    return YAWT_WT_OK;
  }
  
  // Accumulate bytes
  size_t take = avail;
  if (take > sizeof(wt_stream->hdr) - wt_stream->hdr_accumulated) {
    take = sizeof(wt_stream->hdr) - wt_stream->hdr_accumulated;
  }
  memcpy(wt_stream->hdr + wt_stream->hdr_accumulated, chunk->data + start, take);
  wt_stream->hdr_accumulated += take;
  wt_stream->stream_offset += chunk->data_len;
  
  // Try to decode varint
  YAWT_Q_ReadCursor_t rc = {
    .data = wt_stream->hdr,
    .len = wt_stream->hdr_accumulated,
    .cursor = 0,
    .err = YAWT_Q_OK,
  };
  YAWT_q_varint_decode(&rc, &wt_stream->session_id);
  if (rc.err == YAWT_Q_OK) {
    wt_stream->session_id_complete = true;
  }
  
  *cursor = chunk->data_len;
  return YAWT_WT_OK;
}

YAWT_WT_Error_t YAWT_wt_on_event(YAWT_Q_Context_t *con,
                                    YAWT_Q_EventType_t event,
                                    YAWT_Q_EventParam_t param) {
  if (!con) return YAWT_WT_ERR_INVALID_PARAM;

  if (event == YAWT_Q_EVT_CONNECTED) {
    YAWT_WT_Context_t *ctx = _wt_conn_create(con);
    if (!ctx) return YAWT_WT_ERR_INVALID_PARAM;
    YAWT_q_con_set_user_data(con, YAWT_UD_WT, ctx);
    return YAWT_WT_OK;
  }

  YAWT_WT_Context_t *ctx = YAWT_q_con_get_user_data(con, YAWT_UD_WT);

  if (event == YAWT_Q_EVT_CLOSE) {
    if (ctx) {
      _wt_conn_destroy(ctx);
      YAWT_q_con_set_user_data(con, YAWT_UD_WT, NULL);
    }
    return YAWT_WT_OK;
  }

  if (!ctx) return YAWT_WT_OK;

  switch (event) {
    case YAWT_Q_EVT_STREAM: {
      const YAWT_Q_Frame_Stream_t *chunk = param.P_EVT_STREAM.frame;
      if (!chunk) return YAWT_WT_ERR_INVALID_PARAM;

      YAWT_Q_StreamUserData_t *sud = param.P_EVT_STREAM.stream_ud;
      if (!sud) {
        YAWT_LOG(YAWT_LOG_WARN, "wt: EVT_STREAM with NULL stream_ud");
        return YAWT_WT_OK;
      }
      YAWT_H3_Stream_t *h3_stream = sud->user_data[YAWT_UD_H3];
      if (!h3_stream) {
        return YAWT_WT_OK;
      }

      switch (h3_stream->type) {
        case YAWT_H3_STREAM_WT: {
          YAWT_WT_Stream_t *wt_stream = _wt_stream_get_or_create(sud, chunk->stream_id);
          if (!wt_stream) return YAWT_WT_ERR_INVALID_PARAM;

          size_t cursor = 0;
          _wt_buffer_session_id(wt_stream, chunk, &cursor);

          if (wt_stream->session_id_complete && !wt_stream->session) {
            if ((wt_stream->session_id & 0x03) != 0x00) {
              YAWT_LOG(YAWT_LOG_ERROR, "wt: session_id %lu is not a client-initiated bidi stream",
                       wt_stream->session_id);
              YAWT_q_con_close(con, YAWT_ERR_H3_ID_ERROR);
              return YAWT_WT_ERR_INVALID_PARAM;
            }

            YAWT_WT_Session_t *session = _wt_session_find(ctx, wt_stream->session_id);
            if (session) {
              wt_stream->session = session;
            }
          }

          if (wt_stream->session && cursor < chunk->data_len) {
            _wt_emit_event(ctx, wt_stream->session, YAWT_WT_EVT_STREAM_DATA, (YAWT_WT_EventParam_t){
              .P_EVT_STREAM_DATA = {
                .session_id = wt_stream->session_id,
                .stream_id = chunk->stream_id,
                .data = chunk->data + cursor,
                .len = chunk->data_len - cursor,
                .fin = chunk->fin,
              }
            });
          }
          return YAWT_WT_OK;
        }
        default:
          return YAWT_WT_OK;
      }
    }
    case YAWT_Q_EVT_DATAGRAM: {
      return YAWT_WT_OK;
    }
    default:
      return YAWT_WT_OK;
  }
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
    case YAWT_H3_EVT_DATA: {
      uint64_t stream_id = param.P_EVT_DATA.stream_id;
      const uint8_t *data = param.P_EVT_DATA.data;
      size_t len = param.P_EVT_DATA.len;

      YAWT_Q_StreamUserData_t *sud = YAWT_q_con_get_stream_userdata(qcon, stream_id);
      YAWT_H3_Stream_t *h3_stream = sud ? sud->user_data[YAWT_UD_H3] : NULL;
      if (!h3_stream || h3_stream->type != YAWT_H3_STREAM_WT_CONNECT) {
        return YAWT_WT_OK;
      }

      YAWT_WT_Stream_t *wt_stream = _wt_stream_get_or_create(sud, stream_id);
      if (!wt_stream) return YAWT_WT_ERR_INVALID_PARAM;

      if (!wt_stream->session_id_complete) {
        wt_stream->session_id = stream_id;
        wt_stream->session_id_complete = true;
        wt_stream->session = _wt_session_find(ctx, stream_id);
      }

      YAWT_WT_Session_t *session = wt_stream->session;
      if (!session) return YAWT_WT_OK;

      YAWT_WT_CapsuleType_t type;
      YAWT_WT_Capsule_t capsule;
      int rc = YAWT_wt_parse_capsule(&wt_stream->capsule_parser, data, len, &type, &capsule);
      if (rc == YAWT_CAPSULE_OK) {
        _wt_emit_event(ctx, session, YAWT_WT_EVT_CAPSULE_RECEIVED, (YAWT_WT_EventParam_t){
          .P_EVT_CAPSULE_RECEIVED = {
            .session_id = wt_stream->session_id,
            .stream_id = stream_id,
            .type = type,
            .capsule = capsule,
          }
        });
      }
      return YAWT_WT_OK;
    }
    default:
      return YAWT_WT_OK;
  }
}

YAWT_WT_Error_t YAWT_wt_send_data(YAWT_WT_Context_t *ctx,
                                    uint64_t session_id,
                                    uint64_t stream_id,
                                    const uint8_t *data, size_t len,
                                    int fin) {
  if (!ctx || !ctx->qcon) return YAWT_WT_ERR_INVALID_PARAM;

  YAWT_WT_Session_t *session = _wt_session_find(ctx, session_id);
  if (!session) return YAWT_WT_ERR_NO_SESSION;

  // Look up H3 stream to determine type
  YAWT_H3_Context_t *h3 = YAWT_q_con_get_user_data(ctx->qcon, YAWT_UD_H3);
  if (!h3) return YAWT_WT_ERR_INVALID_PARAM;

  YAWT_Q_StreamUserData_t *sud = YAWT_q_con_get_stream_userdata(ctx->qcon, stream_id);
  YAWT_H3_Stream_t *h3_stream = sud ? sud->user_data[YAWT_UD_H3] : NULL;
  if (!h3_stream) return YAWT_WT_ERR_INVALID_PARAM;

  // Send data based on stream type
  if (h3_stream->type == YAWT_H3_STREAM_WT_CONNECT) {
    // Upgraded CONNECT — send as capsules in DATA frames
    // For now, just send raw data as DATA frames
    // TODO: proper capsule encoding
    return YAWT_h3_send_data(h3, stream_id, data, len, fin) == YAWT_H3_OK ?
           YAWT_WT_OK : YAWT_WT_ERR_SHORT_BUFFER;
  } else {
    // WT_UNI or WT_BIDI — send raw data
    // TODO: implement raw stream sending
    return YAWT_WT_ERR_INVALID_PARAM;
  }
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
      uint64_t error_code;
      YAWT_q_varint_decode(&cursor, &error_code);
      if (cursor.err != YAWT_Q_OK) return YAWT_CAPSULE_ERROR;
      capsule_out->close_session.app_error_code = (uint32_t)error_code;
      capsule_out->close_session.app_error_message = payload + cursor.cursor;
      capsule_out->close_session.message_len = payload_len - cursor.cursor;
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
