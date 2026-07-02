#include "h3.h"
#include "h3_header.h"
#include "qpack.h"
#include "quic.h"   // YAWT_q_varint_* + YAWT_Q_ReadCursor_t — H3 reuses the QUIC varint codec
#include "quic_connection.h"  // YAWT_Q_Context_t, user_data slots, event types
#include "impl/quic_types.h"  // YAWT_Q_Context_t definition
#include "impl/h3_types.h"    // YAWT_H3_Context_t and YAWT_H3_Stream_t definitions
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
  [YAWT_H3_IDX_WT_ENABLED_DRAFT02]          = 0x2b603742, /**< WebTransport enabled (draft-02) */
  [YAWT_H3_IDX_H3_DATAGRAM_DRAFT04]         = 0x00ffd277, /**< HTTP/3 datagrams (draft-04) */
};

static const char *_h3_setting_names[YAWT_H3_NUM_SETTINGS] = {
  [YAWT_H3_IDX_QPACK_MAX_TABLE_CAPACITY]  = "QPACK_MAX_TABLE_CAPACITY",
  [YAWT_H3_IDX_MAX_FIELD_SECTION_SIZE]    = "MAX_FIELD_SECTION_SIZE",
  [YAWT_H3_IDX_QPACK_BLOCKED_STREAMS]     = "QPACK_BLOCKED_STREAMS",
  [YAWT_H3_IDX_ENABLE_CONNECT_PROTOCOL]   = "ENABLE_CONNECT_PROTOCOL",
  [YAWT_H3_IDX_H3_DATAGRAM]               = "H3_DATAGRAM",
  [YAWT_H3_IDX_WT_ENABLED]                = "WT_ENABLED",
  [YAWT_H3_IDX_WT_MAX_SESSIONS]           = "WT_MAX_SESSIONS",
  [YAWT_H3_IDX_WT_INITIAL_MAX_STREAMS_UNI]  = "WT_INITIAL_MAX_STREAMS_UNI",
  [YAWT_H3_IDX_WT_INITIAL_MAX_STREAMS_BIDI] = "WT_INITIAL_MAX_STREAMS_BIDI",
  [YAWT_H3_IDX_WT_INITIAL_MAX_DATA]         = "WT_INITIAL_MAX_DATA",
  [YAWT_H3_IDX_WT_ENABLED_DRAFT02]          = "WT_ENABLED_DRAFT02",
  [YAWT_H3_IDX_H3_DATAGRAM_DRAFT04]         = "H3_DATAGRAM_DRAFT04",
};


static const char *_h3_setting_name(YAWT_H3_SettingIdx_t idx) {
  if (idx < 0 || idx >= YAWT_H3_NUM_SETTINGS) return "unknown";
  return _h3_setting_names[idx];
}

static int _h3_setting_wire_to_idx(uint64_t wire_id, YAWT_H3_SettingIdx_t *out) {
  for (int i = 0; i < YAWT_H3_NUM_SETTINGS; i++) {
    if (_h3_setting_wire_ids[i] == wire_id) {
      *out = (YAWT_H3_SettingIdx_t)i;
      return 0;
    }
  }
  return -1;
}

static YAWT_H3_WT_Version_t _h3_detect_wt_version(const YAWT_H3_Settings_t *peer) {
  if (YAWT_h3_setting_isset(peer, YAWT_H3_IDX_WT_ENABLED_DRAFT02))
    return YAWT_H3_WT_VERSION_DRAFT02;
  return YAWT_H3_WT_VERSION_DEFAULT;
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
    YAWT_LOG(YAWT_LOG_DEBUG, "h3: encoded setting %s (wire 0x%lx) = %lu, total bytes=%zu",
             _h3_setting_name((YAWT_H3_SettingIdx_t)i), _h3_setting_wire_ids[i], settings->vals[i], off);
  }

  *written = off;
  return YAWT_H3_OK;
}

static YAWT_H3_Context_t *_h3_conn_create(YAWT_Q_Context_t *con) {
  YAWT_H3_Context_t *h3 = calloc(1, sizeof(*h3));
  if (!h3) return NULL;

  h3->qcon = con;
  return h3;
}

static void _h3_conn_destroy(YAWT_H3_Context_t *h3) {
  if (!h3) return;
  YAWT_Q_Context_t *con = YAWT_h3_get_qcon(h3);
  if (con) {
    YAWT_q_con_set_user_data(con, YAWT_UD_H3, NULL);
  }
  free(h3->local_settings);
  free(h3->peer_settings);
  free(h3);
}

static void _h3_stream_destroy(YAWT_H3_Stream_t *stream) {
  if (!stream) return;
  if (stream->frame.payload_blob != NULL) {
    ANB_blob_destroy(stream->frame.payload_blob);
  }
  if (stream->request_headers) {
    YAWT_h3_header_fields_destroy(stream->request_headers);
  }
  if (stream->response_headers) {
    YAWT_h3_header_fields_destroy(stream->response_headers);
  }
  free(stream);
}

static YAWT_H3_Stream_t *_h3_stream_get_or_create(YAWT_Q_StreamUserData_t *sud) {
  YAWT_H3_Stream_t *stream = sud->user_data[YAWT_UD_H3];
  if (!stream) {
    stream = (YAWT_H3_Stream_t *)malloc(sizeof(YAWT_H3_Stream_t));
    if (!stream) return NULL;
    memset(stream, 0, sizeof(*stream));
    stream->id = sud->stream_id;
    stream->type = YAWT_H3_STREAM_UNASSIGNED;
    sud->user_data[YAWT_UD_H3] = stream;
  }
  return stream;
}

// Resolve a stream's role from its leading stream-type varint (RFC 9114
// §6.2, RFC 9204 §4.2) or WT signal (draft-15 §4.2/4.3), accumulating across
// chunks into stream->hdr. On success sets stream->type and reports via
// *consumed how many bytes of THIS chunk were the prefix — the rest is
// stream body the caller forwards on.
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

  YAWT_Q_ReadCursor_t rc = {0};
  rc.data = stream->hdr;
  rc.len = stream->accumulated;
  uint64_t wire = 0;
  YAWT_q_varint_decode(&rc, &wire);
  if (rc.err != YAWT_Q_OK) {
    *consumed = take;
    return YAWT_H3_ERR_INCOMPLETE;
  }

  bool is_bidi = (chunk->stream_type == YAWT_Q_C_BIDI || chunk->stream_type == YAWT_Q_S_BIDI);

  if (is_bidi) {
    if (wire == YAWT_H3_STREAM_WIRE_WT_BIDI) {
      stream->type = YAWT_H3_STREAM_WT;
      *consumed = (size_t)rc.cursor - accumulated_before;
      YAWT_LOG(YAWT_LOG_INFO, "h3: stream %lu is WT bidi (0x%lx)", chunk->stream_id, wire);
      return YAWT_H3_OK;
    } else {
      stream->type = YAWT_H3_STREAM_FRAME;
      *consumed = 0;
      stream->accumulated = 0;
      YAWT_LOG(YAWT_LOG_DEBUG, "h3: stream %lu is normal H3 bidi (frame type 0x%lx)", chunk->stream_id, wire);
      return YAWT_H3_OK;
    }
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
    case YAWT_H3_STREAM_WIRE_WT_UNI:
      stream->type = YAWT_H3_STREAM_WT;
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
    YAWT_H3_Context_t *h3,
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


// Check if decoded headers indicate a WT CONNECT upgrade (draft-15 §3.2).
// Request streams are always client-initiated bidi. The distinction between
// request (server receives) and response (client receives) is the connection role.
// Server side: marks stream as WT_CONNECT_PENDING if :method=CONNECT and :protocol=webtransport-h3.
// Client side: upgrades WT_CONNECT_PENDING to WT_CONNECT on 2xx response, or reverts to FRAME on non-2xx.
static void _process_wt_connect_upgrade(YAWT_H3_Context_t *con, 
            YAWT_Q_StreamUserData_t *sud) {

  YAWT_H3_Stream_t *stream = sud->user_data[YAWT_UD_H3];
  bool is_client_bidi = ((stream->id) & 0x03) == YAWT_Q_C_BIDI;
  YAWT_LOG(YAWT_LOG_DEBUG, "WT Connect Upgrade Check");

  if (!is_client_bidi) {
    YAWT_LOG(YAWT_LOG_DEBUG, "h3: stream %lu is not client-initiated bidi, skipping WT upgrade check", stream->id);
    return;
  }

  bool is_server = (con->qcon->role == YAWT_Q_ROLE_SERVER);
  bool is_upgrade_related = false;

  if (is_server) {
    const char *expected_protocol = (con->wt_version == YAWT_H3_WT_VERSION_DRAFT02)
        ? "webtransport" : "webtransport-h3";
    YAWT_H3_Header_Field_t method = YAWT_h3_header_find_str(stream->request_headers, ":method");
    YAWT_H3_Header_Field_t protocol = YAWT_h3_header_find_str(stream->request_headers, ":protocol");

    if (method.name && strncmp(method.value, "CONNECT", method.value_len) == 0 &&
        protocol.name && protocol.value_len == strlen(expected_protocol) &&
        strncmp(protocol.value, expected_protocol, protocol.value_len) == 0) {
      stream->type = YAWT_H3_STREAM_WT_CONNECT_PENDING;
      YAWT_LOG(YAWT_LOG_INFO, "h3: stream %lu is WT CONNECT pending upgrade", stream->id);
      is_upgrade_related = true;
    }
  } else {
    // Client receives response from server
    YAWT_H3_Header_Field_t status = YAWT_h3_header_find_str(stream->request_headers, ":status");
    if (status.name && stream->type == YAWT_H3_STREAM_WT_CONNECT_PENDING) {
      if (status.value_len > 0 && status.value[0] == '2') {
        stream->type = YAWT_H3_STREAM_WT_CONNECT;
        YAWT_LOG(YAWT_LOG_INFO, "h3: stream %lu upgraded to WT CONNECT (2xx response)", stream->id);
      } else {
        stream->type = YAWT_H3_STREAM_FRAME;
        YAWT_LOG(YAWT_LOG_INFO, "h3: stream %lu CONNECT rejected (status %.*s)",
                 stream->id, (int)status.value_len, status.value);
      }
      is_upgrade_related = true;
    }
  }

  if (is_upgrade_related) {
    // App can observe the stream type to determine if CONNECT was accepted or rejected
    YAWT_H3_EventParam_t param;
    param.P_EVT_WT_UPGRADE.stream_id = stream->id;
    con->app_handler(con, YAWT_H3_EVT_WT_UPGRADE, param);
  }
}

// Dispatch a completed buffered frame (SETTINGS, HEADERS) based on stream type.
// Returns true on success, false on protocol error (caller should close connection).
static bool _dispatch_buffered_frame(YAWT_H3_Context_t *con,
                                       YAWT_Q_StreamUserData_t *sud) {

  YAWT_H3_Stream_t *stream = sud->user_data[YAWT_UD_H3];
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
          con->wt_version = _h3_detect_wt_version(con->peer_settings);
          YAWT_LOG(YAWT_LOG_INFO, "h3: peer settings decoded (val_set=0x%lx, wt_version=%d)",
                   con->peer_settings->val_set, con->wt_version);
          con->app_handler(con, YAWT_H3_EVT_SETTINGS, (YAWT_H3_EventParam_t){
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
          YAWT_LOG(YAWT_LOG_DEBUG, "h3: HEADERS frame on stream %lu, payload_len=%lu", stream->id, f->payload_len);
          const uint8_t *hb_data = ANB_blob_data(f->payload_blob);
          for (size_t i = 0; i < (size_t)f->payload_len && i < 64; i++) {
            YAWT_LOG(YAWT_LOG_DEBUG, "  hb[%zu] = 0x%02x", i, hb_data[i]);
          }
          YAWT_QPACK_Error_t qerr = YAWT_qpack_decode_header_block(
              hb_data, (size_t)f->payload_len, stream->request_headers);
          if (qerr != YAWT_QPACK_OK) {
            YAWT_LOG(YAWT_LOG_ERROR, "h3: QPACK decode failed on stream %lu: %d",
                     stream->id, qerr);
            YAWT_h3_header_fields_destroy(stream->request_headers);
            stream->request_headers = NULL;
            return false;
          }
          YAWT_LOG(YAWT_LOG_DEBUG, "h3: headers decoded on stream %lu", stream->id);
          ANB_SlabIter_t iter = {0};
          YAWT_H3_Header_Field_t field;
          while ((field = YAWT_h3_header_iter(stream->request_headers, &iter)).name != NULL) {
            YAWT_LOG(YAWT_LOG_DEBUG, "  header: %.*s = %.*s", 
                     (int)field.name_len, field.name,
                     (int)field.value_len, field.value);
          }

          _process_wt_connect_upgrade(con, sud);

          con->app_handler(con, YAWT_H3_EVT_HEADERS, (YAWT_H3_EventParam_t){
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

YAWT_H3_Error_t YAWT_h3_parse_frame(YAWT_H3_Context_t *h3con,
                                    const YAWT_Q_Frame_Stream_t *chunk,
                                    YAWT_H3_Stream_t *stream,
                                    size_t *cursor) {
  if (!h3con || !chunk || !stream || !cursor) {
    return YAWT_H3_ERR_INVALID_PARAM;
  }

  // Frame lifecycle: if the previous frame completed (parsed=true), wipe only
  // the per-frame state to prepare for the next frame header. This does NOT
  // touch stream->type or the stream-type accumulation buffer (stream->hdr /
  // stream->accumulated) — those persist for the stream's entire lifetime.
  // RFC 9114 §6.2: the stream-type varint is sent once at the start of a uni
  // stream and never repeated. The frame struct is per-frame; the stream type
  // is per-stream.
  if (stream->frame.parsed) {
    if (stream->frame.payload_blob) {
      ANB_blob_destroy(stream->frame.payload_blob);
    }
    memset(&stream->frame, 0, sizeof(YAWT_H3_Frame_t));
  }

  YAWT_LOG(YAWT_LOG_DEBUG, "h3: stream %lu received chunk: offset=%lu, len=%zu, fin=%d",
           chunk->stream_id, chunk->offset, chunk->data_len, chunk->fin);

  // Stream type resolution: runs exactly once per stream lifetime. The stream-type
  // varint (RFC 9114 §6.2) or WT signal (draft-15 §4.2/4.3) is consumed from the
  // first chunk(s) via _gather_h3_stream_type() and never re-sent. After this
  // block, stream->type is stable for all subsequent calls on this stream.
  if (stream->type == YAWT_H3_STREAM_UNASSIGNED) {
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
    
    YAWT_LOG(YAWT_LOG_INFO, "h3: stream %lu resolved type %d", chunk->stream_id, stream->type);
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
    case YAWT_H3_STREAM_CONTROL:
    case YAWT_H3_STREAM_WT_CONNECT: {
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
        // for decode. DATA and unknown frames stream through without buffering —
        // the frame header (type + length) is still parsed here, but payload
        // flows directly to the app via _handle_rx_stream_frame() in the caller.
        // This avoids copying large request/response bodies.
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
          YAWT_LOG(YAWT_LOG_DEBUG, "h3: buffering frame type 0x%lx, payload_len=%lu, stream_id=%lu",
                   f->type, f->payload_len, stream->id);
        }
      }
      if (f->payload_blob) {
        size_t avail = chunk->data_len - *cursor;
        uint64_t need = f->payload_len - f->accumulated;
        size_t n = (need < avail) ? (size_t)need : avail;
        ANB_blob_push(f->payload_blob, chunk->data + *cursor, n);
        f->accumulated += n;
        *cursor += n;
        if (f->accumulated < f->payload_len) {
          return YAWT_H3_ERR_INCOMPLETE;
        }
        f->parsed = true;
      }
      return YAWT_H3_OK;
    }

    case YAWT_H3_STREAM_QPACK_ENCODER:
    case YAWT_H3_STREAM_QPACK_DECODER:
    case YAWT_H3_STREAM_UNKNOWN:
    case YAWT_H3_STREAM_WT:
      // Drain: advance cursor to end, no H3 frames on these streams
      // WT streams are handled by the WT layer via YAWT_wt_on_event()
      *cursor = chunk->data_len;
      return YAWT_H3_IGNORED;

    default:
      YAWT_LOG(YAWT_LOG_ERROR, "h3: unhandled stream type %d for stream_id=%lu",
               stream->type, chunk->stream_id);
      return YAWT_H3_ERR_MALFORMED;
  }
}

void _handle_rx_stream_frame(
    YAWT_H3_Context_t *con,
    const YAWT_Q_Frame_Stream_t *chunk,
    YAWT_H3_Stream_t *stream,
    size_t *cursor,
    int chunk_fin) {

  YAWT_H3_Frame_t *f = &stream->frame;
  size_t avail = chunk->data_len - *cursor;

  if (avail == 0) return;

  if (f->type == YAWT_H3_FRAME_DATA && f->payload_len > 0) {
    uint64_t need = f->payload_len - f->accumulated;
    size_t n = (need < avail) ? (size_t)need : avail;
    int is_last = (f->accumulated + n >= f->payload_len) && chunk_fin;

    con->app_handler(con, YAWT_H3_EVT_DATA, (YAWT_H3_EventParam_t){
      .P_EVT_DATA = { .stream_id = stream->id, .data = chunk->data + *cursor, .len = n, .fin = is_last }
      });

    f->accumulated += n;
    *cursor += n;
  } else {
    YAWT_LOG(YAWT_LOG_INFO, "h3: skipping %lu bytes of unknown frame type 0x%lx on stream %lu",
             f->payload_len - f->accumulated, f->type, stream->id);
    uint64_t need = f->payload_len - f->accumulated;
    size_t n = (need < avail) ? (size_t)need : avail;
    f->accumulated += n;
    *cursor += n;
  }
}



YAWT_H3_Error_t YAWT_h3_on_event(YAWT_Q_Context_t *con, YAWT_Q_EventType_t event,
                                   YAWT_Q_EventParam_t param) {

  if (event == YAWT_Q_EVT_CONNECTED) {
    YAWT_H3_Context_t *h3 = _h3_conn_create(con);
    h3->local_settings = calloc(1, sizeof(YAWT_H3_Settings_t));
    if (!h3->local_settings) {
      YAWT_LOG(YAWT_LOG_ERROR, "h3: OOM allocating local_settings");
      abort();
    }

    const YAWT_H3_SecurityPolicy_t *h3_pol = YAWT_h3_security_get();
    YAWT_h3_setting_set(h3->local_settings, YAWT_H3_IDX_MAX_FIELD_SECTION_SIZE, h3_pol->max_field_section_size);

    const YAWT_WT_SecurityPolicy_t *wt_pol = YAWT_wt_security_get();
    if (wt_pol->max_sessions > 0) {
      YAWT_h3_setting_set(h3->local_settings, YAWT_H3_IDX_WT_ENABLED_DRAFT02, 1);
      YAWT_h3_setting_set(h3->local_settings, YAWT_H3_IDX_H3_DATAGRAM_DRAFT04, 1);
    }

    YAWT_h3_setting_set(h3->local_settings, YAWT_H3_IDX_QPACK_MAX_TABLE_CAPACITY, 0);
    YAWT_h3_setting_set(h3->local_settings, YAWT_H3_IDX_QPACK_BLOCKED_STREAMS, 0);
    YAWT_q_con_set_user_data(con, YAWT_UD_H3, h3);
    YAWT_h3_send_settings(h3);
    YAWT_h3_open_qpack_streams(h3);
    return YAWT_H3_OK;
  }

  YAWT_H3_Context_t *h3 = YAWT_q_con_get_user_data(con, YAWT_UD_H3);
  if (!h3) return YAWT_H3_IGNORED;
  if (!h3->app_handler) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: no app handler installed for event %d", event);
    return YAWT_H3_ERR_NO_APP_HANDLER;
  }

  switch (event) {
    case YAWT_Q_EVT_STREAM: {
      YAWT_Q_StreamUserData_t *sud = param.P_EVT_STREAM.stream_ud;
      if (!sud) {
        YAWT_LOG(YAWT_LOG_ERROR, "h3: EVT_STREAM with NULL stream_ud");
        return YAWT_H3_ERR_INVALID_PARAM;
      }
      const YAWT_Q_Frame_Stream_t *chunk = param.P_EVT_STREAM.frame;
      size_t cursor = 0;

      YAWT_H3_Stream_t *stream = _h3_stream_get_or_create(sud);
      if (!stream) {
        YAWT_LOG(YAWT_LOG_ERROR, "h3: failed to allocate stream metadata for stream_id=%lu", chunk->stream_id);
        return YAWT_H3_ERR_INVALID_PARAM;
      }

      while (cursor < chunk->data_len) {
        YAWT_H3_Error_t err = YAWT_h3_parse_frame(h3, chunk, stream, &cursor);

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
        if (stream->frame.payload_blob &&
            stream->frame.accumulated >= stream->frame.payload_len) {
          if (!_dispatch_buffered_frame(h3, sud)) {
            YAWT_LOG(YAWT_LOG_ERROR, "h3: protocol error on stream %lu", stream->id);
          }
          continue;
        }
        _handle_rx_stream_frame(h3, chunk, stream, &cursor, chunk->fin);
        if (stream->frame.hdr_size &&
            stream->frame.accumulated >= stream->frame.payload_len) {
          stream->frame.parsed = true;
        }
      }

      return YAWT_H3_OK;
    }
    case YAWT_Q_EVT_CLOSE: {
      h3->app_handler(h3, YAWT_H3_EVT_CLOSE, (YAWT_H3_EventParam_t){
        .P_EVT_CLOSE = { .error_code = 0, .reason = "connection closed" }
      });
      _h3_conn_destroy(h3);
      return YAWT_H3_OK;
    }
    case YAWT_Q_EVT_DATAGRAM: {
      h3->app_handler(h3, YAWT_H3_EVT_DATAGRAM, (YAWT_H3_EventParam_t){
        .P_EVT_DATAGRAM = {
          .data = param.P_EVT_DATAGRAM.data,
          .len = param.P_EVT_DATAGRAM.len,
        }
      });
      return YAWT_H3_OK;
    }
    default:
      return YAWT_H3_IGNORED;
  }
}

void YAWT_h3_set_event_handler(YAWT_H3_Context_t *con,
                                YAWT_H3_EventHandler_t handler) {
  if (con) {
    con->app_handler = handler;
  }
}

YAWT_Q_Context_t *YAWT_h3_get_qcon(const YAWT_H3_Context_t *con) {
  return con ? con->qcon : NULL;
}

YAWT_H3_Error_t YAWT_h3_core_stream_set(YAWT_H3_Context_t *h3,
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
      YAWT_LOG(YAWT_LOG_DEBUG, "h3: decoded setting %s id=0x%lx value=%lu", 
          _h3_setting_name(idx), id, value);  
    }
  }

  return YAWT_H3_OK;
}

// ---------------------------------------------------------------------------
// TX helpers — open control stream, send SETTINGS/HEADERS/DATA frames.
// ---------------------------------------------------------------------------

// Helper to open a unidirectional stream with a stream-type prefix.
// RFC 9114 §6.2: uni streams begin with a stream-type varint. This helper
// encodes that varint and prepends it to the caller's payload iov array.
// Used by YAWT_h3_send_settings (control stream) and YAWT_h3_open_qpack_streams
// (QPACK encoder/decoder streams).
static YAWT_H3_Error_t _h3_open_uni_stream(
    YAWT_H3_Context_t *h3,
    uint64_t wire_type,
    uint64_t stream_id,
    const YAWT_Q_IoVec_t *payload_iov,
    size_t payload_iov_count,
    int fin) {

  uint8_t stream_type_buf[8];
  uint64_t n;
  if (YAWT_q_varint_encode(wire_type, stream_type_buf, sizeof(stream_type_buf), &n) != YAWT_Q_OK)
    return YAWT_H3_ERR_SHORT_BUFFER;

  YAWT_LOG(YAWT_LOG_DEBUG, "h3: opening uni stream %lu with type 0x%lx (encoded as %lu bytes):",
           stream_id, wire_type, n);
  for (size_t i = 0; i < n; i++) {
    YAWT_LOG(YAWT_LOG_DEBUG, "  stream_type[%zu] = 0x%02x", i, stream_type_buf[i]);
  }

  // Prepend stream-type varint to caller's iov
  YAWT_Q_IoVec_t iov[1 + 4]; // max 4 payload iovs + 1 stream type
  if (payload_iov_count + 1 > sizeof(iov) / sizeof(iov[0]))
    return YAWT_H3_ERR_INVALID_PARAM;

  iov[0] = (YAWT_Q_IoVec_t){ stream_type_buf, n };
  for (size_t i = 0; i < payload_iov_count; i++) {
    iov[1 + i] = payload_iov[i];
  }

  YAWT_Err_t qerr = YAWT_q_con_send_stream(h3->qcon, stream_id, iov, 1 + payload_iov_count, fin);
  if (qerr != YAWT_Q_OK) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: failed to open uni stream %lu (type 0x%lx): %d",
             stream_id, wire_type, qerr);
    return YAWT_H3_ERR_INVALID_PARAM;
  }
  return YAWT_H3_OK;
}

YAWT_H3_Error_t YAWT_h3_send_settings(YAWT_H3_Context_t *h3) {
  if (!h3 || !h3->qcon || !h3->local_settings) return YAWT_H3_ERR_INVALID_PARAM;

  uint8_t settings_payload[256];
  size_t payload_len = 0;
  YAWT_H3_Error_t err = YAWT_h3_settings_encode(
      h3->local_settings, settings_payload, sizeof(settings_payload), &payload_len);
  if (err != YAWT_H3_OK) return err;

  uint8_t frame_hdr[H3_FRAME_MAX_HEADER_BYTES];
  size_t frame_hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_SETTINGS, payload_len, frame_hdr);
  if (frame_hdr_len == 0) return YAWT_H3_ERR_SHORT_BUFFER;

  uint64_t stream_id = (h3->qcon->role == YAWT_Q_ROLE_CLIENT) ? 2 : 3;
  YAWT_Q_IoVec_t payload_iov[2] = {
    { frame_hdr, frame_hdr_len },
    { settings_payload, payload_len }
  };

  // RFC 9114 §6.2.1: Control stream type is 0x00
  err = _h3_open_uni_stream(h3, YAWT_H3_STREAM_WIRE_CONTROL, stream_id, payload_iov, 2, 0);
  if (err != YAWT_H3_OK) return err;

  YAWT_h3_core_stream_set(h3, YAWT_H3_UNIQUE_STREAM_LOCAL_CONTROL, stream_id);
  YAWT_LOG(YAWT_LOG_INFO, "h3: sent SETTINGS on control stream %lu (%zu bytes)",
           stream_id, frame_hdr_len + payload_len);
  return YAWT_H3_OK;
}

YAWT_H3_Error_t YAWT_h3_open_qpack_streams(YAWT_H3_Context_t *h3) {
  if (!h3 || !h3->qcon) return YAWT_H3_ERR_INVALID_PARAM;

  // QPACK streams are unidirectional. Per RFC 9000 §2.1, unidirectional stream
  // IDs step by 4 within their own space: client-uni = 2, 6, 10, ...;
  // server-uni = 3, 7, 11, ... (low 2 bits: 0x2 = client-uni, 0x3 = server-uni).
  // Control stream is first (2 or 3), so QPACK encoder is the next uni ID
  // (6 or 7), and the decoder is the one after (10 or 11).
  uint64_t encoder_stream_id = (h3->qcon->role == YAWT_Q_ROLE_CLIENT) ? 6 : 7;
  uint64_t decoder_stream_id = (h3->qcon->role == YAWT_Q_ROLE_CLIENT) ? 10 : 11;

  // RFC 9204 §4.2: QPACK encoder stream type is 0x02
  YAWT_H3_Error_t err = _h3_open_uni_stream(h3, YAWT_H3_STREAM_WIRE_QPACK_ENCODER, encoder_stream_id, NULL, 0, 0);
  if (err != YAWT_H3_OK) return err;
  YAWT_h3_core_stream_set(h3, YAWT_H3_UNIQUE_STREAM_LOCAL_QPACK_ENCODER, encoder_stream_id);
  YAWT_LOG(YAWT_LOG_INFO, "h3: opened QPACK encoder stream %lu", encoder_stream_id);

  // RFC 9204 §4.2: QPACK decoder stream type is 0x03
  err = _h3_open_uni_stream(h3, YAWT_H3_STREAM_WIRE_QPACK_DECODER, decoder_stream_id, NULL, 0, 0);
  if (err != YAWT_H3_OK) return err;
  YAWT_h3_core_stream_set(h3, YAWT_H3_UNIQUE_STREAM_LOCAL_QPACK_DECODER, decoder_stream_id);
  YAWT_LOG(YAWT_LOG_INFO, "h3: opened QPACK decoder stream %lu", decoder_stream_id);

  return YAWT_H3_OK;
}

YAWT_H3_Error_t YAWT_h3_send_headers(YAWT_H3_Context_t *h3,
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

  /* This is dead code, does not belong here

  // Server side: if this stream is WT_CONNECT_PENDING and we're sending a 2xx
  // response, upgrade it to WT_CONNECT (draft-15 §3.2)
  YAWT_Q_StreamUserData_t *sud = YAWT_q_con_get_stream_userdata(h3->qcon, stream_id);
  YAWT_H3_Stream_t *stream = sud ? sud->user_data[YAWT_UD_H3] : NULL;
  if (stream && stream->type == YAWT_H3_STREAM_WT_CONNECT_PENDING) {
    YAWT_H3_Header_Field_t status = YAWT_h3_header_find_str(headers, ":status");
    if (status.name && status.value_len > 0 && status.value[0] == '2') {
      stream->type = YAWT_H3_STREAM_WT_CONNECT;
      YAWT_LOG(YAWT_LOG_INFO, "h3: stream %lu upgraded to WT CONNECT (sent 2xx response)", stream_id);
    } else {
      // Non-2xx response — revert to normal H3 stream
      stream->type = YAWT_H3_STREAM_FRAME;
      YAWT_LOG(YAWT_LOG_INFO, "h3: stream %lu CONNECT rejected (sent status %.*s)",
               stream_id, (int)status.value_len, status.value);
    }
  }
  */
  return YAWT_H3_OK;
}

YAWT_H3_Error_t YAWT_h3_send_data(YAWT_H3_Context_t *h3,
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


YAWT_H3_Error_t YAWT_h3_webtrans_upgrade(YAWT_H3_Context_t *h3, 
                uint64_t stream_id, const char *scheme, const char *authority, const char *path) {
  if (!h3 || !h3->qcon) return YAWT_H3_ERR_INVALID_PARAM;
  if (!scheme || !authority || !path) return YAWT_H3_ERR_INVALID_PARAM;

  if (h3->qcon->role != YAWT_Q_ROLE_CLIENT) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: webtrans_upgrade called on server role (stream %lu)", stream_id);
    return YAWT_H3_ERR_INVALID_PARAM;
  }

  YAWT_Q_StreamUserData_t *sud = YAWT_q_con_get_stream_userdata(h3->qcon, stream_id);
  YAWT_H3_Stream_t *stream = sud ? sud->user_data[YAWT_UD_H3] : NULL;
  if (!stream) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: webtrans_upgrade: no stream metadata for stream %lu", stream_id);
    return YAWT_H3_ERR_INVALID_PARAM;
  }

  if (stream->type != YAWT_H3_STREAM_FRAME && stream->type != YAWT_H3_STREAM_UNASSIGNED) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: webtrans_upgrade: stream %lu in invalid state %d", stream_id, stream->type);
    return YAWT_H3_ERR_INVALID_STATE;
  }

  YAWT_H3_HeaderFields_t *req = YAWT_h3_header_fields_create();
  if (!req) return YAWT_H3_ERR_SHORT_BUFFER;

  const char *protocol_value = (h3->wt_version == YAWT_H3_WT_VERSION_DRAFT02)
      ? "webtransport" : "webtransport-h3";
  YAWT_h3_header_add_str(req, ":method", "CONNECT");
  YAWT_h3_header_add_str(req, ":protocol", protocol_value);
  YAWT_h3_header_add_str(req, ":scheme", scheme);
  YAWT_h3_header_add_str(req, ":authority", authority);
  YAWT_h3_header_add_str(req, ":path", path);

  if (h3->wt_version == YAWT_H3_WT_VERSION_DRAFT02) {
    // RFC 9114 §4.1.2/§4.2: field names MUST be lowercase on the wire.
    YAWT_h3_header_add_str(req, "sec-webtransport-http3-draft02", "1");
  }

  YAWT_H3_Error_t err = YAWT_h3_send_headers(h3, stream_id, req, 0);
  YAWT_h3_header_fields_destroy(req);

  if (err != YAWT_H3_OK) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: webtrans_upgrade: send_headers failed on stream %lu: %s",
             stream_id, YAWT_h3_err_str(err));
    return err;
  }

  stream->type = YAWT_H3_STREAM_WT_CONNECT_PENDING;
  YAWT_LOG(YAWT_LOG_INFO, "h3: webtrans_upgrade: sent CONNECT request on stream %lu", stream_id);
  return YAWT_H3_OK;
}

YAWT_H3_Error_t YAWT_h3_webtrans_deny(YAWT_H3_Context_t *h3, 
                uint64_t stream_id, uint16_t status_code) {
  if (!h3 || !h3->qcon) return YAWT_H3_ERR_INVALID_PARAM;

  if (h3->qcon->role != YAWT_Q_ROLE_SERVER) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: webtrans_deny called on client role (stream %lu)", stream_id);
    return YAWT_H3_ERR_INVALID_PARAM;
  }

  YAWT_Q_StreamUserData_t *sud = YAWT_q_con_get_stream_userdata(h3->qcon, stream_id);
  YAWT_H3_Stream_t *stream = sud ? sud->user_data[YAWT_UD_H3] : NULL;
  if (!stream) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: webtrans_deny: no stream metadata for stream %lu", stream_id);
    return YAWT_H3_ERR_INVALID_PARAM;
  }

  if (stream->type != YAWT_H3_STREAM_WT_CONNECT_PENDING) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: webtrans_deny: stream %lu not in WT_CONNECT_PENDING state (state=%d)",
             stream_id, stream->type);
    return YAWT_H3_ERR_INVALID_STATE;
  }

  char status_buf[4];
  snprintf(status_buf, sizeof(status_buf), "%u", status_code);

  YAWT_H3_HeaderFields_t *resp = YAWT_h3_header_fields_create();
  if (!resp) return YAWT_H3_ERR_SHORT_BUFFER;

  YAWT_h3_header_add_str(resp, ":status", status_buf);

  YAWT_H3_Error_t err = YAWT_h3_send_headers(h3, stream_id, resp, 1);
  YAWT_h3_header_fields_destroy(resp);

  if (err != YAWT_H3_OK) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: webtrans_deny: send_headers failed on stream %lu: %s",
             stream_id, YAWT_h3_err_str(err));
    return err;
  }

  stream->type = YAWT_H3_STREAM_FRAME;
  YAWT_LOG(YAWT_LOG_INFO, "h3: webtrans_deny: sent %s rejection on stream %lu", status_buf, stream_id);
  return YAWT_H3_OK;
}

YAWT_H3_Error_t YAWT_h3_webtrans_accept(YAWT_H3_Context_t *h3, uint64_t stream_id) {
  if (!h3 || !h3->qcon) return YAWT_H3_ERR_INVALID_PARAM;

  if (h3->qcon->role != YAWT_Q_ROLE_SERVER) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: webtrans_accept called on client role (stream %lu)", stream_id);
    return YAWT_H3_ERR_INVALID_PARAM;
  }

  YAWT_Q_StreamUserData_t *sud = YAWT_q_con_get_stream_userdata(h3->qcon, stream_id);
  YAWT_H3_Stream_t *stream = sud ? sud->user_data[YAWT_UD_H3] : NULL;
  if (!stream) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: webtrans_accept: no stream metadata for stream %lu", stream_id);
    return YAWT_H3_ERR_INVALID_PARAM;
  }

  if (stream->type != YAWT_H3_STREAM_WT_CONNECT_PENDING) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: webtrans_accept: stream %lu not in WT_CONNECT_PENDING state (state=%d)",
             stream_id, stream->type);
    return YAWT_H3_ERR_INVALID_STATE;
  }

  YAWT_H3_HeaderFields_t *resp = YAWT_h3_header_fields_create();
  if (!resp) return YAWT_H3_ERR_SHORT_BUFFER;

  YAWT_h3_header_add_str(resp, ":status", "200");

  if (h3->wt_version == YAWT_H3_WT_VERSION_DRAFT02) {
    // RFC 9114 §4.1.2/§4.2: field names MUST be lowercase on the wire.
    YAWT_h3_header_add_str(resp, "sec-webtransport-http3-draft", "draft02");
  }

  YAWT_H3_Error_t err = YAWT_h3_send_headers(h3, stream_id, resp, 0);
  YAWT_h3_header_fields_destroy(resp);

  if (err != YAWT_H3_OK) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3: webtrans_accept: send_headers failed on stream %lu: %s",
             stream_id, YAWT_h3_err_str(err));
    return err;
  }

  stream->type = YAWT_H3_STREAM_WT_CONNECT;
  YAWT_LOG(YAWT_LOG_INFO, "h3: webtrans_accept: accepted WT CONNECT on stream %lu", stream_id);
  return YAWT_H3_OK;
}
