/**
 * @file h3_types.h
 * @brief HTTP/3 data structures, constants, and enums.
 */

/**
 * @ingroup HTTP3
 * @brief All HTTP/3 and QPACK protocol types, constants, and operations.
 */

#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <allocnbuffer/slab.h>
#include <allocnbuffer/blob.h>

/**
 * @defgroup H3_Connection Connection
 * @ingroup HTTP3
 * @brief HTTP/3 connection object, event system, and callbacks.
 */

/**
 * @defgroup H3_Headers Headers
 * @ingroup HTTP3
 * @brief HTTP/3 header field types and QPACK integration.
 */

/**
 * @defgroup H3_Types Types
 * @ingroup HTTP3
 * @brief HTTP/3 protocol types, enums, frames, streams, and settings.
 */

typedef struct YAWT_Q_Connection YAWT_Q_Connection_t;

#define H3_FRAME_MAX_HEADER_BYTES 16  /**< Max varint size for Type + Length */
#define H3_STREAM_TYPE_MAX_BYTES   8  /**< Uni stream-type prefix is one varint (<=8 bytes) */

/**
 * @note HTTP/3 data types (RFC 9114) — the YAWT_H3 analog of quic_types.h. Holds the
 *       enums and structs; the function API lives in h3.h. See docs/reference.md for
 *       the per-RFC mandatory/skip breakdown.
 *       
 *       Encapsulation: H3 has no packet concept. H3 frames live on the in-order byte
 *       stream of a QUIC stream (delivered by the QUIC layer via YAWT_Q_EVT_STREAM).
 *       A QUIC stream chunk may carry a partial H3 frame or several, so the frame
 *       parser has an INCOMPLETE outcome the QUIC frame parser never needed.
 */

/**
 * @ingroup H3_Types
 * @brief HTTP/3 frame types (RFC 9114 §7.2).
 * @note Named constants; YAWT_H3_Frame_t.type is kept as a raw uint64_t so
 *       unknown/reserved/greased types survive round-trip and are skipped
 *       generically rather than rejected.
 */
typedef enum {
  YAWT_H3_FRAME_DATA         = 0x00, /**< DATA frame — carries request/response body */
  YAWT_H3_FRAME_HEADERS      = 0x01, /**< HEADERS frame — carries header field section */
  YAWT_H3_FRAME_CANCEL_PUSH  = 0x03, /**< CANCEL_PUSH frame — abort a server push */
  YAWT_H3_FRAME_SETTINGS     = 0x04, /**< SETTINGS frame — connection configuration */
  YAWT_H3_FRAME_PUSH_PROMISE = 0x05, /**< PUSH_PROMISE frame — server push promise */
  YAWT_H3_FRAME_GOAWAY       = 0x07, /**< GOAWAY frame — graceful shutdown */
  YAWT_H3_FRAME_MAX_PUSH_ID  = 0x0d, /**< MAX_PUSH_ID frame — limit server push ID */
} YAWT_H3_FrameType_t;

/**
 * @ingroup H3_Types
 * @brief Unidirectional wire format stream types.
 * @note RFC 9114 §6.2, RFC 9204 §4.2, draft-15. The first varint on a client
 *       uni stream selects its role; we read it once into the per-stream slot.
 *       Bidi (request) streams have no such prefix.
 */
typedef enum {
  YAWT_H3_STREAM_WIRE_CONTROL      = 0x00, /**< Control stream (RFC 9114 §6.2.1) */
  YAWT_H3_STREAM_WIRE_PUSH         = 0x01, /**< Push stream (RFC 9114 §6.2.2) */
  YAWT_H3_STREAM_WIRE_QPACK_ENCODER = 0x02, /**< QPACK encoder stream (RFC 9204 §4.2) */
  YAWT_H3_STREAM_WIRE_QPACK_DECODER = 0x03, /**< QPACK decoder stream (RFC 9204 §4.2) */
  YAWT_H3_STREAM_WIRE_WEBTRANSPORT  = 0x54, /**< WebTransport stream (draft-15) */
} YAWT_H3_WireStreamType_t;

/**
 * @ingroup H3_Types
 * @brief Logical HTTP/3 stream types.
 */
typedef enum {
  YAWT_H3_STREAM_UNASSIGNED = 0, /**< Not yet assigned */
  YAWT_H3_STREAM_FRAME,      /**< Bidirectional stream carrying HTTP/3 frames (requests, responses, and DATA) */
  YAWT_H3_STREAM_PUSH,       /**< Push stream (RFC 9114 §6.2.2) */
  YAWT_H3_STREAM_CONTROL,    /**< Control stream (RFC 9114 §6.2.1) */
  YAWT_H3_STREAM_QPACK,      /**< QPACK encoder/decoder stream */
  YAWT_H3_STREAM_WEBTRANSPORT /**< WebTransport stream (draft-15) */
} YAWT_H3_StreamType_t;

/**
 * @ingroup H3_Types
 * @brief SETTINGS identifiers.
 * @note RFC 9114 §7.2.4.1, RFC 9204, RFC 9220, RFC 9297, draft-ietf-webtrans-http3-15.
 *       Values are the on-the-wire identifiers.
 */
typedef enum {
  YAWT_H3_SETTING_QPACK_MAX_TABLE_CAPACITY = 0x01, /**< QPACK dynamic table capacity (RFC 9204) */
  YAWT_H3_SETTING_MAX_FIELD_SECTION_SIZE   = 0x06, /**< Maximum header field section size */
  YAWT_H3_SETTING_QPACK_BLOCKED_STREAMS    = 0x07, /**< QPACK blocked streams limit (RFC 9204) */
  YAWT_H3_SETTING_ENABLE_CONNECT_PROTOCOL  = 0x08, /**< Extended CONNECT protocol (RFC 9220) */
  YAWT_H3_SETTING_H3_DATAGRAM              = 0x33, /**< HTTP datagrams (RFC 9297) */
  YAWT_H3_SETTING_WT_ENABLED               = 0x2c7cf000, /**< WebTransport enabled (draft-15) */
} YAWT_H3_SettingId_t;

/**
 * @ingroup H3_Types
 * @brief Internal return status for H3 functions.
 * @note Distinct from HTTP/3 *wire* error codes (RFC 9114 §8.1, e.g. H3_SETTINGS_ERROR)
 *       — those are added separately when GOAWAY / CONNECTION_CLOSE emission is built.
 */
typedef enum {
  YAWT_H3_OK = 0,               /**< Success */
  YAWT_H3_ERR_SHORT_BUFFER,     /**< Output buffer too small to encode */
  YAWT_H3_ERR_INCOMPLETE,       /**< Not enough stream bytes yet — retry with more */
  YAWT_H3_ERR_MALFORMED,        /**< Structurally invalid (e.g. odd SETTINGS pairs) */
  YAWT_H3_ERR_TOO_LARGE,        /**< Frame exceeds the H3 buffer cap (security policy) */
  YAWT_H3_ERR_INVALID_PARAM,    /**< Invalid parameter */
  YAWT_H3_ERR_NO_APP_HANDLER,   /**< App handler not set via YAWT_h3_set_event_handler() */
  YAWT_H3_IGNORED,              /**< Event was not handled (e.g. DATAGRAM, unknown QUIC event) */
} YAWT_H3_Error_t;

/**
 * @ingroup H3_Types
 * @brief Get a string representation of an H3 error code.
 * @param err The error code.
 * @return A static string describing the error.
 */
static inline const char *YAWT_h3_err_str(YAWT_H3_Error_t err) {
  switch (err) {
    case YAWT_H3_OK:                return "OK";
    case YAWT_H3_ERR_SHORT_BUFFER:  return "SHORT_BUFFER";
    case YAWT_H3_ERR_INCOMPLETE:    return "INCOMPLETE";
    case YAWT_H3_ERR_MALFORMED:     return "MALFORMED";
    case YAWT_H3_ERR_TOO_LARGE:     return "TOO_LARGE";
    case YAWT_H3_ERR_INVALID_PARAM: return "INVALID_PARAM";
    case YAWT_H3_ERR_NO_APP_HANDLER:return "NO_APP_HANDLER";
    case YAWT_H3_IGNORED:           return "IGNORED";
    default:                        return "UNKNOWN";
  }
}

/**
 * @ingroup H3_Types
 * @brief The one H3 frame currently in flight on a stream.
 * @note Holds both the decoded result (type, payload_len, payload) and the
 *       byte-level decode scratch (hdr/hdr_size/accumulated). Only one frame
 *       parses at a time per stream, so a single embedded instance serves.
 * @warning READ-ONLY / NOT retained when handed to the app: `payload` points
 *          into transient stream bytes, and the whole struct is reset and reused
 *          for the next frame, so anything kept beyond the delivering call must be copied.
 */
typedef struct {
  uint64_t type;          // decoded frame type (raw varint; unknown types survive)
  uint64_t payload_len;   // decoded Length
  uint8_t *payload;       // Either malloced or pointing into the current stream chunk; caller must not mutate or retain

  uint8_t  hdr[H3_FRAME_MAX_HEADER_BYTES]; // header (type+len) decode scratch; dead once decoded
  uint8_t  hdr_size;      // bytes of header consumed; 0 == header not yet read
  uint64_t accumulated;   // raw stream bytes accumulated for the current frame (INCOMPLETE)
} YAWT_H3_Frame_t;

/**
 * @ingroup H3_Headers
 * @brief Header fields — backed by ANB_Slab internally.
 * @note huff_scratch (ANB_Blob_t) is used during QPACK decode of Huffman-encoded
 *       literals in header field lines; allocated upfront in YAWT_h3_header_fields_create
 *       and grown as needed.
 */
typedef struct {
  ANB_Slab_t *slab;        // stores _YAWT_H3_BufferedField_t entries
  ANB_Blob_t *huff_scratch; // huffman decode scratch space, as far as I know only headers use huffman
} YAWT_H3_HeaderFields_t;

/**
 * @ingroup H3_Types
 * @brief Per-stream H3 parse state.
 * @note Lives in a preallocated slot pool on the H3 connection (slot index is NOT
 *       the stream id — ids are sparse and grow unbounded, so we store stream_id
 *       and linear-scan, like QUIC's stream_meta). A slot is claimed (in_use=true)
 *       when assigned to a stream id. A stream outlives any single frame and carries
 *       many of them, so the current frame is a union member, reset when advancing
 *       to the next frame.
 */
typedef struct {
  bool     in_use;
  uint64_t id;
  YAWT_H3_StreamType_t type;  // ie frame, qpack, etc; UNASSIGNED until resolved
  // Uni streams begin with a stream-type varint (RFC 9114 §6.2). It may be split
  // across QUIC chunks, so accumulate it here until decoded. Bidi (request)
  // streams have no prefix and resolve straight to STREAM_FRAME; type ==
  // UNASSIGNED is the "prefix not yet read" signal. Unused once type is set.
  uint8_t  hdr[H3_STREAM_TYPE_MAX_BYTES];
  uint64_t accumulated;
  // Header pointers — NULL until parsed
  YAWT_H3_HeaderFields_t *request_headers;
  YAWT_H3_HeaderFields_t *response_headers;
  YAWT_H3_Frame_t frame;
} YAWT_H3_Stream_t;

/**
 * @ingroup H3_Types
 * @brief Negotiated HTTP/3 settings.
 * @note One instance holds the values we advertise; another holds what the peer sent.
 */
typedef struct {
  uint64_t qpack_max_table_capacity;   // we send 0 (static-table-only QPACK)
  uint64_t qpack_blocked_streams;      // we send 0
  uint64_t max_field_section_size;     // inbound header cap; 0 = unset (omitted)
  uint8_t  enable_connect_protocol;    // 0/1 — extended CONNECT (RFC 9220)
  uint8_t  h3_datagram;                // 0/1 — HTTP datagrams (RFC 9297)
  uint8_t  wt_enabled;                 // 0/1 — WebTransport (draft-15)
} YAWT_H3_Settings_t;

/**
 * @ingroup H3_Headers
 * @brief Public view of a header field.
 * @warning Points into slab memory, do not free or mutate.
 * @note i_static and i_name are QPACK static table indexes pre-resolved at add time.
 */
typedef struct {
  const char *name;
  const char *value;
  size_t      name_len;
  size_t      value_len;
  size_t      i_static;  // full name-value match in QPACK static table (0 = none)
  size_t      i_name;    // name-only match in QPACK static table (0 = none)
} YAWT_H3_Header_Field_t;

/**
 * @ingroup H3_Connection
 * @brief Forward declaration for H3 connection object
 */
typedef struct YAWT_H3_Connection YAWT_H3_Connection_t;

/**
 * @ingroup H3_Connection
 * @brief H3 event taxonomy.
 * @note Fired by the H3 layer toward the app via YAWT_H3_EventHandler_t
 *       (set with YAWT_h3_set_event_handler).
 */
typedef enum {
  YAWT_H3_EVT_HEADERS,    /**< HEADERS frame fully decoded; param has stream_id + headers */
  YAWT_H3_EVT_DATA,       /**< DATA frame payload chunk; stream_id + data/len + fin */
  YAWT_H3_EVT_SETTINGS,   /**< SETTINGS frame decoded; param has stream_id + settings ptr */
  YAWT_H3_EVT_CLOSE,      /**< H3-level error/close; param has error_code + reason */
} YAWT_H3_EventType_t;

/**
 * @ingroup H3_Connection
 * @brief Per-event parameters for H3.
 * @warning Transience: ALL pointers in this union are valid ONLY for the duration
 *          of the handler call. They reference internal/transient storage that the
 *          H3/QUIC layer reuses immediately after the handler returns. Copy anything
 *          you need to retain.
 */
typedef union YAWT_H3_EventParam {
  struct {
    uint64_t stream_id;
    YAWT_H3_HeaderFields_t *headers;
  } P_EVT_HEADERS;
  struct {
    uint64_t stream_id;
    const uint8_t *data;
    size_t len;
    int fin;
  } P_EVT_DATA;
  struct {
    uint64_t stream_id;
    YAWT_H3_Settings_t *settings;
  } P_EVT_SETTINGS;
  struct {
    uint64_t error_code;
    const char *reason;
  } P_EVT_CLOSE;
} YAWT_H3_EventParam_t;

/**
 * @ingroup H3_Connection
 * @brief App-level event callback for H3.
 */
typedef void (*YAWT_H3_EventHandler_t)(YAWT_H3_Connection_t *con,
                                        YAWT_H3_EventType_t event,
                                        YAWT_H3_EventParam_t param);

/**
 * @ingroup H3_Connection
 * @brief H3 connection object.
 * @note Hung off the QUIC connection's user_data. Allocated on EVT_CONNECTED,
 *       freed on EVT_CLOSE (which con_free guarantees fires once).
 */
typedef struct YAWT_H3_Connection {
  YAWT_Q_Connection_t *qcon;            // back-reference to the QUIC layer
  YAWT_H3_EventHandler_t app_handler;   // app-level event callback
  YAWT_H3_Settings_t *local_settings;   // NULL until populated
  YAWT_H3_Settings_t *peer_settings;    // NULL until decoded from peer
  uint64_t nstreams;                    // slot pool size (concurrent stream cap)
  YAWT_H3_Stream_t *streams;            // preallocated slot pool, linear-scan by id
  uint64_t control_stream_id;           // server's control stream (UINT64_MAX = not opened)
} YAWT_H3_Connection_t;

/**
 * @ingroup H3_Types
 * @brief Dynamic encoder instructions (RFC 9204 §4.3).
 * @note Not used yet.
 */
typedef enum {
    INSERT_WITH_NAME_REF,    /**< Insert with name reference (RFC 9204 §4.3.2) */
    INSERT_WITH_LITERAL_NAME, /**< Insert with literal name (RFC 9204 §4.3.3) */
    SET_CAPACITY,            /**< Set dynamic table capacity (RFC 9204 §4.3.1) */
    DUPLICATE,               /**< Duplicate entry (RFC 9204 §4.3.4) */
    UNKNOWN                  /**< Unknown instruction */
} YAWT_H3_QPACK_EncoderInstructionType_t;

