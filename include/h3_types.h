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

typedef struct YAWT_Q_Context_t YAWT_Q_Context_t;
typedef struct YAWT_H3_Context_t YAWT_H3_Context_t;

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
 * @internal
 * @ingroup H3_Internal
 * @brief Unidirectional wire format stream types.
 * @note RFC 9114 §6.2, RFC 9204 §4.2, draft-15. The first varint on a client
 *       uni stream selects its role; we read it once into the per-stream slot.
 *       Bidi (request) streams have no such prefix.
 * @note RFC 9287 defines GREASE values for stream types. Endpoints MUST tolerate
 *       unknown stream types (RFC 9114 §6.2.3) and silently drain them.
 */
typedef enum {
  YAWT_H3_STREAM_WIRE_CONTROL      = 0x00, /**< Control stream (RFC 9114 §6.2.1) */
  YAWT_H3_STREAM_WIRE_PUSH         = 0x01, /**< Push stream (RFC 9114 §6.2.2) */
  YAWT_H3_STREAM_WIRE_QPACK_ENCODER = 0x02, /**< QPACK encoder stream (RFC 9204 §4.2) */
  YAWT_H3_STREAM_WIRE_QPACK_DECODER = 0x03, /**< QPACK decoder stream (RFC 9204 §4.2) */
  YAWT_H3_STREAM_WIRE_WT_UNI       = 0x54, /**< WebTransport uni stream (draft-15 §4.2) */
  YAWT_H3_STREAM_WIRE_WT_BIDI      = 0x41, /**< WebTransport bidi stream (draft-15 §4.3) */
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
  YAWT_H3_STREAM_QPACK_ENCODER, /**< QPACK encoder stream (RFC 9204 §4.2) */
  YAWT_H3_STREAM_QPACK_DECODER, /**< QPACK decoder stream (RFC 9204 §4.2) */
  YAWT_H3_STREAM_WT,         /**< WebTransport stream (0x41 bidi or 0x54 uni, draft-15 §4.2/4.3) */
  YAWT_H3_STREAM_WT_CONNECT, /**< Upgraded CONNECT stream (capsules in DATA, draft-15 §3.2) */
  YAWT_H3_STREAM_WT_CONNECT_PENDING, /**< CONNECT awaiting 2xx response (draft-15 §3.2) */
  YAWT_H3_STREAM_UNKNOWN     /**< Unknown/GREASE stream type (RFC 9114 §6.2.3, RFC 9287) */
} YAWT_H3_StreamType_t;

/**
 * @ingroup H3_Types
 * @brief Core stream type identifiers for tracking critical unidirectional streams.
 * @note RFC 9114 §6.2.1 (control), RFC 9204 §4.2 (QPACK encoder/decoder).
 *       Each endpoint opens one control stream and up to one QPACK encoder/decoder stream.
 *       These are tracked separately from the wire stream types to distinguish local vs peer.
 */
typedef enum {
  YAWT_H3_UNIQUE_STREAM_LOCAL_CONTROL = 0,
  YAWT_H3_UNIQUE_STREAM_PEER_CONTROL,
  YAWT_H3_UNIQUE_STREAM_LOCAL_QPACK_ENCODER,
  YAWT_H3_UNIQUE_STREAM_PEER_QPACK_ENCODER,
  YAWT_H3_UNIQUE_STREAM_LOCAL_QPACK_DECODER,
  YAWT_H3_UNIQUE_STREAM_PEER_QPACK_DECODER,
  YAWT_H3_UNIQUE_STREAM_COUNT  // sentinel
} YAWT_H3_Unique_Stream_Type_t;

/**
 * @ingroup H3_Types
 * @brief Status of a core unidirectional stream.
 * @note Tracks whether a critical stream has been opened/received and its stream ID.
 */
typedef struct {
  bool available;
  uint64_t stream_id;
} YAWT_H3_Unique_Stream_Status_t;

/**
 * @ingroup H3_Types
 * @brief Internal setting indices (0-9).
 * @note Used for O(1) get/set operations. Maps directly to bit position in val_set
 *       and array index in vals[]. Must match order in wire mapping table.
 */
typedef enum {
  YAWT_H3_IDX_QPACK_MAX_TABLE_CAPACITY = 0,
  YAWT_H3_IDX_MAX_FIELD_SECTION_SIZE   = 1,
  YAWT_H3_IDX_QPACK_BLOCKED_STREAMS    = 2,
  YAWT_H3_IDX_ENABLE_CONNECT_PROTOCOL  = 3,
  YAWT_H3_IDX_H3_DATAGRAM              = 4,
  YAWT_H3_IDX_WT_ENABLED               = 5,
  YAWT_H3_IDX_WT_MAX_SESSIONS          = 6,
  YAWT_H3_IDX_WT_INITIAL_MAX_STREAMS_UNI  = 7,
  YAWT_H3_IDX_WT_INITIAL_MAX_STREAMS_BIDI = 8,
  YAWT_H3_IDX_WT_INITIAL_MAX_DATA         = 9,
  YAWT_H3_IDX_WT_ENABLED_DRAFT02          = 10,
  YAWT_H3_IDX_H3_DATAGRAM_DRAFT04         = 11,
  YAWT_H3_NUM_SETTINGS = 12
} YAWT_H3_SettingIdx_t;

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
  YAWT_H3_ERR_INVALID_STATE,    /**< Stream/connection in invalid state for operation */
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
    case YAWT_H3_ERR_INVALID_STATE: return "INVALID_STATE";
    case YAWT_H3_ERR_NO_APP_HANDLER:return "NO_APP_HANDLER";
    case YAWT_H3_IGNORED:           return "IGNORED";
    default:                        return "UNKNOWN";
  }
}


/**
 * @ingroup H3_Types
 * @brief The one H3 frame currently in flight on a stream.
 * @note Holds both the decoded result (type, payload_len, payload_blob) and the
 *       blob-backed accumulation state. Only one frame parses at a time per stream,
 *       so a single embedded instance serves.
 *
 *       Lifecycle: Between frames, payload accumulation state is reset when
 *       `parsed` is set — the payload blob is destroyed (fully consumed by
 *       _dispatch_buffered_frame) and hdr_buffer is preserved (cleared by
 *       _gate_h3_frame_head2 on the next header parse). The wipe does NOT
 *       touch the stream type (`stream->type`) or the stream-type accumulation
 *       buffer — those live in YAWT_H3_Stream_t and persist for the stream's
 *       entire lifetime (RFC 9114 §6.2: the stream-type varint is sent once
 *       at the start of a uni stream and never repeated).
 *
 *       For DATA frames, payload_blob is NULL — the payload streams through
 *       _handle_rx_stream_frame() directly to the app without buffering.
 *       Only SETTINGS and HEADERS require whole-frame buffering for decode.
 *
 * @warning READ-ONLY / NOT retained when handed to the app: the blob backing
 *          payload_blob is reused for the next frame, so anything kept beyond
 *          the delivering call must be copied.
 */
typedef struct {
  uint64_t type;          // decoded frame type (raw varint; unknown types survive)
  uint64_t payload_len;   // decoded Length

  // Header tracking: hdr_buffer accumulates frame-header bytes across chunks
  // (blob-backed, lazy-allocated). hdr_size is 0 until header is complete.
  ANB_Blob_t *hdr_buffer;  // frame-header accumulation buffer
  uint8_t  hdr_size;       // bytes of header decoded; 0 == header not yet read
  uint64_t accumulated;    // payload bytes accumulated for the current frame

  ANB_Blob_t *payload_blob; // Buffered payload blob (SETTINGS/HEADERS); NULL otherwise
  bool     parsed;          // set after frame complete; triggers reset on next parse
} YAWT_H3_Frame_t;

/**
 * @ingroup H3_Headers
 * @brief Header fields — backed by ANB_Slab internally.
 */
typedef struct {
  ANB_Slab_t *slab;        // stores _YAWT_H3_BufferedField_t entries
} YAWT_H3_HeaderFields_t;

/**
 * @ingroup H3_Types
 * @brief Per-stream H3 parse state.
 * @note Definition in impl/h3_types.h — include it to access fields directly.
 */
typedef struct YAWT_H3_Stream_t YAWT_H3_Stream_t;

/**
 * @ingroup H3_Types
 * @brief Negotiated HTTP/3 settings.
 * @note One instance holds the values we advertise; another holds what the peer sent.
 *       val_set bitmask tracks which settings have been explicitly set.
 *       vals[] stores values by internal index (O(1) access).
 */
typedef struct {
  uint64_t val_set;                        // bitmask: bit N = setting N explicitly set
  uint64_t vals[YAWT_H3_NUM_SETTINGS];     // values by internal index
} YAWT_H3_Settings_t;

/**
 * @ingroup H3_Headers
 * @brief Public view of a header field.
 * @warning Points into slab memory, do not free or mutate.
 */
typedef struct {
  const char *name;
  const char *value;
  size_t      name_len;
  size_t      value_len;
} YAWT_H3_Header_Field_t;


/**
 * @ingroup H3_Connection
 * @brief H3 event taxonomy.
 * @note Fired by the H3 layer toward the app via YAWT_H3_EventHandler_t
 *       (set with YAWT_h3_set_event_handler).
 */
typedef enum {
  YAWT_H3_EVT_HEADERS,        /**< HEADERS frame fully decoded; param has stream_id + headers */
  YAWT_H3_EVT_DATA,           /**< DATA frame payload chunk; stream_id + data/len + fin */
  YAWT_H3_EVT_SETTINGS,       /**< SETTINGS frame decoded; param has stream_id + settings ptr */
  YAWT_H3_EVT_CLOSE,          /**< H3-level error/close; param has error_code + reason */
  YAWT_H3_EVT_DATAGRAM,          /**< QUIC datagram received; param has data/len (RFC 9297 §2.1) */
  YAWT_H3_EVT_WT_UPGRADE_REQUEST,/**< Server received a WT CONNECT; app must accept/deny (server only) */
  YAWT_H3_EVT_WT_UPGRADE         /**< WT session established post-upgrade; stream is now WT_CONNECT (both roles) */
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
  /** @brief Parameters for YAWT_H3_EVT_DATAGRAM. */
  struct {
    const uint8_t *data;      /**< Borrowed pointer — valid only during callback */
    size_t len;               /**< Length of datagram payload */
  } P_EVT_DATAGRAM;
  /** @brief Parameters for YAWT_H3_EVT_WT_UPGRADE_REQUEST. */
  struct {
    uint64_t stream_id;       /**< The CONNECT stream awaiting accept/deny */
  } P_EVT_WT_UPGRADE_REQUEST;
  /** @brief Parameters for YAWT_H3_EVT_WT_UPGRADE. */
  struct {
    uint64_t stream_id;       /**< The upgraded WT_CONNECT stream (== session ID) */
  } P_EVT_WT_UPGRADE;
} YAWT_H3_EventParam_t;

/**
 * @ingroup H3_Connection
 * @brief App-level event callback for H3.
 */
typedef void (*YAWT_H3_EventHandler_t)(YAWT_H3_Context_t *con,
                                        YAWT_H3_EventType_t event,
                                        YAWT_H3_EventParam_t param);
/**
 * @ingroup H3_Connection
 * @brief H3 connection object.
 * @note Definition in impl/h3_types.h — include it to access fields directly.
 */
typedef struct YAWT_H3_Context_t YAWT_H3_Context_t;


/**
 * @internal
 * @ingroup H3_Internal
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

/**
 * @ingroup H3_Types
 * @brief WebTransport draft version negotiated for this connection.
 * @note Detected from peer SETTINGS: DRAFT02 if peer sent 0x2b603742 (draft-ietf-webtrans-http3-02),
 *       DEFAULT otherwise (draft-15+). Affects :protocol value and draft version headers.
 */
typedef enum {
  YAWT_H3_WT_VERSION_DEFAULT = 0,  /**< Current draft (draft-15+) — :protocol=webtransport-h3 */
  YAWT_H3_WT_VERSION_DRAFT02,      /**< draft-ietf-webtrans-http3-02 — :protocol=webtransport */
} YAWT_H3_WT_Version_t;
