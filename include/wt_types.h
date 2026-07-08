/**
 * @file wt_types.h
 * @brief WebTransport data structures, constants, and enums.
 * @note draft-ietf-webtrans-http3-15, RFC 9297 (capsules, HTTP datagrams).
 */

/**
 * @defgroup WebTransport WebTransport
 * @brief WebTransport over HTTP/3 types, events, and callbacks.
 */

#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct YAWT_Q_Context_t YAWT_Q_Context_t;
typedef struct YAWT_H3_Context_t YAWT_H3_Context_t;
typedef struct YAWT_WT_Context_t YAWT_WT_Context_t;
typedef struct YAWT_WT_Session_t YAWT_WT_Session_t;



/**
 * @internal
 * @ingroup WebTransport_Internal 
 * @brief Wire format stream types.
 * IETF Webtransport over HTTP3 draft 15
 */
typedef enum {
  YAWT_WT_STREAM_WIRE_UNDEFINED    = 0x00, /**< Not yet determined */
  YAWT_WT_STREAM_WIRE_WT_UNI       = 0x54, /**< WebTransport uni stream (draft-15 §4.2) */
  YAWT_WT_STREAM_WIRE_WT_BIDI      = 0x41, /**< WebTransport bidi stream (draft-15 §4.3) */
} YAWT_WT_WireStreamType_t;

/**
 * @ingroup WebTransport
 * @brief Direction of a WebTransport stream to open (draft-15 §4.2/§4.3).
 */
typedef enum {
  YAWT_WT_DIR_UNI,   /**< Unidirectional (wire type 0x54) */
  YAWT_WT_DIR_BIDI,  /**< Bidirectional (wire signal 0x41) */
} YAWT_WT_StreamDir_t;

/**
 * @ingroup WebTransport
 * @brief WebTransport wire error codes (draft-15 §9.5).
 * @note These are sent in RESET_STREAM / CONNECTION_CLOSE when a WT-level
 *       protocol violation occurs.
 */
typedef enum {
  YAWT_WT_ERR_BUFFERED_STREAM_REJECTED = 0x3994bd84, /**< Buffered stream rejected (draft-15 §9.5) */
  YAWT_WT_ERR_SESSION_GONE             = 0x170d7b68, /**< Session no longer exists (draft-15 §9.5) */
  YAWT_WT_ERR_FLOW_CONTROL_ERROR       = 0x045d4487, /**< WT flow control violation (draft-15 §9.5) */
  YAWT_WT_ERR_ALPN_ERROR               = 0x0817b3dd, /**< ALPN negotiation error (draft-15 §9.5) */
  YAWT_WT_ERR_REQUIREMENTS_NOT_MET     = 0x212c0d48, /**< Requirements not met (draft-15 §9.5) */
} YAWT_WT_ErrorCode_t;

/**
 * @ingroup WebTransport
 * @brief First codepoint in the WT_APPLICATION_ERROR range (draft-15 §9.5).
 */
#define YAWT_WT_ERR_APP_RANGE_FIRST  0x52e4a40fa8dbULL

/**
 * @ingroup WebTransport
 * @brief Last codepoint in the WT_APPLICATION_ERROR range (draft-15 §9.5).
 */
#define YAWT_WT_ERR_APP_RANGE_LAST   0x52e5ac983162ULL

/**
 * @ingroup WebTransport
 * @brief Capsule types for WebTransport (draft-15 §9.6, RFC 9297).
 * @note Capsules are TLV-encoded on the CONNECT stream (DATA frames) and on
 *       WT uni streams. Unknown types MUST be silently skipped (RFC 9297 §3.2).
 */
typedef enum {
  YAWT_WT_CAPSULE_DATAGRAM              = 0x00,       /**< DATAGRAM capsule (RFC 9297 §3.5) */
  YAWT_WT_CAPSULE_CLOSE_SESSION         = 0x2843,     /**< WT_CLOSE_SESSION (draft-15 §6) */
  YAWT_WT_CAPSULE_DRAIN_SESSION         = 0x78ae,     /**< WT_DRAIN_SESSION (draft-15 §4.7) */
  YAWT_WT_CAPSULE_MAX_DATA              = 0x190B4D3D, /**< WT_MAX_DATA (draft-15 §5.6.4) */
  YAWT_WT_CAPSULE_MAX_STREAMS_BIDI      = 0x190B4D3F, /**< WT_MAX_STREAMS bidi (draft-15 §5.6.2) */
  YAWT_WT_CAPSULE_MAX_STREAMS_UNI       = 0x190B4D40, /**< WT_MAX_STREAMS uni (draft-15 §5.6.2) */
  YAWT_WT_CAPSULE_DATA_BLOCKED          = 0x190B4D41, /**< WT_DATA_BLOCKED (draft-15 §5.6.5) */
  YAWT_WT_CAPSULE_STREAMS_BLOCKED_BIDI  = 0x190B4D43, /**< WT_STREAMS_BLOCKED bidi (draft-15 §5.6.3) */
  YAWT_WT_CAPSULE_STREAMS_BLOCKED_UNI   = 0x190B4D44, /**< WT_STREAMS_BLOCKED uni (draft-15 §5.6.3) */
} YAWT_WT_CapsuleType_t;

/**
 * @ingroup WebTransport
 * @brief WT_CLOSE_SESSION capsule (draft-15 §6).
 *
 * Sent to terminate a WebTransport session with a detailed error message.
 * After sending this capsule, the endpoint MUST send FIN on the CONNECT stream.
 *
 * Capsule format:
 *   Type (i) = 0x2843
 *   Length (i)
 *   Application Error Code (32)
 *   Application Error Message (..8192)
 */
typedef struct {
  uint32_t app_error_code;           /**< 32-bit application error code */
  const uint8_t *app_error_message;  /**< UTF-8 error message (max 1024 bytes) */
  size_t message_len;                /**< Length of error message */
} YAWT_WT_CapsuleCloseSession_t;

/**
 * @ingroup WebTransport
 * @brief WT_DRAIN_SESSION capsule (draft-15 §4.7).
 *
 * Signals that the session should be gracefully terminated.
 * After sending/receiving, endpoints MAY continue using the session
 * but should attempt graceful termination.
 *
 * Capsule format:
 *   Type (i) = 0x78ae
 *   Length (i) = 0
 */
typedef struct {
  /* No fields - empty capsule */
} YAWT_WT_CapsuleDrainSession_t;

/**
 * @ingroup WebTransport
 * @brief WT_MAX_STREAMS capsule (draft-15 §5.6.2).
 *
 * Informs peer of the cumulative number of streams it can open.
 * Type 0x190B4D3F = bidirectional, 0x190B4D40 = unidirectional.
 *
 * Capsule format:
 *   Type (i) = 0x190B4D3F..0x190B4D40
 *   Length (i)
 *   Maximum Streams (i)
 */
typedef struct {
  uint64_t maximum_streams;          /**< Cumulative stream count (max 2^60) */
  bool is_bidi;                      /**< true=bidirectional, false=unidirectional */
} YAWT_WT_CapsuleMaxStreams_t;

/**
 * @ingroup WebTransport
 * @brief WT_STREAMS_BLOCKED capsule (draft-15 §5.6.3).
 *
 * Sent when sender wants to open a stream but is blocked by peer's limit.
 * Type 0x190B4D43 = bidirectional, 0x190B4D44 = unidirectional.
 *
 * Capsule format:
 *   Type (i) = 0x190B4D43..0x190B4D44
 *   Length (i)
 *   Maximum Streams (i)
 */
typedef struct {
  uint64_t maximum_streams;          /**< Stream limit at time of blocking (max 2^60) */
  bool is_bidi;                      /**< true=bidirectional, false=unidirectional */
} YAWT_WT_CapsuleStreamsBlocked_t;

/**
 * @ingroup WebTransport
 * @brief WT_MAX_DATA capsule (draft-15 §5.6.4).
 *
 * Informs peer of the maximum data that can be sent on the session.
 * Counts all stream body data (excludes capsules, headers, stream type, session ID).
 *
 * Capsule format:
 *   Type (i) = 0x190B4D3D
 *   Length (i)
 *   Maximum Data (i)
 */
typedef struct {
  uint64_t maximum_data;             /**< Session-level byte limit */
} YAWT_WT_CapsuleMaxData_t;

/**
 * @ingroup WebTransport
 * @brief WT_DATA_BLOCKED capsule (draft-15 §5.6.5).
 *
 * Sent when sender wants to send data but is blocked by session-level flow control.
 *
 * Capsule format:
 *   Type (i) = 0x190B4D41
 *   Length (i)
 *   Maximum Data (i)
 */
typedef struct {
  uint64_t maximum_data;             /**< Session-level limit at which blocking occurred */
} YAWT_WT_CapsuleDataBlocked_t;

/**
 * @ingroup WebTransport
 * @brief DATAGRAM capsule (RFC 9297 §3.5).
 *
 * Carries HTTP datagram payload on a stream using the capsule protocol.
 * Used when QUIC DATAGRAM frames are unavailable or undesirable.
 *
 * Capsule format:
 *   Type (i) = 0x00
 *   Length (i)
 *   HTTP Datagram Payload (..)
 */
typedef struct {
  const uint8_t *payload;            /**< Datagram payload (can be empty) */
  size_t payload_len;                /**< Length of payload */
} YAWT_WT_CapsuleDatagram_t;

/**
 * @ingroup WebTransport
 * @brief Parsed capsule union — contains all capsule types.
 * @note Use with YAWT_wt_parse_capsule(). The type field indicates which
 *       union member is valid.
 */
typedef union {
  YAWT_WT_CapsuleCloseSession_t close_session;
  YAWT_WT_CapsuleDrainSession_t drain_session;
  YAWT_WT_CapsuleMaxStreams_t max_streams;
  YAWT_WT_CapsuleStreamsBlocked_t streams_blocked;
  YAWT_WT_CapsuleMaxData_t max_data;
  YAWT_WT_CapsuleDataBlocked_t data_blocked;
  YAWT_WT_CapsuleDatagram_t datagram;
} YAWT_WT_Capsule_t;

/**
 * @ingroup WebTransport
 * @brief Internal return status for WT functions.
 * @note Distinct from wire error codes (YAWT_WT_ErrorCode_t) — those go on the
 *       wire; these are local API return values.
 */
typedef enum {
  YAWT_WT_OK = 0,            /**< Success */
  YAWT_WT_ERR_SHORT_BUFFER,  /**< Output buffer too small */
  YAWT_WT_ERR_INCOMPLETE,    /**< Not enough bytes yet — retry with more */
  YAWT_WT_ERR_MALFORMED,     /**< Structurally invalid */
  YAWT_WT_ERR_INVALID_PARAM, /**< Invalid parameter */
  YAWT_WT_ERR_NO_APP_HANDLER,/**< App handler not set */
  YAWT_WT_ERR_NO_SESSION,    /**< Session ID not found */
  YAWT_WT_ERR_FLOW_CONTROL,  /**< Flow control limit exceeded */
  YAWT_WT_ERR_SESSION_CLOSED,/**< Session already terminated */
} YAWT_WT_Error_t;

/**
 * @ingroup WebTransport
 * @brief Get a string representation of a WT error code.
 * @param err The error code.
 * @return A static string describing the error.
 */
static inline const char *YAWT_wt_err_str(YAWT_WT_Error_t err) {
  switch (err) {
    case YAWT_WT_OK:                return "OK";
    case YAWT_WT_ERR_SHORT_BUFFER:  return "SHORT_BUFFER";
    case YAWT_WT_ERR_INCOMPLETE:    return "INCOMPLETE";
    case YAWT_WT_ERR_MALFORMED:     return "MALFORMED";
    case YAWT_WT_ERR_INVALID_PARAM: return "INVALID_PARAM";
    case YAWT_WT_ERR_NO_APP_HANDLER:return "NO_APP_HANDLER";
    case YAWT_WT_ERR_NO_SESSION:    return "NO_SESSION";
    case YAWT_WT_ERR_FLOW_CONTROL:  return "FLOW_CONTROL";
    case YAWT_WT_ERR_SESSION_CLOSED:return "SESSION_CLOSED";
    default:                        return "UNKNOWN";
  }
}


/**
 * @ingroup WebTransport
 * @brief Per-event parameters for WebTransport.
 * @warning ALL pointers in this union are valid ONLY for the duration of the
 *          handler call. They reference internal/transient storage. Copy anything
 *          you need to retain.
 */
typedef union YAWT_WT_EventParam {
  /** @brief Parameters for YAWT_WT_EVT_SESSION_ESTABLISHED. */
  struct {
    uint64_t session_id;      /**< WT session ID (= CONNECT stream ID) */
  } P_EVT_SESSION_ESTABLISHED;
  /** @brief Parameters for YAWT_WT_EVT_STREAM_DATA. */
  struct {
    uint64_t session_id;      /**< WT session ID */
    uint64_t stream_id;       /**< H3 stream ID carrying the data */
    const uint8_t *data;      /**< Borrowed pointer — valid only during callback */
    size_t len;               /**< Length of data */
    int fin;                  /**< Non-zero if this is the last chunk on the stream */
  } P_EVT_STREAM_DATA;
  /** @brief Parameters for YAWT_WT_EVT_DATAGRAM. */
  struct {
    uint64_t session_id;      /**< WT session ID */
    const uint8_t *data;      /**< Borrowed pointer — valid only during callback */
    size_t len;               /**< Length of datagram payload */
  } P_EVT_DATAGRAM;
  /** @brief Parameters for YAWT_WT_EVT_CAPSULE_RECEIVED. */
  struct {
    uint64_t session_id;      /**< WT session ID */
    uint64_t stream_id;       /**< H3 stream ID carrying the capsule */
    YAWT_WT_CapsuleType_t type;    /**< Capsule type (indicates which union member is valid) */
    YAWT_WT_Capsule_t capsule;     /**< Parsed capsule data */
  } P_EVT_CAPSULE_RECEIVED;
} YAWT_WT_EventParam_t;


/**
 * @ingroup WebTransport
 * @brief WebTransport event taxonomy.
 * @note Fired by the WT layer toward the app via YAWT_WT_EventHandler_t.
 */
typedef enum {
  YAWT_WT_EVT_SESSION_ESTABLISHED, /**< WT session established (CONNECT accepted); param has session_id */
  YAWT_WT_EVT_STREAM_DATA,         /**< Data on a WT uni stream; param has session_id + stream_id + data */
  YAWT_WT_EVT_DATAGRAM,            /**< Datagram received; param has session_id + data */
  YAWT_WT_EVT_CAPSULE_RECEIVED,        /**< Capsule received on a CONNECT stream; param has session_id + capsule_type + data */
} YAWT_WT_EventType_t;


/**
 * @ingroup WebTransport
 * @brief App-level event callback for WebTransport.
 * @param ctx     The WT context this session belongs to.
 * @param session The WT session (NULL for context-level events, if any).
 * @param event   The event type.
 * @param param   Event-specific parameters.
 */
typedef void (*YAWT_WT_EventHandler_t)(YAWT_WT_Context_t *ctx,
                                        YAWT_WT_Session_t *session,
                                        YAWT_WT_EventType_t event,
                                        YAWT_WT_EventParam_t param);
