/**
 * @file impl/wt_types.h
 * @brief WebTransport connection and session internal struct definitions.
 * @note Include this header only if you need direct access to WT internals.
 *       Most users should use the public API in wt.h and wt_types.h.
 */

#pragma once
#include "../wt_types.h"
#include "../quic_connection.h"
#include "../h3_types.h"
#include "../capsule.h"

typedef struct YAWT_WT_Stream_t YAWT_WT_Stream_t;

/**
 * @ingroup WebTransport
 * @brief Per-session WT state.
 * @note Lives in a preallocated slot pool on the WT context (linear-scan by
 *       session_id). A slot is claimed (in_use=true) when a WT session is
 *       accepted. session_id equals the CONNECT stream ID (draft-15 §2.2).
 */
struct YAWT_WT_Session_t {
  bool     in_use;             /**< Slot occupied */
  uint64_t session_id;         /**< = CONNECT stream ID (draft-15 §2.2) */
  uint64_t connect_stream_id;  /**< Same as session_id, kept for clarity */

  /**
   * @name Flow control state (Phase 5)
   * @brief Per-session cumulative stream counts and data byte tracking.
   * @{
   */
  uint64_t max_streams_uni;    /**< Cumulative, from WT_MAX_STREAMS or SETTINGS */
  uint64_t max_streams_bidi;   /**< Cumulative, from WT_MAX_STREAMS or SETTINGS */
  uint64_t max_data;           /**< From WT_MAX_DATA or SETTINGS */
  uint64_t sent_data;          /**< Bytes sent (for data limit enforcement) */
  uint64_t recv_data;          /**< Bytes received (for data limit enforcement) */
  uint64_t open_streams_uni;   /**< Currently open uni streams */
  uint64_t open_streams_bidi;  /**< Currently open bidi streams */
  /** @} */

  bool     draining;           /**< WT_DRAIN_SESSION sent/received */
  bool     closed;             /**< Session terminated */
};

/**
 * @ingroup WebTransport
 * @brief Per-stream WT state.
 * @note Hung off the QUIC stream's YAWT_Q_StreamUserData_t[YAWT_UD_WT] slot.
 *       Allocated by WT layer when it first sees a WT signal (0x41/0x54).
 *       Buffers the session_id varint which may span multiple QUIC chunks.
 */
struct YAWT_WT_Stream_t {
  bool     in_use;
  uint64_t stream_id;              /**< QUIC stream ID */
  
  // Session ID buffering (draft-15 §4.3)
  uint8_t  hdr[8];                 /**< Buffer for session_id varint */
  uint8_t  hdr_accumulated;        /**< Bytes of session_id buffered */
  uint64_t session_id;             /**< Decoded session_id (0 until complete) */
  bool     session_id_complete;    /**< True once varint decoded */
  
  uint64_t stream_offset;          /**< Total bytes seen on this stream */
  
  YAWT_WT_Session_t *session;      /**< NULL until session exists */
  
  YAWT_Capsule_Parser_t capsule_parser;  /**< For WT_CONNECT streams */
};

/**
 * @ingroup WebTransport
 * @brief Per-H3-connection WT manager.
 * @note Hung off the QUIC connection's YAWT_UD_WT slot. Allocated by the app
 *       after H3 SETTINGS confirm WT support, freed on connection close.
 */
struct YAWT_WT_Context_t {
  YAWT_Q_Connection_t *qcon;           /**< Back-reference to the QUIC layer */
  YAWT_H3_Connection_t *h3con;         /**< Back-reference to the H3 layer */
  YAWT_WT_EventHandler_t app_handler;  /**< App-level event callback */
  uint64_t nsessions;                  /**< Slot pool size */
  YAWT_WT_Session_t *sessions;         /**< Preallocated slot pool, linear-scan by session_id */
};
