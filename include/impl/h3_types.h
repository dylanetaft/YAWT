/**
 * @file impl/h3_types.h
 * @brief H3 connection and stream internal struct definitions.
 * @note Include this header only if you need direct access to connection internals.
 *       Most users should use the public API in h3.h and h3_types.h.
 */

// NOTE: The IMPL headers are to discourage direct access to certain structures that should be opaque to the app layer,
// not for separating internal vs public API
// the library does not really have "private" API, as you can also use it to implement QUIC at a lower level than the connection API

#pragma once
#include <allocnbuffer/slab.h>
#include "../h3_types.h"
#include "../quic_connection.h"

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
struct YAWT_H3_Stream_t {
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
};

/**
 * @ingroup H3_Connection
 * @brief H3 connection object.
 * @note Hung off the QUIC connection's YAWT_UD_H3 slot. Allocated on EVT_CONNECTED,
 *       freed on EVT_CLOSE (which con_free guarantees fires once).
 */
struct YAWT_H3_Connection_t {
  YAWT_Q_Connection_t *qcon;            // back-reference to the QUIC layer
  YAWT_H3_EventHandler_t app_handler;   // app-level event callback
  YAWT_H3_Settings_t *local_settings;   // NULL until populated
  YAWT_H3_Settings_t *peer_settings;    // NULL until decoded from peer
  uint64_t nstreams;                    // slot pool size (concurrent stream cap)
  YAWT_H3_Stream_t *streams;            // preallocated slot pool, linear-scan by id
  YAWT_H3_Unique_Stream_Status_t core_stream_status[YAWT_H3_UNIQUE_STREAM_COUNT];
};
