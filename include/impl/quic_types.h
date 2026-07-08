/**
 * @file impl/quic_types.h
 * @brief QUIC connection and stream internal struct definitions.
 * @note Include this header only if you need direct access to connection internals.
 *       Most users should use the public API in quic_connection.h.
 */

// NOTE: The IMPL headers are to discourage direct access to certain structures that should be opaque to the app layer,
// not for separating internal vs public API
// the library does not really have "private" API, as you can also use it to implement QUIC at a lower level than the connection API
#pragma once

#include "../quic_types.h"

#include <allocnbuffer/slab.h>
#include "../quic_connection.h"
#include <uthash/uthash.h>
#include <uthash/utlist.h>
#include "../crypt.h"

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief A QUIC connection.
 * @note Owned by the QUIC layer (created in con_create, destroyed in con_free).
 *       Indexed in global CID hash tables; found via con_find_by_cid.
 *       Threading: NOT thread-safe — one libev loop drives all connections. All
 *       fields are mutated only on that thread, synchronously with con_rx / con_maintain.
 *       Most fields are QUIC-internal; `user_data[]` is the app's per-slot array.
 */
struct YAWT_Q_Context_t {
  YAWT_Q_Cid_t cid;
  YAWT_Q_Cid_t peer_cid;
  YAWT_Q_Cid_t original_dcid;  // client's random DCID from first Initial (temporary index)
  uint32_t version;
  ANB_Slab_t *recv_buffer;
  ANB_Slab_t *tx_buffer;            // queued YAWT_Q_WireFrame_t, flushed by con_maintain
  UT_hash_handle hh_cid;
  UT_hash_handle hh_odcid;
  YAWT_Q_PeerAddr_t peer_addr;
  YAWT_Q_Crypto_t *crypto;
  ANB_Slab_t *stream_rx;            // out-of-order RX: YAWT_Q_Frame_BufferedStream_t items
  ANB_Slab_t *stream_userdata;      // YAWT_Q_StreamUserData_t per open stream
  YAWT_Q_FlowControl_t local_fc;    // our limits (what we advertise to peer)
  YAWT_Q_FlowControl_t peer_fc;     // peer's limits (what we respect when sending)
  bool data_blocked;              /* edge-trigger: connection-level DATA_BLOCKED sent */
  YAWT_Q_Con_Role_t role;         /* client or server */
  YAWT_Q_ConnectionStats_t stats;   // byte counters
  void *user_data[YAWT_UD_COUNT];   // opaque per-slot state; QUIC never dereferences
  uint64_t close_code;              // recorded by close triggers, emitted once by con_free
  char close_reason[256];           // bounded, null-terminated; "" if none
  YAWT_Q_ConnState_t state;         // RFC 9000 §10.2: OPEN, SELF_CLOSE_CLOSING, or PEER_CLOSE_DRAINING
  uint32_t closing_rx_count;        // RFC 9000 §10.2.1: packet counter for closing-state rate limiting
  /* RFC 9000 §2.1: next locally-initiated stream ID per direction (steps by 4).
   * Seeded in con_create from role; advanced by next_stream_id and by local
   * _stream_meta_add (covers H3 hardcoded control/QPACK IDs). */
  uint64_t next_local_stream_id_bidi;
  uint64_t next_local_stream_id_uni;
};

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Stream metadata — one per open stream, stored in the con->stream_userdata slab.
 * @note Tracks reassembly + flow-control position so EVT_STREAM can be delivered gap-free.
 *       RFC 9000 §3.1/3.2: TX and RX are independent state machines.
 *       If the metadata exists, both directions are active by default.
 *       The state field tracks termination reasons (FIN, RESET, STOP_SENDING).
 */
typedef struct {
  uint64_t stream_id;
  uint64_t rx_next_offset;
  uint64_t rx_highest_offset;  // RFC 9000 §4.5: highest offset received — the RX flow-control meter (counts each offset once; retransmits/overlaps consume no new credit)
  uint64_t tx_next_offset;     // RFC 9000 §4.5: highest offset sent (== next to write; TX has no gaps) — the TX flow-control meter
  uint64_t rx_final_size;  // RFC 9000 §4.5: final size once known (FIN or RESET_STREAM)
  YAWT_Q_StreamFC_t fc;
  uint8_t state;  // bitwise OR of YAWT_Q_StreamState_t flags
} YAWT_Q_Stream_t;

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Per-stream user data container — one per open stream, stored in the con->stream_userdata slab.
 * @note Each protocol layer (QUIC, H3, WT, APP) mallocs its per-stream metadata and stores it in user_data[slot].
 *       The QUIC layer mallocs YAWT_Q_Stream_t and stores it in user_data[YAWT_UD_QUIC].
 *       Upper layers malloc their own structs and store in their respective slots.
 */
struct YAWT_Q_StreamUserData_t {
  uint64_t stream_id;
  void *user_data[YAWT_UD_COUNT];
};

