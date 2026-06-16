/**
 * @file impl/quic_types.h
 * @brief QUIC connection and stream internal struct definitions.
 * @note Include this header only if you need direct access to connection internals.
 *       Most users should use the public API in quic_connection.h.
 */

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
 *       Most fields are QUIC-internal; `user_data` is the app's.
 */
struct YAWT_Q_Connection_t {
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
  ANB_Slab_t *stream_meta;          // YAWT_Q_StreamMeta_t per open stream
  YAWT_Q_FlowControl_t local_fc;    // our limits (what we advertise to peer)
  YAWT_Q_FlowControl_t peer_fc;     // peer's limits (what we respect when sending)
  YAWT_Q_ConnectionStats_t stats;   // byte counters
  void *user_data;                  // opaque app/H3 state; QUIC never dereferences it
  uint64_t close_code;              // recorded by close triggers, emitted once by con_free
  char close_reason[256];           // bounded, null-terminated; "" if none
};

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Stream metadata — one per open stream, stored in the con->stream_meta slab.
 * @note Tracks reassembly + flow-control position so EVT_STREAM can be delivered gap-free
 */
typedef struct {
  uint64_t stream_id;
  uint64_t rx_next_offset;
  uint64_t tx_next_offset;
  uint64_t rx_fin_offset;
  uint64_t tx_max_data;
  uint8_t rx_fin;
  uint8_t tx_fin_sent;
} YAWT_Q_StreamMeta_t;

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Result from processing frames in a packet.
 */
typedef struct {
  YAWT_Q_Error_t err;
  int requires_ack;
} YAWT_Q_FrameHandler_Res_t;
