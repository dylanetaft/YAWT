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
  bool data_blocked;              /* edge-trigger: connection-level DATA_BLOCKED sent */
  bool is_server;                 /* 1 if we are the server, 0 if client */
  YAWT_Q_ConnectionStats_t stats;   // byte counters
  void *user_data;                  // opaque app/H3 state; QUIC never dereferences it
  uint64_t close_code;              // recorded by close triggers, emitted once by con_free
  char close_reason[256];           // bounded, null-terminated; "" if none
  YAWT_Q_ConnState_t state;         // RFC 9000 §10.2: OPEN, SELF_CLOSE_CLOSING, or PEER_CLOSE_DRAINING
  uint32_t closing_rx_count;        // RFC 9000 §10.2.1: packet counter for closing-state rate limiting
};

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Per-stream flow control limits.
 */
typedef struct {
  uint64_t tx_max_data;
  uint64_t rx_max_data;
} YAWT_Q_StreamFC_t;

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Stream state flags (bitwise enum).
 * @note RFC 9000 §3.1/3.2: TX and RX are independent state machines.
 *       If the metadata exists, both directions are active by default.
 *       These flags track *why* a direction terminated.
 */
typedef enum {
  YAWT_Q_STREAM_FIN_SENT         = 0x01,  // We sent FIN → TX Data Sent state
  YAWT_Q_STREAM_RESET_SENT       = 0x02,  // We sent RESET_STREAM → TX Reset Sent state
  YAWT_Q_STREAM_STOPPED_RECEIVED = 0x04,  // We received STOP_SENDING → TX terminated by peer
  YAWT_Q_STREAM_FIN_RECEIVED     = 0x08,  // We received FIN → RX Size Known state
  YAWT_Q_STREAM_RESET_RECEIVED   = 0x10,  // We received RESET_STREAM → RX Reset Recvd state
  YAWT_Q_STREAM_STOPPED_SENT     = 0x20,  // We sent STOP_SENDING → RX terminated by us
  YAWT_Q_STREAM_TX_BLOCKED_SENT  = 0x40,  // edge-trigger: sent STREAM_DATA_BLOCKED for this stream
} YAWT_Q_StreamState_t;

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Stream metadata — one per open stream, stored in the con->stream_meta slab.
 * @note Tracks reassembly + flow-control position so EVT_STREAM can be delivered gap-free.
 *       RFC 9000 §3.1/3.2: TX and RX are independent state machines.
 *       If the metadata exists, both directions are active by default.
 *       The state field tracks termination reasons (FIN, RESET, STOP_SENDING).
 */
typedef struct {
  uint64_t stream_id;
  uint64_t rx_next_offset;
  uint64_t tx_next_offset;
  YAWT_Q_StreamFC_t fc;
  uint8_t state;  // bitwise OR of YAWT_Q_StreamState_t flags
} YAWT_Q_StreamMeta_t;

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Check if stream should transmit data.
 * @note Returns true if TX is active (no FIN sent, no RESET sent, not stopped by peer).
 */
static inline bool _stream_should_tx(const YAWT_Q_StreamMeta_t *m) {
  return !(m->state & (YAWT_Q_STREAM_FIN_SENT | YAWT_Q_STREAM_RESET_SENT | YAWT_Q_STREAM_STOPPED_RECEIVED));
}

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Check if stream should receive data.
 * @note Returns true if RX is active (no FIN received, no RESET received, not stopped by us).
 */
static inline bool _stream_should_rx(const YAWT_Q_StreamMeta_t *m) {
  return !(m->state & (YAWT_Q_STREAM_FIN_RECEIVED | YAWT_Q_STREAM_RESET_RECEIVED | YAWT_Q_STREAM_STOPPED_SENT));
}

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Result from processing frames in a packet.
 */
typedef struct {
  YAWT_Q_Error_t err;
  int requires_ack;
} YAWT_Q_FrameHandler_Res_t;
