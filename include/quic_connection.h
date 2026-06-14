/**
 * @file quic_connection.h
 * @brief QUIC connection lifecycle, I/O, and state management (High-Level API).
 */

/**
 * @defgroup YAWT_Q_Core YAWT_Q_Core
 * @brief Primary user-facing QUIC API for connection management and I/O.
 */

#pragma once
#include <stdint.h>
#include <allocnbuffer/slab.h>
#include <uthash/uthash.h>
#include <uthash/utlist.h>
#include "quic.h"
#include "crypt.h"

/**
 * @ingroup Quic Core
 * @brief Peer address — always stored as IPv6 (IPv4 mapped to ::ffff:x.x.x.x).
 */
typedef struct YAWT_Q_PeerAddr {
  uint8_t  addr[16];
  uint16_t port;
} YAWT_Q_PeerAddr_t;

/**
 * @ingroup Quic Core
 * @brief A QUIC connection.
 * @note Owned by the QUIC layer (created in con_create, destroyed in con_free).
 *       Indexed in global CID hash tables; found via con_find_by_cid.
 *       Threading: NOT thread-safe — one libev loop drives all connections. All
 *       fields are mutated only on that thread, synchronously with con_rx / con_maintain.
 *       Most fields are QUIC-internal; `user_data` is the app's.
 */
typedef struct YAWT_Q_Connection {
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
} YAWT_Q_Connection_t;

/**
 * @ingroup Quic Core
 * @brief Connection creation parameters.
 */
typedef struct YAWT_Q_Con_Create_Info {
  int is_server;
  YAWT_Q_Crypto_Cred_t *cred;
  YAWT_Q_Cid_t peer_cid;
  YAWT_Q_Cid_t original_dcid;
  YAWT_Q_PeerAddr_t peer_addr;
  YAWT_Q_FlowControl_t *local_fc;  // NULL = use global defaults
} YAWT_Q_Con_Create_Info_t;

/**
 * @ingroup Quic Core
 * @brief Global maintenance configuration.
 * @note Controls retransmit timing, idle timeout, and keepalive behavior across all connections.
 *       (Frame-level retransmit DOES use exponential backoff; this is distinct from the fixed ACK timer.)
 */
typedef struct {
  double retransmit_initial;   // initial retransmit timeout (default 0.5s)
  double retransmit_backoff;   // per-attempt multiplier of the timeout (default 1.5)
  uint32_t retransmit_max;     // max attempts before giving up (default 10)
  double min_maint_interval;   // smallest maintenance interval across all connections
} YAWT_Q_MaintenanceConfig_t;

// ---------------------------------------------------------------------------
// Connection lifecycle. The two engine entry points are con_rx (ingress) and
// con_maintain (timers/flush); both run synchronously on the libev thread and
// may invoke the event handler (see YAWT_Q_EventHandler_t in quic.h).
// ---------------------------------------------------------------------------

/**
 * @ingroup Quic Core
 * @brief Create a QUIC connection.
 * @param info Connection creation parameters.
 * @return Pointer to the new connection, or NULL on failure.
 * @note Registers it in the CID hash. Lifetime: until YAWT_q_con_free.
 */
YAWT_Q_Connection_t *YAWT_q_con_create(YAWT_Q_Con_Create_Info_t *info);

/**
 * @ingroup Quic Core
 * @brief Find a connection by Connection ID.
 * @param cid The Connection ID to search for.
 * @return Pointer to the connection, or NULL if not found.
 */
YAWT_Q_Connection_t *YAWT_q_con_find_by_cid(const YAWT_Q_Cid_t *cid);

/**
 * @ingroup Quic Core
 * @brief Destroy a connection.
 * @param con Pointer to the connection pointer. Sets *con = NULL.
 * @note SINGLE close chokepoint: emits EVT_CLOSE exactly once before teardown.
 *       Idempotent against NULL (double-free safe).
 */
void YAWT_q_con_free(YAWT_Q_Connection_t **con);

/**
 * @ingroup Quic Core
 * @brief Clear the original DCID from a connection (used after handshake).
 * @param con The connection.
 */
void YAWT_q_con_clear_odcid(YAWT_Q_Connection_t *con);

/**
 * @ingroup Quic Core
 * @brief Single ingress for received UDP datagrams.
 * @param data The datagram payload (borrowed for the call).
 * @param len The datagram length.
 * @param cred The crypto credentials.
 * @param peer_addr The peer's address.
 * @param now Current time (e.g., from ev_now()).
 * @note Looks up/creates the connection, parses, decrypts in-place, and handles frames.
 *       May synchronously emit EVT_CONNECTED / EVT_STREAM / EVT_DATAGRAM.
 */
void YAWT_q_con_rx(uint8_t *data, size_t len, YAWT_Q_Crypto_Cred_t *cred,
                              const YAWT_Q_PeerAddr_t *peer_addr, double now);

/**
 * @ingroup Quic Core
 * @brief Enqueue STREAM frames for the given scatter/gather buffers.
 * @param con The QUIC connection.
 * @param stream_id The target stream ID.
 * @param iov Scatter/gather buffer array.
 * @param iov_count Number of elements in iov.
 * @param fin If true, marks the stream finished after the last chunk.
 * @return YAWT_Q_OK on success, or an error code.
 * @note Ownership: copies all iov[] data (caller keeps its buffers).
 */
YAWT_Q_Error_t YAWT_q_con_send_stream(YAWT_Q_Connection_t *con, uint64_t stream_id,
                                       const YAWT_Q_IoVec_t *iov, int iov_count, int fin);

/**
 * @ingroup Quic Core
 * @brief Update the peer's Connection ID.
 * @param con The QUIC connection.
 * @param new_cid The new peer Connection ID.
 */
void YAWT_q_con_update_peer_cid(YAWT_Q_Connection_t *con, const YAWT_Q_Cid_t *new_cid);

/**
 * @ingroup Quic Core
 * @brief Install the process-wide event handler.
 * @param handler The event handler function. Passing NULL restores the built-in no-op default.
 */
void YAWT_q_con_set_event_handler(YAWT_Q_EventHandler_t handler);

/**
 * @ingroup Quic Core
 * @brief Set opaque per-connection app state.
 * @param con The QUIC connection.
 * @param p Opaque pointer (e.g., the H3 connection object).
 * @note Lifetime is the app's responsibility. QUIC never dereferences it.
 */
static inline void YAWT_q_con_set_user_data(YAWT_Q_Connection_t *con, void *p) {
  if (con) con->user_data = p;
}

/**
 * @ingroup Quic Core
 * @brief Get opaque per-connection app state.
 * @param con The QUIC connection.
 * @return The opaque pointer, or NULL if con is NULL.
 */
static inline void *YAWT_q_con_get_user_data(YAWT_Q_Connection_t *con) {
  return con ? con->user_data : NULL;
}

/**
 * @ingroup Quic Core
 * @brief Initiate graceful close.
 * @param con The QUIC connection.
 * @param error_code The error code to send.
 * @note Idempotent: a no-op if already closing. Enqueues CONNECTION_CLOSE.
 *       The actual free (→ EVT_CLOSE) happens later, after ~3x PTO.
 */
void YAWT_q_con_close(YAWT_Q_Connection_t *con, uint64_t error_code);

/**
 * @ingroup Quic Core
 * @brief Get a pointer to the current global maintenance config.
 * @return Pointer to the global YAWT_Q_MaintenanceConfig_t.
 */
const YAWT_Q_MaintenanceConfig_t *YAWT_q_con_get_maint_config(void);

/**
 * @ingroup Quic Core
 * @brief Unified maintenance pass over all connections.
 * @param now Current time (e.g., from ev_now()).
 * @note Retransmits lost frames, enforces idle timeouts, sends keepalive PINGs,
 *       and flushes queued packets (emits EVT_TX). May free connections whose
 *       close/idle has expired, each emitting EVT_CLOSE via YAWT_q_con_free.
 *       Call periodically from the event loop.
 */
void YAWT_q_con_maintain(double now);
