/**
 * @file quic_connection.h
 * @brief QUIC connection lifecycle, I/O, and state management (High-Level API).
 */

/**
 * @addtogroup QUIC_Connection
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
 * @ingroup QUIC_Connection
 * @brief Opaque peer address — the app's own native sockaddr (in/in6/storage).
 * @note QUIC copies the bytes on connect and hands them back verbatim in EVT_TX;
 *       it never inspects them (routing is by CID). In a connection, `addr` is
 *       owned (dup'd in con_create, freed in con_free). As a con_rx / Create_Info
 *       input it is borrowed — con_create makes its own copy.
 */
typedef struct YAWT_Q_PeerAddr_t {
  void  *addr;   // opaque native sockaddr
  size_t len;
} YAWT_Q_PeerAddr_t;

/**
 * @ingroup QUIC_Connection
 * @brief A QUIC connection.
 * @note Definition in impl/quic_types.h — include it to access fields directly.
 */
typedef struct YAWT_Q_Context_t YAWT_Q_Context_t;

/**
 * @ingroup QUIC_Connection
 * @brief Connection creation parameters.
 */
typedef struct YAWT_Q_Con_Create_Info_t {
  int is_server;
  YAWT_Q_Crypto_Cred_t *cred;
  YAWT_Q_Cid_t peer_cid;
  YAWT_Q_Cid_t original_dcid;
  YAWT_Q_PeerAddr_t peer_addr;
  YAWT_Q_FlowControl_t *local_fc;  // NULL = use global defaults
  const char *hostname;            // SNI hostname for client connections (NULL for server)
} YAWT_Q_Con_Create_Info_t;

/**
 * @ingroup QUIC_Connection
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
 * @internal
 * @ingroup QUIC_Internal
 * @brief Create a QUIC connection.
 * @details This is created in response to an incoming quic packet
 * with an unrecognized CID, managed by the QUIC library
 * @param info Connection creation parameters.
 * @return Pointer to the new connection, or NULL on failure.
 * @note Registers it in the CID hash. Lifetime: until YAWT_q_con_free.
 */
YAWT_Q_Context_t *YAWT_q_con_create(YAWT_Q_Con_Create_Info_t *info);

/**
 * @ingroup QUIC_Connection
 * @brief Initiate a QUIC connection as a client.
 * @param info Connection creation parameters (is_server=0, peer_addr=server, hostname=SNI).
 * @param now Current time (e.g., from ev_now()).
 * @return Pointer to the new connection, or NULL on failure.
 * @note Generates a random DCID, creates the connection, derives initial keys,
 *       starts the TLS handshake (producing ClientHello), and emits the first
 *       Initial packet via EVT_TX. The event handler must be installed before calling.
 */
YAWT_Q_Context_t *YAWT_q_con_connect(YAWT_Q_Con_Create_Info_t *info, double now);

/**
 * @ingroup QUIC_Connection
 * @brief Find a connection by Connection ID.
 * @param cid The Connection ID to search for.
 * @return Pointer to the connection, or NULL if not found.
 */
YAWT_Q_Context_t *YAWT_q_con_find_by_cid(const YAWT_Q_Cid_t *cid);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Destroy a connection.
 * @details This is used by the QUIC library to free connections after close/idle expiration
 * @param con Pointer to the connection pointer. Sets *con = NULL.
 * @note SINGLE close chokepoint: emits EVT_CLOSE exactly once before teardown.
 *       Idempotent against NULL (double-free safe).
 */
void YAWT_q_con_free(YAWT_Q_Context_t **con);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Clear the original DCID from a connection (used after handshake).
 * @param con The connection.
 */
void YAWT_q_con_clear_odcid(YAWT_Q_Context_t *con);

/**
 * @ingroup QUIC_Drive
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
 * @ingroup QUIC_Connection
 * @brief Enqueue STREAM frames for the given scatter/gather buffers.
 * @param con The QUIC connection.
 * @param stream_id The target stream ID.
 * @param iov Scatter/gather buffer array.
 * @param iov_count Number of elements in iov.
 * @param fin If true, marks the stream finished after the last chunk.
 * @return YAWT_ERR_OK on success, or an error code.
 * @note Ownership: copies all iov[] data (caller keeps its buffers).
 */
YAWT_Err_t YAWT_q_con_send_stream(YAWT_Q_Context_t *con, uint64_t stream_id,
                                       const YAWT_Q_IoVec_t *iov, int iov_count, int fin);

/**
 * @ingroup QUIC_Connection
 * @brief Allocate the next unused locally-initiated stream ID of a given direction.
 * @param con The QUIC connection.
 * @param is_bidi True for a bidirectional stream, false for unidirectional.
 * @return The next stream ID for this connection's role + direction. Returns 0
 *         if @p con is NULL.
 * @note The role half of the stream type (RFC 9000 §2.1) is taken from
 *       con->role, so the caller only picks the direction. Advances an internal
 *       monotonic counter; the ID becomes live once sent on via
 *       YAWT_q_con_send_stream(). Hardcoded local opens (e.g. H3 control/QPACK)
 *       also advance the counter via stream metadata creation.
 */
uint64_t YAWT_q_con_next_stream_id(YAWT_Q_Context_t *con, bool is_bidi);

/**
 * @ingroup QUIC_Connection
 * @brief Abruptly terminate a stream (send RESET_STREAM).
 * @param con The QUIC connection.
 * @param stream_id The stream to reset.
 * @param app_error_code Application error code.
 * @return YAWT_ERR_OK on success, or an error code.
 * @note RFC 9000 §3.1: Transitions TX to "Reset Sent" state. Sets RESET_SENT flag, enqueues
 *       RESET_STREAM with final_size=tx_next_offset, and removes pending STREAM frames
 *       from tx_buffer. Returns error if stream doesn't exist or TX already terminated.
 */
YAWT_Err_t YAWT_q_con_reset_stream(YAWT_Q_Context_t *con, uint64_t stream_id,
                                         uint64_t app_error_code);

/**
 * @ingroup QUIC_Connection
 * @brief Request peer to stop sending on a stream (send STOP_SENDING).
 * @param con The QUIC connection.
 * @param stream_id The stream to stop receiving.
 * @param app_error_code Application error code.
 * @return YAWT_ERR_OK on success, or an error code.
 * @note RFC 9000 §3.2: Sets STOPPED_SENT flag and enqueues STOP_SENDING. Per §3.3, peer SHOULD
 *       respond with RESET_STREAM. Returns error if stream doesn't exist or RX already terminated.
 */
YAWT_Err_t YAWT_q_con_stop_sending(YAWT_Q_Context_t *con, uint64_t stream_id,
                                          uint64_t app_error_code);

/**
 * @ingroup QUIC_Connection
 * @brief Update the RX flow control limit for a stream and send MAX_STREAM_DATA.
 * @param con The QUIC connection.
 * @param stream_id The stream whose limit is being raised.
 * @param new_limit The new RX limit (must be > current limit).
 * @note Called from within EVT_FLOW_CONTROL handler to communicate the app's decision.
 *       If new_limit <= current limit, no action is taken.
 */
void YAWT_q_con_set_stream_rx_limit(YAWT_Q_Context_t *con, uint64_t stream_id, uint64_t new_limit);

/**
 * @ingroup QUIC_Connection
 * @brief Update the connection-level RX flow control limit and send MAX_DATA.
 * @param con The QUIC connection.
 * @param new_limit The new connection-level RX limit (must be > current limit).
 * @note Called from within EVT_FLOW_CONTROL handler to communicate the app's decision.
 *       If new_limit <= current limit, no action is taken.
 */
void YAWT_q_con_set_conn_rx_limit(YAWT_Q_Context_t *con, uint64_t new_limit);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Update the peer's Connection ID.
 * @param con The QUIC connection.
 * @param new_cid The new peer Connection ID.
 */
void YAWT_q_con_update_peer_cid(YAWT_Q_Context_t *con, const YAWT_Q_Cid_t *new_cid);

/**
 * @ingroup QUIC_Connection
 * @brief Set per-slot user data on a QUIC connection.
 * @param con The QUIC connection.
 * @param slot The user data slot identifier (e.g., YAWT_UD_H3).
 * @param p Opaque pointer for the given slot.
 * @note Lifetime is the app's responsibility. QUIC never dereferences it.
 *       Each protocol layer uses its own slot; slots never collide.
 */
void YAWT_q_con_set_user_data(YAWT_Q_Context_t *con, YAWT_Q_UserDataSlot_t slot, void *p);

/**
 * @ingroup QUIC_Connection
 * @brief Get per-slot user data from a QUIC connection.
 * @param con The QUIC connection.
 * @param slot The user data slot identifier.
 * @return The opaque pointer for the given slot, or NULL if con is NULL.
 */
void *YAWT_q_con_get_user_data(YAWT_Q_Context_t *con, YAWT_Q_UserDataSlot_t slot);

/**
 * @ingroup QUIC_Connection
 * @brief Get per-stream user data container for a given stream_id.
 * @param con The QUIC connection.
 * @param stream_id The stream to look up.
 * @return Pointer to the stream's user data container, or NULL if stream not found.
 * @note Upper layers access their slot via sud->user_data[YAWT_UD_H3], etc.
 *       The QUIC layer's own metadata is at sud->user_data[YAWT_UD_QUIC].
 *       Full struct definition in impl/quic_types.h.
 */
YAWT_Q_StreamUserData_t *YAWT_q_con_get_stream_userdata(YAWT_Q_Context_t *con, uint64_t stream_id);

/**
 * @ingroup QUIC_Connection
 * @brief Get the stream user data slab for iteration.
 * @param con The QUIC connection.
 * @return Pointer to the ANB_Slab_t containing YAWT_Q_StreamUserData_t items, or NULL if con is NULL.
 * @note Use ANB_slab_peek_item_iter() to iterate. Upper layers use this to clean up
 *       their per-stream data on connection close.
 */
ANB_Slab_t *YAWT_q_con_get_stream_userdata_slab(YAWT_Q_Context_t *con);

/**
 * @ingroup QUIC_Connection
 * @brief Install the process-wide event handler.
 * @param handler The event handler function. Passing NULL restores the built-in no-op default.
 */
void YAWT_q_con_set_event_handler(YAWT_Q_EventHandler_t handler);

/**
 * @ingroup QUIC_Connection
 * @brief Initiate graceful close.
 * @param con The QUIC connection.
 * @param error_code The error code to send.
 * @note No-op if already closing. Enqueues CONNECTION_CLOSE.
 *       The actual free (→ EVT_CLOSE) happens later, after ~3x PTO.
 */
void YAWT_q_con_close(YAWT_Q_Context_t *con, uint64_t error_code);

/**
 * @ingroup QUIC_Connection
 * @brief Get a pointer to the current global maintenance config.
 * @return Pointer to the global YAWT_Q_MaintenanceConfig_t.
 */
const YAWT_Q_MaintenanceConfig_t *YAWT_q_con_get_maint_config(void);

/**
 * @ingroup QUIC_Drive
 * @brief Maintenance function for quic
 * @details Userspace is responsible for calling this periodically
 * on a frequency defined by YAWT_q_con_get_maint_config()->min_maint_interval
 * see examples for usage
 * @param now Current time (e.g., from ev_now()).
 * @note Retransmits lost frames, enforces idle timeouts, sends keepalive PINGs,
 *       and flushes queued packets (emits EVT_TX). May free connections whose
 *       close/idle has expired, each emitting EVT_CLOSE via YAWT_q_con_free.
 */
void YAWT_q_con_maintain(double now);

/** @ingroup QUIC_Connection
 * @brief Get the connection's current Connection ID.
 * @param con The QUIC connection.
 * @return The connection's current Connection ID.
 */
const YAWT_Q_Cid_t *YAWT_q_con_get_cid(const YAWT_Q_Context_t *con);

