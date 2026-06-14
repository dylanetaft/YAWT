#pragma once
#include <stdint.h>
#include <allocnbuffer/slab.h>
#include <uthash/uthash.h>
#include <uthash/utlist.h>
#include "quic.h"
#include "crypt.h"


// Peer address — always stored as IPv6 (IPv4 mapped to ::ffff:x.x.x.x)
typedef struct YAWT_Q_PeerAddr {
  uint8_t  addr[16];  // 128-bit IPv6 address (or IPv4-mapped)
  uint16_t port;      // network byte order
} YAWT_Q_PeerAddr_t;


// A QUIC connection. Owned by the QUIC layer (created in con_create, destroyed
// in con_free). Indexed in global CID hash tables; found via con_find_by_cid.
//   Threading: NOT thread-safe — one libev loop drives all connections. All
//     fields are mutated only on that thread, synchronously with con_rx /
//     con_maintain. Most fields are QUIC-internal; `user_data` is the app's.
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
typedef struct YAWT_Q_Con_Create_Info {
  int is_server;
  YAWT_Q_Crypto_Cred_t *cred;
  YAWT_Q_Cid_t peer_cid;
  YAWT_Q_Cid_t original_dcid;
  YAWT_Q_PeerAddr_t peer_addr;
  YAWT_Q_FlowControl_t *local_fc;  // NULL = use global defaults
} YAWT_Q_Con_Create_Info_t;

// Global maintenance configuration — controls retransmit timing, idle timeout,
// and keepalive behavior across all connections. (Frame-level retransmit DOES
// use exponential backoff; this is distinct from the fixed ACK timer.)
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

// Create a server-side connection (typically from a first Initial). Registers it
// in the CID hash. Lifetime: until con_free.
YAWT_Q_Connection_t *YAWT_q_con_create(YAWT_Q_Con_Create_Info_t *info);
YAWT_Q_Connection_t *YAWT_q_con_find_by_cid(const YAWT_Q_Cid_t *cid);

// Destroy a connection. SINGLE close chokepoint: emits EVT_CLOSE exactly once
// (before teardown, so user_data is still valid), unregisters, frees all slabs
// and crypto, then sets *con = NULL. Idempotent against NULL (double-free safe).
void YAWT_q_con_free(YAWT_Q_Connection_t **con);
void YAWT_q_con_clear_odcid(YAWT_Q_Connection_t *con);

// Single ingress for received UDP datagrams. Looks up/creates the connection,
// parses, decrypts in-place, and handles frames — may synchronously emit
// EVT_CONNECTED / EVT_STREAM / EVT_DATAGRAM. `data` is borrowed for the call.
void YAWT_q_con_rx(uint8_t *data, size_t len, YAWT_Q_Crypto_Cred_t *cred,
                              const YAWT_Q_PeerAddr_t *peer_addr, double now);



// Enqueue STREAM frames for the given scatter/gather buffers on stream_id.
// Fragments across iovec entries as needed, spanning buffer boundaries.
// Ownership: copies all iov[] data (caller keeps its buffers). If fin is set,
// marks the stream finished after the last chunk.
YAWT_Q_Error_t YAWT_q_con_send_stream(YAWT_Q_Connection_t *con, uint64_t stream_id,
                                       const YAWT_Q_IoVec_t *iov, int iov_count, int fin);

void YAWT_q_con_update_peer_cid(YAWT_Q_Connection_t *con, const YAWT_Q_Cid_t *new_cid);

// Install the process-wide event handler. Passing NULL restores the
// built-in no-op default. Replaces any previously installed handler.
void YAWT_q_con_set_event_handler(YAWT_Q_EventHandler_t handler);

// Opaque per-connection app state (e.g. the H3 connection object). The QUIC
// layer stores it and hands it back, never dereferencing it. Lifetime is the
// app's responsibility: typically allocated on YAWT_Q_EVT_CONNECTED and freed
// in the YAWT_Q_EVT_CLOSE handler (which con_free guarantees fires exactly once).
static inline void YAWT_q_con_set_user_data(YAWT_Q_Connection_t *con, void *p) {
  if (con) con->user_data = p;
}
static inline void *YAWT_q_con_get_user_data(YAWT_Q_Connection_t *con) {
  return con ? con->user_data : NULL;
}

// Initiate graceful close. Idempotent: a no-op if already closing. Enqueues
// CONNECTION_CLOSE and enters the closing state; con_maintain flushes the frame
// and the actual free (→ EVT_CLOSE) happens later, after ~3x PTO.
void YAWT_q_con_close(YAWT_Q_Connection_t *con, uint64_t error_code);

// Get a pointer to the current global maintenance config.
const YAWT_Q_MaintenanceConfig_t *YAWT_q_con_get_maint_config(void);

// Unified maintenance pass over all connections: retransmit lost frames (with
// backoff), enforce idle timeouts, send keepalive PINGs, and flush queued
// packets (emits EVT_TX). May free connections whose close/idle has expired,
// each emitting EVT_CLOSE via con_free. Call periodically from the event loop.
void YAWT_q_con_maintain(double now);
