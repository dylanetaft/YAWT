#pragma once
#include <stdint.h>
#include <allocnbuffer/slab.h>
#include <uthash/uthash.h>
#include <uthash/utlist.h>
#include "quic.h"
#include "crypt.h"
#include "callbacks.h"


// Peer address — always stored as IPv6 (IPv4 mapped to ::ffff:x.x.x.x)
typedef struct YAWT_Q_PeerAddr {
  uint8_t  addr[16];  // 128-bit IPv6 address (or IPv4-mapped)
  uint16_t port;      // network byte order
} YAWT_Q_PeerAddr_t;


typedef struct YAWT_Q_Connection {
  YAWT_Q_Cid_t cid;
  YAWT_Q_Cid_t peer_cid;
  YAWT_Q_Cid_t original_dcid;  // client's random DCID from first Initial (temporary index)
  uint32_t version;
  ANB_Slab_t *recv_buffer;
  ANB_Slab_t *tx_buffer;
  UT_hash_handle hh_cid;
  UT_hash_handle hh_odcid;
  YAWT_Q_PeerAddr_t peer_addr;
  YAWT_Q_Crypto_t *crypto;
  ANB_Slab_t *stream_rx;            // buffered YAWT_Q_Frame_Stream_t items
  ANB_Slab_t *stream_meta;          // YAWT_Q_StreamMeta_t per open stream
  YAWT_Q_FlowControl_t local_fc;    // our limits (what we advertise to peer)
  YAWT_Q_FlowControl_t peer_fc;     // peer's limits (what we respect when sending)
  YAWT_Q_ConnectionStats_t stats;   // byte counters
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
// and keepalive behavior across all connections.
typedef struct {
  double retransmit_initial;   // initial retransmit timeout (default 0.5s)
  double retransmit_backoff;   // multiplier per attempt (default 1.5)
  uint32_t retransmit_max;     // max attempts before giving up (default 10)
  double min_maint_interval;   // smallest maintenance interval across all connections
} YAWT_Q_MaintenanceConfig_t;

YAWT_Q_Connection_t *YAWT_q_con_create(YAWT_Q_Con_Create_Info_t *info);
YAWT_Q_Connection_t *YAWT_q_con_find_by_cid(const YAWT_Q_Cid_t *cid);
void YAWT_q_con_free(YAWT_Q_Connection_t **con);
void YAWT_q_con_clear_odcid(YAWT_Q_Connection_t *con);
void YAWT_q_con_rx(uint8_t *data, size_t len, YAWT_Q_Crypto_Cred_t *cred,
                              const YAWT_Q_PeerAddr_t *peer_addr, double now);



// Enqueue STREAM frames for the given data on stream_id. Fragments as needed.
// If fin is set, marks the stream as finished after the last chunk.
YAWT_Q_Error_t YAWT_q_con_send_stream(YAWT_Q_Connection_t *con, uint64_t stream_id,
                                       const uint8_t *data, size_t data_len, int fin);

void YAWT_q_con_update_peer_cid(YAWT_Q_Connection_t *con, const YAWT_Q_Cid_t *new_cid);

// Register a global callback set — copied onto every connection automatically.
void YAWT_q_con_add_default_cb(const YAWT_Q_Callbacks_t *cb);

// Initiate graceful close: enqueue CONNECTION_CLOSE, enter closing state.
// Maintain loop flushes the frame and frees after 3x PTO.
void YAWT_q_con_close(YAWT_Q_Connection_t *con, uint64_t error_code);

// Get a pointer to the current global maintenance config.
const YAWT_Q_MaintenanceConfig_t *YAWT_q_con_get_maint_config(void);

// Unified maintenance: retransmit lost frames, check idle timeouts,
// send keepalive PINGs, and flush queued packets for all connections.
void YAWT_q_con_maintain(double now);
