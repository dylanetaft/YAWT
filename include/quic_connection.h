#pragma once
#include <stdint.h>
#include <allocnbuffer/slab.h>
#include <uthash/uthash.h>
#include "quic.h"
#include "crypt.h"


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
  YAWT_Q_FlowControl_t peer_fc;     // peer's limits (what we respect when sending)
  YAWT_Q_ConnectionStats_t stats;   // byte counters
} YAWT_Q_Connection_t;
typedef struct YAWT_Q_Con_Create_Info {
  int is_server;
  YAWT_Q_Crypto_Cred_t *cred;
  YAWT_Q_Cid_t peer_cid;
  YAWT_Q_Cid_t original_dcid;
  YAWT_Q_PeerAddr_t peer_addr;
} YAWT_Q_Con_Create_Info_t;

YAWT_Q_Connection_t *YAWT_q_con_create(YAWT_Q_Con_Create_Info_t *info);
YAWT_Q_Connection_t *YAWT_q_con_find_by_cid(const YAWT_Q_Cid_t *cid);
void YAWT_q_con_free(YAWT_Q_Connection_t **con);
void YAWT_q_con_clear_odcid(YAWT_Q_Connection_t *con);
void YAWT_q_con_rx(uint8_t *data, size_t len, YAWT_Q_Crypto_Cred_t *cred,
                              const YAWT_Q_PeerAddr_t *peer_addr);

// Send callback type for flush_send
typedef void (*YAWT_Q_Send_Func_t)(const uint8_t *buf, size_t len,
                                    const YAWT_Q_PeerAddr_t *peer_addr, void *ctx);

// Iterate all connections with queued data, pack into packets, encrypt, and send
void YAWT_q_con_tx(YAWT_Q_Send_Func_t send_func, void *send_ctx,
                            double now);

// Check all connections for frames that haven't been ACK'd.
// Timeout starts at YAWT_Q_RETRANSMIT_INITIAL and grows 50% per attempt.
// Marks them for resend (picked up by next flush_send call).
void YAWT_q_con_retransmit_lost(double now);

// Enqueue STREAM frames for the given data on stream_id. Fragments as needed.
// If fin is set, marks the stream as finished after the last chunk.
// Returns total bytes enqueued, or negative on error.
int YAWT_q_con_send_stream(YAWT_Q_Connection_t *con, uint64_t stream_id,
                           const uint8_t *data, size_t data_len, int fin);

void YAWT_q_con_update_peer_cid(YAWT_Q_Connection_t *con, const YAWT_Q_Cid_t *new_cid);


