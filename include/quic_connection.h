#pragma once
#include <stdint.h>
#include <allocnbuffer/fifoslab.h>
#include <uthash/uthash.h>
#include "quic.h"
#include "crypt.h"

// QUIC connection states
typedef enum {
  YAWT_Q_STATE_INITIAL,
  YAWT_Q_STATE_HANDSHAKE,
  YAWT_Q_STATE_ESTABLISHED,
  YAWT_Q_STATE_CLOSING,
  YAWT_Q_STATE_DRAINING,
  YAWT_Q_STATE_CLOSED
} YAWT_Q_Connection_State_t;

typedef struct YAWT_Q_Connection {
  YAWT_Q_Cid_t cid;
  YAWT_Q_Cid_t peer_cid;
  uint32_t version;
  ANB_FifoSlab_t *recv_buffer;
  ANB_FifoSlab_t *tx_buffer;
  UT_hash_handle hh_addr;
  UT_hash_handle hh_cid;
  YAWT_Q_Connection_State_t state;

  // RFC 9000 Section 12.3 - Counters for each space
  uint64_t pkt_num_tx_initial;
  uint64_t pkt_num_rx_initial;
  uint64_t pkt_num_tx_app;
  uint64_t pkt_num_rx_app;
  uint64_t pkt_num_tx_handshake;
  uint64_t pkt_num_rx_handshake;

  YAWT_Q_Crypto_t crypto;
} YAWT_Q_Connection_t;
typedef struct YAWT_Q_Con_Create_Info {
  int is_server;
  YAWT_Q_Crypto_Cred_t *cred;
  YAWT_Q_Cid_t peer_cid;
  
} YAWT_Q_Con_Create_Info_t;

YAWT_Q_Connection_t *YAWT_q_con_create(YAWT_Q_Con_Create_Info_t *info);
YAWT_Q_Connection_t *YAWT_q_con_find_by_cid(const YAWT_Q_Cid_t *cid);
void YAWT_q_con_free(YAWT_Q_Connection_t **con);
void YAWT_q_con_set_state(YAWT_Q_Connection_t *con, YAWT_Q_Connection_State_t new_state);
YAWT_Q_Connection_State_t YAWT_q_con_get_state(YAWT_Q_Connection_t *con);
void YAWT_q_process_datagram(uint8_t *data, size_t len, YAWT_Q_Crypto_Cred_t *cred);

// Send callback type for flush_send
typedef void (*YAWT_Q_Send_Func_t)(const uint8_t *buf, size_t len, void *ctx);

// Pack unsent frames from tx_buffer into packets, encrypt, and send
void YAWT_q_con_flush_send(YAWT_Q_Connection_t *con,
                            YAWT_Q_Send_Func_t send_func,
                            void *send_ctx);

