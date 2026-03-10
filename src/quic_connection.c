#include "quic_connection.h"
#include "quic.h"
#include <stdio.h>
#include <uthash/uthash.h>
#include <allocnbuffer/fifoslab.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include "logger.h"
#include <arpa/inet.h>

YAWT_Q_Connection_t *_hash_cid = NULL; // Hash table of connections by CID
YAWT_Q_Connection_t *_hash_addr = NULL; // Hash table of connections by peer addr

YAWT_Q_Connection_t *YAWT_q_con_create(YAWT_Q_Con_Create_Info_t *info) {
  if (info == NULL) return NULL;
  YAWT_Q_Connection_t *con = malloc(sizeof(YAWT_Q_Connection_t));
  if (!con) return NULL;
  con->cid_len = 20;
  gnutls_rnd(GNUTLS_RND_NONCE, con->cid, con->cid_len);
  con->peer_cid_len = 0;
  con->recv_buffer = ANB_fifoslab_create(4096);
  con->send_buffer = ANB_fifoslab_create(4096);
  con->sent_buffer = ANB_fifoslab_create(4096);
  YAWT_q_crypto_init(&con->crypto, info->is_server, info->cred);
  YAWT_LOG(YAWT_LOG_INFO, "Created connection: CID=%s",
            YAWT_q_cid_to_hex(con->cid, con->cid_len));

  return con;
}

void YAWT_q_con_free(YAWT_Q_Connection_t **con) {
  if (con == NULL || *con == NULL) return;
  YAWT_Q_Connection_t *c = *con;
  if (c->peer_cid_len > 0) HASH_DELETE(hh_peer_cid, _hash_cid, c);
  HASH_DELETE(hh_addr, _hash_addr, c);
  YAWT_q_crypto_free(&c->crypto);
  ANB_fifoslab_destroy(c->recv_buffer);
  ANB_fifoslab_destroy(c->send_buffer);
  ANB_fifoslab_destroy(c->sent_buffer);
  free(c);
  *con = NULL;
}

void YAWT_q_con_set_state(YAWT_Q_Connection_t *con, YAWT_Q_Connection_State_t new_state) {
  if (con == NULL) return;
  con->state = new_state;
}

YAWT_Q_Connection_State_t YAWT_q_con_get_state(YAWT_Q_Connection_t *con) {
  if (con == NULL) return YAWT_Q_STATE_CLOSED;
  return con->state;
}

static const char *_pkt_type_name(YAWT_Q_Packet_Type_t type) {
  switch (type) {
    case YAWT_Q_PKT_TYPE_INITIAL:  return "Initial";
    case YAWT_Q_PKT_TYPE_0RTT:    return "0-RTT";
    case YAWT_Q_PKT_TYPE_HANDSHAKE: return "Handshake";
    case YAWT_Q_PKT_TYPE_RETRY:   return "Retry";
    case YAWT_Q_PKT_TYPE_1RTT:    return "1-RTT";
    default:                       return "Unknown";
  }
}

// Map long header packet type bits to encryption level
static YAWT_Q_Encryption_Level_t _pkt_type_to_level(YAWT_Q_Packet_Type_t type) {
  switch (type) {
    case YAWT_Q_PKT_TYPE_INITIAL:   return YAWT_Q_LEVEL_INITIAL;
    case YAWT_Q_PKT_TYPE_0RTT:      return YAWT_Q_LEVEL_EARLY;
    case YAWT_Q_PKT_TYPE_HANDSHAKE: return YAWT_Q_LEVEL_HANDSHAKE;
    default:                         return YAWT_Q_LEVEL_APPLICATION;
  }
}

YAWT_Q_Connection_t *YAWT_q_con_find_by_cid(const uint8_t *cid, uint8_t cid_len) {
  YAWT_Q_Connection_t *con = NULL;
  HASH_FIND(hh_peer_cid, _hash_cid, cid, cid_len, con);
  return con;
}
void YAWT_q_process_datagram(uint8_t *data, size_t len, YAWT_Q_Crypto_Cred_t *cred) {
  YAWT_Q_ReadCursor_t rc = { .data = data, .len = len, .cursor = 0, .err = YAWT_Q_OK };
  while (rc.cursor < rc.len && rc.err == YAWT_Q_OK) {
    size_t prev = rc.cursor;
    YAWT_Q_Packet_t pkt;
    YAWT_q_parse_packet(&rc, &pkt);
    if (rc.err != YAWT_Q_OK || rc.cursor == prev) break;

    printf("  packet: %s (consumed %zu bytes)\n", _pkt_type_name(pkt.type), rc.cursor - prev);

    // Skip Retry — no encrypted payload
    //if (pkt.type == YAWT_Q_PKT_TYPE_RETRY) continue;
    YAWT_Q_Connection_t *con = YAWT_q_con_find_by_cid(pkt.dest_cid, pkt.dest_cid_len);
    if (!con) {
      YAWT_LOG(YAWT_LOG_INFO, "New connection for CID=%s", YAWT_q_cid_to_hex(pkt.dest_cid, pkt.dest_cid_len));
      YAWT_Q_Con_Create_Info_t info;
      memset(&info, 0, sizeof(info));
      info.is_server = 0;
      info.cred = cred;
      con = YAWT_q_con_create(&info);
    }

    if (!con) {
      YAWT_LOG(YAWT_LOG_ERROR, "Failed to create connection for CID=%s", YAWT_q_cid_to_hex(pkt.dest_cid, pkt.dest_cid_len));
      continue;
    }
    YAWT_Q_Encryption_Level_t level = _pkt_type_to_level(pkt.type);

    // For Initial packets: derive keys from DCID if not done yet
    if (level == YAWT_Q_LEVEL_INITIAL &&
        !con->crypto.level_keys[YAWT_Q_LEVEL_INITIAL].available) {
      const uint8_t *dcid = pkt.dest_cid;
      uint8_t dcid_len = pkt.dest_cid_len;
      int ret = YAWT_q_crypto_derive_initial_keys(&con->crypto, dcid, dcid_len);
      if (ret < 0) {
        YAWT_LOG(YAWT_LOG_ERROR, "Failed to derive initial keys for CID=%s: %d",
                  YAWT_q_cid_to_hex(pkt.dest_cid, pkt.dest_cid_len), ret);
        break;
      }
      YAWT_LOG(YAWT_LOG_INFO, "Derived initial keys for CID=%s from DCID (%u bytes)",
                YAWT_q_cid_to_hex(pkt.dest_cid, pkt.dest_cid_len), pkt.dest_cid_len);
    }

    YAWT_Q_Level_Keys_t *keys = &con->crypto.level_keys[level];
    if (!keys->available) {
      printf("  no keys for level %d, skipping decrypt\n", level);
      continue;
    }

    int ret = YAWT_q_crypto_unprotect_packet(&pkt, keys);
    if (ret < 0) {
      printf("  error: unprotect/decrypt failed: %d\n", ret);
      continue;
    }

    // TODO: parse frames from decrypted payload
  }
  if (rc.err != YAWT_Q_OK) {
    printf("  parse error: %d at cursor %zu\n", rc.err, rc.cursor);
  }
}
