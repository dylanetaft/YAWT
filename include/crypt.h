#pragma once
#include <stdint.h>
#include <stddef.h>
#include <gnutls/gnutls.h>
#include <stdbool.h>
#include "quic.h"


typedef struct YAWT_Q_Crypto_Cred YAWT_Q_Crypto_Cred_t;
typedef struct YAWT_Q_Crypto YAWT_Q_Crypto_t;

// QUIC encryption levels — index into level_keys[4] array.
// These match gnutls_record_encryption_level_t values.
//
// Secret sources per level:
//   INITIAL:     Derived from client's DCID + well-known salt (RFC 9001 §5.2).
//                No TLS handshake needed — both sides compute independently.
//   EARLY:       0-RTT secrets from TLS (not implemented).
//   HANDSHAKE:   TLS handshake secrets, delivered by GnuTLS _on_secret callback.
//   APPLICATION: TLS application traffic secrets, delivered by GnuTLS _on_secret callback.
//
// For all levels, the same HKDF-Expand-Label step converts the traffic secret
// into usable key/iv/hp:
//   key = HKDF-Expand-Label(secret, "quic key", "", key_len)
//   iv  = HKDF-Expand-Label(secret, "quic iv",  "", 12)
//   hp  = HKDF-Expand-Label(secret, "quic hp",  "", key_len)
typedef enum {
  YAWT_Q_LEVEL_INITIAL = 0,
  YAWT_Q_LEVEL_EARLY = 1,
  YAWT_Q_LEVEL_HANDSHAKE = 2,
  YAWT_Q_LEVEL_APPLICATION = 3
} YAWT_Q_Encryption_Level_t;

// Per-level key state — tracks lifecycle of encryption keys at each level.
// INACTIVE: no keys, can't encrypt/decrypt or accept CRYPTO frames.
// ACTIVE:   keys installed, can encrypt/decrypt, accepts CRYPTO frames.
// DONE:     keys installed, can still encrypt/decrypt (retransmits), rejects new CRYPTO frames.
typedef enum {
  YAWT_Q_KEY_STATE_INACTIVE = 0,
  YAWT_Q_KEY_STATE_ACTIVE,
  YAWT_Q_KEY_STATE_DONE
} YAWT_Q_Key_State_t;


YAWT_Q_Crypto_Cred_t *YAWT_q_crypto_cred_new(const char *cert_file,
                                              const char *key_file,
                                              const char *ca_file);

void YAWT_q_crypto_cred_free(YAWT_Q_Crypto_Cred_t **cred);

// Initialize crypto state. is_server=1 for server, 0 for client.
// original_dcid: client's random DCID from first Initial (for transport params).
// our_cid: our source connection ID (for transport params).
// Returns allocated crypto object, or NULL on error (err set if provided).
YAWT_Q_Crypto_t *YAWT_q_crypto_init(int is_server, YAWT_Q_Crypto_Cred_t *cred,
                    const YAWT_Q_Cid_t *original_dcid,
                    const YAWT_Q_Cid_t *our_cid,
                    YAWT_Q_FlowControl_t *local_fc,
                    YAWT_Q_FlowControl_t *peer_fc,
                    YAWT_Q_Error_t *err);

// Cleanup / free GnuTLS resources
void YAWT_q_crypto_free(YAWT_Q_Crypto_t *crypto);

// Get outbound TLS data for a given level. Returns pointer and length.
// Marks the data as consumed (resets length to 0). The pointer remains valid
// until the next crypto_feed call or crypto_free.
// Returns NULL if no data available.
const uint8_t *YAWT_q_crypto_pop_tx(YAWT_Q_Crypto_t *crypto, int level, size_t *out_len);

// Feed a received CRYPTO frame. Determines encryption level from frame->pkt_type.
// Handles offset-based reassembly internally. After calling, check
// crypto->out_buf[level] for handshake data to send back.
int YAWT_q_crypto_feed(YAWT_Q_Crypto_t *crypto,
                        const YAWT_Q_Frame_t *frame);

// Fill buf with len nonce-quality random bytes (not cryptographically secure).
int YAWT_q_crypto_random_nonce(void *buf, size_t len);

// Start the handshake (client calls this to produce initial ClientHello)
int YAWT_q_crypto_start(YAWT_Q_Crypto_t *crypto);

// Derive Initial encryption keys from client's Destination Connection ID (RFC 9001 §5.2).
int YAWT_q_crypto_derive_initial_keys(YAWT_Q_Crypto_t *crypto,
                                       const YAWT_Q_Cid_t *dcid);

// Remove header protection in-place (RFC 9001 §5.4).
int YAWT_q_crypto_unprotect_header(YAWT_Q_Packet_t *pkt, YAWT_Q_Crypto_t *crypto);

// AEAD decrypt payload (RFC 9001 §5.3).
int YAWT_q_crypto_decrypt_payload(YAWT_Q_Packet_t *pkt, YAWT_Q_Crypto_t *crypto);

// Unprotect header + decrypt payload of a parsed packet in-place.
// After this call, the packet's PN and payload contain true values.
// Returns 0 on success, negative on error.
int YAWT_q_crypto_unprotect_packet(YAWT_Q_Packet_t *pkt, YAWT_Q_Crypto_t *crypto);

// Protect (encrypt + apply header protection) an outbound packet in-place.
// Determines encryption level and selects keys from pkt->type.
// buf must contain: unprotected header + plaintext payload + 16 bytes space for AEAD tag.
// Returns 0 on success, negative on error.
int YAWT_q_crypto_protect_packet(uint8_t *buf, size_t buf_len,
                                  const YAWT_Q_Packet_t *pkt,
                                  YAWT_Q_Crypto_t *crypto);

int YAWT_q_crypto_is_handshake_complete(const YAWT_Q_Crypto_t *crypto);

int YAWT_q_crypto_key_level_available(const YAWT_Q_Crypto_t *crypto, YAWT_Q_Encryption_Level_t level);

