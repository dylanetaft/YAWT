#pragma once
#include <stdint.h>
#include <stddef.h>
#include <gnutls/gnutls.h>
#include <stdbool.h>


typedef struct YAWT_Q_Crypto_Cred YAWT_Q_Crypto_Cred_t;

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

// Per-level keys derived by GnuTLS
typedef struct {
  uint8_t secret_read[48];   // traffic secret for reading (max SHA-384 = 48 bytes)
  uint8_t secret_write[48];  // traffic secret for writing
  size_t secret_len;

  // Derived from traffic secret via HKDF-Expand-Label("quic key"/"quic iv"/"quic hp").
  // HKDF-Expand-Label builds TLS 1.3 info: { uint16 length, "tls13 " + label, "" }
  uint8_t key_read[32];   // AEAD key for decryption (16 bytes for AES-128-GCM)
  uint8_t iv_read[12];    // AEAD IV — XOR'd with packet number to form nonce
  uint8_t hp_read[32];    // Header protection key — used with AES-ECB on ciphertext sample
  uint8_t key_write[32];  // AEAD key for encryption
  uint8_t iv_write[12];
  uint8_t hp_write[32];
  size_t key_len;         // 16 for AES-128-GCM (hardcoded for now)

  bool available;             // flag: keys installed for this level
} YAWT_Q_Level_Keys_t;

typedef struct {
  gnutls_session_t session;
  int is_server;

  // Keys per encryption level (Initial=0, Early=1, Handshake=2, Application=3)
  YAWT_Q_Level_Keys_t level_keys[4];

  // Outbound handshake data buffered per level (to be wrapped in CRYPTO frames)
  uint8_t *out_buf[4];
  size_t out_len[4];

  int handshake_complete;
} YAWT_Q_Crypto_t;

YAWT_Q_Crypto_Cred_t *YAWT_q_crypto_cred_new(const char *cert_file,
                                              const char *key_file,
                                              const char *ca_file);

void YAWT_q_crypto_cred_free(YAWT_Q_Crypto_Cred_t **cred);

// Initialize crypto state. is_server=1 for server, 0 for client.
int YAWT_q_crypto_init(YAWT_Q_Crypto_t *crypto,
                    int is_server, YAWT_Q_Crypto_Cred_t *cred);

// Cleanup / free GnuTLS resources
void YAWT_q_crypto_free(YAWT_Q_Crypto_t *crypto);

// Feed received CRYPTO frame data at a given encryption level.
// After calling, check crypto->out_buf[level] for handshake data to send back.
int YAWT_q_crypto_feed(YAWT_Q_Crypto_t *crypto,
                        gnutls_record_encryption_level_t level,
                        const uint8_t *data, size_t data_len);

// Start the handshake (client calls this to produce initial ClientHello)
int YAWT_q_crypto_start(YAWT_Q_Crypto_t *crypto);

// Derive Initial encryption keys from client's Destination Connection ID (RFC 9001 §5.2).
struct YAWT_Q_Cid;
int YAWT_q_crypto_derive_initial_keys(YAWT_Q_Crypto_t *crypto,
                                       const struct YAWT_Q_Cid *dcid);

// Remove header protection in-place (RFC 9001 §5.4).
// pn_offset is the byte offset of the packet number within the packet.
int YAWT_q_crypto_unprotect_header(uint8_t *packet, size_t packet_len,
                                    size_t pn_offset,
                                    const uint8_t *hp_key, size_t hp_key_len);

// AEAD decrypt payload (RFC 9001 §5.3).
int YAWT_q_crypto_decrypt_payload(const uint8_t *key, size_t key_len,
                                   const uint8_t *iv,
                                   uint32_t packet_number,
                                   const uint8_t *header, size_t header_len,
                                   const uint8_t *ciphertext, size_t ciphertext_len,
                                   uint8_t *plaintext, size_t *plaintext_len);

// Forward declaration — full type in quic.h
struct YAWT_Q_Packet;

// Unprotect header + decrypt payload of a parsed packet in-place.
// After this call, the packet's PN and payload contain true values.
// Returns 0 on success, negative on error.
int YAWT_q_crypto_unprotect_packet(struct YAWT_Q_Packet *pkt,
                                    const YAWT_Q_Level_Keys_t *keys);

// Protect (encrypt + apply header protection) an outbound packet in-place.
// packet must contain: unprotected header + plaintext payload + 16 bytes space for AEAD tag.
// packet_len is the total buffer length including the tag space.
// pn_offset is the byte offset of the packet number within the packet.
// pn_length is the length of the packet number field (1-4).
// Returns 0 on success, negative on error.
int YAWT_q_crypto_protect_packet(uint8_t *packet, size_t packet_len,
                                  size_t pn_offset, uint8_t pn_length,
                                  uint32_t packet_num,
                                  const YAWT_Q_Level_Keys_t *keys);
