#include "crypt.h"
#include "quic.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <gnutls/crypto.h>

typedef struct YAWT_Q_Crypto_Cred {
  gnutls_certificate_credentials_t cred;
} YAWT_Q_Crypto_Cred_t;

// RFC 9001 §5.2 — QUIC v1 initial salt
static const uint8_t INITIAL_SALT[] = {
  0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
  0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
};

// Build TLS 1.3 HkdfLabel info and call gnutls_hkdf_expand.
// label is WITHOUT the "tls13 " prefix (e.g. "quic key").
static int _hkdf_expand_label(gnutls_mac_algorithm_t hash,
                               const uint8_t *secret, size_t secret_len,
                               const char *label, size_t label_len,
                               uint8_t *out, size_t out_len) {
  // HkdfLabel = { uint16 length, opaque label<7..255>, opaque context<0..255> }
  // label wire format: "tls13 " + label
  size_t tls_label_len = 6 + label_len; // "tls13 " prefix
  size_t info_len = 2 + 1 + tls_label_len + 1; // length(2) + label_len_byte(1) + label + context_len_byte(1)
  uint8_t info[256];

  if (info_len > sizeof(info)) return -1;

  size_t pos = 0;
  // uint16 length
  info[pos++] = (uint8_t)(out_len >> 8);
  info[pos++] = (uint8_t)(out_len & 0xff);
  // opaque label<7..255>: length byte + "tls13 " + label
  info[pos++] = (uint8_t)tls_label_len;
  memcpy(info + pos, "tls13 ", 6);
  pos += 6;
  memcpy(info + pos, label, label_len);
  pos += label_len;
  // opaque context<0..255>: empty
  info[pos++] = 0;

  gnutls_datum_t secret_d = { .data = (void *)secret, .size = secret_len };
  gnutls_datum_t info_d = { .data = info, .size = pos };

  return gnutls_hkdf_expand(hash, &secret_d, &info_d, out, out_len);
}

// Derive key/iv/hp from a traffic secret. key_len is the AEAD key size (e.g. 16).
static int _derive_pkt_keys(gnutls_mac_algorithm_t hash,
                             const uint8_t *secret, size_t secret_len,
                             uint8_t *key, uint8_t *iv, uint8_t *hp,
                             size_t key_len) {
  int ret;

  ret = _hkdf_expand_label(hash, secret, secret_len, "quic key", 8, key, key_len);
  if (ret < 0) return ret;

  ret = _hkdf_expand_label(hash, secret, secret_len, "quic iv", 7, iv, 12);
  if (ret < 0) return ret;

  ret = _hkdf_expand_label(hash, secret, secret_len, "quic hp", 7, hp, key_len);
  if (ret < 0) return ret;

  return 0;
}

static int _on_handshake_read(gnutls_session_t session,
                               gnutls_record_encryption_level_t level,
                               gnutls_handshake_description_t htype,
                               const void *data, size_t data_size) {
  (void)htype;
  YAWT_Q_Crypto_t *crypto = gnutls_session_get_ptr(session);

  uint8_t *new_buf = realloc(crypto->out_buf[level],
                              crypto->out_len[level] + data_size);
  if (!new_buf) return -1;

  memcpy(new_buf + crypto->out_len[level], data, data_size);
  crypto->out_buf[level] = new_buf;
  crypto->out_len[level] += data_size;
  return 0;
}

static int _on_secret(gnutls_session_t session,
                       gnutls_record_encryption_level_t level,
                       const void *secret_read, const void *secret_write,
                       size_t secret_size) {
  YAWT_Q_Crypto_t *crypto = gnutls_session_get_ptr(session);
  YAWT_Q_Level_Keys_t *keys = &crypto->level_keys[level];

  if (secret_read) memcpy(keys->secret_read, secret_read, secret_size);
  if (secret_write) memcpy(keys->secret_write, secret_write, secret_size);
  keys->secret_len = secret_size;

  // Derive packet protection keys immediately
  // TLS 1.3 with AES-128-GCM uses SHA-256 and 16-byte keys
  gnutls_mac_algorithm_t hash = GNUTLS_MAC_SHA256;
  size_t key_len = 16; // AES-128-GCM

  if (secret_read) {
    _derive_pkt_keys(hash, keys->secret_read, secret_size,
                     keys->key_read, keys->iv_read, keys->hp_read, key_len);
  }
  if (secret_write) {
    _derive_pkt_keys(hash, keys->secret_write, secret_size,
                     keys->key_write, keys->iv_write, keys->hp_write, key_len);
  }
  keys->key_len = key_len;
  keys->available = 1;
  return 0;
}

static int _on_alert(gnutls_session_t session,
                      gnutls_record_encryption_level_t level,
                      gnutls_alert_level_t alert_level,
                      gnutls_alert_description_t alert_desc) {
  (void)session;
  (void)level;
  (void)alert_level;
  (void)alert_desc;
  // TODO: propagate alert to connection layer
  return 0;
}

YAWT_Q_Crypto_Cred_t *YAWT_q_crypto_cred_new(const char *cert_file,
                                               const char *key_file,
                                               const char *ca_file) {
  YAWT_Q_Crypto_Cred_t *cred = malloc(sizeof(YAWT_Q_Crypto_Cred_t));
  if (!cred) return NULL;

  int ret = gnutls_certificate_allocate_credentials(&cred->cred);
  if (ret < 0) {
    free(cred);
    return NULL;
  }

  if (cert_file && key_file) {
    ret = gnutls_certificate_set_x509_key_file(cred->cred,
                                                cert_file, key_file,
                                                GNUTLS_X509_FMT_PEM);
    if (ret < 0) goto fail;
  }

  if (ca_file) {
    ret = gnutls_certificate_set_x509_trust_file(cred->cred,
                                                  ca_file,
                                                  GNUTLS_X509_FMT_PEM);
    if (ret < 0) goto fail;
  }

  return cred;

fail:
  gnutls_certificate_free_credentials(cred->cred);
  free(cred);
  return NULL;
}

void YAWT_q_crypto_cred_free(YAWT_Q_Crypto_Cred_t **cred) {
  if (cred == NULL || *cred == NULL) return;
  gnutls_certificate_free_credentials((*cred)->cred);
  free(*cred);
  *cred = NULL;
}

int YAWT_q_crypto_init(YAWT_Q_Crypto_t *crypto,
                    int is_server, YAWT_Q_Crypto_Cred_t *cred) {
  int ret;

  memset(crypto, 0, sizeof(*crypto));
  crypto->is_server = is_server;

  unsigned int flags = is_server
    ? GNUTLS_SERVER | GNUTLS_NO_AUTO_SEND_TICKET
    : GNUTLS_CLIENT;
  ret = gnutls_init(&crypto->session, flags);
  if (ret < 0) return ret;

  ret = gnutls_priority_set_direct(crypto->session,
                                    "NORMAL:-VERS-ALL:+VERS-TLS1.3", NULL);
  if (ret < 0) return ret;

  ret = gnutls_credentials_set(crypto->session, GNUTLS_CRD_CERTIFICATE,
                                cred->cred);
  if (ret < 0) return ret;

  gnutls_session_set_ptr(crypto->session, crypto);

  gnutls_handshake_set_read_function(crypto->session, _on_handshake_read);
  gnutls_handshake_set_secret_function(crypto->session, _on_secret);
  gnutls_alert_set_read_function(crypto->session, _on_alert);

  // Set ALPN to "h3"
  gnutls_datum_t alpn = { .data = (unsigned char *)"h3", .size = 2 };
  ret = gnutls_alpn_set_protocols(crypto->session, &alpn, 1, 0);
  if (ret < 0) return ret;

  return 0;
}

void YAWT_q_crypto_free(YAWT_Q_Crypto_t *crypto) {
  if (!crypto) return;

  if (crypto->session) {
    gnutls_deinit(crypto->session);
    crypto->session = NULL;
  }

  for (int i = 0; i < 4; i++) {
    free(crypto->out_buf[i]);
    crypto->out_buf[i] = NULL;
    crypto->out_len[i] = 0;
  }
}

int YAWT_q_crypto_start(YAWT_Q_Crypto_t *crypto) {
  int ret = gnutls_handshake(crypto->session);
  if (ret == GNUTLS_E_SUCCESS) {
    crypto->handshake_complete = 1;
    return 0;
  }
  if (ret == GNUTLS_E_AGAIN) {
    return 0; // normal — ClientHello buffered in out_buf
  }
  return ret; // error
}

int YAWT_q_crypto_feed(YAWT_Q_Crypto_t *crypto,
                        gnutls_record_encryption_level_t level,
                        const uint8_t *data, size_t data_len) {
  int ret;

  ret = gnutls_handshake_write(crypto->session, level, data, data_len);
  if (ret < 0) return ret;

  if (!crypto->handshake_complete) {
    ret = gnutls_handshake(crypto->session);
    if (ret == GNUTLS_E_SUCCESS) {
      crypto->handshake_complete = 1;
      return 0;
    }
    if (ret == GNUTLS_E_AGAIN) {
      return 0; // waiting for more data
    }
    return ret; // error
  }

  return 0;
}

// RFC 9001 §5.2 — Initial keys derived from client's Destination Connection ID.
// Salt: 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a (20 bytes)
// Hash: SHA-256, Cipher: AES-128-GCM (hardcoded per spec)
//
// 1. initial_secret = HKDF-Extract(salt, client_dcid)
// 2. client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
// 3. server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", "", 32)
// 4. Derive key/iv/hp from each via _derive_pkt_keys()
//
// For a server: secret_read = client secret, secret_write = server secret.
// For a client: secret_read = server secret, secret_write = client secret.
int YAWT_q_crypto_derive_initial_keys(YAWT_Q_Crypto_t *crypto,
                                       const uint8_t *dcid, size_t dcid_len) {
  YAWT_Q_Level_Keys_t *keys = &crypto->level_keys[YAWT_Q_LEVEL_INITIAL];
  gnutls_mac_algorithm_t hash = GNUTLS_MAC_SHA256;
  size_t hash_len = 32; // SHA-256 output
  size_t key_len = 16;  // AES-128-GCM
  int ret;

  // Step 1: HKDF-Extract(salt, client_dcid) → initial_secret
  uint8_t initial_secret[32];
  gnutls_datum_t salt_d = { .data = (void *)INITIAL_SALT, .size = sizeof(INITIAL_SALT) };
  gnutls_datum_t dcid_d = { .data = (void *)dcid, .size = dcid_len };
  ret = gnutls_hkdf_extract(hash, &dcid_d, &salt_d, initial_secret);
  if (ret < 0) return ret;

  // Step 2: client_initial_secret
  uint8_t client_secret[32];
  ret = _hkdf_expand_label(hash, initial_secret, hash_len,
                            "client in", 9, client_secret, hash_len);
  if (ret < 0) return ret;

  // Step 3: server_initial_secret
  uint8_t server_secret[32];
  ret = _hkdf_expand_label(hash, initial_secret, hash_len,
                            "server in", 9, server_secret, hash_len);
  if (ret < 0) return ret;

  // Step 4: assign read/write based on role
  const uint8_t *read_secret = crypto->is_server ? client_secret : server_secret;
  const uint8_t *write_secret = crypto->is_server ? server_secret : client_secret;

  memcpy(keys->secret_read, read_secret, hash_len);
  memcpy(keys->secret_write, write_secret, hash_len);
  keys->secret_len = hash_len;

  // Step 5: derive packet keys
  ret = _derive_pkt_keys(hash, read_secret, hash_len,
                          keys->key_read, keys->iv_read, keys->hp_read, key_len);
  if (ret < 0) return ret;

  ret = _derive_pkt_keys(hash, write_secret, hash_len,
                          keys->key_write, keys->iv_write, keys->hp_write, key_len);
  if (ret < 0) return ret;

  keys->key_len = key_len;
  keys->available = 1;

  return 0;
}

// Remove header protection in-place (RFC 9001 §5.4).
// 1. Sample 16 bytes of ciphertext starting at pn_offset + 4
// 2. AES-ECB encrypt the sample with the HP key → 16-byte mask
// 3. XOR mask[0] onto byte 0: & 0x0f for long headers, & 0x1f for short
// 4. Read the now-visible PN length from byte 0
// 5. XOR mask[1..pn_len] onto the PN bytes at pn_offset
int YAWT_q_crypto_unprotect_header(uint8_t *packet, size_t packet_len,
                                    size_t pn_offset,
                                    const uint8_t *hp_key, size_t hp_key_len) {
  // Need at least pn_offset + 4 + 16 bytes for the sample
  if (pn_offset + 4 + 16 > packet_len) return -1;

  // Sample 16 bytes starting at pn_offset + 4
  const uint8_t *sample = packet + pn_offset + 4;

  // AES-ECB encrypt the sample to get the mask
  gnutls_cipher_hd_t cipher;
  gnutls_datum_t key_d = { .data = (void *)hp_key, .size = hp_key_len };
  int ret = gnutls_cipher_init(&cipher, GNUTLS_CIPHER_AES_128_CBC, &key_d, NULL);
  if (ret < 0) return ret;

  uint8_t mask[16];
  memcpy(mask, sample, 16);
  // For ECB-like single block: encrypt in-place with CBC and zero IV
  // gnutls doesn't have AES-128-ECB, so use CBC with zero IV for a single block
  ret = gnutls_cipher_encrypt(cipher, mask, 16);
  gnutls_cipher_deinit(cipher);
  if (ret < 0) return ret;

  // Unmask byte 0
  if (packet[0] & 0x80) {
    // Long header: mask lower 4 bits
    packet[0] ^= (mask[0] & 0x0f);
  } else {
    // Short header: mask lower 5 bits
    packet[0] ^= (mask[0] & 0x1f);
  }

  // Read PN length from (now unmasked) byte 0
  uint8_t pn_len = (packet[0] & 0x03) + 1;

  // Unmask PN bytes
  for (uint8_t i = 0; i < pn_len; i++) {
    packet[pn_offset + i] ^= mask[1 + i];
  }

  return 0;
}

// AEAD decryption (RFC 9001 §5.3)
// 1. Construct 12-byte nonce: iv XOR (packet_number zero-padded to 12 bytes)
// 2. AAD = unprotected header bytes (byte 0 through end of PN field)
// 3. Ciphertext includes 16-byte GCM authentication tag at the end
// 4. gnutls_aead_cipher_decrypt() verifies tag and produces plaintext
int YAWT_q_crypto_decrypt_payload(const uint8_t *key, size_t key_len,
                                   const uint8_t *iv,
                                   uint32_t packet_number,
                                   const uint8_t *header, size_t header_len,
                                   const uint8_t *ciphertext, size_t ciphertext_len,
                                   uint8_t *plaintext, size_t *plaintext_len) {
  // Ciphertext must contain at least the 16-byte auth tag
  if (ciphertext_len < 16) return -1;

  // Construct nonce: iv XOR packet_number (right-aligned in 12 bytes)
  uint8_t nonce[12];
  memcpy(nonce, iv, 12);
  nonce[11] ^= (uint8_t)(packet_number);
  nonce[10] ^= (uint8_t)(packet_number >> 8);
  nonce[9]  ^= (uint8_t)(packet_number >> 16);
  nonce[8]  ^= (uint8_t)(packet_number >> 24);

  gnutls_aead_cipher_hd_t cipher;
  gnutls_datum_t key_d = { .data = (void *)key, .size = key_len };
  int ret = gnutls_aead_cipher_init(&cipher, GNUTLS_CIPHER_AES_128_GCM, &key_d);
  if (ret < 0) return ret;

  size_t tag_size = 16;
  ret = gnutls_aead_cipher_decrypt(cipher, nonce, 12,
                                    header, header_len,
                                    tag_size,
                                    ciphertext, ciphertext_len,
                                    plaintext, plaintext_len);
  gnutls_aead_cipher_deinit(cipher);
  return ret;
}

// Unprotect header + decrypt payload of a parsed packet in-place.
// 1. Header unprotection: unmasks byte 0 and PN bytes using HP key
// 2. Re-reads the true PN from the now-unmasked bytes
// 3. AEAD decrypts payload in-place (plaintext replaces ciphertext)
// 4. Updates common struct fields (packet_num, payload_len)
int YAWT_q_crypto_unprotect_packet(YAWT_Q_Packet_t *pkt,
                                    const YAWT_Q_Level_Keys_t *keys) {
  if (!pkt || !keys || !keys->available) return -1;
  if (!pkt->common) return 0; // Retry — nothing to decrypt
  if (!pkt->raw || !pkt->common->payload || pkt->common->payload_len == 0) return -1;

  uint8_t *packet = pkt->raw;
  YAWT_Q_Packet_Common_t *c = pkt->common;

  // Total packet length: from raw through end of payload
  size_t packet_len = (size_t)(c->payload + c->payload_len - packet);

  // Step 1: Header unprotection
  int ret = YAWT_q_crypto_unprotect_header(packet, packet_len,
                                            pkt->pn_offset,
                                            keys->hp_read, keys->key_len);
  if (ret < 0) return ret;

  // Step 2: Re-read true PN length and PN value from unmasked bytes
  c->packet_number_length = (packet[0] & 0x03) + 1;
  c->packet_num = 0;
  for (uint8_t i = 0; i < c->packet_number_length; i++) {
    c->packet_num = (c->packet_num << 8) | packet[pkt->pn_offset + i];
  }

  // Step 3: AEAD decrypt
  // AAD = header bytes (byte 0 through end of PN)
  size_t header_len = pkt->pn_offset + c->packet_number_length;
  // Ciphertext starts right after PN
  const uint8_t *ciphertext = packet + header_len;
  size_t ciphertext_len = (size_t)(c->payload + c->payload_len - ciphertext);

  // Decrypt in-place: write plaintext starting at payload pointer
  size_t plaintext_len = c->payload_len;
  ret = YAWT_q_crypto_decrypt_payload(keys->key_read, keys->key_len,
                                       keys->iv_read, c->packet_num,
                                       packet, header_len,
                                       ciphertext, ciphertext_len,
                                       c->payload, &plaintext_len);
  if (ret < 0) return ret;

  c->payload_len = plaintext_len;

  printf("  decrypted %zu bytes (PN=%u, pn_len=%u)\n",
         plaintext_len, c->packet_num, c->packet_number_length);
  return 0;
}
