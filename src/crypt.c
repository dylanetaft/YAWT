#include "crypt.h"
#include "quic.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <gnutls/crypto.h>
#include "logger.h"


// Per-level keys derived by GnuTLS
typedef struct YAWT_Q_Level_Keys {
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
  size_t key_len;         // 16 for AES-128-GCM, 32 for AES-256-GCM
  int aead_cipher;        // gnutls_cipher_algorithm_t for AEAD encrypt/decrypt

  bool available;             // flag: keys installed for this level
} YAWT_Q_Level_Keys_t;

typedef struct YAWT_Q_Crypto {
  gnutls_session_t session;
  int is_server;

  // Keys per encryption level (Initial=0, Early=1, Handshake=2, Application=3)
  YAWT_Q_Level_Keys_t level_keys[4];

  // Outbound handshake data buffered per level (to be wrapped in CRYPTO frames)
  uint8_t *out_buf[4];
  size_t out_len[4];

  // Inbound CRYPTO reassembly — handles out-of-order CRYPTO frames
  ANB_Slab_t *rx_crypto_buf;              // buffered out-of-order CRYPTO frames
  uint64_t rx_crypto_next_offset[4];      // next expected contiguous byte offset per level

  int handshake_complete;

  // CIDs for transport parameters (RFC 9000 §18.2)
  YAWT_Q_Cid_t original_dcid;   // client's random DCID from first Initial
  YAWT_Q_Cid_t our_cid;         // our source connection ID
} YAWT_Q_Crypto_t;
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
// is_read: 1 = derive read keys, 0 = derive write keys
static int _derive_pkt_keys(YAWT_Q_Level_Keys_t *keys,
                             gnutls_mac_algorithm_t hash, int is_read) {

  const uint8_t *secret = is_read ? keys->secret_read : keys->secret_write;
  uint8_t *key = is_read ? keys->key_read : keys->key_write;
  uint8_t *iv  = is_read ? keys->iv_read  : keys->iv_write;
  uint8_t *hp  = is_read ? keys->hp_read  : keys->hp_write;
  int ret;
  // Key expansion labels (RFC 9001 §5.1)
  ret = _hkdf_expand_label(hash, secret, keys->secret_len, "quic key", 8, key, keys->key_len);
  if (ret < 0) return ret;
  // IV is always 12 bytes for QUIC (RFC 9001 §5.3)
  ret = _hkdf_expand_label(hash, secret, keys->secret_len, "quic iv", 7, iv, 12);
  if (ret < 0) return ret;
  ret = _hkdf_expand_label(hash, secret, keys->secret_len, "quic hp", 7, hp, keys->key_len);
  if (ret < 0) return ret;

  return 0;
}

static int _on_handshake_read(gnutls_session_t session,
                               gnutls_record_encryption_level_t level,
                               gnutls_handshake_description_t htype,
                               const void *data, size_t data_size) {
  YAWT_Q_Crypto_t *crypto = gnutls_session_get_ptr(session);
  YAWT_LOG(YAWT_LOG_DEBUG, "handshake_read: level=%d, htype=%d, size=%zu", level, htype, data_size);

  // QUIC must not send ChangeCipherSpec (RFC 9001 §8.4)
  if (htype == GNUTLS_HANDSHAKE_CHANGE_CIPHER_SPEC) return 0;

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

  gnutls_cipher_algorithm_t neg_cipher = gnutls_cipher_get(session);
  gnutls_mac_algorithm_t neg_mac = gnutls_mac_get(session);
  YAWT_LOG(YAWT_LOG_DEBUG, "_on_secret: level=%d, secret_read=%p, secret_write=%p, size=%zu, "
           "cipher=%d (%s), mac=%d (%s), key_size=%zu",
           level, secret_read, secret_write, secret_size,
           neg_cipher, gnutls_cipher_get_name(neg_cipher),
           neg_mac, gnutls_mac_get_name(neg_mac),
           gnutls_cipher_get_key_size(neg_cipher));

  if (secret_read) memcpy(keys->secret_read, secret_read, secret_size);
  if (secret_write) memcpy(keys->secret_write, secret_write, secret_size);
  keys->secret_len = secret_size;

  // Derive packet protection keys from negotiated cipher suite
  // gnutls_mac_get() returns GNUTLS_MAC_AEAD for TLS 1.3 — use PRF hash instead
  gnutls_mac_algorithm_t hash = (gnutls_mac_algorithm_t)gnutls_prf_hash_get(session);
  keys->key_len = gnutls_cipher_get_key_size(gnutls_cipher_get(session));
  keys->aead_cipher = gnutls_cipher_get(session);

  if (secret_read) _derive_pkt_keys(keys, hash, 1);
  if (secret_write) _derive_pkt_keys(keys, hash, 0);
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

// QUIC transport parameters extension (RFC 9000 §18, extension type 0x0039)
#define QUIC_TP_EXT_TYPE 0x0039

// Receive client's transport parameters (we ignore them for now)
static int _tp_recv(gnutls_session_t session, const unsigned char *data, size_t len) {
  (void)session; (void)data; (void)len;
  return 0;
}

// Append a single transport parameter: varint ID + varint length + raw value
static int _tp_append(gnutls_buffer_t extdata, uint8_t id,
                       const uint8_t *val, size_t val_len) {
  int ret;
  ret = gnutls_buffer_append_data(extdata, &id, 1);
  if (ret < 0) return ret;
  uint8_t len = (uint8_t)val_len;
  ret = gnutls_buffer_append_data(extdata, &len, 1);
  if (ret < 0) return ret;
  if (val_len > 0) {
    ret = gnutls_buffer_append_data(extdata, val, val_len);
    if (ret < 0) return ret;
  }
  return 0;
}

// Send our transport parameters (RFC 9000 §18)
static int _tp_send(gnutls_session_t session, gnutls_buffer_t extdata) {
  YAWT_Q_Crypto_t *crypto = gnutls_session_get_ptr(session);
  int ret;
  size_t total = 0;

  // RFC 9000 §18.2: server MUST include original_destination_connection_id (0x00)
  ret = _tp_append(extdata, 0x00, crypto->original_dcid.id, crypto->original_dcid.len);
  if (ret < 0) return ret;
  total += 2 + crypto->original_dcid.len;

  // RFC 9000 §18.2: both endpoints MUST include initial_source_connection_id (0x0f)
  ret = _tp_append(extdata, 0x0f, crypto->our_cid.id, crypto->our_cid.len);
  if (ret < 0) return ret;
  total += 2 + crypto->our_cid.len;

  // Flow control parameters
  uint8_t params[] = {
    0x04, 0x04, 0x80, 0x10, 0x00, 0x00, // initial_max_data = 1MB
    0x05, 0x04, 0x80, 0x10, 0x00, 0x00, // initial_max_stream_data_bidi_local = 1MB
    0x06, 0x04, 0x80, 0x10, 0x00, 0x00, // initial_max_stream_data_bidi_remote = 1MB
    0x07, 0x04, 0x80, 0x10, 0x00, 0x00, // initial_max_stream_data_uni = 1MB
    0x08, 0x01, 0x10,                    // initial_max_streams_bidi = 16
    0x09, 0x01, 0x10,                    // initial_max_streams_uni = 16
  };
  ret = gnutls_buffer_append_data(extdata, params, sizeof(params));
  if (ret < 0) return ret;
  total += sizeof(params);

  return (int)total;
}

int YAWT_q_crypto_init(YAWT_Q_Crypto_t *crypto,
                    int is_server, YAWT_Q_Crypto_Cred_t *cred,
                    const YAWT_Q_Cid_t *original_dcid,
                    const YAWT_Q_Cid_t *our_cid) {

  if (!crypto || !cred || !original_dcid || !our_cid) {
    YAWT_LOG(YAWT_LOG_ERROR, "Invalid arguments to YAWT_q_crypto_init");
    return -1;
  }
  int ret;

  memset(crypto, 0, sizeof(*crypto));
  crypto->is_server = is_server;
  crypto->rx_crypto_buf = ANB_slab_create(4096);
  // Set CIDs for transport parameters (RFC 9000 §18.2)
  YAWT_q_cid_set(&crypto->original_dcid, original_dcid->id, original_dcid->len);
  YAWT_q_cid_set(&crypto->our_cid, our_cid->id, our_cid->len);

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

  // Register QUIC transport parameters extension (RFC 9000 §18)
  unsigned int ext_flags = GNUTLS_EXT_FLAG_TLS
                         | GNUTLS_EXT_FLAG_CLIENT_HELLO
                         | GNUTLS_EXT_FLAG_EE;
  ret = gnutls_session_ext_register(crypto->session,
                                     "QUIC Transport Parameters",
                                     QUIC_TP_EXT_TYPE,
                                     GNUTLS_EXT_APPLICATION,
                                     _tp_recv, _tp_send,
                                     NULL, NULL, NULL,
                                     ext_flags);
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
  if (crypto->rx_crypto_buf) {
    ANB_slab_destroy(crypto->rx_crypto_buf);
    crypto->rx_crypto_buf = NULL;
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

// Write contiguous data to GnuTLS and drive the handshake forward
static int _crypto_handshake_write(YAWT_Q_Crypto_t *crypto,
                                    YAWT_Q_Encryption_Level_t level,
                                    const uint8_t *data, size_t data_len) {
  int ret = gnutls_handshake_write(crypto->session,
                                    (gnutls_record_encryption_level_t)level,
                                    data, data_len);
  if (ret < 0) {
    YAWT_LOG(YAWT_LOG_ERROR, "handshake_write failed: %d (%s)", ret, gnutls_strerror(ret));
    return ret;
  }

  if (!crypto->handshake_complete) {
    ret = gnutls_handshake(crypto->session);
    if (ret == GNUTLS_E_SUCCESS) {
      YAWT_LOG(YAWT_LOG_INFO, "handshake complete");
      crypto->handshake_complete = 1;
      return 0;
    }
    if (ret == GNUTLS_E_AGAIN) {
      YAWT_LOG(YAWT_LOG_DEBUG, "handshake needs more data, out_buf: [%zu, %zu, %zu, %zu]",
               crypto->out_len[0], crypto->out_len[1], crypto->out_len[2], crypto->out_len[3]);
      return 0;
    }
    YAWT_LOG(YAWT_LOG_ERROR, "handshake failed: %d (%s)", ret, gnutls_strerror(ret));
    return ret;
  }

  return 0;
}

// Map packet type to encryption level
static YAWT_Q_Encryption_Level_t _pkt_type_to_level(YAWT_Q_Packet_Type_t pkt_type) {
  switch (pkt_type) {
    case YAWT_Q_PKT_TYPE_INITIAL:   return YAWT_Q_LEVEL_INITIAL;
    case YAWT_Q_PKT_TYPE_0RTT:      return YAWT_Q_LEVEL_EARLY;
    case YAWT_Q_PKT_TYPE_HANDSHAKE: return YAWT_Q_LEVEL_HANDSHAKE;
    default:                         return YAWT_Q_LEVEL_APPLICATION;
  }
}

// Drain buffered out-of-order CRYPTO frames that are now contiguous
static int _drain_crypto_buf(YAWT_Q_Crypto_t *crypto) {
  ANB_SlabIter_t iter = {0};
  size_t item_size;
  uint8_t *item;
  while ((item = ANB_slab_peek_item_iter(crypto->rx_crypto_buf, &iter, &item_size)) != NULL) {
    YAWT_Q_Frame_t *buffered = (YAWT_Q_Frame_t *)item;
    YAWT_Q_Encryption_Level_t lvl = _pkt_type_to_level(buffered->pkt_type);

    if (buffered->crypto.offset == crypto->rx_crypto_next_offset[lvl]) {
      int ret = _crypto_handshake_write(crypto, lvl,
                                         buffered->crypto.data, buffered->crypto.len);
      if (ret < 0) return ret;
      crypto->rx_crypto_next_offset[lvl] += buffered->crypto.len;
      ANB_slab_pop_item(crypto->rx_crypto_buf, &iter);
    }
  }
  return 0;
}

int YAWT_q_crypto_feed(YAWT_Q_Crypto_t *crypto,
                        const YAWT_Q_Frame_t *frame) {
  YAWT_Q_Encryption_Level_t level = _pkt_type_to_level(frame->pkt_type);
  uint64_t offset = frame->crypto.offset;
  uint64_t end = offset + frame->crypto.len;

  // Skip fully duplicate data
  if (end <= crypto->rx_crypto_next_offset[level]) return 0;

  // In-order: feed directly to TLS
  if (offset == crypto->rx_crypto_next_offset[level]) {
    int ret = _crypto_handshake_write(crypto, level,
                                       frame->crypto.data, frame->crypto.len);
    if (ret < 0) return ret;
    crypto->rx_crypto_next_offset[level] = end;

    // Check if any buffered frames are now contiguous
    return _drain_crypto_buf(crypto);
  }

  // Out-of-order: buffer for later
  YAWT_LOG(YAWT_LOG_DEBUG, "CRYPTO gap at level %d: expected %lu, got offset %lu — buffering",
            level, crypto->rx_crypto_next_offset[level], offset);
  ANB_slab_push_item(crypto->rx_crypto_buf, (const uint8_t *)frame, sizeof(*frame));
  return 0;
}

const uint8_t *YAWT_q_crypto_pop_tx(YAWT_Q_Crypto_t *crypto, int level, size_t *out_len) {
  if (!crypto || level < 0 || level > 3 || crypto->out_len[level] == 0) {
    if (out_len) *out_len = 0;
    return NULL;
  }
  if (out_len) *out_len = crypto->out_len[level];
  const uint8_t *ptr = crypto->out_buf[level];
  crypto->out_len[level] = 0;
  return ptr;
}

int YAWT_q_crypto_random_nonce(void *buf, size_t len) {
  return gnutls_rnd(GNUTLS_RND_NONCE, buf, len);
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
                                       const YAWT_Q_Cid_t *dcid) {
  // RFC 9000 §7.2 — client DCID must be at least 8 bytes
  if (dcid->len < 8) return -1;
  // RFC 9001 §5.2 initial keys are always derived 
  // using HKDF-SHA256 with AES-128-GCM
  YAWT_Q_Level_Keys_t *keys = &crypto->level_keys[YAWT_Q_LEVEL_INITIAL];
  gnutls_mac_algorithm_t hash = GNUTLS_MAC_SHA256;
  const size_t hash_len = 32; // SHA-256 output
  const size_t key_len = 16;  // AES-128-GCM
  int ret;

  // Step 1: HKDF-Extract(salt, client_dcid) → initial_secret
  uint8_t initial_secret[32];
  gnutls_datum_t salt_d = { .data = (void *)INITIAL_SALT, .size = sizeof(INITIAL_SALT) };
  gnutls_datum_t dcid_d = { .data = (void *)dcid->id, .size = dcid->len };
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
  keys->key_len = key_len;
  keys->aead_cipher = GNUTLS_CIPHER_AES_128_GCM; // RFC 9001 §5.2: Initial always AES-128-GCM

  // Step 5: derive packet keys
  ret = _derive_pkt_keys(keys, hash, 1);
  if (ret < 0) return ret;

  ret = _derive_pkt_keys(keys, hash, 0);
  if (ret < 0) return ret;

  keys->available = 1;

  return 0;
}

// Remove header protection in-place (RFC 9001 §5.4).
// 1. Sample 16 bytes of ciphertext starting at pn_offset + 4
// 2. AES-ECB encrypt the sample with the HP key → 16-byte mask
// 3. XOR mask[0] onto byte 0: & 0x0f for long headers, & 0x1f for short
// 4. Read the now-visible PN length from byte 0
// 5. XOR mask[1..pn_len] onto the PN bytes at pn_offset
// RFC 9001 §5.4.3: HP cipher is the block cipher underlying the negotiated AEAD.
// AES-ECB is emulated via CBC with zero IV on a single block.
static gnutls_cipher_algorithm_t _hp_cipher_for_aead(int aead_cipher) {
  switch (aead_cipher) {
    case GNUTLS_CIPHER_AES_256_GCM: return GNUTLS_CIPHER_AES_256_CBC;
    default:                         return GNUTLS_CIPHER_AES_128_CBC;
  }
}

int YAWT_q_crypto_unprotect_header(YAWT_Q_Packet_t *pkt, YAWT_Q_Crypto_t *crypto) {
  if (!pkt || !crypto) return -1;
  YAWT_Q_Encryption_Level_t level = _pkt_type_to_level(pkt->type);
  const YAWT_Q_Level_Keys_t *keys = &crypto->level_keys[level];
  size_t pn_offset = pkt->pn_offset;
  uint8_t *packet = pkt->raw;
  size_t packet_len = (size_t)(pkt->payload + pkt->payload_len - packet);
  // Need at least pn_offset + 4 + 16 bytes for the sample
  if (pn_offset + 4 + 16 > packet_len) return -1;

  // Sample 16 bytes starting at pn_offset + 4
  const uint8_t *sample = packet + pn_offset + 4;

  // AES-ECB encrypt the sample to get the mask
  // CBC with zero IV on a single block is equivalent to ECB
  gnutls_cipher_hd_t cipher;
  gnutls_datum_t key_d = { .data = (void *)keys->hp_read, .size = keys->key_len };
  uint8_t zero_iv[16] = {0};
  gnutls_datum_t iv_d = { .data = zero_iv, .size = sizeof(zero_iv) };
  int ret = gnutls_cipher_init(&cipher, _hp_cipher_for_aead(keys->aead_cipher), &key_d, &iv_d);
  if (ret < 0) return ret;

  uint8_t mask[16];
  memcpy(mask, sample, 16);
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
// Decrypts in-place and updates pkt->payload / pkt->payload_len.
// Must be called after unprotect_header (needs true PN).
int YAWT_q_crypto_decrypt_payload(YAWT_Q_Packet_t *pkt, YAWT_Q_Crypto_t *crypto) {
  if (!pkt || !crypto) return -1;

  YAWT_Q_Encryption_Level_t level = _pkt_type_to_level(pkt->type);
  const YAWT_Q_Level_Keys_t *keys = &crypto->level_keys[level];
  uint8_t *packet = pkt->raw;

  // AAD = header bytes (byte 0 through end of PN)
  size_t header_len = pkt->pn_offset + pkt->packet_number_length;
  // Ciphertext starts right after PN
  uint8_t *ciphertext = packet + header_len;
  size_t ciphertext_len = (size_t)(pkt->payload + pkt->payload_len - ciphertext);

  // Ciphertext must contain at least the 16-byte auth tag
  if (ciphertext_len < 16) return -1;

  // Construct nonce: iv XOR packet_number (right-aligned in 12 bytes)
  uint8_t nonce[12];
  memcpy(nonce, keys->iv_read, 12);
  nonce[11] ^= (uint8_t)(pkt->packet_num);
  nonce[10] ^= (uint8_t)(pkt->packet_num >> 8);
  nonce[9]  ^= (uint8_t)(pkt->packet_num >> 16);
  nonce[8]  ^= (uint8_t)(pkt->packet_num >> 24);

  gnutls_aead_cipher_hd_t cipher;
  gnutls_datum_t key_d = { .data = (void *)keys->key_read, .size = keys->key_len };
  int ret = gnutls_aead_cipher_init(&cipher, keys->aead_cipher, &key_d);
  if (ret < 0) return ret;

  size_t tag_size = 16;
  size_t plaintext_len = ciphertext_len;
  ret = gnutls_aead_cipher_decrypt(cipher, nonce, 12,
                                    packet, header_len,
                                    tag_size,
                                    ciphertext, ciphertext_len,
                                    ciphertext, &plaintext_len);
  gnutls_aead_cipher_deinit(cipher);
  if (ret < 0) return ret;

  // Update payload to point to decrypted frames
  pkt->payload = ciphertext;
  pkt->payload_len = plaintext_len;
  return 0;
}

// Unprotect header + decrypt payload of a parsed packet in-place.
// 1. Header unprotection: unmasks byte 0 and PN bytes using HP key
// 2. Re-reads the true PN from the now-unmasked bytes
// 3. AEAD decrypts payload in-place (plaintext replaces ciphertext)
// 4. Updates common struct fields (packet_num, payload_len)
int YAWT_q_crypto_unprotect_packet(YAWT_Q_Packet_t *pkt, YAWT_Q_Crypto_t *crypto) {

  if (!pkt || !crypto) return -1;

  if (pkt->type == YAWT_Q_PKT_TYPE_RETRY) return 0; // Retry — nothing to decrypt
  if (!pkt->raw || !pkt->payload || pkt->payload_len == 0) return -1;

  uint8_t *packet = pkt->raw;

  // Step 1: Header unprotection
  int ret = YAWT_q_crypto_unprotect_header(pkt, crypto); 
  if (ret < 0) return ret;

  // Step 2: Re-read true PN length and PN value from unmasked bytes
  pkt->packet_number_length = (packet[0] & 0x03) + 1;
  pkt->packet_num = 0;
  for (uint8_t i = 0; i < pkt->packet_number_length; i++) {
    pkt->packet_num = (pkt->packet_num << 8) | packet[pkt->pn_offset + i];
  }

  // Step 3: AEAD decrypt
  ret = YAWT_q_crypto_decrypt_payload(pkt, crypto);
  if (ret < 0) return ret;

  YAWT_LOG(YAWT_LOG_DEBUG, "Decrypted %zu bytes (PN=%u, pn_len=%u)",
           pkt->payload_len, pkt->packet_num, pkt->packet_number_length);
  return 0;
}

// Protect (encrypt + header protect) an outbound packet in-place (RFC 9001 §5.3, §5.4).
// The buffer layout on entry:
//   [header (pn_offset bytes)] [PN (pn_length bytes)] [plaintext] [16 bytes tag space]
// After AEAD encrypt:
//   [header] [PN] [ciphertext + tag]
// After header protection:
//   [masked header] [masked PN] [ciphertext + tag]
// Note: protect_packet takes a separate buffer+length (rather than using pkt->raw)
// because the encode path rebuilds packets from buffered frames with fresh PNs —
// the output buffer is owned by the encoder, not the packet struct.
int YAWT_q_crypto_protect_packet(uint8_t *packet, size_t packet_len,
                                  const YAWT_Q_Packet_t *pkt,
                                  YAWT_Q_Crypto_t *crypto) {
  YAWT_Q_Encryption_Level_t level = _pkt_type_to_level(pkt->type);
  const YAWT_Q_Level_Keys_t *keys = &crypto->level_keys[level];
  if (!packet || !keys->available) return -1;

  size_t pn_offset = pkt->pn_offset;
  uint8_t pn_length = pkt->packet_number_length;
  uint32_t packet_num = pkt->packet_num;

  size_t header_len = pn_offset + pn_length;
  if (header_len >= packet_len) return -1;

  // Plaintext starts after header, ends 16 bytes before buffer end (tag space)
  size_t ciphertext_area = packet_len - header_len;
  if (ciphertext_area < 16) return -1; // need at least tag space
  size_t plaintext_len = ciphertext_area - 16;

  // Construct nonce: iv XOR packet_number (right-aligned in 12 bytes)
  uint8_t nonce[12];
  memcpy(nonce, keys->iv_write, 12);
  nonce[11] ^= (uint8_t)(packet_num);
  nonce[10] ^= (uint8_t)(packet_num >> 8);
  nonce[9]  ^= (uint8_t)(packet_num >> 16);
  nonce[8]  ^= (uint8_t)(packet_num >> 24);

  // AEAD encrypt
  gnutls_aead_cipher_hd_t cipher;
  gnutls_datum_t key_d = { .data = (void *)keys->key_write, .size = keys->key_len };
  int ret = gnutls_aead_cipher_init(&cipher, keys->aead_cipher, &key_d);
  if (ret < 0) return ret;

  // Encrypt plaintext in-place. Output goes to same location (header_len offset).
  // gnutls_aead_cipher_encrypt writes ciphertext + tag.
  uint8_t *plaintext = packet + header_len;
  size_t out_len = ciphertext_area; // space for ciphertext + tag
  size_t tag_size = 16;

  ret = gnutls_aead_cipher_encrypt(cipher, nonce, 12,
                                    packet, header_len, // AAD = header
                                    tag_size,
                                    plaintext, plaintext_len,
                                    plaintext, &out_len);
  gnutls_aead_cipher_deinit(cipher);
  if (ret < 0) return ret;

  // Header protection: AES-ECB(hp_key, sample) → mask
  // Sample = 16 bytes starting at pn_offset + 4
  if (pn_offset + 4 + 16 > packet_len) return -1;
  const uint8_t *sample = packet + pn_offset + 4;

  gnutls_cipher_hd_t hp_cipher;
  gnutls_datum_t hp_key_d = { .data = (void *)keys->hp_write, .size = keys->key_len };
  uint8_t zero_iv[16] = {0};
  gnutls_datum_t hp_iv_d = { .data = zero_iv, .size = sizeof(zero_iv) };
  ret = gnutls_cipher_init(&hp_cipher, _hp_cipher_for_aead(keys->aead_cipher), &hp_key_d, &hp_iv_d);
  if (ret < 0) return ret;

  uint8_t mask[16];
  memcpy(mask, sample, 16);
  ret = gnutls_cipher_encrypt(hp_cipher, mask, 16);
  gnutls_cipher_deinit(hp_cipher);
  if (ret < 0) return ret;

  // Mask byte 0
  if (packet[0] & 0x80) {
    // Long header: mask lower 4 bits
    packet[0] ^= (mask[0] & 0x0f);
  } else {
    // Short header: mask lower 5 bits
    packet[0] ^= (mask[0] & 0x1f);
  }

  // Mask PN bytes
  for (uint8_t i = 0; i < pn_length; i++) {
    packet[pn_offset + i] ^= mask[1 + i];
  }

  return 0;
}

int YAWT_q_crypto_is_handshake_complete(const YAWT_Q_Crypto_t *crypto) {
  return crypto ? crypto->handshake_complete : 0;
}

int YAWT_q_crypto_key_level_available(const YAWT_Q_Crypto_t *crypto, YAWT_Q_Encryption_Level_t level) {
  if (!crypto || level < 0 || level > 3) return 0;
  return crypto->level_keys[level].available;
}

