/**
 * @file crypt.h
 * @brief QUIC cryptographic operations — credential management, TLS handshake,
 *        key derivation, and packet protection (GnuTLS backend).
 */

/**
 * @defgroup Crypt 
 * @ingroup QUIC
 * @brief QUIC cryptographic operations and credential management.
 *
 * The credential API (@ref YAWT_q_crypto_cred_new, @ref YAWT_q_crypto_cred_free)
 * is part of the public interface — applications must create credentials before
 * starting the server or client. The remaining functions are used internally by
 * the QUIC connection layer but are documented here for completeness and for
 * users building custom QUIC pipelines.
 */

#pragma once
#include <stdint.h>
#include <stddef.h>
#include <gnutls/gnutls.h>
#include <stdbool.h>
#include "quic.h"
#include "security.h"



/**
 * @ingroup Crypt
 * @brief Opaque cryptographic credential handle.
 * @note Holds TLS certificate, private key, and GnuTLS session configuration.
 *       Created once at startup and shared across all connections.
 */
typedef struct YAWT_Q_Crypto_Cred_t YAWT_Q_Crypto_Cred_t;

/**
 * @ingroup Crypt
 * @brief Opaque per-connection cryptographic state.
 * @note Holds GnuTLS session, key material at each encryption level, and
 *       CRYPTO frame reassembly buffers. Created by YAWT_q_crypto_init().
 */
typedef struct YAWT_Q_Crypto_t YAWT_Q_Crypto_t;

/**
 * @ingroup Crypt
 * @brief QUIC encryption levels — index into level_keys[4] array.
 * @note These match gnutls_record_encryption_level_t values.
 *
 * Secret sources per level:
 *   - INITIAL:     Derived from client's DCID + well-known salt (RFC 9001 §5.2).
 *                  No TLS handshake needed — both sides compute independently.
 *   - EARLY:       0-RTT secrets from TLS (not implemented).
 *   - HANDSHAKE:   TLS handshake secrets, delivered by GnuTLS _on_secret callback.
 *   - APPLICATION: TLS application traffic secrets, delivered by GnuTLS _on_secret callback.
 *
 * For all levels, the same HKDF-Expand-Label step converts the traffic secret
 * into usable key/iv/hp:
 *   - key = HKDF-Expand-Label(secret, "quic key", "", key_len)
 *   - iv  = HKDF-Expand-Label(secret, "quic iv",  "", 12)
 *   - hp  = HKDF-Expand-Label(secret, "quic hp",  "", key_len)
 */
typedef enum {
  YAWT_Q_LEVEL_INITIAL = 0,
  YAWT_Q_LEVEL_EARLY = 1,
  YAWT_Q_LEVEL_HANDSHAKE = 2,
  YAWT_Q_LEVEL_APPLICATION = 3
} YAWT_Q_Encryption_Level_t;

/**
 * @ingroup Crypt
 * @brief Per-level key state — tracks lifecycle of encryption keys at each level.
 * @note - INACTIVE: no keys, can't encrypt/decrypt or accept CRYPTO frames.
 *       - ACTIVE:   keys installed, can encrypt/decrypt, accepts CRYPTO frames.
 *       - DONE:     keys installed, can still encrypt/decrypt (retransmits), rejects new CRYPTO frames.
 */
typedef enum {
  YAWT_Q_KEY_STATE_INACTIVE = 0,
  YAWT_Q_KEY_STATE_ACTIVE,
  YAWT_Q_KEY_STATE_DONE
} YAWT_Q_Key_State_t;


/**
 * @ingroup Crypt
 * @brief Create server or client credentials from certificate and key files.
 * @param cert_file Path to the PEM-encoded certificate file.
 * @param key_file Path to the PEM-encoded private key file.
 * @param ca_file Path to the PEM-encoded CA file for client verification (NULL to skip).
 * @return Allocated credential handle, or NULL on error.
 * @note The credential handle is shared across all connections and must outlive them.
 *       Free with YAWT_q_crypto_cred_free() when no longer needed.
 */
YAWT_Q_Crypto_Cred_t *YAWT_q_crypto_cred_new(const char *cert_file,
                                              const char *key_file,
                                              const char *ca_file);

/**
 * @ingroup Crypt
 * @brief Free credentials and associated GnuTLS resources.
 * @param cred Pointer to the credential handle pointer. Sets *cred = NULL.
 * @note Idempotent against NULL (double-free safe).
 */
void YAWT_q_crypto_cred_free(YAWT_Q_Crypto_Cred_t **cred);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Initialize per-connection crypto state.
 * @param role The endpoint role (client or server).
 * @param cred The shared credential handle.
 * @param original_dcid Client's random DCID from first Initial (for transport params).
 * @param our_cid Our source connection ID (for transport params).
 * @param local_fc Local flow control limits (advertised to peer).
 * @param peer_fc Peer flow control limits (received from peer).
 * @param err Output error code on failure (can be NULL).
 * @return Allocated crypto object, or NULL on error.
 */
YAWT_Q_Crypto_t *YAWT_q_crypto_init(YAWT_Q_Con_Role_t role, YAWT_Q_Crypto_Cred_t *cred,
                    const YAWT_Q_Cid_t *original_dcid,
                    const YAWT_Q_Cid_t *our_cid,
                    YAWT_Q_FlowControl_t *local_fc,
                    YAWT_Q_FlowControl_t *peer_fc,
                    YAWT_Q_Error_t *err);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Free GnuTLS resources and crypto state.
 * @param crypto The crypto object to free.
 */
void YAWT_q_crypto_free(YAWT_Q_Crypto_t *crypto);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Get outbound TLS data for a given encryption level.
 * @param crypto The crypto object.
 * @param level The encryption level.
 * @param out_len Pointer to receive the data length.
 * @return Pointer to the data, or NULL if no data available.
 * @note Marks the data as consumed (resets length to 0). The pointer remains valid
 *       until the next crypto_feed call or crypto_free.
 */
const uint8_t *YAWT_q_crypto_pop_tx(YAWT_Q_Crypto_t *crypto, int level, size_t *out_len);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Feed a received CRYPTO frame to the TLS engine.
 * @param crypto The crypto object.
 * @param frame The CRYPTO frame (determines encryption level from frame->pkt_type).
 * @return YAWT_Q_OK on success, or an error code.
 * @note Handles offset-based reassembly internally. After calling, check
 *       crypto->out_buf[level] for handshake data to send back.
 */
YAWT_Q_Error_t YAWT_q_crypto_feed(YAWT_Q_Crypto_t *crypto,
                                    const YAWT_Q_Frame_t *frame);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Fill a buffer with random bytes (not cryptographically secure).
 * @param buf Output buffer.
 * @param len Number of random bytes to generate.
 * @return 0 on success, negative on error.
 */
int YAWT_q_crypto_random_nonce(void *buf, size_t len);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Start the TLS handshake (client calls this to produce ClientHello).
 * @param crypto The crypto object.
 * @return 0 on success, negative on error.
 */
int YAWT_q_crypto_start(YAWT_Q_Crypto_t *crypto);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Derive Initial encryption keys from client's Destination Connection ID (RFC 9001 §5.2).
 * @param crypto The crypto object.
 * @param dcid The client's Destination Connection ID.
 * @return 0 on success, negative on error.
 */
int YAWT_q_crypto_derive_initial_keys(YAWT_Q_Crypto_t *crypto,
                                       const YAWT_Q_Cid_t *dcid);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Remove header protection in-place (RFC 9001 §5.4).
 * @param pkt The packet whose header protection will be removed.
 * @param crypto The crypto object with keys for the packet's encryption level.
 * @return 0 on success, negative on error.
 */
int YAWT_q_crypto_unprotect_header(YAWT_Q_Packet_t *pkt, YAWT_Q_Crypto_t *crypto);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief AEAD decrypt payload in-place (RFC 9001 §5.3).
 * @param pkt The packet whose payload will be decrypted.
 * @param crypto The crypto object with keys for the packet's encryption level.
 * @return 0 on success, negative on error.
 */
int YAWT_q_crypto_decrypt_payload(YAWT_Q_Packet_t *pkt, YAWT_Q_Crypto_t *crypto);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Unprotect header + decrypt payload of a parsed packet in-place.
 * @param pkt The packet to unprotect.
 * @param crypto The crypto object.
 * @return 0 on success, negative on error.
 * @note After this call, the packet's PN and payload contain true values.
 */
int YAWT_q_crypto_unprotect_packet(YAWT_Q_Packet_t *pkt, YAWT_Q_Crypto_t *crypto);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Protect (encrypt + apply header protection) an outbound packet in-place.
 * @param buf Buffer containing unprotected header + plaintext payload + 16 bytes AEAD tag space.
 * @param buf_len Total buffer length.
 * @param pkt The packet metadata (determines encryption level from pkt->type).
 * @param crypto The crypto object.
 * @return 0 on success, negative on error.
 */
int YAWT_q_crypto_protect_packet(uint8_t *buf, size_t buf_len,
                                  const YAWT_Q_Packet_t *pkt,
                                  YAWT_Q_Crypto_t *crypto);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Check if the TLS handshake has completed.
 * @param crypto The crypto object.
 * @return Non-zero if handshake is complete, 0 otherwise.
 */
int YAWT_q_crypto_is_handshake_complete(const YAWT_Q_Crypto_t *crypto);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Check if keys are available at a given encryption level.
 * @param crypto The crypto object.
 * @param level The encryption level to check.
 * @return Non-zero if keys are available, 0 otherwise.
 */
int YAWT_q_crypto_key_level_available(const YAWT_Q_Crypto_t *crypto, YAWT_Q_Encryption_Level_t level);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Get the last TLS alert received, if any.
 * @param crypto The crypto object.
 * @return The TLS alert description code (0 = no alert received).
 * @note RFC 9000 §22.5: CRYPTO_ERROR = 0x0100 + tls_alert_code.
 */
uint8_t YAWT_q_crypto_get_tls_alert(const YAWT_Q_Crypto_t *crypto);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Clear the stored TLS alert.
 * @param crypto The crypto object.
 */
void YAWT_q_crypto_clear_tls_alert(YAWT_Q_Crypto_t *crypto);
