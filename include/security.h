/**
 * @file security.h
 * @brief Security policy and flow control configuration for QUIC and HTTP/3 layers.
 */

/**
 * @defgroup Security Security
 * @brief Security policy and flow control configuration for QUIC and HTTP/3.
 */

#pragma once
#include <stdint.h>

/**
 * @ingroup Security
 * @brief Flow control limits — populated from transport params, updated by MAX_* frames.
 * @note These values are advertised to the peer and enforced locally. Zero values
 *       indicate the feature is disabled or unlimited.
 */
typedef struct {
  uint64_t max_idle_timeout;            /**< 0x01: milliseconds, 0 = disabled */
  uint64_t max_data;                    /**< 0x04: connection-level byte limit */
  uint64_t max_stream_data_bidi_local;  /**< 0x05: per-stream, sender-initiated bidi */
  uint64_t max_stream_data_bidi_remote; /**< 0x06: per-stream, receiver-initiated bidi */
  uint64_t max_stream_data_uni;         /**< 0x07: per-stream, unidirectional */
  uint64_t max_streams_bidi;            /**< 0x08: max concurrent bidirectional streams */
  uint64_t max_streams_uni;             /**< 0x09: max concurrent unidirectional streams */
  uint64_t max_datagram_frame_size;     /**< 0x20: RFC 9221, 0 = datagrams not supported */
} YAWT_Q_FlowControl_t;

/**
 * @ingroup Security
 * @brief QUIC layer security policy — tunable limits to prevent resource exhaustion.
 * @note These are process-wide settings, not per-connection. The getter returns a
 *       const pointer to a static global; do not free it.
 */
typedef struct {
  uint64_t min_idle_timeout_ms;    /**< Floor for effective idle timeout (ms), 0 = no floor */
  uint64_t max_crypto_buffer_bytes; /**< Max out-of-order CRYPTO buffering per connection, 0 = unlimited */
} YAWT_Q_SecurityPolicy_t;

/**
 * @ingroup Security
 * @brief Get the current QUIC security policy.
 * @return Const pointer to the static global policy (valid for process lifetime).
 * @note The pointed-to values are a snapshot; re-get after a set() to observe changes.
 */
const YAWT_Q_SecurityPolicy_t *YAWT_q_security_get(void);

/**
 * @ingroup Security
 * @brief Set the QUIC security policy.
 * @param policy Pointer to the new policy values (copied into the global).
 * @note Replaces the global policy. Passing NULL is a no-op.
 */
void YAWT_q_security_set(const YAWT_Q_SecurityPolicy_t *policy);

/**
 * @ingroup Security
 * @brief Get the default flow-control limits.
 * @return Const pointer to the static global default limits (valid for process lifetime).
 * @note Used when YAWT_Q_Con_Create_Info_t.local_fc is NULL.
 */
const YAWT_Q_FlowControl_t *YAWT_q_security_get_default_fc(void);

/**
 * @ingroup Security
 * @brief HTTP/3 layer security policy — tunable limits to prevent resource exhaustion.
 * @note Separate struct from the QUIC policy. The security module is centralized but
 *       each layer keeps its own layer-named config.
 */
typedef struct {
  uint64_t max_frame_buffer_bytes; /**< Max bytes the H3 layer accumulates for one
                                    *   must-buffer frame (SETTINGS/HEADERS); a frame
                                    *   whose Length exceeds this is rejected, not buffered */
} YAWT_H3_SecurityPolicy_t;

/**
 * @ingroup Security
 * @brief Get the current HTTP/3 security policy.
 * @return Const pointer to the static global policy (valid for process lifetime).
 * @note Same static-global lifetime contract as the QUIC accessors.
 */
const YAWT_H3_SecurityPolicy_t *YAWT_h3_security_get(void);

/**
 * @ingroup Security
 * @brief Set the HTTP/3 security policy.
 * @param policy Pointer to the new policy values (copied into the global).
 * @note Replaces the global policy. Passing NULL is a no-op.
 */
void YAWT_h3_security_set(const YAWT_H3_SecurityPolicy_t *policy);
