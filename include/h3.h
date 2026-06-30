/**
 * @file h3.h
 * @brief HTTP/3 (RFC 9114) function API — minimal subset for WebTransport.
 */

/**
 * @defgroup HTTP3 
 * @brief Primary HTTP/3 API for connection management, frame parsing, and sending data/headers.
 */

/**
 * @addtogroup H3_Connection
 * @brief HTTP/3 connection management, event dispatch, and sending.
 */

/**
 * @defgroup H3_Internal Internal
 * @ingroup HTTP3 
 * @brief Internal HTTP/3 implementation details — not part of the public API.
 */

#pragma once
#include <stdint.h>
#include <stddef.h>
#include "h3_types.h"
#include "quic.h"   // YAWT_q_varint_*, YAWT_Q_ReadCursor_t, YAWT_Q_EventType_t, YAWT_Q_EventParam_t

/**
 * @internal
 * @ingroup H3_Internal
 * @brief Parse the next H3 frame header from a QUIC stream chunk.
 * @param h3con The H3 connection.
 * @param chunk The QUIC stream frame carrying the bytes.
 * @param out_stream Output: resolved stream metadata (set on YAWT_H3_OK).
 * @param cursor In/out: position in chunk->data. Advanced as bytes are consumed.
 * @return YAWT_H3_OK if frame header parsed (type+length decoded, blob allocated if needed).
 *         YAWT_H3_ERR_INCOMPLETE if more data needed.
 *         YAWT_H3_IGNORED if stream type doesn't carry H3 frames (QPACK/WT/unknown).
 *         Error codes for malformed data or policy violations.
 * @note This is the single gatekeeper: handles stream type resolution, frame header parsing,
 *       buffering decisions (SETTINGS/HEADERS get blobs), and security policy checks.
 */
YAWT_H3_Error_t YAWT_h3_parse_frame(YAWT_H3_Connection_t *h3con,
                                    const YAWT_Q_Frame_Stream_t *chunk,
                                    YAWT_H3_Stream_t *stream,
                                    size_t *cursor);

/**
 * @internal
 * @ingroup H3_Internal
 * @brief Encode an H3 frame header (type varint + length varint) into buf.
 * @param frame_type The H3 frame type.
 * @param payload_len The payload length.
 * @param buf Output buffer.
 * @return Bytes written on success, 0 on error.
 * @note buf must be at least H3_FRAME_MAX_HEADER_BYTES. Safe — minimum valid header is 2 bytes.
 */
size_t YAWT_h3_encode_frame_header(uint64_t frame_type, size_t payload_len, uint8_t *buf);

/**
 * @internal
 * @ingroup H3_Internal
 * @brief Get the number of bytes needed for an H3 frame header.
 * @param payload_len The payload length that will follow.
 * @return Number of bytes needed for type + length varints.
 */
size_t YAWT_h3_frame_header_size(size_t payload_len);

/**
 * @ingroup H3_Connection
 * @brief H3 event handler.
 * @param con The underlying QUIC connection.
 * @param event The QUIC event type.
 * @param param The QUIC event parameters.
 * @return YAWT_H3_OK if processed successfully, YAWT_H3_IGNORED if not an H3 concern,
 *         or YAWT_H3_ERR_NO_APP_HANDLER if app handler not installed.
 * @note Register via YAWT_q_con_set_event_handler, or forward to it from the app's own handler.
 *       Manages the H3 connection object (allocated on CONNECTED, freed on CLOSE) and consumes
 *       stream events. Ignores TX (the app's concern). Connection state is stored in the
 *       QUIC connection's YAWT_UD_H3 user_data slot.
 */
YAWT_H3_Error_t YAWT_h3_on_event(YAWT_Q_Connection_t *con, YAWT_Q_EventType_t event,
                                   YAWT_Q_EventParam_t param);

/**
 * @internal
 * @ingroup H3_Internal
 * @brief Decode a SETTINGS frame body.
 * @param rc Read cursor whose data/len cover exactly the SETTINGS payload.
 * @param out Output settings struct.
 * @return YAWT_H3_OK on success, or an error code.
 * @note The cursor advances as (id, value) pairs are consumed. Enforces: SETTINGS must
 *       appear first on the control stream and only once per connection (RFC 9114 §7.2.4).
 */
YAWT_H3_Error_t YAWT_h3_settings_decode(YAWT_Q_ReadCursor_t *rc,
                                          YAWT_H3_Settings_t *out);

/**
 * @internal
 * @ingroup H3_Internal
 * @brief Encode a SETTINGS frame body (id/value varint pairs) into buf.
 * @param settings The settings to encode.
 * @param buf Output buffer.
 * @param len Output buffer length.
 * @param written Pointer to receive the number of bytes written.
 * @return YAWT_H3_OK on success, or an error code.
 * @note Only encodes settings that have been explicitly set (tracked by val_set bitmask).
 */
YAWT_H3_Error_t YAWT_h3_settings_encode(const YAWT_H3_Settings_t *settings,
                                          uint8_t *buf, size_t len,
                                          size_t *written);

/**
 * @ingroup H3_Types
 * @brief Set a setting value by internal index.
 * @param s The settings struct.
 * @param idx Internal setting index (0-9).
 * @param val The value to set.
 * @return YAWT_H3_OK on success, or YAWT_H3_ERR_INVALID_PARAM if idx is out of range.
 * @note O(1) operation. Sets the bit in val_set and stores the value in vals[].
 */
YAWT_H3_Error_t YAWT_h3_setting_set(YAWT_H3_Settings_t *s, YAWT_H3_SettingIdx_t idx, uint64_t val);

/**
 * @ingroup H3_Types
 * @brief Get a setting value by internal index.
 * @param s The settings struct.
 * @param idx Internal setting index (0-9).
 * @param out Pointer to receive the value.
 * @return YAWT_H3_OK on success, YAWT_H3_ERR_INVALID_PARAM if idx out of range or not set.
 * @note O(1) operation. Returns error if the setting has not been explicitly set.
 */
YAWT_H3_Error_t YAWT_h3_setting_get(const YAWT_H3_Settings_t *s, YAWT_H3_SettingIdx_t idx, uint64_t *out);

/**
 * @ingroup H3_Types
 * @brief Check if a setting has been explicitly set.
 * @param s The settings struct.
 * @param idx Internal setting index (0-9).
 * @return true if the setting has been set, false otherwise.
 * @note O(1) operation. Checks the val_set bitmask.
 */
bool YAWT_h3_setting_isset(const YAWT_H3_Settings_t *s, YAWT_H3_SettingIdx_t idx);

/**
 * @ingroup H3_Connection
 * @brief Install an app-level event handler on an H3 connection.
 * @param con The H3 connection.
 * @param handler The event handler function.
 * @note The handler receives H3-level events (HEADERS decoded, DATA chunks, SETTINGS, errors).
 *       Passing NULL clears any previously installed handler.
 */
void YAWT_h3_set_event_handler(YAWT_H3_Connection_t *con,
                                YAWT_H3_EventHandler_t handler);

/**
 * @ingroup H3_Connection
 * @brief Get the underlying QUIC connection from an H3 connection.
 * @param con The H3 connection.
 * @return Pointer to the underlying QUIC connection.
 */
YAWT_Q_Connection_t *YAWT_h3_get_qcon(const YAWT_H3_Connection_t *con);

/**
 * @ingroup H3_Connection
 * @brief Open the server control stream and send a SETTINGS frame.
 * @param h3 The H3 connection.
 * @return YAWT_H3_OK on success, or an error code.
 * @note Must be called after the QUIC connection is established (typically from
 *       the EVT_CONNECTED handler). No-op if already opened.
 */
YAWT_H3_Error_t YAWT_h3_send_settings(YAWT_H3_Connection_t *h3);

/**
 * @ingroup H3_Connection
 * @brief Open QPACK encoder and decoder unidirectional streams.
 * @param h3 The H3 connection.
 * @return YAWT_H3_OK on success, or an error code.
 * @note Opens two unidirectional streams: encoder (type 0x02) and decoder (type 0x03).
 *       Must be called after YAWT_h3_send_settings(). These are critical streams;
 *       closing them is a connection error (RFC 9204 §4.2).
 */
YAWT_H3_Error_t YAWT_h3_open_qpack_streams(YAWT_H3_Connection_t *h3);

/**
 * @ingroup H3_Connection
 * @brief Register a core stream (control/QPACK) with the connection.
 * @param h3 The H3 connection.
 * @param type The core stream type (local/peer control, local/peer QPACK encoder/decoder).
 * @param stream_id The stream ID to register.
 * @return YAWT_H3_OK on success, YAWT_H3_ERR_INVALID_PARAM if already registered (duplicate).
 * @note Detects duplicate critical streams per RFC 9114 §6.2.1 and RFC 9204 §4.2.
 */
YAWT_H3_Error_t YAWT_h3_core_stream_set(YAWT_H3_Connection_t *h3,
                                         YAWT_H3_Unique_Stream_Type_t type,
                                         uint64_t stream_id);

/**
 * @ingroup H3_Connection
 * @brief Encode headers as a QPACK header block, wrap in an H3 HEADERS frame, and send.
 * @param h3 The H3 connection.
 * @param stream_id The target bidi stream ID.
 * @param headers The header fields to send.
 * @param fin If true, the QUIC stream is closed after this frame (no DATA follows).
 * @return YAWT_H3_OK on success, or an error code.
 */
YAWT_H3_Error_t YAWT_h3_send_headers(YAWT_H3_Connection_t *h3,
                                       uint64_t stream_id,
                                       const YAWT_H3_HeaderFields_t *headers,
                                       int fin);

/**
 * @ingroup H3_Connection
 * @brief Wrap data in an H3 DATA frame and send on the given bidi stream.
 * @param h3 The H3 connection.
 * @param stream_id The target bidi stream ID.
 * @param data The data payload.
 * @param data_len The data payload length.
 * @param fin If true, the QUIC stream is closed after this frame.
 * @return YAWT_H3_OK on success, or an error code.
 */
YAWT_H3_Error_t YAWT_h3_send_data(YAWT_H3_Connection_t *h3,
                                    uint64_t stream_id,
                                    const uint8_t *data, size_t data_len,
                                    int fin);

/**
 * @ingroup H3_Connection
 * @brief Upgrade a request bidi stream to WebTransport (WT) mode.
 * @param h3 The H3 connection.
 * @param stream_id The target bidi stream ID to upgrade.
 * @param scheme The URI scheme (e.g., "https").
 * @param authority The authority (host:port).
 * @param path The request path.
 * @return YAWT_H3_OK on success, or an error code.
 * @note Client-side only: sends a CONNECT request with :method=CONNECT, :protocol=webtransport-h3.
 *       After calling this, the stream enters WT_CONNECT_PENDING state until the server responds.
 *       On 2xx response, stream transitions to WT_CONNECT. On non-2xx, reverts to FRAME.
 *       HEADERS/DATA frames will cease to be interpreted as HTTP/3 once upgraded.
 */
YAWT_H3_Error_t YAWT_h3_webtrans_upgrade(YAWT_H3_Connection_t *h3, uint64_t stream_id,
                                          const char *scheme, const char *authority, const char *path);

/**
 * @ingroup H3_Connection
 * @brief Deny a request bidi stream from being upgraded to WebTransport (WT) mode.
 * @param h3 The H3 connection.
 * @param stream_id The target bidi stream ID to deny.
 * @param status_code The HTTP status code to send (e.g., 403, 404, 503).
 * @return YAWT_H3_OK on success, or an error code.
 * @note Server-side only: sends a non-2xx response to reject the CONNECT request.
 *       HEADERS/DATA frames will continue to be interpreted as HTTP/3.
 *       This would normally be called in the H3 callback for upgrade req (YAWT_H3_EVT_WT_UPGRADE).
 */
YAWT_H3_Error_t YAWT_h3_webtrans_deny(YAWT_H3_Connection_t *h3, uint64_t stream_id, uint16_t status_code);

/**
 * @ingroup H3_Connection
 * @brief Accept a pending WebTransport (WT) CONNECT stream.
 * @param h3 The H3 connection.
 * @param stream_id The target bidi stream ID to accept.
 * @return YAWT_H3_OK on success, or an error code.
 * @note Server-side only: sends a 200 response to accept the CONNECT request.
 *       Stream must be in WT_CONNECT_PENDING state (set by H3 layer on receiving CONNECT).
 *       After calling this, stream transitions to WT_CONNECT and capsules can be exchanged.
 *       This would normally be called in the H3 callback for upgrade req (YAWT_H3_EVT_WT_UPGRADE).
 */
YAWT_H3_Error_t YAWT_h3_webtrans_accept(YAWT_H3_Connection_t *h3, uint64_t stream_id);
