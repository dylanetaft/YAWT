/**
 * @file h3.h
 * @brief HTTP/3 (RFC 9114) function API — minimal subset for WebTransport.
 */

/**
 * @defgroup YAWT_H3_Core YAWT_H3_Core
 * @brief Primary HTTP/3 API for connection management, frame parsing, and sending data/headers.
 */

#pragma once
#include <stdint.h>
#include <stddef.h>
#include "h3_types.h"
#include "quic.h"   // YAWT_q_varint_*, YAWT_Q_ReadCursor_t, YAWT_Q_EventType_t, YAWT_Q_EventParam_t

/**
 * @ingroup YAWT_H3_Core
 * @brief Assembles a frame from located metadata.
 * @param stream The QUIC stream frame.
 * @param meta The H3 stream metadata.
 * @param out Output H3 frame struct.
 * @return YAWT_H3_OK on success, or an error code.
 * @note Will deliver partial frames but we can pull the header fields (Type, Length) out of metadata.
 */
YAWT_H3_Error_t YAWT_h3_parse_frame(YAWT_Q_Frame_Stream_t *stream, 
                                    YAWT_H3_Stream_t *meta,
                                    YAWT_H3_Frame_t *out);

/**
 * @ingroup YAWT_H3_Core
 * @brief Encode an H3 frame header (type varint + length varint) into buf.
 * @param frame_type The H3 frame type.
 * @param payload_len The payload length.
 * @param buf Output buffer.
 * @return Bytes written on success, 0 on error.
 * @note buf must be at least H3_FRAME_MAX_HEADER_BYTES. Safe — minimum valid header is 2 bytes.
 */
size_t YAWT_h3_encode_frame_header(uint64_t frame_type, size_t payload_len, uint8_t *buf);

/**
 * @ingroup YAWT_H3_Core
 * @brief Get the number of bytes needed for an H3 frame header.
 * @param payload_len The payload length that will follow.
 * @return Number of bytes needed for type + length varints.
 */
size_t YAWT_h3_frame_header_size(size_t payload_len);

/**
 * @ingroup YAWT_H3_Core
 * @brief H3 event handler.
 * @param con The underlying QUIC connection.
 * @param event The QUIC event type.
 * @param param The QUIC event parameters.
 * @return YAWT_H3_OK if processed successfully, YAWT_H3_IGNORED if not an H3 concern,
 *         or YAWT_H3_ERR_NO_APP_HANDLER if app handler not installed.
 * @note Register via YAWT_q_con_set_event_handler, or forward to it from the app's own handler.
 *       Manages the H3 connection object (allocated on CONNECTED, freed on CLOSE) and consumes
 *       stream events. Ignores TX (the app's concern). Connection state is stored in the
 *       QUIC connection's user_data.
 */
YAWT_H3_Error_t YAWT_h3_on_event(YAWT_Q_Connection_t *con, YAWT_Q_EventType_t event,
                                   YAWT_Q_EventParam_t param);

/**
 * @ingroup YAWT_H3_Core
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
 * @ingroup YAWT_H3_Core
 * @brief Encode a SETTINGS frame body (id/value varint pairs) into buf.
 * @param settings The settings to encode.
 * @param buf Output buffer.
 * @param len Output buffer length.
 * @param written Pointer to receive the number of bytes written.
 * @return YAWT_H3_OK on success, or an error code.
 * @note Skips settings with value 0.
 */
YAWT_H3_Error_t YAWT_h3_settings_encode(const YAWT_H3_Settings_t *settings,
                                          uint8_t *buf, size_t len,
                                          size_t *written);

/**
 * @ingroup YAWT_H3_Core
 * @brief Install an app-level event handler on an H3 connection.
 * @param con The H3 connection.
 * @param handler The event handler function.
 * @note The handler receives H3-level events (HEADERS decoded, DATA chunks, SETTINGS, errors).
 *       Passing NULL clears any previously installed handler.
 */
void YAWT_h3_set_event_handler(YAWT_H3_Connection_t *con,
                                YAWT_H3_EventHandler_t handler);

/**
 * @ingroup YAWT_H3_Core
 * @brief Get the underlying QUIC connection from an H3 connection.
 * @param con The H3 connection.
 * @return Pointer to the underlying QUIC connection.
 */
YAWT_Q_Connection_t *YAWT_h3_get_qcon(const YAWT_H3_Connection_t *con);

/**
 * @ingroup YAWT_H3_Core
 * @brief Open the server control stream and send a SETTINGS frame.
 * @param h3 The H3 connection.
 * @return YAWT_H3_OK on success, or an error code.
 * @note Must be called after the QUIC connection is established (typically from
 *       the EVT_CONNECTED handler). No-op if already opened.
 */
YAWT_H3_Error_t YAWT_h3_send_settings(YAWT_H3_Connection_t *h3);

/**
 * @ingroup YAWT_H3_Core
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
 * @ingroup YAWT_H3_Core
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
