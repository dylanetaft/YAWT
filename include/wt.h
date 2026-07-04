/**
 * @file wt.h
 * @brief WebTransport API for YAWT.
 * @note draft-ietf-webtrans-http3-15, RFC 9297 (capsules, HTTP datagrams).
 *
 * The WT layer sits parallel to H3, consuming QUIC events and looking up
 * H3 stream metadata to determine which streams are WT-owned. It emits
 * WT-specific events to the application.
 *
 * Usage:
 *   1. In QUIC callback, call YAWT_wt_on_event(con, event, param);
 *   2. In H3 callback, call YAWT_wt_on_h3_event(h3con, event, param);
 *   3. Register event handler: YAWT_wt_set_event_handler(wt, my_handler);
 *      (get WT context from QUIC connection's YAWT_UD_WT slot after EVT_CONNECTED)
 *   4. WT processes WT-owned streams (0x41 bidi, 0x54 uni, upgraded CONNECT)
 */

#pragma once
#include "wt_types.h"
#include "quic_connection.h"
#include "capsule.h"
#include "h3_types.h"

/**
 * @ingroup WebTransport
 * @brief Process a QUIC event in the WT layer.
 * @param con The QUIC connection.
 * @param event The QUIC event type.
 * @param param The event parameters.
 * @return YAWT_WT_OK on success, or an error code.
 * @note This should be called from the app's QUIC event callback, in parallel
 *       with YAWT_h3_on_event(). WT creates its context on EVT_CONNECTED and
 *       destroys it on EVT_CLOSE. WT looks up the H3 connection to check
 *       stream types and processes WT-owned streams.
 */
YAWT_WT_Error_t YAWT_wt_on_event(YAWT_Q_Context_t *con,
                                    YAWT_Q_EventType_t event,
                                    YAWT_Q_EventParam_t param);

/**
 * @ingroup WebTransport
 * @brief Process an H3 event in the WT layer.
 * @param h3con The H3 connection.
 * @param event The H3 event type.
 * @param param The event parameters.
 * @return YAWT_WT_OK on success, or an error code.
 * @note This should be called from the app's H3 event callback. WT parses
 *       capsules from DATA frame payloads on WT_CONNECT streams and emits
 *       WT-specific events to the application.
 */
YAWT_WT_Error_t YAWT_wt_on_h3_event(YAWT_H3_Context_t *h3con,
                                      YAWT_H3_EventType_t event,
                                      YAWT_H3_EventParam_t param);

/**
 * @ingroup WebTransport
 * @brief Set the event handler for a WT context.
 * @param ctx The WT context.
 * @param handler The event handler callback.
 * @note The handler is called for WT-specific events (session established,
 *       stream data, datagrams, etc.).
 */
void YAWT_wt_set_event_handler(YAWT_WT_Context_t *ctx, YAWT_WT_EventHandler_t handler);

/**
 * @ingroup WebTransport
 * @brief Send data on a WT stream.
 * @param ctx The WT context.
 * @param session_id The WT session ID.
 * @param stream_id The H3 stream ID (for uni/bidi streams).
 * @param data The data to send.
 * @param len The length of the data.
 * @param fin Non-zero to set the FIN bit.
 * @return YAWT_WT_OK on success, or an error code.
 * @note For WT_CONNECT streams, this sends capsules. For WT_UNI/WT_BIDI
 *       streams, this sends raw application data.
 */
YAWT_WT_Error_t YAWT_wt_send_data(YAWT_WT_Context_t *ctx,
                                    uint64_t session_id,
                                    uint64_t stream_id,
                                    const uint8_t *data, size_t len,
                                    int fin);

/**
 * @ingroup WebTransport
 * @brief Send a capsule on a WT_CONNECT stream.
 * @param ctx The WT context.
 * @param session_id The WT session ID (must be an upgraded CONNECT stream).
 * @param capsule_type The capsule type (RFC 9297 §3.2).
 * @param value The capsule value.
 * @param len The length of the capsule value.
 * @return YAWT_WT_OK on success, or an error code.
 * @note This encodes the capsule (type + length + value) and sends it as
 *       a DATA frame on the CONNECT stream.
 */
YAWT_WT_Error_t YAWT_wt_send_capsule(YAWT_WT_Context_t *ctx,
                                       uint64_t session_id,
                                       uint64_t capsule_type,
                                       const uint8_t *value, size_t len);

/**
 * @ingroup WebTransport
 * @brief Parse a capsule from accumulated data.
 *
 * @param parser Capsule parser state (accumulates data across calls)
 * @param data Input bytes
 * @param len Number of input bytes
 * @param type_out Output: capsule type (valid when return == YAWT_CAPSULE_OK)
 * @param capsule_out Output: parsed capsule data (valid when return == YAWT_CAPSULE_OK)
 * @return YAWT_CAPSULE_OK when complete, YAWT_CAPSULE_INCOMPLETE if need more data,
 *         YAWT_CAPSULE_ERROR on malformed input
 *
 * @note Similar to YAWT_q_parse_frame() — accumulates data incrementally,
 *       returns OK when a complete capsule is parsed. The type_out indicates
 *       which union member in capsule_out is valid.
 */
int YAWT_wt_parse_capsule(YAWT_Capsule_Parser_t *parser,
                          const uint8_t *data, size_t len,
                          YAWT_WT_CapsuleType_t *type_out,
                          YAWT_WT_Capsule_t *capsule_out);

/**
 * @ingroup WebTransport
 * @brief Process an incoming QUIC datagram for WebTransport.
 *
 * Decodes the Quarter Stream ID (RFC 9297 §2.1), looks up the session,
 * and emits YAWT_WT_EVT_DATAGRAM to the app handler.  The entire datagram
 * must be contained in the buffer — no buffering or reassembly required.
 *
 * @param ctx      The WT context.
 * @param data     Raw HTTP/3 Datagram bytes (Quarter Stream ID + payload).
 * @param len      Length of @p data.
 * @return YAWT_WT_OK on success (or silent drop for unknown session),
 *         or YAWT_WT_ERR_INVALID_PARAM on malformed input.
 *
 * @note Called internally by YAWT_wt_on_h3_event() when it sees
 *       YAWT_H3_EVT_DATAGRAM.  Also available for direct use.
 */
YAWT_WT_Error_t YAWT_wt_on_datagram(YAWT_WT_Context_t *ctx,
                                     const uint8_t *data, size_t len);

/**
 * @ingroup WebTransport
 * @brief Send a datagram for a WT session.
 *
 * Prepends the Quarter Stream ID varint (session->connect_stream_id / 4)
 * and enqueues the packet via YAWT_q_enqueue_frame_datagram().
 *
 * @param ctx        The WT context.
 * @param session_id The WT session ID.
 * @param data       Application payload (no header — Quarter Stream ID
 *                   is added automatically).
 * @param len        Length of @p data.
 * @return YAWT_WT_OK on success, or an error code.
 */
YAWT_WT_Error_t YAWT_wt_send_datagram(YAWT_WT_Context_t *ctx,
                                        uint64_t session_id,
                                        const uint8_t *data, size_t len);
