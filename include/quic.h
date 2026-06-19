/**
 * @file quic.h
 * @brief QUIC low-level protocol operations, utilities, and event system.
 */

/**
 * @defgroup QUIC QUIC
 * @brief QUIC protocol operations and utilities.
 */


/**
 * @defgroup QUIC_Connection Connection
 * @ingroup QUIC
 * @brief QUIC connection lifecycle, state, and event system types.
 */

/**
 * @defgroup QUIC_Wire Wire
 * @ingroup QUIC
 * @brief QUIC wire-format primitives: varints, packets, frames, and cursors.
 */



/**
 * @defgroup QUIC_FRAME_TYPES Frame Types
 * @ingroup QUIC
 * @brief QUIC frame types and their parsed representations.
 */

/**
 * @defgroup QUIC_Drive Drive Functions
 * @ingroup QUIC
 * @brief Functions the user must call from their event loop to drive the QUIC stack.
 * @details The QUIC library is not self-running. The user owns the event loop
 *          and must call these two functions each iteration:
 *          - YAWT_q_con_rx() on incoming UDP data
 *          - YAWT_q_con_maintain() on a timer (see YAWT_q_con_get_maint_config())
 */

/**
 * @defgroup QUIC_Internal Internal
 * @ingroup QUIC
 * @brief Internal QUIC implementation details — not part of the public API.
 */


#pragma once
#include <stdint.h>
#include <stddef.h>
#include <allocnbuffer/slab.h>
#include "quic_types.h"

struct YAWT_Q_Level_Keys;
typedef struct YAWT_Q_Level_Keys_t YAWT_Q_Level_Keys_t;
typedef struct YAWT_Q_Connection_t YAWT_Q_Connection_t;

/**
 * @ingroup QUIC
 * @brief Process-wide event handler.
 * @note Lifetime: a single global, installed via YAWT_q_con_set_event_handler().
 *       Threading: the QUIC layer is single-threaded (one libev loop). The handler
 *       is invoked synchronously from YAWT_q_con_rx() and YAWT_q_con_maintain().
 *       Nothing here is thread-safe.
 */
typedef void (*YAWT_Q_EventHandler_t)(YAWT_Q_Connection_t *con,
                                       YAWT_Q_EventType_t event,
                                       YAWT_Q_EventParam_t param);

// Quic connection initialization goes like this
// Initial -> Handshake -> 1-RTT
// Initial - Establishes header protection key + Client\Server Hello + CIDs
// Handshake - Establishes RTT keys + Handshake messages
// 1-RTT - Application keys
//[IP[UDP[QUICK_PKT[FRAME1[...], FRAME2[...], ...],[QUICK_PKT2.....]]]]
//Loss detection is at the quic packet level, not per frame, uses counter

//UNIMPLEMENTED: Congestion Windows
//UNIMPLEMENTED: Packet coalescing

/**
 * @ingroup QUIC
 * @brief QUIC error codes.
 */
typedef enum {
  YAWT_Q_OK = 0,
  YAWT_Q_ERR_SHORT_BUFFER,
  YAWT_Q_ERR_INVALID_PACKET,
  YAWT_Q_ERR_VARINT_OVERFLOW,
  YAWT_Q_ERR_CID_TOO_LONG,
  YAWT_Q_ERR_INVALID_PARAM,
  YAWT_Q_ERR_ALLOC,
  YAWT_Q_ERR_CRYPTO_BUFFER_EXCEEDED,
  YAWT_Q_ERR_FRAME_TOO_LARGE
} YAWT_Q_Error_t;

/**
 * @ingroup QUIC
 * @brief Get a string representation of a QUIC error code.
 * @param err The error code.
 * @return A static string describing the error.
 */
static inline const char *YAWT_q_err_str(YAWT_Q_Error_t err) {
  switch (err) {
    case YAWT_Q_OK:                 return "OK";
    case YAWT_Q_ERR_SHORT_BUFFER:   return "SHORT_BUFFER";
    case YAWT_Q_ERR_INVALID_PACKET: return "INVALID_PACKET";
    case YAWT_Q_ERR_VARINT_OVERFLOW: return "VARINT_OVERFLOW";
    case YAWT_Q_ERR_CID_TOO_LONG:  return "CID_TOO_LONG";
    case YAWT_Q_ERR_INVALID_PARAM: return "INVALID_PARAM";
    case YAWT_Q_ERR_ALLOC:         return "ALLOC";
    case YAWT_Q_ERR_CRYPTO_BUFFER_EXCEEDED: return "CRYPTO_BUFFER_EXCEEDED";
    case YAWT_Q_ERR_FRAME_TOO_LARGE: return "FRAME_TOO_LARGE";
    default:                         return "UNKNOWN";
  }
}

/**
 * @ingroup QUIC_Wire
 * @brief Read cursor for zero-copy datagram parsing.
 * @note `cursor` advances as bytes are consumed; `data`/`len` are the input buffer.
 *       Errors are STICKY. Once `err` is non-OK, every later decode/parse on this
 *       cursor is a no-op. Transience: pointers handed back point INTO `data`.
 */
typedef struct {
  uint8_t *data;
  size_t len;
  size_t cursor;
  YAWT_Q_Error_t err;
} YAWT_Q_ReadCursor_t;

/**
 * @ingroup QUIC_Wire
 * @brief Generic frame struct for tx_buffer — wire-ready, self-contained.
 * @note Lifetime: produced by the YAWT_q_enqueue_frame_* encoders, which push a
 *       copy into con->tx_buffer (a slab). con_maintain() coalesces these into
 *       packets, sends them (EVT_TX), and retransmits/expires them. Owned by the
 *       slab for its lifetime; the enqueuing caller keeps no reference.
 *       Ownership: `wire_data` is a complete, self-contained copy of the encoded
 *       frame — no pointers into caller memory survive here.
 */
typedef struct {
  YAWT_Q_Frame_Type_t type;
  uint8_t level;  // YAWT_Q_Encryption_Level_t — which packet type to send in

  // STREAM-only: stream ID for per-stream flow control in _flush_connection
  uint64_t stream_id;

  // Send tracking (maintained by con_maintain's retransmit pass)
  uint32_t packet_num;              // PN this was sent in (0 if unsent)
  double last_sent;                 // ev_now() timestamp of last send (0 = needs (re)sending)
  uint32_t retransmit_count;        // attempts so far; drives exponential backoff

  // Wire-encoded frame data
  size_t wire_len;
  uint8_t wire_data[YAWT_Q_MAX_PKT_SIZE];
} YAWT_Q_WireFrame_t;

/**
 * @ingroup QUIC_Connection
 * @brief Connection-level counters and packet number tracking.
 */
typedef struct {
  uint64_t tx_count_bytes;
  uint64_t rx_count_bytes;
  // RFC 9000 Section 12.3 - Counters for each space, indexed by YAWT_Q_Encryption_Level_t
  uint64_t next_pkt_num_tx[4];   // per encryption level: next TX packet number to send
  uint64_t next_pkt_num_rx[4];   // per encryption level: next expected RX packet number
  uint64_t cid_seq_num;     // highest NEW_CONNECTION_ID seq_num seen
  double last_rx;           // ev_now() timestamp of last packet received
  double last_tx;           // ev_now() timestamp of last packet sent
  double closing_at;        // 0 = not closing, else timestamp when close period started
} YAWT_Q_ConnectionStats_t;

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Encode PADDING frames into buf.
 * @param buf Output buffer.
 * @param buf_len Output buffer length.
 * @param pad_len Number of padding bytes to write.
 * @return Bytes written, or negative on error.
 * @note Direct buffer encoder — does NOT touch tx_buffer.
 */
int YAWT_q_encode_frame_padding(uint8_t *buf, size_t buf_len, size_t pad_len);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Encode a CRYPTO frame and push to tx_buffer.
 * @param con The QUIC connection.
 * @param level Encryption level.
 * @param frame The CRYPTO frame to encode.
 * @return YAWT_Q_OK on success, or an error code.
 * @note Ownership: COPIES the encoded frame into con->tx_buffer.
 */
YAWT_Q_Error_t YAWT_q_enqueue_frame_crypto(YAWT_Q_Connection_t *con, uint8_t level,
                                             const YAWT_Q_Frame_Crypto_t *frame);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Encode an ACK frame and push to tx_buffer.
 * @param con The QUIC connection.
 * @param level Encryption level.
 * @param largest_ack Largest acknowledged packet number.
 * @return YAWT_Q_OK on success, or an error code.
 */
YAWT_Q_Error_t YAWT_q_enqueue_frame_ack(YAWT_Q_Connection_t *con, uint8_t level, uint64_t largest_ack);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Encode a STREAM frame and push to tx_buffer.
 * @param con The QUIC connection.
 * @param frame The STREAM frame to encode.
 * @return YAWT_Q_OK on success, or an error code.
 * @note Level: APPLICATION only. Ownership: copies frame->data into the queued WireFrame.
 */
YAWT_Q_Error_t YAWT_q_enqueue_frame_stream(YAWT_Q_Connection_t *con,
                                             const YAWT_Q_Frame_BufferedStream_t *frame);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Encode a PING frame and push to tx_buffer.
 * @param con The QUIC connection.
 * @return YAWT_Q_OK on success, or an error code.
 * @note Level: APPLICATION only.
 */
YAWT_Q_Error_t YAWT_q_enqueue_frame_ping(YAWT_Q_Connection_t *con);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Encode a CONNECTION_CLOSE frame and push to tx_buffer.
 * @param con The QUIC connection.
 * @param level Encryption level.
 * @param error_code The error code.
 * @param frame_type The frame type that triggered the error.
 * @return YAWT_Q_OK on success, or an error code.
 */
YAWT_Q_Error_t YAWT_q_enqueue_frame_connection_close(YAWT_Q_Connection_t *con, uint8_t level,
                                                      uint64_t error_code, uint64_t frame_type);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Encode a PATH_RESPONSE frame and push to tx_buffer.
 * @param con The QUIC connection.
 * @param data The 8-byte data to echo back.
 * @return YAWT_Q_OK on success, or an error code.
 */
YAWT_Q_Error_t YAWT_q_enqueue_frame_path_response(YAWT_Q_Connection_t *con, const uint8_t *data);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Encode a DATAGRAM frame and push to tx_buffer.
 * @param con The QUIC connection.
 * @param data The datagram payload.
 * @param data_len The datagram payload length.
 * @return YAWT_Q_OK on success, or an error code.
 * @note Level: APPLICATION only. Ownership: copies `data`.
 */
YAWT_Q_Error_t YAWT_q_enqueue_frame_datagram(YAWT_Q_Connection_t *con,
                                               const uint8_t *data, size_t data_len);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Encode a HANDSHAKE_DONE frame and push to tx_buffer.
 * @param con The QUIC connection.
 * @return YAWT_Q_OK on success, or an error code.
 * @note Level: APPLICATION only.
 */
YAWT_Q_Error_t YAWT_q_enqueue_frame_handshake_done(YAWT_Q_Connection_t *con);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Encode a RESET_STREAM frame and push to tx_buffer.
 * @param con The QUIC connection.
 * @param stream_id The stream to reset.
 * @param app_error_code Application error code.
 * @param final_size Final byte offset sent on this stream.
 * @return YAWT_Q_OK on success, or an error code.
 * @note Level: APPLICATION only. RFC 9000 §19.4.
 */
YAWT_Q_Error_t YAWT_q_enqueue_frame_reset_stream(YAWT_Q_Connection_t *con,
                                                   uint64_t stream_id,
                                                   uint64_t app_error_code,
                                                   uint64_t final_size);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Encode a STOP_SENDING frame and push to tx_buffer.
 * @param con The QUIC connection.
 * @param stream_id The stream to stop receiving.
 * @param app_error_code Application error code.
 * @return YAWT_Q_OK on success, or an error code.
 * @note Level: APPLICATION only. RFC 9000 §19.5.
 */
YAWT_Q_Error_t YAWT_q_enqueue_frame_stop_sending(YAWT_Q_Connection_t *con,
                                                   uint64_t stream_id,
                                                   uint64_t app_error_code);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Encode a DATA_BLOCKED frame and push to tx_buffer.
 * @param con The QUIC connection.
 * @param max_data The connection-level flow control limit we are blocked at.
 * @return YAWT_Q_OK on success, or an error code.
 * @note Level: APPLICATION only. RFC 9000 §19.12.
 */
YAWT_Q_Error_t YAWT_q_enqueue_frame_data_blocked(YAWT_Q_Connection_t *con, uint64_t max_data);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Encode a MAX_DATA frame and push to tx_buffer.
 * @param con The QUIC connection.
 * @param max_data The new connection-level flow control limit.
 * @return YAWT_Q_OK on success, or an error code.
 * @note Level: APPLICATION only. RFC 9000 §19.9.
 */
YAWT_Q_Error_t YAWT_q_enqueue_frame_max_data(YAWT_Q_Connection_t *con, uint64_t max_data);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Encode a STREAM_DATA_BLOCKED frame and push to tx_buffer.
 * @param con The QUIC connection.
 * @param stream_id The stream that is blocked.
 * @param max_stream_data The stream-level flow control limit we are blocked at.
 * @return YAWT_Q_OK on success, or an error code.
 * @note Level: APPLICATION only. RFC 9000 §19.13.
 */
YAWT_Q_Error_t YAWT_q_enqueue_frame_stream_data_blocked(YAWT_Q_Connection_t *con,
                                                           uint64_t stream_id,
                                                           uint64_t max_stream_data);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Encode a MAX_STREAM_DATA frame and push to tx_buffer.
 * @param con The QUIC connection.
 * @param stream_id The stream whose limit is being raised.
 * @param max_stream_data The new stream-level flow control limit.
 * @return YAWT_Q_OK on success, or an error code.
 * @note Level: APPLICATION only. RFC 9000 §19.10.
 */
YAWT_Q_Error_t YAWT_q_enqueue_frame_max_stream_data(YAWT_Q_Connection_t *con,
                                                       uint64_t stream_id,
                                                       uint64_t max_stream_data);

struct YAWT_Q_Crypto;
typedef struct YAWT_Q_Crypto_t YAWT_Q_Crypto_t;

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Encode + encrypt a packet.
 * @param pkt The packet to encode.
 * @param crypto The crypto context.
 * @param out_buf Pointer to receive the output buffer.
 * @return Total wire bytes (including AEAD tag), or negative on error.
 * @warning Transience: *out_buf points to a STATIC internal buffer, overwritten by the
 *          next encode call. Consume/copy it before encoding again.
 */
int YAWT_q_encode_packet(YAWT_Q_Packet_t *pkt,
                          YAWT_Q_Crypto_t *crypto,
                          const uint8_t **out_buf);

/**
 * @ingroup QUIC_Wire
 * @brief Decode a QUIC varint from cursor.
 * @param rc The read cursor.
 * @param out Output value. If NULL, skips the value (advance only).
 * @note Errors are sticky. SHORT_BUFFER if fewer bytes remain than the varint's encoded length.
 */
void YAWT_q_varint_decode(YAWT_Q_ReadCursor_t *rc, uint64_t *out);

/**
 * @ingroup QUIC_Wire
 * @brief Encode a QUIC varint into buf.
 * @param val The value to encode.
 * @param buf Output buffer.
 * @param len Output buffer length.
 * @param written Pointer to receive the number of bytes written.
 * @return YAWT_Q_OK on success, or an error code.
 */
YAWT_Q_Error_t YAWT_q_varint_encode(uint64_t val, uint8_t *buf, size_t len,
                                     uint64_t *written);

/**
 * @ingroup QUIC_Wire
 * @brief Get the number of bytes needed to encode val as a QUIC varint.
 * @param val The value to check.
 * @return Number of bytes needed, or 0 if val exceeds 62 bits.
 */
size_t YAWT_q_varint_size(uint64_t val);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Parse a QUIC packet from a read cursor.
 * @param rc The read cursor.
 * @param out Output packet struct.
 * @warning Transience: output pointers (payload/raw/token) point INTO rc->data (zero-copy).
 *          Errors are sticky; check rc->err after the call.
 * @note Advances rc->cursor past the parsed packet.
 */
void YAWT_q_parse_packet(YAWT_Q_ReadCursor_t *rc, YAWT_Q_Packet_t *out);

/**
 * @internal
 * @ingroup QUIC_Internal
 * @brief Parse a single frame from the cursor.
 * @param rc The read cursor.
 * @param pkt_type Source packet type (encryption level).
 * @param out Output frame struct.
 * @note Caller loops while rc->cursor < rc->len. `out` is memset, stamped with `pkt_type`,
 *       and pointer fields point INTO rc->data (zero-copy, transient).
 *       Errors are sticky; check rc->err after the call.
 */
void YAWT_q_parse_frame(YAWT_Q_ReadCursor_t *rc, YAWT_Q_Packet_Type_t pkt_type,
                         YAWT_Q_Frame_t *out);
