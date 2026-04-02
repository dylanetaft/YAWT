#pragma once
#include <stdint.h>
#include <stddef.h>
#include <allocnbuffer/slab.h>
#include "quic_types.h"

// Forward declaration — full type in crypt.h
struct YAWT_Q_Level_Keys;
typedef struct YAWT_Q_Level_Keys YAWT_Q_Level_Keys_t;
// Forward declaration — full type in quic_connection.h
typedef struct YAWT_Q_Connection YAWT_Q_Connection_t;


// Quic connection initialization goes like this
// Initial -> Handshake -> 1-RTT
// Initial - Establishes header protection key + Client\Server Hello + CIDs
// Handshake - Establishes RTT keys + Handshake messages
// 1-RTT - Application keys
//[IP[UDP[QUICK_PKT[FRAME1[...], FRAME2[...], ...],[QUICK_PKT2.....]]]]
//Loss detection is at the quic packet level, not per frame, uses counter

//UNIMPLEMENTED: Congestion Windows
//UNIMPLEMENTED: Packet coalescing

// QUIC error codes
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

// Read cursor for zero-copy datagram parsing
typedef struct {
  uint8_t *data;
  size_t len;
  size_t cursor; //offset from data start
  YAWT_Q_Error_t err;
} YAWT_Q_ReadCursor_t;

// Generic frame struct for tx_buffer — wire-ready, self-contained
typedef struct {
  YAWT_Q_Frame_Type_t type;
  uint8_t level;  // YAWT_Q_Encryption_Level_t — which packet type to send in

  // STREAM-only: stream ID for per-stream flow control in _flush_connection
  uint64_t stream_id;

  // Send tracking
  uint32_t packet_num;              // PN this was sent in (0 if unsent)
  double last_sent;                 // ev_now() timestamp of last send (0 = needs sending)
  uint32_t retransmit_count;        // number of times retransmitted

  // Wire-encoded frame data
  size_t wire_len;
  uint8_t wire_data[YAWT_Q_MAX_PKT_SIZE];
} YAWT_Q_WireFrame_t;

// Result from processing frames in a packet
typedef struct {
  YAWT_Q_Error_t err;
  int requires_ack;  // 1 if any ack-eliciting frame was seen
} YAWT_Q_FrameHandler_Res_t;

// Stream metadata — one per open stream, stored in a slab
typedef struct {
  uint64_t stream_id;
  uint64_t rx_next_offset;        // next contiguous byte expected
  uint64_t tx_next_offset;
  uint64_t rx_fin_offset;         // final byte offset (set when FIN arrives)
  uint64_t tx_max_data;           // per-stream TX limit from peer
  uint8_t rx_fin;
  uint8_t tx_fin_sent;
} YAWT_Q_StreamMeta_t;

// Connection-level counters and packet number tracking
typedef struct {
  uint64_t tx_count_bytes;
  uint64_t rx_count_bytes;
  // RFC 9000 Section 12.3 - Counters for each space, indexed by YAWT_Q_Encryption_Level_t
  uint64_t pkt_num_tx[4];   // per encryption level TX packet number
  uint64_t pkt_num_rx[4];   // per encryption level RX packet number (largest seen)
  uint64_t cid_seq_num;     // highest NEW_CONNECTION_ID seq_num seen
  double last_rx;           // ev_now() timestamp of last packet received
  double last_tx;           // ev_now() timestamp of last packet sent
  double closing_at;        // 0 = open, DBL_MAX = close pending flush, else timestamp of close sent
} YAWT_Q_ConnectionStats_t;

// Encode PADDING frames into buf. Returns bytes written, or negative on error.
int YAWT_q_encode_frame_padding(uint8_t *buf, size_t buf_len, size_t pad_len);

// Encode a CRYPTO frame and push to tx_buffer.
YAWT_Q_Error_t YAWT_q_enqueue_frame_crypto(YAWT_Q_Connection_t *con, uint8_t level,
                                             const YAWT_Q_Frame_Crypto_t *frame);

// Encode an ACK frame and push to tx_buffer. Acknowledges packets [0..largest_ack].
YAWT_Q_Error_t YAWT_q_enqueue_frame_ack(YAWT_Q_Connection_t *con, uint8_t level, uint64_t largest_ack);

// Encode a STREAM frame and push to tx_buffer. Always enqueued at APPLICATION level.
YAWT_Q_Error_t YAWT_q_enqueue_frame_stream(YAWT_Q_Connection_t *con,
                                             const YAWT_Q_Frame_Stream_t *frame);

// Encode a PING frame and push to tx_buffer. APPLICATION level only.
YAWT_Q_Error_t YAWT_q_enqueue_frame_ping(YAWT_Q_Connection_t *con);

// Encode a CONNECTION_CLOSE frame (0x1c) and push to tx_buffer.
YAWT_Q_Error_t YAWT_q_enqueue_frame_connection_close(YAWT_Q_Connection_t *con, uint8_t level,
                                                      uint64_t error_code, uint64_t frame_type);

// Encode a PATH_RESPONSE frame (echo 8 bytes back) and push to tx_buffer.
YAWT_Q_Error_t YAWT_q_enqueue_frame_path_response(YAWT_Q_Connection_t *con, const uint8_t *data);

// Encode a DATAGRAM frame (0x31, with length) and push to tx_buffer. APPLICATION level only.
YAWT_Q_Error_t YAWT_q_enqueue_frame_datagram(YAWT_Q_Connection_t *con,
                                               const uint8_t *data, size_t data_len);

// Encode a HANDSHAKE_DONE frame (0x1e) and push to tx_buffer. APPLICATION level only.
YAWT_Q_Error_t YAWT_q_enqueue_frame_handshake_done(YAWT_Q_Connection_t *con);

// Encode + encrypt a packet into internal static buffer.
// Returns total wire bytes (including AEAD tag), or negative on error.
// *out_buf points to internal buffer — valid until next encode call.
struct YAWT_Q_Crypto;
typedef struct YAWT_Q_Crypto YAWT_Q_Crypto_t;

int YAWT_q_encode_packet(YAWT_Q_Packet_t *pkt,
                          YAWT_Q_Crypto_t *crypto,
                          const uint8_t **out_buf);

// Decode a QUIC varint from cursor. Pass NULL for out to skip the value.
void YAWT_q_varint_decode(YAWT_Q_ReadCursor_t *rc, uint64_t *out);

// Encode a QUIC varint into buf. Returns bytes written via *written.
YAWT_Q_Error_t YAWT_q_varint_encode(uint64_t val, uint8_t *buf, size_t len,
                                     int *written);

// Parse a QUIC packet from a read cursor (zero-copy: pointers into cursor data).
// Advances rc->cursor past the parsed packet. Check rc->err after call.
void YAWT_q_parse_packet(YAWT_Q_ReadCursor_t *rc, YAWT_Q_Packet_t *out);

// Parse a single frame from the cursor. Caller loops while rc->cursor < rc->len.
// pkt_type is stored on the output so consumers know the source encryption level.
void YAWT_q_parse_frame(YAWT_Q_ReadCursor_t *rc, YAWT_Q_Packet_Type_t pkt_type,
                         YAWT_Q_Frame_t *out);
