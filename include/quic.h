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

// Process-wide event handler.
//   Lifetime:  a single global, installed via YAWT_q_con_set_event_handler()
//     (NULL restores a built-in no-op; install replaces any previous handler).
//   Threading: the QUIC layer is single-threaded (one libev loop). The handler
//     is invoked synchronously from YAWT_q_con_rx() (CONNECTED/STREAM/DATAGRAM)
//     and YAWT_q_con_maintain() (TX/CLOSE). Nothing here is thread-safe.
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

// Read cursor for zero-copy datagram parsing. `cursor` advances as bytes are
// consumed; `data`/`len` are the input buffer (never copied out of).
//   Errors:     `err` is STICKY. Once it is non-OK, every later varint_decode /
//     parse_packet / parse_frame on this cursor is a no-op. So you can chain
//     several decodes and check `err` ONCE at the end. On SHORT_BUFFER the
//     cursor is left unchanged (no partial advance).
//   Transience: pointers the parsers hand back point INTO `data` (zero-copy);
//     they are valid only as long as the underlying datagram buffer is.
typedef struct {
  uint8_t *data;
  size_t len;
  size_t cursor; //offset from data start
  YAWT_Q_Error_t err;
} YAWT_Q_ReadCursor_t;

// Generic frame struct for tx_buffer — wire-ready, self-contained.
//   Lifetime:  produced by the YAWT_q_enqueue_frame_* encoders, which push a
//     copy into con->tx_buffer (a slab). con_maintain() coalesces these into
//     packets, sends them (EVT_TX), and retransmits/expires them. Owned by the
//     slab for its lifetime; the enqueuing caller keeps no reference.
//   Ownership: `wire_data` is a complete, self-contained copy of the encoded
//     frame — no pointers into caller memory survive here.
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

// Result from processing frames in a packet
typedef struct {
  YAWT_Q_Error_t err;
  int requires_ack;  // 1 if any ack-eliciting frame was seen
} YAWT_Q_FrameHandler_Res_t;

// Stream metadata — one per open stream, stored in the con->stream_meta slab.
// The QUIC layer owns these; they track reassembly + flow-control position so
// EVT_STREAM can be delivered gap-free (see YAWT_Q_EventParam_t P_EVT_STREAM).
typedef struct {
  uint64_t stream_id;
  uint64_t rx_next_offset;        // next contiguous RX byte expected (drives ordered delivery)
  uint64_t tx_next_offset;        // next TX byte offset to assign
  uint64_t rx_fin_offset;         // final byte offset; valid once rx_fin is set
  uint64_t tx_max_data;           // per-stream TX limit from peer (MAX_STREAM_DATA)
  uint8_t rx_fin;                 // 1 once the peer's FIN has been seen
  uint8_t tx_fin_sent;            // 1 once we've queued our FIN
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

// ---------------------------------------------------------------------------
// Frame encoders. Ownership: each COPIES the encoded frame into con->tx_buffer
// (the caller keeps/reuses its own input buffer). Nothing is sent here — frames
// are flushed, coalesced, and retransmitted later by YAWT_q_con_maintain().
// Level: most application frames are APPLICATION (1-RTT) only, as noted.
// ---------------------------------------------------------------------------

// Encode PADDING frames into buf. Returns bytes written, or negative on error.
// (Direct buffer encoder — does NOT touch tx_buffer.)
int YAWT_q_encode_frame_padding(uint8_t *buf, size_t buf_len, size_t pad_len);

// Encode a CRYPTO frame and push to tx_buffer. Level: per `level` arg.
YAWT_Q_Error_t YAWT_q_enqueue_frame_crypto(YAWT_Q_Connection_t *con, uint8_t level,
                                             const YAWT_Q_Frame_Crypto_t *frame);

// Encode an ACK frame and push to tx_buffer. Acknowledges packets [0..largest_ack].
YAWT_Q_Error_t YAWT_q_enqueue_frame_ack(YAWT_Q_Connection_t *con, uint8_t level, uint64_t largest_ack);

// Encode a STREAM frame and push to tx_buffer. Level: APPLICATION only.
// Ownership: copies frame->data into the queued WireFrame.
YAWT_Q_Error_t YAWT_q_enqueue_frame_stream(YAWT_Q_Connection_t *con,
                                             const YAWT_Q_Frame_BufferedStream_t *frame);

// Encode a PING frame and push to tx_buffer. Level: APPLICATION only.
YAWT_Q_Error_t YAWT_q_enqueue_frame_ping(YAWT_Q_Connection_t *con);

// Encode a CONNECTION_CLOSE frame (0x1c) and push to tx_buffer. Level: per arg.
YAWT_Q_Error_t YAWT_q_enqueue_frame_connection_close(YAWT_Q_Connection_t *con, uint8_t level,
                                                      uint64_t error_code, uint64_t frame_type);

// Encode a PATH_RESPONSE frame (echo 8 bytes back) and push to tx_buffer.
YAWT_Q_Error_t YAWT_q_enqueue_frame_path_response(YAWT_Q_Connection_t *con, const uint8_t *data);

// Encode a DATAGRAM frame (0x31, with length) and push to tx_buffer.
// Level: APPLICATION only. Ownership: copies `data`.
YAWT_Q_Error_t YAWT_q_enqueue_frame_datagram(YAWT_Q_Connection_t *con,
                                               const uint8_t *data, size_t data_len);

// Encode a HANDSHAKE_DONE frame (0x1e) and push to tx_buffer. Level: APPLICATION only.
YAWT_Q_Error_t YAWT_q_enqueue_frame_handshake_done(YAWT_Q_Connection_t *con);

// Encode + encrypt a packet.
//   Returns:    total wire bytes (including AEAD tag), or negative on error.
//   Transience: *out_buf points to a STATIC internal buffer, overwritten by the
//     next encode call — consume/copy it before encoding again.
struct YAWT_Q_Crypto;
typedef struct YAWT_Q_Crypto YAWT_Q_Crypto_t;

int YAWT_q_encode_packet(YAWT_Q_Packet_t *pkt,
                          YAWT_Q_Crypto_t *crypto,
                          const uint8_t **out_buf);

// Decode a QUIC varint from cursor. `out == NULL` skips the value (advance only).
// Errors: sticky (see YAWT_Q_ReadCursor_t) — SHORT_BUFFER if fewer bytes remain
// than the varint's encoded length; cursor not advanced on error.
void YAWT_q_varint_decode(YAWT_Q_ReadCursor_t *rc, uint64_t *out);

// Encode a QUIC varint into buf. Returns bytes written via *written.
// Errors: VARINT_OVERFLOW if val exceeds 62 bits; SHORT_BUFFER if `len` too small.
YAWT_Q_Error_t YAWT_q_varint_encode(uint64_t val, uint8_t *buf, size_t len,
                                     uint64_t *written);

// Parse a QUIC packet from a read cursor.
//   Transience: output pointers (payload/raw/token) point INTO rc->data (zero-copy).
//   Errors:     sticky; check rc->err after the call.
// Advances rc->cursor past the parsed packet.
void YAWT_q_parse_packet(YAWT_Q_ReadCursor_t *rc, YAWT_Q_Packet_t *out);

// Parse a single frame from the cursor. Caller loops while rc->cursor < rc->len.
//   `out` is memset, stamped with `pkt_type` (source encryption level), and the
//     frame's pointer fields point INTO rc->data (zero-copy, transient).
//   Errors: sticky; check rc->err after the call.
//   Note:   parses the subset of frame types YAWT handles.
void YAWT_q_parse_frame(YAWT_Q_ReadCursor_t *rc, YAWT_Q_Packet_Type_t pkt_type,
                         YAWT_Q_Frame_t *out);
