#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "logger.h"


// Quic connection initialization goes like this
// Initial -> Handshake -> 1-RTT
// Initial - Establishes header protection key + Client\Server Hello + CIDs
// Handshake - Establishes RTT keys + Handshake messages
// 1-RTT - Application keys
//[IP[UDP[QUICK_PKT[FRAME1[...], FRAME2[...], ...],[QUICK_PKT2.....]]]]
//Loss detection is at the quic packet level, not per frame, uses counter

//UNIMPLEMENTED: Congestion Windows
// QUIC parse error codes
typedef enum {
  YAWT_Q_OK = 0,
  YAWT_Q_ERR_SHORT_BUFFER,
  YAWT_Q_ERR_INVALID_PACKET,
  YAWT_Q_ERR_VARINT_OVERFLOW,
  YAWT_Q_ERR_CID_TOO_LONG
} YAWT_Q_Error_t;

typedef struct YAWT_Q_Cid {
  uint8_t id[20];
  uint8_t len;
} YAWT_Q_Cid_t;

static inline void YAWT_q_cid_set(YAWT_Q_Cid_t *dst, const uint8_t *id, uint8_t len) {
  if (len > 20) {
    len = 20;
    YAWT_LOG(YAWT_LOG_ERROR, "CID length %u exceeds max, truncating to 20", len);
  }
  dst->len = len;
  memcpy(dst->id, id, len);
}

// QUIC packet type (all 5 forms)
typedef enum {
  YAWT_Q_PKT_TYPE_INITIAL,
  YAWT_Q_PKT_TYPE_0RTT,
  YAWT_Q_PKT_TYPE_HANDSHAKE,
  YAWT_Q_PKT_TYPE_RETRY,
  YAWT_Q_PKT_TYPE_1RTT
} YAWT_Q_Packet_Type_t;

// QUIC stream types RFC9000
typedef enum {
  YAWT_Q_C_BIDI = 0x00,
  YAWT_Q_S_BIDI = 0x01,
  YAWT_Q_C_UNI = 0x02,
  YAWT_Q_S_UNI = 0x03
} YAWT_Q_Stream_Type_t;

typedef enum {
  YAWT_Q_FRAME_PADDING = 0x00,
  YAWT_Q_FRAME_PING = 0x01,
  YAWT_Q_FRAME_ACK = 0x02,
  YAWT_Q_FRAME_ACK_ECN = 0x03,
  YAWT_Q_FRAME_RESET_STREAM = 0x04,
  YAWT_Q_FRAME_STOP_SENDING = 0x05,
  YAWT_Q_FRAME_CRYPTO = 0x06,
  YAWT_Q_FRAME_NEW_TOKEN = 0x07,
  YAWT_Q_FRAME_STREAM = 0x08, //0b00001000 - 0b00011111
  YAWT_Q_FRAME_MAX_DATA = 0x10,
  YAWT_Q_FRAME_MAX_STREAM_DATA = 0x11,
  YAWT_Q_FRAME_MAX_STREAMS_BIDI = 0x12,
  YAWT_Q_FRAME_MAX_STREAMS_UNI = 0x13,
  YAWT_Q_FRAME_DATA_BLOCKED = 0x14,
  YAWT_Q_FRAME_STREAM_DATA_BLOCKED = 0x15,
  YAWT_Q_FRAME_STREAMS_BLOCKED_BIDI = 0x16,
  YAWT_Q_FRAME_STREAMS_BLOCKED_UNI = 0x17,
  YAWT_Q_FRAME_NEW_CONNECTION_ID = 0x18,
  YAWT_Q_FRAME_RETIRE_CONNECTION_ID = 0x19,
  YAWT_Q_FRAME_PATH_CHALLENGE = 0x1a,
  YAWT_Q_FRAME_PATH_RESPONSE = 0x1b,
  YAWT_Q_FRAME_CONNECTION_CLOSE = 0x1c,
  YAWT_Q_FRAME_CONNECTION_CLOSE_APP = 0x1d,
  YAWT_Q_FRAME_HANDSHAKE_DONE = 0x1e
} YAWT_Q_Frame_Type_t;

typedef enum {
  YAWT_Q_PKT_INITIAL = 0x00,
  YAWT_Q_PKT_0RTT = 0x01,
  YAWT_Q_PKT_HANDSHAKE = 0x02,
  YAWT_Q_PKT_RETRY = 0x03
} YAWT_Q_Long_Packet_Type_t;

// Flat packet struct — all packet types collapsed into one
typedef struct YAWT_Q_Packet {
  YAWT_Q_Packet_Type_t type;

  // Header fields (all packet types)
  uint32_t version;            // 0 for 1-RTT
  YAWT_Q_Cid_t dest_cid;
  YAWT_Q_Cid_t src_cid;         // zeroed for 1-RTT

  // Encrypted packet fields (not Retry)
  uint8_t reserved;            // 2 bits
  uint8_t packet_number_length; // 1-4
  uint32_t packet_num;
  uint8_t *payload;
  size_t payload_len;

  // Crypto support
  uint8_t *raw;                // pointer to byte 0 in datagram buffer
  size_t pn_offset;            // byte offset of PN from raw

  // Type-specific extras
  union {
    struct {
      uint64_t token_len;
      uint8_t *token;
    } initial;
    struct {
      uint8_t spin_bit;
      uint8_t key_phase;
    } one_rtt;
    struct {
      uint64_t token_len;
      uint8_t *token;
      uint8_t retry_integrity_tag[16];
    } retry;
  } extra;
} YAWT_Q_Packet_t;

// Frame type 0x00 - PADDING
// No fields, just the type byte. No struct needed.

// Frame type 0x01 - PING
// No fields, just the type byte. No struct needed.

// Frame type 0x02 - ACK
typedef struct {
  uint64_t largest_ack; //varint
  uint64_t ack_delay; //varint
  uint64_t ack_range_count; //varint
  uint64_t first_ack_range; //varint
  // followed by ack_range_count ACK) Range fields
} YAWT_Q_Frame_ACK_t;

typedef struct {
  uint64_t gap; //varint
  uint64_t ack_range_len; //varint
} YAWT_Q_ACK_Range_t;

// Frame type 0x03 - ACK with ECN Counts
typedef struct {
  uint64_t largest_ack; //varint
  uint64_t ack_delay; //varint
  uint64_t ack_range_count; //varint
  uint64_t first_ack_range; //varint
  // followed by ack_range_count ACK Range fields, then ECN counts:
  uint64_t ect0_count; //varint
  uint64_t ect1_count; //varint
  uint64_t ecn_ce_count; //varint
} YAWT_Q_Frame_ACK_ECN_t;

// Frame type 0x04 - RESET_STREAM
typedef struct {
  uint64_t stream_id; //varint
  uint64_t app_error_code; //varint
  uint64_t final_size; //varint
} YAWT_Q_Frame_Reset_Stream_t;

// Frame type 0x05 - STOP_SENDING
typedef struct {
  uint64_t stream_id; //varint
  uint64_t app_error_code; //varint
} YAWT_Q_Frame_Stop_Sending_t;

// Frame type 0x06 - CRYPTO
typedef struct {
  uint64_t offset; //varint
  uint64_t len; //varint
  uint8_t *data;
} YAWT_Q_Frame_Crypto_t;

// Frame type 0x07 - NEW_TOKEN
typedef struct {
  uint64_t token_len; //varint
  uint8_t *token;
} YAWT_Q_Frame_New_Token_t;

// Frame type 0x08-0x0f - STREAM
// Low 3 bits of frame type: OFF(0x04) LEN(0x02) FIN(0x01)
typedef struct {
  uint8_t off; //1 bit, from frame type
  uint8_t len_present; //1 bit, from frame type
  uint8_t fin; //1 bit, from frame type
  uint64_t stream_id; //varint
  uint64_t offset; //varint, present if off bit set
  uint64_t len; //varint, present if len bit set
  uint8_t *data;
} YAWT_Q_Frame_Stream_t;

// Frame type 0x10 - MAX_DATA
typedef struct {
  uint64_t max_data; //varint
} YAWT_Q_Frame_Max_Data_t;

// Frame type 0x11 - MAX_STREAM_DATA
typedef struct {
  uint64_t stream_id; //varint
  uint64_t max_stream_data; //varint
} YAWT_Q_Frame_Max_Stream_Data_t;

// Frame type 0x12 - MAX_STREAMS (bidi)
// Frame type 0x13 - MAX_STREAMS (uni)
typedef struct {
  uint64_t max_streams; //varint
} YAWT_Q_Frame_Max_Streams_t;

// Frame type 0x14 - DATA_BLOCKED
typedef struct {
  uint64_t max_data; //varint, limit at which blocking occurred
} YAWT_Q_Frame_Data_Blocked_t;

// Frame type 0x15 - STREAM_DATA_BLOCKED
typedef struct {
  uint64_t stream_id; //varint
  uint64_t max_stream_data; //varint, limit at which blocking occurred
} YAWT_Q_Frame_Stream_Data_Blocked_t;

// Frame type 0x16 - STREAMS_BLOCKED (bidi)
// Frame type 0x17 - STREAMS_BLOCKED (uni)
typedef struct {
  uint64_t max_streams; //varint, limit at which blocking occurred
} YAWT_Q_Frame_Streams_Blocked_t;

// Frame type 0x18 - NEW_CONNECTION_ID
typedef struct {
  uint64_t seq_num; //varint
  uint64_t retire_prior_to; //varint
  YAWT_Q_Cid_t cid;
  uint8_t stateless_reset_token[16];
} YAWT_Q_Frame_New_Connection_ID_t;

// Frame type 0x19 - RETIRE_CONNECTION_ID
typedef struct {
  uint64_t seq_num; //varint
} YAWT_Q_Frame_Retire_Connection_ID_t;

// Frame type 0x1a - PATH_CHALLENGE
typedef struct {
  uint8_t data[8];
} YAWT_Q_Frame_Path_Challenge_t;

// Frame type 0x1b - PATH_RESPONSE
typedef struct {
  uint8_t data[8];
} YAWT_Q_Frame_Path_Response_t;

// Frame type 0x1c - CONNECTION_CLOSE (QUIC layer)
typedef struct {
  uint64_t error_code; //varint
  uint64_t frame_type; //varint, frame type that triggered the error
  uint64_t reason_phrase_len; //varint
  uint8_t *reason_phrase;
} YAWT_Q_Frame_Connection_Close_t;

// Frame type 0x1d - CONNECTION_CLOSE (application layer)
typedef struct {
  uint64_t error_code; //varint
  uint64_t reason_phrase_len; //varint
  uint8_t *reason_phrase;
} YAWT_Q_Frame_Connection_Close_App_t;

// Frame type 0x1e - HANDSHAKE_DONE
// No fields, just the type byte. No struct needed.

// Generic frame struct for tx_buffer — all frame types in one union
typedef struct {
  YAWT_Q_Frame_Type_t type;
  uint8_t level;  // YAWT_Q_Encryption_Level_t — which packet type to send in

  // Send tracking
  uint32_t packet_num;              // PN this was sent in (0 if unsent)
  uint64_t last_sent;               // timestamp of last send (0 = needs sending)

  // Inline data length (for CRYPTO/STREAM data stored after this struct)
  size_t data_len;

  union {
    YAWT_Q_Frame_Crypto_t crypto;
    YAWT_Q_Frame_ACK_t ack;
    YAWT_Q_Frame_Stream_t stream;
  } f;
} YAWT_Q_Frame_t;

// Frame handler callback for parse_frames. frame_type is the wire type.
// frame points to the parsed frame struct (NULL for PADDING/PING).
// Return 0 to continue, non-zero to stop.
typedef int (*YAWT_Q_Frame_Handler_t)(uint64_t frame_type, const void *frame, void *ctx);

// Parse frames from a decrypted payload, calling handler for each frame.
YAWT_Q_Error_t YAWT_q_parse_frames(const uint8_t *payload, size_t payload_len,
                                     YAWT_Q_Frame_Handler_t handler, void *ctx);

// Encode a CRYPTO frame into buf. Returns total bytes written, or negative on error.
int YAWT_q_encode_frame_crypto(uint8_t *buf, size_t buf_len,
                                uint64_t offset, const uint8_t *data, size_t data_len);

// Encode a packet (dispatch by type). Returns YAWT_Q_OK on success.
YAWT_Q_Error_t YAWT_q_encode_packet(const YAWT_Q_Packet_t *pkt,
                                      uint8_t *buf, size_t len, size_t *written);

// Read cursor for zero-copy datagram parsing
typedef struct {
  uint8_t *data;
  size_t len;
  size_t cursor;
  YAWT_Q_Error_t err;
} YAWT_Q_ReadCursor_t;

// Parse a QUIC packet from a read cursor (zero-copy: pointers into cursor data).
// Advances rc->cursor past the parsed packet. Check rc->err after call.
void YAWT_q_parse_packet(YAWT_Q_ReadCursor_t *rc, YAWT_Q_Packet_t *out);

// Format a CID as hex string. Returns pointer to static buffer (not thread-safe).
static inline const char *YAWT_q_cid_to_hex(const YAWT_Q_Cid_t *cid) {
  static char buf[41];
  memset(buf, 0, sizeof(buf));
  for (uint8_t i = 0; i < cid->len && i < 20; i++) {
    sprintf(buf + 2 * i, "%02x", cid->id[i]);
  }
  return buf;
}
