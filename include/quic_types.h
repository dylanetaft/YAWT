/**
 * @file quic_types.h
 * @brief Core QUIC data structures, constants, and enums.
 */

/**
 * @defgroup Quic Quic
 * @brief All QUIC protocol types, constants, and low-level operations.
 */

/**
 * @defgroup Core Core
 * @brief High-level connection management and I/O API for both QUIC and HTTP/3.
 */

#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "logger.h"

/**
 * @ingroup Quic
 * @brief Forward declaration for peer address.
 */
struct YAWT_Q_PeerAddr;
typedef struct YAWT_Q_PeerAddr YAWT_Q_PeerAddr_t;

/** @ingroup Quic Maximum QUIC packet size */
#define YAWT_Q_MAX_PKT_SIZE 1350
/** @ingroup Quic Maximum Connection ID length */
#define YAWT_Q_CID_LEN 20

/** @ingroup Quic Worst-case long header overhead (header + PN + AEAD tag) */
#define YAWT_Q_LONG_HDR_OVERHEAD  69
/** @ingroup Quic Worst-case short header overhead (header + PN + AEAD tag) */
#define YAWT_Q_SHORT_HDR_OVERHEAD 41

/** @ingroup Quic Max frame data that can safely fit in a long header packet */
#define YAWT_Q_MAX_FRAME_PAYLOAD_LONG  (YAWT_Q_MAX_PKT_SIZE - YAWT_Q_LONG_HDR_OVERHEAD)
/** @ingroup Quic Max frame data that can safely fit in a short header packet */
#define YAWT_Q_MAX_FRAME_PAYLOAD_SHORT (YAWT_Q_MAX_PKT_SIZE - YAWT_Q_SHORT_HDR_OVERHEAD)

/**
 * @ingroup Quic
 * @brief QUIC Connection ID.
 */
typedef struct YAWT_Q_Cid {
  uint8_t id[20];
  uint8_t len;
} YAWT_Q_Cid_t;

/**
 * @ingroup Quic
 * @brief Set a Connection ID.
 * @param dst Destination CID struct.
 * @param id Source byte array.
 * @param len Length of the source byte array. Truncated to 20 if > 20.
 */
static inline void YAWT_q_cid_set(YAWT_Q_Cid_t *dst, const uint8_t *id, uint8_t len) {
  if (len > 20) {
    len = 20;
    YAWT_LOG(YAWT_LOG_ERROR, "CID length %u exceeds max, truncating to 20", len);
  }
  dst->len = len;
  memcpy(dst->id, id, len);
}

/**
 * @ingroup Quic
 * @brief Format a CID as a hex string.
 * @param cid The Connection ID to format.
 * @return Pointer to a static buffer containing the hex string (not thread-safe).
 */
static inline const char *YAWT_q_cid_to_hex(const YAWT_Q_Cid_t *cid) {
  static char buf[41];
  memset(buf, 0, sizeof(buf));
  for (uint8_t i = 0; i < cid->len && i < 20; i++) {
    sprintf(buf + 2 * i, "%02x", cid->id[i]);
  }
  return buf;
}

/**
 * @ingroup Quic
 * @brief QUIC packet types (all 5 forms).
 * @note Long-header forms match the 2-bit long-packet type field (RFC 9000 §17.2).
 *       1-RTT has no encoded type bits (short header); 0xFF is an in-memory sentinel.
 */
typedef enum {
  YAWT_Q_PKT_TYPE_INITIAL   = 0x00,
  YAWT_Q_PKT_TYPE_0RTT      = 0x01,
  YAWT_Q_PKT_TYPE_HANDSHAKE = 0x02,
  YAWT_Q_PKT_TYPE_RETRY     = 0x03,
  YAWT_Q_PKT_TYPE_1RTT      = 0xFF
} YAWT_Q_Packet_Type_t;

/**
 * @ingroup Quic
 * @brief QUIC stream types (RFC 9000).
 */
typedef enum {
  YAWT_Q_C_BIDI = 0x00,
  YAWT_Q_S_BIDI = 0x01,
  YAWT_Q_C_UNI = 0x02,
  YAWT_Q_S_UNI = 0x03
} YAWT_Q_Stream_Type_t;

/**
 * @ingroup Quic
 * @brief QUIC frame types.
 */
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
  YAWT_Q_FRAME_HANDSHAKE_DONE = 0x1e,
  // RFC 9221 §5 — DATAGRAM extension (not in RFC 9000 core)
  YAWT_Q_FRAME_DATAGRAM      = 0x30,  // no length field, extends to end of packet
  YAWT_Q_FRAME_DATAGRAM_LEN  = 0x31   // has length field
} YAWT_Q_Frame_Type_t;

/**
 * @ingroup Quic
 * @brief QUIC long packet types.
 */
typedef enum {
  YAWT_Q_PKT_INITIAL = 0x00,
  YAWT_Q_PKT_0RTT = 0x01,
  YAWT_Q_PKT_HANDSHAKE = 0x02,
  YAWT_Q_PKT_RETRY = 0x03
} YAWT_Q_Long_Packet_Type_t;

/**
 * @ingroup Quic
 * @brief Flat packet struct — all packet types collapsed into one.
 * @warning Transience: when produced by YAWT_q_parse_packet, the pointer fields below
 * (payload, raw, and extra.*.token) borrow INTO the input datagram buffer.
 * They are valid only while that buffer is. Decrypt happens in-place on those bytes.
 * Do not retain these pointers beyond the current parse scope.
 */
typedef struct YAWT_Q_Packet {
  YAWT_Q_Packet_Type_t type;

  /** Header fields (all packet types) */
  uint32_t version;
  YAWT_Q_Cid_t dest_cid;
  YAWT_Q_Cid_t src_cid;

  /** Encrypted packet fields (not Retry) */
  uint8_t reserved;
  uint8_t packet_number_length;
  uint32_t packet_num;
  uint8_t *payload;
  size_t payload_len;

  // Crypto support
  uint8_t *raw;                // pointer to byte 0 in datagram buffer
  size_t pn_offset;            // byte offset of PN from raw

  /** Type-specific extras */
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

/**
 * @ingroup Quic
 * @brief ACK frame (0x02).
 */
typedef struct {
  uint64_t largest_ack;
  uint64_t ack_delay;
  uint64_t ack_range_count;
  uint64_t first_ack_range;
  /** @warning Transience: Pointer into raw packet data. Do not retain. */
  uint8_t *ranges;
} YAWT_Q_Frame_ACK_t;

/**
 * @ingroup Quic
 * @brief ACK Range field.
 */
typedef struct {
  uint64_t gap;
  uint64_t ack_range_len;
} YAWT_Q_ACK_Range_t;

/**
 * @ingroup Quic
 * @brief ACK with ECN Counts frame (0x03).
 */
typedef struct {
  uint64_t largest_ack;
  uint64_t ack_delay;
  uint64_t ack_range_count;
  uint64_t first_ack_range;
  uint64_t ect0_count;
  uint64_t ect1_count;
  uint64_t ecn_ce_count;
} YAWT_Q_Frame_ACK_ECN_t;

/**
 * @ingroup Quic
 * @brief RESET_STREAM frame (0x04).
 */
typedef struct {
  uint64_t stream_id;
  uint64_t app_error_code;
  uint64_t final_size;
} YAWT_Q_Frame_Reset_Stream_t;

/**
 * @ingroup Quic
 * @brief STOP_SENDING frame (0x05).
 */
typedef struct {
  uint64_t stream_id;
  uint64_t app_error_code;
} YAWT_Q_Frame_Stop_Sending_t;

/**
 * @ingroup Quic
 * @brief CRYPTO frame (0x06).
 */
typedef struct {
  uint64_t offset;
  uint64_t len;
  /** @warning Transience: Borrowed pointer into the input datagram buffer. Do not retain. */
  uint8_t *data;
} YAWT_Q_Frame_Crypto_t;

/**
 * @ingroup Quic
 * @brief NEW_TOKEN frame (0x07).
 */
typedef struct {
  uint64_t token_len;
  /** @warning Transience: Borrowed pointer into the input datagram buffer. Do not retain. */
  uint8_t *token;
} YAWT_Q_Frame_New_Token_t;

/**
 * @ingroup Quic
 * @brief STREAM frame (0x08-0x0f).
 * @note Low 3 bits of frame type: OFF(0x04) LEN(0x02) FIN(0x01).
 */
typedef struct YAWT_Q_Frame_Stream {
  uint8_t off;
  uint8_t len_present;
  uint8_t fin;
  uint64_t stream_id;
  YAWT_Q_Stream_Type_t stream_type;
  uint64_t offset;
  uint64_t data_len;
  /** @warning Transience: ALWAYS a borrowed pointer. Into the UDP datagram buffer during parse, 
   * or into the owning BufferedStream's data[] during delivery. Never owned, never retain 
   * past the current call/event. To keep bytes, copy them. */
  uint8_t *data;
} YAWT_Q_Frame_Stream_t;

/**
 * @ingroup Quic
 * @brief A STREAM frame plus the storage its .frame.data points at.
 * @note Used when a frame must outlive the input datagram (out-of-order RX buffering 
 * and TX queuing). bf->data is the OWNED inline copy. bf->frame.data is the borrowed 
 * pointer, set to point at bf->data when buffered.
 */
typedef struct YAWT_Q_Frame_BufferedStream {
  YAWT_Q_Frame_Stream_t frame;
  uint8_t data[YAWT_Q_MAX_PKT_SIZE];  // owned copy; frame.data points here when buffered
} YAWT_Q_Frame_BufferedStream_t;

/**
 * @ingroup Quic
 * @brief Scatter/gather buffer element for sending.
 */
typedef struct YAWT_Q_IoVec {
  const uint8_t *buf;
  size_t len;
} YAWT_Q_IoVec_t;

/**
 * @ingroup Quic
 * @brief MAX_DATA frame (0x10).
 */
typedef struct {
  uint64_t max_data;
} YAWT_Q_Frame_Max_Data_t;

/**
 * @ingroup Quic
 * @brief MAX_STREAM_DATA frame (0x11).
 */
typedef struct {
  uint64_t stream_id;
  uint64_t max_stream_data;
} YAWT_Q_Frame_Max_Stream_Data_t;

/**
 * @ingroup Quic
 * @brief MAX_STREAMS frame (0x12 bidi, 0x13 uni).
 */
typedef struct {
  uint64_t max_streams;
} YAWT_Q_Frame_Max_Streams_t;

/**
 * @ingroup Quic
 * @brief DATA_BLOCKED frame (0x14).
 */
typedef struct {
  uint64_t max_data;
} YAWT_Q_Frame_Data_Blocked_t;

/**
 * @ingroup Quic
 * @brief STREAM_DATA_BLOCKED frame (0x15).
 */
typedef struct {
  uint64_t stream_id;
  uint64_t max_stream_data;
} YAWT_Q_Frame_Stream_Data_Blocked_t;

/**
 * @ingroup Quic
 * @brief STREAMS_BLOCKED frame (0x16 bidi, 0x17 uni).
 */
typedef struct {
  uint64_t max_streams;
} YAWT_Q_Frame_Streams_Blocked_t;

/**
 * @ingroup Quic
 * @brief NEW_CONNECTION_ID frame (0x18).
 */
typedef struct {
  uint64_t seq_num;
  uint64_t retire_prior_to;
  YAWT_Q_Cid_t cid;
  uint8_t stateless_reset_token[16];
} YAWT_Q_Frame_New_Connection_ID_t;

/**
 * @ingroup Quic
 * @brief RETIRE_CONNECTION_ID frame (0x19).
 */
typedef struct {
  uint64_t seq_num;
} YAWT_Q_Frame_Retire_Connection_ID_t;

/**
 * @ingroup Quic
 * @brief PATH_CHALLENGE frame (0x1a).
 */
typedef struct {
  uint8_t data[8];
} YAWT_Q_Frame_Path_Challenge_t;

/**
 * @ingroup Quic
 * @brief PATH_RESPONSE frame (0x1b).
 */
typedef struct {
  uint8_t data[8];
} YAWT_Q_Frame_Path_Response_t;

/**
 * @ingroup Quic
 * @brief CONNECTION_CLOSE frame (0x1c, QUIC layer).
 */
typedef struct {
  uint64_t error_code;
  uint64_t frame_type;
  uint64_t reason_phrase_len;
  /** @warning Transience: Borrowed pointer into the input datagram buffer. Do not retain. */
  uint8_t *reason_phrase;
} YAWT_Q_Frame_Connection_Close_t;

/**
 * @ingroup Quic
 * @brief CONNECTION_CLOSE frame (0x1d, application layer).
 */
typedef struct {
  uint64_t error_code;
  uint64_t reason_phrase_len;
  /** @warning Transience: Borrowed pointer into the input datagram buffer. Do not retain. */
  uint8_t *reason_phrase;
} YAWT_Q_Frame_Connection_Close_App_t;

/**
 * @ingroup Quic
 * @brief DATAGRAM frame (0x30-0x31, RFC 9221).
 * @note Low bit: LEN(0x01) — if set, length varint is present.
 */
typedef struct {
  uint8_t len_present;
  uint64_t len;
  /** @warning Transience: Borrowed pointer into the input datagram buffer. Do not retain. */
  uint8_t *dataptr;
} YAWT_Q_Frame_Datagram_t;

/**
 * @ingroup Quic
 * @brief Parsed frame — returned by YAWT_q_parse_frame.
 */
typedef struct {
  YAWT_Q_Frame_Type_t type;
  YAWT_Q_Packet_Type_t pkt_type;
  union {
    YAWT_Q_Frame_ACK_t ack;
    YAWT_Q_Frame_Crypto_t crypto;
    YAWT_Q_Frame_Stream_t stream;
    YAWT_Q_Frame_Connection_Close_t connection_close;
    YAWT_Q_Frame_Connection_Close_App_t connection_close_app;
    YAWT_Q_Frame_New_Connection_ID_t new_connection_id;
    YAWT_Q_Frame_Max_Data_t max_data;
    YAWT_Q_Frame_Max_Stream_Data_t max_stream_data;
    YAWT_Q_Frame_Max_Streams_t max_streams;
    YAWT_Q_Frame_Path_Challenge_t path_challenge;
    YAWT_Q_Frame_Path_Response_t path_response;
    YAWT_Q_Frame_Datagram_t datagram;
  };
} YAWT_Q_Frame_t;

/**
 * @ingroup Quic
 * @brief QUIC event taxonomy.
 * @note New events extend this enum AND add a matching `P_<eventtype>` substruct
 * to YAWT_Q_EventParam_t below. The 1:1 mapping between enum suffix and union
 * member name is part of the contract.
 */
typedef enum {
  YAWT_Q_EVT_CONNECTED,
  YAWT_Q_EVT_STREAM,
  YAWT_Q_EVT_DATAGRAM,
  YAWT_Q_EVT_CLOSE,
  YAWT_Q_EVT_TX,
} YAWT_Q_EventType_t;

/**
 * @ingroup Quic
 * @brief Per-event parameters.
 * @warning Transience: ALL pointers in this union are valid ONLY for the duration
 * of the handler call. They reference internal/transient storage (the input datagram
 * buffer, a slab item, or an encode scratch buffer) that the QUIC layer reuses
 * immediately after the handler returns. Copy anything you need to retain.
 */
typedef union YAWT_Q_EventParam {
  struct { } P_EVT_CONNECTED;

  struct {
    const YAWT_Q_Frame_Stream_t *frame;
  } P_EVT_STREAM;

  struct {
    const uint8_t *data;
    size_t len;
  } P_EVT_DATAGRAM;

  struct {
    uint64_t error_code;
    const char *reason;           // null-terminated, bounded
  } P_EVT_CLOSE;

  struct {
    const uint8_t *buf;
    size_t len;
    const YAWT_Q_PeerAddr_t *peer;
  } P_EVT_TX;
} YAWT_Q_EventParam_t;
