#include <string.h>
#include "quic.h"
#include "crypt.h"

static uint8_t _encode_buf[YAWT_Q_MAX_PKT_SIZE];

static void _varint_decode(YAWT_Q_ReadCursor_t *rc, uint64_t *out) {
  if (rc->err != YAWT_Q_OK) return;
  if (rc->cursor >= rc->len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }

  const uint8_t *buf = rc->data + rc->cursor;
  size_t remaining = rc->len - rc->cursor;

  uint8_t prefix = buf[0] >> 6;
  int vlen = 1 << prefix; // 1, 2, 4, or 8

  if ((size_t)vlen > remaining) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }

  uint64_t val = buf[0] & 0x3f;
  for (int i = 1; i < vlen; i++) {
    val = (val << 8) | buf[i];
  }

  *out = val;
  rc->cursor += vlen;
}

static YAWT_Q_Error_t _varint_encode(uint64_t val, uint8_t *buf, size_t len,
                                      int *written) {
  int vlen;
  uint8_t prefix;

  if (val <= 0x3f) {
    vlen = 1; prefix = 0x00;
  } else if (val <= 0x3fff) {
    vlen = 2; prefix = 0x40;
  } else if (val <= 0x3fffffff) {
    vlen = 4; prefix = 0x80;
  } else if (val <= 0x3fffffffffffffff) {
    vlen = 8; prefix = 0xc0;
  } else {
    return YAWT_Q_ERR_VARINT_OVERFLOW;
  }

  if ((size_t)vlen > len) return YAWT_Q_ERR_SHORT_BUFFER;

  for (int i = vlen - 1; i >= 1; i--) {
    buf[i] = (uint8_t)(val & 0xff);
    val >>= 8;
  }
  buf[0] = (uint8_t)(val & 0x3f) | prefix;

  *written = vlen;
  return YAWT_Q_OK;
}

// Parse the shared long header fields directly into a flat YAWT_Q_Packet_t.
// Advances rc->cursor past consumed bytes. Does NOT parse byte 0's lower 4 bits.
static void _parse_long_header(YAWT_Q_ReadCursor_t *rc, YAWT_Q_Packet_t *pkt) {
  if (rc->err != YAWT_Q_OK) return;

  const uint8_t *in = rc->data;
  size_t len = rc->len;

  // Byte 0: header_form (bit 7), fixed_bit (bit 6), long_packet_type (bits 5-4)
  if (rc->cursor >= len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }
  uint8_t b0 = in[rc->cursor];
  uint8_t fixed_bit = (b0 >> 6) & 1;
  if (!fixed_bit) { rc->err = YAWT_Q_ERR_INVALID_PACKET; return; } // RFC 9000 §17.2
  // Lower 4 bits: reserved (bits 3-2) + packet_number_length (bits 1-0)
  // For Retry these are unused/ignored, but harmless to set.
  pkt->reserved = (b0 >> 2) & 3;
  pkt->packet_number_length = (b0 & 3) + 1;
  rc->cursor++;

  // Version (4 bytes)
  if (rc->cursor + 4 > len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }
  pkt->version = ((uint32_t)in[rc->cursor] << 24) |
                ((uint32_t)in[rc->cursor + 1] << 16) |
                ((uint32_t)in[rc->cursor + 2] << 8) |
                (uint32_t)in[rc->cursor + 3];
  rc->cursor += 4;

  // DCID Length (1 byte) + DCID
  if (rc->cursor >= len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }
  pkt->dest_cid.len = in[rc->cursor];
  rc->cursor++;
  if (pkt->dest_cid.len > sizeof(pkt->dest_cid.id)) { rc->err = YAWT_Q_ERR_CID_TOO_LONG; return; }
  if (rc->cursor + pkt->dest_cid.len > len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }
  memcpy(pkt->dest_cid.id, in + rc->cursor, pkt->dest_cid.len);
  rc->cursor += pkt->dest_cid.len;

  // SCID Length (1 byte) + SCID
  if (rc->cursor >= len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }
  pkt->src_cid.len = in[rc->cursor];
  rc->cursor++;
  if (pkt->src_cid.len > sizeof(pkt->src_cid.id)) { rc->err = YAWT_Q_ERR_CID_TOO_LONG; return; }
  if (rc->cursor + pkt->src_cid.len > len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }
  memcpy(pkt->src_cid.id, in + rc->cursor, pkt->src_cid.len);
  rc->cursor += pkt->src_cid.len;
}

// Parse common PN + payload fields. cursor must be at the PN field.
// pkt_start is the absolute cursor of byte 0 for this packet.
// pkt_end is the absolute cursor of the byte after this packet.
// Note: packet_number_length from byte 0 is unreliable here (still header-protected).
// We record pn_offset and set payload to cover everything after it.
// unprotect_packet will re-read the true PN length after HP removal.
static void _parse_common(YAWT_Q_ReadCursor_t *rc, YAWT_Q_Packet_t *pkt,
                           size_t pkt_start, size_t pkt_end) {
  if (rc->err != YAWT_Q_OK) return;

  // Record pn_offset relative to raw (pkt_start)
  pkt->pn_offset = rc->cursor - pkt_start;

  // Payload = everything from pn_offset to pkt_end (includes PN + ciphertext + tag).
  // unprotect_packet will sort out the real PN length and adjust payload after HP removal.
  pkt->payload = (uint8_t *)(rc->data + rc->cursor);
  pkt->payload_len = pkt_end - rc->cursor;

  // Advance cursor to next packet boundary
  rc->cursor = pkt_end;
}

static void _parse_pkt_initial(YAWT_Q_ReadCursor_t *rc, YAWT_Q_Packet_t *pkt) {
  if (rc->err != YAWT_Q_OK) return;

  size_t pkt_start = rc->cursor;
  _parse_long_header(rc, pkt);
  if (rc->err != YAWT_Q_OK) return;

  // Token Length (varint)
  _varint_decode(rc, &pkt->extra.initial.token_len);
  if (rc->err != YAWT_Q_OK) return;

  // Token (zero-copy pointer into input)
  if (rc->cursor + pkt->extra.initial.token_len > rc->len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }
  pkt->extra.initial.token = pkt->extra.initial.token_len > 0 ? (uint8_t *)(rc->data + rc->cursor) : NULL;
  rc->cursor += pkt->extra.initial.token_len;

  // Length (varint) — marks the packet boundary
  uint64_t wire_len;
  _varint_decode(rc, &wire_len);
  if (rc->err != YAWT_Q_OK) return;
  size_t pkt_end = rc->cursor + wire_len;

  _parse_common(rc, pkt, pkt_start, pkt_end);
}

static void _parse_pkt_0rtt(YAWT_Q_ReadCursor_t *rc, YAWT_Q_Packet_t *pkt) {
  if (rc->err != YAWT_Q_OK) return;

  size_t pkt_start = rc->cursor;
  _parse_long_header(rc, pkt);
  if (rc->err != YAWT_Q_OK) return;

  // Length (varint)
  uint64_t wire_len;
  _varint_decode(rc, &wire_len);
  if (rc->err != YAWT_Q_OK) return;
  size_t pkt_end = rc->cursor + wire_len;

  _parse_common(rc, pkt, pkt_start, pkt_end);
}

static void _parse_pkt_handshake(YAWT_Q_ReadCursor_t *rc, YAWT_Q_Packet_t *pkt) {
  if (rc->err != YAWT_Q_OK) return;

  size_t pkt_start = rc->cursor;
  _parse_long_header(rc, pkt);
  if (rc->err != YAWT_Q_OK) return;

  uint64_t wire_len;
  _varint_decode(rc, &wire_len);
  if (rc->err != YAWT_Q_OK) return;
  size_t pkt_end = rc->cursor + wire_len;

  _parse_common(rc, pkt, pkt_start, pkt_end);
}

static void _parse_pkt_retry(YAWT_Q_ReadCursor_t *rc, YAWT_Q_Packet_t *pkt) {
  if (rc->err != YAWT_Q_OK) return;

  size_t pkt_start = rc->cursor;
  _parse_long_header(rc, pkt);
  if (rc->err != YAWT_Q_OK) return;

  // Retry token = everything between header and last 16 bytes (integrity tag)
  if (rc->cursor + 16 > rc->len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }

  size_t token_bytes = rc->len - rc->cursor - 16;
  if (token_bytes == 0) { rc->err = YAWT_Q_ERR_INVALID_PACKET; return; } // RFC 9000 §17.2.5
  pkt->extra.retry.token_len = token_bytes;
  pkt->extra.retry.token = (uint8_t *)(rc->data + rc->cursor);
  rc->cursor += token_bytes;

  // Retry Integrity Tag (last 16 bytes)
  memcpy(pkt->extra.retry.retry_integrity_tag, rc->data + rc->cursor, 16);

  // Retry consumes rest of datagram
  rc->cursor = rc->len;
}

static void _parse_pkt_1rtt(YAWT_Q_ReadCursor_t *rc, YAWT_Q_Packet_t *pkt) {
  if (rc->err != YAWT_Q_OK) return;
  if (rc->cursor >= rc->len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }

  size_t pkt_start = rc->cursor;

  uint8_t b0 = rc->data[rc->cursor++];
  uint8_t fixed_bit = (b0 >> 6) & 1;
  if (!fixed_bit) { rc->err = YAWT_Q_ERR_INVALID_PACKET; return; } // RFC 9000 §17.3.1
  pkt->extra.one_rtt.spin_bit = (b0 >> 5) & 1;
  pkt->reserved = (b0 >> 3) & 3;
  pkt->extra.one_rtt.key_phase = (b0 >> 2) & 1;
  pkt->packet_number_length = (b0 & 3) + 1; // still header-protected, unreliable until HP removal

  // RFC 9000 §17.3.1: DCID length not on wire — known from connection state (YAWT_Q_CID_LEN)
  if (rc->cursor + YAWT_Q_CID_LEN > rc->len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }
  pkt->dest_cid.len = YAWT_Q_CID_LEN;
  memcpy(pkt->dest_cid.id, rc->data + rc->cursor, YAWT_Q_CID_LEN);
  rc->cursor += YAWT_Q_CID_LEN;

  // 1-RTT is always last in datagram (RFC 9000 §12.2)
  _parse_common(rc, pkt, pkt_start, rc->len);
}

// --- Encode helpers (write into file-static _encode_buf) ---

static int _encode_long_header(const YAWT_Q_Packet_t *pkt, uint8_t long_packet_type,
                                uint8_t type_bits, size_t *cursor) {
  size_t c = *cursor;

  // Byte 0
  if (c + 1 > YAWT_Q_MAX_PKT_SIZE) return -1;
  _encode_buf[c++] = (1 << 7) | (1 << 6) |
                     (long_packet_type << 4) | (type_bits & 0x0f);

  // Version (4 bytes big-endian)
  if (c + 4 > YAWT_Q_MAX_PKT_SIZE) return -1;
  _encode_buf[c++] = (uint8_t)(pkt->version >> 24);
  _encode_buf[c++] = (uint8_t)(pkt->version >> 16);
  _encode_buf[c++] = (uint8_t)(pkt->version >> 8);
  _encode_buf[c++] = (uint8_t)(pkt->version);

  // DCID
  if (pkt->dest_cid.len > sizeof(pkt->dest_cid.id)) return -1;
  if (c + 1 + pkt->dest_cid.len > YAWT_Q_MAX_PKT_SIZE) return -1;
  _encode_buf[c++] = pkt->dest_cid.len;
  memcpy(_encode_buf + c, pkt->dest_cid.id, pkt->dest_cid.len);
  c += pkt->dest_cid.len;

  // SCID
  if (pkt->src_cid.len > sizeof(pkt->src_cid.id)) return -1;
  if (c + 1 + pkt->src_cid.len > YAWT_Q_MAX_PKT_SIZE) return -1;
  _encode_buf[c++] = pkt->src_cid.len;
  memcpy(_encode_buf + c, pkt->src_cid.id, pkt->src_cid.len);
  c += pkt->src_cid.len;

  *cursor = c;
  return 0;
}

static int _encode_pkt_initial(YAWT_Q_Packet_t *pkt, size_t *written) {
  size_t cursor = 0;
  int n;
  YAWT_Q_Error_t err;

  uint8_t type_bits = (pkt->reserved << 2) | ((pkt->packet_number_length - 1) & 3);
  if (_encode_long_header(pkt, YAWT_Q_PKT_INITIAL, type_bits, &cursor) < 0) return -1;

  // Token Length (varint)
  err = _varint_encode(pkt->extra.initial.token_len, _encode_buf + cursor,
                       YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return -1;
  cursor += n;

  // Token
  if (pkt->extra.initial.token_len > 0) {
    if (cursor + pkt->extra.initial.token_len > YAWT_Q_MAX_PKT_SIZE) return -1;
    memcpy(_encode_buf + cursor, pkt->extra.initial.token, pkt->extra.initial.token_len);
    cursor += pkt->extra.initial.token_len;
  }

  // Calculate PADDING needed for 1200-byte minimum datagram (RFC 9000 §14.1)
  // Assume 2-byte varint for Length (always correct when padding is applied)
  size_t base_total = cursor + 2 + pkt->packet_number_length + pkt->payload_len + 16;
  size_t padding_len = (base_total < 1200) ? (1200 - base_total) : 0;

  // Length (varint): pkt_num_len + payload_len + padding + 16 (AEAD tag)
  uint64_t wire_len = pkt->packet_number_length + pkt->payload_len + padding_len + 16;
  err = _varint_encode(wire_len, _encode_buf + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return -1;
  cursor += n;

  pkt->pn_offset = cursor;

  // Packet Number (big-endian)
  if (cursor + pkt->packet_number_length > YAWT_Q_MAX_PKT_SIZE) return -1;
  for (uint8_t i = 0; i < pkt->packet_number_length; i++) {
    _encode_buf[cursor + i] = (uint8_t)(pkt->packet_num >> (8 * (pkt->packet_number_length - 1 - i)));
  }
  cursor += pkt->packet_number_length;

  // Payload
  if (pkt->payload_len > 0) {
    if (cursor + pkt->payload_len > YAWT_Q_MAX_PKT_SIZE) return -1;
    memcpy(_encode_buf + cursor, pkt->payload, pkt->payload_len);
    cursor += pkt->payload_len;
  }

  // PADDING frames
  if (padding_len > 0) {
    int pad = YAWT_q_encode_frame_padding(_encode_buf + cursor,
                                           YAWT_Q_MAX_PKT_SIZE - cursor, padding_len);
    if (pad < 0) return -1;
    cursor += pad;
  }

  // AEAD tag space
  if (cursor + 16 > YAWT_Q_MAX_PKT_SIZE) return -1;
  memset(_encode_buf + cursor, 0, 16);
  cursor += 16;

  *written = cursor;
  return 0;
}

static int _encode_pkt_0rtt(YAWT_Q_Packet_t *pkt, size_t *written) {
  size_t cursor = 0;
  int n;
  YAWT_Q_Error_t err;

  uint8_t type_bits = (pkt->reserved << 2) | ((pkt->packet_number_length - 1) & 3);
  if (_encode_long_header(pkt, YAWT_Q_PKT_0RTT, type_bits, &cursor) < 0) return -1;

  // Length (varint): pkt_num_len + payload_len + 16 (AEAD tag)
  uint64_t wire_len = pkt->packet_number_length + pkt->payload_len + 16;
  err = _varint_encode(wire_len, _encode_buf + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return -1;
  cursor += n;

  pkt->pn_offset = cursor;

  // Packet Number (big-endian)
  if (cursor + pkt->packet_number_length > YAWT_Q_MAX_PKT_SIZE) return -1;
  for (uint8_t i = 0; i < pkt->packet_number_length; i++) {
    _encode_buf[cursor + i] = (uint8_t)(pkt->packet_num >> (8 * (pkt->packet_number_length - 1 - i)));
  }
  cursor += pkt->packet_number_length;

  // Payload + AEAD tag space
  if (cursor + pkt->payload_len + 16 > YAWT_Q_MAX_PKT_SIZE) return -1;
  if (pkt->payload_len > 0) {
    memcpy(_encode_buf + cursor, pkt->payload, pkt->payload_len);
    cursor += pkt->payload_len;
  }
  memset(_encode_buf + cursor, 0, 16);
  cursor += 16;

  *written = cursor;
  return 0;
}

static int _encode_pkt_handshake(YAWT_Q_Packet_t *pkt, size_t *written) {
  size_t cursor = 0;
  int n;
  YAWT_Q_Error_t err;

  uint8_t type_bits = (pkt->reserved << 2) | ((pkt->packet_number_length - 1) & 3);
  if (_encode_long_header(pkt, YAWT_Q_PKT_HANDSHAKE, type_bits, &cursor) < 0) return -1;

  // Length (varint): pkt_num_len + payload_len + 16 (AEAD tag)
  uint64_t wire_len = pkt->packet_number_length + pkt->payload_len + 16;
  err = _varint_encode(wire_len, _encode_buf + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return -1;
  cursor += n;

  pkt->pn_offset = cursor;

  // Packet Number (big-endian)
  if (cursor + pkt->packet_number_length > YAWT_Q_MAX_PKT_SIZE) return -1;
  for (uint8_t i = 0; i < pkt->packet_number_length; i++) {
    _encode_buf[cursor + i] = (uint8_t)(pkt->packet_num >> (8 * (pkt->packet_number_length - 1 - i)));
  }
  cursor += pkt->packet_number_length;

  // Payload + AEAD tag space
  if (cursor + pkt->payload_len + 16 > YAWT_Q_MAX_PKT_SIZE) return -1;
  if (pkt->payload_len > 0) {
    memcpy(_encode_buf + cursor, pkt->payload, pkt->payload_len);
    cursor += pkt->payload_len;
  }
  memset(_encode_buf + cursor, 0, 16);
  cursor += 16;

  *written = cursor;
  return 0;
}

static int _encode_pkt_retry(const YAWT_Q_Packet_t *pkt, size_t *written) {
  size_t cursor = 0;

  uint8_t type_bits = pkt->reserved & 0x0f;
  if (_encode_long_header(pkt, YAWT_Q_PKT_RETRY, type_bits, &cursor) < 0) return -1;

  // Token
  if (pkt->extra.retry.token_len > 0) {
    if (cursor + pkt->extra.retry.token_len > YAWT_Q_MAX_PKT_SIZE) return -1;
    memcpy(_encode_buf + cursor, pkt->extra.retry.token, pkt->extra.retry.token_len);
    cursor += pkt->extra.retry.token_len;
  }

  // Retry Integrity Tag (16 bytes)
  if (cursor + 16 > YAWT_Q_MAX_PKT_SIZE) return -1;
  memcpy(_encode_buf + cursor, pkt->extra.retry.retry_integrity_tag, 16);
  cursor += 16;

  *written = cursor;
  return 0;
}

static int _encode_pkt_1rtt(YAWT_Q_Packet_t *pkt, size_t *written) {
  size_t cursor = 0;

  // Byte 0
  if (cursor + 1 > YAWT_Q_MAX_PKT_SIZE) return -1;
  _encode_buf[cursor++] = (0 << 7) | (1 << 6) | (pkt->extra.one_rtt.spin_bit << 5) |
                           (pkt->reserved << 3) | (pkt->extra.one_rtt.key_phase << 2) |
                           ((pkt->packet_number_length - 1) & 3);

  // DCID
  if (cursor + pkt->dest_cid.len > YAWT_Q_MAX_PKT_SIZE) return -1;
  memcpy(_encode_buf + cursor, pkt->dest_cid.id, pkt->dest_cid.len);
  cursor += pkt->dest_cid.len;

  pkt->pn_offset = cursor;

  // Packet Number (big-endian)
  if (cursor + pkt->packet_number_length > YAWT_Q_MAX_PKT_SIZE) return -1;
  for (uint8_t i = 0; i < pkt->packet_number_length; i++) {
    _encode_buf[cursor + i] = (uint8_t)(pkt->packet_num >> (8 * (pkt->packet_number_length - 1 - i)));
  }
  cursor += pkt->packet_number_length;

  // Payload + AEAD tag space
  if (cursor + pkt->payload_len + 16 > YAWT_Q_MAX_PKT_SIZE) return -1;
  if (pkt->payload_len > 0) {
    memcpy(_encode_buf + cursor, pkt->payload, pkt->payload_len);
    cursor += pkt->payload_len;
  }
  memset(_encode_buf + cursor, 0, 16);
  cursor += 16;

  *written = cursor;
  return 0;
}

void YAWT_q_parse_frame(YAWT_Q_ReadCursor_t *rc, YAWT_Q_Packet_Type_t pkt_type,
                         YAWT_Q_Frame_t *out) {
  memset(out, 0, sizeof(*out));
  out->pkt_type = pkt_type;
  if (rc->err != YAWT_Q_OK || rc->cursor >= rc->len) return;

  uint64_t frame_type;
  _varint_decode(rc, &frame_type);
  if (rc->err != YAWT_Q_OK) return;
  out->type = (YAWT_Q_Frame_Type_t)frame_type;

  switch (frame_type) {
    case YAWT_Q_FRAME_PADDING:
    case YAWT_Q_FRAME_PING:
    case YAWT_Q_FRAME_HANDSHAKE_DONE:
      break;

    case YAWT_Q_FRAME_ACK:
      _varint_decode(rc, &out->ack.largest_ack);
      _varint_decode(rc, &out->ack.ack_delay);
      _varint_decode(rc, &out->ack.ack_range_count);
      _varint_decode(rc, &out->ack.first_ack_range);
      if (rc->err != YAWT_Q_OK) return;
      for (uint64_t i = 0; i < out->ack.ack_range_count; i++) {
        uint64_t gap, range_len;
        _varint_decode(rc, &gap);
        _varint_decode(rc, &range_len);
        if (rc->err != YAWT_Q_OK) return;
      }
      break;

    case YAWT_Q_FRAME_CRYPTO:
      _varint_decode(rc, &out->crypto.offset);
      _varint_decode(rc, &out->crypto.len);
      if (rc->err != YAWT_Q_OK) return;
      if (rc->cursor + out->crypto.len > rc->len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }
      out->crypto.data = (uint8_t *)(rc->data + rc->cursor);
      rc->cursor += out->crypto.len;
      break;

    case YAWT_Q_FRAME_CONNECTION_CLOSE:
      _varint_decode(rc, &out->connection_close.error_code);
      _varint_decode(rc, &out->connection_close.frame_type);
      _varint_decode(rc, &out->connection_close.reason_phrase_len);
      if (rc->err != YAWT_Q_OK) return;
      if (rc->cursor + out->connection_close.reason_phrase_len > rc->len) {
        rc->err = YAWT_Q_ERR_SHORT_BUFFER; return;
      }
      out->connection_close.reason_phrase = out->connection_close.reason_phrase_len > 0
        ? (uint8_t *)(rc->data + rc->cursor) : NULL;
      rc->cursor += out->connection_close.reason_phrase_len;
      break;

    case YAWT_Q_FRAME_NEW_CONNECTION_ID:
      _varint_decode(rc, &out->new_connection_id.seq_num);
      _varint_decode(rc, &out->new_connection_id.retire_prior_to);
      if (rc->err != YAWT_Q_OK) return;
      if (rc->cursor >= rc->len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }
      out->new_connection_id.cid.len = rc->data[rc->cursor++];
      if (out->new_connection_id.cid.len > 20 ||
          rc->cursor + out->new_connection_id.cid.len + 16 > rc->len) {
        rc->err = YAWT_Q_ERR_SHORT_BUFFER; return;
      }
      memcpy(out->new_connection_id.cid.id, rc->data + rc->cursor, out->new_connection_id.cid.len);
      rc->cursor += out->new_connection_id.cid.len;
      memcpy(out->new_connection_id.stateless_reset_token, rc->data + rc->cursor, 16);
      rc->cursor += 16;
      break;

    default:
      rc->err = YAWT_Q_ERR_INVALID_PACKET;
      break;
  }
}

int YAWT_q_encode_frame_padding(uint8_t *buf, size_t buf_len, size_t pad_len) {
  if (pad_len > buf_len) return -1;
  memset(buf, 0x00, pad_len);
  return (int)pad_len;
}

int YAWT_q_enqueue_frame_crypto(ANB_Slab_t *queue, uint8_t level,
                                const YAWT_Q_Frame_Crypto_t *frame) {
  YAWT_Q_WireFrame_t f;
  memset(&f, 0, sizeof(f));

  size_t cursor = 0;
  int n;
  YAWT_Q_Error_t err;

  // Frame type 0x06
  if (cursor + 1 > YAWT_Q_MAX_PKT_SIZE) return -1;
  f.wire_data[cursor++] = 0x06;

  // Offset (varint)
  err = _varint_encode(frame->offset, f.wire_data + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return -1;
  cursor += n;

  // Length (varint)
  err = _varint_encode(frame->len, f.wire_data + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return -1;
  cursor += n;

  // Data
  if (cursor + frame->len > YAWT_Q_MAX_PKT_SIZE) return -1;
  memcpy(f.wire_data + cursor, frame->data, frame->len);
  cursor += frame->len;

  f.type = YAWT_Q_FRAME_CRYPTO;
  f.level = level;
  f.wire_len = cursor;

  ANB_slab_push_item(queue, (const uint8_t *)&f, sizeof(f));

  return (int)cursor;
}

int YAWT_q_enqueue_frame_ack(ANB_Slab_t *queue, uint8_t level, uint64_t largest_ack) {
  YAWT_Q_WireFrame_t f;
  memset(&f, 0, sizeof(f));

  size_t cursor = 0;
  int n;
  YAWT_Q_Error_t err;

  // Frame type 0x02
  f.wire_data[cursor++] = 0x02;

  // Largest Acknowledged (varint)
  err = _varint_encode(largest_ack, f.wire_data + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return -1;
  cursor += n;

  // ACK Delay (varint) = 0
  f.wire_data[cursor++] = 0x00;

  // ACK Range Count (varint) = 0
  f.wire_data[cursor++] = 0x00;

  // First ACK Range = largest_ack (acknowledges packets [0..largest_ack])
  err = _varint_encode(largest_ack, f.wire_data + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return -1;
  cursor += n;

  f.type = YAWT_Q_FRAME_ACK;
  f.level = level;
  f.wire_len = cursor;

  ANB_slab_push_item(queue, (const uint8_t *)&f, sizeof(f));
  return (int)cursor;
}

int YAWT_q_encode_packet(YAWT_Q_Packet_t *pkt,
                          YAWT_Q_Crypto_t *crypto,
                          const uint8_t **out_buf) {
  size_t written = 0;
  int rc;

  switch (pkt->type) {
    case YAWT_Q_PKT_TYPE_INITIAL:
      rc = _encode_pkt_initial(pkt, &written);
      break;
    case YAWT_Q_PKT_TYPE_0RTT:
      rc = _encode_pkt_0rtt(pkt, &written);
      break;
    case YAWT_Q_PKT_TYPE_HANDSHAKE:
      rc = _encode_pkt_handshake(pkt, &written);
      break;
    case YAWT_Q_PKT_TYPE_RETRY:
      rc = _encode_pkt_retry(pkt, &written);
      break;
    case YAWT_Q_PKT_TYPE_1RTT:
      rc = _encode_pkt_1rtt(pkt, &written);
      break;
    default: return -1;
  }

  if (rc < 0) return rc;

  // Encrypt (not for Retry)
  if (pkt->type != YAWT_Q_PKT_TYPE_RETRY) {
    int ret = YAWT_q_crypto_protect_packet(_encode_buf, written, pkt, crypto);
    if (ret < 0) return ret;
  }

  *out_buf = _encode_buf;
  return (int)written;
}

void YAWT_q_parse_packet(YAWT_Q_ReadCursor_t *rc, YAWT_Q_Packet_t *out) {
  memset(out, 0, sizeof(*out));

  if (rc->cursor >= rc->len) {
    rc->err = YAWT_Q_ERR_SHORT_BUFFER;
    return;
  }

  out->raw = rc->data + rc->cursor;

  uint8_t b0 = rc->data[rc->cursor];
  uint8_t header_form = (b0 >> 7) & 1;

  if (header_form == 1) {
    // Long header
    uint8_t long_type = (b0 >> 4) & 3;
    switch (long_type) {
      case 0x00:
        out->type = YAWT_Q_PKT_TYPE_INITIAL;
        _parse_pkt_initial(rc, out);
        break;
      case 0x01:
        out->type = YAWT_Q_PKT_TYPE_0RTT;
        _parse_pkt_0rtt(rc, out);
        break;
      case 0x02:
        out->type = YAWT_Q_PKT_TYPE_HANDSHAKE;
        _parse_pkt_handshake(rc, out);
        break;
      case 0x03:
        out->type = YAWT_Q_PKT_TYPE_RETRY;
        _parse_pkt_retry(rc, out);
        break;
      default:
        rc->err = YAWT_Q_ERR_INVALID_PACKET;
        break;
    }
  } else {
    // Short header (1-RTT)
    out->type = YAWT_Q_PKT_TYPE_1RTT;
    _parse_pkt_1rtt(rc, out);
  }

  // pn_offset is set by _parse_common (not needed for Retry)
}
