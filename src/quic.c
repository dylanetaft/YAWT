#include <string.h>
#include "quic.h"
#include "quic_connection.h"
#include "crypt.h"
#include "corpus.h"
#include "impl/quic_types.h"

static uint8_t _encode_buf[YAWT_Q_MAX_PKT_SIZE];

void YAWT_q_varint_decode(YAWT_Q_ReadCursor_t *rc, uint64_t *out) {
  if (rc->err != YAWT_Q_OK) return;
  if (rc->cursor >= rc->len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }

  const uint8_t *buf = rc->data + rc->cursor;
  size_t remaining = rc->len - rc->cursor;

  uint8_t prefix = buf[0] >> 6;
  int vlen = 1 << prefix; // 1, 2, 4, or 8

  if ((size_t)vlen > remaining) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }

  if (out == NULL) { //parse only, skip value
    rc->cursor += vlen;
    return;
  }

  uint64_t val = buf[0] & 0x3f;
  for (int i = 1; i < vlen; i++) {
    val = (val << 8) | buf[i];
  }

  *out = val;
  rc->cursor += vlen;
}

YAWT_Err_t YAWT_q_varint_encode(uint64_t val, uint8_t *buf, size_t len,
                                     uint64_t *written) {
  uint64_t vlen;
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

size_t YAWT_q_varint_size(uint64_t val) {
  if (val <= 0x3f) return 1;
  if (val <= 0x3fff) return 2;
  if (val <= 0x3fffffff) return 4;
  if (val <= 0x3fffffffffffffff) return 8;
  return 0;
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
  pkt->reserved_zero = 1;
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
  YAWT_q_varint_decode(rc, &pkt->extra.initial.token_len);
  if (rc->err != YAWT_Q_OK) return;

  // Token (zero-copy pointer into input)
  if (rc->cursor + pkt->extra.initial.token_len > rc->len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }
  pkt->extra.initial.token = pkt->extra.initial.token_len > 0 ? (uint8_t *)(rc->data + rc->cursor) : NULL;
  rc->cursor += pkt->extra.initial.token_len;

  // Length (varint) — marks the packet boundary
  uint64_t wire_len;
  YAWT_q_varint_decode(rc, &wire_len);
  if (rc->err != YAWT_Q_OK) return;
  size_t pkt_end = rc->cursor + wire_len;
  YAWT_LOG(YAWT_LOG_DEBUG, "INITIAL PKT WIRE LEN =%lu, pkt_end=%zu", wire_len, pkt_end);

  _parse_common(rc, pkt, pkt_start, pkt_end);
}

static void _parse_pkt_0rtt(YAWT_Q_ReadCursor_t *rc, YAWT_Q_Packet_t *pkt) {
  if (rc->err != YAWT_Q_OK) return;

  size_t pkt_start = rc->cursor;
  _parse_long_header(rc, pkt);
  if (rc->err != YAWT_Q_OK) return;

  // Length (varint)
  uint64_t wire_len;
  YAWT_q_varint_decode(rc, &wire_len);
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
  YAWT_q_varint_decode(rc, &wire_len);
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
  pkt->reserved_zero = 1;
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
  uint64_t n;
  YAWT_Err_t err;

  uint8_t type_bits = (pkt->reserved << 2) | ((pkt->packet_number_length - 1) & 3);
  if (_encode_long_header(pkt, YAWT_Q_PKT_INITIAL, type_bits, &cursor) < 0) return -1;

  // Token Length (varint)
  err = YAWT_q_varint_encode(pkt->extra.initial.token_len, _encode_buf + cursor,
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
  err = YAWT_q_varint_encode(wire_len, _encode_buf + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
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
  uint64_t n;
  YAWT_Err_t err;

  uint8_t type_bits = (pkt->reserved << 2) | ((pkt->packet_number_length - 1) & 3);
  if (_encode_long_header(pkt, YAWT_Q_PKT_0RTT, type_bits, &cursor) < 0) return -1;

  // Length (varint): pkt_num_len + payload_len + 16 (AEAD tag)
  uint64_t wire_len = pkt->packet_number_length + pkt->payload_len + 16;
  err = YAWT_q_varint_encode(wire_len, _encode_buf + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
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
  uint64_t n;
  YAWT_Err_t err;

  uint8_t type_bits = (pkt->reserved << 2) | ((pkt->packet_number_length - 1) & 3);
  if (_encode_long_header(pkt, YAWT_Q_PKT_HANDSHAKE, type_bits, &cursor) < 0) return -1;

  // Length (varint): pkt_num_len + payload_len + 16 (AEAD tag)
  uint64_t wire_len = pkt->packet_number_length + pkt->payload_len + 16;
  err = YAWT_q_varint_encode(wire_len, _encode_buf + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
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
  YAWT_corpus_emit(2,
      rc->data + rc->cursor, rc->len - rc->cursor,
      &pkt_type, sizeof(YAWT_Q_Packet_Type_t));
  memset(out, 0, sizeof(*out));
  out->pkt_type = pkt_type;
  if (rc->err != YAWT_Q_OK || rc->cursor >= rc->len) return;

  uint64_t frame_type;
  YAWT_q_varint_decode(rc, &frame_type);
  if (rc->err != YAWT_Q_OK) return;
  out->type = (YAWT_Q_Frame_Type_t)frame_type;

  // DATAGRAM frames: 0x30 (no length) / 0x31 (with length) — RFC 9221
  if (frame_type == 0x30 || frame_type == 0x31) {
    out->type = YAWT_Q_FRAME_DATAGRAM;
    out->datagram.len_present = (frame_type & 0x01);
    if (out->datagram.len_present) {
      YAWT_q_varint_decode(rc, &out->datagram.len);
    } else {
      out->datagram.len = rc->len - rc->cursor;
    }
    if (rc->err != YAWT_Q_OK) return;
    if (rc->cursor + out->datagram.len > rc->len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }
    out->datagram.dataptr = rc->data + rc->cursor;
    rc->cursor += out->datagram.len;
    return;
  }

  // STREAM frames use type range 0x08-0x0f, low 3 bits: OFF(0x04) LEN(0x02) FIN(0x01)
  if (frame_type >= 0x08 && frame_type <= 0x0f) {
    out->type = YAWT_Q_FRAME_STREAM;
    uint8_t bits = (uint8_t)(frame_type & 0x07);
    out->stream.off = (bits & 0x04) ? 1 : 0;
    out->stream.len_present = (bits & 0x02) ? 1 : 0;
    out->stream.fin = (bits & 0x01) ? 1 : 0;
    YAWT_q_varint_decode(rc, &out->stream.stream_id);

    // c_bidi: 0x00, s_bidi: 0x01, c_uni: 0x02, s_uni: 0x03 
    out->stream.stream_type = (YAWT_Q_Stream_Type_t)(out->stream.stream_id & 0x03);
    
    if (out->stream.off) {
      YAWT_q_varint_decode(rc, &out->stream.offset);
    }
    if (out->stream.len_present) {
      YAWT_q_varint_decode(rc, &out->stream.data_len);
    } else {
      // No length field — data extends to end of packet
      out->stream.data_len = rc->len - rc->cursor;
    }
    if (rc->err != YAWT_Q_OK) return;
    if (rc->cursor + out->stream.data_len > rc->len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }
    out->stream.data = rc->data + rc->cursor;
    rc->cursor += out->stream.data_len;
    return;
  }

  switch (frame_type) {
    case YAWT_Q_FRAME_PADDING:
      while (rc->cursor < rc->len && rc->data[rc->cursor] == 0x00) {
        rc->cursor++;
      }
      YAWT_LOG(YAWT_LOG_DEBUG, "Parsed PADDING frame, len=%zu", rc->cursor);
      break;
    case YAWT_Q_FRAME_PING:
    case YAWT_Q_FRAME_HANDSHAKE_DONE:
      break;

    case YAWT_Q_FRAME_RESET_STREAM:
      YAWT_q_varint_decode(rc, &out->reset_stream.stream_id);
      YAWT_q_varint_decode(rc, &out->reset_stream.app_error_code);
      YAWT_q_varint_decode(rc, &out->reset_stream.final_size);
      break;

    case YAWT_Q_FRAME_STOP_SENDING:
      YAWT_q_varint_decode(rc, &out->stop_sending.stream_id);
      YAWT_q_varint_decode(rc, &out->stop_sending.app_error_code);
      break;

    case YAWT_Q_FRAME_ACK:
      YAWT_q_varint_decode(rc, &out->ack.largest_ack);
      YAWT_q_varint_decode(rc, &out->ack.ack_delay);
      YAWT_q_varint_decode(rc, &out->ack.ack_range_count);
      YAWT_q_varint_decode(rc, &out->ack.first_ack_range);
      if (rc->err != YAWT_Q_OK) return;
      size_t ranges_start = rc->cursor;
      // This is ensuring the packet is well formed
      for (uint64_t i = 0; i < out->ack.ack_range_count; i++) {
        YAWT_q_varint_decode(rc, NULL);
        YAWT_q_varint_decode(rc, NULL);
        if (rc->err != YAWT_Q_OK) return;
      }
      if (out->ack.ack_range_count > 0) {
        out->ack.ranges = (uint8_t *)(rc->data + ranges_start);
      }
      break;

    case YAWT_Q_FRAME_CRYPTO:
      YAWT_q_varint_decode(rc, &out->crypto.offset);
      YAWT_q_varint_decode(rc, &out->crypto.len);
      if (rc->err != YAWT_Q_OK) return;
      if (rc->cursor + out->crypto.len > rc->len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }
      out->crypto.data = (uint8_t *)(rc->data + rc->cursor);
      rc->cursor += out->crypto.len;
      break;

    case YAWT_Q_FRAME_CONNECTION_CLOSE:
      YAWT_q_varint_decode(rc, &out->connection_close.error_code);
      YAWT_q_varint_decode(rc, &out->connection_close.frame_type);
      YAWT_q_varint_decode(rc, &out->connection_close.reason_phrase_len);
      if (rc->err != YAWT_Q_OK) return;
      if (rc->cursor + out->connection_close.reason_phrase_len > rc->len) {
        rc->err = YAWT_Q_ERR_SHORT_BUFFER; return;
      }
      out->connection_close.reason_phrase = out->connection_close.reason_phrase_len > 0
        ? (uint8_t *)(rc->data + rc->cursor) : NULL;
      rc->cursor += out->connection_close.reason_phrase_len;
      break;

    case YAWT_Q_FRAME_CONNECTION_CLOSE_APP:
      YAWT_q_varint_decode(rc, &out->connection_close_app.error_code);
      YAWT_q_varint_decode(rc, &out->connection_close_app.reason_phrase_len);
      if (rc->err != YAWT_Q_OK) return;
      if (rc->cursor + out->connection_close_app.reason_phrase_len > rc->len) {
        rc->err = YAWT_Q_ERR_SHORT_BUFFER; return;
      }
      out->connection_close_app.reason_phrase = out->connection_close_app.reason_phrase_len > 0
        ? (uint8_t *)(rc->data + rc->cursor) : NULL;
      rc->cursor += out->connection_close_app.reason_phrase_len;
      break;

    case YAWT_Q_FRAME_NEW_CONNECTION_ID:
      YAWT_q_varint_decode(rc, &out->new_connection_id.seq_num);
      YAWT_q_varint_decode(rc, &out->new_connection_id.retire_prior_to);
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

    case YAWT_Q_FRAME_MAX_DATA:
      YAWT_q_varint_decode(rc, &out->max_data.max_data);
      break;

    case YAWT_Q_FRAME_MAX_STREAM_DATA:
      YAWT_q_varint_decode(rc, &out->max_stream_data.stream_id);
      YAWT_q_varint_decode(rc, &out->max_stream_data.max_stream_data);
      break;

    case YAWT_Q_FRAME_MAX_STREAMS_BIDI:
    case YAWT_Q_FRAME_MAX_STREAMS_UNI:
      YAWT_q_varint_decode(rc, &out->max_streams.max_streams);
      break;

    case YAWT_Q_FRAME_PATH_CHALLENGE:
      if (rc->cursor + 8 > rc->len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }
      memcpy(out->path_challenge.data, rc->data + rc->cursor, 8);
      rc->cursor += 8;
      break;

    case YAWT_Q_FRAME_PATH_RESPONSE:
      if (rc->cursor + 8 > rc->len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }
      memcpy(out->path_response.data, rc->data + rc->cursor, 8);
      rc->cursor += 8;
      break;

    case YAWT_Q_FRAME_DATA_BLOCKED:
      YAWT_q_varint_decode(rc, &out->data_blocked.max_data);
      break;

    case YAWT_Q_FRAME_STREAM_DATA_BLOCKED:
      YAWT_q_varint_decode(rc, &out->stream_data_blocked.stream_id);
      YAWT_q_varint_decode(rc, &out->stream_data_blocked.max_stream_data);
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

YAWT_Err_t YAWT_q_encode_frame_stream(const YAWT_Q_IoVec_t *iov, int iov_count,
                                             size_t iov_offset, size_t max_chunk_size,
                                             uint64_t stream_id, uint64_t initial_stream_offset,
                                             int set_fin,
                                             YAWT_Q_Frame_BufferedStream_t *out,
                                             size_t *out_iov_offset) {
  if (!iov && iov_count > 0) return YAWT_Q_ERR_INVALID_PARAM;
  if (iov_count < 0) return YAWT_Q_ERR_INVALID_PARAM;
  if (!out) return YAWT_Q_ERR_INVALID_PARAM;
  if (!out_iov_offset) return YAWT_Q_ERR_INVALID_PARAM;
  if (max_chunk_size > YAWT_Q_MAX_PKT_SIZE) return YAWT_Q_ERR_INVALID_PARAM;

  size_t total_len = 0;
  for (int i = 0; i < iov_count; i++) {
    if (iov[i].len > 0 && !iov[i].buf) return YAWT_Q_ERR_INVALID_PARAM;
    total_len += iov[i].len;
  }

  if (iov_offset > total_len) return YAWT_Q_ERR_INVALID_PARAM;

  size_t remaining = total_len - iov_offset;
  size_t chunk_len = (remaining < max_chunk_size) ? remaining : max_chunk_size;

  memset(out, 0, sizeof(*out));

  out->frame.stream_id = stream_id;

  // c_bidi: 0x00, s_bidi: 0x01, c_uni: 0x02, s_uni: 0x03 
  out->frame.stream_type = (YAWT_Q_Stream_Type_t)(stream_id & 0x03);
  uint64_t stream_offset = initial_stream_offset + iov_offset;
  out->frame.offset = stream_offset;
  out->frame.off = (stream_offset > 0) ? 1 : 0;
  out->frame.len_present = 1;
  out->frame.data_len = chunk_len;
  out->frame.fin = (set_fin && (iov_offset + chunk_len >= total_len)) ? 1 : 0;

  size_t dst_off = 0;
  size_t cur_iov_idx = 0;
  size_t cur_iov_off = 0;

  while (cur_iov_idx < iov_count && cur_iov_off + iov[cur_iov_idx].len <= iov_offset) {
    cur_iov_off += iov[cur_iov_idx].len;
    cur_iov_idx++;
  }

  if (cur_iov_idx < iov_count && cur_iov_off < iov_offset) {
    size_t skip = iov_offset - cur_iov_off;
    cur_iov_off += skip;
  }

  while (dst_off < chunk_len && cur_iov_idx < iov_count) {
    size_t avail = iov[cur_iov_idx].len - cur_iov_off;
    size_t need = chunk_len - dst_off;
    size_t copy = (avail < need) ? avail : need;
    memcpy(out->data + dst_off, iov[cur_iov_idx].buf + cur_iov_off, copy);
    dst_off += copy;
    cur_iov_off += copy;
    if (cur_iov_off >= iov[cur_iov_idx].len) {
      cur_iov_idx++;
      cur_iov_off = 0;
    }
  }

  out->frame.data = out->data;

  *out_iov_offset = iov_offset + chunk_len;

  return YAWT_Q_OK;
}

YAWT_Err_t YAWT_q_enqueue_frame_crypto(YAWT_Q_Context_t *con, uint8_t level,
                                             const YAWT_Q_Frame_Crypto_t *frame) {
  ANB_Slab_t *queue = con->tx_buffer;
  YAWT_Q_WireFrame_t f;
  memset(&f, 0, sizeof(f));

  size_t cursor = 0;
  uint64_t n;
  YAWT_Err_t err;

  // Frame type 0x06
  if (cursor + 1 > YAWT_Q_MAX_PKT_SIZE) return YAWT_Q_ERR_SHORT_BUFFER;
  f.wire_data[cursor++] = 0x06;

  // Offset (varint)
  err = YAWT_q_varint_encode(frame->offset, f.wire_data + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  // Length (varint)
  err = YAWT_q_varint_encode(frame->len, f.wire_data + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  // Data
  if (cursor + frame->len > YAWT_Q_MAX_PKT_SIZE) return YAWT_Q_ERR_SHORT_BUFFER;
  memcpy(f.wire_data + cursor, frame->data, frame->len);
  cursor += frame->len;

  f.type = YAWT_Q_FRAME_CRYPTO;
  f.level = level;
  f.wire_len = cursor;

  ANB_slab_push_item(queue, (const uint8_t *)&f, sizeof(f));

  return YAWT_Q_OK;
}

YAWT_Err_t YAWT_q_enqueue_frame_ack(YAWT_Q_Context_t *con, uint8_t level, uint64_t largest_ack) {
  ANB_Slab_t *queue = con->tx_buffer;
  YAWT_Q_WireFrame_t f;
  memset(&f, 0, sizeof(f));

  size_t cursor = 0;
  uint64_t n;
  YAWT_Err_t err;

  // Frame type 0x02
  f.wire_data[cursor++] = 0x02;

  // Largest Acknowledged (varint)
  err = YAWT_q_varint_encode(largest_ack, f.wire_data + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  // ACK Delay (varint) = 0
  f.wire_data[cursor++] = 0x00;

  // ACK Range Count (varint) = 0
  f.wire_data[cursor++] = 0x00;

  // First ACK Range = 0 (acknowledges 1 packet: just largest_ack)
  err = YAWT_q_varint_encode(0, f.wire_data + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  f.type = YAWT_Q_FRAME_ACK;
  f.level = level;
  f.wire_len = cursor;
  YAWT_LOG(YAWT_LOG_DEBUG, "Enqueue ACK frame: level:%i largest_ack=%llu", level, (unsigned long long)largest_ack);
  ANB_slab_push_item(queue, (const uint8_t *)&f, sizeof(f));
  return YAWT_Q_OK;
}

YAWT_Err_t YAWT_q_enqueue_frame_stream(YAWT_Q_Context_t *con,
                                             const YAWT_Q_Frame_BufferedStream_t *frame) {
  ANB_Slab_t *queue = con->tx_buffer;
  const YAWT_Q_Frame_Stream_t *f_in = &frame->frame;
  YAWT_Q_WireFrame_t f;
  memset(&f, 0, sizeof(f));

  size_t cursor = 0;
  uint64_t n;
  YAWT_Err_t err;

  // Type byte: 0x08 | OFF | LEN | FIN
  uint8_t type_byte = 0x08;
  if (f_in->off) type_byte |= 0x04;
  if (f_in->len_present) type_byte |= 0x02;
  if (f_in->fin) type_byte |= 0x01;
  if (cursor + 1 > YAWT_Q_MAX_PKT_SIZE) return YAWT_Q_ERR_SHORT_BUFFER;
  f.wire_data[cursor++] = type_byte;

  // Stream ID (varint)
  err = YAWT_q_varint_encode(f_in->stream_id, f.wire_data + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  // Offset (varint, if OFF bit set)
  if (f_in->off) {
    err = YAWT_q_varint_encode(f_in->offset, f.wire_data + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
    if (err != YAWT_Q_OK) return err;
    cursor += n;
  }

  // Length (varint, if LEN bit set)
  if (f_in->len_present) {
    err = YAWT_q_varint_encode(f_in->data_len, f.wire_data + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
    if (err != YAWT_Q_OK) return err;
    cursor += n;
  }

  // Data
  if (cursor + f_in->data_len > YAWT_Q_MAX_PKT_SIZE) return YAWT_Q_ERR_SHORT_BUFFER;
  memcpy(f.wire_data + cursor, frame->data, f_in->data_len);
  cursor += f_in->data_len;

  f.type = YAWT_Q_FRAME_STREAM;
  f.level = 3;  // YAWT_Q_LEVEL_APPLICATION — STREAM frames are 1-RTT only
  f.stream_id = f_in->stream_id;
  f.wire_len = cursor;

  ANB_slab_push_item(queue, (const uint8_t *)&f, sizeof(f));
  return YAWT_Q_OK;
}

YAWT_Err_t YAWT_q_enqueue_frame_ping(YAWT_Q_Context_t *con) {
  ANB_Slab_t *queue = con->tx_buffer;
  YAWT_Q_WireFrame_t f;
  memset(&f, 0, sizeof(f));

  f.wire_data[0] = 0x01;  // PING
  f.type = YAWT_Q_FRAME_PING;
  f.level = 3;  // APPLICATION level — 1-RTT only
  f.wire_len = 1;

  ANB_slab_push_item(queue, (const uint8_t *)&f, sizeof(f));
  return YAWT_Q_OK;
}

YAWT_Err_t YAWT_q_enqueue_frame_connection_close(YAWT_Q_Context_t *con, uint8_t level,
                                                      uint64_t error_code, uint64_t frame_type) {
  ANB_Slab_t *queue = con->tx_buffer;
  YAWT_Q_WireFrame_t f;
  memset(&f, 0, sizeof(f));

  size_t cursor = 0;
  uint64_t n;
  YAWT_Err_t err;

  // Frame type 0x1c
  f.wire_data[cursor++] = 0x1c;

  // Error code (varint)
  err = YAWT_q_varint_encode(error_code, f.wire_data + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  // Frame type that triggered the error (varint)
  err = YAWT_q_varint_encode(frame_type, f.wire_data + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  // Reason phrase length = 0 (varint)
  f.wire_data[cursor++] = 0x00;

  f.type = YAWT_Q_FRAME_CONNECTION_CLOSE;
  f.level = level;
  f.wire_len = cursor;

  ANB_slab_push_item(queue, (const uint8_t *)&f, sizeof(f));
  return YAWT_Q_OK;
}

YAWT_Err_t YAWT_q_enqueue_frame_path_response(YAWT_Q_Context_t *con, const uint8_t *data) {
  ANB_Slab_t *queue = con->tx_buffer;
  YAWT_Q_WireFrame_t f;
  memset(&f, 0, sizeof(f));

  f.wire_data[0] = 0x1b;  // PATH_RESPONSE
  memcpy(f.wire_data + 1, data, 8);

  f.type = YAWT_Q_FRAME_PATH_RESPONSE;
  f.level = 3;  // APPLICATION level — 1-RTT only
  f.wire_len = 9;

  ANB_slab_push_item(queue, (const uint8_t *)&f, sizeof(f));
  return YAWT_Q_OK;
}

YAWT_Err_t YAWT_q_enqueue_frame_datagram(YAWT_Q_Context_t *con,
                                               const uint8_t *data, size_t data_len) {
  ANB_Slab_t *queue = con->tx_buffer;
  YAWT_Q_WireFrame_t f;
  memset(&f, 0, sizeof(f));

  size_t cursor = 0;
  uint64_t n;
  YAWT_Err_t err;

  // Frame type 0x31 (DATAGRAM with length)
  if (cursor + 1 > YAWT_Q_MAX_PKT_SIZE) return YAWT_Q_ERR_SHORT_BUFFER;
  f.wire_data[cursor++] = 0x31;

  // Length (varint)
  err = YAWT_q_varint_encode(data_len, f.wire_data + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  // Data
  if (cursor + data_len > YAWT_Q_MAX_PKT_SIZE) return YAWT_Q_ERR_SHORT_BUFFER;
  memcpy(f.wire_data + cursor, data, data_len);
  cursor += data_len;

  f.type = YAWT_Q_FRAME_DATAGRAM;
  f.level = 3;  // YAWT_Q_LEVEL_APPLICATION — 1-RTT only
  f.wire_len = cursor;

  //check against peer's max datagram frame size (RFC 9221 §3)
  uint64_t max_p_size = con->peer_fc.max_datagram_frame_size;
  uint64_t max_size = (max_p_size > YAWT_Q_MAX_FRAME_PAYLOAD_SHORT) ? YAWT_Q_MAX_FRAME_PAYLOAD_SHORT : max_p_size;
  if (f.wire_len > max_size) return YAWT_Q_ERR_FRAME_TOO_LARGE;

  ANB_slab_push_item(queue, (const uint8_t *)&f, sizeof(f));
  return YAWT_Q_OK;
}

YAWT_Err_t YAWT_q_enqueue_frame_handshake_done(YAWT_Q_Context_t *con) {
  ANB_Slab_t *queue = con->tx_buffer;
  YAWT_Q_WireFrame_t f;
  memset(&f, 0, sizeof(f));

  f.wire_data[0] = 0x1e;  // HANDSHAKE_DONE
  f.type = YAWT_Q_FRAME_HANDSHAKE_DONE;
  f.level = YAWT_Q_LEVEL_APPLICATION;
  f.wire_len = 1;

  ANB_slab_push_item(queue, (const uint8_t *)&f, sizeof(f));
  return YAWT_Q_OK;
}

YAWT_Err_t YAWT_q_enqueue_frame_reset_stream(YAWT_Q_Context_t *con,
                                                   uint64_t stream_id,
                                                   uint64_t app_error_code,
                                                   uint64_t final_size) {
  ANB_Slab_t *queue = con->tx_buffer;
  YAWT_Q_WireFrame_t f;
  memset(&f, 0, sizeof(f));

  size_t cursor = 0;
  uint64_t n;
  YAWT_Err_t err;

  if (cursor + 1 > YAWT_Q_MAX_PKT_SIZE) return YAWT_Q_ERR_SHORT_BUFFER;
  f.wire_data[cursor++] = 0x04;  // RESET_STREAM

  err = YAWT_q_varint_encode(stream_id, f.wire_data + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  err = YAWT_q_varint_encode(app_error_code, f.wire_data + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  err = YAWT_q_varint_encode(final_size, f.wire_data + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  f.type = YAWT_Q_FRAME_RESET_STREAM;
  f.level = YAWT_Q_LEVEL_APPLICATION;
  f.stream_id = stream_id;
  f.wire_len = cursor;

  ANB_slab_push_item(queue, (const uint8_t *)&f, sizeof(f));
  return YAWT_Q_OK;
}

YAWT_Err_t YAWT_q_enqueue_frame_stop_sending(YAWT_Q_Context_t *con,
                                                   uint64_t stream_id,
                                                   uint64_t app_error_code) {
  ANB_Slab_t *queue = con->tx_buffer;
  YAWT_Q_WireFrame_t f;
  memset(&f, 0, sizeof(f));

  size_t cursor = 0;
  uint64_t n;
  YAWT_Err_t err;

  if (cursor + 1 > YAWT_Q_MAX_PKT_SIZE) return YAWT_Q_ERR_SHORT_BUFFER;
  f.wire_data[cursor++] = 0x05;  // STOP_SENDING

  err = YAWT_q_varint_encode(stream_id, f.wire_data + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  err = YAWT_q_varint_encode(app_error_code, f.wire_data + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  f.type = YAWT_Q_FRAME_STOP_SENDING;
  f.level = YAWT_Q_LEVEL_APPLICATION;
  f.stream_id = stream_id;
  f.wire_len = cursor;

  ANB_slab_push_item(queue, (const uint8_t *)&f, sizeof(f));
  return YAWT_Q_OK;
}

YAWT_Err_t YAWT_q_enqueue_frame_data_blocked(YAWT_Q_Context_t *con, uint64_t max_data) {
  ANB_Slab_t *queue = con->tx_buffer;
  YAWT_Q_WireFrame_t f;
  memset(&f, 0, sizeof(f));

  size_t cursor = 0;
  uint64_t n;
  YAWT_Err_t err;

  if (cursor + 1 > YAWT_Q_MAX_PKT_SIZE) return YAWT_Q_ERR_SHORT_BUFFER;
  f.wire_data[cursor++] = 0x14;  // DATA_BLOCKED

  err = YAWT_q_varint_encode(max_data, f.wire_data + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  f.type = YAWT_Q_FRAME_DATA_BLOCKED;
  f.level = YAWT_Q_LEVEL_APPLICATION;
  f.wire_len = cursor;

  ANB_slab_push_item(queue, (const uint8_t *)&f, sizeof(f));
  return YAWT_Q_OK;
}

YAWT_Err_t YAWT_q_enqueue_frame_max_data(YAWT_Q_Context_t *con, uint64_t max_data) {
  ANB_Slab_t *queue = con->tx_buffer;
  YAWT_Q_WireFrame_t f;
  memset(&f, 0, sizeof(f));

  size_t cursor = 0;
  uint64_t n;
  YAWT_Err_t err;

  if (cursor + 1 > YAWT_Q_MAX_PKT_SIZE) return YAWT_Q_ERR_SHORT_BUFFER;
  f.wire_data[cursor++] = 0x10;  // MAX_DATA

  err = YAWT_q_varint_encode(max_data, f.wire_data + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  f.type = YAWT_Q_FRAME_MAX_DATA;
  f.level = YAWT_Q_LEVEL_APPLICATION;
  f.wire_len = cursor;

  ANB_slab_push_item(queue, (const uint8_t *)&f, sizeof(f));
  return YAWT_Q_OK;
}

YAWT_Err_t YAWT_q_enqueue_frame_stream_data_blocked(YAWT_Q_Context_t *con,
                                                           uint64_t stream_id,
                                                           uint64_t max_stream_data) {
  ANB_Slab_t *queue = con->tx_buffer;
  YAWT_Q_WireFrame_t f;
  memset(&f, 0, sizeof(f));

  size_t cursor = 0;
  uint64_t n;
  YAWT_Err_t err;

  if (cursor + 1 > YAWT_Q_MAX_PKT_SIZE) return YAWT_Q_ERR_SHORT_BUFFER;
  f.wire_data[cursor++] = 0x15;  // STREAM_DATA_BLOCKED

  err = YAWT_q_varint_encode(stream_id, f.wire_data + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  err = YAWT_q_varint_encode(max_stream_data, f.wire_data + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  f.type = YAWT_Q_FRAME_STREAM_DATA_BLOCKED;
  f.level = YAWT_Q_LEVEL_APPLICATION;
  f.wire_len = cursor;

  ANB_slab_push_item(queue, (const uint8_t *)&f, sizeof(f));
  return YAWT_Q_OK;
}

YAWT_Err_t YAWT_q_enqueue_frame_max_stream_data(YAWT_Q_Context_t *con,
                                                       uint64_t stream_id,
                                                       uint64_t max_stream_data) {
  ANB_Slab_t *queue = con->tx_buffer;
  YAWT_Q_WireFrame_t f;
  memset(&f, 0, sizeof(f));

  size_t cursor = 0;
  uint64_t n;
  YAWT_Err_t err;

  if (cursor + 1 > YAWT_Q_MAX_PKT_SIZE) return YAWT_Q_ERR_SHORT_BUFFER;
  f.wire_data[cursor++] = 0x11;  // MAX_STREAM_DATA

  err = YAWT_q_varint_encode(stream_id, f.wire_data + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  err = YAWT_q_varint_encode(max_stream_data, f.wire_data + cursor, YAWT_Q_MAX_PKT_SIZE - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  f.type = YAWT_Q_FRAME_MAX_STREAM_DATA;
  f.level = YAWT_Q_LEVEL_APPLICATION;
  f.wire_len = cursor;

  ANB_slab_push_item(queue, (const uint8_t *)&f, sizeof(f));
  return YAWT_Q_OK;
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

   YAWT_LOG(YAWT_LOG_DEBUG, "encoding tx pkt type: %u payload: %s",
    pkt->type,
    YAWT_q_blob_to_hex(pkt->payload, pkt->payload_len));
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
  YAWT_corpus_emit(1,
      rc->data + rc->cursor, rc->len - rc->cursor);
  memset(out, 0, sizeof(*out));

  if (rc->cursor >= rc->len) {
    rc->err = YAWT_Q_ERR_SHORT_BUFFER;
    return;
  }

  out->raw = rc->data + rc->cursor;

  uint8_t b0 = rc->data[rc->cursor];
  uint8_t header_form = (b0 >> 7) & 1;

  if (header_form == 1) {
    // Long header. The 2-bit long-type field maps directly to the enum values
    // (RFC 9000 §17.2) — see YAWT_Q_PKT_TYPE_* in quic_types.h.
    uint8_t long_type = (b0 >> 4) & 3;
    out->type = (YAWT_Q_Packet_Type_t)long_type;
    switch (long_type) {
      case YAWT_Q_PKT_TYPE_INITIAL:   _parse_pkt_initial(rc, out);   break;
      case YAWT_Q_PKT_TYPE_0RTT:      _parse_pkt_0rtt(rc, out);      break;
      case YAWT_Q_PKT_TYPE_HANDSHAKE: _parse_pkt_handshake(rc, out); break;
      case YAWT_Q_PKT_TYPE_RETRY:     _parse_pkt_retry(rc, out);     break;
      default: rc->err = YAWT_Q_ERR_INVALID_PACKET; break;
    }
  } else {
    // Short header (1-RTT)
    out->type = YAWT_Q_PKT_TYPE_1RTT;
    _parse_pkt_1rtt(rc, out);
  }

  // pn_offset is set by _parse_common (not needed for Retry)
}
