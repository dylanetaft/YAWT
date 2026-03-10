#include <string.h>
#include "quic.h"

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
  pkt->dest_cid_len = in[rc->cursor];
  rc->cursor++;
  if (pkt->dest_cid_len > sizeof(pkt->dest_cid)) { rc->err = YAWT_Q_ERR_CID_TOO_LONG; return; }
  if (rc->cursor + pkt->dest_cid_len > len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }
  memcpy(pkt->dest_cid, in + rc->cursor, pkt->dest_cid_len);
  rc->cursor += pkt->dest_cid_len;

  // SCID Length (1 byte) + SCID
  if (rc->cursor >= len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }
  pkt->src_cid_len = in[rc->cursor];
  rc->cursor++;
  if (pkt->src_cid_len > sizeof(pkt->src_cid)) { rc->err = YAWT_Q_ERR_CID_TOO_LONG; return; }
  if (rc->cursor + pkt->src_cid_len > len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }
  memcpy(pkt->src_cid, in + rc->cursor, pkt->src_cid_len);
  rc->cursor += pkt->src_cid_len;
}

// Parse common PN + payload fields. cursor must be at the PN field.
// pkt_start is the absolute cursor of byte 0 for this packet.
// pkt_end is the absolute cursor of the byte after this packet.
static void _parse_common(YAWT_Q_ReadCursor_t *rc, YAWT_Q_Packet_t *pkt,
                           size_t pkt_start, size_t pkt_end) {
  if (rc->err != YAWT_Q_OK) return;

  // Packet Number (variable length, 1-4 bytes)
  if (rc->cursor + pkt->packet_number_length > rc->len) {
    rc->err = YAWT_Q_ERR_SHORT_BUFFER;
    return;
  }
  pkt->packet_num = 0;
  for (uint8_t i = 0; i < pkt->packet_number_length; i++) {
    pkt->packet_num = (pkt->packet_num << 8) | rc->data[rc->cursor + i];
  }
  rc->cursor += pkt->packet_number_length;

  // Payload (zero-copy)
  pkt->payload = (rc->cursor < rc->len) ? (uint8_t *)(rc->data + rc->cursor) : NULL;
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

  uint8_t b0 = rc->data[rc->cursor++];
  uint8_t fixed_bit = (b0 >> 6) & 1;
  if (!fixed_bit) { rc->err = YAWT_Q_ERR_INVALID_PACKET; return; } // RFC 9000 §17.3.1
  pkt->extra.one_rtt.spin_bit = (b0 >> 5) & 1;
  pkt->reserved = (b0 >> 3) & 3;
  pkt->extra.one_rtt.key_phase = (b0 >> 2) & 1;
  pkt->packet_number_length = (b0 & 3) + 1;

  // 1-RTT DCID length is not encoded on wire — it's known from connection state.
  // The caller must know the DCID length from the connection context.

  // Packet Number
  if (rc->cursor + pkt->packet_number_length > rc->len) {
    rc->err = YAWT_Q_ERR_SHORT_BUFFER;
    return;
  }
  pkt->packet_num = 0;
  for (uint8_t i = 0; i < pkt->packet_number_length; i++) {
    pkt->packet_num = (pkt->packet_num << 8) | rc->data[rc->cursor + i];
  }
  rc->cursor += pkt->packet_number_length;

  pkt->payload = (rc->cursor < rc->len) ? (uint8_t *)(rc->data + rc->cursor) : NULL;
  pkt->payload_len = rc->len - rc->cursor;

  // 1-RTT must be last in datagram
  rc->cursor = rc->len;
}

// --- Encode helpers ---

static YAWT_Q_Error_t _encode_long_header(const YAWT_Q_Packet_t *pkt,
                                           uint8_t long_packet_type,
                                           uint8_t type_bits,
                                           uint8_t *buf, size_t len,
                                           size_t *written) {
  size_t cursor = 0;

  // Byte 0
  if (cursor + 1 > len) return YAWT_Q_ERR_SHORT_BUFFER;
  buf[cursor++] = (1 << 7) | (1 << 6) |
                  (long_packet_type << 4) | (type_bits & 0x0f);

  // Version (4 bytes big-endian)
  if (cursor + 4 > len) return YAWT_Q_ERR_SHORT_BUFFER;
  buf[cursor++] = (uint8_t)(pkt->version >> 24);
  buf[cursor++] = (uint8_t)(pkt->version >> 16);
  buf[cursor++] = (uint8_t)(pkt->version >> 8);
  buf[cursor++] = (uint8_t)(pkt->version);

  // DCID
  if (pkt->dest_cid_len > sizeof(pkt->dest_cid)) return YAWT_Q_ERR_CID_TOO_LONG;
  if (cursor + 1 + pkt->dest_cid_len > len) return YAWT_Q_ERR_SHORT_BUFFER;
  buf[cursor++] = pkt->dest_cid_len;
  memcpy(buf + cursor, pkt->dest_cid, pkt->dest_cid_len);
  cursor += pkt->dest_cid_len;

  // SCID
  if (pkt->src_cid_len > sizeof(pkt->src_cid)) return YAWT_Q_ERR_CID_TOO_LONG;
  if (cursor + 1 + pkt->src_cid_len > len) return YAWT_Q_ERR_SHORT_BUFFER;
  buf[cursor++] = pkt->src_cid_len;
  memcpy(buf + cursor, pkt->src_cid, pkt->src_cid_len);
  cursor += pkt->src_cid_len;

  *written = cursor;
  return YAWT_Q_OK;
}

static YAWT_Q_Error_t _encode_pkt_initial(const YAWT_Q_Packet_t *pkt,
                                           uint8_t *buf, size_t len,
                                           size_t *written) {
  size_t cursor = 0;
  YAWT_Q_Error_t err;
  int n;

  uint8_t type_bits = (pkt->reserved << 2) | ((pkt->packet_number_length - 1) & 3);
  size_t hdr_written;
  err = _encode_long_header(pkt, YAWT_Q_PKT_INITIAL, type_bits, buf, len, &hdr_written);
  if (err != YAWT_Q_OK) return err;
  cursor = hdr_written;

  // Token Length (varint)
  err = _varint_encode(pkt->extra.initial.token_len, buf + cursor, len - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  // Token
  if (pkt->extra.initial.token_len > 0) {
    if (cursor + pkt->extra.initial.token_len > len) return YAWT_Q_ERR_SHORT_BUFFER;
    memcpy(buf + cursor, pkt->extra.initial.token, pkt->extra.initial.token_len);
    cursor += pkt->extra.initial.token_len;
  }

  // Length (varint): pkt_num_len + payload_len
  uint64_t wire_len = pkt->packet_number_length + pkt->payload_len;
  err = _varint_encode(wire_len, buf + cursor, len - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  // Packet Number (big-endian)
  if (cursor + pkt->packet_number_length > len) return YAWT_Q_ERR_SHORT_BUFFER;
  for (uint8_t i = 0; i < pkt->packet_number_length; i++) {
    buf[cursor + i] = (uint8_t)(pkt->packet_num >> (8 * (pkt->packet_number_length - 1 - i)));
  }
  cursor += pkt->packet_number_length;

  // Payload
  if (pkt->payload_len > 0) {
    if (cursor + pkt->payload_len > len) return YAWT_Q_ERR_SHORT_BUFFER;
    memcpy(buf + cursor, pkt->payload, pkt->payload_len);
    cursor += pkt->payload_len;
  }

  *written = cursor;
  return YAWT_Q_OK;
}

static YAWT_Q_Error_t _encode_pkt_0rtt(const YAWT_Q_Packet_t *pkt,
                                        uint8_t *buf, size_t len,
                                        size_t *written) {
  size_t cursor = 0;
  YAWT_Q_Error_t err;
  int n;

  uint8_t type_bits = (pkt->reserved << 2) | ((pkt->packet_number_length - 1) & 3);
  size_t hdr_written;
  err = _encode_long_header(pkt, YAWT_Q_PKT_0RTT, type_bits, buf, len, &hdr_written);
  if (err != YAWT_Q_OK) return err;
  cursor = hdr_written;

  // Length (varint): pkt_num_len + payload_len
  uint64_t wire_len = pkt->packet_number_length + pkt->payload_len;
  err = _varint_encode(wire_len, buf + cursor, len - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  // Packet Number (big-endian)
  if (cursor + pkt->packet_number_length > len) return YAWT_Q_ERR_SHORT_BUFFER;
  for (uint8_t i = 0; i < pkt->packet_number_length; i++) {
    buf[cursor + i] = (uint8_t)(pkt->packet_num >> (8 * (pkt->packet_number_length - 1 - i)));
  }
  cursor += pkt->packet_number_length;

  // Payload
  if (pkt->payload_len > 0) {
    if (cursor + pkt->payload_len > len) return YAWT_Q_ERR_SHORT_BUFFER;
    memcpy(buf + cursor, pkt->payload, pkt->payload_len);
    cursor += pkt->payload_len;
  }

  *written = cursor;
  return YAWT_Q_OK;
}

static YAWT_Q_Error_t _encode_pkt_handshake(const YAWT_Q_Packet_t *pkt,
                                             uint8_t *buf, size_t len,
                                             size_t *written) {
  size_t cursor = 0;
  YAWT_Q_Error_t err;
  int n;

  uint8_t type_bits = (pkt->reserved << 2) | ((pkt->packet_number_length - 1) & 3);
  size_t hdr_written;
  err = _encode_long_header(pkt, YAWT_Q_PKT_HANDSHAKE, type_bits, buf, len, &hdr_written);
  if (err != YAWT_Q_OK) return err;
  cursor = hdr_written;

  // Length (varint): pkt_num_len + payload_len
  uint64_t wire_len = pkt->packet_number_length + pkt->payload_len;
  err = _varint_encode(wire_len, buf + cursor, len - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  // Packet Number (big-endian)
  if (cursor + pkt->packet_number_length > len) return YAWT_Q_ERR_SHORT_BUFFER;
  for (uint8_t i = 0; i < pkt->packet_number_length; i++) {
    buf[cursor + i] = (uint8_t)(pkt->packet_num >> (8 * (pkt->packet_number_length - 1 - i)));
  }
  cursor += pkt->packet_number_length;

  // Payload
  if (pkt->payload_len > 0) {
    if (cursor + pkt->payload_len > len) return YAWT_Q_ERR_SHORT_BUFFER;
    memcpy(buf + cursor, pkt->payload, pkt->payload_len);
    cursor += pkt->payload_len;
  }

  *written = cursor;
  return YAWT_Q_OK;
}

static YAWT_Q_Error_t _encode_pkt_retry(const YAWT_Q_Packet_t *pkt,
                                         uint8_t *buf, size_t len,
                                         size_t *written) {
  size_t cursor = 0;
  YAWT_Q_Error_t err;

  uint8_t type_bits = pkt->reserved & 0x0f;
  size_t hdr_written;
  err = _encode_long_header(pkt, YAWT_Q_PKT_RETRY, type_bits, buf, len, &hdr_written);
  if (err != YAWT_Q_OK) return err;
  cursor = hdr_written;

  // Token
  if (pkt->extra.retry.token_len > 0) {
    if (cursor + pkt->extra.retry.token_len > len) return YAWT_Q_ERR_SHORT_BUFFER;
    memcpy(buf + cursor, pkt->extra.retry.token, pkt->extra.retry.token_len);
    cursor += pkt->extra.retry.token_len;
  }

  // Retry Integrity Tag (16 bytes)
  if (cursor + 16 > len) return YAWT_Q_ERR_SHORT_BUFFER;
  memcpy(buf + cursor, pkt->extra.retry.retry_integrity_tag, 16);
  cursor += 16;

  *written = cursor;
  return YAWT_Q_OK;
}

static YAWT_Q_Error_t _encode_pkt_1rtt(const YAWT_Q_Packet_t *pkt,
                                        uint8_t *buf, size_t len,
                                        size_t *written) {
  size_t cursor = 0;

  // Byte 0
  if (cursor + 1 > len) return YAWT_Q_ERR_SHORT_BUFFER;
  buf[cursor++] = (0 << 7) | (1 << 6) | (pkt->extra.one_rtt.spin_bit << 5) |
                  (pkt->reserved << 3) | (pkt->extra.one_rtt.key_phase << 2) |
                  ((pkt->packet_number_length - 1) & 3);

  // DCID (variable length, known from connection state)
  if (cursor + pkt->dest_cid_len > len) return YAWT_Q_ERR_SHORT_BUFFER;
  memcpy(buf + cursor, pkt->dest_cid, pkt->dest_cid_len);
  cursor += pkt->dest_cid_len;

  // Packet Number (big-endian)
  if (cursor + pkt->packet_number_length > len) return YAWT_Q_ERR_SHORT_BUFFER;
  for (uint8_t i = 0; i < pkt->packet_number_length; i++) {
    buf[cursor + i] = (uint8_t)(pkt->packet_num >> (8 * (pkt->packet_number_length - 1 - i)));
  }
  cursor += pkt->packet_number_length;

  // Payload
  if (pkt->payload_len > 0) {
    if (cursor + pkt->payload_len > len) return YAWT_Q_ERR_SHORT_BUFFER;
    memcpy(buf + cursor, pkt->payload, pkt->payload_len);
    cursor += pkt->payload_len;
  }

  *written = cursor;
  return YAWT_Q_OK;
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

  // Compute pn_offset from payload pointer (payload starts right after PN)
  if (out->type != YAWT_Q_PKT_TYPE_RETRY && out->payload) {
    out->pn_offset = (size_t)(out->payload - out->raw) - out->packet_number_length;
  }
}
