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

// Parse the shared long header fields. Advances rc->cursor past consumed bytes.
// Does NOT parse byte 0's lower 4 bits.
static YAWT_Q_Long_Header_t _parse_long_header(YAWT_Q_ReadCursor_t *rc) {
  YAWT_Q_Long_Header_t hdr;
  memset(&hdr, 0, sizeof(hdr));
  if (rc->err != YAWT_Q_OK) return hdr;

  const uint8_t *in = rc->data;
  size_t len = rc->len;

  // Byte 0: header_form (bit 7), fixed_bit (bit 6), long_packet_type (bits 5-4)
  if (rc->cursor >= len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return hdr; }
  uint8_t b0 = in[rc->cursor];
  hdr.header_form = (b0 >> 7) & 1;
  hdr.fixed_bit = (b0 >> 6) & 1;
  if (!hdr.fixed_bit) { rc->err = YAWT_Q_ERR_INVALID_PACKET; return hdr; } // RFC 9000 §17.2
  hdr.long_packet_type = (b0 >> 4) & 3;
  rc->cursor++;

  // Version (4 bytes)
  if (rc->cursor + 4 > len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return hdr; }
  hdr.version = ((uint32_t)in[rc->cursor] << 24) |
                ((uint32_t)in[rc->cursor + 1] << 16) |
                ((uint32_t)in[rc->cursor + 2] << 8) |
                (uint32_t)in[rc->cursor + 3];
  rc->cursor += 4;

  // DCID Length (1 byte) + DCID
  if (rc->cursor >= len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return hdr; }
  hdr.dest_cid_len = in[rc->cursor];
  rc->cursor++;
  if (hdr.dest_cid_len > sizeof(hdr.dest_cid)) { rc->err = YAWT_Q_ERR_CID_TOO_LONG; return hdr; }
  if (rc->cursor + hdr.dest_cid_len > len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return hdr; }
  memcpy(hdr.dest_cid, in + rc->cursor, hdr.dest_cid_len);
  rc->cursor += hdr.dest_cid_len;

  // SCID Length (1 byte) + SCID
  if (rc->cursor >= len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return hdr; }
  hdr.src_cid_len = in[rc->cursor];
  rc->cursor++;
  if (hdr.src_cid_len > sizeof(hdr.src_cid)) { rc->err = YAWT_Q_ERR_CID_TOO_LONG; return hdr; }
  if (rc->cursor + hdr.src_cid_len > len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return hdr; }
  memcpy(hdr.src_cid, in + rc->cursor, hdr.src_cid_len);
  rc->cursor += hdr.src_cid_len;

  return hdr;
}

// Parse common PN + payload fields. cursor must be at the PN field.
// pkt_start is the absolute cursor of byte 0 for this packet.
// pkt_end is the absolute cursor of the byte after this packet.
static void _parse_common(YAWT_Q_ReadCursor_t *rc, YAWT_Q_Packet_Common_t *c,
                           size_t pkt_start, size_t pkt_end) {
  if (rc->err != YAWT_Q_OK) return;

  // Packet Number (variable length, 1-4 bytes)
  if (rc->cursor + c->packet_number_length > rc->len) {
    rc->err = YAWT_Q_ERR_SHORT_BUFFER;
    return;
  }
  c->packet_num = 0;
  for (uint8_t i = 0; i < c->packet_number_length; i++) {
    c->packet_num = (c->packet_num << 8) | rc->data[rc->cursor + i];
  }
  rc->cursor += c->packet_number_length;

  // Payload (zero-copy)
  c->payload = (rc->cursor < rc->len) ? (uint8_t *)(rc->data + rc->cursor) : NULL;
  c->payload_len = pkt_end - rc->cursor;

  // Advance cursor to next packet boundary
  rc->cursor = pkt_end;
}

static void _parse_pkt_initial(YAWT_Q_ReadCursor_t *rc, YAWT_Q_PKT_Initial_t *pkt) {
  memset(pkt, 0, sizeof(*pkt));
  if (rc->err != YAWT_Q_OK) return;

  size_t pkt_start = rc->cursor;
  pkt->header = _parse_long_header(rc);
  if (rc->err != YAWT_Q_OK) return;

  // Type-specific bits from byte 0: reserved (bits 3-2), pkt_num_len (bits 1-0)
  pkt->reserved = (rc->data[pkt_start] >> 2) & 3;
  pkt->common.packet_number_length = (rc->data[pkt_start] & 3) + 1;

  // Token Length (varint)
  _varint_decode(rc, &pkt->token_len);
  if (rc->err != YAWT_Q_OK) return;

  // Token (zero-copy pointer into input)
  if (rc->cursor + pkt->token_len > rc->len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }
  pkt->token = pkt->token_len > 0 ? (uint8_t *)(rc->data + rc->cursor) : NULL;
  rc->cursor += pkt->token_len;

  // Length (varint) — marks the packet boundary
  _varint_decode(rc, &pkt->len);
  if (rc->err != YAWT_Q_OK) return;
  size_t pkt_end = rc->cursor + pkt->len;

  _parse_common(rc, &pkt->common, pkt_start, pkt_end);
}

static void _parse_pkt_0rtt(YAWT_Q_ReadCursor_t *rc, YAWT_Q_PKT_0RTT_t *pkt) {
  memset(pkt, 0, sizeof(*pkt));
  if (rc->err != YAWT_Q_OK) return;

  size_t pkt_start = rc->cursor;
  pkt->header = _parse_long_header(rc);
  if (rc->err != YAWT_Q_OK) return;

  pkt->reserved = (rc->data[pkt_start] >> 2) & 3;
  pkt->common.packet_number_length = (rc->data[pkt_start] & 3) + 1;

  // Length (varint)
  _varint_decode(rc, &pkt->len);
  if (rc->err != YAWT_Q_OK) return;
  size_t pkt_end = rc->cursor + pkt->len;

  _parse_common(rc, &pkt->common, pkt_start, pkt_end);
}

static void _parse_pkt_handshake(YAWT_Q_ReadCursor_t *rc, YAWT_Q_PKT_Handshake_t *pkt) {
  memset(pkt, 0, sizeof(*pkt));
  if (rc->err != YAWT_Q_OK) return;

  size_t pkt_start = rc->cursor;
  pkt->header = _parse_long_header(rc);
  if (rc->err != YAWT_Q_OK) return;

  pkt->reserved = (rc->data[pkt_start] >> 2) & 3;
  pkt->common.packet_number_length = (rc->data[pkt_start] & 3) + 1;

  _varint_decode(rc, &pkt->len);
  if (rc->err != YAWT_Q_OK) return;
  size_t pkt_end = rc->cursor + pkt->len;

  _parse_common(rc, &pkt->common, pkt_start, pkt_end);
}

static void _parse_pkt_retry(YAWT_Q_ReadCursor_t *rc, YAWT_Q_PKT_Retry_t *pkt) {
  memset(pkt, 0, sizeof(*pkt));
  if (rc->err != YAWT_Q_OK) return;

  size_t pkt_start = rc->cursor;
  pkt->header = _parse_long_header(rc);
  if (rc->err != YAWT_Q_OK) return;

  pkt->unused = rc->data[pkt_start] & 0x0f;

  // Retry token = everything between header and last 16 bytes (integrity tag)
  if (rc->cursor + 16 > rc->len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }

  size_t token_bytes = rc->len - rc->cursor - 16;
  if (token_bytes == 0) { rc->err = YAWT_Q_ERR_INVALID_PACKET; return; } // RFC 9000 §17.2.5
  pkt->token_len = token_bytes;
  pkt->token = (uint8_t *)(rc->data + rc->cursor);
  rc->cursor += token_bytes;

  // Retry Integrity Tag (last 16 bytes)
  memcpy(pkt->retry_integrity_tag, rc->data + rc->cursor, 16);

  // Retry consumes rest of datagram
  rc->cursor = rc->len;
}

static void _parse_pkt_1rtt(YAWT_Q_ReadCursor_t *rc, YAWT_Q_PKT_1RTT_t *pkt) {
  memset(pkt, 0, sizeof(*pkt));
  if (rc->err != YAWT_Q_OK) return;

  if (rc->cursor >= rc->len) { rc->err = YAWT_Q_ERR_SHORT_BUFFER; return; }

  uint8_t b0 = rc->data[rc->cursor++];
  pkt->header_form = (b0 >> 7) & 1;
  pkt->fixed_bit = (b0 >> 6) & 1;
  if (!pkt->fixed_bit) { rc->err = YAWT_Q_ERR_INVALID_PACKET; return; } // RFC 9000 §17.3.1
  pkt->spin_bit = (b0 >> 5) & 1;
  pkt->reserved = (b0 >> 3) & 3;
  pkt->key_phase = (b0 >> 2) & 1;
  pkt->common.packet_number_length = (b0 & 3) + 1;

  // 1-RTT DCID length is not encoded on wire — it's known from connection state.
  // The caller must know the DCID length from the connection context.

  // Packet Number
  if (rc->cursor + pkt->common.packet_number_length > rc->len) {
    rc->err = YAWT_Q_ERR_SHORT_BUFFER;
    return;
  }
  pkt->common.packet_num = 0;
  for (uint8_t i = 0; i < pkt->common.packet_number_length; i++) {
    pkt->common.packet_num = (pkt->common.packet_num << 8) | rc->data[rc->cursor + i];
  }
  rc->cursor += pkt->common.packet_number_length;

  pkt->common.payload = (rc->cursor < rc->len) ? (uint8_t *)(rc->data + rc->cursor) : NULL;
  pkt->common.payload_len = rc->len - rc->cursor;

  // 1-RTT must be last in datagram
  rc->cursor = rc->len;
}

// --- Encode helpers ---

static YAWT_Q_Error_t _encode_long_header(const YAWT_Q_Long_Header_t *hdr,
                                           uint8_t type_bits,
                                           uint8_t *buf, size_t len,
                                           size_t *written) {
  size_t cursor = 0;

  // Byte 0
  if (cursor + 1 > len) return YAWT_Q_ERR_SHORT_BUFFER;
  buf[cursor++] = (1 << 7) | (hdr->fixed_bit << 6) |
                  (hdr->long_packet_type << 4) | (type_bits & 0x0f);

  // Version (4 bytes big-endian)
  if (cursor + 4 > len) return YAWT_Q_ERR_SHORT_BUFFER;
  buf[cursor++] = (uint8_t)(hdr->version >> 24);
  buf[cursor++] = (uint8_t)(hdr->version >> 16);
  buf[cursor++] = (uint8_t)(hdr->version >> 8);
  buf[cursor++] = (uint8_t)(hdr->version);

  // DCID
  if (hdr->dest_cid_len > sizeof(hdr->dest_cid)) return YAWT_Q_ERR_CID_TOO_LONG;
  if (cursor + 1 + hdr->dest_cid_len > len) return YAWT_Q_ERR_SHORT_BUFFER;
  buf[cursor++] = hdr->dest_cid_len;
  memcpy(buf + cursor, hdr->dest_cid, hdr->dest_cid_len);
  cursor += hdr->dest_cid_len;

  // SCID
  if (hdr->src_cid_len > sizeof(hdr->src_cid)) return YAWT_Q_ERR_CID_TOO_LONG;
  if (cursor + 1 + hdr->src_cid_len > len) return YAWT_Q_ERR_SHORT_BUFFER;
  buf[cursor++] = hdr->src_cid_len;
  memcpy(buf + cursor, hdr->src_cid, hdr->src_cid_len);
  cursor += hdr->src_cid_len;

  *written = cursor;
  return YAWT_Q_OK;
}

static YAWT_Q_Error_t _encode_pkt_initial(const YAWT_Q_PKT_Initial_t *pkt,
                                           uint8_t *buf, size_t len,
                                           size_t *written) {
  size_t cursor = 0;
  YAWT_Q_Error_t err;
  int n;

  uint8_t type_bits = (pkt->reserved << 2) | ((pkt->common.packet_number_length - 1) & 3);
  size_t hdr_written;
  err = _encode_long_header(&pkt->header, type_bits, buf, len, &hdr_written);
  if (err != YAWT_Q_OK) return err;
  cursor = hdr_written;

  // Token Length (varint)
  err = _varint_encode(pkt->token_len, buf + cursor, len - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  // Token
  if (pkt->token_len > 0) {
    if (cursor + pkt->token_len > len) return YAWT_Q_ERR_SHORT_BUFFER;
    memcpy(buf + cursor, pkt->token, pkt->token_len);
    cursor += pkt->token_len;
  }

  // Length (varint): pkt_num_len + payload_len
  uint64_t wire_len = pkt->common.packet_number_length + pkt->common.payload_len;
  err = _varint_encode(wire_len, buf + cursor, len - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  // Packet Number (big-endian)
  if (cursor + pkt->common.packet_number_length > len) return YAWT_Q_ERR_SHORT_BUFFER;
  for (uint8_t i = 0; i < pkt->common.packet_number_length; i++) {
    buf[cursor + i] = (uint8_t)(pkt->common.packet_num >> (8 * (pkt->common.packet_number_length - 1 - i)));
  }
  cursor += pkt->common.packet_number_length;

  // Payload
  if (pkt->common.payload_len > 0) {
    if (cursor + pkt->common.payload_len > len) return YAWT_Q_ERR_SHORT_BUFFER;
    memcpy(buf + cursor, pkt->common.payload, pkt->common.payload_len);
    cursor += pkt->common.payload_len;
  }

  *written = cursor;
  return YAWT_Q_OK;
}

static YAWT_Q_Error_t _encode_pkt_0rtt(const YAWT_Q_PKT_0RTT_t *pkt,
                                        uint8_t *buf, size_t len,
                                        size_t *written) {
  size_t cursor = 0;
  YAWT_Q_Error_t err;
  int n;

  uint8_t type_bits = (pkt->reserved << 2) | ((pkt->common.packet_number_length - 1) & 3);
  size_t hdr_written;
  err = _encode_long_header(&pkt->header, type_bits, buf, len, &hdr_written);
  if (err != YAWT_Q_OK) return err;
  cursor = hdr_written;

  // Length (varint): pkt_num_len + payload_len
  uint64_t wire_len = pkt->common.packet_number_length + pkt->common.payload_len;
  err = _varint_encode(wire_len, buf + cursor, len - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  // Packet Number (big-endian)
  if (cursor + pkt->common.packet_number_length > len) return YAWT_Q_ERR_SHORT_BUFFER;
  for (uint8_t i = 0; i < pkt->common.packet_number_length; i++) {
    buf[cursor + i] = (uint8_t)(pkt->common.packet_num >> (8 * (pkt->common.packet_number_length - 1 - i)));
  }
  cursor += pkt->common.packet_number_length;

  // Payload
  if (pkt->common.payload_len > 0) {
    if (cursor + pkt->common.payload_len > len) return YAWT_Q_ERR_SHORT_BUFFER;
    memcpy(buf + cursor, pkt->common.payload, pkt->common.payload_len);
    cursor += pkt->common.payload_len;
  }

  *written = cursor;
  return YAWT_Q_OK;
}

static YAWT_Q_Error_t _encode_pkt_handshake(const YAWT_Q_PKT_Handshake_t *pkt,
                                             uint8_t *buf, size_t len,
                                             size_t *written) {
  size_t cursor = 0;
  YAWT_Q_Error_t err;
  int n;

  uint8_t type_bits = (pkt->reserved << 2) | ((pkt->common.packet_number_length - 1) & 3);
  size_t hdr_written;
  err = _encode_long_header(&pkt->header, type_bits, buf, len, &hdr_written);
  if (err != YAWT_Q_OK) return err;
  cursor = hdr_written;

  // Length (varint): pkt_num_len + payload_len
  uint64_t wire_len = pkt->common.packet_number_length + pkt->common.payload_len;
  err = _varint_encode(wire_len, buf + cursor, len - cursor, &n);
  if (err != YAWT_Q_OK) return err;
  cursor += n;

  // Packet Number (big-endian)
  if (cursor + pkt->common.packet_number_length > len) return YAWT_Q_ERR_SHORT_BUFFER;
  for (uint8_t i = 0; i < pkt->common.packet_number_length; i++) {
    buf[cursor + i] = (uint8_t)(pkt->common.packet_num >> (8 * (pkt->common.packet_number_length - 1 - i)));
  }
  cursor += pkt->common.packet_number_length;

  // Payload
  if (pkt->common.payload_len > 0) {
    if (cursor + pkt->common.payload_len > len) return YAWT_Q_ERR_SHORT_BUFFER;
    memcpy(buf + cursor, pkt->common.payload, pkt->common.payload_len);
    cursor += pkt->common.payload_len;
  }

  *written = cursor;
  return YAWT_Q_OK;
}

static YAWT_Q_Error_t _encode_pkt_retry(const YAWT_Q_PKT_Retry_t *pkt,
                                         uint8_t *buf, size_t len,
                                         size_t *written) {
  size_t cursor = 0;
  YAWT_Q_Error_t err;

  uint8_t type_bits = pkt->unused & 0x0f;
  size_t hdr_written;
  err = _encode_long_header(&pkt->header, type_bits, buf, len, &hdr_written);
  if (err != YAWT_Q_OK) return err;
  cursor = hdr_written;

  // Token
  if (pkt->token_len > 0) {
    if (cursor + pkt->token_len > len) return YAWT_Q_ERR_SHORT_BUFFER;
    memcpy(buf + cursor, pkt->token, pkt->token_len);
    cursor += pkt->token_len;
  }

  // Retry Integrity Tag (16 bytes)
  if (cursor + 16 > len) return YAWT_Q_ERR_SHORT_BUFFER;
  memcpy(buf + cursor, pkt->retry_integrity_tag, 16);
  cursor += 16;

  *written = cursor;
  return YAWT_Q_OK;
}

static YAWT_Q_Error_t _encode_pkt_1rtt(const YAWT_Q_PKT_1RTT_t *pkt,
                                        uint8_t *buf, size_t len,
                                        size_t *written) {
  size_t cursor = 0;

  // Byte 0
  if (cursor + 1 > len) return YAWT_Q_ERR_SHORT_BUFFER;
  buf[cursor++] = (0 << 7) | (pkt->fixed_bit << 6) | (pkt->spin_bit << 5) |
                  (pkt->reserved << 3) | (pkt->key_phase << 2) |
                  ((pkt->common.packet_number_length - 1) & 3);

  // DCID (variable length, known from connection state)
  if (cursor + pkt->dest_cid_len > len) return YAWT_Q_ERR_SHORT_BUFFER;
  memcpy(buf + cursor, pkt->dest_cid, pkt->dest_cid_len);
  cursor += pkt->dest_cid_len;

  // Packet Number (big-endian)
  if (cursor + pkt->common.packet_number_length > len) return YAWT_Q_ERR_SHORT_BUFFER;
  for (uint8_t i = 0; i < pkt->common.packet_number_length; i++) {
    buf[cursor + i] = (uint8_t)(pkt->common.packet_num >> (8 * (pkt->common.packet_number_length - 1 - i)));
  }
  cursor += pkt->common.packet_number_length;

  // Payload
  if (pkt->common.payload_len > 0) {
    if (cursor + pkt->common.payload_len > len) return YAWT_Q_ERR_SHORT_BUFFER;
    memcpy(buf + cursor, pkt->common.payload, pkt->common.payload_len);
    cursor += pkt->common.payload_len;
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
  size_t pkt_start = rc->cursor;

  uint8_t b0 = rc->data[rc->cursor];
  uint8_t header_form = (b0 >> 7) & 1;

  if (header_form == 1) {
    // Long header
    uint8_t long_type = (b0 >> 4) & 3;
    switch (long_type) {
      case 0x00:
        out->type = YAWT_Q_PKT_TYPE_INITIAL;
        _parse_pkt_initial(rc, &out->pkt.initial);
        out->common = &out->pkt.initial.common;
        break;
      case 0x01:
        out->type = YAWT_Q_PKT_TYPE_0RTT;
        _parse_pkt_0rtt(rc, &out->pkt.zero_rtt);
        out->common = &out->pkt.zero_rtt.common;
        break;
      case 0x02:
        out->type = YAWT_Q_PKT_TYPE_HANDSHAKE;
        _parse_pkt_handshake(rc, &out->pkt.handshake);
        out->common = &out->pkt.handshake.common;
        break;
      case 0x03:
        out->type = YAWT_Q_PKT_TYPE_RETRY;
        _parse_pkt_retry(rc, &out->pkt.retry);
        // common stays NULL — Retry has no PN or encrypted payload
        break;
      default:
        rc->err = YAWT_Q_ERR_INVALID_PACKET;
        break;
    }
  } else {
    // Short header (1-RTT)
    out->type = YAWT_Q_PKT_TYPE_1RTT;
    _parse_pkt_1rtt(rc, &out->pkt.one_rtt);
    out->common = &out->pkt.one_rtt.common;
  }

  // Compute pn_offset from payload pointer (payload starts right after PN)
  if (out->common && out->common->payload) {
    out->pn_offset = (size_t)(out->common->payload - out->raw) - out->common->packet_number_length;
  }
}
