#include "qpack.h"
#include "h3_types.h"
#include <string.h>
#include <stdlib.h>

// QPACK static table — RFC 9204 Appendix A, entries 0 through 98.
static const YAWT_QPACK_StaticEntry_t STATIC_TABLE[YAWT_QPACK_STATIC_TABLE_SIZE] = {
  { ":authority",                          "" },   //  0
  { ":path",                               "/" },   //  1
  { "age",                                 "0" },   //  2
  { "content-disposition",                 "" },   //  3
  { "content-length",                      "0" },   //  4
  { "cookie",                              "" },   //  5
  { "date",                                "" },   //  6
  { "etag",                                "" },   //  7
  { "if-modified-since",                   "" },   //  8
  { "if-none-match",                       "" },   //  9
  { "last-modified",                       "" },   // 10
  { "link",                                "" },   // 11
  { "location",                            "" },   // 12
  { "referer",                             "" },   // 13
  { "set-cookie",                          "" },   // 14
  { ":method",                             "CONNECT" },   // 15
  { ":method",                             "DELETE" },   // 16
  { ":method",                             "GET" },   // 17
  { ":method",                             "HEAD" },   // 18
  { ":method",                             "OPTIONS" },   // 19
  { ":method",                             "POST" },   // 20
  { ":method",                             "PUT" },   // 21
  { ":scheme",                             "http" },   // 22
  { ":scheme",                             "https" },   // 23
  { ":status",                             "103" },   // 24
  { ":status",                             "200" },   // 25
  { ":status",                             "304" },   // 26
  { ":status",                             "404" },   // 27
  { ":status",                             "503" },   // 28
  { "accept",                              "*/*" },   // 29
  { "accept",                              "application/dns-message" },   // 30
  { "accept-encoding",                     "gzip, deflate, br" },   // 31
  { "accept-ranges",                       "bytes" },   // 32
  { "access-control-allow-headers",        "cache-control" },   // 33
  { "access-control-allow-headers",        "content-type" },   // 34
  { "access-control-allow-origin",         "*" },   // 35
  { "cache-control",                       "max-age=0" },   // 36
  { "cache-control",                       "max-age=2592000" },   // 37
  { "cache-control",                       "max-age=604800" },   // 38
  { "cache-control",                       "no-cache" },   // 39
  { "cache-control",                       "no-store" },   // 40
  { "cache-control",                       "public, max-age=31536000" },   // 41
  { "content-encoding",                    "br" },   // 42
  { "content-encoding",                    "gzip" },   // 43
  { "content-type",                        "application/dns-message" },   // 44
  { "content-type",                        "application/javascript" },   // 45
  { "content-type",                        "application/json" },   // 46
  { "content-type",                        "application/x-www-form-urlencoded" },   // 47
  { "content-type",                        "image/gif" },   // 48
  { "content-type",                        "image/jpeg" },   // 49
  { "content-type",                        "image/png" },   // 50
  { "content-type",                        "text/css" },   // 51
  { "content-type",                        "text/html; charset=utf-8" },   // 52
  { "content-type",                        "text/plain" },   // 53
  { "content-type",                        "text/plain;charset=utf-8" },   // 54
  { "range",                               "bytes=0-" },   // 55
  { "strict-transport-security",           "max-age=31536000" },   // 56
  { "strict-transport-security",           "max-age=31536000; includesubdomains" },   // 57
  { "strict-transport-security",           "max-age=31536000; includesubdomains; preload" },   // 58
  { "vary",                                "accept-encoding" },   // 59
  { "vary",                                "origin" },   // 60
  { "x-content-type-options",              "nosniff" },   // 61
  { "x-xss-protection",                    "1; mode=block" },   // 62
  { ":status",                             "100" },   // 63
  { ":status",                             "204" },   // 64
  { ":status",                             "206" },   // 65
  { ":status",                             "302" },   // 66
  { ":status",                             "400" },   // 67
  { ":status",                             "403" },   // 68
  { ":status",                             "421" },   // 69
  { ":status",                             "425" },   // 70
  { ":status",                             "500" },   // 71
  { "accept-language",                     "" },   // 72
  { "access-control-allow-credentials",    "FALSE" },   // 73
  { "access-control-allow-credentials",    "TRUE" },   // 74
  { "access-control-allow-headers",        "*" },   // 75
  { "access-control-allow-methods",        "get" },   // 76
  { "access-control-allow-methods",        "get, post, options" },   // 77
  { "access-control-allow-methods",        "options" },   // 78
  { "access-control-expose-headers",       "content-length" },   // 79
  { "access-control-request-headers",      "content-type" },   // 80
  { "access-control-request-method",       "get" },   // 81
  { "access-control-request-method",       "post" },   // 82
  { "alt-svc",                             "clear" },   // 83
  { "authorization",                       "" },   // 84
  { "content-security-policy",             "script-src 'none'; object-src 'none'; base-uri 'none'" },   // 85
  { "early-data",                          "1" },   // 86
  { "expect-ct",                           "" },   // 87
  { "forwarded",                           "" },   // 88
  { "if-range",                            "" },   // 89
  { "origin",                              "" },   // 90
  { "purpose",                             "prefetch" },   // 91
  { "server",                              "" },   // 92
  { "timing-allow-origin",                 "*" },   // 93
  { "upgrade-insecure-requests",           "1" },   // 94
  { "user-agent",                          "" },   // 95
  { "x-forwarded-for",                     "" },   // 96
  { "x-frame-options",                     "deny" },   // 97
  { "x-frame-options",                     "sameorigin" },   // 98
};

const YAWT_QPACK_StaticEntry_t *YAWT_qpack_static_get(uint64_t index) {
  if (index >= YAWT_QPACK_STATIC_TABLE_SIZE) return NULL;
  return &STATIC_TABLE[index];
}

int YAWT_qpack_static_find_name(const char *name) {
  for (int i = 0; i < YAWT_QPACK_STATIC_TABLE_SIZE; i++) {
    if (strcmp(STATIC_TABLE[i].name, name) == 0) {
      return i;
    }
  }
  return -1;
}

int YAWT_qpack_static_find_entry(const char *name, const char *value) {
  for (int i = 0; i < YAWT_QPACK_STATIC_TABLE_SIZE; i++) {
    if (strcmp(STATIC_TABLE[i].name, name) == 0 &&
        strcmp(STATIC_TABLE[i].value, value) == 0) {
      return i;
    }
  }
  return -1;
}

// ---------------------------------------------------------------------------
// Huffman decode — RFC 7541 Appendix B / RFC 9204 §5.1
// Minimal state-machine decoder; no large tables.
// ---------------------------------------------------------------------------

// Canonical Huffman codes for bytes 0–255 (from RFC 7541 Appendix B).
// Each entry: { code, bit_length }
static const struct { uint32_t code; uint8_t bits; } HUFFMAN_TABLE[256] = {
  {0x1ff8, 13}, {0x7fffd8, 24}, {0xfffffe2, 28}, {0xfffffe3, 28},
  {0xfffffe4, 28}, {0xfffffe5, 28}, {0xfffffe6, 28}, {0xfffffe7, 28},
  {0xfffffe8, 28}, {0xffffea, 24}, {0x3ffffffc, 30}, {0xfffffe9, 28},
  {0xfffffea, 28}, {0x3ffffffd, 30}, {0xfffffeb, 28}, {0xfffffec, 28},
  {0xfffffed, 28}, {0xfffffee, 28}, {0xfffffef, 28}, {0xffffff0, 28},
  {0xffffff1, 28}, {0xffffff2, 28}, {0x3ffffffe, 30}, {0xffffff3, 28},
  {0xffffff4, 28}, {0xffffff5, 28}, {0xffffff6, 28}, {0xffffff7, 28},
  {0xffffff8, 28}, {0xffffff9, 28}, {0xffffffa, 28}, {0xffffffb, 28},
  {0x14, 6},      {0x3f8, 10},    {0x3f9, 10},    {0xffa, 12},
  {0x1ff9, 13},   {0x15, 6},      {0xf8, 8},      {0x7fa, 11},
  {0x3fa, 10},    {0x3fb, 10},    {0xf9, 8},      {0x7fb, 11},
  {0xfa, 8},      {0x16, 6},      {0x17, 6},      {0x18, 6},
  {0x0, 5},       {0x1, 5},       {0x2, 5},       {0x19, 6},
  {0x1a, 6},      {0x1b, 6},      {0x1c, 6},      {0x1d, 6},
  {0x1e, 6},      {0x1f, 6},      {0x5c, 7},      {0xfb, 8},
  {0x7ffc, 15},   {0x20, 6},      {0xffb, 12},    {0x3fc, 10},
  {0x1ffa, 13},   {0x21, 6},      {0x5d, 7},      {0x5e, 7},
  {0x5f, 7},      {0x60, 7},      {0x61, 7},      {0x62, 7},
  {0x63, 7},      {0x64, 7},      {0x65, 7},      {0x66, 7},
  {0x67, 7},      {0x68, 7},      {0x69, 7},      {0x6a, 7},
  {0x6b, 7},      {0x6c, 7},      {0x6d, 7},      {0x6e, 7},
  {0x6f, 7},      {0x70, 7},      {0x71, 7},      {0x72, 7},
  {0xfc, 8},      {0x73, 7},      {0xfd, 8},      {0x1ffb, 13},
  {0x7fff0, 19},  {0x1ffc, 13},   {0x3ffc, 14},   {0x22, 6},
  {0x7ffd, 15},   {0x3, 5},       {0x23, 6},      {0x4, 5},
  {0x24, 6},      {0x5, 5},       {0x25, 6},      {0x26, 6},
  {0x27, 6},      {0x6, 5},       {0x74, 7},      {0x75, 7},
  {0x28, 6},      {0x29, 6},      {0x2a, 6},      {0x7, 5},
  {0x2b, 6},      {0x76, 7},      {0x2c, 6},      {0x8, 5},
  {0x9, 5},       {0x2d, 6},      {0x77, 7},      {0x78, 7},
  {0x79, 7},      {0x7a, 7},      {0x7b, 7},      {0x7ffff0, 23},
  {0x7ffff1, 23}, {0x3ffd, 14},   {0x1ffd, 13},   {0xffffffc, 28},
  {0xfffe6, 20},  {0x3fffd2, 22}, {0xfffe7, 20},  {0xfffe8, 20},
  {0x3fffd3, 22}, {0x3fffd4, 22}, {0x3fffd5, 22}, {0x7fffd9, 24},
  {0x3fffd6, 22}, {0x7fffda, 24}, {0x7fffdb, 24}, {0x7fffdc, 24},
  {0x7fffdd, 24}, {0x7fffde, 24}, {0xffffeb, 24}, {0x7fffdf, 24},
  {0xffffec, 24}, {0xffffed, 24}, {0x3fffd7, 22}, {0x7fffe0, 24},
  {0xffffee, 24}, {0x7fffe1, 24}, {0x7fffe2, 24}, {0x7fffe3, 24},
  {0x7fffe4, 24}, {0x1fffdc, 21}, {0x3fffd8, 22}, {0x7fffe5, 24},
  {0x3fffd9, 22}, {0x7fffe6, 24}, {0x7fffe7, 24}, {0xffffef, 24},
  {0x3fffda, 22}, {0x1fffdd, 21}, {0xfffe9, 20},  {0x3fffdb, 22},
  {0x3fffdc, 22}, {0x7fffe8, 24}, {0x7fffe9, 24}, {0x1fffde, 21},
  {0x7fffea, 24}, {0x3fffdd, 22}, {0x3fffde, 22}, {0xfffff0, 24},
  {0x1fffdf, 21}, {0x3fffdf, 22}, {0x7fffeb, 24}, {0x7fffec, 24},
  {0x1fffe0, 21}, {0x1fffe1, 21}, {0x3fffe0, 22}, {0x1fffe2, 21},
  {0x7fffed, 24}, {0x3fffe1, 22}, {0x7fffee, 24}, {0x7fffef, 24},
  {0xfffea, 20},  {0x3fffe2, 22}, {0x3fffe3, 22}, {0x3fffe4, 22},
  {0x7ffff2, 23}, {0x3fffe5, 22}, {0x3fffe6, 22}, {0x7ffff3, 23},
  {0x3fffe7, 22}, {0x7ffff4, 23}, {0x3fffe8, 22}, {0xfffff1, 24},
  {0x3fffe9, 22}, {0xfffff2, 24}, {0x7ffff5, 23}, {0x3fffea, 22},
  {0x3fffeb, 22}, {0x1ffffec, 25}, {0x1ffffed, 25}, {0x7ffff6, 23},
  {0x3fffec, 22}, {0x3fffed, 22}, {0x7ffff7, 23}, {0x3fffee, 22},
  {0x7ffff8, 23}, {0x7ffff9, 23}, {0x1ffffee, 25}, {0x1ffffef, 25},
  {0xfffff3, 24}, {0xfffff4, 24}, {0xfffff5, 24}, {0x3fffff0, 26},
  {0x1fffff0, 25}, {0x1fffff1, 25}, {0x3fffff1, 26}, {0x7ffffc, 23},
  {0x3fffff2, 26}, {0x7ffffd, 23}, {0x3fffff3, 26}, {0x3fffff4, 26},
  {0x3fffff5, 26}, {0x3fffff6, 26}, {0x3fffff7, 26}, {0x3fffff8, 26},
  {0x7fffffe, 27}, {0x7fffffff, 31}, {0x3fffff9, 26}, {0x3fffffa, 26},
  {0x3fffffb, 26}, {0x3fffffc, 26}, {0x3fffffd, 26}, {0x3fffffe, 26},
  {0x3ffffff, 26},
};

// EOS symbol code (used for padding at end of Huffman-encoded string)
#define HUFFMAN_EOS_CODE 0x3fffffc
#define HUFFMAN_EOS_BITS 26


inline uint8_t _int_prefix_bits_needed(uint64_t val)
{
    //hpack integer encoding writes '1's as a prefix
    //up to the size of what size integer is being encoded
    
    uint8_t n = 0;
    uint64_t limit = 1;
    while (limit - 1 <= val) {   // while (2^n - 1) <= val
        if (n == 64) break;
        limit <<= 1;
        n++;
    }
    return n;
}

YAWT_H3_QPACK_EncoderInstructionType_t YAWT_H3_QPACK_decode_encoder_instruction_prefix(uint8_t byte) {
    // Check for '1' prefix (Insert with Name Reference)
    // Bit 7 is 1
    if ((byte & 0x80) == 0x80) {
        return INSERT_WITH_NAME_REF;
    }

    // Check for '001' prefix (Set Dynamic Table Capacity)
    // Bits 7,6 are 0, Bit 5 is 1
    if ((byte & 0xE0) == 0x20) {
        return SET_CAPACITY;
    }

    // Check for '01' prefix (Insert with Literal Name)
    // Bit 7 is 0, Bit 6 is 1
    if ((byte & 0x60) == 0x40) { // Mask 0x60 covers bits 7 and 6. Expected 0x40 means bit 6=1, bit 7=0.
        return INSERT_WITH_LITERAL_NAME;
    }

    // Check for '000' prefix (Duplicate)
    // Bits 7,6,5 are 0
    if ((byte & 0xE0) == 0x00) {
        return DUPLICATE;
    }

    return UNKNOWN;
}

// ---------------------------------------------------------------------------
// QPACK field line representation decoder — RFC 9204 §4.5
// ---------------------------------------------------------------------------

YAWT_QPACK_FieldLineRepType_t YAWT_H3_QPACK_decode_field_line_msb(uint8_t byte, uint8_t *out_prefix_bits) {
    // §4.5.2 — Indexed Field Line
    //   Binary: 1 x x x x x x x
    //   Mask:   1 0 0 0 0 0 0 0 = 0x80
    //   Expected: 1 0 0 0 0 0 0 0 = 0x80
    //   Prefix bits consumed by dispatcher: 1
    if ((byte & 0x80) == 0x80) {
        *out_prefix_bits = 1;
        return YAWT_QPACK_FIELD_LINE_INDEXED;
    }

    // §4.5.6 — Literal Field Line with Literal Name
    //   Binary: 0 0 1 x x x x x
    //   Mask:   1 1 1 0 0 0 0 0 = 0xE0
    //   Expected: 0 0 1 0 0 0 0 0 = 0x20
    //   Prefix bits consumed by dispatcher: 3
    if ((byte & 0xE0) == 0x20) {
        *out_prefix_bits = 3;
        return YAWT_QPACK_FIELD_LINE_LITERAL_LITERAL_NAME;
    }

    // §4.5.4 — Literal Field Line with Name Reference
    //   Binary: 0 1 x x x x x x
    //   Mask:   1 1 0 0 0 0 0 0 = 0xC0
    //   Expected: 0 1 0 0 0 0 0 0 = 0x40
    //   Prefix bits consumed by dispatcher: 2
    if ((byte & 0xC0) == 0x40) {
        *out_prefix_bits = 2;
        return YAWT_QPACK_FIELD_LINE_LITERAL_NAME_REF;
    }

    // §4.5.5 — Literal Field Line with Post-Base Name Reference
    //   Binary: 0 0 0 0 x x x x
    //   Mask:   1 1 1 1 0 0 0 0 = 0xF0
    //   Expected: 0 0 0 0 0 0 0 0 = 0x00
    //   Prefix bits consumed by dispatcher: 4
    if ((byte & 0xF0) == 0x00) {
        *out_prefix_bits = 4;
        return YAWT_QPACK_FIELD_LINE_LITERAL_POST_BASE_NAME_REF;
    }

    // §4.5.3 — Indexed Field Line with Post-Base Index
    //   Binary: 0 0 0 1 x x x x
    //   Mask:   1 1 1 1 0 0 0 0 = 0xF0
    //   Expected: 0 0 0 1 0 0 0 0 = 0x10
    //   Prefix bits consumed by dispatcher: 4
    if ((byte & 0xF0) == 0x10) {
        *out_prefix_bits = 4;
        return YAWT_QPACK_FIELD_LINE_INDEXED_POST_BASE;
    }

    *out_prefix_bits = 0;
    return YAWT_QPACK_FIELD_LINE_UNKNOWN;
}

// ---------------------------------------------------------------------------
// QPACK prefixed integer — RFC 7541 §5.1 / RFC 9204 §4.1.1
// ---------------------------------------------------------------------------

// Decode a prefixed integer starting at `buffer` + `offset_bits`.
// The prefix size N is always 8 - offset_bits; the prefix fills the
// remainder of the starting byte. Continuation octets are full bytes.
//
// RFC 7541 §5.1:
//   "If the integer value is small enough, i.e. strictly less than
//    2^N - 1, it is encoded within the N-bit prefix."
//
//   "Otherwise, all the bits of the prefix are set to 1, and the
//    value, decreased by 2^N-1, is encoded using a list of one or
//    more octets. The most significant bit of each octet is used as
//    a continuation flag: its value is set to 1 except for the last
//    octet in the list."
//
// Continuation octets are always byte-aligned (full bytes).
YAWT_QPACK_Error_t YAWT_H3_QPACK_decode_prefix_int(
    const uint8_t *buffer, size_t buffer_size,
    uint8_t offset_bits,
    uint64_t *out_value, uint64_t *bits_parsed)
{
    if (offset_bits >= 8) return YAWT_QPACK_ERR_INVALID_PARAM;

    uint8_t N          = 8 - offset_bits;
    uint8_t max_val    = (1U << N) - 1;

    // Extract N-bit prefix: lower N bits hold the value.
    uint64_t prefix    = buffer[0] & max_val;
    *bits_parsed       = N;

    // RFC 7541 §5.1: value < 2^N - 1 → prefix holds the value.
    if (prefix < max_val) {
        *out_value = prefix;
        return YAWT_QPACK_OK;
    }

    // Prefix all 1s → at least one continuation byte is required.
    if (buffer_size < 2) return YAWT_QPACK_ERR_SHORT_BUFFER;

    // Prefix all 1s → continuation bytes follow (full octets).
    uint64_t value     = max_val;
    uint64_t multiplier = 1;
    int got_last        = 0;

    for (size_t byte_idx = 1; byte_idx < buffer_size; byte_idx++) {
        uint8_t b = buffer[byte_idx];

        // Guard: multiplier * 128 overflows after ~10 bytes.
        // Clamp contribution to avoid undefined behavior.
        uint64_t contribution;
        if (multiplier > UINT64_MAX / 128ULL) {
            contribution = UINT64_MAX;
        } else {
            contribution = (b & 0x7F) * multiplier;
        }

        if (UINT64_MAX - value < contribution) {
            value = UINT64_MAX;
        } else {
            value += contribution;
        }
        multiplier *= 128;
        *bits_parsed += 8;

        // RFC 7541 §5.1: MSB=0 means last octet in the list.
        if (!(b & 0x80)) {
            got_last = 1;
            break;
        }
    }

    if (!got_last) return YAWT_QPACK_ERR_SHORT_BUFFER;
    *out_value = value;
    return YAWT_QPACK_OK;
}

// Encode value into `buffer` at `offset_bits`, returning bits consumed.
//
// RFC 7541 §5.1 pseudocode:
//   if I < 2^N - 1: encode I on N bits
//   else:
//       encode (2^N - 1) on N bits
//       I = I - (2^N - 1)
//       while I >= 128: encode (I % 128 + 128) on 8 bits, I = I / 128
//       encode I on 8 bits
YAWT_QPACK_Error_t YAWT_H3_QPACK_encode_prefix_int(
    uint8_t *buffer, size_t buffer_size,
    uint8_t offset_bits,
    uint64_t value,
    uint64_t *bits_consumed)
{
    if (offset_bits >= 8) return YAWT_QPACK_ERR_INVALID_PARAM;

    uint8_t N          = 8 - offset_bits;
    uint8_t max_val    = (1U << N) - 1;

    // RFC 7541 §5.1: value fits in the N-bit prefix.
    if (value < max_val) {
        buffer[0] &= ~max_val;
        buffer[0] |= (uint8_t)value;
        *bits_consumed = N;
        return YAWT_QPACK_OK;
    }

    // Prefix all 1s, then continuation bytes.
    buffer[0] |= max_val;
    *bits_consumed = N;

    uint64_t remaining = value - max_val;
    size_t byte_idx = 1;

    // RFC 7541 §5.1: I >= 128 → byte = (I % 128) + 128 (continuation flag set).
    while (remaining >= 128) {
        if (byte_idx >= buffer_size) return YAWT_QPACK_ERR_SHORT_BUFFER;
        buffer[byte_idx++] = (uint8_t)((remaining % 128) + 128);
        remaining /= 128;
        *bits_consumed += 8;
    }

    // Last byte: MSB = 0 (no continuation flag).
    if (byte_idx >= buffer_size) return YAWT_QPACK_ERR_SHORT_BUFFER;
    buffer[byte_idx] = (uint8_t)(remaining & 0x7F);
    *bits_consumed += 8;

    return YAWT_QPACK_OK;
}

