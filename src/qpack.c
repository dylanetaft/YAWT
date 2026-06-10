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
static const struct { uint32_t code; uint8_t bits; } HUFFMAN_TABLE[] = {
 {0x1ff8,13},{0x7fffd8,23},{0xfffffe2,28},{0xfffffe3,28},{0xfffffe4,28},{0xfffffe5,28},{0xfffffe6,28},{0xfffffe7,28},{0xfffffe8,28},{0xffffea,24},{0x3ffffffc,30},{0xfffffe9,28},{0xfffffea,28},{0x3ffffffd,30},{0xfffffeb,28},{0xfffffec,28},{0xfffffed,28},{0xfffffee,28},{0xfffffef,28},{0xffffff0,28},{0xffffff1,28},{0xffffff2,28},{0x3ffffffe,30},{0xffffff3,28},{0xffffff4,28},{0xffffff5,28},{0xffffff6,28},{0xffffff7,28},{0xffffff8,28},{0xffffff9,28},{0xffffffa,28},{0xffffffb,28},{0x14,6},{0x3f8,10},{0x3f9,10},{0xffa,12},{0x1ff9,13},{0x15,6},{0xf8,8},{0x7fa,11},{0x3fa,10},{0x3fb,10},{0xf9,8},{0x7fb,11},{0xfa,8},{0x16,6},{0x17,6},{0x18,6},{0x0,5},{0x1,5},{0x2,5},{0x19,6},{0x1a,6},{0x1b,6},{0x1c,6},{0x1d,6},{0x1e,6},{0x1f,6},{0x5c,7},{0xfb,8},{0x7ffc,15},{0x20,6},{0xffb,12},{0x3fc,10},{0x1ffa,13},{0x21,6},{0x5d,7},{0x5e,7},{0x5f,7},{0x60,7},{0x61,7},{0x62,7},{0x63,7},{0x64,7},{0x65,7},{0x66,7},{0x67,7},{0x68,7},{0x69,7},{0x6a,7},{0x6b,7},{0x6c,7},{0x6d,7},{0x6e,7},{0x6f,7},{0x70,7},{0x71,7},{0x72,7},{0xfc,8},{0x73,7},{0xfd,8},{0x1ffb,13},{0x7fff0,19},{0x1ffc,13},{0x3ffc,14},{0x22,6},{0x7ffd,15},{0x3,5},{0x23,6},{0x4,5},{0x24,6},{0x5,5},{0x25,6},{0x26,6},{0x27,6},{0x6,5},{0x74,7},{0x75,7},{0x28,6},{0x29,6},{0x2a,6},{0x7,5},{0x2b,6},{0x76,7},{0x2c,6},{0x8,5},{0x9,5},{0x2d,6},{0x77,7},{0x78,7},{0x79,7},{0x7a,7},{0x7b,7},{0x7ffe,15},{0x7fc,11},{0x3ffd,14},{0x1ffd,13},{0xffffffc,28},{0xfffe6,20},{0x3fffd2,22},{0xfffe7,20},{0xfffe8,20},{0x3fffd3,22},{0x3fffd4,22},{0x3fffd5,22},{0x7fffd9,23},{0x3fffd6,22},{0x7fffda,23},{0x7fffdb,23},{0x7fffdc,23},{0x7fffdd,23},{0x7fffde,23},{0xffffeb,24},{0x7fffdf,23},{0xffffec,24},{0xffffed,24},{0x3fffd7,22},{0x7fffe0,23},{0xffffee,24},{0x7fffe1,23},{0x7fffe2,23},{0x7fffe3,23},{0x7fffe4,23},{0x1fffdc,21},{0x3fffd8,22},{0x7fffe5,23},{0x3fffd9,22},{0x7fffe6,23},{0x7fffe7,23},{0xffffef,24},{0x3fffda,22},{0x1fffdd,21},{0xfffe9,20},{0x3fffdb,22},{0x3fffdc,22},{0x7fffe8,23},{0x7fffe9,23},{0x1fffde,21},{0x7fffea,23},{0x3fffdd,22},{0x3fffde,22},{0xfffff0,24},{0x1fffdf,21},{0x3fffdf,22},{0x7fffeb,23},{0x7fffec,23},{0x1fffe0,21},{0x1fffe1,21},{0x3fffe0,22},{0x1fffe2,21},{0x7fffed,23},{0x3fffe1,22},{0x7fffee,23},{0x7fffef,23},{0xfffea,20},{0x3fffe2,22},{0x3fffe3,22},{0x3fffe4,22},{0x7ffff0,23},{0x3fffe5,22},{0x3fffe6,22},{0x7ffff1,23},{0x3ffffe0,26},{0x3ffffe1,26},{0xfffeb,20},{0x7fff1,19},{0x3fffe7,22},{0x7ffff2,23},{0x3fffe8,22},{0x1ffffec,25},{0x3ffffe2,26},{0x3ffffe3,26},{0x3ffffe4,26},{0x7ffffde,27},{0x7ffffdf,27},{0x3ffffe5,26},{0xfffff1,24},{0x1ffffed,25},{0x7fff2,19},{0x1fffe3,21},{0x3ffffe6,26},{0x7ffffe0,27},{0x7ffffe1,27},{0x3ffffe7,26},{0x7ffffe2,27},{0xfffff2,24},{0x1fffe4,21},{0x1fffe5,21},{0x3ffffe8,26},{0x3ffffe9,26},{0xffffffd,28},{0x7ffffe3,27},{0x7ffffe4,27},{0x7ffffe5,27},{0xfffec,20},{0xfffff3,24},{0xfffed,20},{0x1fffe6,21},{0x3fffe9,22},{0x1fffe7,21},{0x1fffe8,21},{0x7ffff3,23},{0x3fffea,22},{0x3fffeb,22},{0x1ffffee,25},{0x1ffffef,25},{0xfffff4,24},{0xfffff5,24},{0x3ffffea,26},{0x7ffff4,23},{0x3ffffeb,26},{0x7ffffe6,27},{0x3ffffec,26},{0x3ffffed,26},{0x7ffffe7,27},{0x7ffffe8,27},{0x7ffffe9,27},{0x7ffffea,27},{0x7ffffeb,27},{0xffffffe,28},{0x7ffffec,27},{0x7ffffed,27},{0x7ffffee,27},{0x7ffffef,27},{0x7fffff0,27},{0x3ffffee,26}
};

// EOS symbol code (used for padding at end of Huffman-encoded string)
#define HUFFMAN_EOS_CODE 0x3fffffc
#define HUFFMAN_EOS_BITS 26

// ---------------------------------------------------------------------------
// Huffman decoder tree — lazy-initialized on first decode call.
// ---------------------------------------------------------------------------

static YAWT_QPACK_HuffDecoder_t _g_huff_decoder = {0};

static void huff_decoder_build(void) {
    uint16_t hufftbl_sz = sizeof(HUFFMAN_TABLE) / sizeof(HUFFMAN_TABLE[0]);
    uint32_t mask = (uint32_t)1 << 31;
    // Build the decoder tree by inserting each symbol's code 
    // into the tree according to its bits.
    
    for (uint16_t i = 0; i < hufftbl_sz; i++) {
      uint16_t current = 0; // start at root
        for (uint8_t b = 0; b < HUFFMAN_TABLE[i].bits; b++) {
            uint8_t blen = HUFFMAN_TABLE[i].bits - b;
            uint32_t data = mask & (HUFFMAN_TABLE[i].code << (sizeof(uint32_t) * 8 - blen));
            uint8_t bit = data >> 31;
            uint16_t *next = bit ? &_g_huff_decoder.nodes[current].r : &_g_huff_decoder.nodes[current].l;
            
            if (*next == 0) {
                if (_g_huff_decoder.count >= YAWT_QPACK_HUFF_DEC_TREE_MAX - 1) {
                    abort();
                }
                *next = _g_huff_decoder.count + 1;
                _g_huff_decoder.count++;
                current = *next;
            }
            else current = *next; //we already have a node, move to it
        }
        _g_huff_decoder.nodes[current].value = (uint8_t)i;
        _g_huff_decoder.nodes[current].bits = HUFFMAN_TABLE[i].bits;
    }
}

YAWT_QPACK_Error_t YAWT_QPACK_huff_decode_byte(
    const uint8_t *data, size_t data_len,
    size_t *bit_offset, uint8_t *out_byte)
{
    if (_g_huff_decoder.count == 0) {
        huff_decoder_build();
    }
    if (!data || !bit_offset || !out_byte || data_len == 0) {
        return YAWT_QPACK_ERR_INVALID_PARAM;
    }
    uint16_t current = 0;
    uint16_t next = 0;
    if (*bit_offset >= 8) {
        return YAWT_QPACK_ERR_MALFORMED;
    }
    uint8_t bit_pos = *bit_offset;
    size_t pos = 0;

    while (pos < data_len) {
        uint8_t bit = (data[pos] >> (7 - bit_pos)) & 1;
        bit_pos++;
        if (bit_pos == 8) {
            bit_pos = 0;
            pos++;
        }
        next = bit ? _g_huff_decoder.nodes[current].r : _g_huff_decoder.nodes[current].l;
        if (next == 0) {
            if (_g_huff_decoder.nodes[current].l == 0 &&
                _g_huff_decoder.nodes[current].r == 0) {
                *out_byte = _g_huff_decoder.nodes[current].value;
                *bit_offset = (size_t)bit_pos + (pos * 8);
                return YAWT_QPACK_OK;
            }
            else {
                return YAWT_QPACK_ERR_MALFORMED;
            }
        }
        current = next;
    }
    return YAWT_QPACK_ERR_MALFORMED;
}


YAWT_QPACK_Error_t YAWT_QPACK_huff_decode_string(
    const uint8_t *data, size_t data_len,
    uint8_t *out, size_t out_size, size_t *out_len)
{
    size_t bit_offset = 0;
    size_t decoded = 0;
    size_t total_bits = data_len * 8;

    while (bit_offset < total_bits) {
        if (decoded >= out_size) {
            return YAWT_QPACK_ERR_SHORT_BUFFER;
        }

        YAWT_QPACK_Error_t err = YAWT_QPACK_huff_decode_byte(
            data, data_len, &bit_offset, &out[decoded]);
        if (err == YAWT_QPACK_DONE) {
            *out_len = decoded;
            return YAWT_QPACK_OK;
        }
        if (err != YAWT_QPACK_OK) {
            return err;
        }
        decoded++;
    }

    *out_len = decoded;
    return YAWT_QPACK_OK;
}

YAWT_QPACK_Error_t YAWT_QPACK_huff_encode_string(
    const uint8_t *input, size_t input_len,
    uint8_t *out, size_t out_size, size_t *out_len)
{
    size_t bit_offset = 0;
    uint64_t total_bits = 0;

    for (size_t i = 0; i < input_len; i++) {
        total_bits += HUFFMAN_TABLE[input[i]].bits;
    }
    total_bits += HUFFMAN_EOS_BITS;

    size_t needed_bytes = (total_bits + 7) / 8;
    if (needed_bytes > out_size) {
        return YAWT_QPACK_ERR_SHORT_BUFFER;
    }

    memset(out, 0, needed_bytes);

    for (size_t i = 0; i < input_len; i++) {
        uint32_t code = HUFFMAN_TABLE[input[i]].code;
        uint8_t bits = HUFFMAN_TABLE[input[i]].bits;

        for (uint8_t b = 0; b < bits; b++) {
            uint8_t bit = (code >> (bits - 1 - b)) & 1;
            size_t byte_idx = bit_offset / 8;
            uint8_t bit_pos = 7 - (bit_offset % 8);
            out[byte_idx] |= (bit << bit_pos);
            bit_offset++;
        }
    }

    uint32_t eos_code = HUFFMAN_EOS_CODE;
    for (uint8_t b = 0; b < HUFFMAN_EOS_BITS; b++) {
        uint8_t bit = (eos_code >> (HUFFMAN_EOS_BITS - 1 - b)) & 1;
        size_t byte_idx = bit_offset / 8;
        uint8_t bit_pos = 7 - (bit_offset % 8);
        out[byte_idx] |= (bit << bit_pos);
        bit_offset++;
    }

    *out_len = needed_bytes;
    return YAWT_QPACK_OK;
}


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

// Decode a prefixed integer starting at `buffer`, using `offset_bits` MSB
// positions reserved for the caller's already-dispatched instruction prefix.
// The prefix size N = 8 - offset_bits; the N value bits occupy the lower
// N bit positions of the byte (C bit positions 0..N-1).  The caller sets
// `offset_bits` based on which QPACK instruction format was dispatched.
// Continuation octets are always byte-aligned (full bytes).
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
YAWT_QPACK_Error_t YAWT_H3_QPACK_decode_prefix_int(
    const uint8_t *buffer, size_t buffer_size,
    uint8_t offset_bits,
    uint64_t *out_value, uint64_t *bytes_consumed)
{
    if (offset_bits >= 8) return YAWT_QPACK_ERR_INVALID_PARAM;

    uint8_t N          = 8 - offset_bits;
    uint8_t max_val    = (1U << N) - 1;

    // Extract N-bit prefix: lower N bits hold the value.
    uint64_t prefix    = buffer[0] & max_val;
    *bytes_consumed    = 1;

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
        *bytes_consumed += 1;

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

// Encode `value` into `buffer` at the lower N bits (where N = 8 - offset_bits).
// The `offset_bits` MSB positions are reserved for the caller's instruction
// prefix and are preserved unchanged.  The caller sets `offset_bits` based
// on which QPACK instruction format was dispatched.  Returns the total bytes
// consumed (1 for the prefix byte plus 1 per continuation byte).
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
    uint64_t *bytes_consumed)
{
    if (offset_bits >= 8) return YAWT_QPACK_ERR_INVALID_PARAM;

    uint8_t N          = 8 - offset_bits;
    uint8_t max_val    = (1U << N) - 1;

    // RFC 7541 §5.1: value fits in the N-bit prefix.
    if (value < max_val) {
        buffer[0] &= ~max_val;
        buffer[0] |= (uint8_t)value;
        *bytes_consumed = 1;
        return YAWT_QPACK_OK;
    }

    // Prefix all 1s, then continuation bytes.
    buffer[0] |= max_val;
    *bytes_consumed = 1;

    uint64_t remaining = value - max_val;
    size_t byte_idx = 1;

    // RFC 7541 §5.1: I >= 128 → byte = (I % 128) + 128 (continuation flag set).
    while (remaining >= 128) {
        if (byte_idx >= buffer_size) return YAWT_QPACK_ERR_SHORT_BUFFER;
        buffer[byte_idx++] = (uint8_t)((remaining % 128) + 128);
        remaining /= 128;
        *bytes_consumed += 1;
    }

    // Last byte: MSB = 0 (no continuation flag).
    if (byte_idx >= buffer_size) return YAWT_QPACK_ERR_SHORT_BUFFER;
    buffer[byte_idx] = (uint8_t)(remaining & 0x7F);
    *bytes_consumed += 1;

    return YAWT_QPACK_OK;
}

