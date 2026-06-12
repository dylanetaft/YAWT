#include "qpack.h"
#include "h3_types.h"
#include <string.h>
#include <stdlib.h>
#include "logger.h"
#include <stdio.h>

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
// I converted this to wire format, MSB first, as it is easier to reason about

static const struct { uint8_t code[4]; uint8_t bits; } HUFFMAN_TABLE[] = {
{"\xFF\xC0\x00\x00",13},{"\xFF\xFF\xB0\x00",23},{"\xFF\xFF\xFE\x20",28},{"\xFF\xFF\xFE\x30",28},
{"\xFF\xFF\xFE\x40",28},{"\xFF\xFF\xFE\x50",28},{"\xFF\xFF\xFE\x60",28},{"\xFF\xFF\xFE\x70",28},
{"\xFF\xFF\xFE\x80",28},{"\xFF\xFF\xEA\x00",24},{"\xFF\xFF\xFF\xF0",30},{"\xFF\xFF\xFE\x90",28},
{"\xFF\xFF\xFE\xA0",28},{"\xFF\xFF\xFF\xF4",30},{"\xFF\xFF\xFE\xB0",28},{"\xFF\xFF\xFE\xC0",28},
{"\xFF\xFF\xFE\xD0",28},{"\xFF\xFF\xFE\xE0",28},{"\xFF\xFF\xFE\xF0",28},{"\xFF\xFF\xFF\x00",28},
{"\xFF\xFF\xFF\x10",28},{"\xFF\xFF\xFF\x20",28},{"\xFF\xFF\xFF\xF8",30},{"\xFF\xFF\xFF\x30",28},
{"\xFF\xFF\xFF\x40",28},{"\xFF\xFF\xFF\x50",28},{"\xFF\xFF\xFF\x60",28},{"\xFF\xFF\xFF\x70",28},
{"\xFF\xFF\xFF\x80",28},{"\xFF\xFF\xFF\x90",28},{"\xFF\xFF\xFF\xA0",28},{"\xFF\xFF\xFF\xB0",28},
{"\x50\x00\x00\x00",6},{"\xFE\x00\x00\x00",10},{"\xFE\x40\x00\x00",10},{"\xFF\xA0\x00\x00",12},
{"\xFF\xC8\x00\x00",13},{"\x54\x00\x00\x00",6},{"\xF8\x00\x00\x00",8},{"\xFF\x40\x00\x00",11},
{"\xFE\x80\x00\x00",10},{"\xFE\xC0\x00\x00",10},{"\xF9\x00\x00\x00",8},{"\xFF\x60\x00\x00",11},
{"\xFA\x00\x00\x00",8},{"\x58\x00\x00\x00",6},{"\x5C\x00\x00\x00",6},{"\x60\x00\x00\x00",6},
{"\x00\x00\x00\x00",5},{"\x08\x00\x00\x00",5},{"\x10\x00\x00\x00",5},{"\x64\x00\x00\x00",6},
{"\x68\x00\x00\x00",6},{"\x6C\x00\x00\x00",6},{"\x70\x00\x00\x00",6},{"\x74\x00\x00\x00",6},
{"\x78\x00\x00\x00",6},{"\x7C\x00\x00\x00",6},{"\xB8\x00\x00\x00",7},{"\xFB\x00\x00\x00",8},
{"\xFF\xF8\x00\x00",15},{"\x80\x00\x00\x00",6},{"\xFF\xB0\x00\x00",12},{"\xFF\x00\x00\x00",10},
{"\xFF\xD0\x00\x00",13},{"\x84\x00\x00\x00",6},{"\xBA\x00\x00\x00",7},{"\xBC\x00\x00\x00",7},
{"\xBE\x00\x00\x00",7},{"\xC0\x00\x00\x00",7},{"\xC2\x00\x00\x00",7},{"\xC4\x00\x00\x00",7},
{"\xC6\x00\x00\x00",7},{"\xC8\x00\x00\x00",7},{"\xCA\x00\x00\x00",7},{"\xCC\x00\x00\x00",7},
{"\xCE\x00\x00\x00",7},{"\xD0\x00\x00\x00",7},{"\xD2\x00\x00\x00",7},{"\xD4\x00\x00\x00",7},
{"\xD6\x00\x00\x00",7},{"\xD8\x00\x00\x00",7},{"\xDA\x00\x00\x00",7},{"\xDC\x00\x00\x00",7},
{"\xDE\x00\x00\x00",7},{"\xE0\x00\x00\x00",7},{"\xE2\x00\x00\x00",7},{"\xE4\x00\x00\x00",7},
{"\xFC\x00\x00\x00",8},{"\xE6\x00\x00\x00",7},{"\xFD\x00\x00\x00",8},{"\xFF\xD8\x00\x00",13},
{"\xFF\xFE\x00\x00",19},{"\xFF\xE0\x00\x00",13},{"\xFF\xF0\x00\x00",14},{"\x88\x00\x00\x00",6},
{"\xFF\xFA\x00\x00",15},{"\x18\x00\x00\x00",5},{"\x8C\x00\x00\x00",6},{"\x20\x00\x00\x00",5},
{"\x90\x00\x00\x00",6},{"\x28\x00\x00\x00",5},{"\x94\x00\x00\x00",6},{"\x98\x00\x00\x00",6},
{"\x9C\x00\x00\x00",6},{"\x30\x00\x00\x00",5},{"\xE8\x00\x00\x00",7},{"\xEA\x00\x00\x00",7},
{"\xA0\x00\x00\x00",6},{"\xA4\x00\x00\x00",6},{"\xA8\x00\x00\x00",6},{"\x38\x00\x00\x00",5},
{"\xAC\x00\x00\x00",6},{"\xEC\x00\x00\x00",7},{"\xB0\x00\x00\x00",6},{"\x40\x00\x00\x00",5},
{"\x48\x00\x00\x00",5},{"\xB4\x00\x00\x00",6},{"\xEE\x00\x00\x00",7},{"\xF0\x00\x00\x00",7},
{"\xF2\x00\x00\x00",7},{"\xF4\x00\x00\x00",7},{"\xF6\x00\x00\x00",7},{"\xFF\xFC\x00\x00",15},
{"\xFF\x80\x00\x00",11},{"\xFF\xF4\x00\x00",14},{"\xFF\xE8\x00\x00",13},{"\xFF\xFF\xFF\xC0",28},
{"\xFF\xFE\x60\x00",20},{"\xFF\xFF\x48\x00",22},{"\xFF\xFE\x70\x00",20},{"\xFF\xFE\x80\x00",20},
{"\xFF\xFF\x4C\x00",22},{"\xFF\xFF\x50\x00",22},{"\xFF\xFF\x54\x00",22},{"\xFF\xFF\xB2\x00",23},
{"\xFF\xFF\x58\x00",22},{"\xFF\xFF\xB4\x00",23},{"\xFF\xFF\xB6\x00",23},{"\xFF\xFF\xB8\x00",23},
{"\xFF\xFF\xBA\x00",23},{"\xFF\xFF\xBC\x00",23},{"\xFF\xFF\xEB\x00",24},{"\xFF\xFF\xBE\x00",23},
{"\xFF\xFF\xEC\x00",24},{"\xFF\xFF\xED\x00",24},{"\xFF\xFF\x5C\x00",22},{"\xFF\xFF\xC0\x00",23},
{"\xFF\xFF\xEE\x00",24},{"\xFF\xFF\xC2\x00",23},{"\xFF\xFF\xC4\x00",23},{"\xFF\xFF\xC6\x00",23},
{"\xFF\xFF\xC8\x00",23},{"\xFF\xFE\xE0\x00",21},{"\xFF\xFF\x60\x00",22},{"\xFF\xFF\xCA\x00",23},
{"\xFF\xFF\x64\x00",22},{"\xFF\xFF\xCC\x00",23},{"\xFF\xFF\xCE\x00",23},{"\xFF\xFF\xEF\x00",24},
{"\xFF\xFF\x68\x00",22},{"\xFF\xFE\xE8\x00",21},{"\xFF\xFE\x90\x00",20},{"\xFF\xFF\x6C\x00",22},
{"\xFF\xFF\x70\x00",22},{"\xFF\xFF\xD0\x00",23},{"\xFF\xFF\xD2\x00",23},{"\xFF\xFE\xF0\x00",21},
{"\xFF\xFF\xD4\x00",23},{"\xFF\xFF\x74\x00",22},{"\xFF\xFF\x78\x00",22},{"\xFF\xFF\xF0\x00",24},
{"\xFF\xFE\xF8\x00",21},{"\xFF\xFF\x7C\x00",22},{"\xFF\xFF\xD6\x00",23},{"\xFF\xFF\xD8\x00",23},
{"\xFF\xFF\x00\x00",21},{"\xFF\xFF\x08\x00",21},{"\xFF\xFF\x80\x00",22},{"\xFF\xFF\x10\x00",21},
{"\xFF\xFF\xDA\x00",23},{"\xFF\xFF\x84\x00",22},{"\xFF\xFF\xDC\x00",23},{"\xFF\xFF\xDE\x00",23},
{"\xFF\xFE\xA0\x00",20},{"\xFF\xFF\x88\x00",22},{"\xFF\xFF\x8C\x00",22},{"\xFF\xFF\x90\x00",22},
{"\xFF\xFF\xE0\x00",23},{"\xFF\xFF\x94\x00",22},{"\xFF\xFF\x98\x00",22},{"\xFF\xFF\xE2\x00",23},
{"\xFF\xFF\xF8\x00",26},{"\xFF\xFF\xF8\x40",26},{"\xFF\xFE\xB0\x00",20},{"\xFF\xFE\x20\x00",19},
{"\xFF\xFF\x9C\x00",22},{"\xFF\xFF\xE4\x00",23},{"\xFF\xFF\xA0\x00",22},{"\xFF\xFF\xF6\x00",25},
{"\xFF\xFF\xF8\x80",26},{"\xFF\xFF\xF8\xC0",26},{"\xFF\xFF\xF9\x00",26},{"\xFF\xFF\xFB\xC0",27},
{"\xFF\xFF\xFB\xE0",27},{"\xFF\xFF\xF9\x40",26},{"\xFF\xFF\xF1\x00",24},{"\xFF\xFF\xF6\x80",25},
{"\xFF\xFE\x40\x00",19},{"\xFF\xFF\x18\x00",21},{"\xFF\xFF\xF9\x80",26},{"\xFF\xFF\xFC\x00",27},
{"\xFF\xFF\xFC\x20",27},{"\xFF\xFF\xF9\xC0",26},{"\xFF\xFF\xFC\x40",27},{"\xFF\xFF\xF2\x00",24},
{"\xFF\xFF\x20\x00",21},{"\xFF\xFF\x28\x00",21},{"\xFF\xFF\xFA\x00",26},{"\xFF\xFF\xFA\x40",26},
{"\xFF\xFF\xFF\xD0",28},{"\xFF\xFF\xFC\x60",27},{"\xFF\xFF\xFC\x80",27},{"\xFF\xFF\xFC\xA0",27},
{"\xFF\xFE\xC0\x00",20},{"\xFF\xFF\xF3\x00",24},{"\xFF\xFE\xD0\x00",20},{"\xFF\xFF\x30\x00",21},
{"\xFF\xFF\xA4\x00",22},{"\xFF\xFF\x38\x00",21},{"\xFF\xFF\x40\x00",21},{"\xFF\xFF\xE6\x00",23},
{"\xFF\xFF\xA8\x00",22},{"\xFF\xFF\xAC\x00",22},{"\xFF\xFF\xF7\x00",25},{"\xFF\xFF\xF7\x80",25},
{"\xFF\xFF\xF4\x00",24},{"\xFF\xFF\xF5\x00",24},{"\xFF\xFF\xFA\x80",26},{"\xFF\xFF\xE8\x00",23},
{"\xFF\xFF\xFA\xC0",26},{"\xFF\xFF\xFC\xC0",27},{"\xFF\xFF\xFB\x00",26},{"\xFF\xFF\xFB\x40",26},
{"\xFF\xFF\xFC\xE0",27},{"\xFF\xFF\xFD\x00",27},{"\xFF\xFF\xFD\x20",27},{"\xFF\xFF\xFD\x40",27},
{"\xFF\xFF\xFD\x60",27},{"\xFF\xFF\xFF\xE0",28},{"\xFF\xFF\xFD\x80",27},{"\xFF\xFF\xFD\xA0",27},
{"\xFF\xFF\xFD\xC0",27},{"\xFF\xFF\xFD\xE0",27},{"\xFF\xFF\xFE\x00",27},{"\xFF\xFF\xFB\x80",26}
};


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
      const uint8_t *code = HUFFMAN_TABLE[i].code; //working on this
      size_t bits = HUFFMAN_TABLE[i].bits; //how many bits in this code
      for (int b = 0; b < 4; b++) {
        for (int p = 7; p >= 0; p--) {          // 7..0 = 8 bits
          size_t bit_pos = (size_t)b * 8 + (7 - p);
          if (bit_pos >= bits) break; //end of codeword
          uint8_t bit = (code[b] >> p) & 1u;
            uint16_t *next = bit ? &_g_huff_decoder.nodes[current].r : 
              &_g_huff_decoder.nodes[current].l;
            if (*next == 0) {   //we will create child
                if (_g_huff_decoder.count >= YAWT_QPACK_HUFF_DEC_TREE_MAX - 1) {
                    abort();
                }
                *next = _g_huff_decoder.count + 1;
                _g_huff_decoder.count++;
            }
            // Always follow the edge, whether the child was just created or
            // already existed (shared prefix with a previously inserted code).
            current = *next;
        }
      }
            
      _g_huff_decoder.nodes[current].value = (uint8_t)i;
      _g_huff_decoder.nodes[current].bits = HUFFMAN_TABLE[i].bits;
    }
}

YAWT_QPACK_Error_t YAWT_QPACK_huff_decode_byte(
    const uint8_t *data, size_t data_len,
    uint8_t *bit_offset, uint8_t *out_byte, size_t *advance_bytes)
{
    //YAWT_LOG(YAWT_LOG_DEBUG,"decode byte");
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
        //YAWT_LOG(YAWT_LOG_DEBUG,"Huffman decode: bit=%u, pos=%zu, bit_pos=%u", bit, pos, bit_pos);
        next = bit ? _g_huff_decoder.nodes[current].r : _g_huff_decoder.nodes[current].l;
        if (next == 0) {
            // We are on an internal node that has no edge for this bit:
            // the input does not correspond to a valid Huffman code.
            YAWT_LOG(YAWT_LOG_ERROR,"Malformed Huffman code at pos %zu, bit_pos %u", pos, bit_pos);
            return YAWT_QPACK_ERR_MALFORMED;
        }
        current = next;
        if (_g_huff_decoder.nodes[current].l == 0 &&
            _g_huff_decoder.nodes[current].r == 0) {
            // Reached a leaf: emit immediately, having consumed exactly the
            // code's bits (no over-read of the following symbol).
            *out_byte = _g_huff_decoder.nodes[current].value;
            // bit_offset = residual bit position within the current byte;
            // advance_bytes = number of whole bytes fully consumed.
            *bit_offset = bit_pos;
            if (advance_bytes) {
                *advance_bytes = pos;
            }
            //YAWT_LOG(YAWT_LOG_DEBUG,"Decoded byte: %u, bit_offset: %u, advance_bytes: %zu",
            //         *out_byte, *bit_offset, pos);
            return YAWT_QPACK_OK;
        }
    }
    return YAWT_QPACK_ERR_MALFORMED;
}


YAWT_QPACK_Error_t YAWT_QPACK_huff_decode_string(
    const uint8_t *data, size_t data_len,
    uint8_t *out, size_t out_size, size_t *out_len)
{
    uint8_t bit_offset = 0;
    size_t decoded = 0;
    const uint8_t *cur = data;
    size_t remaining = data_len;

    while (remaining > 0) {
        if (decoded >= out_size) {
            return YAWT_QPACK_ERR_SHORT_BUFFER;
        }

        size_t advance = 0;
        YAWT_QPACK_Error_t err = YAWT_QPACK_huff_decode_byte(
            cur, remaining, &bit_offset, &out[decoded], &advance);
        
        if (err != YAWT_QPACK_OK) {
            if (err == YAWT_QPACK_ERR_MALFORMED && remaining == 1) {
                uint8_t mask = (bit_offset == 0) ? 0xFF : (uint8_t)((1U << (8 - bit_offset)) - 1);
                if ((cur[0] & mask) == mask) {
                    *out_len = decoded;
                    return YAWT_QPACK_OK;
                }
            }
            return err;
        }

        decoded++;
        cur += advance;
        remaining -= advance;

        if (remaining == 0 && bit_offset == 0) {
            break;
        }
    }

    *out_len = decoded;
    return YAWT_QPACK_OK;
}

YAWT_QPACK_Error_t YAWT_QPACK_huff_encode_byte(
    uint8_t in_byte, uint8_t *out, size_t out_size,
    uint8_t *bit_offset, size_t *advance_bytes)
{
    if (!out || !bit_offset && !advance_bytes) {
        return YAWT_QPACK_ERR_INVALID_PARAM;
    }
    if (*bit_offset >= 8) {
      //this param is only for offsetting in the first byte
      return YAWT_QPACK_ERR_INVALID_PARAM;
    }
    // A single code is up to 4 bytes wide and, when written at a non-zero bit
    // offset, can spill into a 5th byte, so we always need room for 5 bytes.
    if (out_size < 5) {
        return YAWT_QPACK_ERR_SHORT_BUFFER;
    }
    uint8_t bits = HUFFMAN_TABLE[in_byte].bits;
    const uint8_t *code = HUFFMAN_TABLE[in_byte].code;
    uint8_t off = *bit_offset;

    if (off == 0) {
        // Byte-aligned: write the whole 4-byte code. Bytes beyond the code are
        // zero padding; clobbering them is fine since output is built strictly
        // left-to-right and they'll be OR'd into on the next call.
        memcpy(out, code, 4);
    } else {
        // We don't care that we're clobbering the bits after the code
        // because the caller is expected to only call this function once per byte of
        // input, and to advance the output pointer by the number of whole bytes
        // Mid-byte: preserve the partial first byte, clobber the rest.
        uint8_t rem = 8 - off;
        out[0] |= code[0] >> off;
        out[1]  = (code[0] << rem) | (code[1] >> off);
        out[2]  = (code[1] << rem) | (code[2] >> off);
        out[3]  = (code[2] << rem) | (code[3] >> off);
        out[4]  = (code[3] << rem); // spill into 5th byte if needed; caller must ensure room
    }

    // New residual bit position within the last byte touched, and the number of
    // whole bytes fully completed (which the caller should advance `out` by).
    *bit_offset = (off + bits) % 8;
    *advance_bytes = (off + bits) / 8;
    return YAWT_QPACK_OK;
}

YAWT_QPACK_Error_t YAWT_QPACK_huff_encode_string(
    const uint8_t *input, size_t input_len,
    uint8_t *out, size_t out_size, size_t *out_len)
{
    size_t total_bits = 0;

    for (size_t i = 0; i < input_len; i++) {
        total_bits += HUFFMAN_TABLE[input[i]].bits;
    }

    size_t needed_bytes = (total_bits + 7) / 8;
    if (needed_bytes > out_size) {
        return YAWT_QPACK_ERR_SHORT_BUFFER;
    }

    memset(out, 0, needed_bytes);

    size_t out_pos = 0;
    uint8_t bit_offset = 0;
    for (size_t i = 0; i < input_len; i++) {
        size_t advance_bytes = 0;
        YAWT_QPACK_Error_t err = YAWT_QPACK_huff_encode_byte(
            input[i], out + out_pos, out_size - out_pos, &bit_offset, &advance_bytes);
        if (err != YAWT_QPACK_OK) {
            return err;
        }
        out_pos += advance_bytes;
    }

    if (bit_offset % 8 != 0) {
        out[out_pos] |= (uint8_t)((1 << (8 - (bit_offset % 8))) - 1);
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

