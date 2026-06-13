#pragma once
#include <stdint.h>
#include <stddef.h>

// Forward declaration — header fields backed by ANB_Slab.
typedef struct ANB_Slab ANB_Slab_t;

// h3_types.h is included here because the static-only field section decoder
// API (YAWT_qpack_decode) operates on YAWT_H3_HeaderFields_t.
#include "h3_types.h"

// ---------------------------------------------------------------------------
// QPACK static table (RFC 9204 Appendix A) — 99 entries, index 0..98.
// Both sides ship with the same table; the encoder emits indexes, the decoder
// looks them up. No allocation, no destruction — compile-time constants.
// ---------------------------------------------------------------------------

#define YAWT_QPACK_STATIC_TABLE_SIZE 99

typedef struct {
  const char *name;
  const char *value;
} YAWT_QPACK_StaticEntry_t;

// Returns the static-table entry at `index`, or NULL if out of range.
const YAWT_QPACK_StaticEntry_t *YAWT_qpack_static_get(uint64_t index);

// Encoder helper: find the first static-table index whose name matches.
// Returns -1 if not found.
int YAWT_qpack_static_find_name(const char *name);

// Encoder helper: find the first static-table index whose name AND value match.
// Returns -1 if not found.
int YAWT_qpack_static_find_entry(const char *name, const char *value);

// ---------------------------------------------------------------------------
// QPACK decoder — static table + literals only (dynamic table rejected).
// ---------------------------------------------------------------------------

typedef enum {
  YAWT_QPACK_OK = 0,
  YAWT_QPACK_ERR_MALFORMED,
  YAWT_QPACK_ERR_DYNAMIC_TABLE_UNSUPPORTED,
  YAWT_QPACK_ERR_REQUIRED_INSERT_COUNT,
  YAWT_QPACK_ERR_SHORT_BUFFER,
  YAWT_QPACK_ERR_INVALID_PARAM,
  YAWT_QPACK_DONE,
} YAWT_QPACK_Error_t;


// ---------------------------------------------------------------------------
// QPACK field line representations — RFC 9204 §4.5.
// These are used to decode the encoded field section inside a HEADERS frame.
// They do NOT modify the dynamic table; they only reference it.
// ---------------------------------------------------------------------------

typedef enum {
    YAWT_QPACK_FIELD_LINE_INDEXED,                     // 1xxxxxxx  - 1 prefix bit
    YAWT_QPACK_FIELD_LINE_INDEXED_POST_BASE,           // 0001xxxx  - 4 prefix bits
    YAWT_QPACK_FIELD_LINE_LITERAL_NAME_REF,            // 01xxxxxx  - 2 prefix bits
    YAWT_QPACK_FIELD_LINE_LITERAL_POST_BASE_NAME_REF,  // 0000xxxx  - 4 prefix bits
    YAWT_QPACK_FIELD_LINE_LITERAL_LITERAL_NAME,        // 001xxxxx  - 3 prefix bits
    YAWT_QPACK_FIELD_LINE_UNKNOWN,
} YAWT_QPACK_FieldLineRepType_t;

// Decode the leading byte of a field line representation and return the type
// plus how many prefix bits were consumed by the dispatcher (see RFC 9204 §4.5).
// The remaining bits are dispatched by the caller after this function returns.
YAWT_QPACK_FieldLineRepType_t YAWT_H3_QPACK_decode_field_line_msb(uint8_t byte, uint8_t *out_prefix_bits);

// Decode a prefixed integer. RFC 7541 §5.1 / RFC 9204 §4.1.1.
YAWT_QPACK_Error_t YAWT_H3_QPACK_decode_prefix_int(
    const uint8_t *buffer, size_t buffer_size,
    uint8_t offset_bits,
    uint64_t *out_value, uint64_t *bytes_consumed);

// Encode an unsigned integer with prefix encoding. RFC 7541 §5.1.
YAWT_QPACK_Error_t YAWT_H3_QPACK_encode_prefix_int(
    uint8_t *buffer, size_t buffer_size,
    uint8_t offset_bits,
    uint64_t value,
    uint64_t *bytes_consumed);

// ---------------------------------------------------------------------------
// Huffman decode — RFC 7541 Appendix B / RFC 9204 §5.1
// Array-indexed binary tree, lazy-initialized on first decode call.
// ---------------------------------------------------------------------------

#define YAWT_QPACK_HUFF_DEC_TREE_MAX 600

typedef struct {
    uint16_t l;       // left child index (0 means no child → leaf when both 0)
    uint16_t r;       // right child index
    uint8_t  value;   // decoded byte (valid at leaf)
    uint8_t  bits;    // bit depth to this leaf (valid at leaf)
} YAWT_QPACK_HuffNode_t;

typedef struct {
    YAWT_QPACK_HuffNode_t nodes[YAWT_QPACK_HUFF_DEC_TREE_MAX];
    uint16_t              count;
} YAWT_QPACK_HuffDecoder_t;

// Decode a single Huffman byte from a bitstream. Lazy-inits the tree.
// On input, *bit_offset is the bit position (0-7) within data[0] at which to
// start (non-zero only when resuming mid-byte).
// On success, *bit_offset is set to the residual bit position (0-7) within the
// last byte touched, and *advance_bytes (if non-NULL) is set to the number of
// whole bytes fully consumed. Callers decoding a stream should advance their
// data pointer by *advance_bytes and carry *bit_offset into the next call.
YAWT_QPACK_Error_t YAWT_QPACK_huff_decode_byte(
    const uint8_t *data, size_t data_len,
    uint8_t *bit_offset, uint8_t *out_byte, size_t *advance_bytes);

// Decode an entire Huffman-encoded string into `out` buffer.
// Lazy-inits the tree on first call.
// Returns YAWT_QPACK_ERR_SHORT_BUFFER if `out_size` is too small.
// Sets *out_len to the number of decoded bytes.
YAWT_QPACK_Error_t YAWT_QPACK_huff_decode_string(
    const uint8_t *data, size_t data_len,
    uint8_t *out, size_t out_size, size_t *out_len);

// Encode a single byte into a Huffman bitstream.
// On input, *bit_offset is the bit position (0-7) within out[0] at which to
// start writing.
// On success, *bit_offset is set to the residual bit position (0-7) within the
// last byte written, and *advance_bytes (if non-NULL) is set to the number of
// whole bytes fully completed; callers building a stream should advance their
// `out` pointer by *advance_bytes and carry *bit_offset into the next call.
// out_size is in bytes; a single code may occupy up to 4 bytes, so out_size
// must be >= 4 or YAWT_QPACK_ERR_SHORT_BUFFER is returned.
YAWT_QPACK_Error_t YAWT_QPACK_huff_encode_byte(
    uint8_t in_byte, uint8_t *out, size_t out_size,
    uint8_t *bit_offset, size_t *advance_bytes);

// Encode a raw byte string into Huffman-encoded form.
// Returns YAWT_QPACK_ERR_SHORT_BUFFER if `out_size` is too small.
// Sets *out_len to the number of encoded bytes written.
YAWT_QPACK_Error_t YAWT_QPACK_huff_encode_string(
    const uint8_t *input, size_t input_len,
    uint8_t *out, size_t out_size, size_t *out_len);


// ---------------------------------------------------------------------------
// QPACK header block prefix + field section decode (RFC 9204 §4.4, §4.5)
// For static-only QPACK (we advertise SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0).
// ---------------------------------------------------------------------------
//
// Encoded Field Section Prefix (RFC 9204 Figure 12, §4.5.1):
//
//   0   1   2   3   4   5   6   7
// +---+---+---+---+---+---+---+---+
// |   Required Insert Count (8+)  |
// +---+---------------------------+
// | S |      Delta Base (7+)      |
// +---+---------------------------+
// |      Encoded Field Lines    ...
// +-------------------------------+
//
// Required Insert Count: prefixed integer, 8-bit prefix (offset_bits=0).
// Delta Base: sign bit S + 7-bit prefix integer (offset_bits=1 on the byte).
// Base is then computed as:
//   if S == 0: Base = RIC + Delta
//   else:      Base = RIC - Delta - 1
//
// For our static-only policy, RIC must decode to 0 (and Base to 0).
// Non-zero RIC or any dynamic/post-base reference is rejected with
// YAWT_QPACK_ERR_REQUIRED_INSERT_COUNT or ERR_DYNAMIC_TABLE_UNSUPPORTED.

YAWT_QPACK_Error_t YAWT_H3_QPACK_decode_header_block_prefix(
    const uint8_t *data, size_t data_len,
    uint64_t *out_required_insert_count,
    uint64_t *out_base,
    size_t *bytes_consumed);

// Decode the entire encoded field section (HEADERS frame payload) into `out`.
// Only static table entries and literal representations are supported.
// Huffman-encoded strings are decoded into out->huff_scratch (ANB_Blob_t,
// lazily allocated and grown as needed).  Name/value pairs are copied into
// out->slab using the existing header field storage.
//
// Returns YAWT_QPACK_OK on success.  On error the section may be left
// partially populated; caller (h3 layer) typically destroys it.
YAWT_QPACK_Error_t YAWT_qpack_decode(
    const uint8_t *data, size_t len,
    YAWT_H3_HeaderFields_t *out);



