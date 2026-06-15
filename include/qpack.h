/**
 * @file qpack.h
 * @brief QPACK compression/decompression utilities.
 */

/**
 * @ingroup HTTP3
 * @brief QPACK compression/decompression utilities.
 */

#pragma once
#include <stdint.h>
#include <stddef.h>
#include "h3_types.h"

#define YAWT_QPACK_STATIC_TABLE_SIZE 99  /**< QPACK static table size (RFC 9204 Appendix A) */
#define YAWT_QPACK_PREFIX_INT_MAX_BYTES 11  /**< Maximum bytes a single prefix-encoded integer can occupy */

/**
 * @ingroup HTTP3
 * @brief QPACK static table entry.
 * @note Both sides ship with the same table; the encoder emits indexes, the decoder
 *       looks them up. No allocation, no destruction — compile-time constants.
 */
typedef struct {
  const char *name;
  const char *value;
} YAWT_QPACK_StaticEntry_t;

/**
 * @internal
 * @ingroup HTTP3
 * @brief Get a static-table entry.
 * @param index The table index (0..98).
 * @return Pointer to the entry, or NULL if out of range.
 */
const YAWT_QPACK_StaticEntry_t *YAWT_qpack_static_get(uint64_t index);

/**
 * @internal
 * @ingroup HTTP3
 * @brief Find the first static-table index whose name matches.
 * @param name The name to search for.
 * @return The index, or -1 if not found.
 */
int YAWT_qpack_static_find_name(const char *name);

/**
 * @internal
 * @ingroup HTTP3
 * @brief Find the first static-table index whose name AND value match.
 * @param name The name to search for.
 * @param value The value to search for.
 * @return The index, or -1 if not found.
 */
int YAWT_qpack_static_find_entry(const char *name, const char *value);

/**
 * @ingroup HTTP3
 * @brief QPACK decoder return status.
 * @note Static table + literals only (dynamic table rejected).
 */
typedef enum {
  YAWT_QPACK_OK = 0,
  YAWT_QPACK_ERR_MALFORMED,
  YAWT_QPACK_ERR_DYNAMIC_TABLE_UNSUPPORTED,
  YAWT_QPACK_ERR_REQUIRED_INSERT_COUNT,
  YAWT_QPACK_ERR_SHORT_BUFFER,
  YAWT_QPACK_ERR_INVALID_PARAM,
  YAWT_QPACK_DONE,
} YAWT_QPACK_Error_t;

/**
 * @ingroup HTTP3
 * @brief QPACK field line representations (RFC 9204 §4.5).
 * @note These are used to decode the encoded field section inside a HEADERS frame.
 *       They do NOT modify the dynamic table; they only reference it.
 */
typedef enum {
    YAWT_QPACK_FIELD_LINE_INDEXED,                     // 1xxxxxxx  - 1 prefix bit
    YAWT_QPACK_FIELD_LINE_INDEXED_POST_BASE,           // 0001xxxx  - 4 prefix bits
    YAWT_QPACK_FIELD_LINE_LITERAL_NAME_REF,            // 01xxxxxx  - 2 prefix bits
    YAWT_QPACK_FIELD_LINE_LITERAL_POST_BASE_NAME_REF,  // 0000xxxx  - 4 prefix bits
    YAWT_QPACK_FIELD_LINE_LITERAL_LITERAL_NAME,        // 001xxxxx  - 3 prefix bits
    YAWT_QPACK_FIELD_LINE_UNKNOWN,
} YAWT_QPACK_FieldLineRepType_t;

/**
 * @internal
 * @ingroup HTTP3
 * @brief Decode the leading byte of a field line representation.
 * @param byte The leading byte.
 * @param out_prefix_bits Pointer to receive the number of prefix bits consumed.
 * @return The field line representation type.
 * @note The remaining bits are dispatched by the caller after this function returns (RFC 9204 §4.5).
 */
YAWT_QPACK_FieldLineRepType_t YAWT_H3_QPACK_decode_field_line_msb(uint8_t byte, uint8_t *out_prefix_bits);

/**
 * @internal
 * @ingroup HTTP3
 * @brief Encode a single field line representation.
 * @param field The header field to encode.
 * @param buf Output buffer.
 * @param len Output buffer length.
 * @param written Pointer to receive the number of bytes written.
 * @param out_type Pointer to receive the representation type that was encoded (can be NULL).
 * @return YAWT_QPACK_OK on success, or an error code.
 * @note Chooses the representation based on field->i_static and field->i_name.
 */
YAWT_QPACK_Error_t YAWT_H3_QPACK_encode_field_line(
    const YAWT_H3_Header_Field_t *field,
    uint8_t *buf, size_t len, size_t *written,
    YAWT_QPACK_FieldLineRepType_t *out_type);

/**
 * @internal
 * @ingroup HTTP3
 * @brief Get the maximum number of bytes a single field line could occupy when encoded.
 * @param field The header field to measure.
 * @return Maximum bytes, assuming worst-case prefix integer sizes (UINT64_MAX).
 * @note String lengths are taken from the field as-is. Useful for right-sizing buffers before encoding.
 */
size_t YAWT_H3_QPACK_encode_field_line_max_size(const YAWT_H3_Header_Field_t *field);

/**
 * @internal
 * @ingroup HTTP3
 * @brief Decode a prefixed integer (RFC 7541 §5.1 / RFC 9204 §4.1.1).
 * @param buffer The input buffer.
 * @param buffer_size The input buffer size.
 * @param offset_bits The number of prefix bits already consumed.
 * @param out_value Pointer to receive the decoded value.
 * @param bytes_consumed Pointer to receive the number of bytes consumed.
 * @return YAWT_QPACK_OK on success, or an error code.
 */
YAWT_QPACK_Error_t YAWT_H3_QPACK_decode_prefix_int(
    const uint8_t *buffer, size_t buffer_size,
    uint8_t offset_bits,
    uint64_t *out_value, uint64_t *bytes_consumed);

/**
 * @internal
 * @ingroup HTTP3
 * @brief Encode an unsigned integer with prefix encoding (RFC 7541 §5.1).
 * @param buffer Output buffer.
 * @param buffer_size Output buffer size.
 * @param offset_bits The number of prefix bits already used.
 * @param value The value to encode.
 * @param bytes_consumed Pointer to receive the number of bytes consumed.
 * @return YAWT_QPACK_OK on success, or an error code.
 */
YAWT_QPACK_Error_t YAWT_H3_QPACK_encode_prefix_int(
    uint8_t *buffer, size_t buffer_size,
    uint8_t offset_bits,
    uint64_t value,
    uint64_t *bytes_consumed);

#define YAWT_QPACK_HUFF_DEC_TREE_MAX 600  /**< Maximum nodes in the Huffman decode tree */

/**
 * @ingroup HTTP3
 * @brief Huffman decode tree node.
 * @note Array-indexed binary tree, lazy-initialized on first decode call.
 */
typedef struct {
    uint16_t l;       // left child index (0 means no child → leaf when both 0)
    uint16_t r;       // right child index
    uint8_t  value;   // decoded byte (valid at leaf)
    uint8_t  bits;    // bit depth to this leaf (valid at leaf)
} YAWT_QPACK_HuffNode_t;

/**
 * @ingroup HTTP3
 * @brief Huffman decoder state.
 */
typedef struct {
    YAWT_QPACK_HuffNode_t nodes[YAWT_QPACK_HUFF_DEC_TREE_MAX];
    uint16_t              count;
} YAWT_QPACK_HuffDecoder_t;

/**
 * @internal
 * @ingroup HTTP3
 * @brief Decode a single Huffman byte from a bitstream.
 * @param data The input bitstream.
 * @param data_len The input bitstream length.
 * @param bit_offset Pointer to the bit position (0-7) within data[0] at which to start.
 * @param out_byte Pointer to receive the decoded byte.
 * @param advance_bytes Pointer to receive the number of whole bytes fully consumed.
 * @return YAWT_QPACK_OK on success, or an error code.
 * @note Lazy-inits the tree. On success, *bit_offset is set to the residual bit position
 *       within the last byte touched. Callers decoding a stream should advance their data
 *       pointer by *advance_bytes and carry *bit_offset into the next call.
 */
YAWT_QPACK_Error_t YAWT_QPACK_huff_decode_byte(
    const uint8_t *data, size_t data_len,
    uint8_t *bit_offset, uint8_t *out_byte, size_t *advance_bytes);

/**
 * @internal
 * @ingroup HTTP3
 * @brief Decode an entire Huffman-encoded string into `out` buffer.
 * @param data The input bitstream.
 * @param data_len The input bitstream length.
 * @param out Output buffer.
 * @param out_size Output buffer size.
 * @param out_len Pointer to receive the number of decoded bytes.
 * @return YAWT_QPACK_OK on success, YAWT_QPACK_ERR_SHORT_BUFFER if `out_size` is too small.
 * @note Lazy-inits the tree on first call.
 */
YAWT_QPACK_Error_t YAWT_QPACK_huff_decode_string(
    const uint8_t *data, size_t data_len,
    uint8_t *out, size_t out_size, size_t *out_len);

/**
 * @internal
 * @ingroup HTTP3
 * @brief Encode a single byte into a Huffman bitstream.
 * @param in_byte The byte to encode.
 * @param out Output buffer.
 * @param out_size Output buffer size (must be >= 4).
 * @param bit_offset Pointer to the bit position (0-7) within out[0] at which to start writing.
 * @param advance_bytes Pointer to receive the number of whole bytes fully completed.
 * @return YAWT_QPACK_OK on success, YAWT_QPACK_ERR_SHORT_BUFFER if `out_size` < 4.
 * @note On success, *bit_offset is set to the residual bit position within the last byte
 *       written. Callers building a stream should advance their `out` pointer by *advance_bytes
 *       and carry *bit_offset into the next call.
 */
YAWT_QPACK_Error_t YAWT_QPACK_huff_encode_byte(
    uint8_t in_byte, uint8_t *out, size_t out_size,
    uint8_t *bit_offset, size_t *advance_bytes);

/**
 * @internal
 * @ingroup HTTP3
 * @brief Encode a raw byte string into Huffman-encoded form.
 * @param input The input string.
 * @param input_len The input string length.
 * @param out Output buffer.
 * @param out_size Output buffer size.
 * @param out_len Pointer to receive the number of encoded bytes written.
 * @return YAWT_QPACK_OK on success, YAWT_QPACK_ERR_SHORT_BUFFER if `out_size` is too small.
 */
YAWT_QPACK_Error_t YAWT_QPACK_huff_encode_string(
    const uint8_t *input, size_t input_len,
    uint8_t *out, size_t out_size, size_t *out_len);

/**
 * @internal
 * @ingroup HTTP3
 * @brief Decode QPACK header block prefix (RFC 9204 §4.5.1).
 * @param data The input data.
 * @param data_len The input data length.
 * @param out_required_insert_count Pointer to receive the Required Insert Count.
 * @param out_base Pointer to receive the Base value.
 * @param bytes_consumed Pointer to receive the number of bytes consumed.
 * @return YAWT_QPACK_OK on success, or an error code.
 * @note For static-only QPACK (we advertise SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0),
 *       RIC must decode to 0 (and Base to 0). Non-zero RIC or any dynamic/post-base
 *       reference is rejected with YAWT_QPACK_ERR_REQUIRED_INSERT_COUNT or
 *       ERR_DYNAMIC_TABLE_UNSUPPORTED.
 */
YAWT_QPACK_Error_t YAWT_H3_QPACK_decode_header_block_prefix(
    const uint8_t *data, size_t data_len,
    uint64_t *out_required_insert_count,
    uint64_t *out_base,
    size_t *bytes_consumed);



