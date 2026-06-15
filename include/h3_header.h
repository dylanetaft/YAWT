/**
 * @file h3_header.h
 * @brief Header field management and QPACK integration wrappers.
 */

/**
 * @ingroup HTTP3
 * @brief Header field management and QPACK integration wrappers.
 */

#pragma once
#include <stddef.h>
#include <stdbool.h>
#include "h3_types.h"
#include "qpack.h"
#include <allocnbuffer/slab.h>

/**
 * @ingroup HTTP3
 * @brief Create a new header fields backed by an ANB_Slab.
 * @return A heap-allocated YAWT_H3_HeaderFields_t*, or NULL on failure.
 * @note Optionally includes a scratch blob for decode. The pointer itself may be
 *       null-checked (non-NULL means resources were allocated and destroy should
 *       be called later).
 */
YAWT_H3_HeaderFields_t *YAWT_h3_header_fields_create(void);

/**
 * @ingroup HTTP3
 * @brief Destroy a header fields section.
 * @param section The header fields to destroy.
 * @note Destroys its slab (and any huff_scratch blob) and frees the
 *       YAWT_H3_HeaderFields_t struct itself.
 */
void YAWT_h3_header_fields_destroy(YAWT_H3_HeaderFields_t *section);

/**
 * @ingroup HTTP3
 * @brief Add a field — copies name and value into slab storage.
 * @param section The header fields section.
 * @param name The field name.
 * @param name_len The field name length.
 * @param value The field value.
 * @param value_len The field value length.
 * @return YAWT_H3_OK on success, or an error code.
 * @note Does not resolve QPACK indexes (i_static=0, i_name=0).
 */
YAWT_H3_Error_t YAWT_h3_header_add(YAWT_H3_HeaderFields_t *section,
                                    const char *name, size_t name_len,
                                    const char *value, size_t value_len);

/**
 * @ingroup HTTP3
 * @brief Add a field using null-terminated strings.
 * @param section The header fields section.
 * @param name The field name.
 * @param value The field value.
 * @return YAWT_H3_OK on success, or an error code.
 */
YAWT_H3_Error_t YAWT_h3_header_add_str(YAWT_H3_HeaderFields_t *section,
                                        const char *name, const char *value);

/**
 * @ingroup HTTP3
 * @brief Add a field with pre-resolved QPACK static table indexes.
 * @param section The header fields section.
 * @param name The field name.
 * @param name_len The field name length.
 * @param value The field value.
 * @param value_len The field value length.
 * @param i_static Full name-value match in QPACK static table.
 * @param i_name Name-only match in QPACK static table.
 * @return YAWT_H3_OK on success, or an error code.
 */
YAWT_H3_Error_t YAWT_h3_header_add_static(YAWT_H3_HeaderFields_t *section,
                                           const char *name, size_t name_len,
                                           const char *value, size_t value_len,
                                           size_t i_static, size_t i_name);

/**
 * @ingroup HTTP3
 * @brief Add a field with pre-resolved indexes using null-terminated strings.
 * @param section The header fields section.
 * @param name The field name.
 * @param value The field value.
 * @param i_static Full name-value match in QPACK static table.
 * @param i_name Name-only match in QPACK static table.
 * @return YAWT_H3_OK on success, or an error code.
 */
YAWT_H3_Error_t YAWT_h3_header_add_str_static(YAWT_H3_HeaderFields_t *section,
                                               const char *name, const char *value,
                                               size_t i_static, size_t i_name);

/**
 * @ingroup HTTP3
 * @brief Resolve QPACK static table indexes for a name/value pair.
 * @param name The field name.
 * @param name_len The field name length.
 * @param value The field value.
 * @param value_len The field value length.
 * @return A populated YAWT_H3_Header_Field_t; pass to add_static or use directly.
 */
YAWT_H3_Header_Field_t YAWT_h3_header_resolve(const char *name, size_t name_len,
                                               const char *value, size_t value_len);

/**
 * @ingroup HTTP3
 * @brief Resolve QPACK static table indexes using null-terminated strings.
 * @param name The field name.
 * @param value The field value.
 * @return A populated YAWT_H3_Header_Field_t.
 */
YAWT_H3_Header_Field_t YAWT_h3_header_resolve_str(const char *name, const char *value);

/**
 * @ingroup HTTP3
 * @brief Look up a field by name.
 * @param section The header fields section.
 * @param name The field name to find.
 * @param name_len The field name length.
 * @return A const view into slab memory. Returns a struct with NULL name if not found.
 */
YAWT_H3_Header_Field_t YAWT_h3_header_find(const YAWT_H3_HeaderFields_t *section,
                                            const char *name, size_t name_len);

/**
 * @ingroup HTTP3
 * @brief Look up a field by name using a null-terminated string.
 * @param section The header fields section.
 * @param name The field name to find.
 * @return A const view into slab memory. Returns a struct with NULL name if not found.
 */
YAWT_H3_Header_Field_t YAWT_h3_header_find_str(const YAWT_H3_HeaderFields_t *section,
                                                const char *name);

/**
 * @ingroup HTTP3
 * @brief Iterate all fields.
 * @param section The header fields section.
 * @param iter The slab iterator. Pass NULL to start.
 * @return A struct with the current field, or a struct with NULL name when done.
 */
YAWT_H3_Header_Field_t YAWT_h3_header_iter(const YAWT_H3_HeaderFields_t *section,
                                            ANB_SlabIter_t *iter);

/**
 * @ingroup HTTP3
 * @brief Check if header fields have been allocated.
 * @param headers The header fields section.
 * @return true if the slab is not NULL.
 */
static inline bool YAWT_h3_headers_is_set(const YAWT_H3_HeaderFields_t *headers) {
  return headers && headers->slab != NULL;
}

/**
 * @internal
 * @ingroup HTTP3
 * @brief Decode the entire encoded field section (HEADERS frame payload).
 * @param data The encoded data.
 * @param len The encoded data length.
 * @param out The output header fields section.
 * @return YAWT_QPACK_OK on success, or an error code.
 * @note Only static table entries and literal representations are supported.
 *       Huffman-encoded strings are decoded into out->huff_scratch (ANB_Blob_t).
 *       Name/value pairs are copied into out->slab using the existing header field storage.
 *       On error the section may be left partially populated; caller (h3 layer)
 *       typically destroys it.
 */
YAWT_QPACK_Error_t YAWT_qpack_decode_header_block(
    const uint8_t *data, size_t len,
    YAWT_H3_HeaderFields_t *out);

/**
 * @internal
 * @ingroup HTTP3
 * @brief Encode a header fields section into a QPACK header block.
 * @param headers The header fields to encode.
 * @param buf Output buffer.
 * @param len Output buffer length.
 * @param written Pointer to receive the number of bytes written.
 * @return YAWT_QPACK_OK on success, YAWT_QPACK_ERR_SHORT_BUFFER if buf is too small.
 * @note Static table only, no Huffman. Writes the 2-byte header block prefix (RIC=0, Base=0)
 *       followed by encoded field lines. Uses Indexed representation for full name+value
 *       matches, Literal with Name Reference for name-only matches, and Literal with
 *       Literal Name for everything else.
 */
YAWT_QPACK_Error_t YAWT_qpack_encode_header_block(
    const YAWT_H3_HeaderFields_t *headers,
    uint8_t *buf, size_t len, size_t *written);

/**
 * @internal
 * @ingroup HTTP3
 * @brief Calculate the encoded size of a header block without actually encoding it.
 * @param headers The header fields to measure.
 * @return The number of bytes that would be written by YAWT_qpack_encode_header_block.
 */
size_t YAWT_qpack_header_block_size(const YAWT_H3_HeaderFields_t *headers);

/**
 * @internal
 * @ingroup HTTP3
 * @brief Calculate an upper bound on the encoded size of a header block.
 * @param headers The header fields to measure.
 * @return The maximum number of bytes, assuming worst-case prefix integer sizes.
 * @note Useful for right-sizing a buffer before calling YAWT_qpack_encode_header_block.
 */
size_t YAWT_qpack_header_block_max_size(const YAWT_H3_HeaderFields_t *headers);
