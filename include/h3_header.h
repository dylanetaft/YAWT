#pragma once
#include <stddef.h>
#include <stdbool.h>
#include "h3_types.h"
#include "qpack.h"
#include <allocnbuffer/slab.h>

// Create a new header fields backed by an ANB_Slab (and optionally a scratch
// blob for decode). Returns a heap-allocated YAWT_H3_HeaderFields_t*.
// The pointer itself may be null-checked (non-NULL means resources were
// allocated and destroy should be called later).
YAWT_H3_HeaderFields_t *YAWT_h3_header_fields_create(void);

// Destroy a header fields: destroys its slab (and any huff_scratch blob) and
// frees the YAWT_H3_HeaderFields_t struct itself.
void YAWT_h3_header_fields_destroy(YAWT_H3_HeaderFields_t *section);

// Add a field — copies name and value into slab storage.
// Does not resolve QPACK indexes (i_static=0, i_name=0).
YAWT_H3_Error_t YAWT_h3_header_add(YAWT_H3_HeaderFields_t *section,
                                    const char *name, size_t name_len,
                                    const char *value, size_t value_len);

// Convenience: null-terminated strings.
YAWT_H3_Error_t YAWT_h3_header_add_str(YAWT_H3_HeaderFields_t *section,
                                        const char *name, const char *value);

// Add a field with pre-resolved QPACK static table indexes.
YAWT_H3_Error_t YAWT_h3_header_add_static(YAWT_H3_HeaderFields_t *section,
                                           const char *name, size_t name_len,
                                           const char *value, size_t value_len,
                                           size_t i_static, size_t i_name);

// Convenience: null-terminated strings with indexes.
YAWT_H3_Error_t YAWT_h3_header_add_str_static(YAWT_H3_HeaderFields_t *section,
                                               const char *name, const char *value,
                                               size_t i_static, size_t i_name);

// Resolve QPACK static table indexes for a name/value pair.
// Returns a populated YAWT_H3_Header_Field_t; pass to add_static or use directly.
YAWT_H3_Header_Field_t YAWT_h3_header_resolve(const char *name, size_t name_len,
                                               const char *value, size_t value_len);

// Convenience: null-terminated strings.
YAWT_H3_Header_Field_t YAWT_h3_header_resolve_str(const char *name, const char *value);

// Look up a field by name — returns a const view into slab memory.
// Returns a struct with NULL name if not found.
YAWT_H3_Header_Field_t YAWT_h3_header_find(const YAWT_H3_HeaderFields_t *section,
                                            const char *name, size_t name_len);

// Convenience: null-terminated name lookup.
YAWT_H3_Header_Field_t YAWT_h3_header_find_str(const YAWT_H3_HeaderFields_t *section,
                                                const char *name);

// Iterate all fields — pass NULL iter to start, returns a struct with NULL name when done.
YAWT_H3_Header_Field_t YAWT_h3_header_iter(const YAWT_H3_HeaderFields_t *section,
                                            ANB_SlabIter_t *iter);

// Returns true if the header fields have been allocated (slab != NULL).
static inline bool YAWT_h3_headers_is_set(const YAWT_H3_HeaderFields_t *headers) {
  return headers && headers->slab != NULL;
}

// Decode the entire encoded field section (HEADERS frame payload) into `out`.
// Only static table entries and literal representations are supported.
// Huffman-encoded strings are decoded into out->huff_scratch (ANB_Blob_t).
// Name/value pairs are copied into out->slab using the existing header field storage.
//
// Returns YAWT_QPACK_OK on success.  On error the section may be left
// partially populated; caller (h3 layer) typically destroys it.
YAWT_QPACK_Error_t YAWT_qpack_decode_header_block(
    const uint8_t *data, size_t len,
    YAWT_H3_HeaderFields_t *out);

// Encode a header fields section into a QPACK header block (static table only,
// no Huffman). Writes the 2-byte header block prefix (RIC=0, Base=0) followed
// by encoded field lines. Uses Indexed representation for full name+value
// matches, Literal with Name Reference for name-only matches, and Literal with
// Literal Name for everything else.
//
// Returns YAWT_QPACK_OK on success, YAWT_QPACK_ERR_SHORT_BUFFER if buf is too
// small. Sets *written to the number of bytes written.
YAWT_QPACK_Error_t YAWT_qpack_encode_header_block(
    const YAWT_H3_HeaderFields_t *headers,
    uint8_t *buf, size_t len, size_t *written);

// Calculate the encoded size of a header block without actually encoding it.
// Returns the number of bytes that would be written by YAWT_qpack_encode_header_block.
size_t YAWT_qpack_header_block_size(const YAWT_H3_HeaderFields_t *headers);

// Returns an upper bound on the encoded size of a header block, assuming
// worst-case prefix integer sizes. Useful for right-sizing a buffer before
// calling YAWT_qpack_encode_header_block.
size_t YAWT_qpack_header_block_max_size(const YAWT_H3_HeaderFields_t *headers);
