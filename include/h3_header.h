#pragma once
#include <stddef.h>
#include <stdbool.h>
#include "h3_types.h"
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
