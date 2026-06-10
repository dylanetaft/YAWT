#include "h3_header.h"
#include "qpack.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


// ---------------------------------------------------------------------------
// Private: buffered field stored in the slab. VLA holds name\0 + value\0.
// ---------------------------------------------------------------------------

typedef struct {
  size_t   i_static;   // QPACK static table index for full name-value (0 = not indexed)
  size_t   i_name;     // QPACK static table index for name only (0 = not indexed)
  size_t   name_len;
  size_t   value_len;
  char     data[];     // VLA: name\0 + value\0
} _YAWT_H3_Header_BufferedField_t;

// ---------------------------------------------------------------------------
// Internal: store a field with given indexes.
// ---------------------------------------------------------------------------

static YAWT_H3_Error_t _store_field(YAWT_H3_HeaderFields_t *section,
                                     const char *name, size_t name_len,
                                     const char *value, size_t value_len,
                                     size_t i_static, size_t i_name) {
  size_t total = sizeof(_YAWT_H3_Header_BufferedField_t) + name_len + 1 + value_len + 1;
  _YAWT_H3_Header_BufferedField_t *bf =
      (_YAWT_H3_Header_BufferedField_t *)ANB_slab_alloc_item(section->slab, total);

  bf->i_static = i_static;
  bf->i_name = i_name;
  bf->name_len = name_len;
  bf->value_len = value_len;

  memcpy(bf->data, name, name_len);
  bf->data[name_len] = '\0';
  memcpy(bf->data + name_len + 1, value, value_len);
  bf->data[name_len + 1 + value_len] = '\0';

  return YAWT_H3_OK;
}

// ---------------------------------------------------------------------------
// Create / destroy
// ---------------------------------------------------------------------------

YAWT_H3_HeaderFields_t *YAWT_h3_header_section_create(void) {
  YAWT_H3_HeaderFields_t *section = calloc(1, sizeof(*section));
  if (!section) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3_header: OOM allocating header fields");
    abort();
  }
  section->slab = ANB_slab_create(256);
  if (!section->slab) {
    YAWT_LOG(YAWT_LOG_ERROR, "h3_header: OOM allocating slab");
    abort();
  }
  return section;
}

void YAWT_h3_header_section_destroy(YAWT_H3_HeaderFields_t *section) {
  if (!section) return;
  ANB_slab_destroy(section->slab);
  free(section);
}

// ---------------------------------------------------------------------------
// Add a field (no index resolution)
// ---------------------------------------------------------------------------

YAWT_H3_Error_t YAWT_h3_header_add(YAWT_H3_HeaderFields_t *section,
                                    const char *name, size_t name_len,
                                    const char *value, size_t value_len) {
  if (!section || !name || !value) return YAWT_H3_ERR_INVALID_PARAM;
  return _store_field(section, name, name_len, value, value_len, 0, 0);
}

YAWT_H3_Error_t YAWT_h3_header_add_str(YAWT_H3_HeaderFields_t *section,
                                        const char *name, const char *value) {
  if (!name || !value) return YAWT_H3_ERR_INVALID_PARAM;
  return YAWT_h3_header_add(section, name, strlen(name), value, strlen(value));
}

// ---------------------------------------------------------------------------
// Add a field with pre-resolved QPACK static table indexes
// ---------------------------------------------------------------------------

YAWT_H3_Error_t YAWT_h3_header_add_static(YAWT_H3_HeaderFields_t *section,
                                           const char *name, size_t name_len,
                                           const char *value, size_t value_len,
                                           size_t i_static, size_t i_name) {
  if (!section || !name || !value) return YAWT_H3_ERR_INVALID_PARAM;
  return _store_field(section, name, name_len, value, value_len, i_static, i_name);
}

YAWT_H3_Error_t YAWT_h3_header_add_str_static(YAWT_H3_HeaderFields_t *section,
                                               const char *name, const char *value,
                                               size_t i_static, size_t i_name) {
  if (!name || !value) return YAWT_H3_ERR_INVALID_PARAM;
  return YAWT_h3_header_add_static(section, name, strlen(name), value, strlen(value),
                                    i_static, i_name);
}

// ---------------------------------------------------------------------------
// Convenience: resolve QPACK static table indexes for a name/value pair.
// Returns a populated YAWT_H3_Header_Field_t; caller passes it to add_static.
// ---------------------------------------------------------------------------

YAWT_H3_Header_Field_t YAWT_h3_header_resolve(const char *name, size_t name_len,
                                               const char *value, size_t value_len) {
  YAWT_H3_Header_Field_t f = {0};
  f.name = name;
  f.value = value;
  f.name_len = name_len;
  f.value_len = value_len;

  int idx = YAWT_qpack_static_find_entry(name, value);
  if (idx >= 0) {
    f.i_static = (size_t)idx;
    return f;
  }

  idx = YAWT_qpack_static_find_name(name);
  if (idx >= 0) {
    f.i_name = (size_t)idx;
  }

  return f;
}

YAWT_H3_Header_Field_t YAWT_h3_header_resolve_str(const char *name, const char *value) {
  return YAWT_h3_header_resolve(name, strlen(name), value, strlen(value));
}

// Helper: build a view from a buffered field.
static YAWT_H3_Header_Field_t _make_view(const _YAWT_H3_Header_BufferedField_t *bf) {
  YAWT_H3_Header_Field_t v = {0};
  v.name = bf->data;
  v.value = bf->data + bf->name_len + 1;
  v.name_len = bf->name_len;
  v.value_len = bf->value_len;
  v.i_static = bf->i_static;
  v.i_name = bf->i_name;
  return v;
}

// ---------------------------------------------------------------------------
// Lookup by name
// ---------------------------------------------------------------------------

YAWT_H3_Header_Field_t YAWT_h3_header_find(const YAWT_H3_HeaderFields_t *section,
                                            const char *name, size_t name_len) {
  YAWT_H3_Header_Field_t not_found = {0};
  if (!section || !name) return not_found;

  ANB_SlabIter_t iter = {0};
  size_t item_size = 0;

  while (1) {
    uint8_t *item = ANB_slab_peek_item_iter(section->slab, &iter, &item_size);
    if (!item) break;

    _YAWT_H3_Header_BufferedField_t *bf = (_YAWT_H3_Header_BufferedField_t *)item;
    if (bf->name_len == name_len &&
        memcmp(bf->data, name, name_len) == 0) {
      return _make_view(bf);
    }
  }

  return not_found;
}

YAWT_H3_Header_Field_t YAWT_h3_header_find_str(const YAWT_H3_HeaderFields_t *section,
                                                const char *name) {
  YAWT_H3_Header_Field_t not_found = {0};
  if (!name) return not_found;
  return YAWT_h3_header_find(section, name, strlen(name));
}

// ---------------------------------------------------------------------------
// Iteration
// ---------------------------------------------------------------------------

YAWT_H3_Header_Field_t YAWT_h3_header_iter(const YAWT_H3_HeaderFields_t *section,
                                            ANB_SlabIter_t *iter) {
  YAWT_H3_Header_Field_t done = {0};
  if (!section) return done;

  ANB_SlabIter_t local_iter;
  ANB_SlabIter_t *p = iter ? iter : &local_iter;
  if (!iter) memset(p, 0, sizeof(*p));

  size_t item_size = 0;
  uint8_t *item = ANB_slab_peek_item_iter(section->slab, p, &item_size);
  if (!item) return done;

  _YAWT_H3_Header_BufferedField_t *bf = (_YAWT_H3_Header_BufferedField_t *)item;
  return _make_view(bf);
}
