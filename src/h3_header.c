#include "h3_header.h"
#include "qpack.h"
#include "corpus.h"
#include "logger.h"
#include "security.h"
#include <allocnbuffer/blob.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


// ---------------------------------------------------------------------------
// Private: buffered field stored in the slab. VLA holds name\0 + value\0.
// ---------------------------------------------------------------------------

typedef struct {
  size_t   name_len;
  size_t   value_len;
  char     data[];     // VLA: name\0 + value\0
} _YAWT_H3_Header_BufferedField_t;

// ---------------------------------------------------------------------------
// Internal: store a field.
// ---------------------------------------------------------------------------

static YAWT_H3_Error_t _store_field(YAWT_H3_HeaderFields_t *section,
                                      const char *name, size_t name_len,
                                      const char *value, size_t value_len) {
  size_t total = sizeof(_YAWT_H3_Header_BufferedField_t) + name_len + 1 + value_len + 1;
  _YAWT_H3_Header_BufferedField_t *bf =
      (_YAWT_H3_Header_BufferedField_t *)ANB_slab_alloc_item(section->slab, total);

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

YAWT_H3_HeaderFields_t *YAWT_h3_header_fields_create(void) {
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

void YAWT_h3_header_fields_destroy(YAWT_H3_HeaderFields_t *section) {
  if (!section) return;
  if (section->slab) {
    ANB_slab_destroy(section->slab);
    section->slab = NULL;
  }
  free(section);
}

// ---------------------------------------------------------------------------
// Add a field (no index resolution)
// ---------------------------------------------------------------------------

YAWT_H3_Error_t YAWT_h3_header_add(YAWT_H3_HeaderFields_t *section,
                                     const char *name, size_t name_len,
                                     const char *value, size_t value_len) {
  if (!section || !name || !value) return YAWT_H3_ERR_INVALID_PARAM;
  return _store_field(section, name, name_len, value, value_len);
}

YAWT_H3_Error_t YAWT_h3_header_add_str(YAWT_H3_HeaderFields_t *section,
                                         const char *name, const char *value) {
  if (!name || !value) return YAWT_H3_ERR_INVALID_PARAM;
  return YAWT_h3_header_add(section, name, strlen(name), value, strlen(value));
}

// Helper: build a view from a buffered field.
static YAWT_H3_Header_Field_t _field_view_from_buffered(const _YAWT_H3_Header_BufferedField_t *bf) {
  YAWT_H3_Header_Field_t v = {0};
  v.name = bf->data;
  v.value = bf->data + bf->name_len + 1;
  v.name_len = bf->name_len;
  v.value_len = bf->value_len;
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
      return _field_view_from_buffered(bf);
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
  return _field_view_from_buffered(bf);
}


// ---------------------------------------------------------------------------
// QPACK field section decode (static table + literals only).
// Implementation lives here (rather than qpack.c) to keep qpack.c free of
// H3 header/blob includes for cleaner test builds, while the API is declared
// in qpack.h for the existing call-site name.
// ---------------------------------------------------------------------------
/*
// Decode one string literal from the block (H bit + 7+ length + payload).
// On Huffman, decodes into scratch blob at offset (grows on demand).
// Returns pointer/len into the blob data. Caller advances offset by *out_len.
// Advances the caller's cur/remaining.
// FIXME pretty sure this function should not exist
static YAWT_QPACK_Error_t _h3_decode_string_literal_with_length(
    const uint8_t **cur, size_t *remaining,
    ANB_Blob_t *scratch,
    size_t str_len, int huff,
    const uint8_t **out, size_t *out_len)
{
    YAWT_LOG(YAWT_LOG_DEBUG, "_h3_decode_string_literal_with_length: str_len=%zu, huff=%d, remaining=%zu", str_len, huff, *remaining);
    if (*remaining < str_len) {
      YAWT_LOG(YAWT_LOG_ERROR, "  SHORT_BUFFER: remaining=%zu < str_len=%zu", *remaining, str_len);
      return YAWT_QPACK_ERR_SHORT_BUFFER;
    }

    const uint8_t *str_data = *cur;
    uint8_t *buf = ANB_blob_data(scratch);
    size_t cap = ANB_blob_capacity(scratch);

    if (huff) {
        size_t decoded = 0;
        YAWT_QPACK_Error_t err = YAWT_QPACK_huff_decode_string(str_data, str_len,
                                            buf, cap, &decoded);
        if (err != YAWT_QPACK_OK) return err;
        *out = buf;
        *out_len = decoded;
    } else {
        memcpy(buf, str_data, str_len);
        *out = buf;
        *out_len = str_len;
    }

    *cur += str_len;
    *remaining -= str_len;
    return YAWT_QPACK_OK;
}
*/
static YAWT_QPACK_Error_t _h3_decode_string_literal(
    const uint8_t **cur, size_t *remaining,
    ANB_Blob_t *scratch,
    const uint8_t **out, size_t *out_len)
{
    YAWT_LOG(YAWT_LOG_DEBUG, "_h3_decode_string_literal: remaining=%zu", *remaining);
    if (*remaining == 0) return YAWT_QPACK_ERR_SHORT_BUFFER;

    uint8_t first = **cur;
    int huff = (first & 0x80) != 0;
    uint64_t str_len = 0;
    uint64_t cons = 0;
    YAWT_QPACK_Error_t err = YAWT_H3_QPACK_decode_prefix_int(
        *cur, *remaining, 1, &str_len, &cons);
    YAWT_LOG(YAWT_LOG_DEBUG, "  prefix_int: err=%d, str_len=%lu, cons=%lu, huff=%d", err, str_len, cons, huff);
    if (err != YAWT_QPACK_OK) return err;

    if (cons > *remaining || str_len > *remaining - cons) {
      YAWT_LOG(YAWT_LOG_ERROR, "  SHORT_BUFFER: remaining=%zu < cons=%lu+str_len=%lu", *remaining, cons, str_len);
      return YAWT_QPACK_ERR_SHORT_BUFFER;
    }

    const uint8_t *str_data = *cur + cons;

    uint8_t *buf = ANB_blob_data(scratch);
    size_t cap = ANB_blob_capacity(scratch);

    if (huff) {
        size_t decoded = 0;
        err = YAWT_QPACK_huff_decode_string(str_data, (size_t)str_len,
                                            buf, cap, &decoded);
        if (err != YAWT_QPACK_OK) return err;
        *out = buf;
        *out_len = decoded;
    } else {
        memcpy(buf, str_data, (size_t)str_len);
        *out = buf;
        *out_len = (size_t)str_len;
    }

    *cur += cons + (size_t)str_len;
    *remaining -= cons + (size_t)str_len;
    return YAWT_QPACK_OK;
}

// The entry point declared in qpack.h .
YAWT_QPACK_Error_t YAWT_qpack_decode_header_block(
    const uint8_t *data, size_t len,
    YAWT_H3_HeaderFields_t *out)
{
    YAWT_corpus_emit(1, data, len);
    YAWT_LOG(YAWT_LOG_DEBUG, "YAWT_qpack_decode_header_block: len=%zu", len);
    if (!data || !out) return YAWT_QPACK_ERR_INVALID_PARAM;

    static ANB_Blob_t *s_scratch_n = NULL;
    static ANB_Blob_t *s_scratch_v = NULL;
    if (!s_scratch_n || !s_scratch_v) {
        const YAWT_H3_SecurityPolicy_t *sec = YAWT_h3_security_get();
        size_t scratch_size = sec->max_field_section_size * 2;
        s_scratch_n = ANB_blob_create(scratch_size);
        s_scratch_v = ANB_blob_create(scratch_size);
        if (!s_scratch_n || !s_scratch_v) {
            YAWT_LOG(YAWT_LOG_ERROR, "h3_header: OOM creating scratch blobs");
            abort();
        }
    }

    size_t pcons = 0;
    uint64_t ric = 0, base = 0;
    YAWT_QPACK_Error_t err = YAWT_H3_QPACK_decode_header_block_prefix(
        data, len, &ric, &base, &pcons);
    if (err != YAWT_QPACK_OK) return err;

    if (ric != 0) {
        return YAWT_QPACK_ERR_REQUIRED_INSERT_COUNT;
    }

    const uint8_t *cur = data + pcons;
    size_t rem = len - pcons;
    YAWT_LOG(YAWT_LOG_DEBUG, "  prefix decoded: pcons=%zu, rem=%zu, ric=%lu, base=%lu", pcons, rem, ric, base);

    while (rem > 0) {
        uint8_t b = *cur;
        uint8_t pbits = 0;
        YAWT_QPACK_FieldLineRepType_t rep =
            YAWT_H3_QPACK_decode_field_line_msb(b, &pbits);
        YAWT_LOG(YAWT_LOG_DEBUG, "  dispatch: byte=0x%02x, rep=%d, pbits=%d, rem=%zu", b, rep, pbits, rem);

        switch (rep) {
        case YAWT_QPACK_FIELD_LINE_INDEXED: {
            int T = (b >> 6) & 1;
            uint64_t idx = 0, cons = 0;
            err = YAWT_H3_QPACK_decode_prefix_int(cur, rem, pbits + 1, &idx, &cons);
            YAWT_LOG(YAWT_LOG_DEBUG, "  INDEXED: T=%d, idx=%lu, cons=%lu, rem_before=%zu", T, idx, cons, rem);
            if (err != YAWT_QPACK_OK) return err;
            cur += cons; rem -= cons;

            if (T == 0) return YAWT_QPACK_ERR_DYNAMIC_TABLE_UNSUPPORTED;
            const YAWT_QPACK_StaticEntry_t *e = YAWT_qpack_static_get(idx);
            if (!e) return YAWT_QPACK_ERR_MALFORMED;

            if (YAWT_h3_header_add(out,
                    e->name, strlen(e->name),
                    e->value, strlen(e->value)) != YAWT_H3_OK)
                return YAWT_QPACK_ERR_MALFORMED;
            break;
        }

        case YAWT_QPACK_FIELD_LINE_LITERAL_NAME_REF: {
            int T = (b >> 4) & 1;
            uint64_t idx = 0, cons = 0;
            YAWT_LOG(YAWT_LOG_DEBUG, "  LITERAL_NAME_REF: byte=0x%02x, rem=%zu", b, rem);
            err = YAWT_H3_QPACK_decode_prefix_int(cur, rem, pbits + 2, &idx, &cons);
            YAWT_LOG(YAWT_LOG_DEBUG, "    T=%d, idx=%lu, cons=%lu", T, idx, cons);
            if (err != YAWT_QPACK_OK) return err;
            cur += cons; rem -= cons;

            if (T == 0) return YAWT_QPACK_ERR_DYNAMIC_TABLE_UNSUPPORTED;
            const YAWT_QPACK_StaticEntry_t *e = YAWT_qpack_static_get(idx);
            if (!e) return YAWT_QPACK_ERR_MALFORMED;

            const uint8_t *val = NULL; size_t vlen = 0;
            err = _h3_decode_string_literal(&cur, &rem, s_scratch_v, &val, &vlen);
            if (err != YAWT_QPACK_OK) return err;

            if (YAWT_h3_header_add(out,
                    e->name, strlen(e->name),
                    (const char *)val, vlen) != YAWT_H3_OK)
                return YAWT_QPACK_ERR_MALFORMED;
            break;
        }

        case YAWT_QPACK_FIELD_LINE_LITERAL_LITERAL_NAME: {
            uint64_t name_len = 0, cons = 0;
            int T_name = (b >> 3) & 1;
            YAWT_LOG(YAWT_LOG_DEBUG, "  LITERAL_LITERAL_NAME: byte=0x%02x, rem=%zu, T_name=%d", b, rem, T_name);
            //FIXME
            // Pretty sure we just want to use _h3_decode_string_literal here
            // as it handles the prefix integer and Huffman bit for us 
            /*
            err = YAWT_H3_QPACK_decode_prefix_int(cur, rem, pbits + 2, &name_len, &cons);
            YAWT_LOG(YAWT_LOG_DEBUG, "    name_len=%lu, cons=%lu", name_len, cons);
            if (err != YAWT_QPACK_OK) return err;
            cur += cons; rem -= cons;

            const uint8_t *name = NULL; size_t nlen = 0;
            err = _h3_decode_string_literal_with_length(&cur, &rem, s_scratch_n, (size_t)name_len, T_name, &name, &nlen);
            */
            
            const uint8_t *name = NULL; size_t nlen = 0;
            err = _h3_decode_string_literal(&cur, &rem, s_scratch_n, &name, &nlen);
            YAWT_LOG(YAWT_LOG_DEBUG, "    decoded name: nlen=%zu, name=%.*s, err=%d", nlen, (int)nlen, name, err);
            YAWT_LOG(YAWT_LOG_DEBUG,"There is a FIXME overhere if a unit test broke.");
            if (err != YAWT_QPACK_OK) return err;
            //TODO confirm this is right - name and val follow eachother immediately
            const uint8_t *val = NULL; size_t vlen = 0;
            err = _h3_decode_string_literal(&cur, &rem, s_scratch_v, &val, &vlen);
            if (err != YAWT_QPACK_OK) return err;

            if (YAWT_h3_header_add(out, (const char *)name, nlen,
                                   (const char *)val, vlen) != YAWT_H3_OK)
                return YAWT_QPACK_ERR_MALFORMED;
            break;
        }

        case YAWT_QPACK_FIELD_LINE_INDEXED_POST_BASE:
        case YAWT_QPACK_FIELD_LINE_LITERAL_POST_BASE_NAME_REF:
            return YAWT_QPACK_ERR_DYNAMIC_TABLE_UNSUPPORTED;

        default:
            return YAWT_QPACK_ERR_MALFORMED;
        }
    }

    return YAWT_QPACK_OK;
}

// ---------------------------------------------------------------------------
// QPACK field section encode (static table only, no Huffman).
// ---------------------------------------------------------------------------

YAWT_QPACK_Error_t YAWT_qpack_encode_header_block(
    const YAWT_H3_HeaderFields_t *headers,
    uint8_t *buf, size_t len, size_t *written) {
  if (!headers || !buf || !written) return YAWT_QPACK_ERR_INVALID_PARAM;

  size_t off = 0;

  if (len < 2) return YAWT_QPACK_ERR_SHORT_BUFFER;
  buf[off++] = 0x00;
  buf[off++] = 0x00;

  ANB_SlabIter_t iter = {0};
  size_t item_size = 0;

  while (1) {
    _YAWT_H3_Header_BufferedField_t *bf = (_YAWT_H3_Header_BufferedField_t *)ANB_slab_peek_item_iter(headers->slab, &iter, &item_size);
    if (!bf) break;
    YAWT_H3_Header_Field_t v = _field_view_from_buffered(bf);
    YAWT_LOG(YAWT_LOG_INFO, "h3: qpack encoding header field: %s: %s", v.name, v.value);
    size_t flen = 0;
    YAWT_QPACK_Error_t err = YAWT_H3_QPACK_encode_field_line(
        &v, buf + off, len - off, &flen, NULL);
    if (err != YAWT_QPACK_OK) return err;
    YAWT_LOG(YAWT_LOG_DEBUG, "  encoded %zu bytes: %s=%02x %02x %02x %02x %02x %02x %02x %02x", flen, v.name,
        buf[off+0], buf[off+1], buf[off+2], buf[off+3], buf[off+4], buf[off+5], buf[off+6], buf[off+7]);
    off += flen;
  }

  *written = off;
  return YAWT_QPACK_OK;
}

// ---------------------------------------------------------------------------
// QPACK header block size calculation (static table only, no Huffman).
// ---------------------------------------------------------------------------

// Computes encoded size of an HPACK/QPACK prefix integer (RFC 7541 §5.1).
// This is NOT the same as QUIC varint encoding (RFC 9000 §16) — prefix integers
// use a variable-width prefix (8 - offset_bits) followed by continuation bytes
// with MSB=1, while QUIC varints are always 1/2/4/8 bytes with a 2-bit length prefix.
static size_t _prefix_int_size(uint64_t val, uint8_t offset_bits) {
  uint8_t N = 8 - offset_bits;
  uint64_t max = (1ULL << N) - 1;
  if (val < max) return 1;
  size_t size = 1;
  uint64_t remaining = val - max;
  while (remaining >= 128) {
    remaining /= 128;
    size++;
  }
  return size + 1;
}

static size_t _string_literal_size(size_t str_len) {
  return 1 + _prefix_int_size(str_len, 7) + str_len;
}

size_t YAWT_qpack_header_block_size(const YAWT_H3_HeaderFields_t *headers) {
  if (!headers || !headers->slab) return 0;

  size_t size = 2;  // 2-byte header block prefix (RIC=0, Base=0)

  ANB_SlabIter_t iter = {0};
  size_t item_size = 0;

  while (1) {
    uint8_t *item = ANB_slab_peek_item_iter(headers->slab, &iter, &item_size);
    if (!item) break;

    _YAWT_H3_Header_BufferedField_t *bf = (_YAWT_H3_Header_BufferedField_t *)item;
    YAWT_H3_Header_Field_t v = _field_view_from_buffered(bf);

    // Look up in static table at encode time
    int idx = YAWT_qpack_static_find_entry(&v);
    if (idx >= 0) {
      // Indexed representation
      size += 1 + _prefix_int_size((uint64_t)idx, 6);
    } else {
      idx = YAWT_qpack_static_find_name(&v);
      if (idx >= 0) {
        // Literal w/ Name Reference
        size += 1 + _prefix_int_size((uint64_t)idx, 4);
        size += _string_literal_size(v.value_len);
      } else {
        // Literal w/ Literal Name
        size += 1;  // 0x20 prefix byte
        size += _string_literal_size(v.name_len);
        size += _string_literal_size(v.value_len);
      }
    }
  }

  return size;
}

size_t YAWT_qpack_header_block_max_size(const YAWT_H3_HeaderFields_t *headers) {
  if (!headers || !headers->slab) return 0;

  size_t size = 2;

  ANB_SlabIter_t iter = {0};
  size_t item_size = 0;

  while (1) {
    uint8_t *item = ANB_slab_peek_item_iter(headers->slab, &iter, &item_size);
    if (!item) break;

    _YAWT_H3_Header_BufferedField_t *bf = (_YAWT_H3_Header_BufferedField_t *)item;
    YAWT_H3_Header_Field_t v = _field_view_from_buffered(bf);
    size += YAWT_H3_QPACK_encode_field_line_max_size(&v);
  }

  return size;
}

size_t YAWT_h3_header_section_size(const YAWT_H3_HeaderFields_t *headers) {
  if (!headers || !headers->slab) return 0;

  size_t size = 0;
  ANB_SlabIter_t iter = {0};
  size_t item_size = 0;

  while (1) {
    uint8_t *item = ANB_slab_peek_item_iter(headers->slab, &iter, &item_size);
    if (!item) break;

    _YAWT_H3_Header_BufferedField_t *bf = (_YAWT_H3_Header_BufferedField_t *)item;
    YAWT_H3_Header_Field_t v = _field_view_from_buffered(bf);

    size += v.name_len + v.value_len + 32;
  }

  return size;
}
