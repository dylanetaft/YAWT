/**
 * fuzzer: YAWT_qpack_decode_header_block
 *
 * Reads corpus files produced by YAWT_corpus_emit() with num_pairs=1:
 *   pair 0: QPACK encoded header block (bytes)
 *
 * Corpus wire format:
 *   [num_pairs: 1 byte] (expected: 0x01)
 *   [len0: 4 bytes LE][data0: len0 bytes]
 *
 * Fallback: if input doesn't match corpus header, treat as raw bytes.
 */

#include "h3_header.h"
#include "qpack.h"
#include "h3_types.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

static uint32_t read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    const uint8_t *qpack_data = data;
    size_t qpack_len = size;

    size_t pos = 0;
    uint8_t num_pairs = data[pos++];
    if (num_pairs == 1 && pos + 4 <= size) {
        uint32_t len0 = read_u32_le(data + pos);
        pos += 4;
        if (pos + len0 <= size) {
            qpack_data = data + pos;
            qpack_len  = len0;
        }
    }

    if (qpack_len == 0) return 0;

    YAWT_H3_HeaderFields_t *fields = YAWT_h3_header_fields_create();
    YAWT_qpack_decode_header_block(qpack_data, qpack_len, fields);
    YAWT_h3_header_fields_destroy(fields);

    return 0;
}
