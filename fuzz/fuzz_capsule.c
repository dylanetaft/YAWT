/**
 * fuzzer: YAWT_capsule_parse_feed
 *
 * Reads corpus files produced by YAWT_corpus_emit() with num_pairs=2:
 *   pair 0: YAWT_Capsule_Parser_t state (bytes)
 *   pair 1: input data chunk (bytes)
 *
 * Corpus wire format:
 *   [num_pairs: 1 byte] (expected: 0x02)
 *   [len0: 4 bytes LE][data0: len0 bytes]    (parser state)
 *   [len1: 4 bytes LE][data1: len1 bytes]    (input chunk)
 *
 * Fallback: if input doesn't match corpus header, treat as raw bytes with fresh parser.
 */

#include "capsule.h"

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

    size_t pos = 0;
    uint8_t num_pairs = data[pos++];

    YAWT_Capsule_Parser_t parser = {0};
    const uint8_t *chunk_data = data;
    size_t chunk_len = size;

    if (num_pairs == 2) {
        /* Pair 0: parser state */
        if (pos + 4 > size) return 0;
        uint32_t len0 = read_u32_le(data + pos);
        pos += 4;
        if (pos + len0 > size) return 0;
        /* Sanity: parser struct should be ~sizeof(YAWT_Capsule_Parser_t) */
        if (len0 <= sizeof(parser)) {
            memcpy(&parser, data + pos, len0);
        }
        pos += len0;

        /* Pair 1: input chunk */
        if (pos + 4 > size) return 0;
        uint32_t len1 = read_u32_le(data + pos);
        pos += 4;
        if (pos + len1 > size) return 0;
        chunk_data = data + pos;
        chunk_len  = len1;
    }

    if (chunk_len == 0) return 0;

    YAWT_capsule_parse_feed(&parser, chunk_data, chunk_len);

    return 0;
}
