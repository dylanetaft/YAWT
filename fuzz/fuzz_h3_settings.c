/**
 * fuzzer: YAWT_h3_settings_decode
 *
 * Reads corpus files produced by YAWT_corpus_emit() with num_pairs=1:
 *   pair 0: ReadCursor readable slice (settings payload bytes)
 *
 * Corpus wire format:
 *   [num_pairs: 1 byte] (expected: 0x01)
 *   [len0: 4 bytes LE][data0: len0 bytes]
 *
 * Fallback: if input doesn't match corpus header, treat as raw bytes.
 */

#include "h3.h"
#include "quic.h"

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

    const uint8_t *settings_data = data;
    size_t settings_len = size;

    size_t pos = 0;
    uint8_t num_pairs = data[pos++];
    if (num_pairs == 1 && pos + 4 <= size) {
        uint32_t len0 = read_u32_le(data + pos);
        pos += 4;
        if (pos + len0 <= size) {
            settings_data = data + pos;
            settings_len  = len0;
        }
    }

    if (settings_len == 0) return 0;

    YAWT_Q_ReadCursor_t rc = {
        .data   = (uint8_t *)settings_data,
        .len    = settings_len,
        .cursor = 0,
        .err    = YAWT_Q_OK
    };
    YAWT_H3_Settings_t settings = {0};
    YAWT_h3_settings_decode(&rc, &settings);

    return 0;
}
