/**
 * fuzzer: YAWT_q_parse_frame
 *
 * Reads corpus files produced by YAWT_corpus_emit() with num_pairs=2:
 *   pair 0: ReadCursor readable slice (bytes the function will scan)
 *   pair 1: YAWT_Q_Packet_Type_t scalar
 *
 * Corpus wire format:
 *   [num_pairs: 1 byte]
 *   [len0: 4 bytes LE][data0: len0 bytes]    (cursor slice)
 *   [len1: 4 bytes LE][data1: len1 bytes]    (pkt_type scalar)
 */

#include "quic.h"
#include "corpus.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

static uint32_t read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    size_t pos = 0;

    /* If starts with a valid corpus header (num_pairs == 2), decode pairs.
     * Otherwise treat the whole input as raw frame bytes with INITIAL packet type
     * (for mutation-friendly fuzzing from raw seeds). */
    const uint8_t *frame_data;
    size_t frame_len;
    YAWT_Q_Packet_Type_t pkt_type = YAWT_Q_PKT_TYPE_INITIAL;

    uint8_t num_pairs = data[pos++];
    if (num_pairs == 2 && pos + 4 <= size) {
        /* Pair 0: cursor slice */
        uint32_t len0 = read_u32_le(data + pos);
        pos += 4;
        if (pos + len0 > size) return 0;
        frame_data = data + pos;
        frame_len  = len0;
        pos += len0;

        /* Pair 1: pkt_type */
        if (pos + 4 > size) return 0;
        uint32_t len1 = read_u32_le(data + pos);
        pos += 4;
        if (pos + len1 < 4) return 0;
        if (len1 >= sizeof(uint32_t)) {
            pkt_type = (YAWT_Q_Packet_Type_t)read_u32_le(data + pos);
        }
    } else {
        /* Raw fallback: treat entire input as frame bytes */
        frame_data = data;
        frame_len  = size;
    }

    if (frame_len == 0) return 0;

    YAWT_Q_ReadCursor_t rc = {
        .data   = (uint8_t *)frame_data,
        .len    = frame_len,
        .cursor = 0,
        .err    = YAWT_Q_OK
    };
    YAWT_Q_Frame_t frame;
    YAWT_q_parse_frame(&rc, pkt_type, &frame);

    return 0;
}
