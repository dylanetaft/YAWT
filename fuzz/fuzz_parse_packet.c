/**
 * fuzzer: YAWT_q_parse_packet
 *
 * Reads corpus files produced by YAWT_corpus_emit() with num_pairs=1:
 *   pair 0: ReadCursor readable slice (bytes the function will scan)
 *
 * Corpus wire format:
 *   [num_pairs: 1 byte] (expected: 0x01)
 *   [len0: 4 bytes LE][data0: len0 bytes]
 *
 * Fallback: if input doesn't match corpus header, treat as raw bytes.
 */

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

    const uint8_t *pkt_data = data;
    size_t pkt_len = size;

    size_t pos = 0;
    uint8_t num_pairs = data[pos++];
    if (num_pairs == 1 && pos + 4 <= size) {
        uint32_t len0 = read_u32_le(data + pos);
        pos += 4;
        if (pos + len0 <= size) {
            pkt_data = data + pos;
            pkt_len  = len0;
        }
    }

    if (pkt_len == 0) return 0;

    YAWT_Q_ReadCursor_t rc = {
        .data   = (uint8_t *)pkt_data,
        .len    = pkt_len,
        .cursor = 0,
        .err    = YAWT_Q_OK
    };
    YAWT_Q_Packet_t pkt;
    YAWT_q_parse_packet(&rc, &pkt);

    return 0;
}
