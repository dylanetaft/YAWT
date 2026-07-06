/**
 * fuzzer: YAWT_h3_parse_frame
 *
 * Reads corpus files produced by YAWT_corpus_emit() with num_pairs=1:
 *   pair 0: the raw H3 stream chunk bytes the parser scans
 *
 * Corpus wire format:
 *   [num_pairs: 1 byte] (expected: 0x01)
 *   [len0: 4 bytes LE][data0: len0 bytes]
 *
 * Fallback: if the input doesn't match the corpus header, the whole input is
 * treated as raw frame bytes (mutation-friendly for raw seeds).
 *
 * YAWT_h3_parse_frame is stateful: it mutates a YAWT_H3_Stream_t (resolving the
 * stream type once and lazily allocating hdr/payload blobs). The harness starts
 * from a fresh zero-initialized stream, drives the parser over the chunk the way
 * the real caller does (looping while it makes forward progress), then frees any
 * blobs it allocated — mirroring _h3_stream_destroy() (src/h3.c) minus the free()
 * of the stack object — so ASAN/LSan stay clean.
 */

#include "h3.h"
#include "h3_header.h"
#include "quic.h"
#include "impl/h3_types.h"   /* full struct YAWT_H3_Stream_t definition */

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

    const uint8_t *frame_data = data;
    size_t frame_len = size;

    size_t pos = 0;
    uint8_t num_pairs = data[pos++];
    if (num_pairs == 1 && pos + 4 <= size) {
        uint32_t len0 = read_u32_le(data + pos);
        pos += 4;
        if (pos + len0 <= size) {
            frame_data = data + pos;
            frame_len  = len0;
        }
    }

    if (frame_len == 0) return 0;

    YAWT_Q_Frame_Stream_t chunk = {
        .data      = (uint8_t *)frame_data,
        .data_len  = frame_len,
        .stream_id = 0,   /* client-initiated bidi request stream -> STREAM_FRAME */
        .offset    = 0,
        .fin       = 1,
    };

    YAWT_H3_Stream_t stream = {0};  /* type == YAWT_H3_STREAM_UNASSIGNED, blobs NULL */

    /* Drive the parser like the real caller: keep going while it returns OK and
     * advances the cursor. Bound by data_len and a generous iteration cap so a
     * zero-progress OK return can never spin forever. */
    size_t cursor = 0;
    for (size_t iters = 0; cursor < chunk.data_len && iters < frame_len + 8; iters++) {
        size_t prev = cursor;
        YAWT_H3_Error_t err = YAWT_h3_parse_frame(&chunk, &stream, &cursor);
        if (err != YAWT_H3_OK) break;
        if (cursor == prev) break;  /* no forward progress -> stop */
    }

    /* Cleanup — mirror _h3_stream_destroy() minus free() (stack object).
     * ANB_blob_destroy is NULL-safe. */
    ANB_blob_destroy(stream.hdr_buffer);
    ANB_blob_destroy(stream.frame.hdr_buffer);
    ANB_blob_destroy(stream.frame.payload_blob);
    if (stream.request_headers)  YAWT_h3_header_fields_destroy(stream.request_headers);
    if (stream.response_headers) YAWT_h3_header_fields_destroy(stream.response_headers);

    return 0;
}
