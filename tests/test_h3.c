#include "unity.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "h3.h"
#include "h3_header.h"
#include "h3_types.h"
#include "impl/h3_types.h"
#include "quic.h"
#include "impl/quic_types.h"
#include "security.h"
#include "qpack.h"

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

static YAWT_H3_Connection_t *alloc_minimal_h3_conn(void) {
    //we'll just reuse a static connection for simplicity, since we don't need to test multiple connections in parallel
    static YAWT_H3_Connection_t h3 = {0};
    h3.nstreams = 16;
    h3.streams = realloc(h3.streams, sizeof(YAWT_H3_Stream_t) * h3.nstreams);
    memset(h3.streams, 0, sizeof(YAWT_H3_Stream_t) * h3.nstreams);
    h3.local_settings = realloc(h3.local_settings, sizeof(YAWT_H3_Settings_t));
    memset(h3.local_settings, 0, sizeof(YAWT_H3_Settings_t));

    return &h3;
}

/* Helper: create a buffered stream frame from H3 components using YAWT_q_encode_frame_stream */
static YAWT_Q_Frame_BufferedStream_t make_buffered_chunk(
    uint64_t stream_id, YAWT_Q_Stream_Type_t stream_type,
    const uint8_t *stream_type_prefix, size_t prefix_len,
    const uint8_t *frame_hdr, size_t hdr_len,
    const uint8_t *payload, size_t payload_len,
    uint64_t offset, size_t max_chunk_size, int fin)
{
    YAWT_Q_IoVec_t iov[3];
    int iov_count = 0;

    if (stream_type_prefix && prefix_len > 0) {
        iov[iov_count].buf = stream_type_prefix;
        iov[iov_count].len = prefix_len;
        iov_count++;
    }

    if (frame_hdr && hdr_len > 0) {
        iov[iov_count].buf = frame_hdr;
        iov[iov_count].len = hdr_len;
        iov_count++;
    }

    if (payload && payload_len > 0) {
        iov[iov_count].buf = payload;
        iov[iov_count].len = payload_len;
        iov_count++;
    }

    YAWT_Q_Frame_BufferedStream_t bf = {0};
    bf.frame.stream_id = stream_id;
    bf.frame.stream_type = stream_type;

    size_t out_offset = 0;
    YAWT_Err_t err = YAWT_q_encode_frame_stream(iov, iov_count, offset, max_chunk_size,
                                                 stream_id, 0, fin, &bf, &out_offset);
    TEST_ASSERT_EQUAL(YAWT_Q_OK, err);

    return bf;
}

/* ------------------------------------------------------------------ */
/*  1. Settings frame on bidi stream (no stream-type prefix)           */
/* ------------------------------------------------------------------ */

static void test_settings_frame_on_bidi_stream(void) {
    uint8_t payload[64];
    size_t plen = 0;
    uint64_t n;

    YAWT_q_varint_encode(0x01, payload + plen, sizeof(payload) - plen, &n); plen += n;
    YAWT_q_varint_encode(100, payload + plen, sizeof(payload) - plen, &n); plen += n;
    YAWT_q_varint_encode(0x06, payload + plen, sizeof(payload) - plen, &n); plen += n;
    YAWT_q_varint_encode(200, payload + plen, sizeof(payload) - plen, &n); plen += n;

    uint8_t frame_buf[128];
    size_t hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_SETTINGS, plen, frame_buf);
    TEST_ASSERT_GREATER_THAN(0, hdr_len);

    YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();
    TEST_ASSERT_NOT_NULL(h3);

    YAWT_Q_Frame_BufferedStream_t bf = make_buffered_chunk(
        0, YAWT_Q_C_BIDI, NULL, 0, frame_buf, hdr_len, payload, plen, 0, 1350, 0);

    YAWT_H3_Stream_t *stream = NULL;
    size_t cursor = 0;
    YAWT_H3_Error_t err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
    TEST_ASSERT_EQUAL(YAWT_H3_OK, err);
    TEST_ASSERT_NOT_NULL(stream);
    TEST_ASSERT_EQUAL(YAWT_H3_STREAM_FRAME, stream->type);
    TEST_ASSERT_EQUAL(YAWT_H3_FRAME_SETTINGS, stream->frame.type);
    TEST_ASSERT_NOT_NULL(stream->frame.payload_blob);
    TEST_ASSERT_EQUAL(plen, ANB_blob_data_len(stream->frame.payload_blob));

}

/* ------------------------------------------------------------------ */
/*  2. Settings out-of-order chunks on bidi stream                     */
/* ------------------------------------------------------------------ */

static void test_settings_out_of_order_chunks(void) {
    uint8_t payload[64];
    size_t plen = 0;
    uint64_t n;

    YAWT_q_varint_encode(0x01, payload + plen, sizeof(payload) - plen, &n); plen += n;
    YAWT_q_varint_encode(100, payload + plen, sizeof(payload) - plen, &n); plen += n;
    YAWT_q_varint_encode(0x06, payload + plen, sizeof(payload) - plen, &n); plen += n;
    YAWT_q_varint_encode(200, payload + plen, sizeof(payload) - plen, &n); plen += n;

    uint8_t frame_buf[128];
    size_t hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_SETTINGS, plen, frame_buf);

    size_t third = plen / 3;
    size_t chunk_size = hdr_len + third;

    YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();
    TEST_ASSERT_NOT_NULL(h3);

    YAWT_Q_Frame_BufferedStream_t bf1 = make_buffered_chunk(
        0, YAWT_Q_C_BIDI, NULL, 0, frame_buf, hdr_len, payload, plen, 0, chunk_size, 0);
    YAWT_Q_Frame_BufferedStream_t bf2 = make_buffered_chunk(
        0, YAWT_Q_C_BIDI, NULL, 0, frame_buf, hdr_len, payload, plen, chunk_size, chunk_size, 0);
    YAWT_Q_Frame_BufferedStream_t bf3 = make_buffered_chunk(
        0, YAWT_Q_C_BIDI, NULL, 0, frame_buf, hdr_len, payload, plen, 2 * chunk_size, chunk_size, 0);

    YAWT_H3_Stream_t *stream = NULL;
    size_t cursor = 0;
    YAWT_H3_Error_t err;

    err = YAWT_h3_parse_frame(h3, &bf1.frame, &stream, &cursor);
    TEST_ASSERT_EQUAL(YAWT_H3_OK, err);
    TEST_ASSERT_NOT_NULL(stream);

    cursor = 0;
    err = YAWT_h3_parse_frame(h3, &bf3.frame, &stream, &cursor);
    TEST_ASSERT_EQUAL(YAWT_H3_OK, err);

    cursor = 0;
    err = YAWT_h3_parse_frame(h3, &bf2.frame, &stream, &cursor);
    TEST_ASSERT_EQUAL(YAWT_H3_OK, err);

    TEST_ASSERT_EQUAL(plen, ANB_blob_data_len(stream->frame.payload_blob));

}

/* ------------------------------------------------------------------ */
/*  3. Settings frame header-only (no payload)                         */
/* ------------------------------------------------------------------ */

static void test_settings_frame_header_only(void) {
    uint8_t frame_buf[32];
    size_t hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_SETTINGS, 0, frame_buf);

    YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();
    TEST_ASSERT_NOT_NULL(h3);

    YAWT_Q_Frame_BufferedStream_t bf = make_buffered_chunk(
        0, YAWT_Q_C_BIDI, NULL, 0, frame_buf, hdr_len, NULL, 0, 0, 1350, 0);

    YAWT_H3_Stream_t *stream = NULL;
    size_t cursor = 0;
    YAWT_H3_Error_t err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
    TEST_ASSERT_EQUAL(YAWT_H3_OK, err);

    TEST_ASSERT_NOT_NULL(stream);
    TEST_ASSERT_EQUAL(YAWT_H3_FRAME_SETTINGS, stream->frame.type);
    TEST_ASSERT_EQUAL_UINT64(0, stream->frame.payload_len);

}

/* ------------------------------------------------------------------ */
/*  4. Single chunk contains multiple SETTINGS frames                  */
/* ------------------------------------------------------------------ */

static void test_single_chunk_multiple_frames(void) {

  //it's parsable, but not valid h3
  //we're just testing parser though
  uint8_t payload_a[256];
  size_t payload_a_len = 0;
  uint8_t payload_b[256];
  size_t payload_b_len = 0;
  YAWT_H3_Settings_t settings = {0};
  YAWT_h3_setting_set(&settings, YAWT_H3_IDX_MAX_FIELD_SECTION_SIZE, 100); 
  YAWT_h3_setting_set(&settings, YAWT_H3_IDX_QPACK_MAX_TABLE_CAPACITY, 200);
  YAWT_h3_settings_encode(&settings, payload_a, sizeof(payload_a), &payload_a_len);
  YAWT_h3_setting_set(&settings, YAWT_H3_IDX_MAX_FIELD_SECTION_SIZE, 300);
  YAWT_h3_setting_set(&settings, YAWT_H3_IDX_QPACK_MAX_TABLE_CAPACITY, 400);
  YAWT_h3_settings_encode(&settings, payload_b, sizeof(payload_b), &payload_b_len);


  uint8_t stream_type_buf[8];
  uint8_t frame_hdr_a[H3_FRAME_MAX_HEADER_BYTES];
  uint8_t frame_hdr_b[H3_FRAME_MAX_HEADER_BYTES];
  size_t stream_type_len = 0;
  uint64_t n;
  //RFC 9114 §6.2.1: Control stream type is 0x00
  YAWT_q_varint_encode(YAWT_H3_STREAM_WIRE_CONTROL, stream_type_buf, sizeof(stream_type_buf), &stream_type_len);
  size_t frame_hdr_a_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_SETTINGS, payload_a_len, frame_hdr_a);
  size_t frame_hdr_b_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_SETTINGS, payload_b_len, frame_hdr_b);

  uint64_t stream_id = 2;
  YAWT_Q_IoVec_t iov_a[5] = {
    { stream_type_buf, stream_type_len },
    { frame_hdr_a, frame_hdr_a_len },
    { payload_a, payload_a_len },
    { frame_hdr_b, frame_hdr_b_len },
    { payload_b, payload_b_len }
  };



  YAWT_Err_t err;
  YAWT_Q_Frame_BufferedStream_t bf;
  size_t out_iov_offset = 0;
  err = YAWT_q_encode_frame_stream(iov_a,5,0,1000,stream_id,0,0,&bf, &out_iov_offset);
  TEST_ASSERT_EQUAL(YAWT_Q_OK, err);
  YAWT_H3_Error_t h3_err;
  YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();
  size_t cursor = 0;
  YAWT_H3_Stream_t *stream = NULL;
  cursor = 0;
  //parse combined frame
  h3_err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor); 
  TEST_ASSERT_EQUAL(YAWT_H3_OK, h3_err);
  TEST_ASSERT_NOT_NULL(stream);
  YAWT_LOG(YAWT_LOG_INFO, "parsed len: %zu", stream->frame.payload_len);
  YAWT_Q_ReadCursor_t dec = {0};
  dec.data = ANB_blob_data(stream->frame.payload_blob);
  dec.len = stream->frame.payload_len;
  dec.cursor = 0;
  dec.err = YAWT_Q_OK;

  YAWT_H3_Settings_t out_settings_a = {0};
  h3_err = YAWT_h3_settings_decode(&dec, &out_settings_a);

  TEST_ASSERT_EQUAL(YAWT_H3_OK, h3_err);
  TEST_ASSERT_EQUAL(100, out_settings_a.vals[YAWT_H3_IDX_MAX_FIELD_SECTION_SIZE]); 
  TEST_ASSERT_EQUAL(200, out_settings_a.vals[YAWT_H3_IDX_QPACK_MAX_TABLE_CAPACITY]);
  ANB_blob_destroy(stream->frame.payload_blob);
  memset(&stream->frame, 0, sizeof(YAWT_H3_Frame_t));
  YAWT_H3_Settings_t out_settings_b = {0};
  //advances to the next frame with cursor
  h3_err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor); 
  TEST_ASSERT_EQUAL(YAWT_H3_OK, h3_err);
  dec.data = ANB_blob_data(stream->frame.payload_blob);
  dec.len = stream->frame.payload_len;
  dec.cursor = 0;
  dec.err = YAWT_Q_OK;
  h3_err = YAWT_h3_settings_decode(&dec, &out_settings_b);
  TEST_ASSERT_EQUAL(YAWT_H3_OK, h3_err);
  TEST_ASSERT_EQUAL(300, out_settings_b.vals[YAWT_H3_IDX_MAX_FIELD_SECTION_SIZE]); 
  TEST_ASSERT_EQUAL(400, out_settings_b.vals[YAWT_H3_IDX_QPACK_MAX_TABLE_CAPACITY]); 

}

/* ------------------------------------------------------------------ */
/*  5. Frame split across two chunks (SETTINGS)                        */
/* ------------------------------------------------------------------ */

static void test_frame_split_across_two_chunks(void) {
    uint8_t payload[64];
    size_t plen = 0;
    uint64_t n;
    YAWT_q_varint_encode(0x01, payload + plen, sizeof(payload) - plen, &n); plen += n;
    YAWT_q_varint_encode(77, payload + plen, sizeof(payload) - plen, &n); plen += n;

    uint8_t frame_buf[128];
    size_t hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_SETTINGS, plen, frame_buf);

    size_t half = plen / 2;
    size_t chunk_size = hdr_len + half;

    YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();
    TEST_ASSERT_NOT_NULL(h3);

    YAWT_Q_Frame_BufferedStream_t bf1 = make_buffered_chunk(
        0, YAWT_Q_C_BIDI, NULL, 0, frame_buf, hdr_len, payload, plen, 0, chunk_size, 0);
    YAWT_Q_Frame_BufferedStream_t bf2 = make_buffered_chunk(
        0, YAWT_Q_C_BIDI, NULL, 0, frame_buf, hdr_len, payload, plen, chunk_size, chunk_size, 0);

    YAWT_H3_Stream_t *stream = NULL;
    size_t cursor = 0;
    YAWT_H3_Error_t err = YAWT_h3_parse_frame(h3, &bf1.frame, &stream, &cursor);
    TEST_ASSERT_EQUAL(YAWT_H3_OK, err);
    TEST_ASSERT_NOT_NULL(stream);
    TEST_ASSERT_EQUAL(YAWT_H3_FRAME_SETTINGS, stream->frame.type);
    TEST_ASSERT_NOT_NULL(stream->frame.payload_blob);
    TEST_ASSERT_EQUAL(half, ANB_blob_data_len(stream->frame.payload_blob));

    cursor = 0;
    err = YAWT_h3_parse_frame(h3, &bf2.frame, &stream, &cursor);
    TEST_ASSERT_EQUAL(YAWT_H3_OK, err);

    TEST_ASSERT_EQUAL(plen, ANB_blob_data_len(stream->frame.payload_blob));

}

/* ------------------------------------------------------------------ */
/*  6. Incomplete frame returns OK but frame not dispatched yet        */
/* ------------------------------------------------------------------ */

static void test_incomplete_frame_state(void) {
    uint8_t frame_buf[32];
    size_t hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_SETTINGS, 100, frame_buf);

    uint8_t partial_payload[16];
    memset(partial_payload, 0x42, sizeof(partial_payload));

    YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();
    TEST_ASSERT_NOT_NULL(h3);

    YAWT_Q_Frame_BufferedStream_t bf = make_buffered_chunk(
        0, YAWT_Q_C_BIDI, NULL, 0, frame_buf, hdr_len, partial_payload, sizeof(partial_payload), 0, 1350, 0);

    YAWT_H3_Stream_t *stream = NULL;
    size_t cursor = 0;
    YAWT_H3_Error_t err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);

    TEST_ASSERT_EQUAL(YAWT_H3_OK, err);
    TEST_ASSERT_NOT_NULL(stream);
    TEST_ASSERT_EQUAL(100, stream->frame.payload_len);
    TEST_ASSERT_NOT_NULL(stream->frame.payload_blob);

}

/* ------------------------------------------------------------------ */
/*  7. DATA frame no buffering                                         */
/* ------------------------------------------------------------------ */

static void test_data_frame_no_buffering(void) {
    uint8_t data_payload[32] = "hello world, this is data";
    size_t data_len = strlen((char *)data_payload);

    uint8_t frame_buf[64];
    size_t hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_DATA, data_len, frame_buf);

    YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();
    TEST_ASSERT_NOT_NULL(h3);

    YAWT_Q_Frame_BufferedStream_t bf = make_buffered_chunk(
        1, YAWT_Q_S_BIDI, NULL, 0, frame_buf, hdr_len, data_payload, data_len, 0, 1350, 0);

    YAWT_H3_Stream_t *stream = NULL;
    size_t cursor = 0;
    YAWT_H3_Error_t err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
    TEST_ASSERT_EQUAL(YAWT_H3_OK, err);

    TEST_ASSERT_NOT_NULL(stream);
    TEST_ASSERT_EQUAL(YAWT_H3_FRAME_DATA, stream->frame.type);
    TEST_ASSERT_EQUAL(data_len, stream->frame.payload_len);
    TEST_ASSERT_NULL(stream->frame.payload_blob);

}

/* ------------------------------------------------------------------ */
/*  8. DATA frame fragmented chunks                                   */
/* ------------------------------------------------------------------ */

static void test_data_frame_fragmented_chunks(void) {
    uint8_t payload[64];
    memset(payload, 'A', 20);
    memset(payload + 20, 'B', 20);
    memset(payload + 40, 'C', 20);
    size_t data_len = 60;

    uint8_t frame_buf[64];
    size_t hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_DATA, data_len, frame_buf);

    size_t chunk_size = hdr_len + 20;

    YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();
    TEST_ASSERT_NOT_NULL(h3);

    YAWT_Q_Frame_BufferedStream_t bf1 = make_buffered_chunk(
        1, YAWT_Q_S_BIDI, NULL, 0, frame_buf, hdr_len, payload, data_len, 0, chunk_size, 0);
    YAWT_Q_Frame_BufferedStream_t bf2 = make_buffered_chunk(
        1, YAWT_Q_S_BIDI, NULL, 0, frame_buf, hdr_len, payload, data_len, hdr_len + 40, 20, 0);
    YAWT_Q_Frame_BufferedStream_t bf3 = make_buffered_chunk(
        1, YAWT_Q_S_BIDI, NULL, 0, frame_buf, hdr_len, payload, data_len, hdr_len + 20, 20, 0);

    YAWT_H3_Stream_t *stream = NULL;
    size_t cursor = 0;
    YAWT_H3_Error_t err = YAWT_h3_parse_frame(h3, &bf1.frame, &stream, &cursor);
    TEST_ASSERT_EQUAL(YAWT_H3_OK, err);
    TEST_ASSERT_NOT_NULL(stream);
    TEST_ASSERT_EQUAL(YAWT_H3_FRAME_DATA, stream->frame.type);
    TEST_ASSERT_EQUAL(data_len, stream->frame.payload_len);

    cursor = 0;
    err = YAWT_h3_parse_frame(h3, &bf2.frame, &stream, &cursor);
    TEST_ASSERT_EQUAL(YAWT_H3_OK, err);

    cursor = 0;
    err = YAWT_h3_parse_frame(h3, &bf3.frame, &stream, &cursor);
    TEST_ASSERT_EQUAL(YAWT_H3_OK, err);

}

/* ------------------------------------------------------------------ */
/*  9. Stream type resolution — bidi stream (no prefix)               */
/* ------------------------------------------------------------------ */

static void test_stream_type_bidi(void) {
    uint8_t frame_buf[32];
    size_t hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_HEADERS, 0, frame_buf);

    YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();
    TEST_ASSERT_NOT_NULL(h3);

    YAWT_Q_Frame_BufferedStream_t bf = make_buffered_chunk(
        0, YAWT_Q_C_BIDI, NULL, 0, frame_buf, hdr_len, NULL, 0, 0, 1350, 0);

    YAWT_H3_Stream_t *stream = NULL;
    size_t cursor = 0;
    YAWT_H3_Error_t err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
    TEST_ASSERT_EQUAL(YAWT_H3_OK, err);
    TEST_ASSERT_NOT_NULL(stream);

    TEST_ASSERT_EQUAL(YAWT_H3_STREAM_FRAME, stream->type);

}

/* ------------------------------------------------------------------ */
/*  10. Stream type resolution — control uni stream (prefix 0x00)     */
/* ------------------------------------------------------------------ */

static void test_stream_type_control_uni(void) {
    uint8_t stream_type_byte = 0x00;

    YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();
    TEST_ASSERT_NOT_NULL(h3);

    YAWT_Q_Frame_BufferedStream_t bf = make_buffered_chunk(
        3, YAWT_Q_S_UNI, &stream_type_byte, 1, NULL, 0, NULL, 0, 0, 1350, 0);

    YAWT_H3_Stream_t *stream = NULL;
    size_t cursor = 0;
    YAWT_H3_Error_t err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
    printf("DEBUG test_stream_type_control_uni: err=%d stream_type=%lu data_len=%zu stream_type_field=%lu\n", err, stream ? stream->type : -1, bf.frame.data_len, bf.frame.stream_type);
    TEST_ASSERT_EQUAL(YAWT_H3_OK, err);
    TEST_ASSERT_NOT_NULL(stream);

    TEST_ASSERT_EQUAL(YAWT_H3_STREAM_CONTROL, stream->type);

}

/* ------------------------------------------------------------------ */
/*  11. Stream type — QPACK encoder/decoder uni streams              */
/* ------------------------------------------------------------------ */

static void test_stream_type_qpack_encoder(void) {
    uint8_t prefix = 0x02; /* QPACK encoder */

    YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();
    TEST_ASSERT_NOT_NULL(h3);

    YAWT_Q_Frame_BufferedStream_t bf = make_buffered_chunk(
        5, YAWT_Q_S_UNI, &prefix, 1, NULL, 0, NULL, 0, 0, 1350, 0);

    YAWT_H3_Stream_t *stream = NULL;
    size_t cursor = 0;
    YAWT_H3_Error_t err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
    TEST_ASSERT_EQUAL(YAWT_H3_OK, err);
    TEST_ASSERT_NOT_NULL(stream);
    TEST_ASSERT_EQUAL(YAWT_H3_STREAM_QPACK_ENCODER, stream->type);

}

static void test_stream_type_qpack_decoder(void) {
    uint8_t prefix = 0x03; /* QPACK decoder */

    YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();
    TEST_ASSERT_NOT_NULL(h3);

    YAWT_Q_Frame_BufferedStream_t bf = make_buffered_chunk(
        7, YAWT_Q_S_UNI, &prefix, 1, NULL, 0, NULL, 0, 0, 1350, 0);

    YAWT_H3_Stream_t *stream = NULL;
    size_t cursor = 0;
    YAWT_H3_Error_t err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
    TEST_ASSERT_EQUAL(YAWT_H3_OK, err);
    TEST_ASSERT_NOT_NULL(stream);
    TEST_ASSERT_EQUAL(YAWT_H3_STREAM_QPACK_DECODER, stream->type);

}

/* ------------------------------------------------------------------ */
/*  12. Stream type — uni stream split across chunks                 */
/* ------------------------------------------------------------------ */

static void test_stream_type_uni_split_chunks(void) {
    /* Varint 0x3FFF encodes as 0xFF 0x7F (2 bytes).
     * Split across two chunks, deliver in order. */
    uint8_t full_varint[4];
    uint64_t n;
    YAWT_q_varint_encode(0x3FFF, full_varint, sizeof(full_varint), &n);
    TEST_ASSERT_EQUAL(2, (int)n);

    uint8_t byte1 = full_varint[0];
    uint8_t byte2 = full_varint[1];

    YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();
    TEST_ASSERT_NOT_NULL(h3);

    YAWT_H3_Stream_t *stream = NULL;
    size_t cursor = 0;
    YAWT_H3_Error_t err;

    /* Deliver first byte */
    YAWT_Q_Frame_BufferedStream_t bf1 = make_buffered_chunk(
        5, YAWT_Q_S_UNI, &byte1, 1, NULL, 0, NULL, 0, 0, 1350, 0);
    err = YAWT_h3_parse_frame(h3, &bf1.frame, &stream, &cursor);
    TEST_ASSERT_EQUAL(YAWT_H3_ERR_INCOMPLETE, err);

    /* Deliver second byte */
    YAWT_Q_Frame_BufferedStream_t bf2 = make_buffered_chunk(
        5, YAWT_Q_S_UNI, &byte2, 1, NULL, 0, NULL, 0, 1, 1350, 0);
    cursor = 0;
    err = YAWT_h3_parse_frame(h3, &bf2.frame, &stream, &cursor);
    TEST_ASSERT_EQUAL(YAWT_H3_OK, err);
    TEST_ASSERT_NOT_NULL(stream);

    TEST_ASSERT_EQUAL(YAWT_H3_STREAM_UNKNOWN, stream->type);

}

/* ------------------------------------------------------------------ */
/*  13. Invalid param tests                                            */
/* ------------------------------------------------------------------ */

static void test_h3_parse_frame_null_params(void) {
    YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();
    TEST_ASSERT_NOT_NULL(h3);

    uint8_t fake_data[4] = "test";
    YAWT_Q_Frame_BufferedStream_t bf = make_buffered_chunk(
        1, YAWT_Q_S_BIDI, NULL, 0, NULL, 0, fake_data, 4, 0, 1350, 0);

    YAWT_H3_Stream_t *stream = NULL;
    size_t cursor = 0;

    YAWT_H3_Error_t err = YAWT_h3_parse_frame(NULL, &bf.frame, &stream, &cursor);
    TEST_ASSERT_EQUAL(YAWT_H3_ERR_INVALID_PARAM, err);

    cursor = 0;
    err = YAWT_h3_parse_frame(h3, NULL, &stream, &cursor);
    TEST_ASSERT_EQUAL(YAWT_H3_ERR_INVALID_PARAM, err);

    cursor = 0;
    err = YAWT_h3_parse_frame(h3, &bf.frame, NULL, &cursor);
    TEST_ASSERT_EQUAL(YAWT_H3_ERR_INVALID_PARAM, err);

    cursor = 0;
    err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, NULL);
    TEST_ASSERT_EQUAL(YAWT_H3_ERR_INVALID_PARAM, err);

}

/* ------------------------------------------------------------------ */
/*  14. HEADERS frame with QPACK-encoded payload                      */
/* ------------------------------------------------------------------ */

static void test_headers_frame_with_payload(void) {
    YAWT_H3_HeaderFields_t *headers = YAWT_h3_header_fields_create();
    YAWT_h3_header_add_str(headers, ":method", "GET");
    YAWT_h3_header_add_str(headers, ":path", "/");
    YAWT_h3_header_add_str(headers, ":scheme", "https");
    YAWT_h3_header_add_str(headers, ":authority", "example.com");

    uint8_t qpack_buf[256];
    size_t qpack_len = 0;
    YAWT_QPACK_Error_t qerr = YAWT_qpack_encode_header_block(headers, qpack_buf, sizeof(qpack_buf), &qpack_len);
    TEST_ASSERT_EQUAL(YAWT_QPACK_OK, qerr);
    TEST_ASSERT_GREATER_THAN(0, qpack_len);

    uint8_t frame_buf[512];
    size_t hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_HEADERS, qpack_len, frame_buf);

    YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();
    TEST_ASSERT_NOT_NULL(h3);

    YAWT_Q_Frame_BufferedStream_t bf = make_buffered_chunk(
        0, YAWT_Q_C_BIDI, NULL, 0, frame_buf, hdr_len, qpack_buf, qpack_len, 0, 1350, 0);

    YAWT_H3_Stream_t *stream = NULL;
    size_t cursor = 0;
    YAWT_H3_Error_t err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
    TEST_ASSERT_EQUAL(YAWT_H3_OK, err);
    TEST_ASSERT_NOT_NULL(stream);

    TEST_ASSERT_EQUAL(YAWT_H3_FRAME_HEADERS, stream->frame.type);
    TEST_ASSERT_NOT_NULL(stream->frame.payload_blob);
    TEST_ASSERT_EQUAL(qpack_len, ANB_blob_data_len(stream->frame.payload_blob));

    YAWT_h3_header_fields_destroy(headers);
}

/* ------------------------------------------------------------------ */
/*  15. HEADERS frame out-of-order chunks                             */
/* ------------------------------------------------------------------ */

static void test_headers_frame_out_of_order_chunks(void) {
    YAWT_H3_HeaderFields_t *headers = YAWT_h3_header_fields_create();
    YAWT_h3_header_add_str(headers, ":method", "POST");
    YAWT_h3_header_add_str(headers, ":path", "/api/data");
    YAWT_h3_header_add_str(headers, "content-type", "application/json");
    YAWT_h3_header_add_str(headers, "content-length", "256");

    uint8_t qpack_buf[512];
    size_t qpack_len = 0;
    YAWT_QPACK_Error_t qerr = YAWT_qpack_encode_header_block(headers, qpack_buf, sizeof(qpack_buf), &qpack_len);
    TEST_ASSERT_EQUAL(YAWT_QPACK_OK, qerr);

    uint8_t frame_buf[512];
    size_t hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_HEADERS, qpack_len, frame_buf);

    size_t chunk_size = qpack_len / 4;
    if (chunk_size == 0) chunk_size = 1;

    YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();
    TEST_ASSERT_NOT_NULL(h3);

    YAWT_Q_Frame_BufferedStream_t bf[4];
    for (int i = 0; i < 4; i++) {
        size_t offset = i * chunk_size;
        size_t len = chunk_size;
        if (i == 3) len = qpack_len - 3 * chunk_size;
        bf[i] = make_buffered_chunk(0, YAWT_Q_C_BIDI, NULL, 0, frame_buf, hdr_len,
                                     qpack_buf + offset, len, offset, 1350, 0);
    }

    YAWT_H3_Stream_t *stream = NULL;
    size_t cursor;
    YAWT_H3_Error_t err;

    /* Out of order: [3, 1, 2, 0] */
    int order[] = {3, 1, 2, 0};

    for (int i = 0; i < 4; i++) {
        int idx = order[i];
        cursor = 0;
        err = YAWT_h3_parse_frame(h3, &bf[idx].frame, &stream, &cursor);
        if (err != YAWT_H3_OK && err != YAWT_H3_ERR_INCOMPLETE) {
            break;
        }
    }

    TEST_ASSERT_NOT_NULL(stream);
    TEST_ASSERT_EQUAL(YAWT_H3_FRAME_HEADERS, stream->frame.type);
    TEST_ASSERT_NOT_NULL(stream->frame.payload_blob);
    TEST_ASSERT_EQUAL(qpack_len, ANB_blob_data_len(stream->frame.payload_blob));

    YAWT_h3_header_fields_destroy(headers);
}

/* ------------------------------------------------------------------ */
/*  16. Oversized HEADERS frame                                        */
/* ------------------------------------------------------------------ */

static void test_oversized_headers_frame(void) {
    uint8_t fake_payload[1024];
    memset(fake_payload, 0, sizeof(fake_payload));
    size_t fake_len = sizeof(fake_payload);

    uint8_t frame_buf[64];
    size_t hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_HEADERS, fake_len, frame_buf);

    YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();
    TEST_ASSERT_NOT_NULL(h3);

    YAWT_Q_Frame_BufferedStream_t bf = make_buffered_chunk(
        0, YAWT_Q_C_BIDI, NULL, 0, frame_buf, hdr_len, fake_payload, fake_len, 0, 1350, 0);

    YAWT_H3_Stream_t *stream = NULL;
    size_t cursor = 0;
    YAWT_H3_Error_t err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);

    TEST_ASSERT_EQUAL(YAWT_H3_OK, err);
    TEST_ASSERT_NOT_NULL(stream);
    TEST_ASSERT_EQUAL(YAWT_H3_FRAME_HEADERS, stream->frame.type);
    TEST_ASSERT_EQUAL(fake_len, stream->frame.payload_len);

}

/* ------------------------------------------------------------------ */
/*  17. Cursor advancement in parse loop                               */
/* ------------------------------------------------------------------ */

static void test_cursor_advancement(void) {
    uint8_t frame_buf[32];
    size_t hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_SETTINGS, 0, frame_buf);

    YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();
    TEST_ASSERT_NOT_NULL(h3);

    YAWT_Q_Frame_BufferedStream_t bf = make_buffered_chunk(
        0, YAWT_Q_C_BIDI, NULL, 0, frame_buf, hdr_len, NULL, 0, 0, 1350, 0);

    YAWT_H3_Stream_t *stream = NULL;
    size_t cursor = 0;
    YAWT_H3_Error_t err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);

    TEST_ASSERT_EQUAL(YAWT_H3_OK, err);
    TEST_ASSERT_EQUAL(hdr_len, cursor);

}

/* ------------------------------------------------------------------ */
/*  18. Stream type — WebTransport uni stream (prefix 0x54)           */
/* ------------------------------------------------------------------ */

static void test_stream_type_webtransport_uni(void) {
    uint8_t prefix = 0x54; /* WebTransport stream type */

    YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();
    TEST_ASSERT_NOT_NULL(h3);

    YAWT_Q_Frame_BufferedStream_t bf = make_buffered_chunk(
        9, YAWT_Q_S_UNI, &prefix, 1, NULL, 0, NULL, 0, 0, 1350, 0);

    YAWT_H3_Stream_t *stream = NULL;
    size_t cursor = 0;
    YAWT_H3_Error_t err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
    TEST_ASSERT_EQUAL(YAWT_H3_OK, err);
    TEST_ASSERT_NOT_NULL(stream);
    TEST_ASSERT_EQUAL(YAWT_H3_STREAM_WEBTRANSPORT, stream->type);

}

/* ------------------------------------------------------------------ */
/*  19. Server bidi stream type                                        */
/* ------------------------------------------------------------------ */

static void test_stream_type_server_bidi(void) {
    uint8_t frame_buf[32];
    size_t hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_HEADERS, 0, frame_buf);

    YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();
    TEST_ASSERT_NOT_NULL(h3);

    YAWT_Q_Frame_BufferedStream_t bf = make_buffered_chunk(
        1, YAWT_Q_S_BIDI, NULL, 0, frame_buf, hdr_len, NULL, 0, 0, 1350, 0);

    YAWT_H3_Stream_t *stream = NULL;
    size_t cursor = 0;
    YAWT_H3_Error_t err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
    TEST_ASSERT_EQUAL(YAWT_H3_OK, err);
    TEST_ASSERT_NOT_NULL(stream);
    TEST_ASSERT_EQUAL(YAWT_H3_STREAM_FRAME, stream->type);

}

/* ------------------------------------------------------------------ */
/*  Registration                                                       */
/* ------------------------------------------------------------------ */

void test_h3_register(void) {
    /*
    RUN_TEST(test_settings_frame_on_bidi_stream);
    RUN_TEST(test_settings_out_of_order_chunks);
    RUN_TEST(test_settings_frame_header_only);
    */
    RUN_TEST(test_single_chunk_multiple_frames);
    /*
    RUN_TEST(test_frame_split_across_two_chunks);
    RUN_TEST(test_incomplete_frame_state);
    RUN_TEST(test_data_frame_no_buffering);
    RUN_TEST(test_data_frame_fragmented_chunks);
    RUN_TEST(test_stream_type_bidi);
    RUN_TEST(test_stream_type_control_uni);
    RUN_TEST(test_stream_type_qpack_encoder);
    RUN_TEST(test_stream_type_qpack_decoder);
    RUN_TEST(test_stream_type_uni_split_chunks);
    RUN_TEST(test_h3_parse_frame_null_params);
    RUN_TEST(test_headers_frame_with_payload);
    RUN_TEST(test_headers_frame_out_of_order_chunks);
    RUN_TEST(test_oversized_headers_frame);
    RUN_TEST(test_cursor_advancement);
    RUN_TEST(test_stream_type_webtransport_uni);
    RUN_TEST(test_stream_type_server_bidi);
    */
}
