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
    memset(h3.core_stream_status, 0, sizeof(h3.core_stream_status));

    return &h3;
}


/* ------------------------------------------------------------------ */
/*  1. Settings frame on bidi stream (no stream-type prefix)           */
/* ------------------------------------------------------------------ */

static void test_settings_frame_on_bidi_stream(void) {
  YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();
  YAWT_H3_Settings_t settings = {0};
  YAWT_h3_setting_set(&settings, YAWT_H3_IDX_MAX_FIELD_SECTION_SIZE, 1000);
  YAWT_h3_setting_set(&settings, YAWT_H3_IDX_QPACK_MAX_TABLE_CAPACITY, 2000);

  uint8_t payload[256];
  size_t payload_len = 0;
  YAWT_h3_settings_encode(&settings, payload, sizeof(payload), &payload_len);

  uint8_t frame_hdr[H3_FRAME_MAX_HEADER_BYTES];
  size_t frame_hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_SETTINGS, payload_len, frame_hdr);

  uint64_t stream_id = 0;
  YAWT_Q_IoVec_t iov[] = {
    { frame_hdr, frame_hdr_len },
    { payload, payload_len }
  };

  YAWT_Err_t err;
  YAWT_Q_Frame_BufferedStream_t bf;
  size_t out_iov_offset = 0;
  err = YAWT_q_encode_frame_stream(iov, sizeof(iov)/sizeof(iov[0]), 0, 1000, stream_id, 0, 0, &bf, &out_iov_offset);
  TEST_ASSERT_EQUAL(YAWT_Q_OK, err);

  YAWT_H3_Error_t h3_err;
  size_t cursor = 0;
  YAWT_H3_Stream_t *stream = NULL;
  h3_err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
  TEST_ASSERT_EQUAL(YAWT_H3_OK, h3_err);
  TEST_ASSERT_NOT_NULL(stream);
  TEST_ASSERT_EQUAL(YAWT_H3_STREAM_FRAME, stream->type);
  TEST_ASSERT_EQUAL(YAWT_H3_FRAME_SETTINGS, stream->frame.type);
  TEST_ASSERT_EQUAL(payload_len, stream->frame.payload_len);
  TEST_ASSERT_NOT_NULL(stream->frame.payload_blob);

  YAWT_Q_ReadCursor_t dec = {0};
  dec.data = ANB_blob_data(stream->frame.payload_blob);
  dec.len = stream->frame.payload_len;
  dec.cursor = 0;
  dec.err = YAWT_Q_OK;

  YAWT_H3_Settings_t out_settings = {0};
  h3_err = YAWT_h3_settings_decode(&dec, &out_settings);
  TEST_ASSERT_EQUAL(YAWT_H3_OK, h3_err);
  TEST_ASSERT_EQUAL(1000, out_settings.vals[YAWT_H3_IDX_MAX_FIELD_SECTION_SIZE]);
  TEST_ASSERT_EQUAL(2000, out_settings.vals[YAWT_H3_IDX_QPACK_MAX_TABLE_CAPACITY]);
}

/* ------------------------------------------------------------------ */
/*  2. Settings out-of-order chunks on uni stream                     */
/* ------------------------------------------------------------------ */

static void test_settings_out_of_order_chunks(void) {
  YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();
  YAWT_H3_Settings_t settings_a = {0};
  YAWT_h3_setting_set(&settings_a, YAWT_H3_IDX_QPACK_MAX_TABLE_CAPACITY, 500);
  YAWT_H3_Settings_t settings_b = {0};
  YAWT_h3_setting_set(&settings_b, YAWT_H3_IDX_MAX_FIELD_SECTION_SIZE, 1500);

  uint8_t payload_a[256], payload_b[256];
  size_t payload_a_len = 0, payload_b_len = 0;
  YAWT_h3_settings_encode(&settings_a, payload_a, sizeof(payload_a), &payload_a_len);
  YAWT_h3_settings_encode(&settings_b, payload_b, sizeof(payload_b), &payload_b_len);

  uint8_t frame_hdr_a[H3_FRAME_MAX_HEADER_BYTES], frame_hdr_b[H3_FRAME_MAX_HEADER_BYTES];
  size_t frame_hdr_a_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_SETTINGS, payload_a_len, frame_hdr_a);
  size_t frame_hdr_b_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_SETTINGS, payload_b_len, frame_hdr_b);

  /* Deliver frame B first, then frame A (out of order via IOV) */
  YAWT_Q_IoVec_t iov_reordered[] = {
    { frame_hdr_b, frame_hdr_b_len },
    { payload_b, payload_b_len },
    { frame_hdr_a, frame_hdr_a_len },
    { payload_a, payload_a_len }
  };

  YAWT_Err_t err;
  YAWT_Q_Frame_BufferedStream_t bf;
  size_t out_iov_offset = 0;
  err = YAWT_q_encode_frame_stream(iov_reordered, sizeof(iov_reordered)/sizeof(iov_reordered[0]), 0, 1000, 4, 0, 0, &bf, &out_iov_offset);
  TEST_ASSERT_EQUAL(YAWT_Q_OK, err);

  YAWT_H3_Error_t h3_err;
  size_t cursor = 0;
  YAWT_H3_Stream_t *stream = NULL;

  h3_err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
  TEST_ASSERT_EQUAL(YAWT_H3_OK, h3_err);
  TEST_ASSERT_EQUAL(YAWT_H3_FRAME_SETTINGS, stream->frame.type);

YAWT_Q_ReadCursor_t dec = {0};
   dec.data = ANB_blob_data(stream->frame.payload_blob);
   dec.len = stream->frame.payload_len;
   dec.cursor = 0;
   dec.err = YAWT_Q_OK;

   YAWT_H3_Settings_t out_settings = {0};
   h3_err = YAWT_h3_settings_decode(&dec, &out_settings);
   TEST_ASSERT_EQUAL(YAWT_H3_OK, h3_err);
   TEST_ASSERT_EQUAL(1500, out_settings.vals[YAWT_H3_IDX_MAX_FIELD_SECTION_SIZE]);
   TEST_ASSERT_EQUAL(0, out_settings.vals[YAWT_H3_IDX_QPACK_MAX_TABLE_CAPACITY]);

   h3_err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
   TEST_ASSERT_EQUAL(YAWT_H3_OK, h3_err);
   dec.data = ANB_blob_data(stream->frame.payload_blob);
   dec.len = stream->frame.payload_len;
   dec.cursor = 0;
   dec.err = YAWT_Q_OK;

   YAWT_H3_Settings_t out_settings2 = {0};
   h3_err = YAWT_h3_settings_decode(&dec, &out_settings2);
   TEST_ASSERT_EQUAL(YAWT_H3_OK, h3_err);
   TEST_ASSERT_EQUAL(500, out_settings2.vals[YAWT_H3_IDX_QPACK_MAX_TABLE_CAPACITY]);
}

/* ------------------------------------------------------------------ */
/*  3. Settings frame header-only (no payload)                         */
/* ------------------------------------------------------------------ */

static void test_settings_frame_header_only(void) {
  YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();

  uint8_t frame_hdr[H3_FRAME_MAX_HEADER_BYTES];
  size_t frame_hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_SETTINGS, 0, frame_hdr);

  uint64_t stream_id = 0;
  YAWT_Q_IoVec_t iov[] = {
    { frame_hdr, frame_hdr_len }
  };

  YAWT_Err_t err;
  YAWT_Q_Frame_BufferedStream_t bf;
  size_t out_iov_offset = 0;
  err = YAWT_q_encode_frame_stream(iov, sizeof(iov)/sizeof(iov[0]), 0, 1000, stream_id, 0, 0, &bf, &out_iov_offset);
  TEST_ASSERT_EQUAL(YAWT_Q_OK, err);

  YAWT_H3_Error_t h3_err;
  size_t cursor = 0;
  YAWT_H3_Stream_t *stream = NULL;
h3_err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
   TEST_ASSERT_EQUAL(YAWT_H3_OK, h3_err);
   TEST_ASSERT_NOT_NULL(stream);
   TEST_ASSERT_EQUAL(YAWT_H3_FRAME_SETTINGS, stream->frame.type);
   TEST_ASSERT_EQUAL(0, stream->frame.payload_len);
}

/* ------------------------------------------------------------------ */
/*  4. Single chunk contains multiple SETTINGS frames                  */
/* ------------------------------------------------------------------ */

static void test_single_chunk_multiple_frames(void) {

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


  uint8_t frame_hdr_a[H3_FRAME_MAX_HEADER_BYTES];
  uint8_t frame_hdr_b[H3_FRAME_MAX_HEADER_BYTES];
  size_t frame_hdr_a_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_SETTINGS, payload_a_len, frame_hdr_a);
  size_t frame_hdr_b_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_SETTINGS, payload_b_len, frame_hdr_b);

  uint8_t stream_type = YAWT_H3_STREAM_WIRE_CONTROL;
  uint64_t stream_id = 3; /* server-initiated uni (RFC 9114 §6.2.1) */
  YAWT_Q_IoVec_t iov_a[] = {
    { &stream_type, 1 },
    { frame_hdr_a, frame_hdr_a_len },
    { payload_a, payload_a_len },
    { frame_hdr_b, frame_hdr_b_len },
    { payload_b, payload_b_len }
  };



  YAWT_Err_t err;
  YAWT_Q_Frame_BufferedStream_t bf;
  size_t out_iov_offset = 0;
  err = YAWT_q_encode_frame_stream(iov_a,sizeof(iov_a)/sizeof(iov_a[0]),0,1000,stream_id,0,0,&bf, &out_iov_offset);
  TEST_ASSERT_EQUAL(YAWT_Q_OK, err);
  YAWT_H3_Error_t h3_err;
  YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();
  size_t cursor = 0;
  YAWT_H3_Stream_t *stream = NULL;
  YAWT_H3_Settings_t out_settings_a = {0};
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
  h3_err = YAWT_h3_settings_decode(&dec, &out_settings_a);

  TEST_ASSERT_EQUAL(YAWT_H3_OK, h3_err);
  TEST_ASSERT_EQUAL(100, out_settings_a.vals[YAWT_H3_IDX_MAX_FIELD_SECTION_SIZE]); 
  TEST_ASSERT_EQUAL(200, out_settings_a.vals[YAWT_H3_IDX_QPACK_MAX_TABLE_CAPACITY]);
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
  YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();
  YAWT_H3_Settings_t settings = {0};
  YAWT_h3_setting_set(&settings, YAWT_H3_IDX_QPACK_MAX_TABLE_CAPACITY, 777);

  uint8_t payload[256];
  size_t payload_len = 0;
  YAWT_h3_settings_encode(&settings, payload, sizeof(payload), &payload_len);

  uint8_t frame_hdr[H3_FRAME_MAX_HEADER_BYTES];
  size_t frame_hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_SETTINGS, payload_len, frame_hdr);

  /* Split the SETTINGS frame: chunk1 = header + first half, chunk2 = second half */
  size_t mid = payload_len / 2;

  uint8_t chunk1_buf[512];
  memcpy(chunk1_buf, frame_hdr, frame_hdr_len);
  memcpy(chunk1_buf + frame_hdr_len, payload, mid);
  size_t chunk1_len = frame_hdr_len + mid;

  uint8_t chunk2_buf[256];
  memcpy(chunk2_buf, payload + mid, payload_len - mid);
  size_t chunk2_len = payload_len - mid;

  /* Encode chunk 1 (header + first half of payload) */
  YAWT_Q_IoVec_t iov1[] = { { chunk1_buf, chunk1_len } };
  YAWT_Q_Frame_BufferedStream_t bf1;
  size_t out_offset = 0;
  YAWT_Err_t err = YAWT_q_encode_frame_stream(iov1, sizeof(iov1)/sizeof(iov1[0]), 0, 1000, 8, 0, 0, &bf1, &out_offset);
  TEST_ASSERT_EQUAL(YAWT_Q_OK, err);

  /* Encode chunk 2 (second half of payload, offset = mid) */
  YAWT_Q_IoVec_t iov2[] = { { chunk2_buf, chunk2_len } };
  YAWT_Q_Frame_BufferedStream_t bf2;
  out_offset = 0;
  err = YAWT_q_encode_frame_stream(iov2, sizeof(iov2)/sizeof(iov2[0]), 0, 1000, 8, mid, 0, &bf2, &out_offset);
  TEST_ASSERT_EQUAL(YAWT_Q_OK, err);

  /* Parse chunk 1: frame header is complete but payload is truncated */
  YAWT_H3_Error_t h3_err;
  size_t cursor = 0;
  YAWT_H3_Stream_t *stream = NULL;

  cursor = 0;
  h3_err = YAWT_h3_parse_frame(h3, &bf1.frame, &stream, &cursor);
  TEST_ASSERT_EQUAL(YAWT_H3_ERR_INCOMPLETE, h3_err);
  TEST_ASSERT_NOT_NULL(stream);
  TEST_ASSERT_EQUAL(YAWT_H3_FRAME_SETTINGS, stream->frame.type);

  /* Parse chunk 2: completes the frame */
  cursor = 0;
  h3_err = YAWT_h3_parse_frame(h3, &bf2.frame, &stream, &cursor);
  TEST_ASSERT_EQUAL(YAWT_H3_OK, h3_err);
  TEST_ASSERT_EQUAL(payload_len, stream->frame.payload_len);
  TEST_ASSERT_NOT_NULL(stream->frame.payload_blob);

  YAWT_Q_ReadCursor_t dec = {0};
  dec.data = ANB_blob_data(stream->frame.payload_blob);
  dec.len = stream->frame.payload_len;
  dec.cursor = 0;
  dec.err = YAWT_Q_OK;

  YAWT_H3_Settings_t out_settings = {0};
  h3_err = YAWT_h3_settings_decode(&dec, &out_settings);
  TEST_ASSERT_EQUAL(YAWT_H3_OK, h3_err);
  TEST_ASSERT_EQUAL(777, out_settings.vals[YAWT_H3_IDX_QPACK_MAX_TABLE_CAPACITY]);
}

/* ------------------------------------------------------------------ */
/*  6. Incomplete frame returns OK but frame not dispatched yet        */
/* ------------------------------------------------------------------ */

static void test_incomplete_frame_state(void) {
  /* A truncated frame header should return INCOMPLETE, not parse a frame. */
  YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();

  uint8_t payload[256];
  size_t payload_len = 0;
  YAWT_H3_Settings_t settings = {0};
  YAWT_h3_setting_set(&settings, YAWT_H3_IDX_QPACK_MAX_TABLE_CAPACITY, 100);
  YAWT_h3_settings_encode(&settings, payload, sizeof(payload), &payload_len);

  uint8_t frame_hdr[H3_FRAME_MAX_HEADER_BYTES];
  size_t frame_hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_SETTINGS, payload_len, frame_hdr);

  /* Send only the type byte of the frame header (truncate the length) */
  uint8_t truncated_frame[512];
  /* frame_hdr starts with type varint, then length varint */
  /* Copy just the first byte of the frame header (frame type) */
  truncated_frame[0] = frame_hdr[0];
  size_t truncated_len = 1;

   YAWT_Q_IoVec_t iov[] = { { truncated_frame, truncated_len } };
   YAWT_Q_Frame_BufferedStream_t bf;
   size_t out_offset = 0;
   YAWT_Err_t err = YAWT_q_encode_frame_stream(iov, sizeof(iov)/sizeof(iov[0]), 0, 1000, 8, 0, 0, &bf, &out_offset);
  TEST_ASSERT_EQUAL(YAWT_Q_OK, err);

  YAWT_H3_Error_t h3_err;
  size_t cursor = 0;
  YAWT_H3_Stream_t *stream = NULL;

  h3_err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
  TEST_ASSERT_EQUAL(YAWT_H3_ERR_INCOMPLETE, h3_err);
  TEST_ASSERT_NOT_NULL(stream);

  /* The frame should not have a payload blob yet */
  TEST_ASSERT_NULL(stream->frame.payload_blob);
}

/* ------------------------------------------------------------------ */
/*  7. DATA frame no buffering                                         */
/* ------------------------------------------------------------------ */

static void test_data_frame_no_buffering(void) {
  /* DATA frames should not allocate a payload blob — they are passed through
   * directly. The frame type should be DATA and the payload should be available
   * from the chunk data itself. */
  YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();

  uint8_t data[] = "Hello, HTTP/3!";
  uint8_t frame_hdr[H3_FRAME_MAX_HEADER_BYTES];
  size_t frame_hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_DATA, sizeof(data) - 1, frame_hdr);

  YAWT_Q_IoVec_t iov[] = {
    { frame_hdr, frame_hdr_len },
    { data, sizeof(data) - 1 }
  };

  YAWT_Q_Frame_BufferedStream_t bf;
  size_t out_offset = 0;
  YAWT_Err_t err = YAWT_q_encode_frame_stream(iov, sizeof(iov)/sizeof(iov[0]), 0, 1000, 12, 0, 0, &bf, &out_offset);
  TEST_ASSERT_EQUAL(YAWT_Q_OK, err);

  YAWT_H3_Error_t h3_err;
  size_t cursor = 0;
  YAWT_H3_Stream_t *stream = NULL;

  h3_err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
  TEST_ASSERT_EQUAL(YAWT_H3_OK, h3_err);
  TEST_ASSERT_EQUAL(YAWT_H3_FRAME_DATA, stream->frame.type);
  TEST_ASSERT_EQUAL(sizeof(data) - 1, stream->frame.payload_len);
  /* DATA frames should not allocate a blob */
  TEST_ASSERT_NULL(stream->frame.payload_blob);
}

/* ------------------------------------------------------------------ */
/*  8. DATA frame fragmented chunks                                   */
/* ------------------------------------------------------------------ */

static void test_data_frame_fragmented_chunks(void) {
  /* A HEADERS frame split across multiple QUIC chunks should be correctly
    * reassembled. HEADERS frames require buffering since payload_len must
    * be known before allocating the blob. */
   YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();

   uint8_t data[] = "This is a fragmented HEADERS frame test payload";
   size_t data_len = sizeof(data) - 1;

   /* Build a complete HTTP/3 HEADERS frame: frame_header + payload */
    uint8_t frame_hdr[H3_FRAME_MAX_HEADER_BYTES];
    size_t frame_hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_HEADERS, data_len, frame_hdr);

    uint8_t frame_data[256];
    size_t frame_len = 0;
    memcpy(frame_data + frame_len, frame_hdr, frame_hdr_len);
    frame_len += frame_hdr_len;
    memcpy(frame_data + frame_len, data, data_len);
    frame_len += data_len;

    /* Chunk 1: frame header + partial payload (incomplete) */
    size_t split_point = frame_hdr_len + 5; /* frame_hdr + 5 bytes of payload */
    uint8_t chunk1[256];
    memcpy(chunk1, frame_data, split_point);
    size_t chunk1_len = split_point;

    /* Chunk 2: remaining payload */
    uint8_t chunk2[256];
    memcpy(chunk2, frame_data + split_point, frame_len - split_point);
    size_t chunk2_len = frame_len - split_point;

     YAWT_Q_IoVec_t iov1[] = { { chunk1, chunk1_len } };
     YAWT_Q_Frame_BufferedStream_t bf1;
     size_t out_offset = 0;
     YAWT_Err_t err = YAWT_q_encode_frame_stream(iov1, sizeof(iov1)/sizeof(iov1[0]), 0, 1000, 0, 0, 0, &bf1, &out_offset);
     TEST_ASSERT_EQUAL(YAWT_Q_OK, err);

     YAWT_Q_IoVec_t iov2[] = { { chunk2, chunk2_len } };
     YAWT_Q_Frame_BufferedStream_t bf2;
     out_offset = 0;
     err = YAWT_q_encode_frame_stream(iov2, sizeof(iov2)/sizeof(iov2[0]), 0, 1000, 0, split_point, 0, &bf2, &out_offset);
    TEST_ASSERT_EQUAL(YAWT_Q_OK, err);

   YAWT_H3_Error_t h3_err;
   size_t cursor = 0;
   YAWT_H3_Stream_t *stream = NULL;

   /* First chunk: incomplete because payload is truncated */
   cursor = 0;
   h3_err = YAWT_h3_parse_frame(h3, &bf1.frame, &stream, &cursor);
   TEST_ASSERT_EQUAL(YAWT_H3_ERR_INCOMPLETE, h3_err);
   TEST_ASSERT_NOT_NULL(stream);
   TEST_ASSERT_EQUAL(YAWT_H3_FRAME_HEADERS, stream->frame.type);

   /* Second chunk: completes the frame */
   cursor = 0;
   h3_err = YAWT_h3_parse_frame(h3, &bf2.frame, &stream, &cursor);
   TEST_ASSERT_EQUAL(YAWT_H3_OK, h3_err);
   TEST_ASSERT_EQUAL(YAWT_H3_FRAME_HEADERS, stream->frame.type);
   TEST_ASSERT_EQUAL(data_len, stream->frame.payload_len);
   TEST_ASSERT_NOT_NULL(stream->frame.payload_blob);
   TEST_ASSERT_EQUAL(data_len, ANB_blob_data_len(stream->frame.payload_blob));
}

/* ------------------------------------------------------------------ */
/*  9. Stream type resolution — bidi stream (no prefix)               */
/* ------------------------------------------------------------------ */

static void test_stream_type_bidi(void) {
  /* Bidirectional streams have no stream-type prefix and should resolve
   * immediately to STREAM_FRAME. */
  YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();

  uint8_t payload[] = "bidi stream data";
  uint8_t frame_hdr[H3_FRAME_MAX_HEADER_BYTES];
  size_t frame_hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_DATA, sizeof(payload) - 1, frame_hdr);

  YAWT_Q_IoVec_t iov[] = {
    { frame_hdr, frame_hdr_len },
    { payload, sizeof(payload) - 1 }
  };

  YAWT_Q_Frame_BufferedStream_t bf;
  size_t out_offset = 0;
  YAWT_Err_t err = YAWT_q_encode_frame_stream(iov, sizeof(iov)/sizeof(iov[0]), 0, 1000, 16, 0, 0, &bf, &out_offset);
  TEST_ASSERT_EQUAL(YAWT_Q_OK, err);

  YAWT_H3_Error_t h3_err;
  size_t cursor = 0;
  YAWT_H3_Stream_t *stream = NULL;

  h3_err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
  TEST_ASSERT_EQUAL(YAWT_H3_OK, h3_err);
  TEST_ASSERT_EQUAL(YAWT_H3_STREAM_FRAME, stream->type);
  TEST_ASSERT_EQUAL(YAWT_H3_FRAME_DATA, stream->frame.type);
}

/* ------------------------------------------------------------------ */
/*  10. Stream type resolution — control uni stream (prefix 0x00)     */
/* ------------------------------------------------------------------ */

static void test_stream_type_control_uni(void) {
  /* Unidirectional stream with 0x00 prefix should resolve to STREAM_CONTROL. */
  YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();

  uint8_t stream_type_buf[8];
  size_t stream_type_len = 0;
  YAWT_q_varint_encode(YAWT_H3_STREAM_WIRE_CONTROL, stream_type_buf, sizeof(stream_type_buf), &stream_type_len);

  uint8_t payload[] = "control stream data";
  uint8_t frame_hdr[H3_FRAME_MAX_HEADER_BYTES];
  size_t frame_hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_SETTINGS, sizeof(payload) - 1, frame_hdr);

  YAWT_Q_IoVec_t iov[] = {
    { stream_type_buf, stream_type_len },
    { frame_hdr, frame_hdr_len },
    { payload, sizeof(payload) - 1 }
  };

  YAWT_Q_Frame_BufferedStream_t bf;
  size_t out_offset = 0;
  YAWT_Err_t err = YAWT_q_encode_frame_stream(iov, sizeof(iov)/sizeof(iov[0]), 0, 1000, 19, 0, 0, &bf, &out_offset);
  TEST_ASSERT_EQUAL(YAWT_Q_OK, err);

  YAWT_H3_Error_t h3_err;
  size_t cursor = 0;
  YAWT_H3_Stream_t *stream = NULL;

  h3_err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
  TEST_ASSERT_EQUAL(YAWT_H3_OK, h3_err);
  TEST_ASSERT_EQUAL(YAWT_H3_STREAM_CONTROL, stream->type);
  TEST_ASSERT_EQUAL(YAWT_H3_FRAME_SETTINGS, stream->frame.type);
}

/* ------------------------------------------------------------------ */
/*  11. Stream type — QPACK encoder/decoder uni streams              */
/* ------------------------------------------------------------------ */

static void test_stream_type_qpack_encoder(void) {
  /* Unidirectional stream with 0x02 prefix should resolve to QPACK_ENCODER.
   * stream_id=19 is server-initiated uni (19%4=3), valid for QPACK streams. */
  YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();

  uint8_t stream_type_buf[8];
  size_t stream_type_len = 0;
  YAWT_q_varint_encode(YAWT_H3_STREAM_WIRE_QPACK_ENCODER, stream_type_buf, sizeof(stream_type_buf), &stream_type_len);

  /* QPACK streams don't carry H3 frames, so the parser should return IGNORED */
  YAWT_Q_IoVec_t iov[] = {
    { stream_type_buf, stream_type_len }
  };

  YAWT_Q_Frame_BufferedStream_t bf;
  size_t out_offset = 0;
   YAWT_Err_t err = YAWT_q_encode_frame_stream(iov, sizeof(iov)/sizeof(iov[0]), 0, 1000, 19, 0, 0, &bf, &out_offset);
  TEST_ASSERT_EQUAL(YAWT_Q_OK, err);

  YAWT_H3_Error_t h3_err;
  size_t cursor = 0;
  YAWT_H3_Stream_t *stream = NULL;

  h3_err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
  TEST_ASSERT_EQUAL(YAWT_H3_IGNORED, h3_err);
  TEST_ASSERT_EQUAL(YAWT_H3_STREAM_QPACK_ENCODER, stream->type);
}

static void test_stream_type_qpack_decoder(void) {
  /* Unidirectional stream with 0x03 prefix should resolve to QPACK_DECODER.
   * stream_id=23 is server-initiated uni (23%4=3), valid for QPACK streams. */
  YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();

  uint8_t stream_type_buf[8];
  size_t stream_type_len = 0;
  YAWT_q_varint_encode(YAWT_H3_STREAM_WIRE_QPACK_DECODER, stream_type_buf, sizeof(stream_type_buf), &stream_type_len);

  YAWT_Q_IoVec_t iov[] = {
    { stream_type_buf, stream_type_len }
  };

  YAWT_Q_Frame_BufferedStream_t bf;
  size_t out_offset = 0;
  YAWT_Err_t err = YAWT_q_encode_frame_stream(iov, sizeof(iov)/sizeof(iov[0]), 0, 1000, 23, 0, 0, &bf, &out_offset);
  TEST_ASSERT_EQUAL(YAWT_Q_OK, err);

  YAWT_H3_Error_t h3_err;
  size_t cursor = 0;
  YAWT_H3_Stream_t *stream = NULL;

  h3_err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
  TEST_ASSERT_EQUAL(YAWT_H3_IGNORED, h3_err);
  TEST_ASSERT_EQUAL(YAWT_H3_STREAM_QPACK_DECODER, stream->type);
}

/* ------------------------------------------------------------------ */
/*  12. Stream type — uni stream split across chunks                 */
/* ------------------------------------------------------------------ */

static void test_stream_type_uni_split_chunks(void) {
  /* A uni stream type varint (0x00) can be split across chunks. The parser
    * should accumulate the bytes until the varint is fully decoded. */
   YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();

   uint8_t stream_type_buf[8];
   size_t stream_type_len = 0;
   YAWT_q_varint_encode(YAWT_H3_STREAM_WIRE_QPACK_DECODER, stream_type_buf, sizeof(stream_type_buf), &stream_type_len);

   uint8_t frame_hdr[H3_FRAME_MAX_HEADER_BYTES];
   size_t frame_hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_SETTINGS, 0, frame_hdr);

   uint8_t combined[16];
   memcpy(combined, stream_type_buf, stream_type_len);
   memcpy(combined + stream_type_len, frame_hdr, frame_hdr_len);
   size_t combined_len = stream_type_len + frame_hdr_len;

   YAWT_Q_IoVec_t iov1[] = { { combined, combined_len } };
   YAWT_Q_Frame_BufferedStream_t bf1;
   size_t out_offset = 0;
    YAWT_Err_t err = YAWT_q_encode_frame_stream(iov1, sizeof(iov1)/sizeof(iov1[0]), 0, 1000, 27, 0, 0, &bf1, &out_offset);
   TEST_ASSERT_EQUAL(YAWT_Q_OK, err);

   YAWT_H3_Error_t h3_err;
   size_t cursor = 0;
   YAWT_H3_Stream_t *stream = NULL;

   h3_err = YAWT_h3_parse_frame(h3, &bf1.frame, &stream, &cursor);
   TEST_ASSERT_EQUAL(YAWT_H3_IGNORED, h3_err);
   TEST_ASSERT_EQUAL(YAWT_H3_STREAM_QPACK_DECODER, stream->type);
}

/* ------------------------------------------------------------------ */
/*  13. Invalid param tests                                            */
/* ------------------------------------------------------------------ */

static void test_h3_parse_frame_null_params(void) {
  /* Passing NULL pointers should return INVALID_PARAM. */
  YAWT_H3_Error_t h3_err;
  YAWT_Q_Frame_Stream_t dummy_frame = {0};

  h3_err = YAWT_h3_parse_frame(NULL, &dummy_frame, NULL, NULL);
  TEST_ASSERT_EQUAL(YAWT_H3_ERR_INVALID_PARAM, h3_err);

  YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();

  h3_err = YAWT_h3_parse_frame(h3, NULL, NULL, NULL);
  TEST_ASSERT_EQUAL(YAWT_H3_ERR_INVALID_PARAM, h3_err);

  h3_err = YAWT_h3_parse_frame(h3, &dummy_frame, NULL, NULL);
  TEST_ASSERT_EQUAL(YAWT_H3_ERR_INVALID_PARAM, h3_err);

  h3_err = YAWT_h3_parse_frame(h3, &dummy_frame, NULL, NULL);
  TEST_ASSERT_EQUAL(YAWT_H3_ERR_INVALID_PARAM, h3_err);
}

/* ------------------------------------------------------------------ */
/*  14. HEADERS frame with QPACK-encoded payload                      */
/* ------------------------------------------------------------------ */

static void test_headers_frame_with_payload(void) {
  /* A HEADERS frame should allocate a payload blob and parse correctly.
   * The payload contains QPACK-encoded data, but we're only testing the
   * frame parsing layer, not QPACK decoding. */
  YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();

  /* Simulate QPACK-encoded header section (raw bytes, not actually valid QPACK) */
  uint8_t headers_data[] = { 0x00, 0x01, 0x80, 0x00, 0xFF };

  uint8_t frame_hdr[H3_FRAME_MAX_HEADER_BYTES];
  size_t frame_hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_HEADERS, sizeof(headers_data), frame_hdr);

  YAWT_Q_IoVec_t iov[] = {
    { frame_hdr, frame_hdr_len },
    { headers_data, sizeof(headers_data) }
  };

  YAWT_Q_Frame_BufferedStream_t bf;
  size_t out_offset = 0;
   YAWT_Err_t err = YAWT_q_encode_frame_stream(iov, sizeof(iov)/sizeof(iov[0]), 0, 1000, 24, 0, 0, &bf, &out_offset);
  TEST_ASSERT_EQUAL(YAWT_Q_OK, err);

  YAWT_H3_Error_t h3_err;
  size_t cursor = 0;
  YAWT_H3_Stream_t *stream = NULL;

  h3_err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
  TEST_ASSERT_EQUAL(YAWT_H3_OK, h3_err);
  TEST_ASSERT_EQUAL(YAWT_H3_FRAME_HEADERS, stream->frame.type);
  TEST_ASSERT_EQUAL(sizeof(headers_data), stream->frame.payload_len);
  /* HEADERS frames allocate a payload blob */
  TEST_ASSERT_NOT_NULL(stream->frame.payload_blob);
  TEST_ASSERT_EQUAL(sizeof(headers_data), ANB_blob_data_len(stream->frame.payload_blob));
}

/* ------------------------------------------------------------------ */
/*  15. HEADERS frame out-of-order chunks                             */
/* ------------------------------------------------------------------ */

static void test_headers_frame_out_of_order_chunks(void) {
  /* A HEADERS frame split across two chunks should be correctly
   * reassembled. The parser should accumulate bytes and only dispatch
   * the frame when all data arrives. */
  YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();

  uint8_t headers_data[] = { 0x00, 0x01, 0x82, 0x00, 0x7F, 0xFF, 0xAA, 0xBB };
  size_t headers_len = sizeof(headers_data);

  uint8_t frame_hdr[H3_FRAME_MAX_HEADER_BYTES];
  size_t frame_hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_HEADERS, headers_len, frame_hdr);

  /* Split: chunk1 = header + first 3 bytes, chunk2 = remaining 5 bytes */
  size_t split = 3;

  uint8_t chunk1_buf[256];
  memcpy(chunk1_buf, frame_hdr, frame_hdr_len);
  memcpy(chunk1_buf + frame_hdr_len, headers_data, split);
  size_t chunk1_len = frame_hdr_len + split;

  uint8_t chunk2_buf[256];
  memcpy(chunk2_buf, headers_data + split, headers_len - split);
  size_t chunk2_len = headers_len - split;

  YAWT_Q_IoVec_t iov1[] = { { chunk1_buf, chunk1_len } };
  YAWT_Q_Frame_BufferedStream_t bf1;
  size_t out_offset = 0;
  YAWT_Err_t err = YAWT_q_encode_frame_stream(iov1, sizeof(iov1)/sizeof(iov1[0]), 0, 1000, 28, 0, 0, &bf1, &out_offset);
  TEST_ASSERT_EQUAL(YAWT_Q_OK, err);

  YAWT_Q_IoVec_t iov2[] = { { chunk2_buf, chunk2_len } };
  YAWT_Q_Frame_BufferedStream_t bf2;
  out_offset = 0;
  err = YAWT_q_encode_frame_stream(iov2, sizeof(iov2)/sizeof(iov2[0]), 0, 1000, 28, split, 0, &bf2, &out_offset);
  TEST_ASSERT_EQUAL(YAWT_Q_OK, err);

  YAWT_H3_Error_t h3_err;
  size_t cursor = 0;
  YAWT_H3_Stream_t *stream = NULL;

  /* First chunk: incomplete (payload truncated) */
  cursor = 0;
  h3_err = YAWT_h3_parse_frame(h3, &bf1.frame, &stream, &cursor);
  TEST_ASSERT_EQUAL(YAWT_H3_ERR_INCOMPLETE, h3_err);

  /* Second chunk: completes the HEADERS frame */
  cursor = 0;
  h3_err = YAWT_h3_parse_frame(h3, &bf2.frame, &stream, &cursor);
  TEST_ASSERT_EQUAL(YAWT_H3_OK, h3_err);
  TEST_ASSERT_EQUAL(YAWT_H3_FRAME_HEADERS, stream->frame.type);
  TEST_ASSERT_EQUAL(headers_len, stream->frame.payload_len);
  TEST_ASSERT_NOT_NULL(stream->frame.payload_blob);
}

/* ------------------------------------------------------------------ */
/*  16. Oversized HEADERS frame                                        */
/* ------------------------------------------------------------------ */

static void test_oversized_headers_frame(void) {
  /* A HEADERS frame exceeding the max_field_section_size security limit
   * should be rejected with TOO_LARGE. */
  YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();

  /* Set a small max_field_section_size to trigger rejection */
  YAWT_H3_SecurityPolicy_t policy = {0};
  policy.max_field_section_size = 500;
  YAWT_h3_security_set(&policy);

  /* Create a payload larger than the configured limit */
  uint8_t large_headers[1000];
  memset(large_headers, 0xFF, sizeof(large_headers));

  uint8_t frame_hdr[H3_FRAME_MAX_HEADER_BYTES];
  size_t frame_hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_HEADERS, sizeof(large_headers), frame_hdr);

  YAWT_Q_IoVec_t iov[] = {
    { frame_hdr, frame_hdr_len },
    { large_headers, sizeof(large_headers) }
  };

  YAWT_Q_Frame_BufferedStream_t bf;
  size_t out_offset = 0;
  YAWT_Err_t err = YAWT_q_encode_frame_stream(iov, sizeof(iov)/sizeof(iov[0]), 0, 1000, 0, 0, 0, &bf, &out_offset);
  TEST_ASSERT_EQUAL(YAWT_Q_OK, err);

  YAWT_H3_Error_t h3_err;
  size_t cursor = 0;
  YAWT_H3_Stream_t *stream = NULL;

  h3_err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
  TEST_ASSERT_EQUAL(YAWT_H3_ERR_TOO_LARGE, h3_err);

  /* Restore default policy */
  YAWT_H3_SecurityPolicy_t default_policy = {0};
  default_policy.max_field_section_size = 16384;
  YAWT_h3_security_set(&default_policy);
}

/* ------------------------------------------------------------------ */
/*  17. Cursor advancement in parse loop                               */
/* ------------------------------------------------------------------ */

static void test_cursor_advancement(void) {
  /* The cursor should advance past each fully-parsed frame so the next
   * parse call picks up the next frame in the stream. */
  YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();

  uint8_t payload_a[256], payload_b[256];
  size_t payload_a_len = 0, payload_b_len = 0;
  YAWT_H3_Settings_t settings_a = {0};
  YAWT_h3_setting_set(&settings_a, YAWT_H3_IDX_QPACK_MAX_TABLE_CAPACITY, 100);
  YAWT_h3_settings_encode(&settings_a, payload_a, sizeof(payload_a), &payload_a_len);

  YAWT_H3_Settings_t settings_b = {0};
  YAWT_h3_setting_set(&settings_b, YAWT_H3_IDX_MAX_FIELD_SECTION_SIZE, 200);
  YAWT_h3_settings_encode(&settings_b, payload_b, sizeof(payload_b), &payload_b_len);

  uint8_t frame_hdr_a[H3_FRAME_MAX_HEADER_BYTES], frame_hdr_b[H3_FRAME_MAX_HEADER_BYTES];
  size_t frame_hdr_a_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_SETTINGS, payload_a_len, frame_hdr_a);
  size_t frame_hdr_b_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_SETTINGS, payload_b_len, frame_hdr_b);

  size_t frame_a_total = frame_hdr_a_len + payload_a_len;

  YAWT_Q_IoVec_t iov[] = {
    { frame_hdr_a, frame_hdr_a_len },
    { payload_a, payload_a_len },
    { frame_hdr_b, frame_hdr_b_len },
    { payload_b, payload_b_len }
  };

  YAWT_Q_Frame_BufferedStream_t bf;
  size_t out_offset = 0;
  YAWT_Err_t err = YAWT_q_encode_frame_stream(iov, sizeof(iov)/sizeof(iov[0]), 0, 1000, 32, 0, 0, &bf, &out_offset);
  TEST_ASSERT_EQUAL(YAWT_Q_OK, err);

  YAWT_H3_Error_t h3_err;
  size_t cursor = 0;
  YAWT_H3_Stream_t *stream = NULL;

  /* First parse: should consume frame A entirely, cursor should advance */
  cursor = 0;
  h3_err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
  TEST_ASSERT_EQUAL(YAWT_H3_OK, h3_err);
  size_t after_first = cursor;
  TEST_ASSERT_GREATER_THAN(0, after_first);

  /* Second parse: should pick up frame B at the cursor position */
  h3_err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
  TEST_ASSERT_EQUAL(YAWT_H3_OK, h3_err);
  TEST_ASSERT_EQUAL(YAWT_H3_FRAME_SETTINGS, stream->frame.type);
  TEST_ASSERT_EQUAL(payload_b_len, stream->frame.payload_len);

  YAWT_Q_ReadCursor_t dec = {0};
  dec.data = ANB_blob_data(stream->frame.payload_blob);
  dec.len = stream->frame.payload_len;
  dec.cursor = 0;
  dec.err = YAWT_Q_OK;

  YAWT_H3_Settings_t out_settings = {0};
  h3_err = YAWT_h3_settings_decode(&dec, &out_settings);
  TEST_ASSERT_EQUAL(YAWT_H3_OK, h3_err);
  TEST_ASSERT_EQUAL(200, out_settings.vals[YAWT_H3_IDX_MAX_FIELD_SECTION_SIZE]);

  /* Third parse: should return INCOMPLETE since all frames consumed */
  h3_err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
  TEST_ASSERT_EQUAL(YAWT_H3_ERR_INCOMPLETE, h3_err);
}

/* ------------------------------------------------------------------ */
/*  18. Server bidi stream type                                        */
/* ------------------------------------------------------------------ */

static void test_stream_type_server_bidi(void) {
  /* Server-initiated bidirectional streams also have no prefix and resolve
     * to STREAM_FRAME. Server bidi stream IDs are odd (stream_id % 4 == 1). */
   YAWT_H3_Connection_t *h3 = alloc_minimal_h3_conn();

   uint8_t payload[] = "server bidi response";
   uint8_t frame_hdr[H3_FRAME_MAX_HEADER_BYTES];
   size_t frame_hdr_len = YAWT_h3_encode_frame_header(YAWT_H3_FRAME_DATA, sizeof(payload) - 1, frame_hdr);

   uint64_t server_bidi_stream_id = 5; /* server-initiated bidi (stream_id % 4 == 1) */

  YAWT_Q_IoVec_t iov[] = {
    { frame_hdr, frame_hdr_len },
    { payload, sizeof(payload) - 1 }
  };

  YAWT_Q_Frame_BufferedStream_t bf;
  size_t out_offset = 0;
  YAWT_Err_t err = YAWT_q_encode_frame_stream(iov, sizeof(iov)/sizeof(iov[0]), 0, 1000, server_bidi_stream_id, 0, 0, &bf, &out_offset);
  TEST_ASSERT_EQUAL(YAWT_Q_OK, err);

  YAWT_H3_Error_t h3_err;
  size_t cursor = 0;
  YAWT_H3_Stream_t *stream = NULL;

  h3_err = YAWT_h3_parse_frame(h3, &bf.frame, &stream, &cursor);
  TEST_ASSERT_EQUAL(YAWT_H3_OK, h3_err);
  TEST_ASSERT_EQUAL(YAWT_H3_STREAM_FRAME, stream->type);
  TEST_ASSERT_EQUAL(YAWT_H3_FRAME_DATA, stream->frame.type);
}

/* ------------------------------------------------------------------ */
/*  Registration                                                       */
/* ------------------------------------------------------------------ */

void test_h3_register(void) {
    RUN_TEST(test_settings_frame_on_bidi_stream);
    RUN_TEST(test_settings_out_of_order_chunks);
    RUN_TEST(test_settings_frame_header_only);
    RUN_TEST(test_single_chunk_multiple_frames);
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
    RUN_TEST(test_stream_type_server_bidi);
}
