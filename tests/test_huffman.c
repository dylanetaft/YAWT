#include "unity.h"
#include <stdint.h>
#include <string.h>
#include "qpack.h"
#include "test_huffman.h"
#include <string.h>


void test_huff_encode_aligned(void) {
  char data[] = "p(";
  uint8_t bit_offset = 0;
  size_t advance = 0;
  uint8_t encoded[4];
  memset(encoded, 0, sizeof(encoded));
  uint8_t *cur = encoded;
  size_t remaining = sizeof(encoded);

  YAWT_QPACK_Error_t err = YAWT_QPACK_huff_encode_byte(
      (uint8_t)data[0], cur, remaining, &bit_offset, &advance);
  TEST_ASSERT_EQUAL(YAWT_QPACK_OK, err);
  cur += advance;
  remaining -= advance;

  err = YAWT_QPACK_huff_encode_byte(
      (uint8_t)data[1], cur, remaining, &bit_offset, &advance);
  TEST_ASSERT_EQUAL(YAWT_QPACK_OK, err);
  uint8_t expected[] = { 0xAF, 0xFA };
  TEST_ASSERT_EQUAL_MEMORY(expected, encoded, sizeof(expected));
}

void test_huff_decode_aligned(void) {
  uint8_t encoded[] = { 0xAF, 0xFA };
  uint8_t bit_offset = 0;
  uint8_t out_byte;
  size_t advance = 0;
  const uint8_t *cur = encoded;
  size_t remaining = sizeof(encoded);

  YAWT_QPACK_Error_t err = YAWT_QPACK_huff_decode_byte(
      cur, remaining, &bit_offset, &out_byte, &advance);
  TEST_ASSERT_EQUAL(YAWT_QPACK_OK, err);
  TEST_ASSERT_EQUAL_UINT8(112, out_byte);
  cur += advance;
  remaining -= advance;

  err = YAWT_QPACK_huff_decode_byte(
      cur, remaining, &bit_offset, &out_byte, &advance);
  TEST_ASSERT_EQUAL(YAWT_QPACK_OK, err);
  TEST_ASSERT_EQUAL_UINT8(40, out_byte);
}

void test_huff_roundtrip_aligned(void) {
  // A single code can occupy up to 4 bytes, so encode requires a >=4 byte buffer.
  uint8_t encoded[4];
  memset(encoded, 0, sizeof(encoded));
  uint8_t bit_offset = 0;
  size_t advance = 0;
  uint8_t *enc = encoded;
  size_t enc_remaining = sizeof(encoded);

  YAWT_QPACK_Error_t err = YAWT_QPACK_huff_encode_byte(
      112, enc, enc_remaining, &bit_offset, &advance);
  TEST_ASSERT_EQUAL(YAWT_QPACK_OK, err);
  enc += advance;
  enc_remaining -= advance;
  err = YAWT_QPACK_huff_encode_byte(
      40, enc, enc_remaining, &bit_offset, &advance);
  TEST_ASSERT_EQUAL(YAWT_QPACK_OK, err);

  bit_offset = 0;
  uint8_t out_byte;
  const uint8_t *cur = encoded;
  size_t remaining = sizeof(encoded);

  err = YAWT_QPACK_huff_decode_byte(
      cur, remaining, &bit_offset, &out_byte, &advance);
  TEST_ASSERT_EQUAL(YAWT_QPACK_OK, err);
  TEST_ASSERT_EQUAL_UINT8(112, out_byte);
  cur += advance;
  remaining -= advance;

  err = YAWT_QPACK_huff_decode_byte(
      cur, remaining, &bit_offset, &out_byte, &advance);
  TEST_ASSERT_EQUAL(YAWT_QPACK_OK, err);
  TEST_ASSERT_EQUAL_UINT8(40, out_byte);
}

void test_huffman_register(void) {
  RUN_TEST(test_huff_encode_aligned);
  RUN_TEST(test_huff_decode_aligned);
  RUN_TEST(test_huff_roundtrip_aligned);
}
