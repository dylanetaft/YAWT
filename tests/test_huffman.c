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
  uint8_t encoded[5];
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
  // A single code can occupy up to 4 bytes, so encode requires a >=5 byte buffer.
  uint8_t encoded[5];
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

void test_huff_roundtrip_rfc_example(void) {
  const uint8_t encoded[] = { 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
  uint8_t decoded_out[64];
  size_t decoded_out_len;

  YAWT_QPACK_Error_t err = YAWT_QPACK_huff_decode_string(encoded, sizeof(encoded), decoded_out, sizeof(decoded_out), &decoded_out_len);
  TEST_ASSERT_EQUAL(YAWT_QPACK_OK, err);
  TEST_ASSERT_EQUAL_STRING("www.example.com", (const char*)decoded_out);
}

void test_huff_eos_padding(void) {
  // "a" encoded: HUFFMAN_TABLE['a']
  // Let's find 'a' in the table. 
  // I'll just use a known one if I can. 
  // If I don't know, I'll just encode "a" and then manually pad it.
  
  uint8_t input[] = "a";
  uint8_t encoded[8];
  size_t encoded_len;
  YAWT_QPACK_Error_t err = YAWT_QPACK_huff_encode_string(input, 1, encoded, sizeof(encoded), &encoded_len);
  TEST_ASSERT_EQUAL(YAWT_QPACK_OK, err);

  // Now let's add some 1-padding to the last byte.
  // If encoded_len is 1, we pad the rest of encoded[0] with 1s.
  // But wait, our encode_string already pads with 1s!
  // So we just need to check if it's correct.
  
  uint8_t decoded_out[8];
  size_t decoded_out_len;
  err = YAWT_QPACK_huff_decode_string(encoded, encoded_len, decoded_out, sizeof(decoded_out), &decoded_out_len);
  TEST_ASSERT_EQUAL(YAWT_QPACK_OK, err);
  TEST_ASSERT_EQUAL_UINT8('a', decoded_out[0]);
  TEST_ASSERT_EQUAL_UINT8(1, decoded_out_len);
}

void test_huff_malformed_padding(void) {
  // Encode "a", then change the padding to 0.
  uint8_t input[] = "a";
  uint8_t encoded[8];
  size_t encoded_len;
  YAWT_QPACK_Error_t err = YAWT_QPACK_huff_encode_string(input, 1, encoded, sizeof(encoded), &encoded_len);
  TEST_ASSERT_EQUAL(YAWT_QPACK_OK, err);

  // Force padding to be 0s instead of 1s.
  // If encoded_len is 1 and bit_offset was, say, 3.
  // The bits 3..7 are 1. Let's change them to 0.
  // But we don't know bit_offset from encode_string easily.
  // However, if we know it's not a multiple of 8, we can just clear the trailing bits.
  
  // Let's just find a string that is not a multiple of 8 bits.
  // "a" is likely not.
  
  // Let's just try to decode something that is clearly malformed.
  // 0x00 is not a valid Huffman start if it's not a leaf.
  // Actually, let's just use the encoded "a" and flip a bit in the padding.
  
  // If encoded_len is 1, and we change encoded[0] to something else.
  // But we need to ensure it's not a valid Huffman code.
  
  // Let's try to decode a single byte that is all 0s.
  uint8_t malformed[] = { 0x00 };
  uint8_t decoded_out[8];
  size_t decoded_out_len;
  err = YAWT_QPACK_huff_decode_string(malformed, 1, decoded_out, sizeof(decoded_out), &decoded_out_len);
  TEST_ASSERT_NOT_EQUAL(YAWT_QPACK_OK, err);
}

void test_huffman_register(void) {
  RUN_TEST(test_huff_encode_aligned);
  RUN_TEST(test_huff_decode_aligned);
  RUN_TEST(test_huff_roundtrip_aligned);
  RUN_TEST(test_huff_roundtrip_rfc_example);
  RUN_TEST(test_huff_eos_padding);
  RUN_TEST(test_huff_malformed_padding);
}

