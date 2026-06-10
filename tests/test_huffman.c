#include "unity.h"
#include <stdint.h>
#include <string.h>
#include "qpack.h"
#include "test_huffman.h"
#include <string.h>


void test_huff_encode_fixed_byte(void) {
  char data[] = "p(";
  size_t bit_offset = 0;
  uint8_t encoded[2];
  memset(encoded, 0, sizeof(encoded));
  YAWT_QPACK_Error_t err = YAWT_QPACK_huff_encode_byte(
      (uint8_t)data[0], encoded, sizeof(encoded), &bit_offset);
  TEST_ASSERT_EQUAL(YAWT_QPACK_OK, err);
  err = YAWT_QPACK_huff_encode_byte(
      (uint8_t)data[1], encoded, sizeof(encoded), &bit_offset);
  TEST_ASSERT_EQUAL(YAWT_QPACK_OK, err);
  uint8_t expected[] = { 0xAF, 0xFA };
  TEST_ASSERT_EQUAL_MEMORY(expected, encoded, sizeof(expected));
}

void test_huffman_register(void) {
  RUN_TEST(test_huff_encode_fixed_byte);
}
