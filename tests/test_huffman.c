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
  size_t sz = sizeof(encoded) * 8;
  YAWT_QPACK_Error_t err = YAWT_QPACK_huff_encode_byte(
      (uint8_t)data[0], encoded, sz, &bit_offset);
  TEST_ASSERT_EQUAL(YAWT_QPACK_OK, err);
  sz -= bit_offset;
  err = YAWT_QPACK_huff_encode_byte(
      (uint8_t)data[1], encoded, sz, &bit_offset);
  TEST_ASSERT_EQUAL(YAWT_QPACK_OK, err);
  uint16_t res;
  memcpy(&res, encoded, sizeof(res));
  TEST_ASSERT_EQUAL_UINT16(0xAFFA, res);
}

void test_huffman_register(void) {
  RUN_TEST(test_huff_encode_fixed_byte);
}
