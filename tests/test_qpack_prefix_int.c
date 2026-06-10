#include "unity.h"
#include "qpack.h"
#include "test_qpack_prefix_int.h"

#define TEST_EQUAL(expected, actual) \
    TEST_ASSERT_EQUAL_UINT64((expected), (uint64_t)(actual))

void test_qpack_decode_prefix_8_value_zero(void) {
    uint8_t buf[] = { 0x00 };
    uint64_t val, bytes;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 0, &val, &bytes);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(0, val);
    TEST_EQUAL(1, bytes);
}

void test_qpack_decode_prefix_8_value_small(void) {
    uint8_t buf[] = { 0x42 };
    uint64_t val, bytes;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 0, &val, &bytes);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(0x42, val);
    TEST_EQUAL(1, bytes);
}

void test_qpack_decode_prefix_8_max_in_prefix(void) {
    uint8_t buf[] = { 0xFE };
    uint64_t val, bytes;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 0, &val, &bytes);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(254, val);
    TEST_EQUAL(1, bytes);
}

void test_qpack_decode_prefix_8_continuation(void) {
    uint8_t buf[] = { 0xFF, 0x00 };
    uint64_t val, bytes;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 0, &val, &bytes);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(255, val);
    TEST_EQUAL(2, bytes);
}

void test_qpack_decode_prefix_8_multi_continuation(void) {
    uint8_t buf[] = { 0xFF, 0x80, 0x01 };
    uint64_t val, bytes;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 0, &val, &bytes);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(383, val);
    TEST_EQUAL(3, bytes);
}

void test_qpack_decode_prefix_6_fits(void) {
    uint8_t buf[] = { 0x3E };
    uint64_t val, bytes;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 2, &val, &bytes);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(62, val);
    TEST_EQUAL(1, bytes);
}

void test_qpack_decode_prefix_6_continuation(void) {
    uint8_t buf[] = { 0x3F, 0x00 };
    uint64_t val, bytes;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 2, &val, &bytes);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(63, val);
    TEST_EQUAL(2, bytes);
}

void test_qpack_decode_prefix_3_fits(void) {
    uint8_t buf[] = { 0xE6 };
    uint64_t val, bytes;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 5, &val, &bytes);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(6, val);
    TEST_EQUAL(1, bytes);
}

void test_qpack_decode_prefix_3_continuation(void) {
    uint8_t buf[] = { 0x67, 0x00 };
    uint64_t val, bytes;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 5, &val, &bytes);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(7, val);
    TEST_EQUAL(2, bytes);
}

void test_qpack_decode_invalid_offset(void) {
    uint8_t buf[] = { 0x00 };
    uint64_t val, bytes;
    TEST_EQUAL(YAWT_QPACK_ERR_INVALID_PARAM,
               YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 8, &val, &bytes));
    TEST_EQUAL(YAWT_QPACK_ERR_INVALID_PARAM,
               YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 9, &val, &bytes));
}

void test_qpack_decode_short_buffer_no_cont(void) {
    uint8_t buf[] = { 0xFF };
    uint64_t val, bytes;
    TEST_EQUAL(YAWT_QPACK_ERR_SHORT_BUFFER,
               YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 0, &val, &bytes));
}

void test_qpack_decode_short_buffer_mid_cont(void) {
    uint8_t buf[] = { 0xFF, 0x80 };
    uint64_t val, bytes;
    TEST_EQUAL(YAWT_QPACK_ERR_SHORT_BUFFER,
               YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 0, &val, &bytes));
}

void test_qpack_decode_overflow(void) {
    uint8_t buf[16] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01 };
    uint64_t val, bytes;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 0, &val, &bytes);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(UINT64_MAX, val);
}

void test_qpack_encode_small(void) {
    uint8_t buf[16] = { 0xFF };
    uint64_t consumed;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 0, 42, &consumed);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(42, buf[0]);
    TEST_EQUAL(1, consumed);
}

void test_qpack_encode_prefix_6(void) {
    uint8_t buf[16] = { 0x00 };
    uint64_t consumed;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 2, 10, &consumed);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(0x0A, buf[0]);
    TEST_EQUAL(1, consumed);
}

void test_qpack_encode_prefix_3(void) {
    uint8_t buf[16] = { 0x00 };
    uint64_t consumed;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 5, 5, &consumed);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(0x05, buf[0]);
    TEST_EQUAL(1, consumed);
}

void test_qpack_encode_large(void) {
    uint8_t buf[16] = { 0xFF };
    uint64_t consumed;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 0, 255, &consumed);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(0xFF, buf[0]);
    TEST_EQUAL(0x00, buf[1]);
    TEST_EQUAL(2, consumed);
}

void test_qpack_encode_multi_byte(void) {
    uint8_t buf[16] = { 0xFF };
    uint64_t consumed;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 0, 383, &consumed);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(0xFF, buf[0]);
    TEST_EQUAL(0x80, buf[1]);
    TEST_EQUAL(0x01, buf[2]);
    TEST_EQUAL(3, consumed);
}

void test_qpack_encode_short_buffer(void) {
    uint8_t buf[1] = { 0xFF };
    uint64_t consumed;
    TEST_EQUAL(YAWT_QPACK_ERR_SHORT_BUFFER,
               YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 0, 255, &consumed));
}

void test_qpack_roundtrip_small(void) {
    for (uint64_t v = 0; v < 200; v++) {
        uint8_t buf[16] = { 0xFF };
        uint64_t consumed;
        YAWT_QPACK_Error_t e = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 0, v, &consumed);
        TEST_EQUAL(YAWT_QPACK_OK, e);
        uint64_t val, bytes;
        YAWT_QPACK_Error_t d = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 0, &val, &bytes);
        TEST_EQUAL(YAWT_QPACK_OK, d);
        TEST_EQUAL(v, val);
        TEST_EQUAL(consumed, bytes);
    }
}

void test_qpack_roundtrip_large(void) {
    uint64_t vals[] = { 254, 255, 256, 383, 511, 16383, 16384, 32767, 100000, 1000000 };
    for (size_t i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
        uint8_t buf[16] = { 0xFF };
        uint64_t consumed;
        YAWT_QPACK_Error_t e = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 0, vals[i], &consumed);
        TEST_EQUAL(YAWT_QPACK_OK, e);
        uint64_t val, bytes;
        YAWT_QPACK_Error_t d = YAWT_H3_QPACK_decode_prefix_int(buf, consumed + 1, 0, &val, &bytes);
        TEST_EQUAL(YAWT_QPACK_OK, d);
        TEST_EQUAL(vals[i], val);
        TEST_EQUAL(consumed, bytes);
    }
}

void test_qpack_roundtrip_prefix_6(void) {
    for (uint64_t v = 0; v < 200; v++) {
        uint8_t buf[16] = { 0xFF };
        uint64_t consumed;
        YAWT_QPACK_Error_t e = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 2, v, &consumed);
        TEST_EQUAL(YAWT_QPACK_OK, e);
        uint64_t val, bytes;
        YAWT_QPACK_Error_t d = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 2, &val, &bytes);
        TEST_EQUAL(YAWT_QPACK_OK, d);
        TEST_EQUAL(v, val);
        TEST_EQUAL(consumed, bytes);
    }
}

void test_qpack_roundtrip_prefix_3(void) {
    for (uint64_t v = 0; v < 200; v++) {
        uint8_t buf[16] = { 0xFF };
        uint64_t consumed;
        YAWT_QPACK_Error_t e = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 5, v, &consumed);
        TEST_EQUAL(YAWT_QPACK_OK, e);
        uint64_t val, bytes;
        YAWT_QPACK_Error_t d = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 5, &val, &bytes);
        TEST_EQUAL(YAWT_QPACK_OK, d);
        TEST_EQUAL(v, val);
        TEST_EQUAL(consumed, bytes);
    }
}

void test_qpack_roundtrip_uint64_max(void) {
    uint8_t buf[16] = { 0xFF };
    uint64_t consumed;
    YAWT_QPACK_Error_t e = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 0, UINT64_MAX, &consumed);
    TEST_EQUAL(YAWT_QPACK_OK, e);
    uint64_t val, bytes;
    YAWT_QPACK_Error_t d = YAWT_H3_QPACK_decode_prefix_int(buf, consumed + 1, 0, &val, &bytes);
    TEST_EQUAL(YAWT_QPACK_OK, d);
    TEST_EQUAL(UINT64_MAX, val);
    TEST_EQUAL(consumed, bytes);
}

void test_qpack_encode_decode_zero(void) {
    uint8_t buf[16] = { 0xFF };
    uint64_t consumed;
    YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 0, 0, &consumed);
    uint64_t val, bytes;
    YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 0, &val, &bytes);
    TEST_EQUAL(0, val);
}

void test_qpack_encode_decode_max_prefix(void) {
    uint8_t buf[16] = { 0xFF };
    uint64_t consumed;
    YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 0, 254, &consumed);
    uint64_t val, bytes;
    YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 0, &val, &bytes);
    TEST_EQUAL(254, val);
}

void test_qpack_encode_decode_boundary_minus_one(void) {
    uint8_t buf[16] = { 0xFF };
    uint64_t consumed;
    YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 2, 62, &consumed);
    uint64_t val, bytes;
    YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 2, &val, &bytes);
    TEST_EQUAL(62, val);
}

void test_qpack_encode_preserves_high_bits_n6(void) {
    uint8_t buf[16] = { 0xC0 };
    uint64_t consumed;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 2, 10, &consumed);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(0xCA, buf[0]);
}

void test_qpack_encode_preserves_high_bits_n3(void) {
    uint8_t buf[16] = { 0xE0 };
    uint64_t consumed;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 5, 5, &consumed);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(0xE5, buf[0]);
}

void test_qpack_encode_preserves_high_bits_n4(void) {
    uint8_t buf[16] = { 0xF0 };
    uint64_t consumed;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 4, 0, &consumed);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(0xF0, buf[0]);
}

void test_qpack_encode_continuation_preserves_high_bits_n3(void) {
    uint8_t buf[16] = { 0xE0 };
    uint64_t consumed;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 5, 8, &consumed);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(0xE7, buf[0]);
    TEST_EQUAL(0x01, buf[1]);
    TEST_EQUAL(2, consumed);
}

void test_qpack_encode_continuation_preserves_high_bits_n6(void) {
    uint8_t buf[16] = { 0xC0 };
    uint64_t consumed;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 2, 64, &consumed);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(0xFF, buf[0]);
    TEST_EQUAL(0x01, buf[1]);
    TEST_EQUAL(2, consumed);
}

void test_qpack_prefix_int_register(void) {
    RUN_TEST(test_qpack_decode_prefix_8_value_zero);
    RUN_TEST(test_qpack_decode_prefix_8_value_small);
    RUN_TEST(test_qpack_decode_prefix_8_max_in_prefix);
    RUN_TEST(test_qpack_decode_prefix_8_continuation);
    RUN_TEST(test_qpack_decode_prefix_8_multi_continuation);

    RUN_TEST(test_qpack_decode_prefix_6_fits);
    RUN_TEST(test_qpack_decode_prefix_6_continuation);

    RUN_TEST(test_qpack_decode_prefix_3_fits);
    RUN_TEST(test_qpack_decode_prefix_3_continuation);

    RUN_TEST(test_qpack_decode_invalid_offset);
    RUN_TEST(test_qpack_decode_short_buffer_no_cont);
    RUN_TEST(test_qpack_decode_short_buffer_mid_cont);

    RUN_TEST(test_qpack_decode_overflow);

    RUN_TEST(test_qpack_encode_small);
    RUN_TEST(test_qpack_encode_prefix_6);
    RUN_TEST(test_qpack_encode_prefix_3);
    RUN_TEST(test_qpack_encode_large);
    RUN_TEST(test_qpack_encode_multi_byte);
    RUN_TEST(test_qpack_encode_short_buffer);

    RUN_TEST(test_qpack_roundtrip_small);
    RUN_TEST(test_qpack_roundtrip_large);
    RUN_TEST(test_qpack_roundtrip_prefix_6);
    RUN_TEST(test_qpack_roundtrip_prefix_3);
    RUN_TEST(test_qpack_roundtrip_uint64_max);

    RUN_TEST(test_qpack_encode_decode_zero);
    RUN_TEST(test_qpack_encode_decode_max_prefix);
    RUN_TEST(test_qpack_encode_decode_boundary_minus_one);

    RUN_TEST(test_qpack_encode_preserves_high_bits_n6);
    RUN_TEST(test_qpack_encode_preserves_high_bits_n3);
    RUN_TEST(test_qpack_encode_preserves_high_bits_n4);
    RUN_TEST(test_qpack_encode_continuation_preserves_high_bits_n3);
    RUN_TEST(test_qpack_encode_continuation_preserves_high_bits_n6);
}
