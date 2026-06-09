#include "unity.h"
#include "qpack.h"

#define TEST_EQUAL(expected, actual) \
    TEST_ASSERT_EQUAL_UINT64((expected), (uint64_t)(actual))

void setUp(void) {}
void tearDown(void) {}

/* ------------------------------------------------------------------ */
/* Decode tests — prefix 8 (offset_bits = 0)                          */
/* ------------------------------------------------------------------ */

void test_decode_prefix_8_value_zero(void) {
    uint8_t buf[] = { 0x00 };
    uint64_t val, bits;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 0, &val, &bits);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(0, val);
    TEST_EQUAL(8, bits);
}

void test_decode_prefix_8_value_small(void) {
    uint8_t buf[] = { 0x42 };
    uint64_t val, bits;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 0, &val, &bits);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(0x42, val);
    TEST_EQUAL(8, bits);
}

void test_decode_prefix_8_max_in_prefix(void) {
    /* 2^8 - 2 = 254 = 0xFE — still fits in prefix (max = 2^8-2 = 254) */
    uint8_t buf[] = { 0xFE };
    uint64_t val, bits;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 0, &val, &bits);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(254, val);
    TEST_EQUAL(8, bits);
}

void test_decode_prefix_8_continuation(void) {
    /* prefix = 0xFF = 2^8-1, continuation byte 0x00 → value = 255 + 0 = 255 */
    uint8_t buf[] = { 0xFF, 0x00 };
    uint64_t val, bits;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 0, &val, &bits);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(255, val);
    TEST_EQUAL(16, bits);
}

void test_decode_prefix_8_multi_continuation(void) {
    /* prefix = 0xFF, cont1 = 0x80 (val=0, more), cont2 = 0x01 (val=1, last)
       value = 255 + 0*1 + 1*128 = 383 */
    uint8_t buf[] = { 0xFF, 0x80, 0x01 };
    uint64_t val, bits;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 0, &val, &bits);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(383, val);
    TEST_EQUAL(24, bits);
}

/* ------------------------------------------------------------------ */
/* Decode tests — prefix 6 (offset_bits = 2)                          */
/* ------------------------------------------------------------------ */

void test_decode_prefix_6_fits(void) {
    /* MSB bits 7-6 = 0x00, lower 6 bits = 0x3E = 62, which is < max_val(63) */
    uint8_t buf[] = { 0x3E };
    uint64_t val, bits;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 2, &val, &bits);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(62, val);
    TEST_EQUAL(6, bits);
}

void test_decode_prefix_6_continuation(void) {
    /* MSB = 0x00, lower 6 bits = 0x3F (=max), continuation 0x00
       value = 63 + 0 = 63 */
    uint8_t buf[] = { 0x3F, 0x00 };
    uint64_t val, bits;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 2, &val, &bits);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(63, val);
    TEST_EQUAL(14, bits);
}

/* ------------------------------------------------------------------ */
/* Decode tests — prefix 3 (offset_bits = 5)                          */
/* ------------------------------------------------------------------ */

void test_decode_prefix_3_fits(void) {
    /* MSB bits 7-5 = 0xE0, lower 3 bits = 0x06 = 6, which is < max_val(7) */
    uint8_t buf[] = { 0xE6 };
    uint64_t val, bits;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 5, &val, &bits);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(6, val);
    TEST_EQUAL(3, bits);
}

void test_decode_prefix_3_continuation(void) {
    /* MSB = 0x60, lower 3 bits = 0x07 (=max), continuation 0x00
       value = 7 + 0 = 7 */
    uint8_t buf[] = { 0x67, 0x00 };
    uint64_t val, bits;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 5, &val, &bits);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(7, val);
    TEST_EQUAL(11, bits);
}

/* ------------------------------------------------------------------ */
/* Decode error tests                                                 */
/* ------------------------------------------------------------------ */

void test_decode_invalid_offset(void) {
    uint8_t buf[] = { 0x00 };
    uint64_t val, bits;
    TEST_EQUAL(YAWT_QPACK_ERR_INVALID_PARAM,
               YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 8, &val, &bits));
    TEST_EQUAL(YAWT_QPACK_ERR_INVALID_PARAM,
               YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 9, &val, &bits));
}

void test_decode_short_buffer_no_cont(void) {
    uint8_t buf[] = { 0xFF };
    uint64_t val, bits;
    /* prefix = 0xFF needs continuation but no bytes remain */
    TEST_EQUAL(YAWT_QPACK_ERR_SHORT_BUFFER,
               YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 0, &val, &bits));
}

void test_decode_short_buffer_mid_cont(void) {
    uint8_t buf[] = { 0xFF, 0x80 };
    uint64_t val, bits;
    /* continuation byte 0x80 has MSB=1 (more to come) but no more bytes */
    TEST_EQUAL(YAWT_QPACK_ERR_SHORT_BUFFER,
               YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 0, &val, &bits));
}

/* ------------------------------------------------------------------ */
/* Decode overflow test                                               */
/* ------------------------------------------------------------------ */

void test_decode_overflow(void) {
    /* Many continuation bytes that overflow uint64, with a proper last byte.
       prefix=0xFF, then 10 bytes of 0xFF (continuation), then 0x01 (last).
       This triggers the overflow clamp, so value = UINT64_MAX. */
    uint8_t buf[16] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01 };
    uint64_t val, bits;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 0, &val, &bits);
    /* Should clamp to UINT64_MAX without crashing */
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(UINT64_MAX, val);
}

/* ------------------------------------------------------------------ */
/* Encode tests                                                       */
/* ------------------------------------------------------------------ */

void test_encode_small(void) {
    uint8_t buf[16] = { 0xFF };
    uint64_t consumed;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 0, 42, &consumed);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(42, buf[0]);
    TEST_EQUAL(8, consumed);
}

void test_encode_prefix_6(void) {
    /* offset_bits=2, N=6, value=10 → lower 6 bits = 0x0A, MSB cleared */
    uint8_t buf[16] = { 0x00 };
    uint64_t consumed;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 2, 10, &consumed);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(0x0A, buf[0]);
    TEST_EQUAL(6, consumed);
}

void test_encode_prefix_3(void) {
    /* offset_bits=5, N=3, value=5 → lower 3 bits = 0x05, MSB cleared */
    uint8_t buf[16] = { 0x00 };
    uint64_t consumed;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 5, 5, &consumed);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(0x05, buf[0]);
    TEST_EQUAL(3, consumed);
}

void test_encode_large(void) {
    /* offset_bits=0, N=8, value=255 → prefix=0xFF + continuation */
    uint8_t buf[16] = { 0xFF };
    uint64_t consumed;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 0, 255, &consumed);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(0xFF, buf[0]);
    TEST_EQUAL(0x00, buf[1]);
    TEST_EQUAL(16, consumed);
}

void test_encode_multi_byte(void) {
    /* offset_bits=0, N=8, value=383 → prefix=0xFF + 0x80 + 0x01 */
    uint8_t buf[16] = { 0xFF };
    uint64_t consumed;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 0, 383, &consumed);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(0xFF, buf[0]);
    TEST_EQUAL(0x80, buf[1]);
    TEST_EQUAL(0x01, buf[2]);
    TEST_EQUAL(24, consumed);
}

void test_encode_short_buffer(void) {
    uint8_t buf[1] = { 0xFF };
    uint64_t consumed;
    /* value=255 needs continuation but no room */
    TEST_EQUAL(YAWT_QPACK_ERR_SHORT_BUFFER,
               YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 0, 255, &consumed));
}

/* ------------------------------------------------------------------ */
/* Round-trip tests                                                   */
/* ------------------------------------------------------------------ */

void test_roundtrip_small(void) {
    for (uint64_t v = 0; v < 200; v++) {
        uint8_t buf[16] = { 0xFF };
        uint64_t consumed;
        YAWT_QPACK_Error_t e = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 0, v, &consumed);
        TEST_EQUAL(YAWT_QPACK_OK, e);
        uint64_t val, bits;
        YAWT_QPACK_Error_t d = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 0, &val, &bits);
        TEST_EQUAL(YAWT_QPACK_OK, d);
        TEST_EQUAL(v, val);
        TEST_EQUAL(consumed, bits);
    }
}

void test_roundtrip_large(void) {
    uint64_t vals[] = { 254, 255, 256, 383, 511, 16383, 16384, 32767, 100000, 1000000 };
    for (size_t i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
        uint8_t buf[16] = { 0xFF };
        uint64_t consumed;
        YAWT_QPACK_Error_t e = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 0, vals[i], &consumed);
        TEST_EQUAL(YAWT_QPACK_OK, e);
        uint64_t val, bits;
        YAWT_QPACK_Error_t d = YAWT_H3_QPACK_decode_prefix_int(buf, consumed / 8 + 1, 0, &val, &bits);
        TEST_EQUAL(YAWT_QPACK_OK, d);
        TEST_EQUAL(vals[i], val);
        TEST_EQUAL(consumed, bits);
    }
}

void test_roundtrip_prefix_6(void) {
    for (uint64_t v = 0; v < 200; v++) {
        uint8_t buf[16] = { 0xFF };
        uint64_t consumed;
        YAWT_QPACK_Error_t e = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 2, v, &consumed);
        TEST_EQUAL(YAWT_QPACK_OK, e);
        uint64_t val, bits;
        YAWT_QPACK_Error_t d = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 2, &val, &bits);
        TEST_EQUAL(YAWT_QPACK_OK, d);
        TEST_EQUAL(v, val);
        TEST_EQUAL(consumed, bits);
    }
}

void test_roundtrip_prefix_3(void) {
    for (uint64_t v = 0; v < 200; v++) {
        uint8_t buf[16] = { 0xFF };
        uint64_t consumed;
        YAWT_QPACK_Error_t e = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 5, v, &consumed);
        TEST_EQUAL(YAWT_QPACK_OK, e);
        uint64_t val, bits;
        YAWT_QPACK_Error_t d = YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 5, &val, &bits);
        TEST_EQUAL(YAWT_QPACK_OK, d);
        TEST_EQUAL(v, val);
        TEST_EQUAL(consumed, bits);
    }
}

void test_roundtrip_uint64_max(void) {
    uint8_t buf[16] = { 0xFF };
    uint64_t consumed;
    YAWT_QPACK_Error_t e = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 0, UINT64_MAX, &consumed);
    TEST_EQUAL(YAWT_QPACK_OK, e);
    uint64_t val, bits;
    YAWT_QPACK_Error_t d = YAWT_H3_QPACK_decode_prefix_int(buf, consumed / 8 + 1, 0, &val, &bits);
    TEST_EQUAL(YAWT_QPACK_OK, d);
    TEST_EQUAL(UINT64_MAX, val);
    TEST_EQUAL(consumed, bits);
}

/* ------------------------------------------------------------------ */
/* Boundary tests                                                     */
/* ------------------------------------------------------------------ */

void test_encode_decode_zero(void) {
    uint8_t buf[16] = { 0xFF };
    uint64_t consumed;
    YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 0, 0, &consumed);
    uint64_t val, bits;
    YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 0, &val, &bits);
    TEST_EQUAL(0, val);
}

void test_encode_decode_max_prefix(void) {
    /* For N=8, max_in_prefix = 2^8-2 = 254 */
    uint8_t buf[16] = { 0xFF };
    uint64_t consumed;
    YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 0, 254, &consumed);
    uint64_t val, bits;
    YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 0, &val, &bits);
    TEST_EQUAL(254, val);
}

void test_encode_decode_boundary_minus_one(void) {
    /* For N=6, max_in_prefix = 63, test 62 */
    uint8_t buf[16] = { 0xFF };
    uint64_t consumed;
    YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 2, 62, &consumed);
    uint64_t val, bits;
    YAWT_H3_QPACK_decode_prefix_int(buf, sizeof(buf), 2, &val, &bits);
    TEST_EQUAL(62, val);
}

/* ------------------------------------------------------------------ */
/* MSB preservation tests — encode must not clobber the MSB bits      */
/* ------------------------------------------------------------------ */

void test_encode_preserves_high_bits_n6(void) {
    /* offset_bits=2, N=6.  MSB bits = positions 7-6.  Set them to 0xC0
       (binary 11xxxxxx), encode value=10 (0b001010).  Result should be
       0xCA (0b11001010). */
    uint8_t buf[16] = { 0xC0 };
    uint64_t consumed;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 2, 10, &consumed);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(0xCA, buf[0]);
}

void test_encode_preserves_high_bits_n3(void) {
    /* offset_bits=5, N=3.  MSB bits = positions 7-5.  Set them to 0xE0
       (binary 111xxxxx), encode value=5 (0b101).  Result should be 0xE5. */
    uint8_t buf[16] = { 0xE0 };
    uint64_t consumed;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 5, 5, &consumed);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(0xE5, buf[0]);
}

void test_encode_preserves_high_bits_n4(void) {
    /* offset_bits=4, N=4.  MSB bits = positions 7-4.  Set them to 0xF0,
       encode value=0.  Result should be 0xF0 (high bits preserved, low cleared). */
    uint8_t buf[16] = { 0xF0 };
    uint64_t consumed;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 4, 0, &consumed);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(0xF0, buf[0]);
}

void test_encode_continuation_preserves_high_bits_n3(void) {
    /* offset_bits=5, N=3.  MSB = 0xE0, encode value=8 (= max_val+1, needs cont).
       prefix byte = 0xE7 (lower 3 bits = 7 = max), continuation encodes 8-7=1. */
    uint8_t buf[16] = { 0xE0 };
    uint64_t consumed;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 5, 8, &consumed);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(0xE7, buf[0]);
    TEST_EQUAL(0x01, buf[1]);
    TEST_EQUAL(11, consumed);
}

void test_encode_continuation_preserves_high_bits_n6(void) {
    /* offset_bits=2, N=6.  MSB = 0xC0, encode value=64 (= max_val+1, needs cont).
       prefix byte = 0xFF (0xC0 | 0x3F), continuation encodes 64-63=1. */
    uint8_t buf[16] = { 0xC0 };
    uint64_t consumed;
    YAWT_QPACK_Error_t rc = YAWT_H3_QPACK_encode_prefix_int(buf, sizeof(buf), 2, 64, &consumed);
    TEST_EQUAL(YAWT_QPACK_OK, rc);
    TEST_EQUAL(0xFF, buf[0]);
    TEST_EQUAL(0x01, buf[1]);
    TEST_EQUAL(14, consumed);
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */

int main(void) {
    UNITY_BEGIN();

    /* Decode — prefix 8 */
    RUN_TEST(test_decode_prefix_8_value_zero);
    RUN_TEST(test_decode_prefix_8_value_small);
    RUN_TEST(test_decode_prefix_8_max_in_prefix);
    RUN_TEST(test_decode_prefix_8_continuation);
    RUN_TEST(test_decode_prefix_8_multi_continuation);

    /* Decode — prefix 6 */
    RUN_TEST(test_decode_prefix_6_fits);
    RUN_TEST(test_decode_prefix_6_continuation);

    /* Decode — prefix 3 */
    RUN_TEST(test_decode_prefix_3_fits);
    RUN_TEST(test_decode_prefix_3_continuation);

    /* Decode — errors */
    RUN_TEST(test_decode_invalid_offset);
    RUN_TEST(test_decode_short_buffer_no_cont);
    RUN_TEST(test_decode_short_buffer_mid_cont);

    /* Decode — overflow */
    RUN_TEST(test_decode_overflow);

    /* Encode */
    RUN_TEST(test_encode_small);
    RUN_TEST(test_encode_prefix_6);
    RUN_TEST(test_encode_prefix_3);
    RUN_TEST(test_encode_large);
    RUN_TEST(test_encode_multi_byte);
    RUN_TEST(test_encode_short_buffer);

    /* Round-trip */
    RUN_TEST(test_roundtrip_small);
    RUN_TEST(test_roundtrip_large);
    RUN_TEST(test_roundtrip_prefix_6);
    RUN_TEST(test_roundtrip_prefix_3);
    RUN_TEST(test_roundtrip_uint64_max);

    /* Boundary values */
    RUN_TEST(test_encode_decode_zero);
    RUN_TEST(test_encode_decode_max_prefix);
    RUN_TEST(test_encode_decode_boundary_minus_one);

    /* MSB preservation */
    RUN_TEST(test_encode_preserves_high_bits_n6);
    RUN_TEST(test_encode_preserves_high_bits_n3);
    RUN_TEST(test_encode_preserves_high_bits_n4);
    RUN_TEST(test_encode_continuation_preserves_high_bits_n3);
    RUN_TEST(test_encode_continuation_preserves_high_bits_n6);

    return UNITY_END();
}
