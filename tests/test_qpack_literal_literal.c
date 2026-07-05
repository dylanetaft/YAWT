/**
 * @file test_qpack_literal_literal.c
 * @brief Decode tests for QPACK §4.5.6 — Literal Field Line with Literal Name.
 *
 * Exercises _h3_decode_string_literal at offset_bits=4 (name) and 0 (value),
 * including the 3-bit prefix integer continuation path.
 *
 * All wire bytes are hand-crafted per RFC 9204 Figure 17:
 *
 *       0   1   2   3   4   5   6   7
 *     +---+---+---+---+---+---+---+---+
 *     | 0 | 0 | 1 | N | H |NameLen(3+)|
 *     +---+---+---+---+---+-----------+
 *     |  Name String (Length bytes)   |
 *     +---+---------------------------+
 *     | H |     Value Length (7+)     |
 *     +---+---------------------------+
 *     |  Value String (Length bytes)  |
 *     +-------------------------------+
 */

#include "unity.h"
#include "qpack.h"
#include "h3.h"
#include "h3_header.h"
#include "h3_types.h"
#include "security.h"

/* ------------------------------------------------------------------ */
/* Wire encoding helpers — build a complete §4.5.6 header block       */
/* ------------------------------------------------------------------ */

/*
 * Wire a QPACK header block prefix: Required Insert Count = 0, Base = 0.
 */
static void emit_block_prefix(uint8_t *buf, size_t *off) {
    buf[(*off)++] = 0x00;   /* RIC = 0 (8-bit prefix int, 1 byte) */
    buf[(*off)++] = 0x00;   /* Delta Base = 0, S=0 (7-bit prefix int, 1 byte) */
}

/*
 * Wire a non-Huffman §4.5.6 literal name line with explicit name length,
 * even when 3-bit prefix overflows.  Caller supplies the buffer.
 *
 * Wire: [001|N|H|NameLen(3+)] [continuation bytes] [name bytes]
 *       [0|ValueLen(7+)]       [value bytes]
 */
static void emit_literal_literal(uint8_t *buf, size_t *off,
                                 const char *name, size_t name_len,
                                 const char *val,  size_t val_len)
{
    /* First byte holds: 001 prefix | N=0 | H_name=0 | NameLen prefix (3 bits). */
    size_t o = *off;
    uint32_t max_in_prefix = 7;   /* 2^3 - 1 */

    uint8_t first = 0x20;         /* bits: 0 0 1 0 0 0 0 0 */
    if (name_len < max_in_prefix) {
        first |= (uint8_t)(name_len & 0x07);
        buf[o++] = first;
    } else {
        /* All 3 prefix bits set to 1, then continuation bytes. */
        first |= 0x07;
        buf[o++] = first;
        uint32_t remaining = (uint32_t)(name_len - max_in_prefix);
        while (remaining >= 128) {
            buf[o++] = 0x80 | (uint8_t)(remaining & 0x7F);
            remaining >>= 7;
        }
        buf[o++] = (uint8_t)remaining;
    }

    /* Name string bytes (non-Huffman). */
    memcpy(buf + o, name, name_len);
    o += name_len;

    /* Value: single byte with H=0 and 7-bit length prefix. */
    TEST_ASSERT_LESS_OR_EQUAL(127, val_len);
    buf[o++] = (uint8_t)(val_len & 0x7F);

    /* Value string bytes (non-Huffman). */
    memcpy(buf + o, val, val_len);
    o += val_len;

    *off = o;
}

/* ------------------------------------------------------------------ */
/* Helper: decode a wire block and look up a field by name            */
/* ------------------------------------------------------------------ */

static YAWT_H3_Header_Field_t decode_and_find(
    const uint8_t *wire, size_t wire_len,
    const char *search_name)
{
    YAWT_H3_HeaderFields_t *headers = YAWT_h3_header_fields_create();
    TEST_ASSERT_NOT_NULL(headers);

    YAWT_QPACK_Error_t err = YAWT_qpack_decode_header_block(wire, wire_len, headers);
    TEST_ASSERT_EQUAL_HEX(YAWT_QPACK_OK, err);

    YAWT_H3_Header_Field_t f = YAWT_h3_header_find_str(headers, search_name);
    /* Deliberately leak headers in tests; they live for the process lifetime. */
    (void)headers;
    return f;
}

/* ------------------------------------------------------------------ */
/* Test: simple name + value, both fit in the prefix                  */
/* ------------------------------------------------------------------ */

/*
 * Wire: 0x00 0x00 | 0x23 "foo" | 0x03 "bar"
 *
 *   0x23 = 0010 0011:
 *     bits 0-2 = 001    (dispatch pattern)
 *     bit  3   = 0      (N=0, not-never)
 *     bit  4   = 0      (H=0, no Huffman)
 *     bits 5-7 = 011    (NameLen = 3)
 */
static void test_literal_literal_simple(void) {
    uint8_t wire[32];
    size_t o = 0;
    emit_block_prefix(wire, &o);

    /* Field line: name="foo", value="bar", no Huffman, no N flag */
    wire[o++] = 0x23;                        /* 001 0 0 | 011 */
    wire[o++] = 'f'; wire[o++] = 'o'; wire[o++] = 'o';
    wire[o++] = 0x03;                        /* 0 | 0000011 (ValueLen=3) */
    wire[o++] = 'b'; wire[o++] = 'a'; wire[o++] = 'r';

    YAWT_H3_Header_Field_t f = decode_and_find(wire, o, "foo");
    TEST_ASSERT_NOT_NULL(f.name);
    TEST_ASSERT_EQUAL_UINT(3, f.name_len);
    TEST_ASSERT_EQUAL_MEMORY("foo", f.name, 3);
    TEST_ASSERT_NOT_NULL(f.value);
    TEST_ASSERT_EQUAL_UINT(3, f.value_len);
    TEST_ASSERT_EQUAL_MEMORY("bar", f.value, 3);
}

/* ------------------------------------------------------------------ */
/* Test: name length overflows the 3-bit prefix (requires continuation)    */
/* ------------------------------------------------------------------ */

/*
 * name = "12345678" (8 bytes), value = "v" (1 byte)
 *
 * 3-bit prefix for name length: max in-prefix = 7 (2^3 - 1).
 * Since 8 >= 7, we set all 3 bits to 1 and emit a continuation byte:
 * remaining = 8 - 7 = 1 → continuation byte 0x01.
 *
 * Wire: [0x00 0x00] [0x27 0x01] [12345678] [0x01] [v]
 */
static void test_literal_literal_name_len_continuation(void) {
    uint8_t wire[64];
    size_t o = 0;
    emit_block_prefix(wire, &o);

    /* Field line: name="12345678" (8 bytes), H=0, N=0 */
    wire[o++] = 0x27;                        /* 001 0 0 | 111 (prefix all 1s) */
    wire[o++] = 0x01;                        /* continuation: 8 - 7 = 1 */
    memcpy(wire + o, "12345678", 8);
    o += 8;
    wire[o++] = 0x01;                        /* 0 | 0000001 (ValueLen=1) */
    wire[o++] = 'v';

    YAWT_H3_Header_Field_t f = decode_and_find(wire, o, "12345678");
    TEST_ASSERT_NOT_NULL(f.name);
    TEST_ASSERT_EQUAL_UINT(8, f.name_len);
    TEST_ASSERT_EQUAL_MEMORY("12345678", f.name, 8);
    TEST_ASSERT_NOT_NULL(f.value);
    TEST_ASSERT_EQUAL_UINT(1, f.value_len);
    TEST_ASSERT_EQUAL_MEMORY("v", f.value, 1);
}

/* ------------------------------------------------------------------ */
/* Test: N (never-indexed) bit must be ignored, not misread as H      */
/* ------------------------------------------------------------------ */

/*
 * With N=1 and H=0 the name is not Huffman-encoded.  If the decoder
 * accidentally read N as the H bit the lookup would fail or corrupt the name.
 *
 * Wire: [0x00 0x00] [0x2b] [h, w] [0x02] [w, b]
 *   0x2b = 0010 1011:
 *     bits 0-2 = 001  (dispatch)
 *     bit  3   = 1    (N=1, never-indexed)
 *     bit  4   = 0    (H_name=0, no Huffman)
 *     bits 5-7 = 011  (NameLen=3)
 */
static void test_literal_literal_N_bit_ignored(void) {
    uint8_t wire[32];
    size_t o = 0;
    emit_block_prefix(wire, &o);

    /* 0x33 = 0011 0011: RFC bits 0-2=001, bit 3=N=1, bit 4=H=0, bits 5-7=011(len=3).
     * Note: RFC bit 0 is MSB (byte bit 7), so N is byte bit 4 (0x10),
     *       H is byte bit 3 (0x08).  With N=1,H=0: 0x20|0x10|0x00|0x03 = 0x33. */
    wire[o++] = 0x33;                        /* 0011 0011  (N=1, H=0, len=3) */
    wire[o++] = 'h'; wire[o++] = 'w'; wire[o++] = 'a';
    wire[o++] = 0x02;                        /* 0 | 0000010 (ValueLen=2) */
    wire[o++] = 'w'; wire[o++] = 'b';

    YAWT_H3_Header_Field_t f = decode_and_find(wire, o, "hwa");
    TEST_ASSERT_NOT_NULL(f.name);
    TEST_ASSERT_EQUAL_UINT(3, f.name_len);
    TEST_ASSERT_EQUAL_MEMORY("hwa", f.name, 3);
    TEST_ASSERT_EQUAL_UINT(2, f.value_len);
    TEST_ASSERT_EQUAL_MEMORY("wb", f.value, 2);
}

/* ------------------------------------------------------------------ */
/* Test: short buffer returns an error, not a crash                   */
/* ------------------------------------------------------------------ */

static void test_literal_literal_short_buffer(void) {
    /* Header is complete in test_literal_literal_simple; truncate by one byte. */
    uint8_t wire[] = { 0x00, 0x00, 0x23, 'f', 'o', 'o', 0x03, 'b', 'a' };
    size_t wire_len = sizeof(wire);          /* missing trailing 'r' for value */

    YAWT_H3_HeaderFields_t *headers = YAWT_h3_header_fields_create();
    TEST_ASSERT_NOT_NULL(headers);

    YAWT_QPACK_Error_t err = YAWT_qpack_decode_header_block(wire, wire_len, headers);
    TEST_ASSERT_NOT_EQUAL(YAWT_QPACK_OK, err);
    (void)headers;
}

/* ------------------------------------------------------------------ */
/* Test: name length exactly at the 3-bit prefix ceiling (7 bytes)    */
/* ------------------------------------------------------------------ */

/*
 * name = "abcdefg" (7 bytes), value = "x" (1 byte)
 *
 * 3-bit prefix ceil = 2^3 - 1 = 7, so len=7 fits in the prefix itself
 * (no continuation byte is required).
 */
static void test_literal_literal_name_len_max_in_prefix(void) {
    uint8_t wire[32];
    size_t o = 0;
    emit_block_prefix(wire, &o);

    /* Name len = 7 = 2^3 - 1.  In a 3-bit prefix integer, value 7 does NOT
     * fit (< 2^N-1 required), so all prefix bits must be 1 with continuation
     * byte 0x00 (7 - 7 = 0). */
    wire[o++] = 0x27;                        /* 001 0 0 | 111 (all 1s, needs cont) */
    wire[o++] = 0x00;                        /* continuation: 7 - 7 = 0 */
    memcpy(wire + o, "abcdefg", 7);
    o += 7;
    wire[o++] = 0x01;                        /* 0 | 0000001 (ValueLen=1) */
    wire[o++] = 'x';

    YAWT_H3_Header_Field_t f = decode_and_find(wire, o, "abcdefg");
    TEST_ASSERT_NOT_NULL(f.name);
    TEST_ASSERT_EQUAL_UINT(7, f.name_len);
    TEST_ASSERT_EQUAL_MEMORY("abcdefg", f.name, 7);
    TEST_ASSERT_EQUAL_UINT(1, f.value_len);
    TEST_ASSERT_EQUAL_MEMORY("x", f.value, 1);
}

/* ------------------------------------------------------------------ */
/* Registration: register all tests above into the Unity runner       */
/* ------------------------------------------------------------------ */

static const struct {
    const char *name;
    void (*func)(void);
} tests[] = {
    { "test_literal_literal_simple",                  test_literal_literal_simple },
    { "test_literal_literal_name_len_continuation",   test_literal_literal_name_len_continuation },
    { "test_literal_literal_N_bit_ignored",           test_literal_literal_N_bit_ignored },
    { "test_literal_literal_short_buffer",            test_literal_literal_short_buffer },
    { "test_literal_literal_name_len_max_in_prefix",  test_literal_literal_name_len_max_in_prefix },
    { NULL, NULL }
};

void test_qpack_literal_literal_register(void) {
    UNITY_BEGIN();
    for (size_t i = 0; tests[i].name; i++) {
        UnityDefaultTestRun(tests[i].func, tests[i].name, (int)(i + 1));
    }
    UNITY_END();
}
