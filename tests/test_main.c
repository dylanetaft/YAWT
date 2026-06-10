#include "unity.h"
#include "test_qpack_prefix_int.h"
#include "test_huffman.h"

void setUp(void) {}
void tearDown(void) {}

int main(void) {
    UNITY_BEGIN();

    test_qpack_prefix_int_register();
    test_huffman_register();  

    return UNITY_END();
}
