cmake_minimum_required(VERSION 3.14)

FetchContent_Declare(
    unity
    GIT_REPOSITORY https://github.com/ThrowTheSwitch/Unity.git
    GIT_TAG        v2.6.1
)
FetchContent_MakeAvailable(unity)

add_executable(yawt_tests
    test_main.c
    test_qpack_prefix_int.c
    test_huffman.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/qpack.c
)

target_link_libraries(yawt_tests unity)

target_include_directories(yawt_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${unity_SOURCE_DIR}/src
    ${unity_BINARY_DIR}
)

add_test(NAME yawt_tests COMMAND yawt_tests)
