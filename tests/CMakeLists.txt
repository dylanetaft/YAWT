cmake_minimum_required(VERSION 3.14)

option(YAWT_ENABLE_LOGGING "Enable debug logging" ON)
set(YAWT_LOG_LEVEL 0 CACHE STRING "Set log level (0=DEBUG, 1=INFO, 2=WARN, 3=ERROR)")

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

if(YAWT_ENABLE_LOGGING)
  target_compile_definitions(yawt_tests PRIVATE
    YAWT_ENABLE_LOGGING
    YAWT_LOG_LEVEL=${YAWT_LOG_LEVEL}
  )
endif()

add_test(NAME yawt_tests COMMAND yawt_tests)
