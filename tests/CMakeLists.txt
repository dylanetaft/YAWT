cmake_minimum_required(VERSION 3.14)

find_package(unity REQUIRED)

add_executable(yawt_tests
    test_main.c
    test_qpack_prefix_int.c
    test_qpack_literal_literal.c
    test_huffman.c
    test_h3.c
    test_pn_window.c
)

target_link_libraries(yawt_tests PRIVATE unity::framework yawt)

# yawt target already propagates public headers and dependency includes transitively.
# Only add paths not covered by the yawt target.
target_include_directories(yawt_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)

if(YAWT_ENABLE_LOGGING)
  target_compile_definitions(yawt_tests PRIVATE
    YAWT_ENABLE_LOGGING
    YAWT_LOG_LEVEL=${YAWT_LOG_LEVEL}
  )
endif()

add_dependencies(yawt_tests yawt)
add_test(NAME yawt_tests COMMAND yawt_tests)

if(BUILD_EXAMPLES)
  find_program(PYTHON3 python3 REQUIRED)
  # Integration tests default YAWT_BUILD_DIR to ../../build relative to the
  # test scripts (which resolves to the superbuild binary dir).
  # Scripts look for: ${YAWT_BUILD_DIR}/yawt-prefix/src/yawt-build/examples/<binary>
  # (the ExternalProject build tree — no `make install` needed).
  # Override with YAWT_EXAMPLES_DIR to test installed binaries instead.
  add_test(NAME h3_server_integration
    COMMAND ${PYTHON3} ${CMAKE_CURRENT_SOURCE_DIR}/integration/test_h3_server.py
  )
  add_test(NAME h3_client_integration
    COMMAND ${PYTHON3} ${CMAKE_CURRENT_SOURCE_DIR}/integration/test_h3_client.py
  )
endif()
