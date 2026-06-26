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
    test_h3.c
)

target_link_libraries(yawt_tests unity yawt)

target_include_directories(yawt_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_INSTALL_PREFIX}/include
    ${unity_SOURCE_DIR}/src
    ${unity_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)

if(YAWT_ENABLE_LOGGING)
  target_compile_definitions(yawt_tests PRIVATE
    YAWT_ENABLE_LOGGING
    YAWT_LOG_LEVEL=${YAWT_LOG_LEVEL}
  )
endif()

add_dependencies(yawt_tests yawt)

if(YAWT_ENABLE_LOGGING)
  target_compile_definitions(yawt_tests PRIVATE
    YAWT_ENABLE_LOGGING
    YAWT_LOG_LEVEL=${YAWT_LOG_LEVEL}
  )
endif()

add_test(NAME yawt_tests COMMAND yawt_tests)

if(BUILD_EXAMPLES)
  add_test(NAME h3_server_integration
    COMMAND ${CMAKE_COMMAND} -E env YAWT_BUILD_DIR=${CMAKE_INSTALL_PREFIX}/..
            python3 ${CMAKE_CURRENT_SOURCE_DIR}/integration/test_h3_server.py
  )
  add_test(NAME h3_client_integration
    COMMAND ${CMAKE_COMMAND} -E env YAWT_BUILD_DIR=${CMAKE_INSTALL_PREFIX}/..
            python3 ${CMAKE_CURRENT_SOURCE_DIR}/integration/test_h3_client.py
  )
endif()
