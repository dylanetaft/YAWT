cmake_minimum_required(VERSION 3.14)
project(yawt_fuzz)

if(NOT BUILD_FUZZ)
    return()
endif()

# All harnesses link against yawt static lib (built by parent CMakeLists.txt).
# yawt is defined as an ALIAS by the parent build via include_directories / add_subdirectory.

set(FUZZ_TARGETS
    fuzz_parse_frame
    fuzz_parse_packet
    fuzz_h3_settings
    fuzz_qpack
    fuzz_capsule
)

foreach(target ${FUZZ_TARGETS})
    add_executable(${target} ${target}.c)

    target_include_directories(${target} PRIVATE
        ${PROJECT_SOURCE_DIR}/../include
        ${CMAKE_INSTALL_PREFIX}/include
    )

    target_link_libraries(${target} yawt)

    target_compile_options(${target} PRIVATE -fsanitize=fuzzer,address,undefined -g -O1)
    target_link_options(${target} PRIVATE -fsanitize=fuzzer,address,undefined)
endforeach()
