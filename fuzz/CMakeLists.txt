cmake_minimum_required(VERSION 3.14)
project(yawt_fuzz)

if(NOT BUILD_FUZZ)
    return()
endif()

set(FUZZ_TARGETS
    fuzz_parse_frame
    fuzz_parse_packet
    fuzz_h3_settings
    fuzz_qpack
    fuzz_capsule
)

foreach(target ${FUZZ_TARGETS})
    add_executable(${target} ${target}.c)

    # yawt propagates all dependency includes transitively
    target_link_libraries(${target} PRIVATE yawt)

    target_compile_options(${target} PRIVATE -fsanitize=fuzzer,address,undefined -g -O1)
    target_link_options(${target} PRIVATE -fsanitize=fuzzer,address,undefined)
endforeach()
