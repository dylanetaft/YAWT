cmake_minimum_required(VERSION 3.14)
project(yawt)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
#option(BUILD_EXAMPLES "Build example programs" ON)
#option(YAWT_ENABLE_FUZZ_CORPUS "Enable fuzz corpus collection" ON)


file(GLOB_RECURSE YAWT_SOURCES ${PROJECT_SOURCE_DIR}/*.c)

add_library(yawt STATIC ${YAWT_SOURCES})

target_include_directories(yawt SYSTEM PUBLIC
    ${PROJECT_SOURCE_DIR}/../include
    ${CMAKE_INSTALL_PREFIX}/include
)

if(YAWT_ENABLE_LOGGING)
  target_compile_definitions(yawt PRIVATE
    YAWT_ENABLE_LOGGING
    YAWT_LOG_LEVEL=${YAWT_LOG_LEVEL}
  )
endif()

if(YAWT_ENABLE_FUZZ_CORPUS)
  target_compile_definitions(yawt PRIVATE YAWT_ENABLE_FUZZ_CORPUS)
endif()

find_library(LIBEV ev REQUIRED)
find_library(ALLOCNBUFFER allocnbuffer REQUIRED)

find_package(PkgConfig REQUIRED)
set(ENV{PKG_CONFIG_PATH} "${CMAKE_INSTALL_PREFIX}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
pkg_check_modules(GNUTLS REQUIRED IMPORTED_TARGET gnutls)

target_link_libraries(yawt ${LIBEV} ${ALLOCNBUFFER}
    ${GNUTLS_STATIC_LIBRARIES})

install(TARGETS yawt ARCHIVE DESTINATION lib64)
install(DIRECTORY ${PROJECT_SOURCE_DIR}/../include/ DESTINATION include/yawt
        FILES_MATCHING PATTERN "*.h")

if(BUILD_EXAMPLES)
    add_subdirectory(${PROJECT_SOURCE_DIR}/../examples ${CMAKE_BINARY_DIR}/examples)
endif()

if(BUILD_TESTS)
    enable_testing()
    include(FetchContent)
    add_subdirectory(${PROJECT_SOURCE_DIR}/../tests ${CMAKE_BINARY_DIR}/tests)
endif()

if(BUILD_FUZZ)
    add_subdirectory(${PROJECT_SOURCE_DIR}/../fuzz ${CMAKE_BINARY_DIR}/fuzz)
endif()
