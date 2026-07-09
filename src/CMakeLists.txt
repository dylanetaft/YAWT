cmake_minimum_required(VERSION 3.14)
project(yawt VERSION 0.1.0 LANGUAGES C)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(GNUInstallDirs)
include(FetchContent)
include(CMakePackageConfigHelpers)

file(GLOB_RECURSE YAWT_SOURCES ${PROJECT_SOURCE_DIR}/*.c)

add_library(yawt STATIC ${YAWT_SOURCES})

target_include_directories(yawt PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/../include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/yawt>
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

# --- Dependencies ---

# libev: built by superbuild via ExternalProject, installed to CMAKE_PREFIX_PATH
find_library(LIBEV ev REQUIRED PATHS ${CMAKE_PREFIX_PATH}/lib ${CMAKE_PREFIX_PATH}/lib64 NO_DEFAULT_PATH)
find_path(LIBEV_INCLUDE_DIR ev.h REQUIRED PATHS ${CMAKE_PREFIX_PATH}/include NO_DEFAULT_PATH)
add_library(ev::ev STATIC IMPORTED)
set_target_properties(ev::ev PROPERTIES
    IMPORTED_LOCATION             "${LIBEV}"
    INTERFACE_INCLUDE_DIRECTORIES "${LIBEV_INCLUDE_DIR}"
)

# uthash: header-only, installed by superbuild
find_path(UTHASH_INCLUDE_DIR uthash.h REQUIRED PATHS ${CMAKE_PREFIX_PATH}/include/uthash NO_DEFAULT_PATH)
add_library(uthash::uthash INTERFACE IMPORTED)
set_target_properties(uthash::uthash PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${UTHASH_INCLUDE_DIR}"
)

# AllocNBuffer: installed by superbuild with proper CMake config exports
find_package(allocnbuffer REQUIRED)

# GnuTLS: system package
find_package(PkgConfig REQUIRED)
pkg_check_modules(GNUTLS REQUIRED IMPORTED_TARGET gnutls)

target_link_libraries(yawt PUBLIC
    ev::ev
    uthash::uthash
    allocnbuffer::static
    PkgConfig::GNUTLS
)

# --- Installation ---

install(TARGETS yawt
    EXPORT yawtTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY ${PROJECT_SOURCE_DIR}/../include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/yawt
    FILES_MATCHING PATTERN "*.h"
)

# --- CMake package config so downstreams can `find_package(yawt)` ---
# yawt links its dependencies PUBLIC (ev::ev, uthash::uthash,
# allocnbuffer::static, PkgConfig::GNUTLS), so the exported target's link line
# names those targets. The generated yawtConfig.cmake re-creates / re-finds them
# in the consumer before pulling in yawtTargets.cmake.
install(EXPORT yawtTargets
    FILE yawtTargets.cmake
    NAMESPACE yawt::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/yawt
)

configure_package_config_file(
    ${PROJECT_SOURCE_DIR}/cmake/yawtConfig.cmake.in
    ${PROJECT_BINARY_DIR}/yawtConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/yawt
)

write_basic_package_version_file(
    ${PROJECT_BINARY_DIR}/yawtConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${PROJECT_BINARY_DIR}/yawtConfig.cmake
    ${PROJECT_BINARY_DIR}/yawtConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/yawt
)

if(BUILD_EXAMPLES)
    add_subdirectory(${PROJECT_SOURCE_DIR}/../examples ${CMAKE_BINARY_DIR}/examples)
endif()

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(${PROJECT_SOURCE_DIR}/../tests ${CMAKE_BINARY_DIR}/tests)
endif()

if(BUILD_FUZZ)
    add_subdirectory(${PROJECT_SOURCE_DIR}/../fuzz ${CMAKE_BINARY_DIR}/fuzz)
endif()
