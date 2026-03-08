cmake_minimum_required(VERSION 3.14)
project(yawt)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
option(YAWT_ENABLE_LOGGING "Enable debug logging" ON)
set(YAWT_LOG_LEVEL 0 CACHE STRING "Set log level (0=DEBUG, 1=INFO, 2=WARN, 3=ERROR)")


file(GLOB_RECURSE SOURCE_FILES ${PROJECT_SOURCE_DIR}/*.c)
add_executable(${PROJECT_NAME} ${SOURCE_FILES})


find_library(LIBEV ev REQUIRED)
find_library(ALLOCNBUFFER allocnbuffer REQUIRED)

find_package(PkgConfig REQUIRED)
set(ENV{PKG_CONFIG_PATH} "${CMAKE_INSTALL_PREFIX}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
pkg_check_modules(GNUTLS REQUIRED IMPORTED_TARGET gnutls)


target_include_directories(${PROJECT_NAME} PRIVATE
    ${PROJECT_SOURCE_DIR}/../include
    ${CMAKE_INSTALL_PREFIX}/include
)
target_link_libraries(${PROJECT_NAME} ${LIBEV} ${ALLOCNBUFFER}
    ${GNUTLS_STATIC_LIBRARIES})

install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)


