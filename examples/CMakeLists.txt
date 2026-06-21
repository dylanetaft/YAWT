add_executable(h3_server h3_server.c)

target_include_directories(h3_server PRIVATE
    ${CMAKE_INSTALL_PREFIX}/include
)

target_compile_definitions(h3_server PRIVATE
    YAWT_ENABLE_LOGGING
    YAWT_LOG_LEVEL=0
)

target_link_libraries(h3_server yawt)

install(TARGETS h3_server RUNTIME DESTINATION bin/examples)

add_executable(h3_client h3_client.c)

target_include_directories(h3_client PRIVATE
    ${CMAKE_INSTALL_PREFIX}/include
)

target_compile_definitions(h3_client PRIVATE
    YAWT_ENABLE_LOGGING
    YAWT_LOG_LEVEL=0
)

target_link_libraries(h3_client yawt)

install(TARGETS h3_client RUNTIME DESTINATION bin/examples)
