set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

foreach(target h3_server h3_client minimal_h3_client wt_server)
    add_executable(${target} ${target}.c)

    target_compile_definitions(${target} PRIVATE
        YAWT_ENABLE_LOGGING
        YAWT_LOG_LEVEL=0
    )

    target_link_libraries(${target} PRIVATE yawt)

    include(GNUInstallDirs)
    install(TARGETS ${target} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}/examples)
endforeach()
