set(CLI_SOURCES
    main.c
    args.c
    dispatch.c
    verbs/version.c
    verbs/agent.c
    output/output.c
    workers/limiter.c
    workers/workers.c
    signals.c
    psctl/psctl_commands.c
    psctl/psctl_connection.c
    psctl/psctl_format.c
    psctl/psctl_shell.c
    ../agent/src/platform/unix.c
)

add_executable(packetsonde ${CLI_SOURCES})
target_include_directories(packetsonde PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/psctl
    ${CMAKE_CURRENT_SOURCE_DIR}/../agent/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../agent/include
    ${CMAKE_BINARY_DIR}/src/agent
)
target_link_libraries(packetsonde PRIVATE packetsonde_lib)
if(APPLE)
    target_link_libraries(packetsonde PRIVATE edit)
endif()

if(BUILD_TESTING)
    add_executable(test_args tests/test_args.c args.c)
    target_include_directories(test_args PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(test_args PRIVATE packetsonde_lib)
    add_test(NAME test_args COMMAND test_args)

    add_executable(test_output tests/test_output.c output/output.c)
    target_include_directories(test_output PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(test_output PRIVATE packetsonde_lib)
    add_test(NAME test_output COMMAND test_output)

    add_executable(test_limiter tests/test_limiter.c workers/limiter.c)
    target_include_directories(test_limiter PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(test_limiter PRIVATE packetsonde_lib)
    add_test(NAME test_limiter COMMAND test_limiter)

    add_executable(test_workers tests/test_workers.c workers/workers.c workers/limiter.c)
    target_include_directories(test_workers PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(test_workers PRIVATE packetsonde_lib pthread)
    add_test(NAME test_workers COMMAND test_workers)
endif()

include(GNUInstallDirs)
install(TARGETS packetsonde RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
