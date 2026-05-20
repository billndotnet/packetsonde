set(CLI_SOURCES
    main.c
    args.c
    dispatch.c
    verbs/version.c
    verbs/agent.c
    # psctl handlers, linked directly into packetsonde:
    ../agent/src/psctl/psctl_commands.c
    ../agent/src/psctl/psctl_connection.c   # shim forwards to ps_ipc_*
    ../agent/src/psctl/psctl_format.c
    ../agent/src/psctl/psctl_shell.c
    ../agent/src/platform/unix.c
)

add_executable(packetsonde ${CLI_SOURCES})
target_include_directories(packetsonde PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../agent/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../agent/src/psctl
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
endif()
