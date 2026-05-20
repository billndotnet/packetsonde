set(CLI_SOURCES
    main.c
    args.c
    dispatch.c
    verbs/version.c
    verbs/agent.c
    verbs/audit.c
    verbs/findings.c
    verbs/config.c
    registry/agents.c
    audit/tls.c
    output/output.c
    workers/limiter.c
    workers/workers.c
    signals.c
    util/targets.c
    findings_util/reader.c
    findings_util/filter.c
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
find_package(OpenSSL REQUIRED)
target_link_libraries(packetsonde PRIVATE OpenSSL::SSL OpenSSL::Crypto)
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

    add_executable(test_targets tests/test_targets.c util/targets.c)
    target_include_directories(test_targets PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(test_targets PRIVATE packetsonde_lib)
    add_test(NAME test_targets COMMAND test_targets)

    add_executable(test_findings_filter
        tests/test_findings_filter.c
        findings_util/reader.c
        findings_util/filter.c)
    target_include_directories(test_findings_filter PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(test_findings_filter PRIVATE packetsonde_lib)
    add_test(NAME test_findings_filter COMMAND test_findings_filter)

    add_executable(test_agents_registry tests/test_agents_registry.c registry/agents.c)
    target_include_directories(test_agents_registry PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(test_agents_registry PRIVATE packetsonde_lib)
    add_test(NAME test_agents_registry COMMAND test_agents_registry)

    add_test(NAME test_audit_tls
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_audit_tls.sh)
    set_tests_properties(test_audit_tls PROPERTIES
        SKIP_RETURN_CODE 77
        ENVIRONMENT "PS_BUILD_DIR=${CMAKE_BINARY_DIR}")
endif()

include(GNUInstallDirs)
install(TARGETS packetsonde RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
