set(CLI_SOURCES
    main.c
    args.c
    dispatch.c
    verbs/version.c
    verbs/agent.c
    verbs/audit.c
    verbs/findings.c
    verbs/config.c
    verbs/probe.c
    verbs/report.c
    audit_loader.c
    registry/agents.c
    audit/tls.c
    audit/dns.c
    audit/http.c
    audit/ssh.c
    audit/smb.c
    audit/telnet.c
    audit/ftp.c
    audit/redis.c
    audit/ntp.c
    audit/memcached.c
    audit/elasticsearch.c
    audit/smtp.c
    audit/mysql.c
    audit/postgresql.c
    probe/tcp.c
    probe/traceroute.c
    discover/neighbors.c
    discover/hosts.c
    verbs/discover.c
    verbs/scan.c
    scan/ports.c
    scan/udp.c
    probe/connect.c
    output/output.c
    workers/limiter.c
    workers/workers.c
    signals.c
    util/targets.c
    util/fail_on.c
    runstate.c
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
# dlopen / dlsym for the audit plugin loader. macOS has it in libSystem;
# Linux needs explicit -ldl.
if(NOT APPLE)
    target_link_libraries(packetsonde PRIVATE ${CMAKE_DL_LIBS})
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

    add_executable(test_fail_on tests/test_fail_on.c util/fail_on.c)
    target_include_directories(test_fail_on PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(test_fail_on PRIVATE packetsonde_lib)
    add_test(NAME test_fail_on COMMAND test_fail_on)

    add_test(NAME test_audit_tls
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_audit_tls.sh)
    set_tests_properties(test_audit_tls PROPERTIES
        SKIP_RETURN_CODE 77
        ENVIRONMENT "PS_BUILD_DIR=${CMAKE_BINARY_DIR}")
endif()

include(GNUInstallDirs)
install(TARGETS packetsonde RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# ---- Audit modules built as loadable plugins ----
#
# Each plugin compiles the same audit source as a MODULE library and exports
# ps_audit_module(). The CLI's plugin loader scans for these at runtime
# (PS_AUDITS_DIR override, XDG config, build-tree default, /usr/[local/]lib).
# Plugins are emitted into ${CMAKE_BINARY_DIR}/src/cli/audit/ where the CLI's
# build-tree default search path picks them up during development.
#
# Audits still living in CLI_SOURCES above are statically linked into the
# binary too; the loader dedupes by name (first-loaded wins) so a developer
# can shadow a built-in by dropping a .dylib into the search path.

set(_audit_plugin_dir ${CMAKE_BINARY_DIR}/src/cli/audit)

function(ps_add_audit_plugin name)
    add_library(audit-${name} MODULE audit/${name}.c)
    target_compile_definitions(audit-${name} PRIVATE PS_AUDIT_PLUGIN_BUILD=1)
    target_include_directories(audit-${name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../lib
    )
    target_link_libraries(audit-${name} PRIVATE packetsonde_lib)
    if(name STREQUAL "tls" OR name STREQUAL "http" OR name STREQUAL "elasticsearch")
        find_package(OpenSSL REQUIRED)
        target_link_libraries(audit-${name} PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
    set_target_properties(audit-${name} PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${_audit_plugin_dir}
        PREFIX ""
        OUTPUT_NAME "audit-${name}"
    )
    if(APPLE)
        set_target_properties(audit-${name} PROPERTIES SUFFIX ".dylib")
    endif()
endfunction()

# All audit kinds, also built as loadable plugins. Static-linked into
# packetsonde too; the loader dedupes by name, so a user-supplied .dylib
# at a higher-priority path overrides a built-in.
foreach(_a tls dns http ssh smb telnet ftp redis ntp memcached
        elasticsearch smtp mysql postgresql)
    ps_add_audit_plugin(${_a})
endforeach()
