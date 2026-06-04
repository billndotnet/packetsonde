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
    verbs/key.c
    verbs/register.c
    verbs/report_central.c
    verbs/collect.c
    verbs/recipe.c
    verbs/watch.c
    verbs/sandbox_suggest.c
    recipe/runner.c
    ../agent/src/config.c
    remote/audit_via.c
    remote/ingest_via.c
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
    audit/ldap.c
    audit/imap.c
    audit/pop3.c
    audit/snmp.c
    audit/rdp.c
    audit/mssql.c
    audit/kafka.c
    audit/vnc.c
    audit/haproxy.c
    audit/proxmox.c
    audit/nginx.c
    audit/opnsense.c
    audit/audit_common.c
    probe/tcp.c
    probe/icmp.c
    probe/traceroute.c
    discover/neighbors.c
    discover/hosts.c
    discover/agents.c
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
# libedit is used by the psctl shell on all platforms. macOS ships it in
# /usr/lib so plain `-ledit` works; Linux distros ship it as a package
# (apt: libedit-dev, dnf: libedit-devel) -- detect via find_library so a
# missing libedit produces a clean error message instead of a link
# failure deep in the build.
if(APPLE)
    target_link_libraries(packetsonde PRIVATE edit)
else()
    find_library(EDIT_LIB edit)
    if(NOT EDIT_LIB)
        message(FATAL_ERROR
            "libedit not found -- install libedit-dev (Debian/Ubuntu) "
            "or libedit-devel (RHEL/Fedora) and re-run cmake")
    endif()
    target_link_libraries(packetsonde PRIVATE ${EDIT_LIB})
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

    add_test(NAME test_audit_ssh
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_audit_ssh.sh)
    set_tests_properties(test_audit_ssh PROPERTIES
        SKIP_RETURN_CODE 77
        ENVIRONMENT "PS_BUILD_DIR=${CMAKE_BINARY_DIR}")

    add_test(NAME test_audit_imap
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_audit_imap.sh)
    set_tests_properties(test_audit_imap PROPERTIES
        SKIP_RETURN_CODE 77
        ENVIRONMENT "PS_BUILD_DIR=${CMAKE_BINARY_DIR}")

    add_test(NAME test_audit_pop3
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_audit_pop3.sh)
    set_tests_properties(test_audit_pop3 PROPERTIES
        SKIP_RETURN_CODE 77
        ENVIRONMENT "PS_BUILD_DIR=${CMAKE_BINARY_DIR}")

    add_test(NAME test_audit_snmp
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_audit_snmp.sh)
    set_tests_properties(test_audit_snmp PROPERTIES
        SKIP_RETURN_CODE 77
        ENVIRONMENT "PS_BUILD_DIR=${CMAKE_BINARY_DIR}")

    add_test(NAME test_audit_rdp
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_audit_rdp.sh)
    set_tests_properties(test_audit_rdp PROPERTIES
        SKIP_RETURN_CODE 77
        ENVIRONMENT "PS_BUILD_DIR=${CMAKE_BINARY_DIR}")

    add_test(NAME test_audit_mssql
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_audit_mssql.sh)
    set_tests_properties(test_audit_mssql PROPERTIES
        SKIP_RETURN_CODE 77
        ENVIRONMENT "PS_BUILD_DIR=${CMAKE_BINARY_DIR}")

    add_test(NAME test_audit_kafka
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_audit_kafka.sh)
    set_tests_properties(test_audit_kafka PROPERTIES
        SKIP_RETURN_CODE 77
        ENVIRONMENT "PS_BUILD_DIR=${CMAKE_BINARY_DIR}")

    add_test(NAME test_discover_agents
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_discover_agents.sh)
    set_tests_properties(test_discover_agents PROPERTIES
        SKIP_RETURN_CODE 77
        ENVIRONMENT "PS_BUILD_DIR=${CMAKE_BINARY_DIR}")

    add_test(NAME test_via_e2e
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_via_e2e.sh)
    set_tests_properties(test_via_e2e PROPERTIES
        SKIP_RETURN_CODE 77
        ENVIRONMENT "PS_BUILD_DIR=${CMAKE_BINARY_DIR}")

    add_test(NAME test_via_fail_on
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_via_fail_on.sh)
    set_tests_properties(test_via_fail_on PROPERTIES
        SKIP_RETURN_CODE 77
        ENVIRONMENT "PS_BUILD_DIR=${CMAKE_BINARY_DIR}")

    add_test(NAME test_probe_icmp
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_probe_icmp.sh)
    set_tests_properties(test_probe_icmp PROPERTIES
        SKIP_RETURN_CODE 77
        ENVIRONMENT "PS_BUILD_DIR=${CMAKE_BINARY_DIR}")

    add_test(NAME test_via_multihop
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_via_multihop.sh)
    set_tests_properties(test_via_multihop PROPERTIES
        SKIP_RETURN_CODE 77
        ENVIRONMENT "PS_BUILD_DIR=${CMAKE_BINARY_DIR}")

    # ---- coverage backfill for audit kinds that previously had no
    # integration test (review finding #14). Same Python+FIFO mock pattern
    # as the existing tests.
    foreach(_kind smtp redis memcached ftp telnet http
                  elasticsearch postgresql mysql
                  dns ntp ldap smb
                  vnc haproxy nginx)
        add_test(NAME test_audit_${_kind}
                 COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_audit_${_kind}.sh)
        set_tests_properties(test_audit_${_kind} PROPERTIES
            SKIP_RETURN_CODE 77
            ENVIRONMENT "PS_BUILD_DIR=${CMAKE_BINARY_DIR}")
    endforeach()
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
    # audit_common.c carries the shared parse_target + tcp_connect
    # helpers; every audit module links it directly so plugins can be
    # loaded standalone via dlopen without resolving CLI-internal
    # symbols at runtime.
    add_library(audit-${name} MODULE audit/${name}.c audit/audit_common.c)
    target_compile_definitions(audit-${name} PRIVATE PS_AUDIT_PLUGIN_BUILD=1)
    target_include_directories(audit-${name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../lib
    )
    target_link_libraries(audit-${name} PRIVATE packetsonde_lib)
    if(name STREQUAL "tls" OR name STREQUAL "http" OR name STREQUAL "elasticsearch"
       OR name STREQUAL "proxmox" OR name STREQUAL "ssh"
       OR name STREQUAL "opnsense")
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
        elasticsearch smtp mysql postgresql ldap imap pop3 snmp rdp mssql kafka vnc
        haproxy proxmox nginx opnsense)
    ps_add_audit_plugin(${_a})
endforeach()
