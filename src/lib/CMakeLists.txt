# libpacketsonde — shared static library used by agent and cli.
add_library(packetsonde_lib STATIC
    json.c
    log.c
    ulid.c
    ipc.c
    finding.c
    traceroute.c
    discovery.c
    keystore.c
    agent_proto.c
    agent_transport.c
    http_client.c
    registration.c
    reporter.c
    relay_attest.c
    json_extract.c
    collect.c
    recipe_parse.c
    recipe_verify.c
    recipe_engine.c
    suppress.c
    proc_parse.c
    sock_parse.c
    activity_record.c
    cgroup_unit.c
    systemd_policy.c
    policy_eval.c
    unit_envelope.c
    sandbox_synth.c
    exe_slug.c
    baseline_set.c
    baseline_decide.c
)
target_include_directories(packetsonde_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# Keep position-independent so a future shared-lib build is painless.
set_target_properties(packetsonde_lib PROPERTIES POSITION_INDEPENDENT_CODE ON)
# Ed25519 sign/verify + SHA-256 fingerprints live in discovery.c / keystore.c.
find_package(OpenSSL REQUIRED)
target_link_libraries(packetsonde_lib PUBLIC OpenSSL::Crypto OpenSSL::SSL)

if(BUILD_TESTING)
    add_executable(test_ulid tests/test_ulid.c)
    target_link_libraries(test_ulid PRIVATE packetsonde_lib)
    add_test(NAME test_ulid COMMAND test_ulid)

    add_executable(test_json tests/test_json.c)
    target_link_libraries(test_json PRIVATE packetsonde_lib)
    add_test(NAME test_json COMMAND test_json)

    add_executable(test_json_extract tests/test_json_extract.c)
    target_link_libraries(test_json_extract PRIVATE packetsonde_lib)
    add_test(NAME test_json_extract COMMAND test_json_extract)

    add_executable(test_collect tests/test_collect.c)
    target_link_libraries(test_collect PRIVATE packetsonde_lib)
    add_test(NAME test_collect COMMAND test_collect)

    add_executable(test_suppress tests/test_suppress.c)
    target_link_libraries(test_suppress PRIVATE packetsonde_lib)
    add_test(NAME test_suppress COMMAND test_suppress)

    add_executable(test_finding tests/test_finding.c)
    target_link_libraries(test_finding PRIVATE packetsonde_lib)
    add_test(NAME test_finding COMMAND test_finding)

    add_executable(test_traceroute tests/test_traceroute.c)
    target_link_libraries(test_traceroute PRIVATE packetsonde_lib)
    add_test(NAME test_traceroute COMMAND test_traceroute)

    add_executable(test_discovery tests/test_discovery.c)
    target_link_libraries(test_discovery PRIVATE packetsonde_lib)
    add_test(NAME test_discovery COMMAND test_discovery)

    add_executable(test_http_client tests/test_http_client.c)
    target_link_libraries(test_http_client PRIVATE packetsonde_lib)
    add_test(NAME test_http_client COMMAND test_http_client)

    add_executable(test_registration tests/test_registration.c)
    target_link_libraries(test_registration PRIVATE packetsonde_lib)
    add_test(NAME test_registration COMMAND test_registration)

    add_executable(test_keystore_sign tests/test_keystore_sign.c)
    target_link_libraries(test_keystore_sign PRIVATE packetsonde_lib)
    add_test(NAME test_keystore_sign COMMAND test_keystore_sign)

    add_executable(test_reporter tests/test_reporter.c)
    target_link_libraries(test_reporter PRIVATE packetsonde_lib)
    add_test(NAME test_reporter COMMAND test_reporter)

    add_executable(test_relay_attest tests/test_relay_attest.c)
    target_link_libraries(test_relay_attest PRIVATE packetsonde_lib)
    add_test(NAME test_relay_attest COMMAND test_relay_attest)

    add_executable(test_agent_proto tests/test_agent_proto.c)
    target_link_libraries(test_agent_proto PRIVATE packetsonde_lib)
    add_test(NAME test_agent_proto COMMAND test_agent_proto)

    add_executable(test_agent_transport tests/test_agent_transport.c)
    target_link_libraries(test_agent_transport PRIVATE packetsonde_lib pthread)
    add_test(NAME test_agent_transport COMMAND test_agent_transport)

    add_executable(test_recipe tests/test_recipe.c)
    target_link_libraries(test_recipe PRIVATE packetsonde_lib)
    add_test(NAME test_recipe COMMAND test_recipe)

    add_executable(test_recipe_engine tests/test_recipe_engine.c)
    target_link_libraries(test_recipe_engine PRIVATE packetsonde_lib)
    add_test(NAME test_recipe_engine COMMAND test_recipe_engine)

    add_executable(test_proc_parse tests/test_proc_parse.c)
    target_link_libraries(test_proc_parse PRIVATE packetsonde_lib)
    add_test(NAME test_proc_parse COMMAND test_proc_parse)

    add_executable(test_sock_parse tests/test_sock_parse.c)
    target_link_libraries(test_sock_parse PRIVATE packetsonde_lib)
    add_test(NAME test_sock_parse COMMAND test_sock_parse)

    add_executable(test_activity_record tests/test_activity_record.c)
    target_link_libraries(test_activity_record PRIVATE packetsonde_lib)
    add_test(NAME test_activity_record COMMAND test_activity_record)

    add_executable(test_cgroup_unit tests/test_cgroup_unit.c)
    target_link_libraries(test_cgroup_unit PRIVATE packetsonde_lib)
    add_test(NAME test_cgroup_unit COMMAND test_cgroup_unit)

    add_executable(test_systemd_policy tests/test_systemd_policy.c)
    target_link_libraries(test_systemd_policy PRIVATE packetsonde_lib)
    add_test(NAME test_systemd_policy COMMAND test_systemd_policy)

    add_executable(test_systemd_policy_cache tests/test_systemd_policy_cache.c)
    target_link_libraries(test_systemd_policy_cache PRIVATE packetsonde_lib)
    add_test(NAME test_systemd_policy_cache COMMAND test_systemd_policy_cache)

    add_executable(test_policy_eval tests/test_policy_eval.c)
    target_link_libraries(test_policy_eval PRIVATE packetsonde_lib)
    add_test(NAME test_policy_eval COMMAND test_policy_eval)

    add_executable(test_unit_envelope tests/test_unit_envelope.c)
    target_link_libraries(test_unit_envelope PRIVATE packetsonde_lib)
    add_test(NAME test_unit_envelope COMMAND test_unit_envelope)

    add_executable(test_unit_envelope_json tests/test_unit_envelope_json.c)
    target_link_libraries(test_unit_envelope_json PRIVATE packetsonde_lib)
    add_test(NAME test_unit_envelope_json COMMAND test_unit_envelope_json)

    add_executable(test_sandbox_synth tests/test_sandbox_synth.c)
    target_link_libraries(test_sandbox_synth PRIVATE packetsonde_lib)
    add_test(NAME test_sandbox_synth COMMAND test_sandbox_synth)

    add_executable(test_exe_slug tests/test_exe_slug.c)
    target_link_libraries(test_exe_slug PRIVATE packetsonde_lib)
    add_test(NAME test_exe_slug COMMAND test_exe_slug)

    add_executable(test_baseline_set tests/test_baseline_set.c)
    target_link_libraries(test_baseline_set PRIVATE packetsonde_lib)
    add_test(NAME test_baseline_set COMMAND test_baseline_set)

    add_executable(test_baseline_decide tests/test_baseline_decide.c)
    target_link_libraries(test_baseline_decide PRIVATE packetsonde_lib)
    add_test(NAME test_baseline_decide COMMAND test_baseline_decide)
endif()
