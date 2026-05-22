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
endif()
