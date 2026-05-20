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
)
target_include_directories(packetsonde_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# Keep position-independent so a future shared-lib build is painless.
set_target_properties(packetsonde_lib PROPERTIES POSITION_INDEPENDENT_CODE ON)
# Ed25519 sign/verify + SHA-256 fingerprints live in discovery.c / keystore.c.
find_package(OpenSSL REQUIRED)
target_link_libraries(packetsonde_lib PUBLIC OpenSSL::Crypto)

if(BUILD_TESTING)
    add_executable(test_ulid tests/test_ulid.c)
    target_link_libraries(test_ulid PRIVATE packetsonde_lib)
    add_test(NAME test_ulid COMMAND test_ulid)

    add_executable(test_finding tests/test_finding.c)
    target_link_libraries(test_finding PRIVATE packetsonde_lib)
    add_test(NAME test_finding COMMAND test_finding)

    add_executable(test_traceroute tests/test_traceroute.c)
    target_link_libraries(test_traceroute PRIVATE packetsonde_lib)
    add_test(NAME test_traceroute COMMAND test_traceroute)

    add_executable(test_discovery tests/test_discovery.c)
    target_link_libraries(test_discovery PRIVATE packetsonde_lib)
    add_test(NAME test_discovery COMMAND test_discovery)
endif()
