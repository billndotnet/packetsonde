# libpacketsonde — shared static library used by agent and cli.
add_library(packetsonde_lib STATIC
    json.c
    log.c
    ulid.c
    ipc.c
    finding.c
)
target_include_directories(packetsonde_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# Keep position-independent so a future shared-lib build is painless.
set_target_properties(packetsonde_lib PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(BUILD_TESTING)
    add_executable(test_ulid tests/test_ulid.c)
    target_link_libraries(test_ulid PRIVATE packetsonde_lib)
    add_test(NAME test_ulid COMMAND test_ulid)

    add_executable(test_finding tests/test_finding.c)
    target_link_libraries(test_finding PRIVATE packetsonde_lib)
    add_test(NAME test_finding COMMAND test_finding)
endif()
