set(CLI_SOURCES
    main.c
    args.c
    dispatch.c
    verbs/version.c
)

add_executable(packetsonde ${CLI_SOURCES})
target_include_directories(packetsonde PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../agent/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../agent/src/psctl
)
target_link_libraries(packetsonde PRIVATE packetsonde_lib)

if(BUILD_TESTING)
    add_executable(test_args tests/test_args.c args.c)
    target_include_directories(test_args PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(test_args PRIVATE packetsonde_lib)
    add_test(NAME test_args COMMAND test_args)
endif()
