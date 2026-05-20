# libpacketsonde — shared static library used by agent and cli.
# Real contents land in Task 5.
add_library(packetsonde_lib INTERFACE)
target_include_directories(packetsonde_lib INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
