# kernelsonde — Linux host behavioral-detection daemon + priv worker.
add_executable(kernelsonde-priv
    src/kernel_priv_worker.c
    src/fan_monitor.c
    src/proc_enrich.c
    src/sock_snapshot.c
)
target_include_directories(kernelsonde-priv PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/agent/src        # priv_protocol.h
    ${CMAKE_SOURCE_DIR}/src/agent/include)
target_link_libraries(kernelsonde-priv PRIVATE packetsonde_lib pthread)
