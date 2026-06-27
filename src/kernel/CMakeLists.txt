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

# kernelsonded — the detection brain. Forks kernelsonde-priv, drops privs,
# registers the two detect modules, serves the IPC socket, ships to central.
add_executable(kernelsonded
    src/main.c
    src/activity_ring.c
    src/baseline_store.c
    src/capture_session.c
    src/modules/policy_overwatch.c
    src/modules/baseline_monitor.c
)
target_include_directories(kernelsonded PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/modules
    ${CMAKE_SOURCE_DIR}/src/agent/src
    ${CMAKE_SOURCE_DIR}/src/agent/include)
target_link_libraries(kernelsonded PRIVATE packetsonde_daemon packetsonde_lib pthread)
