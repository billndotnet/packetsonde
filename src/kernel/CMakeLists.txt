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

# Install rules (mirror src/agent's pattern, gated by PS_PACKAGED_BUILD).
# PS_PACKAGED_BUILD is defined in src/agent/CMakeLists.txt (processed first by
# the root); it's a cache variable and therefore visible here.
include(GNUInstallDirs)
install(TARGETS kernelsonded kernelsonde-priv RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})

set(KS_CONFIG_DIR "/etc/kernelsonded" CACHE PATH "kernelsonded config + keys dir")
install(DIRECTORY DESTINATION ${KS_CONFIG_DIR})
install(DIRECTORY DESTINATION ${KS_CONFIG_DIR}/keys/authorized)
install(FILES ${CMAKE_SOURCE_DIR}/packaging/kernelsonded.toml
        DESTINATION ${KS_CONFIG_DIR} RENAME kernelsonded.toml.example)

# systemd unit (Linux, from-source only). Package builds install the unit via
# dh_installsystemd instead (see debian/rules).
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT PS_PACKAGED_BUILD)
    install(FILES ${CMAKE_SOURCE_DIR}/packaging/kernelsonded.service
            DESTINATION /etc/systemd/system)
endif()
