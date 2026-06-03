cmake_minimum_required(VERSION 3.20)
project(packetsonde-agent VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Optional: libpcap
find_library(PCAP_LIBRARY pcap)
find_path(PCAP_INCLUDE_DIR pcap.h)
if(PCAP_LIBRARY AND PCAP_INCLUDE_DIR)
    set(HAVE_PCAP TRUE)
    message(STATUS "Found libpcap: ${PCAP_LIBRARY}")
else()
    set(HAVE_PCAP FALSE)
    message(STATUS "libpcap not found — passive capture modules disabled")
endif()

# Optional: hiredis for Redis bridge
find_library(HIREDIS_LIBRARY hiredis)
find_path(HIREDIS_INCLUDE_DIR hiredis/hiredis.h)
if(HIREDIS_LIBRARY AND HIREDIS_INCLUDE_DIR)
    set(HAVE_HIREDIS TRUE)
    message(STATUS "Found hiredis: ${HIREDIS_LIBRARY}")
else()
    set(HAVE_HIREDIS FALSE)
    message(STATUS "hiredis not found — Redis bridge disabled")
endif()

# Optional: OpenSSL (for TLS probe module)
find_package(OpenSSL)
if(OPENSSL_FOUND)
    message(STATUS "Found OpenSSL: ${OPENSSL_VERSION}")
else()
    message(STATUS "OpenSSL not found — TLS probe module disabled")
endif()

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/build_config.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/build_config.h"
)

if(NOT DEFINED SYSCONFDIR)
    set(SYSCONFDIR "/etc" CACHE PATH "System configuration directory")
endif()

option(WITH_REDIS "Enable Redis bridge" ON)
option(WITH_PCAP "Enable libpcap" ON)
option(WITH_SSL "Enable OpenSSL/TLS" ON)
option(BUILD_STATIC "Build statically linked binaries" OFF)

if(NOT WITH_REDIS)
    set(HAVE_HIREDIS FALSE)
endif()
if(NOT WITH_PCAP)
    set(HAVE_PCAP FALSE)
endif()
if(NOT WITH_SSL)
    set(OPENSSL_FOUND FALSE)
endif()
if(BUILD_STATIC)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
endif()

set(AGENT_CORE_SOURCES
    src/config.c
    src/config_to_env.c
    src/central_checkin.c
    src/module.c
    src/host_table.c
    src/ipc_server.c
    src/priv_client.c
    src/platform/unix.c
    src/flow_tracker.c
    src/netflow_export.c
    src/redis_bridge.c
    src/iface_enum.c
    src/iface_snapshot.c
    src/iso8601.c
    src/modules/icmp_traceroute.c
    src/modules/tcp_traceroute.c
    src/modules/udp_traceroute.c
    src/modules/dublin_traceroute.c
    src/modules/tcp_probe.c
    src/modules/udp_probe.c
    src/modules/tls_probe.c
    src/modules/flow_tracker_mod.c
    src/modules/neighbor_listener.c
    src/modules/dhcp_listener.c
    src/modules/stp_listener.c
    src/modules/mld_listener.c
    src/modules/dns_listener.c
    src/modules/lldp_listener.c
    src/modules/cdp_listener.c
    src/modules/ssdp_listener.c
    src/modules/netbios_listener.c
    src/modules/ospf_listener.c
    src/modules/vrrp_listener.c
    src/modules/broadcast_listener.c
    src/modules/iface_monitor.c
    src/modules/honeypot_listener.c
    src/modules/discovery_listener.c
    src/modules/network_listener.c
    src/capture/capture_handle.c
    src/capture/protocol_demux.c
    src/obs_queue.c
)

# Agent binary
add_executable(packetsonde-agent src/main.c ${AGENT_CORE_SOURCES})
# Brand name on disk is `packetsonded` (matches the README, systemd
# unit, launchd plist, and rc.d script). The CMake target stays
# `packetsonde-agent` for readability in build output.
set_target_properties(packetsonde-agent PROPERTIES OUTPUT_NAME packetsonded)
target_include_directories(packetsonde-agent PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/compat
    ${CMAKE_CURRENT_BINARY_DIR}
)
target_link_libraries(packetsonde-agent PRIVATE packetsonde_lib)
if(HAVE_PCAP)
    target_compile_definitions(packetsonde-agent PRIVATE HAVE_PCAP=1)
    target_include_directories(packetsonde-agent PRIVATE ${PCAP_INCLUDE_DIR})
    target_link_libraries(packetsonde-agent PRIVATE ${PCAP_LIBRARY})
endif()
if(OPENSSL_FOUND)
    target_link_libraries(packetsonde-agent PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(packetsonde-agent PRIVATE HAVE_OPENSSL=1)
endif()
if(HAVE_HIREDIS)
    target_include_directories(packetsonde-agent PRIVATE ${HIREDIS_INCLUDE_DIR})
    target_link_libraries(packetsonde-agent PRIVATE ${HIREDIS_LIBRARY})
    target_compile_definitions(packetsonde-agent PRIVATE HAVE_HIREDIS=1)
endif()

# (Install rules consolidated at the bottom of this file; the priv
# worker target is declared just below so we install it there.)

# Priv worker binary
add_executable(packetsonde-priv src/priv_worker.c src/platform/unix.c)
target_include_directories(packetsonde-priv PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}
)
target_link_libraries(packetsonde-priv PRIVATE packetsonde_lib)
if(HAVE_PCAP)
    target_compile_definitions(packetsonde-priv PRIVATE HAVE_PCAP=1)
    target_include_directories(packetsonde-priv PRIVATE ${PCAP_INCLUDE_DIR})
    target_link_libraries(packetsonde-priv PRIVATE ${PCAP_LIBRARY})
endif()

# Tests (will be added in later tasks)
enable_testing()

# Test: priv protocol
add_executable(test_priv_protocol tests/test_priv_protocol.c)
target_include_directories(test_priv_protocol PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}
)
add_test(NAME test_priv_protocol COMMAND test_priv_protocol)

# Test: config parser
add_executable(test_config tests/test_config.c src/config.c)
target_include_directories(test_config PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}
)
add_test(NAME test_config COMMAND test_config)

# Test: config -> env translation
add_executable(test_config_to_env tests/test_config_to_env.c src/config.c src/config_to_env.c)
target_include_directories(test_config_to_env PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}
)
add_test(NAME test_config_to_env COMMAND test_config_to_env)

# Test: IPC framing
add_executable(test_ipc_framing tests/test_ipc_framing.c src/ipc_server.c)
target_include_directories(test_ipc_framing PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}
)
target_link_libraries(test_ipc_framing PRIVATE packetsonde_lib)
add_test(NAME test_ipc_framing COMMAND test_ipc_framing)

add_executable(test_module_registry tests/test_module_registry.c src/module.c)
target_include_directories(test_module_registry PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}
)
target_link_libraries(test_module_registry PRIVATE packetsonde_lib)
add_test(NAME test_module_registry COMMAND test_module_registry)

# Test: ICMP traceroute module (includes .c directly — no root or network needed)
add_executable(test_icmp_traceroute tests/test_icmp_traceroute.c src/platform/unix.c)
target_include_directories(test_icmp_traceroute PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}
)
target_link_libraries(test_icmp_traceroute PRIVATE packetsonde_lib)
target_compile_definitions(test_icmp_traceroute PRIVATE PS_TESTING=1)
add_test(NAME test_icmp_traceroute COMMAND test_icmp_traceroute)

# Test: TCP traceroute module (includes .c directly — no root or network needed)
add_executable(test_tcp_traceroute tests/test_tcp_traceroute.c src/platform/unix.c)
target_include_directories(test_tcp_traceroute PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_tcp_traceroute PRIVATE packetsonde_lib)
target_compile_definitions(test_tcp_traceroute PRIVATE PS_TESTING=1)
add_test(NAME test_tcp_traceroute COMMAND test_tcp_traceroute)

# Test: UDP traceroute module (includes .c directly — no root or network needed)
add_executable(test_udp_traceroute tests/test_udp_traceroute.c src/platform/unix.c)
target_include_directories(test_udp_traceroute PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_udp_traceroute PRIVATE packetsonde_lib)
target_compile_definitions(test_udp_traceroute PRIVATE PS_TESTING=1)
add_test(NAME test_udp_traceroute COMMAND test_udp_traceroute)

# Test: TCP probe module (includes .c directly — no root or network needed)
add_executable(test_tcp_probe tests/test_tcp_probe.c src/platform/unix.c)
target_include_directories(test_tcp_probe PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_tcp_probe PRIVATE packetsonde_lib)
target_compile_definitions(test_tcp_probe PRIVATE PS_TCP_PROBE_TESTING=1)
add_test(NAME test_tcp_probe COMMAND test_tcp_probe)

# Test: UDP probe module (includes .c directly — no network needed)
add_executable(test_udp_probe tests/test_udp_probe.c src/platform/unix.c)
target_include_directories(test_udp_probe PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_udp_probe PRIVATE packetsonde_lib)
target_compile_definitions(test_udp_probe PRIVATE PS_UDP_PROBE_TESTING=1)
add_test(NAME test_udp_probe COMMAND test_udp_probe)

# Test: discovery_listener -- end-to-end including signed reply on lo.
add_executable(test_discovery_listener tests/test_discovery_listener.c)
target_include_directories(test_discovery_listener PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_discovery_listener PRIVATE packetsonde_lib)
add_test(NAME test_discovery_listener COMMAND test_discovery_listener)

# Test: NetFlow / IPFIX exporter wire format
add_executable(test_netflow_export
    tests/test_netflow_export.c
    src/netflow_export.c
)
target_include_directories(test_netflow_export PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_netflow_export PRIVATE packetsonde_lib)
add_test(NAME test_netflow_export COMMAND test_netflow_export)

# Standalone driver for the e2e --via test (no add_test; the bash test
# invokes it as a subprocess).
add_executable(test_network_listener_driver tests/test_network_listener_driver.c)
target_include_directories(test_network_listener_driver PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_network_listener_driver PRIVATE packetsonde_lib pthread)

# Test: flow tracker (synthetic packets — no pcap or network needed)
add_executable(test_flow_tracker tests/test_flow_tracker.c src/flow_tracker.c src/netflow_export.c src/platform/unix.c)
target_include_directories(test_flow_tracker PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/compat ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_flow_tracker PRIVATE packetsonde_lib)
add_test(NAME test_flow_tracker COMMAND test_flow_tracker)

# Test: neighbor listener (synthetic Ethernet frames — no pcap or network needed)
add_executable(test_neighbor_listener tests/test_neighbor_listener.c src/platform/unix.c)
target_include_directories(test_neighbor_listener PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_neighbor_listener PRIVATE packetsonde_lib)
target_compile_definitions(test_neighbor_listener PRIVATE PS_NEIGHBOR_LISTENER_TESTING=1)
add_test(NAME test_neighbor_listener COMMAND test_neighbor_listener)

# Test: DNS listener (synthetic Ethernet+IP+UDP+DNS frames — no pcap or network needed)
add_executable(test_dns_listener tests/test_dns_listener.c src/platform/unix.c)
target_include_directories(test_dns_listener PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_dns_listener PRIVATE packetsonde_lib)
target_compile_definitions(test_dns_listener PRIVATE PS_DNS_LISTENER_TESTING=1)
add_test(NAME test_dns_listener COMMAND test_dns_listener)

# Test: honeypot listener (config parser + socket lifecycle + JSON events — no pcap or Redis needed)
add_executable(test_honeypot_listener tests/test_honeypot_listener.c src/platform/unix.c)
target_include_directories(test_honeypot_listener PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_honeypot_listener PRIVATE packetsonde_lib)
target_compile_definitions(test_honeypot_listener PRIVATE PS_HONEYPOT_LISTENER_TESTING=1)
add_test(NAME test_honeypot_listener COMMAND test_honeypot_listener)

# Test: interface enumeration (getifaddrs + prefix-exclude logic — no pcap or network needed)
add_executable(test_iface_enum tests/test_iface_enum.c src/iface_enum.c)
target_include_directories(test_iface_enum PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR})
add_test(NAME test_iface_enum COMMAND test_iface_enum)

# Test: interface snapshot + pure diff (synthetic snapshots — no pcap or network needed)
add_executable(test_iface_snapshot tests/test_iface_snapshot.c src/iface_snapshot.c)
target_include_directories(test_iface_snapshot PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR})
add_test(NAME test_iface_snapshot COMMAND test_iface_snapshot)

# Test: pure UTC ISO-8601 formatter (no library deps)
add_executable(test_iso8601 tests/test_iso8601.c src/iso8601.c)
target_include_directories(test_iso8601 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR})
add_test(NAME test_iso8601 COMMAND test_iso8601)

# Test: capture handle close (single-iface teardown — no pcap or network needed)
add_executable(test_capture_close tests/test_capture_close.c src/capture/capture_handle.c)
target_include_directories(test_capture_close PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_capture_close PRIVATE packetsonde_lib)
add_test(NAME test_capture_close COMMAND test_capture_close)

# Test: bounded observation queue + event-JSON wrapper
add_executable(test_obs_queue tests/test_obs_queue.c src/obs_queue.c)
target_include_directories(test_obs_queue PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_obs_queue PRIVATE pthread)
add_test(NAME test_obs_queue COMMAND test_obs_queue)

include(GNUInstallDirs)

# Per-platform install layout, intended for `sudo make install` from a
# from-source build. Default CMAKE_INSTALL_PREFIX is /usr/local.
#
#   /usr/local/sbin/packetsonded           agent daemon
#   /usr/local/sbin/packetsonde-priv       priv worker (raw sockets / pcap)
#   /usr/local/bin/packetsonde             CLI (installed by src/cli/CMakeLists.txt)
#   /etc/packetsonded/packetsonded.toml    example config (installed if missing)
#   /etc/packetsonded/keys/authorized/     directory only -- operator
#                                          populates with client .pub files
#   /etc/systemd/system/packetsonded.service   Linux only
#   /usr/local/etc/rc.d/packetsonded           FreeBSD only

install(TARGETS packetsonde-agent packetsonde-priv
        RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})

set(PS_CONFIG_DIR "/etc/packetsonded" CACHE PATH
    "Where to install packetsonded's config + keys directory")

# Config: install as <name>.toml.example so an existing config isn't
# clobbered. Operator copies .example -> .toml on first deployment.
install(DIRECTORY DESTINATION ${PS_CONFIG_DIR})
install(DIRECTORY DESTINATION ${PS_CONFIG_DIR}/keys/authorized)
install(FILES ${CMAKE_SOURCE_DIR}/packaging/packetsonded.toml
        DESTINATION ${PS_CONFIG_DIR}
        RENAME packetsonded.toml.example)

# systemd unit (Linux). Installs to /etc/systemd/system regardless of
# prefix because that's where systemd reads unconditionally; from-source
# install at /usr/local/lib/systemd/system isn't picked up without an
# operator step.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    install(FILES ${CMAKE_SOURCE_DIR}/packaging/packetsonded.service
            DESTINATION /etc/systemd/system)
endif()

# rc.d script (FreeBSD / OPNsense / pfSense).
if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    install(PROGRAMS ${CMAKE_SOURCE_DIR}/packaging/freebsd/packetsonded.rc
            DESTINATION ${SYSCONFDIR}/rc.d
            RENAME packetsonded)
endif()

# Post-install message: operator next-steps. Printed by CMake at the
# end of `make install` -- helpful for first-deploy walk-through.
install(CODE "
message(STATUS \"\")
message(STATUS \"=== packetsonded install complete ===\")
message(STATUS \"\")
message(STATUS \"Next steps:\")
message(STATUS \"  1. Create the unprivileged service user (Linux):\")
message(STATUS \"       sudo useradd --system --no-create-home --shell /usr/sbin/nologin packetsonded\")
message(STATUS \"  2. Activate the config:\")
message(STATUS \"       sudo cp ${PS_CONFIG_DIR}/packetsonded.toml.example ${PS_CONFIG_DIR}/packetsonded.toml\")
message(STATUS \"  3. Generate the agent identity keypair (writes ${PS_CONFIG_DIR}/keys/agent.{pub,sec}):\")
message(STATUS \"       sudo PS_KEY_DIR=${PS_CONFIG_DIR}/keys packetsonde key generate --name agent\")
message(STATUS \"  4. Authorize a CLI pubkey:\")
message(STATUS \"       sudo cp ~/.config/packetsonde/keys/default.pub ${PS_CONFIG_DIR}/keys/authorized/\")
message(STATUS \"  5. Start the daemon:\")
message(STATUS \"       Linux:   sudo systemctl daemon-reload && sudo systemctl enable --now packetsonded\")
message(STATUS \"       macOS:   sudo launchctl bootstrap system /Library/LaunchDaemons/net.billn.packetsonded.plist\")
message(STATUS \"       FreeBSD: sudo sysrc packetsonded_enable=YES && sudo service packetsonded start\")
message(STATUS \"\")
")
