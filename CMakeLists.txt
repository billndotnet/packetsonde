cmake_minimum_required(VERSION 3.20)
project(packetsonde VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

enable_testing()
set(BUILD_TESTING ON)

# Project-wide options propagate to subdirs.
option(WITH_REDIS    "Enable Redis bridge"             ON)
option(WITH_PCAP     "Enable libpcap"                  ON)
option(WITH_SSL      "Enable OpenSSL/TLS"              ON)
option(BUILD_STATIC  "Build statically linked binaries" OFF)

if(BUILD_STATIC)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
endif()

# Order matters: lib first (others depend on it), then agent and cli.
add_subdirectory(src/lib)
add_subdirectory(src/agent)
add_subdirectory(src/cli)
