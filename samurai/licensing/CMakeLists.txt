cmake_minimum_required(VERSION 3.16)
project(samurai_license LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(OpenSSL REQUIRED)

# samurai_license — native licensing layer, the C++ replacement for the offline
# core of samurai/licensing:
#   license_types.* -> tiers / features / limits / LicenseResult
#   constants.hpp   -> server/endpoint/cache/env configuration
#   hwid.*          -> hardware fingerprint (SHA-256)
#   gates.*         -> feature-gate enforcement (+ ExecGrantClient)
#   cache.*         -> encrypted offline cache (AES-256-GCM, HWID-derived key)
#   http_client.*   -> native HTTP(S) POST client (POSIX sockets + OpenSSL TLS)
#   client.*        -> HttpLicenseClient: validate + server-side exec-grant
#
# The license-server heartbeat/deactivate and the self-updater remain to be
# added as needed.
add_library(
  samurai_license
  STATIC
  license_types.cpp
  hwid.cpp
  gates.cpp
  cache.cpp
  http_client.cpp
  client.cpp
  anti_tamper.cpp)
target_include_directories(samurai_license PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(samurai_license PUBLIC samurai_core PRIVATE OpenSSL::SSL OpenSSL::Crypto)

add_executable(samurai_license_selftest selftest.cpp)
target_link_libraries(samurai_license_selftest PRIVATE samurai_license)
