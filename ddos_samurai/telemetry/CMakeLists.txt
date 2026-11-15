cmake_minimum_required(VERSION 3.16)
project(samurai_telemetry LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
  set(SAMURAI_TELEMETRY_ARCH_FLAGS "-msse4.2")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
  set(SAMURAI_TELEMETRY_ARCH_FLAGS "-march=armv8-a+crc")
else()
  set(SAMURAI_TELEMETRY_ARCH_FLAGS "")
endif()

add_library(samurai_telemetry STATIC
  flow_cache.cpp
  ipfix_exporter.cpp
)

target_include_directories(samurai_telemetry PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
)

if(SAMURAI_TELEMETRY_ARCH_FLAGS)
  target_compile_options(samurai_telemetry PRIVATE ${SAMURAI_TELEMETRY_ARCH_FLAGS})
endif()

target_link_libraries(samurai_telemetry PUBLIC pthread)

if(TARGET samurai_telecom_static AND TARGET samurai_l7emu AND TARGET samurai_core)
  find_package(OpenSSL QUIET)
  add_executable(test_telecom_telemetry_native
    ${CMAKE_CURRENT_SOURCE_DIR}/../../tests/test_telecom_telemetry_native.cpp
  )
  target_include_directories(test_telecom_telemetry_native PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
  )
  target_link_libraries(test_telecom_telemetry_native PRIVATE
    samurai_telemetry
    samurai_telecom_static
    samurai_l7emu
    samurai_core
    pthread
  )
  if(OpenSSL_FOUND)
    target_link_libraries(test_telecom_telemetry_native PRIVATE OpenSSL::Crypto)
  endif()
  if(SAMURAI_TELEMETRY_ARCH_FLAGS)
    target_compile_options(test_telecom_telemetry_native PRIVATE ${SAMURAI_TELEMETRY_ARCH_FLAGS})
  endif()
  add_test(NAME telecom_telemetry_native COMMAND test_telecom_telemetry_native)
endif()
