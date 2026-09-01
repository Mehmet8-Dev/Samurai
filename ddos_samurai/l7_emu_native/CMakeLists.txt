cmake_minimum_required(VERSION 3.16)
project(samurai_l7emu LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(OPENSSL QUIET openssl)
  pkg_check_modules(NGHTTP2 QUIET libnghttp2)
  pkg_check_modules(NGTCP2 QUIET libngtcp2)
  pkg_check_modules(NGTCP2_GNUTLS QUIET libngtcp2_crypto_gnutls)
  pkg_check_modules(NGHTTP3 QUIET libnghttp3)
  pkg_check_modules(GNUTLS QUIET gnutls)
endif()

# samurai_l7emu — the native L7 emulation engine (HTTP/1.1, HTTP/2 via nghttp2,
# custom TCP bridge over samurai_l4, and the in-process QUIC/H3 stack). The
# pybind facade (module.cpp) is gone; the JSON bridge (bridge.cpp) is the ZMQ
# worker entry point. TLS/HTTP2/QUIC backends compile in when the toolchain is
# present and are otherwise reported as unavailable by detect_capabilities().
set(SAMURAI_L7EMU_SOURCES
  engine.cpp
  bridge.cpp
  tls_session_engine.cpp
  dns_client_engine.cpp
  l2l3_stack/dhcp_state_machine.cpp
  l2l3_stack/arp_engine.cpp
  l2l3_stack/igmp_engine.cpp
  l2l3_stack/nd_engine.cpp
  custom_quic_stack/crypto_backend.cpp
  custom_quic_stack/h3_control_plane.cpp
  custom_quic_stack/h3_minimal_client.cpp
  custom_quic_stack/h3_ngtcp2_client.cpp
  custom_quic_stack/h3_parity_state.cpp
  custom_quic_stack/h3_real_client.cpp
  custom_quic_stack/loss_recovery.cpp
  custom_quic_stack/quic_metrics.cpp
  custom_quic_stack/quic_stack.cpp
  custom_quic_stack/udp_io.cpp)

add_library(samurai_l7emu STATIC ${SAMURAI_L7EMU_SOURCES})
target_include_directories(samurai_l7emu PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(samurai_l7emu PUBLIC samurai_l4 samurai_core pthread dl)

if(OPENSSL_FOUND)
  target_compile_definitions(samurai_l7emu PUBLIC SAMURAI_WITH_OPENSSL=1)
  target_include_directories(samurai_l7emu PUBLIC ${OPENSSL_INCLUDE_DIRS})
  target_link_directories(samurai_l7emu PUBLIC ${OPENSSL_LIBRARY_DIRS})
  target_link_libraries(samurai_l7emu PUBLIC ${OPENSSL_LIBRARIES})
else()
  message(STATUS "openssl not found: TLS/HTTP2 native paths compiled out")
endif()

if(NGHTTP2_FOUND)
  target_compile_definitions(samurai_l7emu PUBLIC SAMURAI_WITH_NGHTTP2=1)
  target_include_directories(samurai_l7emu PUBLIC ${NGHTTP2_INCLUDE_DIRS})
  target_link_directories(samurai_l7emu PUBLIC ${NGHTTP2_LIBRARY_DIRS})
  target_link_libraries(samurai_l7emu PUBLIC ${NGHTTP2_LIBRARIES})
else()
  message(STATUS "libnghttp2 not found: HTTP/2 native paths compiled out")
endif()

set(SAMURAI_QUIC_BACKENDS 0)
if(NGTCP2_FOUND)
  target_compile_definitions(samurai_l7emu PUBLIC SAMURAI_WITH_NGTCP2=1)
  set(SAMURAI_QUIC_BACKENDS 1)
endif()
if(NGHTTP3_FOUND)
  target_compile_definitions(samurai_l7emu PUBLIC SAMURAI_WITH_NGHTTP3=1)
endif()
if(GNUTLS_FOUND)
  target_compile_definitions(samurai_l7emu PUBLIC SAMURAI_WITH_GNUTLS=1)
endif()
if(NGTCP2_FOUND AND GNUTLS_FOUND)
  target_compile_definitions(samurai_l7emu PUBLIC SAMURAI_WITH_NGTCP2_GNUTLS=1)
endif()
if(SAMURAI_QUIC_BACKENDS)
  target_link_libraries(samurai_l7emu PUBLIC ${NGTCP2_LIBRARIES} ${NGTCP2_GNUTLS_LIBRARIES} ${NGHTTP3_LIBRARIES} ${GNUTLS_LIBRARIES})
endif()

add_executable(test_l2l3_astf test_l2l3_astf.cpp)
target_link_libraries(test_l2l3_astf PRIVATE samurai_l7emu samurai_l4 samurai_core pthread dl)

# kernel_socket H1 threaded driver e2e: real localhost HTTP/1.1 server + shards>1.
add_executable(test_kernel_threaded_l7 test_kernel_threaded_l7.cpp)
target_link_libraries(test_kernel_threaded_l7 PRIVATE samurai_l7emu samurai_l4 samurai_core pthread dl)

