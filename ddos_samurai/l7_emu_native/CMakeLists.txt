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
  pkg_check_modules(DPDK QUIET libdpdk)
  pkg_check_modules(URING QUIET liburing)
endif()
find_path(LINUX_IO_URING_H NAMES "linux/io_uring.h")

# samurai_l7emu — the native L7 emulation engine (HTTP/1.1, HTTP/2 via nghttp2,
# custom TCP bridge over samurai_l4, and the in-process QUIC/H3 stack). The
# pybind facade (module.cpp) is gone; the JSON bridge (bridge.cpp) is the ZMQ
# worker entry point. TLS/HTTP2/QUIC backends compile in when the toolchain is
# present and are otherwise reported as unavailable by detect_capabilities().
set(SAMURAI_L7EMU_SOURCES
  engine.cpp
  engine_arena.cpp
  engine_h1_transport.cpp
  engine_h1_parser.cpp
  engine_h2_session.cpp
  engine_custom_tcp.cpp
  engine_runtime.cpp
  engine_h1_request.cpp
  engine_h2_profile.cpp
  engine_dns_l2l3.cpp
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
  custom_quic_stack/udp_io.cpp
  # Tek native DPDK çekirdeği. Başlık rte/Python bağımsız; kaynak kendini
  # SAMURAI_WITH_DPDK ile gate'ler (libdpdk yokken güvenli saplama derlenir).
  # Burada konsolide edilir ki samurai_l7emu'yu link'leyen tüm tüketiciler
  # (own-wire DPDK teli, QUIC DPDK backend, dpdk/scenario worker) tek kopyayı
  # paylaşsın — worker'larda ayrıca derlemek çift-sembol yaratırdı.
  ../dpdk/dpdk_core.cpp)

add_library(samurai_l7emu STATIC ${SAMURAI_L7EMU_SOURCES})
target_include_directories(samurai_l7emu PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../dpdk)
target_link_libraries(samurai_l7emu PUBLIC samurai_l4 samurai_core pthread dl)

if(DPDK_FOUND)
  # PUBLIC: gate + link bayrakları tüketicilere yayılır; worker'lar artık
  # dpdk_core.cpp'yi ayrıca derlemez, define'ı buradan miras alır.
  target_compile_definitions(samurai_l7emu PUBLIC SAMURAI_WITH_DPDK=1)
  target_include_directories(samurai_l7emu PUBLIC ${DPDK_INCLUDE_DIRS})
  target_link_directories(samurai_l7emu PUBLIC ${DPDK_LIBRARY_DIRS})
  target_link_libraries(samurai_l7emu PUBLIC ${DPDK_LIBRARIES})
  target_compile_options(samurai_l7emu PUBLIC ${DPDK_CFLAGS_OTHER})
  target_link_options(samurai_l7emu PUBLIC ${DPDK_LDFLAGS_OTHER})
else()
  message(STATUS "libdpdk not found: samurai_l7emu links the DPDK stub (no native DPDK path)")
endif()

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

if(URING_FOUND)
  target_compile_definitions(samurai_l7emu PUBLIC SAMURAI_WITH_IO_URING=1 SAMURAI_WITH_LIBURING=1)
  target_include_directories(samurai_l7emu PUBLIC ${URING_INCLUDE_DIRS})
  target_link_libraries(samurai_l7emu PUBLIC ${URING_LIBRARIES})
  message(STATUS "liburing found: native io_uring reactor enabled with liburing")
elseif(LINUX_IO_URING_H)
  target_compile_definitions(samurai_l7emu PUBLIC SAMURAI_WITH_IO_URING=1)
  message(STATUS "linux/io_uring.h found: native io_uring reactor enabled via direct kernel ring")
else()
  message(STATUS "io_uring not found: io_uring native reactor disabled (fallback to socket_epoll)")
endif()

add_executable(test_l2l3_astf test_l2l3_astf.cpp)
target_link_libraries(test_l2l3_astf PRIVATE samurai_l7emu samurai_l4 samurai_core pthread dl)

# kernel_socket H1 threaded driver e2e: real localhost HTTP/1.1 server + shards>1.
add_executable(test_kernel_threaded_l7 test_kernel_threaded_l7.cpp)
target_link_libraries(test_kernel_threaded_l7 PRIVATE samurai_l7emu samurai_l4 samurai_core pthread dl)

# kernel_socket H2 threaded driver e2e: real h2c server (test_h2c_server.py) + shards>1.
# The harness starts the Python h2 server and passes its port via H2_TEST_PORT.
add_executable(test_kernel_threaded_h2 test_kernel_threaded_h2.cpp)
target_link_libraries(test_kernel_threaded_h2 PRIVATE samurai_l7emu samurai_l4 samurai_core pthread dl)

# QUIC/H3 threaded driver e2e: real HTTP/3 server (test_h3_server.py, aioquic).
# The harness starts the server and passes its UDP port via H3_TEST_PORT. Runs the
# threaded fan-out and the serial reference and asserts they match.
add_executable(test_kernel_threaded_h3 test_kernel_threaded_h3.cpp)
target_link_libraries(test_kernel_threaded_h3 PRIVATE samurai_l7emu samurai_l4 samurai_core pthread dl)

if(LINUX_IO_URING_H OR URING_FOUND)
  add_executable(test_kernel_threaded_io_uring test_kernel_threaded_io_uring.cpp)
  target_link_libraries(test_kernel_threaded_io_uring PRIVATE samurai_l7emu samurai_l4 samurai_core pthread dl)
endif()

