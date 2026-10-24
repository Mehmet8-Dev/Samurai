cmake_minimum_required(VERSION 3.16)
project(samurai_workers LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(LIBZMQ QUIET libzmq)
  pkg_check_modules(DPDK QUIET libdpdk)
endif()

if(NOT LIBZMQ_FOUND)
  message(WARNING "libzmq not found: C++ worker binaries will not be built in this environment.")
  return()
endif()

# Native engine libraries consumed by the workers. They no longer ship as
# pybind extensions; the ZMQ daemons link them directly as static libs.
# When this file is configured as part of the root samurai_native tree, the
# engines are already owned by that tree (core/l4/l7_emu/scenario are added
# at the top level); only the standalone zmq build pulls them in here.
if(NOT SAMURAI_ENGINES_OWNED_BY_ROOT)
  add_subdirectory(../core core)
  add_subdirectory(../scenario_engine_native scenario_engine_native)
  add_subdirectory(../l4 l4)
  add_subdirectory(../l7_emu_native l7_emu_native)
endif()

add_library(
  pacing_engine_static
  STATIC
  lib/pacing_engine.c
)
target_include_directories(pacing_engine_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/lib)

add_library(
  cpu_native_static
  STATIC
  ../cpu_native/engine.cpp
  ../cpu_native/amp.cpp
  ../cpu_native/packets.cpp
  ../cpu_native/pool.cpp
  ../cpu_native/spoofing.cpp
)
target_include_directories(cpu_native_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../cpu_native)

# Kernel-socket TX/RX engine (commodity NICs, no AF_XDP/DPDK). Pure C, no Python.
# Shared single target: the root tree already added it (before l4, which links it
# as the custom_tcp wire backend); a standalone zmq build adds it here.
if(NOT TARGET af_packet_static)
  add_subdirectory(../af_packet af_packet)
endif()

function(add_samurai_worker target_name source_file)
  add_executable(${target_name} ${source_file})
  target_include_directories(${target_name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/daemon ${CMAKE_CURRENT_SOURCE_DIR}/lib ${CMAKE_CURRENT_SOURCE_DIR}/.. ${CMAKE_CURRENT_SOURCE_DIR}/../core ${CMAKE_CURRENT_SOURCE_DIR}/../cpu_native ${CMAKE_CURRENT_SOURCE_DIR}/../l7_emu_native ${LIBZMQ_INCLUDE_DIRS})
  target_link_directories(${target_name} PRIVATE ${LIBZMQ_LIBRARY_DIRS})
  target_link_libraries(${target_name} PRIVATE ${LIBZMQ_LIBRARIES} samurai_core)
  target_compile_options(${target_name} PRIVATE ${LIBZMQ_CFLAGS_OTHER})
endfunction()

add_samurai_worker(samurai_cpu_worker daemon/cpu_worker.cpp)
target_include_directories(samurai_cpu_worker PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../af_packet)
target_link_libraries(samurai_cpu_worker PRIVATE pacing_engine_static cpu_native_static af_packet_static pthread)
add_samurai_worker(samurai_gpu_worker daemon/gpu_worker.cpp)
# Link the af_packet engine so the CUDA host path's weak AF_PACKET TX_RING
# bridge symbols (afpkt_send_ring_bridge/afpkt_cleanup_ring_bridge) resolve.
target_include_directories(samurai_gpu_worker PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../af_packet)
target_link_libraries(samurai_gpu_worker PRIVATE pacing_engine_static af_packet_static pthread dl)
add_samurai_worker(samurai_dpdk_worker daemon/dpdk_worker.cpp)
# Tek native DPDK çekirdeği (dpdk/dpdk_core) artık samurai_l7emu içinde konsolide
# derlenir ve SAMURAI_WITH_DPDK + DPDK link bayrakları PUBLIC yayılır; worker onu
# transitif link'ler (burada ayrıca derlemek çift-sembol yaratırdı).
# Paylaşılan userspace stateful TCP fast-path sürücüsü (rte/xdp header'ı içermez).
target_sources(samurai_dpdk_worker PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/daemon/stateful_fastpath.cpp)
target_include_directories(samurai_dpdk_worker PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../dpdk)
target_link_libraries(samurai_dpdk_worker PRIVATE pacing_engine_static cpu_native_static samurai_l7emu pthread dl)
if(DPDK_FOUND)
  target_compile_definitions(samurai_dpdk_worker PRIVATE SAMURAI_WITH_DPDK=1)
  target_include_directories(samurai_dpdk_worker PRIVATE ${DPDK_INCLUDE_DIRS})
  target_link_directories(samurai_dpdk_worker PRIVATE ${DPDK_LIBRARY_DIRS})
  target_link_libraries(samurai_dpdk_worker PRIVATE ${DPDK_LIBRARIES})
  target_compile_options(samurai_dpdk_worker PRIVATE ${DPDK_CFLAGS_OTHER})
  target_link_options(samurai_dpdk_worker PRIVATE ${DPDK_LDFLAGS_OTHER})
else()
  message(STATUS "libdpdk not found: samurai_dpdk_worker will build without native DPDK path.")
endif()
add_samurai_worker(samurai_afxdp_worker daemon/afxdp_worker.cpp)
target_sources(samurai_afxdp_worker PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/daemon/stateful_fastpath.cpp)
target_link_libraries(samurai_afxdp_worker PRIVATE pacing_engine_static cpu_native_static samurai_l7emu pthread dl)
add_samurai_worker(samurai_doca_worker daemon/doca_gpunetio_worker.cpp)
target_link_libraries(samurai_doca_worker PRIVATE pacing_engine_static cpu_native_static pthread dl)
add_samurai_worker(samurai_l7_worker daemon/l7_worker.cpp)
target_link_libraries(samurai_l7_worker PRIVATE pacing_engine_static samurai_l7emu pthread)
add_samurai_worker(samurai_defense_worker daemon/defense_worker.cpp)
target_link_libraries(samurai_defense_worker PRIVATE pacing_engine_static cpu_native_static pthread dl)
add_samurai_worker(samurai_scenario_worker daemon/scenario_worker.cpp)
target_include_directories(samurai_scenario_worker PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../af_packet ${CMAKE_CURRENT_SOURCE_DIR}/../dpdk)
# Opt-in DPDK: senaryo load_model.transport="dpdk_direct" için dpdk_worker ile AYNI
# native çekirdek + paylaşılan stateful fast-path sürücüsü. Header'lar rte/xdp içermez;
# libdpdk yokken kaynak SAMURAI_WITH_DPDK ile güvenli saplama derler ve worker
# kernel_socket'e düşer (varsayılan commodity yol değişmez). dpdk_core artık
# samurai_l7emu içinde konsolide (bkz. l7_emu_native/CMakeLists.txt); transitif link'lenir.
target_sources(samurai_scenario_worker PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/daemon/stateful_fastpath.cpp)
target_link_libraries(samurai_scenario_worker PRIVATE pacing_engine_static cpu_native_static af_packet_static samurai_scenario samurai_l7emu pthread)
if(DPDK_FOUND)
  target_compile_definitions(samurai_scenario_worker PRIVATE SAMURAI_WITH_DPDK=1)
  target_include_directories(samurai_scenario_worker PRIVATE ${DPDK_INCLUDE_DIRS})
  target_link_directories(samurai_scenario_worker PRIVATE ${DPDK_LIBRARY_DIRS})
  target_link_libraries(samurai_scenario_worker PRIVATE ${DPDK_LIBRARIES})
  target_compile_options(samurai_scenario_worker PRIVATE ${DPDK_CFLAGS_OTHER})
  target_link_options(samurai_scenario_worker PRIVATE ${DPDK_LDFLAGS_OTHER})
endif()
add_samurai_worker(samurai_afpacket_worker daemon/afpacket_worker.cpp)
target_include_directories(samurai_afpacket_worker PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../af_packet)
target_link_libraries(samurai_afpacket_worker PRIVATE pacing_engine_static cpu_native_static af_packet_static pthread)

# Paylaşılan stateful fast-path sürücüsünün in-process (NIC'siz) doğrulama testi.
add_executable(test_stateful_fastpath
  ${CMAKE_CURRENT_SOURCE_DIR}/daemon/test_stateful_fastpath.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/daemon/stateful_fastpath.cpp)
target_include_directories(test_stateful_fastpath PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/daemon ${CMAKE_CURRENT_SOURCE_DIR}/lib ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(test_stateful_fastpath PRIVATE pacing_engine_static samurai_l4 pthread)

# Shared-nothing çok-çekirdek stateful fast-path (ShardedFastpathDriver) doğrulaması.
add_executable(test_sharded_fastpath
  ${CMAKE_CURRENT_SOURCE_DIR}/daemon/test_sharded_fastpath.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/daemon/stateful_fastpath.cpp)
target_include_directories(test_sharded_fastpath PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/daemon ${CMAKE_CURRENT_SOURCE_DIR}/lib ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(test_sharded_fastpath PRIVATE pacing_engine_static samurai_l4 pthread)

# Shared-nothing custom_tcp own-wire (per-shard AF_PACKET) e2e doğrulaması.
# Namespace+veth harness (run_customtcp_ownwire_veth.sh) ile koşar; env yoksa skip.
add_executable(test_customtcp_ownwire_l7
  ${CMAKE_CURRENT_SOURCE_DIR}/daemon/test_customtcp_ownwire_l7.cpp)
target_include_directories(test_customtcp_ownwire_l7 PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/daemon ${CMAKE_CURRENT_SOURCE_DIR}/lib
  ${CMAKE_CURRENT_SOURCE_DIR}/.. ${CMAKE_CURRENT_SOURCE_DIR}/../core
  ${CMAKE_CURRENT_SOURCE_DIR}/../l7_emu_native)
target_link_libraries(test_customtcp_ownwire_l7 PRIVATE pacing_engine_static samurai_l7emu samurai_core pthread)

# Faz 2: gerçek run_profile_json (dpdk_direct) L7 akışını sürücü üzerinden doğrular.
add_executable(test_stateful_fastpath_l7
  ${CMAKE_CURRENT_SOURCE_DIR}/daemon/test_stateful_fastpath_l7.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/daemon/stateful_fastpath.cpp)
target_include_directories(test_stateful_fastpath_l7 PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/daemon ${CMAKE_CURRENT_SOURCE_DIR}/lib
  ${CMAKE_CURRENT_SOURCE_DIR}/.. ${CMAKE_CURRENT_SOURCE_DIR}/../core
  ${CMAKE_CURRENT_SOURCE_DIR}/../l7_emu_native)
target_link_libraries(test_stateful_fastpath_l7 PRIVATE pacing_engine_static samurai_l7emu samurai_core pthread)

add_executable(bench_l7_stateful_userspace
  ${CMAKE_CURRENT_SOURCE_DIR}/daemon/bench_l7_stateful_userspace.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/daemon/stateful_fastpath.cpp)
target_include_directories(bench_l7_stateful_userspace PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/daemon ${CMAKE_CURRENT_SOURCE_DIR}/lib
  ${CMAKE_CURRENT_SOURCE_DIR}/.. ${CMAKE_CURRENT_SOURCE_DIR}/../core
  ${CMAKE_CURRENT_SOURCE_DIR}/../l7_emu_native)
target_link_libraries(bench_l7_stateful_userspace PRIVATE pacing_engine_static samurai_l7emu samurai_core samurai_l4 pthread dl)

