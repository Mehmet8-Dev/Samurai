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
  ../cpu_native/amp.cpp
  ../cpu_native/common.cpp
  ../cpu_native/packets.cpp
  ../cpu_native/pool.cpp
  ../cpu_native/spoofing.cpp
)
target_include_directories(cpu_native_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../cpu_native)

function(add_samurai_worker target_name source_file)
  add_executable(${target_name} ${source_file})
  target_include_directories(${target_name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/daemon ${CMAKE_CURRENT_SOURCE_DIR}/lib ${CMAKE_CURRENT_SOURCE_DIR}/../cpu_native ${LIBZMQ_INCLUDE_DIRS})
  target_link_directories(${target_name} PRIVATE ${LIBZMQ_LIBRARY_DIRS})
  target_link_libraries(${target_name} PRIVATE ${LIBZMQ_LIBRARIES})
  target_compile_options(${target_name} PRIVATE ${LIBZMQ_CFLAGS_OTHER})
endfunction()

add_samurai_worker(samurai_cpu_worker daemon/cpu_worker.cpp)
target_link_libraries(samurai_cpu_worker PRIVATE pacing_engine_static cpu_native_static pthread)
add_samurai_worker(samurai_gpu_worker daemon/gpu_worker.cpp)
target_link_libraries(samurai_gpu_worker PRIVATE pacing_engine_static pthread dl)
add_samurai_worker(samurai_dpdk_worker daemon/dpdk_worker.cpp)
target_link_libraries(samurai_dpdk_worker PRIVATE pacing_engine_static cpu_native_static pthread)
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
target_link_libraries(samurai_afxdp_worker PRIVATE pacing_engine_static cpu_native_static pthread dl)
add_samurai_worker(samurai_doca_worker daemon/doca_gpunetio_worker.cpp)
target_link_libraries(samurai_doca_worker PRIVATE pacing_engine_static cpu_native_static pthread dl)
add_samurai_worker(samurai_l7_worker daemon/l7_worker.cpp)
target_link_libraries(samurai_l7_worker PRIVATE pacing_engine_static samurai_l7emu pthread)
add_samurai_worker(samurai_defense_worker daemon/defense_worker.cpp)
target_link_libraries(samurai_defense_worker PRIVATE pacing_engine_static cpu_native_static pthread dl)
add_samurai_worker(samurai_scenario_worker daemon/scenario_worker.cpp)
target_link_libraries(samurai_scenario_worker PRIVATE pacing_engine_static cpu_native_static samurai_scenario pthread)
