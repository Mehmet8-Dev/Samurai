cmake_minimum_required(VERSION 3.16)
project(samurai_optional_backends LANGUAGES C CXX)

# Optional native backend libraries — the CMake replacement for the toolchain-
# gated builds that used to live in setup.py (OptionalBuildExt). These produce
# the runtime .so libraries the corresponding ZMQ workers dlopen at runtime:
#
#   libgpu_packet_cuda.so  (nvcc)      -> gpu worker
#   dpdk_pmd_core.so       (libdpdk)   -> dpdk worker
#   xdp/xdp_sender.so      (libbpf)    -> afxdp worker
#   DOCA backends          (DOCA SDK)  -> doca worker
#
# Every backend is conditional on its toolchain being present; when it is not,
# the backend is skipped with a status message (exactly as setup.py did). The
# legacy pybind `pacing_engine` Python extension is intentionally NOT ported —
# pybind is legacy and the native workers use the pacing_engine_static C library
# built under zmq/.
#
# Outputs are written into the source tree next to where the workers look for
# them via dlopen.

set(SAMURAI_PKG_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)  # ddos_samurai/
find_package(PkgConfig QUIET)

# --- CUDA: libgpu_packet_cuda.so (nvcc) -----------------------------------
if(NOT DEFINED ENV{SAMURAI_SKIP_CUDA_BUILD})
  find_program(SAMURAI_NVCC nvcc HINTS ENV SAMURAI_NVCC /usr/local/cuda/bin)
  set(_cuda_src ${SAMURAI_PKG_DIR}/gpu_packet_cuda.cu)
  if(SAMURAI_NVCC AND EXISTS ${_cuda_src})
    set(_cuda_out ${SAMURAI_PKG_DIR}/libgpu_packet_cuda.so)
    add_custom_command(
      OUTPUT ${_cuda_out}
      COMMAND ${SAMURAI_NVCC} -std=c++20 -O3 -Xcompiler -fPIC -diag-suppress=177
              -I ${SAMURAI_PKG_DIR}/.. -c ${_cuda_src} -o ${CMAKE_CURRENT_BINARY_DIR}/gpu_packet_cuda.o
      COMMAND ${SAMURAI_NVCC} -shared ${CMAKE_CURRENT_BINARY_DIR}/gpu_packet_cuda.o -ldl -o ${_cuda_out}
      DEPENDS ${_cuda_src}
      COMMENT "Building libgpu_packet_cuda.so (nvcc)"
      VERBATIM)
    add_custom_target(gpu_packet_cuda ALL DEPENDS ${_cuda_out})
  else()
    message(STATUS "optional: nvcc/gpu_packet_cuda.cu not found -> skipping libgpu_packet_cuda.so")
  endif()
else()
  message(STATUS "optional: SAMURAI_SKIP_CUDA_BUILD set -> skipping CUDA backend")
endif()

# --- DPDK: dpdk_pmd_core.so (libdpdk) -------------------------------------
set(_dpdk_src ${SAMURAI_PKG_DIR}/dpdk/dpdk_pmd_core.cpp)
if(DEFINED ENV{SAMURAI_WITH_DPDK} AND EXISTS ${_dpdk_src})
  if(PkgConfig_FOUND)
    pkg_check_modules(DPDK QUIET libdpdk)
  endif()
  if(DPDK_FOUND)
    add_library(dpdk_pmd_core SHARED ${_dpdk_src})
    set_target_properties(dpdk_pmd_core PROPERTIES
      LIBRARY_OUTPUT_DIRECTORY ${SAMURAI_PKG_DIR} PREFIX "" OUTPUT_NAME "dpdk_pmd_core")
    target_compile_features(dpdk_pmd_core PRIVATE cxx_std_17)
    target_include_directories(dpdk_pmd_core PRIVATE ${DPDK_INCLUDE_DIRS})
    target_link_libraries(dpdk_pmd_core PRIVATE ${DPDK_LIBRARIES} pthread m)
  else()
    message(STATUS "optional: SAMURAI_WITH_DPDK set but libdpdk not found -> skipping dpdk_pmd_core")
  endif()
else()
  message(STATUS "optional: DPDK not requested/unavailable -> skipping dpdk_pmd_core")
endif()

# --- AF_XDP: xdp/xdp_sender.so (libbpf/libxdp) ----------------------------
set(_xdp_src ${SAMURAI_PKG_DIR}/xdp/xdp_sender.c)
if(EXISTS ${_xdp_src})
  set(_have_xsk 0)
  if(PkgConfig_FOUND)
    pkg_check_modules(LIBXDP QUIET libxdp)
    pkg_check_modules(LIBBPF QUIET libbpf)
  endif()
  if(LIBXDP_FOUND OR LIBBPF_FOUND)
    add_library(xdp_sender SHARED ${_xdp_src}
      ${SAMURAI_PKG_DIR}/xdp/xdp_core.c ${SAMURAI_PKG_DIR}/pacing_engine.c)
    set_target_properties(xdp_sender PROPERTIES
      LIBRARY_OUTPUT_DIRECTORY ${SAMURAI_PKG_DIR}/xdp PREFIX "" OUTPUT_NAME "xdp_sender")
    target_include_directories(xdp_sender PRIVATE ${LIBXDP_INCLUDE_DIRS} ${LIBBPF_INCLUDE_DIRS})
    target_link_libraries(xdp_sender PRIVATE ${LIBXDP_LIBRARIES} ${LIBBPF_LIBRARIES} pthread m)
  else()
    message(STATUS "optional: libbpf/libxdp not found -> skipping xdp/xdp_sender.so")
  endif()
else()
  message(STATUS "optional: xdp/xdp_sender.c not found -> skipping xdp_sender.so")
endif()

# --- DOCA GPUNetIO / Flow backends (DOCA SDK) -----------------------------
# The DOCA backends require the Mellanox DOCA SDK + nvcc device build and are
# only produced where that SDK is installed (SAMURAI_WITH_DOCA_GPUNETIO_DEVICE);
# left as a toolchain-gated build, off by default (as in setup.py).
if(DEFINED ENV{SAMURAI_WITH_DOCA_GPUNETIO_DEVICE})
  message(STATUS "optional: DOCA GPUNetIO requested -> requires DOCA SDK + nvcc (built out-of-tree)")
else()
  message(STATUS "optional: DOCA backends not requested -> skipping")
endif()
