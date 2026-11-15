cmake_minimum_required(VERSION 3.16)
project(samurai_optional_backends LANGUAGES C CXX)

# Optional native backend libraries — toolchain-gated builds that produce the
# runtime .so libraries the corresponding ZMQ workers dlopen at runtime:
#
#   libgpu_packet_cuda.so  (nvcc)      -> gpu worker
#   xdp/xdp_sender.so      (libbpf)    -> afxdp worker
#   DOCA backends          (DOCA SDK)  -> doca worker
#
# NOT: DPDK artık burada üretilmez; native çekirdek (dpdk/dpdk_core) doğrudan
# samurai_dpdk_worker'a derlenir (zmq/CMakeLists.txt).
#
# Every backend is conditional on its toolchain being present; when it is not,
# the backend is skipped with a status message. The native workers use the
# pacing_engine_static C library built under zmq/.
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
    file(GLOB _cuda_hdrs CONFIGURE_DEPENDS ${SAMURAI_PKG_DIR}/gpu_packet_cuda/*.cuh ${SAMURAI_PKG_DIR}/gpu_packet_cuda.hpp)
    set(_cuda_out ${SAMURAI_PKG_DIR}/libgpu_packet_cuda.so)
    add_custom_command(
      OUTPUT ${_cuda_out}
      COMMAND ${SAMURAI_NVCC} -std=c++20 -O3 -Xcompiler -fPIC -diag-suppress=177
              -I ${SAMURAI_PKG_DIR}/.. -c ${_cuda_src} -o ${CMAKE_CURRENT_BINARY_DIR}/gpu_packet_cuda.o
      COMMAND ${SAMURAI_NVCC} -shared ${CMAKE_CURRENT_BINARY_DIR}/gpu_packet_cuda.o -ldl -o ${_cuda_out}
      DEPENDS ${_cuda_src} ${_cuda_hdrs}
      COMMENT "Building libgpu_packet_cuda.so (nvcc)"
      VERBATIM)
    add_custom_target(gpu_packet_cuda ALL DEPENDS ${_cuda_out})
    if(TARGET build_test_gpu_telecom_kernels)
      add_dependencies(build_test_gpu_telecom_kernels gpu_packet_cuda)
    endif()
    if(TARGET build_test_dpu_arm_cups_gpu_bridge)
      add_dependencies(build_test_dpu_arm_cups_gpu_bridge gpu_packet_cuda)
    endif()
  else()
    message(STATUS "optional: nvcc/gpu_packet_cuda.cu not found -> skipping libgpu_packet_cuda.so")
  endif()
else()
  message(STATUS "optional: SAMURAI_SKIP_CUDA_BUILD set -> skipping CUDA backend")
endif()

# --- DPDK ------------------------------------------------------------------
# Artık ayrı bir CPython eklentisi (dpdk_pmd_core.so) YOK. DPDK katmanı tek bir
# native çekirdeğe (ddos_samurai/dpdk/dpdk_core.{hpp,cpp}) konsolide edildi ve
# doğrudan samurai_dpdk_worker binary'sine (zmq/CMakeLists.txt) derlenir.
message(STATUS "optional: DPDK native core, samurai_dpdk_worker ile birlikte derlenir (bkz. zmq/CMakeLists.txt)")

# --- AF_XDP: xdp/xdp_sender.so (libbpf/libxdp) ----------------------------
set(_xdp_src ${SAMURAI_PKG_DIR}/xdp/xdp_sender.c)
if(EXISTS ${_xdp_src})
  set(_have_xsk 0)
  if(PkgConfig_FOUND)
    pkg_check_modules(LIBXDP QUIET libxdp)
    pkg_check_modules(LIBBPF QUIET libbpf)
  endif()
  find_package(Python3 COMPONENTS Interpreter Development QUIET)
  if((LIBXDP_FOUND OR LIBBPF_FOUND) AND Python3_Development_FOUND)
    add_library(xdp_sender SHARED ${_xdp_src}
      ${SAMURAI_PKG_DIR}/xdp/xdp_core.c)
    set_target_properties(xdp_sender PROPERTIES
      LIBRARY_OUTPUT_DIRECTORY ${SAMURAI_PKG_DIR}/xdp PREFIX "" OUTPUT_NAME "xdp_sender")
    target_include_directories(xdp_sender PRIVATE
      ${SAMURAI_PKG_DIR}
      ${SAMURAI_PKG_DIR}/xdp
      ${LIBXDP_INCLUDE_DIRS}
      ${LIBBPF_INCLUDE_DIRS}
      ${Python3_INCLUDE_DIRS})
    target_link_libraries(xdp_sender PRIVATE
      ${LIBXDP_LIBRARIES}
      ${LIBBPF_LIBRARIES}
      Python3::Python
      pthread m)
  else()
    message(STATUS "optional: libbpf/libxdp or Python3 development headers not found -> skipping xdp/xdp_sender.so")
  endif()
else()
  message(STATUS "optional: xdp/xdp_sender.c not found -> skipping xdp_sender.so")
endif()

# --- DOCA GPUNetIO / Flow backends (DOCA SDK) -----------------------------
# The DOCA backends require the Mellanox DOCA SDK + nvcc device build and are
# only produced where that SDK is installed (SAMURAI_WITH_DOCA_GPUNETIO_DEVICE);
# left as a toolchain-gated build, off by default.
if(DEFINED ENV{SAMURAI_WITH_DOCA_GPUNETIO_DEVICE})
  message(STATUS "optional: DOCA GPUNetIO requested -> requires DOCA SDK + nvcc (built out-of-tree)")
else()
  message(STATUS "optional: DOCA backends not requested -> skipping")
endif()
