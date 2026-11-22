cmake_minimum_required(VERSION 3.16)
project(samurai_native LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the build type" FORCE)
endif()

option(SAMURAI_NATIVE_ARCH "Optimize native binaries for the target host CPU (-march=native)" OFF)
if(SAMURAI_NATIVE_ARCH)
  include(CheckCXXCompilerFlag)
  include(CheckCCompilerFlag)
  check_cxx_compiler_flag("-march=native" SAMURAI_CXX_HAS_MARCH_NATIVE)
  check_c_compiler_flag("-march=native" SAMURAI_C_HAS_MARCH_NATIVE)
  if(SAMURAI_CXX_HAS_MARCH_NATIVE)
    add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-march=native> $<$<COMPILE_LANGUAGE:CXX>:-mtune=native>)
  endif()
  if(SAMURAI_C_HAS_MARCH_NATIVE)
    add_compile_options($<$<COMPILE_LANGUAGE:C>:-march=native> $<$<COMPILE_LANGUAGE:C>:-mtune=native>)
  endif()
  message(STATUS "Samurai target tuning: SAMURAI_NATIVE_ARCH=ON (-march=native enabled=${SAMURAI_CXX_HAS_MARCH_NATIVE})")
else()
  message(STATUS "Samurai target tuning: portable release (pass -DSAMURAI_NATIVE_ARCH=ON to optimize for this CPU)")
endif()

# Exploit mitigation & binary hardening flags
add_compile_options(
  -fvisibility=hidden
  -fvisibility-inlines-hidden
  -fstack-protector-strong
  $<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=2>
)

add_link_options(
  -Wl,-z,relro,-z,now
  $<$<CONFIG:Release>:-s>
)

enable_testing()

# This tree builds the full native worker + orchestrator + CLI layer.
add_subdirectory(core)
add_subdirectory(control)
add_subdirectory(scenario_engine_native)
add_subdirectory(af_packet)  # before l4: samurai_l4 uses it as the custom_tcp wire backend
add_subdirectory(l4)
add_subdirectory(l7_emu_native)
add_subdirectory(telecom)
add_subdirectory(telemetry)
set(SAMURAI_ENGINES_OWNED_BY_ROOT ON)
add_subdirectory(zmq)
add_subdirectory(mcp)
add_subdirectory(cli)
# Toolchain-gated optional backends (CUDA/DPDK/AF_XDP/DOCA); each skips cleanly
# when its toolchain is absent.
add_subdirectory(optional)
