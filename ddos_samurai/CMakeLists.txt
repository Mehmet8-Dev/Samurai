cmake_minimum_required(VERSION 3.16)
project(samurai_native LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the build type" FORCE)
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
add_subdirectory(licensing)
add_subdirectory(scenario_engine_native)
add_subdirectory(af_packet)  # before l4: samurai_l4 uses it as the custom_tcp wire backend
add_subdirectory(l4)
add_subdirectory(l7_emu_native)
add_subdirectory(telecom)
set(SAMURAI_ENGINES_OWNED_BY_ROOT ON)
add_subdirectory(zmq)
add_subdirectory(cli)
# Toolchain-gated optional backends (CUDA/DPDK/AF_XDP/DOCA); each skips cleanly
# when its toolchain is absent.
add_subdirectory(optional)
