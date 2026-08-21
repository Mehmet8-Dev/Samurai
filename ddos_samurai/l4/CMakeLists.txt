cmake_minimum_required(VERSION 3.16)
project(samurai_l4 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# samurai_l4 — the L4 TCP state engine + dataplane core, exposed through the
# clean C FFI (l4se_* / tcp_dp_*). The legacy pybind module (state_engine_module.cpp)
# is gone; ZMQ workers link this static library directly.
add_library(
  samurai_l4
  STATIC
  l4_state_engine_core.cpp
  l4_state_engine_ffi.cpp
  tcp_dataplane_core.cpp
  tcp_dataplane_ffi.cpp
  hw_timestamping.cpp)
target_include_directories(samurai_l4 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# af_packet is the custom_tcp wire backend (kernel sockets on commodity NICs).
# Standalone builds of this tree add the subdirectory themselves; guarded so it
# is defined exactly once when the root already added it.
if(NOT TARGET af_packet_static)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../af_packet af_packet)
endif()
target_link_libraries(samurai_l4 PUBLIC af_packet_static)
