cmake_minimum_required(VERSION 3.16)
project(samurai_l4 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# samurai_l4 — the L4 User-Space TCP Dataplane core, exposed through the
# clean C FFI (tcp_dp_*).
add_library(
  samurai_l4
  STATIC
  tcp_dataplane_core.cpp
  tcp_dataplane_ffi.cpp
  hw_timestamping.cpp)
target_include_directories(samurai_l4 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# Vendored header-only flat hash map (ankerl::unordered_dense, MIT, v4.4.0).
# PUBLIC because tcp_dataplane_core.hpp includes it in a public type, so every
# consumer of samurai_l4 must see it on their include path.
target_include_directories(samurai_l4 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../third_party)

# af_packet is the custom_tcp wire backend (kernel sockets on commodity NICs).
# Standalone builds of this tree add the subdirectory themselves; guarded so it
# is defined exactly once when the root already added it.
if(NOT TARGET af_packet_static)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../af_packet af_packet)
endif()
target_link_libraries(samurai_l4 PUBLIC af_packet_static)

# Focused, NIC-less verification of the sliding-window TCP sender (multi-outstanding
# + effective window + Reno cwnd). Proves stop-and-wait removal against the real core.
add_executable(test_tcp_sliding_window test_tcp_sliding_window.cpp)
target_link_libraries(test_tcp_sliding_window PRIVATE samurai_l4 pthread)

# TASK-TEST-L2-01: 100,000 active TCP flows & 4-tuple lock shard distribution benchmark
add_executable(test_100k_tcp_flows test_100k_tcp_flows.cpp)
target_link_libraries(test_100k_tcp_flows PRIVATE samurai_l4 pthread)

# TASK-TEST-L2-02: 1,000,000 active TCP flows scale & benchmark
add_executable(test_1m_tcp_flows test_1m_tcp_flows.cpp)
target_link_libraries(test_1m_tcp_flows PRIVATE samurai_l4 pthread)

# Real-wire (netns + veth + AF_PACKET + live Linux kernel TCP listener) verification & benchmark
add_executable(test_tcpdp_veth_wire test_tcpdp_veth_wire.cpp)
target_link_libraries(test_tcpdp_veth_wire PRIVATE samurai_l4 pthread)


