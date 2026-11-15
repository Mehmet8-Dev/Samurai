cmake_minimum_required(VERSION 3.16)
project(samurai_af_packet LANGUAGES C)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# af_packet — native kernel-socket TX/RX engine (commodity NICs; no AF_XDP/DPDK).
# Pure C, no external deps. Consumed by the ZMQ afpacket/gpu workers and, as the
# custom_tcp wire backend, by samurai_l4. Guard the target so multiple consumers
# can each add this subdirectory without a duplicate-target error.
if(NOT TARGET af_packet_static)
  add_library(af_packet_static STATIC af_packet.c)
  target_include_directories(af_packet_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
endif()
