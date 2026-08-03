cmake_minimum_required(VERSION 3.16)
project(samurai_control LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# samurai_control — native control-plane layer, the C++ replacement for the
# Python ddos_samurai/control package. Increment 1 covers the transport-agnostic
# pure logic:
#   shard.*     -> split_job_to_shards (equal/capability/region)
#   auth.*      -> endpoint parsing, cluster-secret metadata, RBAC resolution
#   autoscale.* -> the K8s autoscale decision state machine (in-memory mode)
#   discovery.* -> manual endpoint discovery
#
# Networked modules (client/server/slave/master/ha/management_api/multimaster)
# and JWT/telemetry are ported in later increments, using the ZMQ transport that
# the workers already speak.
add_library(
  samurai_control
  STATIC
  shard.cpp
  auth.cpp
  autoscale.cpp
  discovery.cpp)
target_include_directories(samurai_control PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(samurai_control PUBLIC samurai_core)

# Self-test driver: verifies the ported logic matches the Python contract.
add_executable(samurai_control_selftest selftest.cpp)
target_link_libraries(samurai_control_selftest PRIVATE samurai_control)
