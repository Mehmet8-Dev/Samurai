cmake_minimum_required(VERSION 3.16)
project(samurai_core LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# samurai_core — shared native utility layer, generic helpers plus shared JSON:
#   log.*           -> log_info/log_warning/log_error/log_critical + timestamp
#   net_utils.*     -> get_local_ip / get_gateway_mac / mac_to_int
#   target_safety.* -> validate_target_safety (allow/deny lists, public gate)
#   json.*          -> minimal JSON value/parser/serializer for the control plane
#
# Consumed by the CLI/orchestrator, control and licensing layers.
add_library(
  samurai_core
  STATIC
  log.cpp
  net_utils.cpp
  target_safety.cpp
  json.cpp)
target_include_directories(samurai_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
