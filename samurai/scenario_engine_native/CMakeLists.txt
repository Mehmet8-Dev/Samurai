cmake_minimum_required(VERSION 3.16)
project(samurai_scenario LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# samurai_scenario — the scenario engine native kernels (spec parse + flow
# compiler + worker scheduler + SLA evaluator). Plain C++ now: the pybind facade
# is gone and the ZMQ scenario worker consumes the JSON API directly.
add_library(
  samurai_scenario
  STATIC
  compiler.cpp
  scheduler.cpp
  sla.cpp)
target_include_directories(samurai_scenario PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(samurai_scenario PUBLIC samurai_core)
