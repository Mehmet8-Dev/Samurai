cmake_minimum_required(VERSION 3.16)
project(samurai_mcp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Modular native C++17 MCP server library (zero Python, zero external MCP SDK).
add_library(
  samurai_mcp_lib
  STATIC
  protocol.cpp
  safety.cpp
  runtime_tools.cpp
  autopilot_tools.cpp
  scenario_tools.cpp
  tool_registry.cpp
)
target_include_directories(samurai_mcp_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(samurai_mcp_lib PUBLIC samurai_core samurai_control samurai_scenario)

# Native stdio MCP server binary (`samurai_mcp`).
add_executable(samurai_mcp main.cpp)
target_link_libraries(samurai_mcp PRIVATE samurai_mcp_lib)

# Native C++17 verification suite (`test_samurai_mcp`).
add_executable(test_samurai_mcp test_samurai_mcp.cpp)
target_link_libraries(test_samurai_mcp PRIVATE samurai_mcp_lib)
add_test(NAME test_samurai_mcp COMMAND test_samurai_mcp)
