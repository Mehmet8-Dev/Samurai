cmake_minimum_required(VERSION 3.16)
project(samurai_mcp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Lightweight MCP setup & doctor library (depends solely on samurai_core).
add_library(
  samurai_mcp_setup
  STATIC
  setup_tools.cpp
)
target_include_directories(samurai_mcp_setup PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(samurai_mcp_setup PUBLIC samurai_core)

# Embed skills/samurai-*/SKILL.md into the binary as zero-dependency fallback.
set(SAMURAI_SKILLS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../skills")
set(SAMURAI_EMBEDDED_SKILLS_HPP "${CMAKE_CURRENT_BINARY_DIR}/embedded_skills.hpp")
set(SAMURAI_SKILL_INPUTS
  "${SAMURAI_SKILLS_ROOT}/samurai-netbench/SKILL.md"
  "${SAMURAI_SKILLS_ROOT}/samurai-cluster-orchestrator/SKILL.md"
  "${SAMURAI_SKILLS_ROOT}/samurai-autopilot-rl/SKILL.md"
  "${SAMURAI_SKILLS_ROOT}/samurai-scenario-author/SKILL.md"
  "${SAMURAI_SKILLS_ROOT}/samurai-hardware-dataplane/SKILL.md"
)
add_custom_command(
  OUTPUT "${SAMURAI_EMBEDDED_SKILLS_HPP}"
  COMMAND "${CMAKE_COMMAND}"
    "-DSKILLS_ROOT=${SAMURAI_SKILLS_ROOT}"
    "-DOUTPUT_HPP=${SAMURAI_EMBEDDED_SKILLS_HPP}"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/generate_embedded_skills.cmake"
  DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/generate_embedded_skills.cmake" ${SAMURAI_SKILL_INPUTS}
  COMMENT "Generating embedded_skills.hpp from skills/*/SKILL.md"
  VERBATIM
)

# Modular native C++17 MCP server library (zero Python, zero external MCP SDK).
add_library(
  samurai_mcp_lib
  STATIC
  protocol.cpp
  safety.cpp
  runtime_tools.cpp
  autopilot_tools.cpp
  scenario_tools.cpp
  cluster_tools.cpp
  discovery_tools.cpp
  tool_registry.cpp
  "${SAMURAI_EMBEDDED_SKILLS_HPP}"
)
target_include_directories(samurai_mcp_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(samurai_mcp_lib PUBLIC samurai_core samurai_control samurai_scenario samurai_mcp_setup)

# Native stdio MCP server binary (`samurai_mcp`).
add_executable(samurai_mcp main.cpp)
target_link_libraries(samurai_mcp PRIVATE samurai_mcp_lib)

# Native C++17 verification suite (`test_samurai_mcp`).
add_executable(test_samurai_mcp test_samurai_mcp.cpp)
target_link_libraries(test_samurai_mcp PRIVATE samurai_mcp_lib)
add_test(NAME test_samurai_mcp COMMAND test_samurai_mcp)
