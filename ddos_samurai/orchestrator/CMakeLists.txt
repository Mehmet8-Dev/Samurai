cmake_minimum_required(VERSION 3.16)
project(samurai_orchestrator LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(LIBZMQ QUIET libzmq)
endif()

if(NOT LIBZMQ_FOUND)
  message(WARNING "libzmq not found: native samurai orchestrator will not be built.")
  return()
endif()

# Native orchestrator / CLI front-end. Spawns and drives the compiled worker
# binaries (built by ../zmq/CMakeLists.txt) over the shared ZMQ wire protocol.
add_executable(
  samurai
  main.cpp
  supervisor.cpp
  cli/cli_parser.cpp
  cli/cli_validate.cpp
)
target_include_directories(
  samurai
  PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../zmq/daemon
  ${LIBZMQ_INCLUDE_DIRS})
target_link_directories(samurai PRIVATE ${LIBZMQ_LIBRARY_DIRS})
target_link_libraries(samurai PRIVATE ${LIBZMQ_LIBRARIES} pthread)
target_compile_options(samurai PRIVATE ${LIBZMQ_CFLAGS_OTHER})
