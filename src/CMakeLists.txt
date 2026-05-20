cmake_minimum_required(VERSION 3.16)
project(samurai_workers LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(PkgConfig QUIET)
if(NOT PkgConfig_FOUND)
  message(FATAL_ERROR "pkg-config is required to find libzmq")
endif()

pkg_check_modules(LIBZMQ REQUIRED libzmq)

add_executable(samurai_cpu_worker daemon/cpu_worker.cpp)
target_include_directories(samurai_cpu_worker PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/daemon ${LIBZMQ_INCLUDE_DIRS})
target_link_directories(samurai_cpu_worker PRIVATE ${LIBZMQ_LIBRARY_DIRS})
target_link_libraries(samurai_cpu_worker PRIVATE ${LIBZMQ_LIBRARIES})
target_compile_options(samurai_cpu_worker PRIVATE ${LIBZMQ_CFLAGS_OTHER})
