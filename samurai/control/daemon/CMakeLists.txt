# Native control-plane daemons. Built only when libzmq is available (they use
# the ZMQ transport). samurai_slave additionally compiles the orchestrator
# supervisor to execute dispatched shards against the native worker binaries.

add_executable(samurai_master master_main.cpp)
target_include_directories(samurai_master PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../licensing)
target_link_libraries(samurai_master PRIVATE samurai_control samurai_license)

add_executable(samurai_slave
  slave_main.cpp
  supervisor_shard_runner.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../../orchestrator/supervisor.cpp)
target_include_directories(samurai_slave PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../../orchestrator
  ${CMAKE_CURRENT_SOURCE_DIR}/../../zmq/daemon
  ${LIBZMQ_INCLUDE_DIRS})
target_link_directories(samurai_slave PRIVATE ${LIBZMQ_LIBRARY_DIRS})
target_link_libraries(samurai_slave PRIVATE samurai_control ${LIBZMQ_LIBRARIES})
