cmake_minimum_required(VERSION 3.16)
project(samurai_control LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(LIBZMQ QUIET libzmq)
endif()

# samurai_control — native control-plane layer, the C++ replacement for the
# Python ddos_samurai/control package.
#   shard.*         -> split_job_to_shards (equal/capability/region)
#   auth.*          -> endpoint parsing, cluster-secret metadata, RBAC resolution
#   autoscale.*     -> the K8s autoscale decision state machine (in-memory mode)
#   discovery.*     -> manual endpoint discovery
#   jwt.*           -> HS256 JWT decode/verify + encode (OpenSSL HMAC-SHA256)
#   telemetry.*     -> DistributedAggregator (per-shard/worker/region rollups)
#   multimaster.*   -> cross-region coordinator over a KvStore backend
#   control_auth.*  -> server-side RBAC/secret/JWT authorization (interceptor)
#   servicer.*      -> master control service (worker registry + 8 RPCs)
#   worker_shard_service.* -> slave-side shard lifecycle service (StartShard/
#                    StopShard/GetWorkerStatus + leader-epoch fencing)
#   master_coordinator.*   -> master job dispatch state machine (_run_single_job)
#   ha.*            -> leader election: static + file-lease electors (redis/etcd/
#                    raft electors deferred)
#   audit_log.*     -> RBAC audit chain (SHA256 hash-chained, tamper-evident)
#   management_api.* -> HTTP management server (REST endpoints + auth; POSIX
#                    sockets, no framework); SSE/WS streams deferred
#   control_server/client.* -> ZMQ transport (built only when libzmq is present)
#
# Remaining networked pieces (register/heartbeat loops, redis/etcd/raft electors,
# management_api, arg-wired entrypoints) land in a later increment.
set(CONTROL_SOURCES
  shard.cpp
  auth.cpp
  autoscale.cpp
  discovery.cpp
  jwt.cpp
  telemetry.cpp
  multimaster.cpp
  control_auth.cpp
  servicer.cpp
  worker_shard_service.cpp
  master_coordinator.cpp
  ha.cpp
  audit_log.cpp
  management_api.cpp)

if(LIBZMQ_FOUND)
  list(APPEND CONTROL_SOURCES
    control_server.cpp
    control_client.cpp
    curve.cpp             # CURVE transport-encryption helpers (opt-in)
    master_adapters.cpp   # Servicer->MasterView + WorkerControlClient->WorkerCommander
    slave_node.cpp)       # register/heartbeat orchestration loop
else()
  message(WARNING "libzmq not found: native control ZMQ transport will not be built.")
endif()

add_library(samurai_control STATIC ${CONTROL_SOURCES})
target_include_directories(samurai_control PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# Header-only worker catalog (worker_registry.hpp -> wire_protocol.h) so the
# management API can enumerate worker binaries for the bundle agent manifest.
target_include_directories(samurai_control PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../orchestrator
  ${CMAKE_CURRENT_SOURCE_DIR}/../zmq/daemon)
target_link_libraries(samurai_control PUBLIC samurai_core Threads::Threads PRIVATE OpenSSL::Crypto OpenSSL::SSL)

if(LIBZMQ_FOUND)
  target_include_directories(samurai_control PRIVATE ${LIBZMQ_INCLUDE_DIRS})
  target_link_directories(samurai_control PUBLIC ${LIBZMQ_LIBRARY_DIRS})
  target_link_libraries(samurai_control PUBLIC ${LIBZMQ_LIBRARIES})
  target_compile_options(samurai_control PRIVATE ${LIBZMQ_CFLAGS_OTHER})
  target_compile_definitions(samurai_control PUBLIC SAMURAI_CONTROL_HAVE_ZMQ=1)
endif()

# Self-test driver: verifies the ported logic matches the Python contract.
add_executable(samurai_control_selftest selftest.cpp)
target_link_libraries(samurai_control_selftest PRIVATE samurai_control)

# Native control daemons (samurai_master / samurai_slave) — need the ZMQ transport.
if(LIBZMQ_FOUND)
  add_subdirectory(daemon)
endif()
