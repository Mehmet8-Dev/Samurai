cmake_minimum_required(VERSION 3.16)
project(samurai_native LANGUAGES C CXX)

# Native build tree for Samurai:
#   core/         -> shared native utility layer (logging, net helpers, target
#                    safety)
#   control/      -> native control-plane layer (shard/auth/autoscale/discovery
#                    so far)
#   zmq/          -> the ZMQ worker daemons (samurai_*_worker)
#   orchestrator/ -> the native orchestrator engine (worker registry, job
#                    builder, ZMQ supervisor); header + supervisor.cpp, compiled
#                    into the CLI target
#   cli/          -> the native CLI front-end (`samurai`)
#
# This tree builds the full native worker + orchestrator + CLI layer.
add_subdirectory(core)
add_subdirectory(control)
add_subdirectory(licensing)
add_subdirectory(scenario_engine_native)
add_subdirectory(af_packet)  # before l4: samurai_l4 uses it as the custom_tcp wire backend
add_subdirectory(l4)
add_subdirectory(l7_emu_native)
set(SAMURAI_ENGINES_OWNED_BY_ROOT ON)
add_subdirectory(zmq)
add_subdirectory(cli)
# Toolchain-gated optional backends (CUDA/DPDK/AF_XDP/DOCA); each skips cleanly
# when its toolchain is absent.
add_subdirectory(optional)
