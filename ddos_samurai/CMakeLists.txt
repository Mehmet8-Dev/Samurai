cmake_minimum_required(VERSION 3.16)
project(samurai_native LANGUAGES C CXX)

# Native build tree for Samurai:
#   core/         -> shared native utility layer (logging, net helpers, target
#                    safety); the C++ replacement for ddos_samurai/utils.py
#   zmq/          -> the ZMQ worker daemons (samurai_*_worker)
#   orchestrator/ -> the native orchestrator engine (worker registry, job
#                    builder, ZMQ supervisor); header + supervisor.cpp, compiled
#                    into the CLI target
#   cli/          -> the native CLI front-end (`samurai`), replacing the former
#                    Python ddos_samurai/cli package
#
# Python C-extensions are still built separately via setup.py; this tree covers
# the native worker + orchestrator + CLI layer that replaces the Python
# launcher/orchestrator/CLI path.
add_subdirectory(core)
add_subdirectory(zmq)
add_subdirectory(cli)
