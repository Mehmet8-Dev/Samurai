cmake_minimum_required(VERSION 3.16)
project(samurai_native LANGUAGES C CXX)

# Native build tree for Samurai:
#   zmq/          -> the ZMQ worker daemons (samurai_*_worker)
#   orchestrator/ -> the native orchestrator/CLI front-end (samurai)
#
# Python C-extensions are still built separately via setup.py; this tree covers
# the native worker + orchestrator/CLI layer that is replacing the Python
# launcher/orchestrator path.
add_subdirectory(zmq)
add_subdirectory(orchestrator)
