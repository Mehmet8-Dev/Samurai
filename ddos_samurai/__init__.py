"""
Samurai: High-Performance Network Stress Testing Tool.

The runtime is native (C/C++): the ZMQ worker daemons plus the native
orchestrator/CLI under ddos_samurai/{zmq,orchestrator,cli}/. This package
initializer only exposes version metadata that the remaining (being-ported)
Python modules still reference.
"""
__version__ = "2.2.0"
__codename__ = "Shogun"
__author__ = "Mehmet Okur"
