"""
Samurai: High-Performance Network Stress Testing Tool.

The runtime is native (C/C++): the ZMQ worker daemons plus the native
orchestrator/CLI under ddos_samurai/{zmq,orchestrator,cli}/. This package
initializer only exposes version metadata for the ML/VAE defense package
(ddos_samurai.models.vae) that ships alongside the native runtime.
"""
__version__ = "2.2.0"
__codename__ = "Shogun"
__author__ = "Mehmet Okur"
