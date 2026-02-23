#!/usr/bin/env python3

"""
DDoSamurai v2.0 - Main Entry Point

This script serves as the primary entry point for the DDoSamurai application.
It initializes the command-line interface and delegates execution to the
core application logic within the 'ddos_samur ai' package.

To run the application, execute this script from your terminal:
    python advv2.py --target <IP> --port <PORT> [OPTIONS]
"""

import multiprocessing
if __name__ == "__main__":
    # Set the multiprocessing start method to 'spawn' for compatibility and performance
    # on Unix-like systems. This should be done only once.
    try:
        # 'spawn' is required for CUDA to work correctly with multiprocessing.
        multiprocessing.set_start_method("spawn")
        print(f"[DEBUG] Multiprocessing start method set to: {multiprocessing.get_start_method()}")
    except RuntimeError as e:
        print(f"[WARNING] Could not set start method to 'spawn': {e}")
        print(f"[DEBUG] Current start method: {multiprocessing.get_start_method()}")
        pass

    # Call the main function from the CLI module to start the application
    from ddos_samurai.cli import main
    main()