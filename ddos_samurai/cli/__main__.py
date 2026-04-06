"""Module execution entrypoint for `python -m ddos_samurai.cli`."""

from __future__ import annotations

import multiprocessing

from .app import main

if __name__ == "__main__":
    try:
        multiprocessing.set_start_method("spawn")
    except RuntimeError:
        pass
    raise SystemExit(main())
