from __future__ import annotations

from .zmq_worker_prototype import main as _generic_main
from .zmq_wire import WorkerKind


DEFAULT_KIND = WorkerKind.DOCA


def main(argv: list[str] | None = None) -> int:
    return _generic_main(argv, default_kind=DEFAULT_KIND)


if __name__ == "__main__":
    raise SystemExit(main())
