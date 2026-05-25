from __future__ import annotations

from .wire import WorkerKind
from .worker_prototype import ZmqWorkerPrototype, main as _generic_main


class CpuWorkerPrototype(ZmqWorkerPrototype):
    def __init__(self, **kwargs):
        super().__init__(worker_kind=WorkerKind.CPU, **kwargs)


def main(argv: list[str] | None = None) -> int:
    return _generic_main(argv, default_kind=WorkerKind.CPU)


if __name__ == "__main__":
    raise SystemExit(main())
