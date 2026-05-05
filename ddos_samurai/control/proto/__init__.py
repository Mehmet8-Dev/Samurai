"""Generated protobuf stubs live in this package."""

from __future__ import annotations


def load_generated():
    try:
        from . import samurai_control_pb2 as pb2
        from . import samurai_control_pb2_grpc as pb2_grpc
    except ImportError as exc:
        raise ImportError(
            "Generated proto modules not found. Run grpc codegen first:\n"
            "python -m grpc_tools.protoc -Iddos_samurai/control/proto "
            "--python_out=ddos_samurai/control/proto "
            "--grpc_python_out=ddos_samurai/control/proto "
            "ddos_samurai/control/proto/samurai_control.proto"
        ) from exc

    if not hasattr(pb2_grpc, "SamuraiControlStub") or not hasattr(pb2_grpc, "SamuraiControlServicer"):
        raise ImportError(
            "Generated grpc stubs are missing required symbols. "
            "Re-run grpc codegen for samurai_control.proto."
        )
    return pb2, pb2_grpc
