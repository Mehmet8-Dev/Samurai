"""Manual smoke helper for ZMQ-only GPU facade."""

from ddos_samurai import gpu_packet


if __name__ == "__main__":
    print("backend:", gpu_packet.get_active_backend_name())
    print("kernel_mode:", gpu_packet.get_kernel_mode())
    print("stats:", gpu_packet.read_stream_stats())
