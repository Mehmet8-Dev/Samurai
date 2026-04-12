"""Thin facade for the additive custom TCP dataplane API."""

from .l4 import state_engine as _state_engine

collect_tcp_completions = _state_engine.collect_tcp_completions
collect_tcp_rx_payloads = _state_engine.collect_tcp_rx_payloads
configure_tcp_dataplane = _state_engine.configure_tcp_dataplane
drain_tcp_tx_packets = _state_engine.drain_tcp_tx_packets
enqueue_tcp_connect = _state_engine.enqueue_tcp_connect
enqueue_tcp_send = _state_engine.enqueue_tcp_send
get_tcp_flow = _state_engine.get_tcp_flow
ingest_tcp_tx_packets = _state_engine.ingest_tcp_tx_packets
ingest_tcp_rx_frame = _state_engine.ingest_tcp_rx_frame
poll_tcp_dataplane = _state_engine.poll_tcp_dataplane
snapshot_tcp_dataplane = _state_engine.snapshot_tcp_dataplane
drain_tcp_tx_buffer = getattr(_state_engine, "drain_tcp_tx_buffer", None)
peek_tcp_tx_buffer_strided = getattr(_state_engine, "peek_tcp_tx_buffer_strided", None)
consume_tcp_tx_packets = getattr(_state_engine, "consume_tcp_tx_packets", None)

__all__ = [
    "collect_tcp_completions",
    "collect_tcp_rx_payloads",
    "configure_tcp_dataplane",
    "drain_tcp_tx_packets",
    "enqueue_tcp_connect",
    "enqueue_tcp_send",
    "get_tcp_flow",
    "ingest_tcp_tx_packets",
    "ingest_tcp_rx_frame",
    "poll_tcp_dataplane",
    "snapshot_tcp_dataplane",
]

if callable(drain_tcp_tx_buffer):
    __all__.append("drain_tcp_tx_buffer")
if callable(peek_tcp_tx_buffer_strided):
    __all__.append("peek_tcp_tx_buffer_strided")
if callable(consume_tcp_tx_packets):
    __all__.append("consume_tcp_tx_packets")
