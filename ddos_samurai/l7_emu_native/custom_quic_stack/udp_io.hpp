#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <sys/types.h>
#include <vector>

#include "../engine.hpp"

namespace ddos_samurai::l7_emu_native::custom_quic_stack {

// UDP I/O backend codes (stable metric contract):
// 0=kernel_socket, 1=af_xdp, 2=dpdk, 3=af_packet
enum class QuicUdpIoBackendCode : int {
  KernelSocket = 0,
  AfXdp = 1,
  Dpdk = 2,
  AfPacket = 3,
};

inline bool is_native_hot_path_backend(QuicUdpIoBackendCode backend) {
  return backend == QuicUdpIoBackendCode::AfXdp ||
         backend == QuicUdpIoBackendCode::AfPacket ||
         backend == QuicUdpIoBackendCode::Dpdk;
}

struct UdpProbeCounters {
  int conn_attempted{0};
  int conn_established{0};
  int responses{0};
  int timeouts{0};
  int connect_fail{0};
  int handshake_fail{0};
  int send_ok{0};
  int errors{0};
  int response_headers_ok{0};
  int response_body_ok{0};
  int response_expected_header_ok{0};
  int response_expected_body_match_ok{0};
  int response_validation_fail{0};
  int h3_goaway_events{0};
  int h3_drain_cycles{0};
  int h3_replace_now{0};
  int h3_replace_after_idle{0};
  int h3_control_plane_failures{0};
  int h3_graceful_close_count{0};
  int h3_qpack_dynamic_events{0};
  int h3_qpack_encoder_inserts{0};
  int h3_qpack_decoder_inserts{0};
  int h3_qpack_evictions{0};
  int h3_priority_update_events{0};
  int h3_extended_connect_events{0};
  int h3_datagram_tx_events{0};
  int h3_datagram_rx_events{0};
  int h3_server_push_events{0};
  int h3_feature_failures{0};
  int runtime_udp_io_backend{0};  // QuicUdpIoBackendCode
  int runtime_native_hot_path_ready{0};
  int runtime_backend_requested{0};  // QuicUdpIoBackendCode
  int backend_fallback_count{0};
  int tx_datagrams{0};
  int rx_datagrams{0};
  int pacing_wait_events{0};
  int tls_session_resume_attempted{0};
  int tls_session_resume_applied{0};
  int tls_session_resumed{0};
  int tls_early_data_accepted{0};
  int tls_session_ticket_received{0};
  int tls_cache_load_hit{0};
  int tls_cache_store_updates{0};
  // Multi-step scenario / per-step SLA telemetry (H1/H2 parity).
  int scenario_multi_step{0};
  int scenario_steps_planned{0};
  int scenario_steps_completed{0};
  int scenario_steps_passed{0};
  int scenario_steps_failed{0};
  int scenario_think_time_total_ms{0};
  double scenario_step_latency_ms_sum{0.0};
  double scenario_step_latency_ms_max{0.0};
  std::size_t tx_bytes{0};
  std::size_t rx_bytes{0};
};

using UdpResponseObserver = bool (*)(const unsigned char* data, std::size_t len, void* ctx);

constexpr std::size_t kUdpIoMaxUdpPayloadBytes = 1400u;
constexpr std::size_t kUdpIoMaxL2FrameBytes =
    14u + 20u + 8u + kUdpIoMaxUdpPayloadBytes;  // eth + ipv4 + udp + payload

struct AfPacketUdpEndpoint {
  int fd{-1};
  int ifindex{0};
  std::array<uint8_t, 6> src_mac{};
  std::array<uint8_t, 6> dst_mac{};
  uint32_t src_ip_nbo{0};
  uint32_t dst_ip_nbo{0};
  uint16_t src_port_nbo{0};
  uint16_t dst_port_nbo{0};
  uint16_t ip_id{1};
  std::array<uint8_t, kUdpIoMaxL2FrameBytes> tx_frame{};
};

QuicUdpIoBackendCode parse_quic_udp_io_backend(const std::string& raw);
QuicUdpIoBackendCode resolve_quic_udp_io_backend(const Profile& profile);

bool parse_mac_address(const std::string& text, std::array<uint8_t, 6>* out);
bool read_iface_mac_address(const std::string& iface, std::array<uint8_t, 6>* out);
bool read_iface_ipv4_nbo(const std::string& iface, uint32_t* out_nbo);
std::optional<std::array<uint8_t, 6>> lookup_arp_mac_address(
    const std::string& iface,
    const std::string& target_ip);

bool build_ipv4_udp_ethernet_frame(
    const std::array<uint8_t, 6>& dst_mac,
    const std::array<uint8_t, 6>& src_mac,
    uint32_t src_ip_nbo,
    uint32_t dst_ip_nbo,
    uint16_t src_port_nbo,
    uint16_t dst_port_nbo,
    uint16_t* ip_id,
    const uint8_t* payload,
    std::size_t payload_len,
    uint8_t* out_frame,
    std::size_t out_frame_cap,
    std::size_t* out_frame_len);

bool open_af_packet_udp(
    const Profile& profile,
    uint32_t dst_ip_nbo,
    uint16_t dst_port_host,
    AfPacketUdpEndpoint* out);

void close_af_packet_udp(AfPacketUdpEndpoint* ep);

ssize_t af_packet_send_udp(AfPacketUdpEndpoint* ep, const uint8_t* payload, std::size_t payload_len);

// Returns number of accepted UDP payloads written into payload_buf (stride bytes each).
int af_packet_recv_udp(
    AfPacketUdpEndpoint* ep,
    uint8_t* payload_buf,
    std::size_t stride,
    std::size_t* lens_out,
    int max_packets);

// Wait for a UDP socket to become readable through an io_uring readiness poll
// instead of ::poll(), so the QUIC/HTTP-3 kernel-socket event loop shares the
// same ring machinery as the H1/H2 reactor. Returns 1 if the fd became readable
// (or errored), 0 on timeout, and -1 when io_uring is unavailable on this build
// or host - in which case the caller MUST fall back to ::poll(). Safe to call
// unconditionally; the io_uring ring is a lazily-initialised thread-local.
int quic_uring_wait_readable(int fd, int timeout_ms);

// True when the thread-local io_uring ring is active (diagnostics / metrics).
bool quic_uring_available();

bool run_udp_probe_batch(
    const Profile& profile,
    int attempted,
    int timeout_ms,
    const unsigned char* payload_data,
    std::size_t payload_len,
    UdpResponseObserver observer,
    void* observer_ctx,
    UdpProbeCounters* out);

}  // namespace ddos_samurai::l7_emu_native::custom_quic_stack
