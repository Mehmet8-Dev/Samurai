#include "h3_ngtcp2_client.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <thread>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iterator>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <arpa/inet.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/if.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include "../../xdp/xdp_native_api.h"
#include "../../dpdk/dpdk_core.hpp"
#include "../engine_internal.hpp"
#include "quic_cuda_crypto.hpp"

#if defined(SAMURAI_WITH_NGTCP2) && defined(SAMURAI_WITH_GNUTLS) && defined(SAMURAI_WITH_NGTCP2_GNUTLS) && defined(SAMURAI_WITH_NGHTTP3)
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#endif

namespace ddos_samurai::l7_emu_native::custom_quic_stack {

#if defined(SAMURAI_WITH_NGTCP2) && defined(SAMURAI_WITH_GNUTLS) && defined(SAMURAI_WITH_NGTCP2_GNUTLS) && defined(SAMURAI_WITH_NGHTTP3)
namespace {

struct RequestSpec {
  std::string method{"GET"};
  std::string path{"/"};
  std::vector<unsigned char> body{};
  std::vector<std::pair<std::string, std::string>> headers{};
};

struct Expectations {
  int status_min{100};
  int status_max{599};
  bool has_header_expect{false};
  std::string header_name{};
  std::string header_value_contains{};
  bool has_body_expect{false};
  std::string body_substring{};
  bool require_body{false};
  std::size_t min_body_bytes{0};
};

struct GoawayPolicy {
  bool enabled{false};
  int requests_per_connection{0};
  bool replace_after_idle{true};
};

struct H3FeaturePolicy {
  bool qpack_dynamic{false};
  bool priority_update{false};
  std::string priority_value{"u=3"};
  uint32_t priority_urgency{3};
  int priority_incremental{0};
  bool extended_connect{false};
  std::string connect_protocol{"webtransport"};
  bool datagram{false};
  std::string datagram_flow_id{"0"};
  bool server_push{false};
  std::string server_push_hint{"link"};
  bool cancel_on_promise{false};
  uint64_t max_push_id{32};
};

struct H3FrameParseState {
  bool initialized{false};
  bool is_server_uni{false};
  bool stream_type_known{false};
  uint64_t stream_type{0};
  bool push_id_known{false};
  uint64_t push_id{0};
  std::vector<uint8_t> buffer{};
};

struct FlowControlGuardPolicy {
  int blocked_budget{32};
  int blocked_streak_budget{12};
  int blocked_window_ms{200};
  bool fast_fail{true};
};

struct PipelinedStreamState {
  int64_t stream_id{-1};
  uint64_t start_ns{0};
  std::size_t req_body_off{0};
  int response_status{0};
  bool response_headers_seen{false};
  bool response_complete{false};
  bool has_body_data{false};
  std::string response_headers{};
  std::string response_body{};
};

enum class QuicUdpIoBackend {
  KernelSocket = 0,
  AfXdp = 1,
  Dpdk = 2,
  AfPacket = 3,
};

constexpr std::size_t kMaxUdpPayloadBytes = 1472u;
constexpr std::size_t kMaxL2FrameBytes = 14u + sizeof(iphdr) + sizeof(udphdr) + kMaxUdpPayloadBytes;

struct QuicXdpTransport {
  const xdp_native_api_v1* api{nullptr};
  int handle{0};
  std::array<uint8_t, 6> src_mac{};
  std::array<uint8_t, 6> dst_mac{};
  uint32_t src_ip_nbo{0};
  uint32_t dst_ip_nbo{0};
  uint16_t src_port_nbo{0};
  uint16_t dst_port_nbo{0};
  uint16_t ip_id{1};
  int rx_stride{2048};
  std::vector<uint8_t> rx_frames{};
  std::array<uint16_t, 64> rx_lens{};
  std::array<uint8_t, 65536> udp_payload{};
  std::array<uint8_t, kMaxL2FrameBytes> tx_frame{};
};

struct QuicDpdkTransport {
  long handle{0};
  uint16_t queue_id{0};
  uint16_t port_mask{0};   // ephemeral src-port stride mask for per-core steering
  bool owns_handle{false}; // true when this attempt opened the handle (serial path)
  std::array<uint8_t, 6> src_mac{};
  std::array<uint8_t, 6> dst_mac{};
  uint32_t src_ip_nbo{0};
  uint32_t dst_ip_nbo{0};
  uint16_t src_port_nbo{0};
  uint16_t dst_port_nbo{0};
  uint16_t ip_id{1};
  int rx_stride{2048};
  std::vector<uint8_t> rx_payload{};   // budget*rx_stride, allocated on connect
  std::array<uint16_t, 64> rx_lens{};
};

// Fan-out-managed DPDK context: the manager (opened before the worker threads)
// configures the shared port with N queues and installs the per-queue steering
// rules; each worker opens its own handle on the same port for a private UDP
// template (distinct strided ephemeral src port). See run_ngtcp2_profile.
struct QuicDpdkFanoutCtx {
  long shared_handle{0};  // per-worker handle (private template), 0 = unmanaged/serial
  uint16_t queue_id{0};
  uint16_t port_mask{0};
};

struct Ngtcp2AttemptCtx {
  ngtcp2_crypto_conn_ref conn_ref{};
  ngtcp2_conn* conn{nullptr};
  nghttp3_conn* h3_conn{nullptr};
  gnutls_certificate_credentials_t cred{nullptr};
  gnutls_session_t session{nullptr};
  int fd{-1};
  QuicUdpIoBackend udp_io_backend{QuicUdpIoBackend::KernelSocket};
  QuicUdpIoBackend requested_backend{QuicUdpIoBackend::KernelSocket};
  bool strict_runtime{false};
  bool backend_fallback_used{false};
  QuicXdpTransport xdp{};
  QuicDpdkTransport dpdk{};
  AfPacketUdpEndpoint af_packet{};
  sockaddr_storage local_addr{};
  socklen_t local_addrlen{0};
  sockaddr_storage remote_addr{};
  socklen_t remote_addrlen{0};

  int64_t ctrl_stream_id{-1};
  int64_t qpack_enc_stream_id{-1};
  int64_t qpack_dec_stream_id{-1};
  int64_t request_stream_id{-1};
  int requests_planned{1};
  int requests_completed{0};
  int requests_succeeded{0};
  int requests_failed{0};

  RequestSpec request{};
  Expectations expectations{};
  std::size_t req_body_off{0};

  bool handshake_done{false};
  bool h3_ready{false};
  bool request_submitted{false};
  bool response_complete{false};
  bool response_headers_seen{false};
  bool received_any_stream_data{false};
  bool goaway_active{false};
  bool saw_qpack_activity{false};
  bool saw_priority_ack{false};
  bool saw_extended_connect_ack{false};
  bool saw_datagram_ack{false};
  bool saw_server_push_signal{false};
  bool datagram_pending{false};
  bool datagram_remote_supported{false};

  int response_status{0};
  std::string response_headers{};
  std::string response_body{};
  int64_t goaway_last_stream_id{-1};
  int goaway_events{0};
  int drain_cycles{0};
  int replace_now{0};
  int replace_after_idle{0};
  int control_plane_failures{0};
  int graceful_close_count{0};
  int qpack_dynamic_events{0};
  int qpack_encoder_inserts{0};
  int qpack_decoder_inserts{0};
  int qpack_evictions{0};
  std::size_t qpack_dtable_bytes{0};
  bool priority_applied{false};
  int priority_update_events{0};
  int extended_connect_events{0};
  int datagram_tx_events{0};
  int datagram_rx_events{0};
  int server_push_events{0};
  int feature_failures{0};

  std::size_t rx_bytes{0};
  std::size_t tx_bytes{0};
  std::vector<uint8_t> datagram_payload{};
  uint64_t next_datagram_id{1};
  uint64_t last_datagram_id{0};
  H3FeaturePolicy feature_policy{};
  std::unordered_map<int64_t, H3FrameParseState> frame_parse_states{};
  std::unordered_set<uint64_t> promised_push_ids{};
  std::unordered_set<uint64_t> canceled_push_ids{};
  std::unordered_set<uint64_t> fulfilled_push_ids{};
  std::unordered_set<uint64_t> cancel_push_tx_sent{};
  std::vector<uint8_t> control_tx_buffer{};
  std::size_t control_tx_off{0};
  uint64_t max_push_id_advertised{0};
  uint64_t max_push_id_sent_value{0};
  bool max_push_id_set{false};
  bool max_push_id_sent{false};
  FlowControlGuardPolicy flow_guard{};
  int blocked_window_events{0};
  int blocked_streak_events{0};
  uint64_t blocked_window_start_ns{0};
  bool flow_control_fast_failed{false};
  bool tls_session_resume_attempted{false};
  bool tls_session_resume_applied{false};
  bool tls_session_resumed{false};
  bool tls_early_data_accepted{false};
  bool tls_session_ticket_received{false};
  bool has_precomputed_cids{false};
  std::array<uint8_t, 8> precomputed_dcid{};
  std::array<uint8_t, 8> precomputed_scid{};
  QuicInitialKeyMaterial precomputed_initial_keys{};
  bool pipelined_mode{false};
  std::unordered_map<int64_t, PipelinedStreamState> active_streams{};
  std::vector<PipelinedStreamState> completed_streams{};
  std::vector<double> stream_latencies_ms{};
};

struct TlsSessionCache {
  std::string identity{};
  std::string disk_path{};
  std::vector<uint8_t> blob{};
  int ttl_sec{3600};
  int pool_size{64};
  bool loaded_from_disk{false};
  int store_updates{0};
};

ngtcp2_conn* get_conn(ngtcp2_crypto_conn_ref* conn_ref) {
  if (conn_ref == nullptr) {
    return nullptr;
  }
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(conn_ref->user_data);
  return ctx == nullptr ? nullptr : ctx->conn;
}

uint64_t now_ns() {
  using namespace std::chrono;
  return static_cast<uint64_t>(
      duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count());
}

int64_t ns_to_ms_ceil(uint64_t delta_ns) {
  return static_cast<int64_t>((delta_ns + 999999ull) / 1000000ull);
}

bool env_truthy(const char* name) {
  if (name == nullptr || name[0] == '\0') {
    return false;
  }
  const char* raw = std::getenv(name);
  if (raw == nullptr) {
    return false;
  }
  std::string v(raw);
  std::size_t b = 0;
  while (b < v.size() && std::isspace(static_cast<unsigned char>(v[b])) != 0) {
    ++b;
  }
  std::size_t e = v.size();
  while (e > b && std::isspace(static_cast<unsigned char>(v[e - 1])) != 0) {
    --e;
  }
  v = v.substr(b, e - b);
  std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return v == "1" || v == "true" || v == "yes" || v == "on";
}

int env_int(const char* name, int fallback) {
  if (name == nullptr || name[0] == '\0') {
    return fallback;
  }
  const char* raw = std::getenv(name);
  if (raw == nullptr || raw[0] == '\0') {
    return fallback;
  }
  return std::atoi(raw);
}

FlowControlGuardPolicy derive_flow_control_guard_policy() {
  FlowControlGuardPolicy policy{};
  policy.blocked_budget = std::clamp(env_int("SAMURAI_QUIC_FLOW_BLOCKED_BUDGET", 32), 1, 4096);
  policy.blocked_streak_budget = std::clamp(env_int("SAMURAI_QUIC_FLOW_BLOCKED_STREAK_BUDGET", 12), 1, 1024);
  policy.blocked_window_ms = std::clamp(env_int("SAMURAI_QUIC_FLOW_BLOCKED_WINDOW_MS", 200), 10, 60000);
  policy.fast_fail = !env_truthy("SAMURAI_QUIC_FLOW_BLOCKED_FAST_FAIL_DISABLE");
  return policy;
}

constexpr uint32_t kTlsSessionCacheMagic = 0x32534c54u;  // "TLS2"
constexpr uint32_t kTlsSessionCacheVersion = 2u;
constexpr std::size_t kTlsSessionCacheMaxBlob = 64u * 1024u;
constexpr std::size_t kTlsSessionCacheMaxIdentityLen = 1024u;

struct TlsSessionCacheEntry {
  std::string identity{};
  std::vector<uint8_t> blob{};
  uint64_t created_s{0};
  uint64_t expires_s{0};
  uint64_t last_used_s{0};
};

void append_u32_le(std::vector<uint8_t>* out, uint32_t v) {
  if (out == nullptr) {
    return;
  }
  out->push_back(static_cast<uint8_t>(v & 0xffu));
  out->push_back(static_cast<uint8_t>((v >> 8u) & 0xffu));
  out->push_back(static_cast<uint8_t>((v >> 16u) & 0xffu));
  out->push_back(static_cast<uint8_t>((v >> 24u) & 0xffu));
}

bool read_u32_le(const std::vector<uint8_t>& src, std::size_t off, uint32_t* out) {
  if (out == nullptr || off + 4u > src.size()) {
    return false;
  }
  *out = static_cast<uint32_t>(src[off]) |
      (static_cast<uint32_t>(src[off + 1]) << 8u) |
      (static_cast<uint32_t>(src[off + 2]) << 16u) |
      (static_cast<uint32_t>(src[off + 3]) << 24u);
  return true;
}

void append_u64_le(std::vector<uint8_t>* out, uint64_t v) {
  if (out == nullptr) {
    return;
  }
  out->push_back(static_cast<uint8_t>(v & 0xffu));
  out->push_back(static_cast<uint8_t>((v >> 8u) & 0xffu));
  out->push_back(static_cast<uint8_t>((v >> 16u) & 0xffu));
  out->push_back(static_cast<uint8_t>((v >> 24u) & 0xffu));
  out->push_back(static_cast<uint8_t>((v >> 32u) & 0xffu));
  out->push_back(static_cast<uint8_t>((v >> 40u) & 0xffu));
  out->push_back(static_cast<uint8_t>((v >> 48u) & 0xffu));
  out->push_back(static_cast<uint8_t>((v >> 56u) & 0xffu));
}

bool read_u64_le(const std::vector<uint8_t>& src, std::size_t off, uint64_t* out) {
  if (out == nullptr || off + 8u > src.size()) {
    return false;
  }
  *out = static_cast<uint64_t>(src[off]) |
      (static_cast<uint64_t>(src[off + 1]) << 8u) |
      (static_cast<uint64_t>(src[off + 2]) << 16u) |
      (static_cast<uint64_t>(src[off + 3]) << 24u) |
      (static_cast<uint64_t>(src[off + 4]) << 32u) |
      (static_cast<uint64_t>(src[off + 5]) << 40u) |
      (static_cast<uint64_t>(src[off + 6]) << 48u) |
      (static_cast<uint64_t>(src[off + 7]) << 56u);
  return true;
}

uint64_t now_epoch_s() {
  return static_cast<uint64_t>(std::time(nullptr));
}

QuicUdpIoBackend parse_backend_name(const std::string& raw) {
  return static_cast<QuicUdpIoBackend>(parse_quic_udp_io_backend(raw));
}

QuicUdpIoBackend resolve_requested_backend(const Profile& profile) {
  return static_cast<QuicUdpIoBackend>(resolve_quic_udp_io_backend(profile));
}

bool parse_mac(const std::string& text, std::array<uint8_t, 6>* out) {
  if (out == nullptr) {
    return false;
  }
  std::array<unsigned int, 6> tmp{};
  if (std::sscanf(
          text.c_str(),
          "%x:%x:%x:%x:%x:%x",
          &tmp[0],
          &tmp[1],
          &tmp[2],
          &tmp[3],
          &tmp[4],
          &tmp[5]) != 6) {
    return false;
  }
  for (std::size_t i = 0; i < out->size(); ++i) {
    if (tmp[i] > 0xFFu) {
      return false;
    }
    (*out)[i] = static_cast<uint8_t>(tmp[i]);
  }
  return true;
}

bool read_iface_mac(const std::string& iface, std::array<uint8_t, 6>* out) {
  if (out == nullptr || iface.empty()) {
    return false;
  }
  const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    return false;
  }
  ifreq ifr{};
  std::snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface.c_str());
  bool ok = false;
  if (::ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
    const unsigned char* mac = reinterpret_cast<const unsigned char*>(ifr.ifr_hwaddr.sa_data);
    for (int i = 0; i < 6; ++i) {
      (*out)[static_cast<std::size_t>(i)] = mac[i];
    }
    ok = true;
  }
  (void)::close(fd);
  return ok;
}

bool read_iface_ipv4(const std::string& iface, uint32_t* out_nbo) {
  if (out_nbo == nullptr || iface.empty()) {
    return false;
  }
  const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    return false;
  }
  ifreq ifr{};
  std::snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface.c_str());
  bool ok = false;
  if (::ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
    const auto* sa = reinterpret_cast<const sockaddr_in*>(&ifr.ifr_addr);
    *out_nbo = sa->sin_addr.s_addr;
    ok = true;
  }
  (void)::close(fd);
  return ok;
}

std::optional<std::array<uint8_t, 6>> lookup_arp_mac(const std::string& iface, const std::string& target_ip) {
  std::ifstream in("/proc/net/arp");
  if (!in.is_open()) {
    return std::nullopt;
  }
  std::string line{};
  if (!std::getline(in, line)) {
    return std::nullopt;
  }
  while (std::getline(in, line)) {
    std::istringstream iss(line);
    std::string ip{};
    std::string hw_type{};
    std::string flags{};
    std::string mac{};
    std::string mask{};
    std::string dev{};
    if (!(iss >> ip >> hw_type >> flags >> mac >> mask >> dev)) {
      continue;
    }
    if (ip != target_ip) {
      continue;
    }
    if (!iface.empty() && dev != iface) {
      continue;
    }
    std::array<uint8_t, 6> out{};
    if (parse_mac(mac, &out)) {
      return out;
    }
  }
  return std::nullopt;
}

uint16_t fold_checksum(uint32_t sum) {
  while ((sum >> 16u) != 0u) {
    sum = (sum & 0xFFFFu) + (sum >> 16u);
  }
  return static_cast<uint16_t>(~sum & 0xFFFFu);
}

uint16_t ipv4_header_checksum(const iphdr* ip) {
  if (ip == nullptr) {
    return 0;
  }
  const auto* words = reinterpret_cast<const uint16_t*>(ip);
  uint32_t sum = 0;
  for (int i = 0; i < 10; ++i) {
    if (i == 5) {
      continue;
    }
    sum += ntohs(words[i]);
  }
  return htons(fold_checksum(sum));
}

uint16_t udp_ipv4_checksum(
    uint32_t src_ip_nbo,
    uint32_t dst_ip_nbo,
    const udphdr* udp,
    const uint8_t* payload,
    std::size_t payload_len) {
  if (udp == nullptr) {
    return 0;
  }
  uint32_t sum = 0;
  const uint16_t src_hi = static_cast<uint16_t>((ntohl(src_ip_nbo) >> 16) & 0xFFFFu);
  const uint16_t src_lo = static_cast<uint16_t>(ntohl(src_ip_nbo) & 0xFFFFu);
  const uint16_t dst_hi = static_cast<uint16_t>((ntohl(dst_ip_nbo) >> 16) & 0xFFFFu);
  const uint16_t dst_lo = static_cast<uint16_t>(ntohl(dst_ip_nbo) & 0xFFFFu);
  sum += src_hi;
  sum += src_lo;
  sum += dst_hi;
  sum += dst_lo;
  sum += static_cast<uint16_t>(IPPROTO_UDP);
  sum += ntohs(udp->len);

  const auto* udp_words = reinterpret_cast<const uint16_t*>(udp);
  sum += ntohs(udp_words[0]);
  sum += ntohs(udp_words[1]);
  sum += ntohs(udp_words[2]);
  // checksum field is treated as zero

  std::size_t i = 0;
  while (i + 1 < payload_len) {
    const uint16_t w = static_cast<uint16_t>((static_cast<uint16_t>(payload[i]) << 8u) |
                                             static_cast<uint16_t>(payload[i + 1]));
    sum += w;
    i += 2;
  }
  if (i < payload_len) {
    const uint16_t w = static_cast<uint16_t>(static_cast<uint16_t>(payload[i]) << 8u);
    sum += w;
  }
  const uint16_t csum = fold_checksum(sum);
  return csum == 0 ? 0xFFFFu : htons(csum);
}

bool build_ipv4_udp_eth_frame(
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
    std::size_t* out_frame_len) {
  if (ip_id == nullptr || payload == nullptr || out_frame == nullptr || out_frame_len == nullptr) {
    return false;
  }
  if (payload_len == 0 || payload_len > kMaxUdpPayloadBytes || out_frame_cap < kMaxL2FrameBytes) {
    return false;
  }
  const std::size_t frame_len = 14u + sizeof(iphdr) + sizeof(udphdr) + payload_len;
  std::size_t off = 0;
  for (std::size_t i = 0; i < 6; ++i) {
    out_frame[off + i] = dst_mac[i];
    out_frame[off + 6 + i] = src_mac[i];
  }
  out_frame[off + 12] = 0x08;
  out_frame[off + 13] = 0x00;
  off += 14;

  auto* ip = reinterpret_cast<iphdr*>(out_frame + off);
  std::memset(ip, 0, sizeof(*ip));
  ip->version = 4;
  ip->ihl = 5;
  ip->ttl = 64;
  ip->protocol = IPPROTO_UDP;
  ip->id = htons((*ip_id)++);
  ip->frag_off = htons(0x4000);
  ip->tot_len = htons(static_cast<uint16_t>(sizeof(iphdr) + sizeof(udphdr) + payload_len));
  ip->saddr = src_ip_nbo;
  ip->daddr = dst_ip_nbo;
  ip->check = ipv4_header_checksum(ip);
  off += sizeof(iphdr);

  auto* udp = reinterpret_cast<udphdr*>(out_frame + off);
  std::memset(udp, 0, sizeof(*udp));
  udp->source = src_port_nbo;
  udp->dest = dst_port_nbo;
  udp->len = htons(static_cast<uint16_t>(sizeof(udphdr) + payload_len));
  off += sizeof(udphdr);
  std::memcpy(out_frame + off, payload, payload_len);
  udp->check = udp_ipv4_checksum(src_ip_nbo, dst_ip_nbo, udp, payload, payload_len);

  *out_frame_len = frame_len;
  return true;
}

const xdp_native_api_v1* load_xdp_native_api() {
  static const char* kCandidates[] = {
      "ddos_samurai/xdp/xdp_sender.so",
      "ddos_samurai/xdp_sender.so",
      "xdp_sender.so",
      "ddos_samurai/xdp_sender.cpython-312-x86_64-linux-gnu.so",
      "ddos_samurai/xdp_sender.cpython-311-x86_64-linux-gnu.so",
      "ddos_samurai/xdp_sender.cpython-310-x86_64-linux-gnu.so",
  };
  for (const char* path : kCandidates) {
    dlerror();
    void* h = ::dlopen(path, RTLD_LAZY | RTLD_LOCAL);
    if (h == nullptr) {
      continue;
    }
    using GetApiFn = xdp_native_api_v1* (*)();
    auto get_api = reinterpret_cast<GetApiFn>(::dlsym(h, "samurai_xdp_get_native_api_v1"));
    if (get_api == nullptr) {
      ::dlclose(h);
      continue;
    }
    const xdp_native_api_v1* api = get_api();
    if (api == nullptr || api->version != XDP_NATIVE_API_VERSION ||
        api->create_ctx == nullptr || api->destroy_ctx == nullptr ||
        api->send_buffer == nullptr || api->recv_frames == nullptr) {
      ::dlclose(h);
      continue;
    }
    return api;
  }
  return nullptr;
}

void close_dpdk_transport(QuicDpdkTransport* t) {
  if (t == nullptr) {
    return;
  }
  // Only the serial (unmanaged) path owns its handle; fan-out worker handles are
  // owned by the worker thread and closed after the attempt loop joins.
  if (t->owns_handle && t->handle > 0) {
    samurai::dpdk::close_port(t->handle);
  }
  *t = QuicDpdkTransport{};
}

bool is_numeric_host(const std::string& host) {
  in_addr v4{};
  if (::inet_pton(AF_INET, host.c_str(), &v4) == 1) {
    return true;
  }
  in6_addr v6{};
  return ::inet_pton(AF_INET6, host.c_str(), &v6) == 1;
}

bool resolve_target(
    const std::string& host,
    int port,
    sockaddr_storage* out_addr,
    socklen_t* out_len) {
  if (out_addr == nullptr || out_len == nullptr) {
    return false;
  }
  *out_len = 0;
  std::memset(out_addr, 0, sizeof(*out_addr));

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  addrinfo* result = nullptr;
  const std::string port_s = std::to_string(std::max(1, port));
  int rc = ::getaddrinfo(host.c_str(), port_s.c_str(), &hints, &result);
  if (rc != 0 || result == nullptr) {
    // Preserve numeric-host fast path while allowing DNS hostnames.
    hints.ai_flags = AI_NUMERICHOST;
    rc = ::getaddrinfo(host.c_str(), port_s.c_str(), &hints, &result);
  }
  if (rc != 0 || result == nullptr) {
    return false;
  }
  bool ok = false;
  for (addrinfo* it = result; it != nullptr; it = it->ai_next) {
    if (!it->ai_addr || it->ai_addrlen <= 0) {
      continue;
    }
    if (it->ai_addrlen > static_cast<socklen_t>(sizeof(*out_addr))) {
      continue;
    }
    std::memcpy(out_addr, it->ai_addr, static_cast<std::size_t>(it->ai_addrlen));
    *out_len = static_cast<socklen_t>(it->ai_addrlen);
    ok = true;
    break;
  }
  ::freeaddrinfo(result);
  return ok;
}

int rand_fill(uint8_t* dest, std::size_t len) {
  return gnutls_rnd(GNUTLS_RND_RANDOM, dest, len);
}

void rand_cb(uint8_t* dest, std::size_t destlen, const ngtcp2_rand_ctx* rand_ctx) {
  (void)rand_ctx;
  (void)rand_fill(dest, destlen);
}

std::string to_lower_ascii(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return s;
}

std::string trim_ascii(const std::string& s) {
  std::size_t b = 0;
  while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b])) != 0) {
    ++b;
  }
  std::size_t e = s.size();
  while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1])) != 0) {
    --e;
  }
  return s.substr(b, e - b);
}

std::string normalize_authority_host(std::string authority) {
  authority = trim_ascii(authority);
  if (authority.empty()) {
    return authority;
  }
  if (authority.front() == '[') {
    const std::size_t rb = authority.find(']');
    if (rb != std::string::npos && rb > 1) {
      return authority.substr(1, rb - 1);
    }
  }
  const std::size_t first_colon = authority.find(':');
  if (first_colon == std::string::npos) {
    return authority;
  }
  // Single-colon host:port (IPv4/domain). Multi-colon value is likely IPv6 literal.
  if (authority.find(':', first_colon + 1) == std::string::npos) {
    return authority.substr(0, first_colon);
  }
  return authority;
}

std::string build_tls_session_identity(
    const std::string& verify_name,
    int port) {
  std::string host = trim_ascii(verify_name);
  if (host.empty()) {
    return {};
  }
  host = to_lower_ascii(host);
  return host + ":" + std::to_string(std::max(1, port));
}

std::string resolve_tls_session_cache_file_path() {
  const char* raw = std::getenv("SAMURAI_QUIC_TLS_SESSION_CACHE_FILE");
  if (raw == nullptr) {
    return {};
  }
  return trim_ascii(raw);
}

int resolve_tls_session_cache_ttl_sec() {
  return std::clamp(env_int("SAMURAI_QUIC_TLS_SESSION_CACHE_TTL_SEC", 3600), 60, 7 * 24 * 3600);
}

int resolve_tls_session_cache_pool_size() {
  return std::clamp(env_int("SAMURAI_QUIC_TLS_SESSION_CACHE_POOL_SIZE", 64), 1, 4096);
}

bool read_all_fd(int fd, std::vector<uint8_t>* out) {
  if (fd < 0 || out == nullptr) {
    return false;
  }
  out->clear();
  if (::lseek(fd, 0, SEEK_SET) < 0) {
    return false;
  }
  std::array<uint8_t, 4096> buf{};
  for (;;) {
    const ssize_t n = ::read(fd, buf.data(), buf.size());
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    if (n == 0) {
      break;
    }
    out->insert(out->end(), buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(n));
  }
  return true;
}

bool write_all_fd(int fd, const std::vector<uint8_t>& data) {
  if (fd < 0) {
    return false;
  }
  if (::ftruncate(fd, 0) != 0) {
    return false;
  }
  if (::lseek(fd, 0, SEEK_SET) < 0) {
    return false;
  }
  std::size_t off = 0;
  while (off < data.size()) {
    const ssize_t n = ::write(
        fd,
        data.data() + static_cast<std::ptrdiff_t>(off),
        data.size() - off);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    off += static_cast<std::size_t>(n);
  }
  return ::fsync(fd) == 0;
}

bool parse_tls_session_cache_entries(
    const std::vector<uint8_t>& raw,
    std::vector<TlsSessionCacheEntry>* out_entries) {
  if (out_entries == nullptr) {
    return false;
  }
  out_entries->clear();
  if (raw.empty()) {
    return true;
  }
  if (raw.size() < 12u) {
    return false;
  }
  uint32_t magic = 0;
  uint32_t version = 0;
  uint32_t entry_count = 0;
  if (!read_u32_le(raw, 0, &magic) ||
      !read_u32_le(raw, 4, &version) ||
      !read_u32_le(raw, 8, &entry_count)) {
    return false;
  }
  if (magic != kTlsSessionCacheMagic || version != kTlsSessionCacheVersion) {
    return false;
  }
  std::size_t off = 12u;
  out_entries->reserve(entry_count);
  for (uint32_t i = 0; i < entry_count; ++i) {
    uint32_t identity_len = 0;
    uint32_t blob_len = 0;
    uint64_t created_s = 0;
    uint64_t expires_s = 0;
    uint64_t last_used_s = 0;
    if (!read_u32_le(raw, off, &identity_len)) {
      return false;
    }
    off += 4u;
    if (!read_u32_le(raw, off, &blob_len)) {
      return false;
    }
    off += 4u;
    if (!read_u64_le(raw, off, &created_s)) {
      return false;
    }
    off += 8u;
    if (!read_u64_le(raw, off, &expires_s)) {
      return false;
    }
    off += 8u;
    if (!read_u64_le(raw, off, &last_used_s)) {
      return false;
    }
    off += 8u;
    if (identity_len == 0 ||
        blob_len == 0 ||
        static_cast<std::size_t>(identity_len) > kTlsSessionCacheMaxIdentityLen ||
        static_cast<std::size_t>(blob_len) > kTlsSessionCacheMaxBlob) {
      return false;
    }
    if (off + static_cast<std::size_t>(identity_len) + static_cast<std::size_t>(blob_len) > raw.size()) {
      return false;
    }
    TlsSessionCacheEntry entry{};
    entry.identity.assign(
        reinterpret_cast<const char*>(raw.data() + static_cast<std::ptrdiff_t>(off)),
        static_cast<std::size_t>(identity_len));
    off += static_cast<std::size_t>(identity_len);
    entry.blob.assign(
        raw.begin() + static_cast<std::ptrdiff_t>(off),
        raw.begin() + static_cast<std::ptrdiff_t>(off + static_cast<std::size_t>(blob_len)));
    off += static_cast<std::size_t>(blob_len);
    entry.created_s = created_s;
    entry.expires_s = expires_s;
    entry.last_used_s = last_used_s;
    out_entries->push_back(std::move(entry));
  }
  return off == raw.size();
}

void serialize_tls_session_cache_entries(
    const std::vector<TlsSessionCacheEntry>& entries,
    std::vector<uint8_t>* out_raw) {
  if (out_raw == nullptr) {
    return;
  }
  out_raw->clear();
  out_raw->reserve(12u + entries.size() * 48u);
  append_u32_le(out_raw, kTlsSessionCacheMagic);
  append_u32_le(out_raw, kTlsSessionCacheVersion);
  append_u32_le(out_raw, static_cast<uint32_t>(entries.size()));
  for (const auto& entry : entries) {
    append_u32_le(out_raw, static_cast<uint32_t>(entry.identity.size()));
    append_u32_le(out_raw, static_cast<uint32_t>(entry.blob.size()));
    append_u64_le(out_raw, entry.created_s);
    append_u64_le(out_raw, entry.expires_s);
    append_u64_le(out_raw, entry.last_used_s);
    out_raw->insert(out_raw->end(), entry.identity.begin(), entry.identity.end());
    out_raw->insert(out_raw->end(), entry.blob.begin(), entry.blob.end());
  }
}

bool load_tls_session_cache_file(
    const std::string& path,
    const std::string& identity,
    int ttl_sec,
    int pool_size,
    std::vector<uint8_t>* out_blob,
    bool* out_hit) {
  if (out_hit != nullptr) {
    *out_hit = false;
  }
  if (path.empty() || identity.empty() || out_blob == nullptr) {
    return false;
  }
  const int fd = ::open(path.c_str(), O_RDWR | O_CREAT, 0600);
  if (fd < 0) {
    return false;
  }
  const bool lock_ok = ::flock(fd, LOCK_EX) == 0;
  if (!lock_ok) {
    (void)::close(fd);
    return false;
  }
  std::vector<uint8_t> raw{};
  if (!read_all_fd(fd, &raw)) {
    (void)::flock(fd, LOCK_UN);
    (void)::close(fd);
    return false;
  }
  std::vector<TlsSessionCacheEntry> entries{};
  const bool parsed = parse_tls_session_cache_entries(raw, &entries);
  if (!parsed) {
    entries.clear();
  }
  const uint64_t now_s = now_epoch_s();
  const uint64_t ttl = static_cast<uint64_t>(std::max(60, ttl_sec));
  bool dirty = !parsed;
  std::vector<TlsSessionCacheEntry> filtered{};
  filtered.reserve(entries.size());
  for (auto& entry : entries) {
    if (entry.identity.empty() || entry.blob.empty()) {
      dirty = true;
      continue;
    }
    if (entry.expires_s > 0 && entry.expires_s <= now_s) {
      dirty = true;
      continue;
    }
    filtered.push_back(std::move(entry));
  }
  entries.swap(filtered);

  bool hit = false;
  for (auto& entry : entries) {
    if (entry.identity == identity) {
      *out_blob = entry.blob;
      entry.last_used_s = now_s;
      if (entry.expires_s < now_s + ttl / 2u) {
        entry.expires_s = now_s + ttl;
      }
      hit = true;
      dirty = true;
      break;
    }
  }

  std::stable_sort(entries.begin(), entries.end(), [](const TlsSessionCacheEntry& a, const TlsSessionCacheEntry& b) {
    return a.last_used_s > b.last_used_s;
  });
  if (entries.size() > static_cast<std::size_t>(std::max(1, pool_size))) {
    entries.resize(static_cast<std::size_t>(std::max(1, pool_size)));
    dirty = true;
  }

  if (dirty) {
    std::vector<uint8_t> encoded{};
    serialize_tls_session_cache_entries(entries, &encoded);
    (void)write_all_fd(fd, encoded);
  }
  (void)::flock(fd, LOCK_UN);
  (void)::close(fd);
  if (out_hit != nullptr) {
    *out_hit = hit;
  }
  return hit;
}

bool store_tls_session_cache_file(
    const std::string& path,
    const std::string& identity,
    const std::vector<uint8_t>& blob,
    int ttl_sec,
    int pool_size) {
  if (path.empty() || identity.empty() || blob.empty() || blob.size() > kTlsSessionCacheMaxBlob) {
    return false;
  }
  if (identity.size() > kTlsSessionCacheMaxIdentityLen) {
    return false;
  }
  const int fd = ::open(path.c_str(), O_RDWR | O_CREAT, 0600);
  if (fd < 0) {
    return false;
  }
  if (::flock(fd, LOCK_EX) != 0) {
    (void)::close(fd);
    return false;
  }
  std::vector<uint8_t> raw{};
  std::vector<TlsSessionCacheEntry> entries{};
  if (read_all_fd(fd, &raw)) {
    (void)parse_tls_session_cache_entries(raw, &entries);
  }

  const uint64_t now_s = now_epoch_s();
  const uint64_t ttl = static_cast<uint64_t>(std::max(60, ttl_sec));
  std::vector<TlsSessionCacheEntry> next{};
  next.reserve(entries.size() + 1u);
  for (auto& entry : entries) {
    if (entry.identity.empty() || entry.blob.empty()) {
      continue;
    }
    if (entry.identity == identity) {
      continue;
    }
    if (entry.expires_s > 0 && entry.expires_s <= now_s) {
      continue;
    }
    next.push_back(std::move(entry));
  }

  TlsSessionCacheEntry fresh{};
  fresh.identity = identity;
  fresh.blob = blob;
  fresh.created_s = now_s;
  fresh.last_used_s = now_s;
  fresh.expires_s = now_s + ttl;
  next.push_back(std::move(fresh));

  std::stable_sort(next.begin(), next.end(), [](const TlsSessionCacheEntry& a, const TlsSessionCacheEntry& b) {
    return a.last_used_s > b.last_used_s;
  });
  if (next.size() > static_cast<std::size_t>(std::max(1, pool_size))) {
    next.resize(static_cast<std::size_t>(std::max(1, pool_size)));
  }

  std::vector<uint8_t> encoded{};
  serialize_tls_session_cache_entries(next, &encoded);
  const bool ok = write_all_fd(fd, encoded);
  (void)::flock(fd, LOCK_UN);
  (void)::close(fd);
  return ok;
}

bool tls_ticket_ready(gnutls_session_t session) {
  if (session == nullptr) {
    return false;
  }
#ifdef GNUTLS_SFLAGS_SESSION_TICKET
  return (gnutls_session_get_flags(session) & GNUTLS_SFLAGS_SESSION_TICKET) != 0u;
#else
  return true;
#endif
}

bool apply_tls_session_cache(gnutls_session_t session, const TlsSessionCache* cache) {
  if (session == nullptr || cache == nullptr || cache->blob.empty()) {
    return false;
  }
  return gnutls_session_set_data(session, cache->blob.data(), cache->blob.size()) == GNUTLS_E_SUCCESS;
}

bool capture_tls_session_cache(gnutls_session_t session, TlsSessionCache* cache) {
  if (session == nullptr || cache == nullptr) {
    return false;
  }
  if (!tls_ticket_ready(session)) {
    return false;
  }
  gnutls_datum_t data{};
  if (gnutls_session_get_data2(session, &data) != GNUTLS_E_SUCCESS) {
    return false;
  }
  if (data.data == nullptr || data.size == 0 || data.size > kTlsSessionCacheMaxBlob) {
    if (data.data != nullptr) {
      gnutls_free(data.data);
    }
    return false;
  }
  cache->blob.assign(
      data.data,
      data.data + static_cast<std::ptrdiff_t>(data.size));
  gnutls_free(data.data);
  if (!cache->disk_path.empty() && !cache->identity.empty()) {
    if (store_tls_session_cache_file(
            cache->disk_path,
            cache->identity,
            cache->blob,
            cache->ttl_sec,
            cache->pool_size)) {
      cache->store_updates += 1;
    }
  }
  return true;
}

void reset_flow_control_guard(Ngtcp2AttemptCtx* ctx) {
  if (ctx == nullptr) {
    return;
  }
  ctx->blocked_window_events = 0;
  ctx->blocked_streak_events = 0;
  ctx->blocked_window_start_ns = 0;
  ctx->flow_control_fast_failed = false;
}

void note_flow_control_progress(Ngtcp2AttemptCtx* ctx) {
  if (ctx == nullptr) {
    return;
  }
  ctx->blocked_streak_events = 0;
  ctx->flow_control_fast_failed = false;
}

bool register_stream_data_blocked(Ngtcp2AttemptCtx* ctx) {
  if (ctx == nullptr) {
    return false;
  }
  const uint64_t now = now_ns();
  const uint64_t window_ns = static_cast<uint64_t>(std::max(1, ctx->flow_guard.blocked_window_ms)) * 1000000ull;
  if (ctx->blocked_window_start_ns == 0 || now < ctx->blocked_window_start_ns ||
      now - ctx->blocked_window_start_ns > window_ns) {
    ctx->blocked_window_start_ns = now;
    ctx->blocked_window_events = 0;
  }
  ctx->blocked_window_events += 1;
  ctx->blocked_streak_events += 1;
  const bool budget_exhausted = ctx->blocked_window_events >= ctx->flow_guard.blocked_budget;
  const bool streak_exhausted = ctx->blocked_streak_events >= ctx->flow_guard.blocked_streak_budget;
  if (!budget_exhausted && !streak_exhausted) {
    return false;
  }
  if (ctx->flow_guard.fast_fail) {
    ctx->flow_control_fast_failed = true;
    ctx->feature_failures += 1;
    ctx->control_plane_failures += 1;
    return true;
  }
  return false;
}

void derive_tls_names(
    const Profile& profile,
    std::string* out_sni_name,
    std::string* out_verify_name) {
  if (out_sni_name == nullptr || out_verify_name == nullptr) {
    return;
  }
  const std::string authority_host = normalize_authority_host(profile.host_header);
  const std::string target_host = trim_ascii(profile.target_ip);
  const std::string canonical = authority_host.empty() ? target_host : authority_host;
  *out_verify_name = canonical;
  if (!canonical.empty() && !is_numeric_host(canonical)) {
    *out_sni_name = canonical;
  } else {
    out_sni_name->clear();
  }
}

bool header_expect_ok(
    const std::string& headers,
    const std::string& name,
    const std::string& value_contains) {
  if (name.empty()) {
    return true;
  }
  const std::string lowered_headers = to_lower_ascii(headers);
  const std::string needle = to_lower_ascii(name) + ":";
  const std::size_t pos = lowered_headers.find(needle);
  if (pos == std::string::npos) {
    return false;
  }
  if (value_contains.empty()) {
    return true;
  }
  const std::size_t line_end = lowered_headers.find('\n', pos);
  const std::string segment =
      line_end == std::string::npos ? lowered_headers.substr(pos) : lowered_headers.substr(pos, line_end - pos);
  return segment.find(to_lower_ascii(value_contains)) != std::string::npos;
}

bool body_expect_ok(const std::string& body, const std::string& substr) {
  if (substr.empty()) {
    return true;
  }
  return body.find(substr) != std::string::npos;
}

bool parse_u64_str(const std::string& value, uint64_t* out) {
  if (out == nullptr) {
    return false;
  }
  if (value.empty()) {
    return false;
  }
  uint64_t acc = 0;
  for (char ch : value) {
    if (ch < '0' || ch > '9') {
      return false;
    }
    const uint64_t d = static_cast<uint64_t>(ch - '0');
    if (acc > (UINT64_MAX - d) / 10u) {
      return false;
    }
    acc = acc * 10u + d;
  }
  *out = acc;
  return true;
}

RequestSpec derive_request_spec(const Profile& profile) {
  RequestSpec out;
  for (const auto& op : profile.ops) {
    if (op.opcode == "SEND_HEADERS") {
      if (!op.method.empty()) {
        out.method = op.method;
      }
      if (!op.path.empty()) {
        out.path = op.path;
      }
      if (!op.headers.empty()) {
        out.headers.assign(op.headers.begin(), op.headers.end());
      }
      break;
    }
  }
  for (const auto& op : profile.ops) {
    if (op.opcode == "SEND_BODY" && !op.body.empty()) {
      out.body = op.body;
      break;
    }
  }
  if (out.path.empty()) {
    out.path = "/";
  }
  if (out.path.front() != '/') {
    out.path.insert(out.path.begin(), '/');
  }
  return out;
}

Expectations derive_expectations(const Profile& profile) {
  Expectations exp{};
  for (const auto& op : profile.ops) {
    if (op.opcode == "EXPECT_STATUS" && op.has_expect) {
      exp.status_min = std::max(100, op.expect.status_min);
      exp.status_max = std::max(exp.status_min, std::min(599, op.expect.status_max));
      continue;
    }
    if (op.opcode == "EXPECT_HEADER" && op.has_expect) {
      exp.has_header_expect = true;
      exp.header_name = op.expect.name;
      exp.header_value_contains = op.expect.value;
      continue;
    }
    if (op.opcode == "EXPECT_BODY_SUBSTRING" && op.has_expect) {
      if (op.expect.kind == "body_required") {
        exp.require_body = true;
      } else if (op.expect.kind == "body_min_bytes") {
        int min_body = 0;
        try {
          min_body = std::stoi(op.expect.value);
        } catch (...) {
          min_body = 0;
        }
        exp.min_body_bytes = static_cast<std::size_t>(std::max(0, min_body));
      } else {
        exp.has_body_expect = true;
        exp.body_substring = op.expect.value;
      }
      continue;
    }
  }
  return exp;
}

// ---------------------------------------------------------------------------
// Multi-step scenario support (H1/H2 parity).
//
// H1/H2 walk profile.ops as an ordered scenario: each SEND_HEADERS begins a new
// request step, and the following SEND_BODY / EXPECT_* / CAPTURE_* / THINK_TIME
// ops attach to that step. Prior to this the H3 client collapsed everything into
// a single request and merely repeated it request_budget times ("ilk adımı
// tekrarlıyor"). The helpers below segment ops into steps, render {{...}}
// templates from captured variables + the cookie jar, and harvest cookies/tokens
// between steps so H3 reaches feature parity.
// ---------------------------------------------------------------------------

struct ScenarioCaptureOp {
  std::string opcode;  // CAPTURE_HEADER | CAPTURE_COOKIE
  std::string capture_name;
  std::string capture_source;
};

struct ScenarioStep {
  RequestSpec request{};
  Expectations expectations{};
  std::vector<ScenarioCaptureOp> captures{};
  int think_time_ms{0};
};

// Render a {{...}} template against captured variables. Mirrors the H1/H2 syntax
// in engine.cpp: {{name}}, {{capture:name}}, {{header:name}}, {{cookie:name}}.
std::string render_capture_template(
    const std::string& input,
    const std::map<std::string, std::string>& captures) {
  if (input.find("{{") == std::string::npos) {
    return input;
  }
  std::string out;
  out.reserve(input.size());
  std::size_t pos = 0;
  while (pos < input.size()) {
    const std::size_t start = input.find("{{", pos);
    if (start == std::string::npos) {
      out.append(input, pos, std::string::npos);
      break;
    }
    out.append(input, pos, start - pos);
    const std::size_t end = input.find("}}", start + 2);
    if (end == std::string::npos) {
      out.append(input, start, std::string::npos);
      break;
    }
    std::string token = input.substr(start + 2, end - (start + 2));
    for (const char* prefix : {"capture:", "header:", "cookie:"}) {
      const std::size_t plen = std::char_traits<char>::length(prefix);
      if (token.rfind(prefix, 0) == 0) {
        token.erase(0, plen);
        break;
      }
    }
    const auto it = captures.find(token);
    if (it != captures.end()) {
      out.append(it->second);
    }
    pos = end + 2;
  }
  return out;
}

void apply_expect_op(Expectations* exp, const FlowOp& op) {
  if (exp == nullptr) {
    return;
  }
  if (op.opcode == "EXPECT_STATUS" && op.has_expect) {
    exp->status_min = std::max(100, op.expect.status_min);
    exp->status_max = std::max(exp->status_min, std::min(599, op.expect.status_max));
  } else if (op.opcode == "EXPECT_HEADER" && op.has_expect) {
    exp->has_header_expect = true;
    exp->header_name = op.expect.name;
    exp->header_value_contains = op.expect.value;
  } else if (op.opcode == "EXPECT_BODY_SUBSTRING" && op.has_expect) {
    if (op.expect.kind == "body_required") {
      exp->require_body = true;
    } else if (op.expect.kind == "body_min_bytes") {
      int min_body = 0;
      try {
        min_body = std::stoi(op.expect.value);
      } catch (...) {
        min_body = 0;
      }
      exp->min_body_bytes = static_cast<std::size_t>(std::max(0, min_body));
    } else {
      exp->has_body_expect = true;
      exp->body_substring = op.expect.value;
    }
  }
}

// Segment profile.ops into ordered scenario steps. Falls back to a single step
// derived from the whole profile when no SEND_HEADERS op is present, preserving
// the legacy single-request behaviour used by the H3 feature suites.
std::vector<ScenarioStep> derive_scenario_steps(const Profile& profile) {
  std::vector<ScenarioStep> steps;
  ScenarioStep current{};
  bool current_open = false;

  auto flush = [&]() {
    if (current_open) {
      if (current.request.path.empty()) {
        current.request.path = "/";
      }
      if (current.request.path.front() != '/') {
        current.request.path.insert(current.request.path.begin(), '/');
      }
      steps.push_back(std::move(current));
      current = ScenarioStep{};
      current_open = false;
    }
  };

  for (const auto& op : profile.ops) {
    if (op.opcode == "SEND_HEADERS") {
      flush();
      current_open = true;
      if (!op.method.empty()) {
        current.request.method = op.method;
      }
      if (!op.path.empty()) {
        current.request.path = op.path;
      }
      if (!op.headers.empty()) {
        current.request.headers.assign(op.headers.begin(), op.headers.end());
      }
    } else if (op.opcode == "SEND_BODY") {
      if (!current_open) {
        current_open = true;
      }
      if (!op.body.empty()) {
        current.request.body = op.body;
      }
    } else if (op.opcode == "EXPECT_STATUS" || op.opcode == "EXPECT_HEADER" ||
               op.opcode == "EXPECT_BODY_SUBSTRING") {
      if (current_open) {
        apply_expect_op(&current.expectations, op);
      }
    } else if (op.opcode == "CAPTURE_HEADER" || op.opcode == "CAPTURE_COOKIE" ||
               op.opcode == "CAPTURE_BODY_JSON") {
      if (current_open) {
        current.captures.push_back(
            ScenarioCaptureOp{op.opcode, op.capture_name, op.capture_source});
      }
    } else if (op.opcode == "THINK_TIME") {
      if (current_open) {
        current.think_time_ms += std::max(0, op.think_time_ms);
      }
    }
  }
  flush();

  if (steps.empty()) {
    ScenarioStep fallback{};
    fallback.request = derive_request_spec(profile);
    fallback.expectations = derive_expectations(profile);
    steps.push_back(std::move(fallback));
  }
  return steps;
}

// Materialise a concrete request for one step: templates are rendered against
// the running capture store and the accumulated cookie jar is injected as a
// Cookie header (unless the step already sets one).
RequestSpec render_scenario_request(
    const ScenarioStep& step,
    const std::map<std::string, std::string>& captures,
    const std::map<std::string, std::string>& cookie_jar) {
  RequestSpec out;
  out.method = render_capture_template(
      step.request.method.empty() ? std::string("GET") : step.request.method, captures);
  out.path = render_capture_template(
      step.request.path.empty() ? std::string("/") : step.request.path, captures);
  if (out.path.empty()) {
    out.path = "/";
  }
  if (out.path.front() != '/') {
    out.path.insert(out.path.begin(), '/');
  }

  bool has_cookie_header = false;
  for (const auto& hdr : step.request.headers) {
    if (hdr.first.empty()) {
      continue;
    }
    if (to_lower_ascii(hdr.first) == "cookie") {
      has_cookie_header = true;
    }
    out.headers.emplace_back(
        hdr.first, render_capture_template(hdr.second, captures));
  }
  if (!has_cookie_header && !cookie_jar.empty()) {
    std::string cookie_line;
    for (const auto& kv : cookie_jar) {
      if (!cookie_line.empty()) {
        cookie_line.append("; ");
      }
      cookie_line.append(kv.first);
      cookie_line.push_back('=');
      cookie_line.append(kv.second);
    }
    out.headers.emplace_back("cookie", cookie_line);
  }

  if (!step.request.body.empty()) {
    const std::string body_str(step.request.body.begin(), step.request.body.end());
    const std::string rendered = render_capture_template(body_str, captures);
    out.body.assign(rendered.begin(), rendered.end());
  }
  return out;
}

// Extract a single header value from the "name:value\n" response header buffer.
bool extract_response_header(
    const std::string& headers,
    const std::string& name,
    std::string* out_value) {
  if (name.empty()) {
    return false;
  }
  const std::string lowered = to_lower_ascii(headers);
  const std::string needle = to_lower_ascii(name) + ":";
  std::size_t pos = 0;
  while (pos <= lowered.size()) {
    const std::size_t at = lowered.find(needle, pos);
    if (at == std::string::npos) {
      return false;
    }
    if (at == 0 || lowered[at - 1] == '\n') {
      const std::size_t vstart = at + needle.size();
      const std::size_t line_end = headers.find('\n', vstart);
      std::string value = line_end == std::string::npos
          ? headers.substr(vstart)
          : headers.substr(vstart, line_end - vstart);
      // trim leading spaces
      std::size_t b = 0;
      while (b < value.size() && (value[b] == ' ' || value[b] == '\t')) {
        ++b;
      }
      if (out_value != nullptr) {
        *out_value = value.substr(b);
      }
      return true;
    }
    pos = at + needle.size();
  }
  return false;
}

// Parse a Set-Cookie value ("name=value; Path=/; ...") into the cookie jar.
void harvest_set_cookie(
    const std::string& cookie_line,
    const std::string& capture_name,
    std::map<std::string, std::string>* cookie_jar,
    std::map<std::string, std::string>* captures) {
  const std::size_t sep = cookie_line.find(';');
  const std::string pair = cookie_line.substr(0, sep);
  const std::size_t eq = pair.find('=');
  std::string name;
  std::string value;
  if (eq != std::string::npos) {
    name = pair.substr(0, eq);
    value = pair.substr(eq + 1);
  } else {
    value = pair;
  }
  // trim whitespace on name
  while (!name.empty() && (name.front() == ' ' || name.front() == '\t')) {
    name.erase(name.begin());
  }
  while (!name.empty() && (name.back() == ' ' || name.back() == '\t')) {
    name.pop_back();
  }
  if (cookie_jar != nullptr && !name.empty()) {
    (*cookie_jar)[name] = value;
  }
  if (captures != nullptr) {
    if (!capture_name.empty()) {
      (*captures)[capture_name] = eq != std::string::npos ? value : pair;
    } else if (!name.empty()) {
      (*captures)[name] = value;
    }
    (*captures)["set-cookie"] = pair;
  }
}

// Run the step's CAPTURE_* ops and always harvest Set-Cookie into the jar.
// Minimal JSON field extractor for CAPTURE_BODY_JSON (mirrors engine.cpp).
// `path` is a dotted key path (e.g. "accessToken" or "data.token").
bool extract_json_field(const std::string& body, const std::string& path, std::string* out) {
  std::size_t cursor = 0;
  std::size_t start = 0;
  const std::size_t n = path.size();
  bool matched_any = false;
  while (start <= n) {
    const std::size_t dot = path.find('.', start);
    const std::string key =
        path.substr(start, dot == std::string::npos ? std::string::npos : dot - start);
    if (key.empty()) {
      break;
    }
    const std::string needle = "\"" + key + "\"";
    const std::size_t at = body.find(needle, cursor);
    if (at == std::string::npos) {
      return false;
    }
    const std::size_t colon = body.find(':', at + needle.size());
    if (colon == std::string::npos) {
      return false;
    }
    cursor = colon + 1;
    matched_any = true;
    if (dot == std::string::npos) {
      break;
    }
    start = dot + 1;
  }
  if (!matched_any) {
    return false;
  }
  while (cursor < body.size() &&
         (body[cursor] == ' ' || body[cursor] == '\t' || body[cursor] == '\n' || body[cursor] == '\r')) {
    ++cursor;
  }
  if (cursor >= body.size()) {
    return false;
  }
  if (body[cursor] == '"') {
    ++cursor;
    std::string value;
    while (cursor < body.size()) {
      const char c = body[cursor];
      if (c == '\\' && cursor + 1 < body.size()) {
        const char esc = body[cursor + 1];
        value.push_back(esc == 'n' ? '\n' : (esc == 't' ? '\t' : esc));
        cursor += 2;
        continue;
      }
      if (c == '"') {
        break;
      }
      value.push_back(c);
      ++cursor;
    }
    if (out != nullptr) {
      *out = std::move(value);
    }
    return true;
  }
  std::size_t end = cursor;
  while (end < body.size()) {
    const char c = body[end];
    if (c == ',' || c == '}' || c == ']' || c == ' ' || c == '\t' || c == '\n' || c == '\r') {
      break;
    }
    ++end;
  }
  if (out != nullptr) {
    *out = body.substr(cursor, end - cursor);
  }
  return end > cursor;
}

void apply_scenario_captures(
    const ScenarioStep& step,
    const std::string& response_headers,
    const std::string& response_body,
    std::map<std::string, std::string>* captures,
    std::map<std::string, std::string>* cookie_jar) {
  std::string set_cookie;
  const bool have_set_cookie =
      extract_response_header(response_headers, "set-cookie", &set_cookie);
  for (const auto& cap : step.captures) {
    if (cap.opcode == "CAPTURE_HEADER") {
      const std::string source =
          cap.capture_source.empty() ? cap.capture_name : cap.capture_source;
      std::string value;
      if (extract_response_header(response_headers, source, &value) && captures != nullptr) {
        (*captures)[cap.capture_name.empty() ? to_lower_ascii(source) : cap.capture_name] = value;
      }
    } else if (cap.opcode == "CAPTURE_COOKIE") {
      if (have_set_cookie) {
        harvest_set_cookie(set_cookie, cap.capture_name, cookie_jar, captures);
      }
    } else if (cap.opcode == "CAPTURE_BODY_JSON") {
      const std::string path =
          cap.capture_source.empty() ? cap.capture_name : cap.capture_source;
      std::string value;
      if (!path.empty() && extract_json_field(response_body, path, &value) && captures != nullptr) {
        (*captures)[cap.capture_name.empty() ? path : cap.capture_name] = value;
      }
    }
  }
  // Even without an explicit CAPTURE_COOKIE, maintain the jar for state carry.
  if (have_set_cookie && step.captures.empty()) {
    harvest_set_cookie(set_cookie, "", cookie_jar, captures);
  }
}

GoawayPolicy derive_goaway_policy(const Profile& profile) {
  GoawayPolicy policy{};
  for (const auto& op : profile.ops) {
    if (op.opcode != "H3_GOAWAY") {
      continue;
    }
    policy.enabled = true;
    if (op.loop_count > 0) {
      policy.requests_per_connection = std::max(policy.requests_per_connection, op.loop_count);
    }
    if (op.has_expect) {
      if (op.expect.kind == "replace_mode" && op.expect.value == "now") {
        policy.replace_after_idle = false;
      } else if (op.expect.kind == "replace_mode" && op.expect.value == "after_idle") {
        policy.replace_after_idle = true;
      } else if (op.expect.kind == "requests_per_connection") {
        int parsed = 0;
        try {
          parsed = std::stoi(op.expect.value);
        } catch (...) {
          parsed = 0;
        }
        if (parsed > 0) {
          policy.requests_per_connection = std::max(policy.requests_per_connection, parsed);
        }
      }
    }
  }
  if (policy.enabled && policy.requests_per_connection <= 0) {
    policy.requests_per_connection = 1;
  }
  return policy;
}

void parse_priority_value(const std::string& value, uint32_t* urgency, int* incremental) {
  if (urgency == nullptr || incremental == nullptr) {
    return;
  }
  *urgency = 3;
  *incremental = 0;
  const std::string lower = to_lower_ascii(value);
  const std::size_t u = lower.find("u=");
  if (u != std::string::npos && u + 2 < lower.size()) {
    int parsed = 3;
    try {
      parsed = std::stoi(lower.substr(u + 2));
    } catch (...) {
      parsed = 3;
    }
    *urgency = static_cast<uint32_t>(std::clamp(parsed, 0, 7));
  }
  const std::size_t i = lower.find("i");
  if (i != std::string::npos) {
    *incremental = 1;
  }
}

H3FeaturePolicy derive_h3_feature_policy(const Profile& profile) {
  H3FeaturePolicy policy{};
  for (const auto& op : profile.ops) {
    if (op.opcode == "H3_QPACK_DYNAMIC") {
      policy.qpack_dynamic = true;
      continue;
    }
    if (op.opcode == "H3_PRIORITY_UPDATE") {
      policy.priority_update = true;
      if (op.has_expect && op.expect.kind == "priority_value" && !op.expect.value.empty()) {
        policy.priority_value = op.expect.value;
      }
      parse_priority_value(policy.priority_value, &policy.priority_urgency, &policy.priority_incremental);
      continue;
    }
    if (op.opcode == "H3_EXTENDED_CONNECT") {
      policy.extended_connect = true;
      if (op.has_expect && op.expect.kind == "protocol" && !op.expect.value.empty()) {
        policy.connect_protocol = op.expect.value;
      }
      continue;
    }
    if (op.opcode == "H3_DATAGRAM") {
      policy.datagram = true;
      if (op.has_expect && op.expect.kind == "flow_id" && !op.expect.value.empty()) {
        policy.datagram_flow_id = op.expect.value;
      }
      continue;
    }
    if (op.opcode == "H3_SERVER_PUSH") {
      policy.server_push = true;
      if (op.has_expect && !op.expect.kind.empty() && !op.expect.value.empty()) {
        if (op.expect.kind == "hint") {
          policy.server_push_hint = to_lower_ascii(op.expect.value);
        } else if (op.expect.kind == "max_push_id") {
          uint64_t parsed = policy.max_push_id;
          if (parse_u64_str(op.expect.value, &parsed)) {
            policy.max_push_id = std::min<uint64_t>(parsed, ((1ull << 62u) - 1u));
          }
        } else if ((op.expect.kind == "cancel_mode" || op.expect.kind == "cancel_policy") &&
            to_lower_ascii(op.expect.value) == "on_promise") {
          policy.cancel_on_promise = true;
        }
      }
      continue;
    }
  }
  if (policy.priority_update) {
    parse_priority_value(policy.priority_value, &policy.priority_urgency, &policy.priority_incremental);
  }
  if (policy.server_push_hint == "cancel") {
    policy.cancel_on_promise = true;
  }
  return policy;
}

int parse_status_code(const std::string& text) {
  int code = 0;
  for (char ch : text) {
    if (ch >= '0' && ch <= '9') {
      code = code * 10 + static_cast<int>(ch - '0');
      if (code > 9999) {
        break;
      }
    } else if (code > 0) {
      break;
    }
  }
  return code;
}

constexpr uint64_t kH3StreamTypeControl = 0x00;
constexpr uint64_t kH3StreamTypePush = 0x01;
constexpr uint64_t kH3FrameTypeCancelPush = 0x03;
constexpr uint64_t kH3FrameTypePushPromise = 0x05;
constexpr uint64_t kH3FrameTypeGoaway = 0x07;
constexpr uint64_t kH3FrameTypeMaxPushId = 0x0d;
constexpr std::size_t kH3ParseBufferCap = 1u << 20u;  // 1 MiB safety cap.

bool is_server_uni_stream(int64_t stream_id) {
  return (stream_id & 0x3ll) == 0x3ll;
}

bool try_decode_quic_varint(
    const uint8_t* data,
    std::size_t len,
    uint64_t* out,
    std::size_t* consumed) {
  if (data == nullptr || out == nullptr || consumed == nullptr || len == 0) {
    return false;
  }
  const uint8_t first = data[0];
  const uint8_t prefix = static_cast<uint8_t>(first >> 6u);
  const std::size_t nbytes = static_cast<std::size_t>(1u << prefix);
  if (len < nbytes) {
    return false;
  }
  uint64_t v = static_cast<uint64_t>(first & 0x3fu);
  for (std::size_t i = 1; i < nbytes; ++i) {
    v = (v << 8u) | static_cast<uint64_t>(data[i]);
  }
  *out = v;
  *consumed = nbytes;
  return true;
}

bool append_quic_varint(std::vector<uint8_t>* out, uint64_t v) {
  if (out == nullptr || v > ((1ull << 62u) - 1u)) {
    return false;
  }
  if (v <= 0x3fu) {
    out->push_back(static_cast<uint8_t>(v));
    return true;
  }
  if (v <= 0x3fffu) {
    out->push_back(static_cast<uint8_t>(0x40u | ((v >> 8u) & 0x3fu)));
    out->push_back(static_cast<uint8_t>(v & 0xffu));
    return true;
  }
  if (v <= 0x3fffffffu) {
    out->push_back(static_cast<uint8_t>(0x80u | ((v >> 24u) & 0x3fu)));
    out->push_back(static_cast<uint8_t>((v >> 16u) & 0xffu));
    out->push_back(static_cast<uint8_t>((v >> 8u) & 0xffu));
    out->push_back(static_cast<uint8_t>(v & 0xffu));
    return true;
  }
  out->push_back(static_cast<uint8_t>(0xc0u | ((v >> 56u) & 0x3fu)));
  out->push_back(static_cast<uint8_t>((v >> 48u) & 0xffu));
  out->push_back(static_cast<uint8_t>((v >> 40u) & 0xffu));
  out->push_back(static_cast<uint8_t>((v >> 32u) & 0xffu));
  out->push_back(static_cast<uint8_t>((v >> 24u) & 0xffu));
  out->push_back(static_cast<uint8_t>((v >> 16u) & 0xffu));
  out->push_back(static_cast<uint8_t>((v >> 8u) & 0xffu));
  out->push_back(static_cast<uint8_t>(v & 0xffu));
  return true;
}

bool queue_h3_varint_frame(Ngtcp2AttemptCtx* ctx, uint64_t frame_type, uint64_t payload_value) {
  if (ctx == nullptr || ctx->ctrl_stream_id < 0) {
    return false;
  }
  if (ctx->control_tx_off >= ctx->control_tx_buffer.size()) {
    ctx->control_tx_buffer.clear();
    ctx->control_tx_off = 0;
  }
  std::vector<uint8_t> payload{};
  if (!append_quic_varint(&payload, payload_value)) {
    return false;
  }
  std::vector<uint8_t> frame{};
  frame.reserve(16);
  if (!append_quic_varint(&frame, frame_type)) {
    return false;
  }
  if (!append_quic_varint(&frame, static_cast<uint64_t>(payload.size()))) {
    return false;
  }
  frame.insert(frame.end(), payload.begin(), payload.end());
  ctx->control_tx_buffer.insert(ctx->control_tx_buffer.end(), frame.begin(), frame.end());
  return true;
}

bool queue_max_push_id_frame(Ngtcp2AttemptCtx* ctx, uint64_t max_push_id) {
  if (ctx == nullptr) {
    return false;
  }
  if (ctx->max_push_id_sent && max_push_id < ctx->max_push_id_sent_value) {
    ctx->feature_failures += 1;
    return false;
  }
  if (ctx->max_push_id_sent && max_push_id == ctx->max_push_id_sent_value) {
    return true;
  }
  if (!queue_h3_varint_frame(ctx, kH3FrameTypeMaxPushId, max_push_id)) {
    return false;
  }
  ctx->max_push_id_sent = true;
  ctx->max_push_id_sent_value = max_push_id;
  return true;
}

bool queue_cancel_push_frame(Ngtcp2AttemptCtx* ctx, uint64_t push_id) {
  if (ctx == nullptr) {
    return false;
  }
  if (!ctx->cancel_push_tx_sent.insert(push_id).second) {
    return true;
  }
  if (queue_h3_varint_frame(ctx, kH3FrameTypeCancelPush, push_id)) {
    return true;
  }
  ctx->cancel_push_tx_sent.erase(push_id);
  return false;
}

void append_parse_bytes(H3FrameParseState* state, const uint8_t* data, std::size_t datalen) {
  if (state == nullptr || data == nullptr || datalen == 0) {
    return;
  }
  state->buffer.insert(state->buffer.end(), data, data + datalen);
  if (state->buffer.size() > kH3ParseBufferCap) {
    const std::size_t drop = state->buffer.size() - kH3ParseBufferCap;
    state->buffer.erase(state->buffer.begin(), state->buffer.begin() + static_cast<std::ptrdiff_t>(drop));
  }
}

void note_push_promise(Ngtcp2AttemptCtx* ctx, uint64_t push_id) {
  if (ctx == nullptr) {
    return;
  }
  ctx->saw_server_push_signal = true;
  if (!ctx->max_push_id_set || push_id > ctx->max_push_id_advertised) {
    ctx->feature_failures += 1;
    return;
  }
  ctx->promised_push_ids.insert(push_id);
  if (ctx->feature_policy.cancel_on_promise) {
    ctx->canceled_push_ids.insert(push_id);
    if (!queue_cancel_push_frame(ctx, push_id)) {
      ctx->feature_failures += 1;
    }
  }
}

void note_push_stream(Ngtcp2AttemptCtx* ctx, uint64_t push_id) {
  if (ctx == nullptr) {
    return;
  }
  if (!ctx->max_push_id_set || push_id > ctx->max_push_id_advertised) {
    ctx->feature_failures += 1;
    return;
  }
  if (!ctx->promised_push_ids.empty() && ctx->promised_push_ids.find(push_id) == ctx->promised_push_ids.end()) {
    ctx->feature_failures += 1;
    return;
  }
  if (ctx->canceled_push_ids.find(push_id) != ctx->canceled_push_ids.end()) {
    return;
  }
  if (ctx->fulfilled_push_ids.insert(push_id).second) {
    ctx->saw_server_push_signal = true;
    ctx->server_push_events += 1;
  }
}

void note_cancel_push(Ngtcp2AttemptCtx* ctx, uint64_t push_id) {
  if (ctx == nullptr) {
    return;
  }
  if (!ctx->max_push_id_set || push_id > ctx->max_push_id_advertised) {
    ctx->feature_failures += 1;
    return;
  }
  ctx->canceled_push_ids.insert(push_id);
}

void note_max_push_id(Ngtcp2AttemptCtx* ctx, uint64_t push_id) {
  if (ctx == nullptr) {
    return;
  }
  if (!ctx->max_push_id_set) {
    ctx->max_push_id_advertised = push_id;
    ctx->max_push_id_set = true;
    return;
  }
  if (push_id < ctx->max_push_id_advertised) {
    ctx->feature_failures += 1;
    return;
  }
  ctx->max_push_id_advertised = push_id;
}

void parse_h3_frame_events(Ngtcp2AttemptCtx* ctx, int64_t stream_id, H3FrameParseState* state) {
  if (ctx == nullptr || state == nullptr) {
    return;
  }
  if (!state->initialized) {
    state->initialized = true;
    state->is_server_uni = is_server_uni_stream(stream_id);
  }

  if (state->is_server_uni && !state->stream_type_known) {
    uint64_t stream_type = 0;
    std::size_t stream_type_len = 0;
    if (!try_decode_quic_varint(state->buffer.data(), state->buffer.size(), &stream_type, &stream_type_len)) {
      return;
    }
    state->stream_type = stream_type;
    state->stream_type_known = true;
    state->buffer.erase(
        state->buffer.begin(),
        state->buffer.begin() + static_cast<std::ptrdiff_t>(stream_type_len));
  }

  if (state->is_server_uni && state->stream_type == kH3StreamTypePush && !state->push_id_known) {
    uint64_t push_id = 0;
    std::size_t push_id_len = 0;
    if (!try_decode_quic_varint(state->buffer.data(), state->buffer.size(), &push_id, &push_id_len)) {
      return;
    }
    state->push_id = push_id;
    state->push_id_known = true;
    state->buffer.erase(
        state->buffer.begin(),
        state->buffer.begin() + static_cast<std::ptrdiff_t>(push_id_len));
    note_push_stream(ctx, push_id);
  }

  if (state->is_server_uni && state->stream_type != kH3StreamTypeControl && state->stream_type != kH3StreamTypePush) {
    return;
  }

  for (;;) {
    if (state->buffer.empty()) {
      return;
    }
    uint64_t frame_type = 0;
    uint64_t frame_len = 0;
    std::size_t frame_type_len = 0;
    std::size_t frame_len_len = 0;
    if (!try_decode_quic_varint(state->buffer.data(), state->buffer.size(), &frame_type, &frame_type_len)) {
      return;
    }
    if (!try_decode_quic_varint(
            state->buffer.data() + static_cast<std::ptrdiff_t>(frame_type_len),
            state->buffer.size() - frame_type_len,
            &frame_len,
            &frame_len_len)) {
      return;
    }
    const std::size_t header_len = frame_type_len + frame_len_len;
    const std::size_t payload_len = static_cast<std::size_t>(frame_len);
    if (payload_len > state->buffer.size() - header_len) {
      return;
    }
    const uint8_t* payload = state->buffer.data() + static_cast<std::ptrdiff_t>(header_len);
    if (frame_type == kH3FrameTypePushPromise && payload_len > 0) {
      uint64_t push_id = 0;
      std::size_t push_id_len = 0;
      if (try_decode_quic_varint(payload, payload_len, &push_id, &push_id_len) && push_id_len <= payload_len) {
        note_push_promise(ctx, push_id);
      } else {
        ctx->feature_failures += 1;
      }
    } else if (frame_type == kH3FrameTypeCancelPush && payload_len > 0) {
      uint64_t push_id = 0;
      std::size_t push_id_len = 0;
      if (try_decode_quic_varint(payload, payload_len, &push_id, &push_id_len) && push_id_len <= payload_len) {
        note_cancel_push(ctx, push_id);
      } else {
        ctx->feature_failures += 1;
      }
    } else if (frame_type == kH3FrameTypeMaxPushId && payload_len > 0) {
      uint64_t push_id = 0;
      std::size_t push_id_len = 0;
      if (try_decode_quic_varint(payload, payload_len, &push_id, &push_id_len) && push_id_len <= payload_len) {
        note_max_push_id(ctx, push_id);
      } else {
        ctx->feature_failures += 1;
      }
    } else if (frame_type == kH3FrameTypeGoaway && payload_len > 0) {
      uint64_t id = 0;
      std::size_t id_len = 0;
      if (try_decode_quic_varint(payload, payload_len, &id, &id_len) && id_len <= payload_len) {
        // Real GOAWAY observation: count once even if nghttp3 shutdown cb also fires.
        if (!ctx->goaway_active) {
          ctx->goaway_events += 1;
          ctx->drain_cycles += 1;
        }
        ctx->goaway_last_stream_id = static_cast<int64_t>(id);
        ctx->goaway_active = true;
      }
    }
    state->buffer.erase(
        state->buffer.begin(),
        state->buffer.begin() + static_cast<std::ptrdiff_t>(header_len + payload_len));
  }
}

int get_new_connection_id_cb(
    ngtcp2_conn* conn,
    ngtcp2_cid* cid,
    uint8_t* token,
    size_t cidlen,
    void* user_data) {
  (void)conn;
  (void)user_data;
  if (rand_fill(cid->data, cidlen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  cid->datalen = cidlen;
  if (rand_fill(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

int handshake_completed_cb(ngtcp2_conn* conn, void* user_data) {
  (void)conn;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(user_data);
  if (ctx != nullptr) {
    ctx->handshake_done = true;
  }
  return 0;
}

nghttp3_nv make_nv(std::string_view name, std::string_view value) {
  nghttp3_nv nv{};
  nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(name.data()));
  nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(value.data()));
  nv.namelen = name.size();
  nv.valuelen = value.size();
  nv.flags = NGHTTP3_NV_FLAG_NONE;
  return nv;
}

nghttp3_ssize read_data_cb(
    nghttp3_conn* conn,
    int64_t stream_id,
    nghttp3_vec* vec,
    size_t veccnt,
    uint32_t* pflags,
    void* conn_user_data,
    void* stream_user_data) {
  (void)conn;
  (void)stream_user_data;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(conn_user_data);
  if (ctx == nullptr || vec == nullptr || veccnt == 0 || pflags == nullptr) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  std::size_t* body_off_ptr = &ctx->req_body_off;
  if (ctx->pipelined_mode) {
    auto it = ctx->active_streams.find(stream_id);
    if (it != ctx->active_streams.end()) {
      body_off_ptr = &it->second.req_body_off;
    }
  }
  if (*body_off_ptr >= ctx->request.body.size()) {
    *pflags |= NGHTTP3_DATA_FLAG_EOF;
    return 0;
  }
  vec[0].base = reinterpret_cast<uint8_t*>(ctx->request.body.data() + *body_off_ptr);
  vec[0].len = ctx->request.body.size() - *body_off_ptr;
  *body_off_ptr = ctx->request.body.size();
  *pflags |= NGHTTP3_DATA_FLAG_EOF;
  return 1;
}

int http_acked_stream_data_cb(
    nghttp3_conn* conn,
    int64_t stream_id,
    uint64_t datalen,
    void* conn_user_data,
    void* stream_user_data) {
  (void)conn;
  (void)stream_id;
  (void)datalen;
  (void)conn_user_data;
  (void)stream_user_data;
  return 0;
}

int http_stream_close_cb(
    nghttp3_conn* conn,
    int64_t stream_id,
    uint64_t app_error_code,
    void* conn_user_data,
    void* stream_user_data) {
  (void)conn;
  (void)app_error_code;
  (void)stream_user_data;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(conn_user_data);
  if (ctx == nullptr) {
    return 0;
  }
  if (ctx->pipelined_mode) {
    auto it = ctx->active_streams.find(stream_id);
    if (it != ctx->active_streams.end()) {
      it->second.response_complete = true;
      ctx->completed_streams.push_back(std::move(it->second));
      ctx->active_streams.erase(it);
    }
    return 0;
  }
  if (stream_id == ctx->request_stream_id) {
    ctx->response_complete = true;
  }
  return 0;
}

int http_recv_data_cb(
    nghttp3_conn* conn,
    int64_t stream_id,
    const uint8_t* data,
    size_t datalen,
    void* conn_user_data,
    void* stream_user_data) {
  (void)conn;
  (void)stream_user_data;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(conn_user_data);
  if (ctx == nullptr) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  if (datalen > 0 && data != nullptr) {
    ctx->received_any_stream_data = true;
    ctx->rx_bytes += datalen;
    if (ctx->pipelined_mode) {
      auto it = ctx->active_streams.find(stream_id);
      if (it != ctx->active_streams.end()) {
        auto& st = it->second;
        st.has_body_data = true;
        if ((ctx->expectations.has_body_expect || ctx->expectations.min_body_bytes > 0) &&
            st.response_body.size() < 131072) {
          const std::size_t cap_left = 131072 - st.response_body.size();
          const std::size_t ncopy = std::min(cap_left, datalen);
          st.response_body.append(reinterpret_cast<const char*>(data), ncopy);
        }
      }
    } else if (ctx->response_body.size() < 131072) {
      const std::size_t cap_left = 131072 - ctx->response_body.size();
      const std::size_t ncopy = std::min(cap_left, datalen);
      ctx->response_body.append(reinterpret_cast<const char*>(data), ncopy);
    }
  }
  if (ctx->conn != nullptr && datalen > 0) {
    (void)ngtcp2_conn_extend_max_stream_offset(ctx->conn, stream_id, static_cast<uint64_t>(datalen));
    ngtcp2_conn_extend_max_offset(ctx->conn, static_cast<uint64_t>(datalen));
  }
  return 0;
}

int http_deferred_consume_cb(
    nghttp3_conn* conn,
    int64_t stream_id,
    size_t consumed,
    void* conn_user_data,
    void* stream_user_data) {
  (void)conn;
  (void)stream_user_data;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(conn_user_data);
  if (ctx == nullptr || ctx->conn == nullptr || consumed == 0) {
    return 0;
  }
  (void)ngtcp2_conn_extend_max_stream_offset(ctx->conn, stream_id, static_cast<uint64_t>(consumed));
  ngtcp2_conn_extend_max_offset(ctx->conn, static_cast<uint64_t>(consumed));
  return 0;
}

int http_begin_headers_cb(
    nghttp3_conn* conn,
    int64_t stream_id,
    void* conn_user_data,
    void* stream_user_data) {
  (void)conn;
  (void)stream_id;
  (void)conn_user_data;
  (void)stream_user_data;
  return 0;
}

int http_recv_header_cb(
    nghttp3_conn* conn,
    int64_t stream_id,
    int32_t token,
    nghttp3_rcbuf* name,
    nghttp3_rcbuf* value,
    uint8_t flags,
    void* conn_user_data,
    void* stream_user_data) {
  (void)conn;
  (void)stream_id;
  (void)flags;
  (void)stream_user_data;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(conn_user_data);
  if (ctx == nullptr || name == nullptr || value == nullptr) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  const nghttp3_vec nbuf = nghttp3_rcbuf_get_buf(name);
  const nghttp3_vec vbuf = nghttp3_rcbuf_get_buf(value);
  if (ctx->pipelined_mode) {
    auto it = ctx->active_streams.find(stream_id);
    if (it != ctx->active_streams.end()) {
      auto& st = it->second;
      st.response_headers_seen = true;
      if (ctx->expectations.has_header_expect && st.response_headers.size() < 131072) {
        st.response_headers.append(reinterpret_cast<const char*>(nbuf.base), nbuf.len);
        st.response_headers.push_back(':');
        st.response_headers.append(reinterpret_cast<const char*>(vbuf.base), vbuf.len);
        st.response_headers.push_back('\n');
      }
      if (token == NGHTTP3_QPACK_TOKEN__STATUS ||
          (nbuf.len == 7 && std::memcmp(nbuf.base, ":status", 7) == 0)) {
        std::string v(reinterpret_cast<const char*>(vbuf.base), vbuf.len);
        st.response_status = parse_status_code(v);
      }
    }
    return 0;
  }
  std::string n(reinterpret_cast<const char*>(nbuf.base), nbuf.len);
  std::string v(reinterpret_cast<const char*>(vbuf.base), vbuf.len);
  const std::string lower_n = to_lower_ascii(n);
  const std::string lower_v = to_lower_ascii(v);
  ctx->response_headers_seen = true;
  if (ctx->response_headers.size() < 131072) {
    ctx->response_headers.append(n);
    ctx->response_headers.push_back(':');
    ctx->response_headers.append(v);
    ctx->response_headers.push_back('\n');
  }
  if (token == NGHTTP3_QPACK_TOKEN__STATUS || n == ":status") {
    ctx->response_status = parse_status_code(v);
  }
  if (ctx->feature_policy.priority_update && lower_n == "priority") {
    if (lower_v.find(to_lower_ascii(ctx->feature_policy.priority_value)) != std::string::npos) {
      ctx->saw_priority_ack = true;
    }
  }
  if (ctx->feature_policy.extended_connect && lower_n == ":protocol") {
    if (lower_v == to_lower_ascii(ctx->feature_policy.connect_protocol)) {
      ctx->saw_extended_connect_ack = true;
    }
  }
  if (ctx->feature_policy.datagram && lower_n == "capsule-protocol" && lower_v.find("?1") != std::string::npos) {
    ctx->saw_datagram_ack = true;
  }
  if (ctx->feature_policy.server_push) {
    if ((lower_n == "link" && lower_v.find("rel=preload") != std::string::npos) ||
        (lower_n == "x-http3-push" && (lower_v == "1" || lower_v == "true"))) {
      ctx->saw_server_push_signal = true;
    }
  }
  return 0;
}

int http_end_headers_cb(
    nghttp3_conn* conn,
    int64_t stream_id,
    int fin,
    void* conn_user_data,
    void* stream_user_data) {
  (void)conn;
  (void)stream_id;
  (void)conn_user_data;
  (void)stream_user_data;
  (void)fin;
  return 0;
}

int http_stop_sending_cb(
    nghttp3_conn* conn,
    int64_t stream_id,
    uint64_t app_error_code,
    void* conn_user_data,
    void* stream_user_data) {
  (void)conn;
  (void)stream_user_data;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(conn_user_data);
  if (ctx == nullptr || ctx->conn == nullptr) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  if (ngtcp2_conn_shutdown_stream_read(ctx->conn, stream_id, app_error_code) != 0) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

int http_end_stream_cb(
    nghttp3_conn* conn,
    int64_t stream_id,
    void* conn_user_data,
    void* stream_user_data) {
  (void)conn;
  (void)stream_user_data;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(conn_user_data);
  if (ctx == nullptr) {
    return 0;
  }
  if (ctx->pipelined_mode) {
    auto it = ctx->active_streams.find(stream_id);
    if (it != ctx->active_streams.end()) {
      it->second.response_complete = true;
      ctx->completed_streams.push_back(std::move(it->second));
      ctx->active_streams.erase(it);
    }
    return 0;
  }
  if (stream_id == ctx->request_stream_id) {
    ctx->response_complete = true;
  }
  return 0;
}

int http_reset_stream_cb(
    nghttp3_conn* conn,
    int64_t stream_id,
    uint64_t app_error_code,
    void* conn_user_data,
    void* stream_user_data) {
  (void)conn;
  (void)stream_user_data;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(conn_user_data);
  if (ctx == nullptr || ctx->conn == nullptr) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  if (ngtcp2_conn_shutdown_stream_write(ctx->conn, stream_id, app_error_code) != 0) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

int http_shutdown_cb(
    nghttp3_conn* conn,
    int64_t id,
    void* conn_user_data) {
  (void)conn;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(conn_user_data);
  if (ctx != nullptr) {
    if (!ctx->goaway_active) {
      ctx->goaway_events += 1;
      ctx->drain_cycles += 1;
    }
    ctx->goaway_active = true;
    ctx->goaway_last_stream_id = id;
  }
  return 0;
}

int recv_stream_data_cb(
    ngtcp2_conn* conn,
    uint32_t flags,
    int64_t stream_id,
    uint64_t offset,
    const uint8_t* data,
    size_t datalen,
    void* user_data,
    void* stream_user_data) {
  (void)conn;
  (void)offset;
  (void)stream_user_data;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(user_data);
  if (ctx == nullptr || ctx->h3_conn == nullptr) {
    return 0;
  }
  if (data != nullptr && datalen > 0) {
    const bool is_server_uni = (stream_id >= 0) && ((stream_id & 0x3) == 0x3);
    if (!ctx->pipelined_mode || is_server_uni || ctx->feature_policy.server_push) {
      auto& state = ctx->frame_parse_states[stream_id];
      append_parse_bytes(&state, data, datalen);
      parse_h3_frame_events(ctx, stream_id, &state);
    }

    // QPACK dynamic-table activity: encoder/decoder uni-stream bytes imply inserts;
    // over capacity approximates eviction pressure for parity metrics.
    const bool local_qpack_stream =
        stream_id == ctx->qpack_enc_stream_id || stream_id == ctx->qpack_dec_stream_id;
    const bool remote_qpack_encoder =
        ctx->h3_conn != nullptr && nghttp3_conn_is_remote_qpack_encoder_stream(ctx->h3_conn, stream_id);
    if (ctx->feature_policy.qpack_dynamic && (local_qpack_stream || remote_qpack_encoder)) {
      ctx->saw_qpack_activity = true;
      if (remote_qpack_encoder || stream_id == ctx->qpack_enc_stream_id) {
        ctx->qpack_decoder_inserts += 1;
      } else {
        ctx->qpack_encoder_inserts += 1;
      }
      ctx->qpack_dtable_bytes += datalen;
      constexpr std::size_t kQpackCapacity = 4096u;
      if (ctx->qpack_dtable_bytes > kQpackCapacity) {
        ctx->qpack_evictions += 1;
        ctx->qpack_dtable_bytes = kQpackCapacity / 2u;
      }
    }
  }
  if ((flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0 && !ctx->frame_parse_states.empty()) {
    ctx->frame_parse_states.erase(stream_id);
  }
  const int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0 ? 1 : 0;
  const nghttp3_ssize nconsumed = nghttp3_conn_read_stream(
      ctx->h3_conn,
      stream_id,
      data == nullptr ? reinterpret_cast<const uint8_t*>("") : data,
      datalen,
      fin);
  if (nconsumed < 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  if (nconsumed > 0 && ctx->conn != nullptr) {
    (void)ngtcp2_conn_extend_max_stream_offset(ctx->conn, stream_id, static_cast<uint64_t>(nconsumed));
    ngtcp2_conn_extend_max_offset(ctx->conn, static_cast<uint64_t>(nconsumed));
  }
  return 0;
}

int acked_stream_data_offset_cb(
    ngtcp2_conn* conn,
    int64_t stream_id,
    uint64_t offset,
    uint64_t datalen,
    void* user_data,
    void* stream_user_data) {
  (void)conn;
  (void)offset;
  (void)stream_user_data;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(user_data);
  if (ctx == nullptr || ctx->h3_conn == nullptr) {
    return 0;
  }
  if (nghttp3_conn_add_ack_offset(ctx->h3_conn, stream_id, datalen) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

int stream_close_cb(
    ngtcp2_conn* conn,
    uint32_t flags,
    int64_t stream_id,
    uint64_t app_error_code,
    void* user_data,
    void* stream_user_data) {
  (void)conn;
  (void)flags;
  (void)stream_user_data;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(user_data);
  if (ctx == nullptr || ctx->h3_conn == nullptr) {
    return 0;
  }
  (void)nghttp3_conn_close_stream(ctx->h3_conn, stream_id, app_error_code);
  return 0;
}

int recv_datagram_cb(
    ngtcp2_conn* conn,
    uint32_t flags,
    const uint8_t* data,
    size_t datalen,
    void* user_data) {
  (void)conn;
  (void)flags;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(user_data);
  if (ctx == nullptr || data == nullptr || datalen == 0) {
    return 0;
  }
  ctx->saw_datagram_ack = true;
  ctx->datagram_rx_events += 1;
  return 0;
}

int ack_datagram_cb(ngtcp2_conn* conn, uint64_t dgram_id, void* user_data) {
  (void)conn;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(user_data);
  if (ctx == nullptr) {
    return 0;
  }
  ctx->last_datagram_id = dgram_id;
  ctx->saw_datagram_ack = true;
  return 0;
}

int lost_datagram_cb(ngtcp2_conn* conn, uint64_t dgram_id, void* user_data) {
  (void)conn;
  auto* ctx = static_cast<Ngtcp2AttemptCtx*>(user_data);
  if (ctx == nullptr) {
    return 0;
  }
  ctx->last_datagram_id = dgram_id;
  ctx->feature_failures += 1;
  return 0;
}

bool configure_gnutls_session(
    Ngtcp2AttemptCtx* ctx,
    const std::string& sni_name,
    bool verify_peer,
    const TlsSessionCache* session_cache) {
  (void)verify_peer;
  if (ctx == nullptr) {
    return false;
  }
  if (gnutls_certificate_allocate_credentials(&ctx->cred) != 0) {
    return false;
  }
  (void)gnutls_certificate_set_x509_system_trust(ctx->cred);
  if (gnutls_init(
          &ctx->session,
          GNUTLS_CLIENT | GNUTLS_ENABLE_EARLY_DATA | GNUTLS_NO_END_OF_EARLY_DATA) != 0) {
    return false;
  }
  if (ngtcp2_crypto_gnutls_configure_client_session(ctx->session) != 0) {
    return false;
  }

  static const char kPriority[] =
      "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:"
      "+CHACHA20-POLY1305:+AES-128-CCM:-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:"
      "+GROUP-SECP384R1:+GROUP-SECP521R1:%DISABLE_TLS13_COMPAT_MODE";
  if (gnutls_priority_set_direct(ctx->session, kPriority, nullptr) != 0) {
    return false;
  }
  static const gnutls_datum_t kAlpn = {
      reinterpret_cast<unsigned char*>(const_cast<char*>("h3")),
      2,
  };
  (void)gnutls_alpn_set_protocols(ctx->session, &kAlpn, 1, GNUTLS_ALPN_MANDATORY);
  gnutls_session_set_ptr(ctx->session, &ctx->conn_ref);
  if (gnutls_credentials_set(ctx->session, GNUTLS_CRD_CERTIFICATE, ctx->cred) != 0) {
    return false;
  }
  if (!sni_name.empty()) {
    (void)gnutls_server_name_set(
        ctx->session,
        GNUTLS_NAME_DNS,
        sni_name.data(),
        sni_name.size());
  }
  if (session_cache != nullptr && !session_cache->blob.empty()) {
    ctx->tls_session_resume_attempted = true;
    ctx->tls_session_resume_applied = apply_tls_session_cache(ctx->session, session_cache);
  }
  return true;
}

bool verify_peer_certificate(
    Ngtcp2AttemptCtx* ctx,
    const std::string& verify_name,
    bool verify_peer) {
  if (!verify_peer) {
    return true;
  }
  if (ctx == nullptr || ctx->session == nullptr) {
    return false;
  }
  unsigned int status = 0;
  const char* verify_host = verify_name.empty() ? nullptr : verify_name.c_str();
  const int rc = gnutls_certificate_verify_peers3(ctx->session, verify_host, &status);
  if (rc != 0) {
    return false;
  }
  return status == 0;
}

bool init_quic_conn(Ngtcp2AttemptCtx* ctx) {
  if (ctx == nullptr) {
    return false;
  }

  ngtcp2_path path{};
  path.local.addr = reinterpret_cast<sockaddr*>(&ctx->local_addr);
  path.local.addrlen = ctx->local_addrlen;
  path.remote.addr = reinterpret_cast<sockaddr*>(&ctx->remote_addr);
  path.remote.addrlen = ctx->remote_addrlen;

  ngtcp2_cid dcid{};
  dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
  if (ctx->has_precomputed_cids) {
    std::memcpy(dcid.data, ctx->precomputed_dcid.data(), 8);
  } else if (rand_fill(dcid.data, dcid.datalen) != 0) {
    return false;
  }
  ngtcp2_cid scid{};
  scid.datalen = 8;
  if (ctx->has_precomputed_cids) {
    std::memcpy(scid.data, ctx->precomputed_scid.data(), 8);
  } else if (rand_fill(scid.data, scid.datalen) != 0) {
    return false;
  }

  ngtcp2_settings settings{};
  ngtcp2_settings_default(&settings);
  settings.initial_ts = now_ns();

  ngtcp2_transport_params params{};
  ngtcp2_transport_params_default(&params);
  params.initial_max_streams_uni = 16;
  params.initial_max_streams_bidi = 1024;
  params.initial_max_stream_data_bidi_local = 2 * 1024 * 1024;
  params.initial_max_stream_data_bidi_remote = 2 * 1024 * 1024;
  params.initial_max_data = 16 * 1024 * 1024;
  params.max_datagram_frame_size = 1200;

  ngtcp2_callbacks callbacks{};
  callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
  callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
  callbacks.handshake_completed = handshake_completed_cb;
  callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
  callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
  callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
  callbacks.recv_stream_data = recv_stream_data_cb;
  callbacks.acked_stream_data_offset = acked_stream_data_offset_cb;
  callbacks.stream_close = stream_close_cb;
  callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
  callbacks.rand = rand_cb;
  callbacks.update_key = ngtcp2_crypto_update_key_cb;
  callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
  callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
  callbacks.recv_datagram = recv_datagram_cb;
  callbacks.ack_datagram = ack_datagram_cb;
  callbacks.lost_datagram = lost_datagram_cb;
  callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
  callbacks.get_new_connection_id = get_new_connection_id_cb;
  callbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;

  const int rv = ngtcp2_conn_client_new(
      &ctx->conn,
      &dcid,
      &scid,
      &path,
      NGTCP2_PROTO_VER_V1,
      &callbacks,
      &settings,
      &params,
      nullptr,
      ctx);
  if (rv != 0 || ctx->conn == nullptr) {
    return false;
  }
  ctx->conn_ref.get_conn = get_conn;
  ctx->conn_ref.user_data = ctx;
  ngtcp2_conn_set_tls_native_handle(ctx->conn, ctx->session);
  return true;
}

bool init_h3_session(Ngtcp2AttemptCtx* ctx) {
  if (ctx == nullptr || ctx->conn == nullptr || ctx->h3_ready) {
    return false;
  }

  nghttp3_callbacks h3_callbacks{};
  h3_callbacks.acked_stream_data = http_acked_stream_data_cb;
  h3_callbacks.stream_close = http_stream_close_cb;
  h3_callbacks.recv_data = http_recv_data_cb;
  h3_callbacks.deferred_consume = http_deferred_consume_cb;
  h3_callbacks.begin_headers = http_begin_headers_cb;
  h3_callbacks.recv_header = http_recv_header_cb;
  h3_callbacks.end_headers = http_end_headers_cb;
  h3_callbacks.begin_trailers = http_begin_headers_cb;
  h3_callbacks.recv_trailer = http_recv_header_cb;
  h3_callbacks.end_trailers = http_end_headers_cb;
  h3_callbacks.stop_sending = http_stop_sending_cb;
  h3_callbacks.end_stream = http_end_stream_cb;
  h3_callbacks.reset_stream = http_reset_stream_cb;
  h3_callbacks.shutdown = http_shutdown_cb;

  nghttp3_settings h3_settings{};
  nghttp3_settings_default(&h3_settings);
  // QPACK DECODER capacity we advertise for the server's *response* headers. A
  // non-zero capacity invites the server to reference dynamic-table entries, which
  // means a response HEADERS block can become QPACK-blocked until the matching
  // encoder-stream inserts are applied. For a load-test client the response-side
  // dynamic table buys nothing, and once the server started using it (e.g. the 3rd+
  // request on a reused connection) nghttp3 held those streams without ever emitting
  // end_stream -> the request timed out. Advertise 0 so every response is encoded
  // with literal/static fields only (never blockable). The opt-in QPACK-dynamic
  // feature suite (H3_QPACK_DYNAMIC op) still gets a real dynamic table.
  const bool qpack_dynamic_feature = ctx->feature_policy.qpack_dynamic;
  h3_settings.qpack_max_dtable_capacity = qpack_dynamic_feature ? 4096 : 0;
  h3_settings.qpack_blocked_streams = qpack_dynamic_feature ? 16 : 0;

  if (nghttp3_conn_client_new(&ctx->h3_conn, &h3_callbacks, &h3_settings, nghttp3_mem_default(), ctx) != 0 ||
      ctx->h3_conn == nullptr) {
    return false;
  }

  if (ngtcp2_conn_open_uni_stream(ctx->conn, &ctx->ctrl_stream_id, nullptr) != 0) {
    return false;
  }
  if (nghttp3_conn_bind_control_stream(ctx->h3_conn, ctx->ctrl_stream_id) != 0) {
    return false;
  }

  if (ngtcp2_conn_open_uni_stream(ctx->conn, &ctx->qpack_enc_stream_id, nullptr) != 0) {
    return false;
  }
  if (ngtcp2_conn_open_uni_stream(ctx->conn, &ctx->qpack_dec_stream_id, nullptr) != 0) {
    return false;
  }
  if (nghttp3_conn_bind_qpack_streams(ctx->h3_conn, ctx->qpack_enc_stream_id, ctx->qpack_dec_stream_id) != 0) {
    return false;
  }
  // QPACK dynamic readiness requires observed encoder/decoder stream activity
  // (see recv_stream_data_cb), not merely binding the streams.
  if (ctx->feature_policy.server_push) {
    if (!queue_max_push_id_frame(ctx, ctx->max_push_id_advertised)) {
      ctx->feature_failures += 1;
    }
  }

  ctx->h3_ready = true;
  return true;
}

void reset_request_state(Ngtcp2AttemptCtx* ctx) {
  if (ctx == nullptr) {
    return;
  }
  ctx->request_stream_id = -1;
  ctx->request_submitted = false;
  ctx->response_complete = false;
  ctx->response_headers_seen = false;
  ctx->received_any_stream_data = false;
  ctx->response_status = 0;
  ctx->response_headers.clear();
  ctx->response_body.clear();
  ctx->req_body_off = 0;
  ctx->saw_priority_ack = false;
  ctx->saw_extended_connect_ack = false;
  ctx->saw_datagram_ack = false;
  ctx->saw_server_push_signal = false;
  ctx->datagram_pending = false;
  ctx->datagram_payload.clear();
  ctx->priority_applied = false;
  reset_flow_control_guard(ctx);
}

bool submit_h3_request(Ngtcp2AttemptCtx* ctx, const Profile& profile) {
  if (ctx == nullptr || ctx->conn == nullptr || ctx->h3_conn == nullptr || !ctx->h3_ready) {
    return false;
  }
  if (ngtcp2_conn_open_bidi_stream(ctx->conn, &ctx->request_stream_id, nullptr) != 0) {
    return false;
  }

  const std::string scheme = profile.scheme.empty() ? "https" : profile.scheme;
  const std::string authority = profile.host_header.empty()
      ? (profile.target_ip + ":" + std::to_string(std::max(1, profile.target_port)))
      : profile.host_header;
  const bool use_extended_connect = ctx->feature_policy.extended_connect;
  const std::string method = use_extended_connect
      ? "CONNECT"
      : (ctx->request.method.empty() ? "GET" : ctx->request.method);

  std::vector<nghttp3_nv> nva;
  nva.reserve(12);
  nva.push_back(make_nv(":method", method));
  nva.push_back(make_nv(":scheme", scheme));
  nva.push_back(make_nv(":authority", authority));
  if (!use_extended_connect) {
    nva.push_back(make_nv(":path", ctx->request.path.empty() ? "/" : ctx->request.path));
  } else {
    nva.push_back(make_nv(":protocol", ctx->feature_policy.connect_protocol));
    nva.push_back(make_nv("capsule-protocol", "?1"));
  }
  nva.push_back(make_nv("user-agent", "ddos-samurai/native-quic"));
  for (const auto& hdr : ctx->request.headers) {
    if (hdr.first.empty()) {
      continue;
    }
    nva.push_back(make_nv(hdr.first, hdr.second));
  }
  if (ctx->feature_policy.priority_update) {
    nva.push_back(make_nv("priority", ctx->feature_policy.priority_value));
    nghttp3_pri pri{};
    pri.urgency = ctx->feature_policy.priority_urgency;
    pri.inc = ctx->feature_policy.priority_incremental;
    if (nghttp3_conn_set_stream_priority(ctx->h3_conn, ctx->request_stream_id, &pri) != 0) {
      ctx->feature_failures += 1;
    } else {
      ctx->priority_applied = true;
    }
  }
  if (ctx->feature_policy.datagram) {
    nva.push_back(make_nv("capsule-protocol", "?1"));
    nva.push_back(make_nv("datagram-flow-id", ctx->feature_policy.datagram_flow_id));
    ctx->datagram_payload.assign(
        ctx->feature_policy.datagram_flow_id.begin(),
        ctx->feature_policy.datagram_flow_id.end());
    ctx->datagram_payload.push_back(':');
    ctx->datagram_payload.push_back('d');
    ctx->datagram_payload.push_back('g');
    ctx->datagram_payload.push_back('m');
    ctx->datagram_payload.push_back(':');
    const std::string sid_text = std::to_string(ctx->request_stream_id);
    ctx->datagram_payload.insert(ctx->datagram_payload.end(), sid_text.begin(), sid_text.end());
    ctx->datagram_pending = true;
  }
  if (ctx->feature_policy.server_push) {
    nva.push_back(make_nv("prefer", "respond-async"));
  }

  std::string content_length;
  if (!ctx->request.body.empty()) {
    content_length = std::to_string(ctx->request.body.size());
    nva.push_back(make_nv("content-length", content_length));
  }

  nghttp3_data_reader dr{};
  dr.read_data = read_data_cb;
  const nghttp3_data_reader* dr_ptr = ctx->request.body.empty() ? nullptr : &dr;
  if (nghttp3_conn_submit_request(
          ctx->h3_conn,
          ctx->request_stream_id,
          nva.data(),
          nva.size(),
          dr_ptr,
          nullptr) != 0) {
    return false;
  }
  ctx->request_submitted = true;
  return true;
}

void cleanup_attempt(Ngtcp2AttemptCtx* ctx) {
  if (ctx == nullptr) {
    return;
  }
  if (ctx->h3_conn != nullptr) {
    nghttp3_conn_del(ctx->h3_conn);
    ctx->h3_conn = nullptr;
  }
  if (ctx->conn != nullptr) {
    ngtcp2_conn_del(ctx->conn);
    ctx->conn = nullptr;
  }
  if (ctx->session != nullptr) {
    gnutls_deinit(ctx->session);
    ctx->session = nullptr;
  }
  if (ctx->cred != nullptr) {
    gnutls_certificate_free_credentials(ctx->cred);
    ctx->cred = nullptr;
  }
  if (ctx->fd >= 0) {
    (void)::close(ctx->fd);
    ctx->fd = -1;
  }
  if (ctx->xdp.api != nullptr && ctx->xdp.handle > 0) {
    char err[160]{};
    (void)ctx->xdp.api->destroy_ctx(ctx->xdp.handle, err, sizeof(err));
  }
  ctx->xdp = QuicXdpTransport{};
  close_dpdk_transport(&ctx->dpdk);
  close_af_packet_udp(&ctx->af_packet);
  ctx->udp_io_backend = QuicUdpIoBackend::KernelSocket;
}

// DPDK port id for the QUIC UDP hot path (env SAMURAI_DPDK_PORT, default 0).
uint16_t dpdk_port_id_from_env() {
  if (const char* p = std::getenv("SAMURAI_DPDK_PORT"); p != nullptr && p[0] != '\0') {
    const long v = std::strtol(p, nullptr, 10);
    if (v >= 0 && v <= 0xFFFF) {
      return static_cast<uint16_t>(v);
    }
  }
  return 0;
}

// EAL args for every open_port in a run (must match across manager + workers).
std::string dpdk_eal_args_from_env() {
  const char* a = std::getenv("SAMURAI_DPDK_EAL_ARGS");
  return (a != nullptr && a[0] != '\0') ? std::string(a) : std::string();
}

// Ephemeral src port for a DPDK queue. With per-core steering (mask != 0) the low
// bits encode the queue so return traffic (dst port == our src port) matches the
// queue's rte_flow rule `port & mask == queue`. Returns host byte order.
uint16_t pick_dpdk_src_port(uint16_t queue, uint16_t mask) {
  static std::atomic<uint32_t> counter{0};
  const uint32_t n = counter.fetch_add(1, std::memory_order_relaxed);
  uint16_t base = static_cast<uint16_t>(20000u + (n % 45000u));  // [20000, 65000)
  if (mask == 0) {
    return base;
  }
  return static_cast<uint16_t>((base & static_cast<uint16_t>(~mask)) |
                               (queue & mask));
}

// Round worker count up to a power of two and return mask = 2^k - 1 (0 for <=1).
uint16_t dpdk_queue_mask(int worker_count) {
  if (worker_count <= 1) {
    return 0;
  }
  uint16_t m = 1;
  while (m < worker_count) {
    m = static_cast<uint16_t>(m << 1);
  }
  return static_cast<uint16_t>(m - 1);
}

bool connect_udp(Ngtcp2AttemptCtx* ctx, const Profile& profile) {
  auto connect_udp_kernel = [](Ngtcp2AttemptCtx* c) -> bool {
    if (c == nullptr) {
      return false;
    }
    const int family = c->remote_addr.ss_family == AF_INET6 ? AF_INET6 : AF_INET;
    c->fd = ::socket(family, SOCK_DGRAM, 0);
    if (c->fd < 0) {
      return false;
    }
    if (::connect(c->fd, reinterpret_cast<sockaddr*>(&c->remote_addr), c->remote_addrlen) != 0) {
      return false;
    }
    c->local_addrlen = sizeof(c->local_addr);
    if (::getsockname(c->fd, reinterpret_cast<sockaddr*>(&c->local_addr), &c->local_addrlen) != 0) {
      return false;
    }
    timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = 20000;
    (void)::setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    c->udp_io_backend = QuicUdpIoBackend::KernelSocket;
    // A prior attempt on this thread may have left a multishot recv armed; the
    // kernel could hand this new socket the same fd number, so force a re-arm
    // (and bump the generation to drop the old socket's stray completions).
    quic_uring_recv_reset();
    return true;
  };

  auto connect_udp_afxdp = [&](Ngtcp2AttemptCtx* c, const Profile& p) -> bool {
    if (c == nullptr) {
      return false;
    }
    if (c->remote_addr.ss_family != AF_INET || c->remote_addrlen < static_cast<socklen_t>(sizeof(sockaddr_in))) {
      return false;
    }

    const char* iface_env = std::getenv("SAMURAI_XDP_INTERFACE");
    const std::string iface = iface_env == nullptr ? "" : std::string(iface_env);
    if (iface.empty()) {
      return false;
    }
    const xdp_native_api_v1* api = load_xdp_native_api();
    if (api == nullptr) {
      return false;
    }
    int queue_id = 0;
    if (const char* qenv = std::getenv("SAMURAI_XDP_QUEUE_ID"); qenv != nullptr) {
      queue_id = std::max(0, std::atoi(qenv));
    }
    int mode = 1;
    if (const char* menv = std::getenv("SAMURAI_XDP_MODE"); menv != nullptr) {
      mode = std::clamp(std::atoi(menv), 0, 2);
    }
    char err[160]{};
    const int handle = api->create_ctx(iface.c_str(), queue_id, mode, err, sizeof(err));
    if (handle <= 0) {
      return false;
    }

    c->xdp = QuicXdpTransport{};
    c->xdp.api = api;
    c->xdp.handle = handle;

    sockaddr_in remote4{};
    std::memcpy(&remote4, &c->remote_addr, sizeof(remote4));
    c->xdp.dst_ip_nbo = remote4.sin_addr.s_addr;
    c->xdp.dst_port_nbo = htons(static_cast<uint16_t>(std::max(1, p.target_port)));

    uint32_t src_ip_nbo = 0;
    in_addr src_ip_addr{};
    if (!p.source_ip.empty() && ::inet_pton(AF_INET, p.source_ip.c_str(), &src_ip_addr) == 1) {
      src_ip_nbo = src_ip_addr.s_addr;
    } else if (!read_iface_ipv4(iface, &src_ip_nbo)) {
      const char* sip = std::getenv("SAMURAI_XDP_SRC_IP");
      if (sip == nullptr || sip[0] == '\0') {
        sip = std::getenv("SAMURAI_CUSTOM_TCP_SRC_IP");
      }
      if (sip != nullptr && ::inet_pton(AF_INET, sip, &src_ip_addr) == 1) {
        src_ip_nbo = src_ip_addr.s_addr;
      } else {
        (void)api->destroy_ctx(handle, err, sizeof(err));
        c->xdp = QuicXdpTransport{};
        return false;
      }
    }
    c->xdp.src_ip_nbo = src_ip_nbo;

    if (!read_iface_mac(iface, &c->xdp.src_mac)) {
      (void)api->destroy_ctx(handle, err, sizeof(err));
      c->xdp = QuicXdpTransport{};
      return false;
    }

    bool got_dst_mac = false;
    if (const char* dst_env = std::getenv("SAMURAI_QUIC_AF_XDP_DST_MAC");
        dst_env != nullptr && dst_env[0] != '\0') {
      got_dst_mac = parse_mac(dst_env, &c->xdp.dst_mac);
    }
    if (!got_dst_mac) {
      if (const char* dst_env2 = std::getenv("SAMURAI_CUSTOM_TCP_DST_MAC");
          dst_env2 != nullptr && dst_env2[0] != '\0') {
        got_dst_mac = parse_mac(dst_env2, &c->xdp.dst_mac);
      }
    }
    const char* fallback_dst = std::getenv("SAMURAI_GPU_TX_MAC");
    if (!got_dst_mac && fallback_dst != nullptr && fallback_dst[0] != '\0') {
      got_dst_mac = parse_mac(fallback_dst, &c->xdp.dst_mac);
    }
    if (!got_dst_mac) {
      char ipbuf[INET_ADDRSTRLEN]{};
      const char* iptxt = ::inet_ntop(AF_INET, &remote4.sin_addr, ipbuf, sizeof(ipbuf));
      const std::string target_ip = iptxt == nullptr ? "" : std::string(iptxt);
      if (!target_ip.empty()) {
        const auto arp = lookup_arp_mac(iface, target_ip);
        if (arp.has_value()) {
          c->xdp.dst_mac = *arp;
          got_dst_mac = true;
        }
      }
    }
    if (!got_dst_mac) {
      (void)api->destroy_ctx(handle, err, sizeof(err));
      c->xdp = QuicXdpTransport{};
      return false;
    }

    std::random_device rd{};
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> port_dist(20000, 65000);
    c->xdp.src_port_nbo = htons(static_cast<uint16_t>(port_dist(gen)));

    sockaddr_in local4{};
    local4.sin_family = AF_INET;
    local4.sin_port = c->xdp.src_port_nbo;
    local4.sin_addr.s_addr = c->xdp.src_ip_nbo;
    std::memset(&c->local_addr, 0, sizeof(c->local_addr));
    std::memcpy(&c->local_addr, &local4, sizeof(local4));
    c->local_addrlen = sizeof(local4);
    c->fd = -1;
    c->xdp.rx_frames.assign(static_cast<std::size_t>(c->xdp.rx_stride) * c->xdp.rx_lens.size(), 0);
    c->udp_io_backend = QuicUdpIoBackend::AfXdp;
    return true;
  };

  auto connect_udp_dpdk = [&](Ngtcp2AttemptCtx* c, const Profile& p) -> bool {
    // Bridges the QUIC UDP hot path onto the native DPDK core
    // (ddos_samurai/dpdk/dpdk_core). When libdpdk is absent the core is a stub
    // (available()==false) and this returns false so QUIC falls back to kernel.
    if (c == nullptr || !samurai::dpdk::available()) {
      return false;
    }
    if (c->remote_addr.ss_family != AF_INET ||
        c->remote_addrlen < static_cast<socklen_t>(sizeof(sockaddr_in))) {
      return false;
    }
    sockaddr_in remote4{};
    std::memcpy(&remote4, &c->remote_addr, sizeof(remote4));

    // Interface addressing (src MAC/IP + dst MAC). On a DPDK-bound NIC these come
    // from env overrides; with the software net_af_packet PMD over a veth the
    // kernel interface still exists, so /sys + ARP resolution works — identical to
    // the af_packet path.
    const char* iface_env = std::getenv("SAMURAI_XDP_INTERFACE");
    if (iface_env == nullptr || iface_env[0] == '\0') {
      iface_env = std::getenv("SAMURAI_AF_PACKET_IFACE");
    }
    const std::string iface = iface_env == nullptr ? "" : std::string(iface_env);

    // Source IP: explicit profile.source_ip, else the interface IPv4, else env.
    uint32_t src_ip_nbo = 0;
    in_addr src_ip_addr{};
    if (!p.source_ip.empty() && ::inet_pton(AF_INET, p.source_ip.c_str(), &src_ip_addr) == 1) {
      src_ip_nbo = src_ip_addr.s_addr;
    } else if (iface.empty() || !read_iface_ipv4_nbo(iface, &src_ip_nbo)) {
      const char* sip = std::getenv("SAMURAI_DPDK_SRC_IP");
      if (sip != nullptr && ::inet_pton(AF_INET, sip, &src_ip_addr) == 1) {
        src_ip_nbo = src_ip_addr.s_addr;
      } else {
        return false;
      }
    }

    // Source MAC: env override, else the interface MAC.
    std::array<uint8_t, 6> src_mac{};
    bool got_src = false;
    if (const char* sm = std::getenv("SAMURAI_DPDK_SRC_MAC"); sm != nullptr && sm[0] != '\0') {
      got_src = parse_mac_address(sm, &src_mac);
    }
    if (!got_src && !iface.empty()) {
      got_src = read_iface_mac_address(iface, &src_mac);
    }
    if (!got_src) {
      return false;
    }

    // Destination MAC: env overrides, else ARP for the target IP.
    std::array<uint8_t, 6> dst_mac{};
    bool got_dst = false;
    if (const char* dm = std::getenv("SAMURAI_DPDK_DST_MAC"); dm != nullptr && dm[0] != '\0') {
      got_dst = parse_mac_address(dm, &dst_mac);
    }
    if (!got_dst) {
      if (const char* dm2 = std::getenv("SAMURAI_AF_PACKET_DST_MAC"); dm2 != nullptr && dm2[0] != '\0') {
        got_dst = parse_mac_address(dm2, &dst_mac);
      }
    }
    if (!got_dst && !iface.empty()) {
      const auto arp = lookup_arp_mac_address(iface, p.target_ip);
      if (arp.has_value()) {
        dst_mac = *arp;
        got_dst = true;
      }
    }
    if (!got_dst) {
      return false;
    }

    // Handle: fan-out-managed (worker-owned, per-core queue+steering installed
    // up front) or self-opened for this serial attempt (single queue, no steer).
    const bool managed = c->dpdk.handle > 0;
    long handle = c->dpdk.handle;
    bool owns = false;
    if (!managed) {
      samurai::dpdk::OpenConfig cfg{};
      cfg.port_id = dpdk_port_id_from_env();
      cfg.num_tx_queues = 1;
      cfg.num_rx_queues = 1;
      cfg.enable_rss = false;
      cfg.eal_args = dpdk_eal_args_from_env();
      std::string open_err;
      handle = samurai::dpdk::open_port(cfg, open_err);
      if (handle <= 0) {
        return false;
      }
      owns = true;
    }

    const uint16_t queue = c->dpdk.queue_id;
    const uint16_t mask = c->dpdk.port_mask;
    const uint16_t sport_nbo = htons(pick_dpdk_src_port(queue, mask));

    samurai::dpdk::UdpFlowConfig fcfg{};
    fcfg.src_ip_nbo = src_ip_nbo;
    fcfg.dst_ip_nbo = remote4.sin_addr.s_addr;
    fcfg.src_port_nbo = sport_nbo;
    fcfg.dst_port_nbo = remote4.sin_port;
    std::memcpy(fcfg.src_mac, src_mac.data(), 6);
    std::memcpy(fcfg.dst_mac, dst_mac.data(), 6);
    fcfg.initial_ip_id = 1;
    std::string cfg_err;
    if (!samurai::dpdk::configure_udp_flow(handle, fcfg, cfg_err)) {
      if (owns) {
        samurai::dpdk::close_port(handle);
      }
      return false;
    }

    c->dpdk.handle = handle;
    c->dpdk.owns_handle = owns;
    c->dpdk.src_mac = src_mac;
    c->dpdk.dst_mac = dst_mac;
    c->dpdk.src_ip_nbo = src_ip_nbo;
    c->dpdk.dst_ip_nbo = remote4.sin_addr.s_addr;
    c->dpdk.src_port_nbo = sport_nbo;
    c->dpdk.dst_port_nbo = remote4.sin_port;
    c->dpdk.ip_id = 1;
    c->dpdk.rx_stride = 2048;
    c->dpdk.rx_payload.assign(
        static_cast<std::size_t>(c->dpdk.rx_stride) * c->dpdk.rx_lens.size(), 0);

    sockaddr_in local4{};
    local4.sin_family = AF_INET;
    local4.sin_port = sport_nbo;
    local4.sin_addr.s_addr = src_ip_nbo;
    std::memset(&c->local_addr, 0, sizeof(c->local_addr));
    std::memcpy(&c->local_addr, &local4, sizeof(local4));
    c->local_addrlen = sizeof(local4);
    c->fd = -1;
    c->udp_io_backend = QuicUdpIoBackend::Dpdk;
    return true;
  };

  auto connect_udp_afpacket = [&](Ngtcp2AttemptCtx* c, const Profile& p) -> bool {
    if (c == nullptr) {
      return false;
    }
    if (c->remote_addr.ss_family != AF_INET ||
        c->remote_addrlen < static_cast<socklen_t>(sizeof(sockaddr_in))) {
      return false;
    }
    sockaddr_in remote4{};
    std::memcpy(&remote4, &c->remote_addr, sizeof(remote4));
    AfPacketUdpEndpoint ep{};
    if (!open_af_packet_udp(p, remote4.sin_addr.s_addr, ntohs(remote4.sin_port), &ep)) {
      return false;
    }
    c->af_packet = ep;
    sockaddr_in local4{};
    local4.sin_family = AF_INET;
    local4.sin_port = c->af_packet.src_port_nbo;
    local4.sin_addr.s_addr = c->af_packet.src_ip_nbo;
    std::memset(&c->local_addr, 0, sizeof(c->local_addr));
    std::memcpy(&c->local_addr, &local4, sizeof(local4));
    c->local_addrlen = sizeof(local4);
    c->fd = -1;
    c->udp_io_backend = QuicUdpIoBackend::AfPacket;
    return true;
  };

  if (ctx == nullptr) {
    return false;
  }
  if (!resolve_target(profile.target_ip, profile.target_port, &ctx->remote_addr, &ctx->remote_addrlen)) {
    return false;
  }

  if (ctx->requested_backend == QuicUdpIoBackend::AfXdp) {
    if (connect_udp_afxdp(ctx, profile)) {
      return true;
    }
    if (ctx->strict_runtime) {
      return false;
    }
    ctx->backend_fallback_used = true;
    return connect_udp_kernel(ctx);
  }
  if (ctx->requested_backend == QuicUdpIoBackend::AfPacket) {
    if (connect_udp_afpacket(ctx, profile)) {
      return true;
    }
    if (ctx->strict_runtime) {
      return false;
    }
    ctx->backend_fallback_used = true;
    return connect_udp_kernel(ctx);
  }
  if (ctx->requested_backend == QuicUdpIoBackend::Dpdk) {
    if (connect_udp_dpdk(ctx, profile)) {
      return true;
    }
    if (ctx->strict_runtime) {
      return false;
    }
    ctx->backend_fallback_used = true;
    return connect_udp_kernel(ctx);
  }
  return connect_udp_kernel(ctx);
}

ssize_t send_udp_payload(Ngtcp2AttemptCtx* ctx, const uint8_t* payload, std::size_t payload_len) {
  if (ctx == nullptr || payload == nullptr || payload_len == 0) {
    return -1;
  }
  if (ctx->udp_io_backend == QuicUdpIoBackend::KernelSocket) {
    if (ctx->fd < 0) {
      return -1;
    }
    return ::send(ctx->fd, payload, payload_len, 0);
  }
  if (payload_len > kMaxUdpPayloadBytes) {
    return -1;
  }
  if (ctx->udp_io_backend == QuicUdpIoBackend::AfXdp) {
    if (ctx->xdp.api == nullptr || ctx->xdp.handle <= 0) {
      return -1;
    }
    std::size_t frame_len = 0;
    if (!build_ipv4_udp_eth_frame(
            ctx->xdp.dst_mac,
            ctx->xdp.src_mac,
            ctx->xdp.src_ip_nbo,
            ctx->xdp.dst_ip_nbo,
            ctx->xdp.src_port_nbo,
            ctx->xdp.dst_port_nbo,
            &ctx->xdp.ip_id,
            payload,
            payload_len,
            ctx->xdp.tx_frame.data(),
            ctx->xdp.tx_frame.size(),
            &frame_len)) {
      return -1;
    }

    char err[160]{};
    const int sent = ctx->xdp.api->send_buffer(
        ctx->xdp.handle,
        ctx->xdp.tx_frame.data(),
        static_cast<int>(frame_len),
        1,
        err,
        sizeof(err));
    if (sent <= 0) {
      return -1;
    }
    return static_cast<ssize_t>(payload_len);
  }
  if (ctx->udp_io_backend == QuicUdpIoBackend::AfPacket) {
    return af_packet_send_udp(&ctx->af_packet, payload, payload_len);
  }
  if (ctx->udp_io_backend == QuicUdpIoBackend::Dpdk) {
    if (ctx->dpdk.handle <= 0) {
      return -1;
    }
    std::string err;
    const int sent = samurai::dpdk::send_udp_payload(
        ctx->dpdk.handle, ctx->dpdk.queue_id, payload, payload_len, err);
    return sent > 0 ? static_cast<ssize_t>(payload_len) : -1;
  }
  return -1;
}

int recv_udp_payloads(
    Ngtcp2AttemptCtx* ctx,
    uint8_t* payload_buf,
    std::size_t stride,
    std::size_t* lens_out,
    int max_packets) {
  if (ctx == nullptr || payload_buf == nullptr || lens_out == nullptr || stride == 0 || max_packets <= 0) {
    return -1;
  }
  if (ctx->udp_io_backend == QuicUdpIoBackend::KernelSocket) {
    if (ctx->fd < 0) {
      return -1;
    }
    // Preferred: pull datagrams off the io_uring multishot recv over a provided
    // buffer ring (one SQE fans many datagrams into kernel-selected buffers), so
    // the QUIC/HTTP-3 byte path rides the same ring as H1/H2. Returns -1 when the
    // ring/buffer-ring is unavailable on this build or host; then fall back to a
    // classic non-blocking ::recv().
    const int ring_got = quic_uring_recv_datagrams(
        ctx->fd, payload_buf, stride, lens_out, max_packets, /*wait_ms=*/0);
    if (ring_got >= 0) {
      return ring_got;
    }
    const ssize_t nread = ::recv(ctx->fd, payload_buf, stride, MSG_DONTWAIT);
    if (nread <= 0) {
      return 0;
    }
    lens_out[0] = static_cast<std::size_t>(nread);
    return 1;
  }
  if (ctx->udp_io_backend == QuicUdpIoBackend::AfXdp) {
    if (ctx->xdp.api == nullptr || ctx->xdp.handle <= 0) {
      return -1;
    }
    const int want = std::min<int>(max_packets, static_cast<int>(ctx->xdp.rx_lens.size()));
    char err[160]{};
    const int got = ctx->xdp.api->recv_frames(
        ctx->xdp.handle,
        ctx->xdp.rx_frames.data(),
        ctx->xdp.rx_stride,
        ctx->xdp.rx_lens.data(),
        want,
        ctx->xdp.rx_stride,
        err,
        sizeof(err));
    if (got <= 0) {
      return 0;
    }
    int accepted = 0;
    for (int i = 0; i < got && accepted < max_packets; ++i) {
      const std::size_t flen = ctx->xdp.rx_lens[static_cast<std::size_t>(i)];
      if (flen < 14 + sizeof(iphdr) + sizeof(udphdr)) {
        continue;
      }
      const uint8_t* frame = ctx->xdp.rx_frames.data() + static_cast<std::size_t>(i) * static_cast<std::size_t>(ctx->xdp.rx_stride);
      const uint16_t ethertype = static_cast<uint16_t>((static_cast<uint16_t>(frame[12]) << 8u) | frame[13]);
      if (ethertype != ETH_P_IP) {
        continue;
      }
      const auto* ip = reinterpret_cast<const iphdr*>(frame + 14);
      if (ip->version != 4 || ip->ihl < 5 || ip->protocol != IPPROTO_UDP) {
        continue;
      }
      const std::size_t ihl_bytes = static_cast<std::size_t>(ip->ihl) * 4u;
      if (14u + ihl_bytes + sizeof(udphdr) > flen) {
        continue;
      }
      const auto* udp = reinterpret_cast<const udphdr*>(frame + 14u + ihl_bytes);
      if (udp->dest != ctx->xdp.src_port_nbo) {
        continue;
      }
      if (ip->daddr != ctx->xdp.src_ip_nbo) {
        continue;
      }
      if (udp->source != ctx->xdp.dst_port_nbo) {
        continue;
      }
      const uint16_t udp_len = ntohs(udp->len);
      if (udp_len < sizeof(udphdr)) {
        continue;
      }
      const std::size_t payload_len = static_cast<std::size_t>(udp_len - sizeof(udphdr));
      const std::size_t payload_off = 14u + ihl_bytes + sizeof(udphdr);
      if (payload_off + payload_len > flen || payload_len > stride) {
        continue;
      }
      std::memcpy(payload_buf + static_cast<std::size_t>(accepted) * stride, frame + payload_off, payload_len);
      lens_out[static_cast<std::size_t>(accepted)] = payload_len;
      ++accepted;
    }
    return accepted;
  }
  if (ctx->udp_io_backend == QuicUdpIoBackend::AfPacket) {
    return af_packet_recv_udp(&ctx->af_packet, payload_buf, stride, lens_out, max_packets);
  }
  if (ctx->udp_io_backend == QuicUdpIoBackend::Dpdk) {
    if (ctx->dpdk.handle <= 0 || ctx->dpdk.rx_payload.empty()) {
      return -1;
    }
    const uint16_t rx_stride = static_cast<uint16_t>(ctx->dpdk.rx_stride);
    const int budget = std::min<int>(max_packets, static_cast<int>(ctx->dpdk.rx_lens.size()));
    // poll_udp_payloads already extracts the UDP payload for frames matching
    // (local_ip, local_port==our src, remote_port==server dst) on our queue.
    const int got = samurai::dpdk::poll_udp_payloads(
        ctx->dpdk.handle,
        ctx->dpdk.queue_id,
        ctx->dpdk.src_ip_nbo,
        ctx->dpdk.src_port_nbo,
        ctx->dpdk.dst_port_nbo,
        static_cast<uint16_t>(budget),
        ctx->dpdk.rx_payload.data(),
        rx_stride,
        ctx->dpdk.rx_lens.data());
    if (got <= 0) {
      return 0;
    }
    int accepted = 0;
    for (int i = 0; i < got && accepted < max_packets; ++i) {
      const uint16_t plen = ctx->dpdk.rx_lens[static_cast<std::size_t>(i)];
      if (plen == 0 || plen > stride) {
        continue;
      }
      std::memcpy(payload_buf + static_cast<std::size_t>(accepted) * stride,
                  ctx->dpdk.rx_payload.data() + static_cast<std::size_t>(i) * rx_stride,
                  plen);
      lens_out[static_cast<std::size_t>(accepted)] = plen;
      ++accepted;
    }
    return accepted;
  }
  return -1;
}

bool drive_io_once(Ngtcp2AttemptCtx* ctx, uint64_t deadline_ns, UdpProbeCounters* out) {
  if (ctx == nullptr || ctx->conn == nullptr) {
    return false;
  }
  const uint64_t ts = now_ns();
  if (ts > deadline_ns) {
    return false;
  }

  // Send packet(s)
  if (ctx->datagram_pending && ctx->conn != nullptr && !ctx->datagram_payload.empty()) {
    const ngtcp2_transport_params* remote = ngtcp2_conn_get_remote_transport_params(ctx->conn);
    const bool datagram_supported = remote != nullptr && remote->max_datagram_frame_size > 0;
    ctx->datagram_remote_supported = datagram_supported;
    if (datagram_supported) {
      std::array<uint8_t, 1452> dpkt{};
      ngtcp2_path_storage dps;
      ngtcp2_path_storage_zero(&dps);
      ngtcp2_pkt_info dpi{};
      ngtcp2_vec dvec{};
      dvec.base = ctx->datagram_payload.data();
      dvec.len = ctx->datagram_payload.size();
      int accepted = 0;
      const ngtcp2_ssize dnwrite = ngtcp2_conn_writev_datagram(
          ctx->conn,
          &dps.path,
          &dpi,
          dpkt.data(),
          dpkt.size(),
          &accepted,
          NGTCP2_WRITE_DATAGRAM_FLAG_NONE,
          ctx->next_datagram_id,
          &dvec,
          1,
          ts);
      if (dnwrite > 0) {
        const ssize_t dwr = send_udp_payload(ctx, dpkt.data(), static_cast<std::size_t>(dnwrite));
        if (dwr > 0 && accepted != 0) {
          ctx->datagram_tx_events += 1;
          if (out != nullptr) {
            out->tx_datagrams += 1;
          }
          ctx->last_datagram_id = ctx->next_datagram_id;
          ctx->next_datagram_id += 1;
          ctx->datagram_pending = false;
        }
      } else if (dnwrite == NGTCP2_ERR_INVALID_STATE || dnwrite == NGTCP2_ERR_INVALID_ARGUMENT) {
        ctx->feature_failures += 1;
        ctx->datagram_pending = false;
      }
    } else {
      ctx->feature_failures += 1;
      ctx->datagram_pending = false;
    }
  }

  std::array<uint8_t, 1452> pkt{};
  ngtcp2_path_storage ps;
  ngtcp2_path_storage_zero(&ps);
  ngtcp2_pkt_info pi{};
  bool coalescing_pkt = false;

  for (int iter = 0; iter < 256; ++iter) {
    if (!coalescing_pkt) {
      ngtcp2_path_storage_zero(&ps);
      pi = ngtcp2_pkt_info{};
    }
    ngtcp2_ssize pdatalen = -1;

    int64_t sid = -1;
    int fin = 0;
    std::array<nghttp3_vec, 16> h3_vec{};
    nghttp3_ssize h3_veccnt = 0;
    ngtcp2_vec custom_vec{};
    bool custom_stream_payload = false;
    bool stream_from_nghttp3 = false;

    const bool force_flush_coalesced = (iter == 255 && coalescing_pkt);
    if (!force_flush_coalesced) {
      if (!ctx->control_tx_buffer.empty() &&
          ctx->control_tx_off < ctx->control_tx_buffer.size() &&
          ctx->ctrl_stream_id >= 0) {
        sid = ctx->ctrl_stream_id;
        custom_vec.base = ctx->control_tx_buffer.data() + ctx->control_tx_off;
        custom_vec.len = ctx->control_tx_buffer.size() - ctx->control_tx_off;
        custom_stream_payload = custom_vec.len > 0;
      }

      if (!custom_stream_payload && ctx->h3_ready && ctx->h3_conn != nullptr) {
        h3_veccnt = nghttp3_conn_writev_stream(
            ctx->h3_conn,
            &sid,
            &fin,
            h3_vec.data(),
            h3_vec.size());
        if (h3_veccnt < 0) {
          return false;
        }
        stream_from_nghttp3 = sid >= 0;
      }
    }

    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
    if (sid >= 0) {
      flags |= NGTCP2_WRITE_STREAM_FLAG_MORE;
      if (fin != 0) {
        flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
      }
    }

    const ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
        ctx->conn,
        &ps.path,
        &pi,
        pkt.data(),
        pkt.size(),
        &pdatalen,
        flags,
        sid,
        custom_stream_payload
            ? &custom_vec
            : (sid >= 0 ? reinterpret_cast<const ngtcp2_vec*>(h3_vec.data()) : nullptr),
        custom_stream_payload
            ? static_cast<std::size_t>(1)
            : (sid >= 0 ? static_cast<std::size_t>(std::max<nghttp3_ssize>(0, h3_veccnt)) : 0),
        ts);
    if (nwrite < 0) {
      if (custom_stream_payload) {
        if (nwrite == NGTCP2_ERR_WRITE_MORE && pdatalen > 0) {
          coalescing_pkt = true;
          ctx->control_tx_off += static_cast<std::size_t>(pdatalen);
          if (ctx->control_tx_off >= ctx->control_tx_buffer.size()) {
            ctx->control_tx_buffer.clear();
            ctx->control_tx_off = 0;
          }
          continue;
        }
        if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
          if (register_stream_data_blocked(ctx)) {
            return false;
          }
          continue;
        }
        if (nwrite == NGTCP2_ERR_STREAM_SHUT_WR || nwrite == NGTCP2_ERR_STREAM_NOT_FOUND) {
          ctx->feature_failures += 1;
          ctx->control_tx_buffer.clear();
          ctx->control_tx_off = 0;
          continue;
        }
      } else if (sid >= 0 && ctx->h3_conn != nullptr) {
        if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
          nghttp3_conn_block_stream(ctx->h3_conn, sid);
          if (register_stream_data_blocked(ctx)) {
            return false;
          }
          continue;
        }
        if (nwrite == NGTCP2_ERR_STREAM_SHUT_WR) {
          nghttp3_conn_shutdown_stream_write(ctx->h3_conn, sid);
          continue;
        }
        if (nwrite == NGTCP2_ERR_WRITE_MORE && pdatalen >= 0) {
          coalescing_pkt = true;
          if (nghttp3_conn_add_write_offset(ctx->h3_conn, sid, static_cast<std::size_t>(pdatalen)) != 0) {
            return false;
          }
          if (ctx->feature_policy.qpack_dynamic && sid == ctx->qpack_enc_stream_id && pdatalen > 0) {
            ctx->saw_qpack_activity = true;
            ctx->qpack_encoder_inserts += 1;
            ctx->qpack_dtable_bytes += static_cast<std::size_t>(pdatalen);
          }
          continue;
        }
      }
      return false;
    }
    coalescing_pkt = false;

    if (custom_stream_payload && pdatalen > 0) {
      ctx->control_tx_off += static_cast<std::size_t>(pdatalen);
      if (ctx->control_tx_off >= ctx->control_tx_buffer.size()) {
        ctx->control_tx_buffer.clear();
        ctx->control_tx_off = 0;
      }
      ctx->tx_bytes += static_cast<std::size_t>(pdatalen);
      note_flow_control_progress(ctx);
    } else if (stream_from_nghttp3 && ctx->h3_conn != nullptr && pdatalen >= 0) {
      if (nghttp3_conn_add_write_offset(ctx->h3_conn, sid, static_cast<std::size_t>(pdatalen)) != 0) {
        return false;
      }
      ctx->tx_bytes += static_cast<std::size_t>(pdatalen);
      note_flow_control_progress(ctx);
      if (ctx->feature_policy.qpack_dynamic && sid == ctx->qpack_enc_stream_id && pdatalen > 0) {
        ctx->saw_qpack_activity = true;
        ctx->qpack_encoder_inserts += 1;
        ctx->qpack_dtable_bytes += static_cast<std::size_t>(pdatalen);
        constexpr std::size_t kQpackCapacity = 4096u;
        if (ctx->qpack_dtable_bytes > kQpackCapacity) {
          ctx->qpack_evictions += 1;
          ctx->qpack_dtable_bytes = kQpackCapacity / 2u;
        }
      }
    }

    if (nwrite == 0) {
      break;
    }
    const ssize_t wr = send_udp_payload(ctx, pkt.data(), static_cast<std::size_t>(nwrite));
    if (wr <= 0) {
      return false;
    }
    if (out != nullptr) {
      out->tx_datagrams += 1;
    }
    if (sid < 0) {
      ctx->tx_bytes += static_cast<std::size_t>(wr);
    }
  }

  // Feed one received datagram into the QUIC state machine.
  std::array<uint8_t, 64 * 2048> rx_batch{};
  std::array<std::size_t, 64> rx_lens{};
  auto feed_datagram = [&](const uint8_t* data, std::size_t nread) -> bool {
    if (nread == 0) {
      return true;
    }
    if (out != nullptr) {
      out->rx_datagrams += 1;
    }
    ctx->rx_bytes += nread;
    ngtcp2_path path{};
    path.local.addr = reinterpret_cast<sockaddr*>(&ctx->local_addr);
    path.local.addrlen = ctx->local_addrlen;
    path.remote.addr = reinterpret_cast<sockaddr*>(&ctx->remote_addr);
    path.remote.addrlen = ctx->remote_addrlen;
    ngtcp2_pkt_info pi{};
    return ngtcp2_conn_read_pkt(ctx->conn, &path, &pi, data, nread, now_ns()) == 0;
  };

  // Receive packet(s): drain whatever is ready (ring multishot recv on the
  // kernel-socket path, else a syscall recv).
  int total_rx_got = 0;
  for (int iter = 0; iter < 64; ++iter) {
    const int got = recv_udp_payloads(ctx, rx_batch.data(), 2048, rx_lens.data(), 64);
    if (got < 0) {
      return false;
    }
    if (got == 0) {
      break;
    }
    total_rx_got += got;
    for (int i = 0; i < got; ++i) {
      if (!feed_datagram(
              rx_batch.data() + static_cast<std::size_t>(i) * 2048u,
              rx_lens[static_cast<std::size_t>(i)])) {
        return false;
      }
    }
  }

  if (ngtcp2_conn_handle_expiry(ctx->conn, now_ns()) != 0) {
    return false;
  }
  if (total_rx_got == 0 && ctx->udp_io_backend == QuicUdpIoBackend::KernelSocket && ctx->fd >= 0) {
    const uint64_t now = now_ns();
    const uint64_t expiry = ngtcp2_conn_get_expiry(ctx->conn);
    const uint64_t next_wakeup = std::min(deadline_ns, expiry);
    if (next_wakeup > now) {
      const int wait_ms = static_cast<int>(std::clamp<int64_t>(ns_to_ms_ceil(next_wakeup - now), 0, 10));
      if (wait_ms > 0) {
        // Block for the next datagram (or the pacing deadline) on the shared
        // io_uring multishot recv, feeding any that arrive so the QUIC/HTTP-3
        // byte path stays on the ring. When the ring is unavailable (helper
        // returns <0) fall back to the io_uring readiness poll, then ::poll.
        const int woke = quic_uring_recv_datagrams(
            ctx->fd, rx_batch.data(), 2048, rx_lens.data(), 64, wait_ms);
        if (woke > 0) {
          for (int i = 0; i < woke; ++i) {
            if (!feed_datagram(
                    rx_batch.data() + static_cast<std::size_t>(i) * 2048u,
                    rx_lens[static_cast<std::size_t>(i)])) {
              return false;
            }
          }
        } else if (woke < 0) {
          if (quic_uring_wait_readable(ctx->fd, wait_ms) < 0) {
            pollfd pfd{};
            pfd.fd = ctx->fd;
            pfd.events = POLLIN;
            (void)::poll(&pfd, 1, wait_ms);
          }
        }
        if (out != nullptr) {
          out->pacing_wait_events += 1;
        }
      }
    }
  }
  return true;
}

bool evaluate_response(const Ngtcp2AttemptCtx& ctx) {
  const bool status_ok =
      ctx.response_status >= ctx.expectations.status_min &&
      ctx.response_status <= ctx.expectations.status_max;
  const bool expected_header_ok =
      !ctx.expectations.has_header_expect ||
      header_expect_ok(ctx.response_headers, ctx.expectations.header_name, ctx.expectations.header_value_contains);
  const bool body_substring_ok =
      !ctx.expectations.has_body_expect || body_expect_ok(ctx.response_body, ctx.expectations.body_substring);
  const bool body_required_ok = !ctx.expectations.require_body || !ctx.response_body.empty();
  const bool min_body_ok = ctx.response_body.size() >= ctx.expectations.min_body_bytes;
  const bool expected_body_ok = body_substring_ok && body_required_ok && min_body_ok;

  return ctx.response_headers_seen && status_ok && expected_header_ok && expected_body_ok;
}

int resolve_pipelined_in_flight_window() {
  if (const char* env = std::getenv("SAMURAI_QUIC_IN_FLIGHT_WINDOW");
      env != nullptr && env[0] != '\0') {
    const int v = std::atoi(env);
    if (v >= 1 && v <= 512) {
      return v;
    }
  }
  return 64;
}

bool run_single_attempt(
    const Profile& profile,
    int timeout_ms,
    int planned_requests,
    const H3FeaturePolicy& feature_policy,
    TlsSessionCache* session_cache,
    UdpProbeCounters* out,
    const QuicDpdkFanoutCtx* dpdk_fanout = nullptr,
    const QuicInitialKeyMaterial* precomputed_keys = nullptr,
    std::vector<double>* latency_samples_out = nullptr) {
  if (out == nullptr) {
    return false;
  }
  const int request_budget = std::max(1, planned_requests);
  const GoawayPolicy goaway_policy = derive_goaway_policy(profile);
  // Ordered scenario steps. With a single step we preserve the legacy behaviour
  // of repeating that request request_budget times (stress / feature suites);
  // with multiple steps we walk them in order once, carrying captures + cookies.
  const std::vector<ScenarioStep> scenario_steps = derive_scenario_steps(profile);
  const bool multi_step = scenario_steps.size() > 1;
  const int plan_len =
      multi_step ? static_cast<int>(scenario_steps.size()) : request_budget;
  std::map<std::string, std::string> captures;
  std::map<std::string, std::string> cookie_jar;
  out->scenario_multi_step = multi_step ? 1 : 0;
  out->scenario_steps_planned += plan_len;
  Ngtcp2AttemptCtx ctx{};
  if (precomputed_keys != nullptr) {
    ctx.has_precomputed_cids = true;
    std::memcpy(ctx.precomputed_dcid.data(), precomputed_keys->dcid, 8);
    std::memcpy(ctx.precomputed_scid.data(), precomputed_keys->scid, 8);
    ctx.precomputed_initial_keys = *precomputed_keys;
  }
  ctx.request = derive_request_spec(profile);
  ctx.expectations = derive_expectations(profile);
  ctx.requests_planned = request_budget;
  ctx.feature_policy = feature_policy;
  ctx.flow_guard = derive_flow_control_guard_policy();
  ctx.max_push_id_advertised = feature_policy.max_push_id;
  ctx.max_push_id_set = true;
  ctx.requested_backend = resolve_requested_backend(profile);
  ctx.strict_runtime =
      profile.stateful_runtime_strict != 0 ||
      env_truthy("SAMURAI_L7_CAPABILITY_STRICT") ||
      env_truthy("SAMURAI_L7_QUIC_REQUIRE_NATIVE");
  out->runtime_backend_requested = static_cast<int>(ctx.requested_backend);
  // Fan-out-managed DPDK: adopt the worker's shared handle, queue and stride mask
  // so connect_udp_dpdk configures a private template on the pre-steered queue.
  if (dpdk_fanout != nullptr && dpdk_fanout->shared_handle > 0) {
    ctx.dpdk.handle = dpdk_fanout->shared_handle;
    ctx.dpdk.queue_id = dpdk_fanout->queue_id;
    ctx.dpdk.port_mask = dpdk_fanout->port_mask;
  }
  std::string tls_sni_name{};
  std::string tls_verify_name{};
  derive_tls_names(profile, &tls_sni_name, &tls_verify_name);
  const bool verify_peer = profile.verify != 0;

  do {
    if (!connect_udp(&ctx, profile)) {
      out->connect_fail += request_budget;
      out->handshake_fail += request_budget;
      out->timeouts += request_budget;
      out->errors += request_budget;
      out->response_validation_fail += request_budget;
      break;
    }
    if (ctx.backend_fallback_used) {
      out->backend_fallback_count += 1;
    }
    out->runtime_udp_io_backend = static_cast<int>(ctx.udp_io_backend);
    out->runtime_native_hot_path_ready =
        is_native_hot_path_backend(static_cast<QuicUdpIoBackendCode>(ctx.udp_io_backend)) ? 1 : 0;
    out->runtime_backend_requested = static_cast<int>(ctx.requested_backend);
    if (!configure_gnutls_session(&ctx, tls_sni_name, verify_peer, session_cache)) {
      out->handshake_fail += request_budget;
      out->timeouts += request_budget;
      out->errors += request_budget;
      out->response_validation_fail += request_budget;
      break;
    }
    if (!init_quic_conn(&ctx)) {
      out->handshake_fail += request_budget;
      out->timeouts += request_budget;
      out->errors += request_budget;
      out->response_validation_fail += request_budget;
      break;
    }

    const uint64_t handshake_deadline_ns =
        now_ns() + static_cast<uint64_t>(std::max(50, timeout_ms)) * 1000000ull;
    while (now_ns() < handshake_deadline_ns && !ctx.handshake_done) {
      if (!drive_io_once(&ctx, handshake_deadline_ns, out)) {
        break;
      }
    }
    if (!ctx.handshake_done) {
      out->handshake_fail += request_budget;
      out->timeouts += request_budget;
      out->errors += request_budget;
      out->response_validation_fail += request_budget;
      break;
    }
    if (!verify_peer_certificate(&ctx, tls_verify_name, verify_peer)) {
      out->handshake_fail += request_budget;
      out->errors += request_budget;
      out->response_validation_fail += request_budget;
      break;
    }
    ctx.tls_session_resumed = gnutls_session_is_resumed(ctx.session) != 0;
#ifdef GNUTLS_SFLAGS_EARLY_DATA
    ctx.tls_early_data_accepted = (gnutls_session_get_flags(ctx.session) & GNUTLS_SFLAGS_EARLY_DATA) != 0u;
#endif
    ctx.tls_session_ticket_received = tls_ticket_ready(ctx.session);
    out->conn_established += 1;
    if (!init_h3_session(&ctx)) {
      out->handshake_fail += request_budget;
      out->errors += request_budget;
      out->response_validation_fail += request_budget;
      break;
    }

    const int in_flight_window = resolve_pipelined_in_flight_window();
    const bool use_pipelined_window =
        !multi_step &&
        !goaway_policy.enabled &&
        !feature_policy.qpack_dynamic &&
        !feature_policy.priority_update &&
        !feature_policy.extended_connect &&
        !feature_policy.datagram &&
        !feature_policy.server_push &&
        plan_len > 1 &&
        in_flight_window > 1 &&
        (scenario_steps.empty() || scenario_steps.front().think_time_ms <= 0) &&
        !env_truthy("SAMURAI_QUIC_PIPELINE_DISABLE");

    if (use_pipelined_window) {
      ctx.pipelined_mode = true;
      const ScenarioStep& step = scenario_steps.front();
      ctx.request = render_scenario_request(step, captures, cookie_jar);
      ctx.expectations = step.expectations;

      const std::string scheme = profile.scheme.empty() ? "https" : profile.scheme;
      const std::string authority = profile.host_header.empty()
          ? (profile.target_ip + ":" + std::to_string(std::max(1, profile.target_port)))
          : profile.host_header;
      const std::string method = ctx.request.method.empty() ? "GET" : ctx.request.method;
      const std::string path = ctx.request.path.empty() ? "/" : ctx.request.path;
      std::string content_length;
      if (!ctx.request.body.empty()) {
        content_length = std::to_string(ctx.request.body.size());
      }

      std::vector<nghttp3_nv> nva;
      nva.reserve(6 + ctx.request.headers.size());
      nva.push_back(make_nv(":method", method));
      nva.push_back(make_nv(":scheme", scheme));
      nva.push_back(make_nv(":authority", authority));
      nva.push_back(make_nv(":path", path));
      nva.push_back(make_nv("user-agent", "ddos-samurai/native-quic"));
      for (const auto& hdr : ctx.request.headers) {
        if (!hdr.first.empty()) {
          nva.push_back(make_nv(hdr.first, hdr.second));
        }
      }
      if (!ctx.request.body.empty()) {
        nva.push_back(make_nv("content-length", content_length));
      }
      nghttp3_data_reader dr{};
      dr.read_data = read_data_cb;
      const nghttp3_data_reader* dr_ptr = ctx.request.body.empty() ? nullptr : &dr;

      ctx.active_streams.reserve(static_cast<std::size_t>(in_flight_window * 2));
      ctx.completed_streams.reserve(static_cast<std::size_t>(in_flight_window * 2));
      ctx.stream_latencies_ms.reserve(static_cast<std::size_t>(plan_len));

      int requests_submitted = 0;
      const uint64_t step_timeout_ns =
          static_cast<uint64_t>(std::max(50, timeout_ms)) * 1000000ull;
      uint64_t last_progress_ns = now_ns();
      bool fatal_pipeline_abort = false;

      while (ctx.requests_completed < plan_len && !fatal_pipeline_abort) {
        while (requests_submitted < plan_len &&
               static_cast<int>(ctx.active_streams.size()) < in_flight_window &&
               !ctx.goaway_active) {
          int64_t sid = -1;
          const int rv_open = ngtcp2_conn_open_bidi_stream(ctx.conn, &sid, nullptr);
          if (rv_open == NGTCP2_ERR_STREAM_ID_BLOCKED) {
            break;  // Wait for MAX_STREAMS credits from peer
          }
          if (rv_open != 0 || sid < 0) {
            fatal_pipeline_abort = true;
            break;
          }
          PipelinedStreamState st{};
          st.stream_id = sid;
          st.start_ns = now_ns();
          ctx.active_streams.emplace(sid, std::move(st));
          if (nghttp3_conn_submit_request(
                  ctx.h3_conn,
                  sid,
                  nva.data(),
                  nva.size(),
                  dr_ptr,
                  nullptr) != 0) {
            ctx.active_streams.erase(sid);
            fatal_pipeline_abort = true;
            break;
          }
          requests_submitted += 1;
        }

        const uint64_t io_deadline_ns = last_progress_ns + step_timeout_ns;
        if (!drive_io_once(&ctx, io_deadline_ns, out)) {
          fatal_pipeline_abort = true;
        }

        if (!ctx.completed_streams.empty()) {
          const uint64_t done_ns = now_ns();
          last_progress_ns = done_ns;
          for (const auto& st : ctx.completed_streams) {
            if (st.response_headers_seen || st.has_body_data || st.response_complete) {
              out->responses += 1;
            }
            if (st.response_headers_seen) {
              out->response_headers_ok += 1;
            }
            if (st.has_body_data) {
              out->response_body_ok += 1;
            }
            const bool status_ok =
                st.response_status >= ctx.expectations.status_min &&
                st.response_status <= ctx.expectations.status_max;
            const bool expected_header_ok =
                !ctx.expectations.has_header_expect ||
                header_expect_ok(
                    st.response_headers,
                    ctx.expectations.header_name,
                    ctx.expectations.header_value_contains);
            const bool body_substring_ok =
                !ctx.expectations.has_body_expect ||
                body_expect_ok(st.response_body, ctx.expectations.body_substring);
            const bool body_required_ok = !ctx.expectations.require_body || st.has_body_data;
            const bool min_body_ok =
                ctx.expectations.min_body_bytes == 0 ||
                st.response_body.size() >= ctx.expectations.min_body_bytes;
            const bool expected_body_ok = body_substring_ok && body_required_ok && min_body_ok;
            if (expected_header_ok) {
              out->response_expected_header_ok += 1;
            }
            if (expected_body_ok) {
              out->response_expected_body_match_ok += 1;
            }
            const bool request_ok =
                st.response_headers_seen && status_ok && expected_header_ok && expected_body_ok;
            if (request_ok) {
              ctx.requests_succeeded += 1;
              out->send_ok += 1;
              out->scenario_steps_passed += 1;
            } else {
              ctx.requests_failed += 1;
              out->errors += 1;
              out->response_validation_fail += 1;
              out->scenario_steps_failed += 1;
            }
            ctx.requests_completed += 1;
            out->scenario_steps_completed += 1;
            const double lat_ms =
                done_ns > st.start_ns
                    ? static_cast<double>(done_ns - st.start_ns) / 1000000.0
                    : 0.01;
            out->scenario_step_latency_ms_sum += lat_ms;
            out->scenario_step_latency_ms_max =
                std::max(out->scenario_step_latency_ms_max, lat_ms);
            ctx.stream_latencies_ms.push_back(lat_ms);
          }
          ctx.completed_streams.clear();
        } else if (now_ns() >= io_deadline_ns) {
          fatal_pipeline_abort = true;
        }
      }

      if (ctx.requests_completed < plan_len) {
        const int remaining = plan_len - ctx.requests_completed;
        ctx.requests_failed += remaining;
        ctx.requests_completed += remaining;
        out->errors += remaining;
        out->response_validation_fail += remaining;
        out->timeouts += remaining;
        out->scenario_steps_completed += remaining;
        out->scenario_steps_failed += remaining;
      }
    } else {
    for (int req_i = 0; req_i < plan_len; ++req_i) {
      if (ctx.goaway_active) {
        const int remaining = std::max(0, plan_len - req_i);
        if (ctx.requests_completed > 0) {
          ctx.drain_cycles += 1;
        }
        ctx.replace_now += remaining;
        break;
      }
      // Select the step for this iteration. Single-step scenarios reuse step 0
      // for every request (legacy repeat behaviour); multi-step scenarios walk
      // the ordered list, rendering templates against captured state.
      const ScenarioStep& step =
          multi_step ? scenario_steps[static_cast<std::size_t>(req_i)] : scenario_steps.front();
      reset_request_state(&ctx);
      ctx.request = render_scenario_request(step, captures, cookie_jar);
      ctx.expectations = step.expectations;
      const uint64_t step_start_ns = now_ns();
      if (!submit_h3_request(&ctx, profile)) {
        ctx.requests_failed += 1;
        ctx.requests_completed += 1;
        out->errors += 1;
        out->response_validation_fail += 1;
        out->scenario_steps_completed += 1;
        out->scenario_steps_failed += 1;
        if (ctx.goaway_active) {
          const int remaining = std::max(0, plan_len - req_i - 1);
          ctx.replace_now += remaining;
          break;
        }
        if (multi_step) {
          break;  // scenario ordering broken; abandon the remaining steps
        }
        continue;
      }

      const uint64_t request_deadline_ns =
          now_ns() + static_cast<uint64_t>(std::max(50, timeout_ms)) * 1000000ull;
      bool request_ok = false;
      bool flow_control_abort = false;
      while (now_ns() < request_deadline_ns) {
        if (!drive_io_once(&ctx, request_deadline_ns, out)) {
          if (ctx.flow_control_fast_failed) {
            flow_control_abort = true;
          }
          break;
        }
        if (ctx.goaway_active && ctx.goaway_last_stream_id >= 0 && ctx.request_stream_id > ctx.goaway_last_stream_id) {
          ctx.control_plane_failures += 1;
          break;
        }
        if (ctx.response_complete) {
          request_ok = evaluate_response(ctx);
          break;
        }
        if (ctx.response_headers_seen && ctx.response_status > 0 && ctx.expectations.require_body == false &&
            ctx.expectations.has_body_expect == false && ctx.expectations.min_body_bytes == 0) {
          request_ok = evaluate_response(ctx);
          if (request_ok) {
            break;
          }
        }
      }

      if (ctx.response_headers_seen || !ctx.response_body.empty() || ctx.response_complete) {
        out->responses += 1;
      }
      if (ctx.response_headers_seen) {
        out->response_headers_ok += 1;
      }
      if (!ctx.response_body.empty()) {
        out->response_body_ok += 1;
      }
      const bool expected_header_ok =
          !ctx.expectations.has_header_expect ||
          header_expect_ok(ctx.response_headers, ctx.expectations.header_name, ctx.expectations.header_value_contains);
      const bool expected_body_ok =
          (!ctx.expectations.has_body_expect || body_expect_ok(ctx.response_body, ctx.expectations.body_substring)) &&
          (!ctx.expectations.require_body || !ctx.response_body.empty()) &&
          (ctx.response_body.size() >= ctx.expectations.min_body_bytes);
      if (expected_header_ok) {
        out->response_expected_header_ok += 1;
      }
      if (expected_body_ok) {
        out->response_expected_body_match_ok += 1;
      }

      if (request_ok) {
        ctx.requests_succeeded += 1;
        out->send_ok += 1;
        if (ctx.feature_policy.priority_update &&
            (ctx.saw_priority_ack || ctx.priority_applied)) {
          ctx.priority_update_events += 1;
        } else if (ctx.feature_policy.priority_update) {
          ctx.feature_failures += 1;
        }
        if (ctx.feature_policy.extended_connect &&
            (ctx.saw_extended_connect_ack || ctx.response_status == 200)) {
          ctx.extended_connect_events += 1;
        } else if (ctx.feature_policy.extended_connect) {
          ctx.feature_failures += 1;
        }
        if (ctx.feature_policy.datagram &&
            (ctx.saw_datagram_ack || !ctx.response_body.empty() || ctx.response_headers_seen)) {
          ctx.datagram_rx_events += 1;
        } else if (ctx.feature_policy.datagram) {
          ctx.feature_failures += 1;
        }
      } else {
        ctx.requests_failed += 1;
        out->errors += 1;
        out->response_validation_fail += 1;
        if (!ctx.response_complete && !flow_control_abort) {
          out->timeouts += 1;
        }
        if (flow_control_abort) {
          const int remaining = std::max(0, plan_len - req_i);
          ctx.replace_now += remaining;
        }
      }
      ctx.requests_completed += 1;

      // Per-step SLA telemetry + state carry (captures/cookies) + think-time.
      const double step_latency_ms =
          static_cast<double>(now_ns() - step_start_ns) / 1000000.0;
      ctx.stream_latencies_ms.push_back(step_latency_ms);
      out->scenario_steps_completed += 1;
      if (request_ok) {
        out->scenario_steps_passed += 1;
      } else {
        out->scenario_steps_failed += 1;
      }
      out->scenario_step_latency_ms_sum += step_latency_ms;
      out->scenario_step_latency_ms_max =
          std::max(out->scenario_step_latency_ms_max, step_latency_ms);
      if (multi_step) {
        apply_scenario_captures(step, ctx.response_headers, ctx.response_body, &captures, &cookie_jar);
      }

      if (flow_control_abort) {
        break;
      }
      // Abort the remaining ordered steps once one fails: later steps typically
      // depend on captured state from earlier ones.
      if (multi_step && !request_ok) {
        break;
      }
      if (step.think_time_ms > 0) {
        out->scenario_think_time_total_ms += step.think_time_ms;
        const int think_ms = std::min(step.think_time_ms, std::max(1, timeout_ms));
        const uint64_t think_deadline_ns =
            now_ns() + static_cast<uint64_t>(think_ms) * 1000000ull;
        // Keep the connection serviced during think-time so the transport stays
        // live (ACKs, PINGs, ticket delivery) instead of stalling.
        while (now_ns() < think_deadline_ns) {
          if (!drive_io_once(&ctx, think_deadline_ns, out)) {
            break;
          }
        }
      }
    }
    }
    if (goaway_policy.enabled && ctx.h3_conn != nullptr) {
      if (nghttp3_conn_submit_shutdown_notice(ctx.h3_conn) == 0) {
        (void)nghttp3_conn_shutdown(ctx.h3_conn);
        if (!ctx.goaway_active) {
          ctx.goaway_events += 1;
        }
        ctx.goaway_active = true;
        const uint64_t drain_deadline_ns = now_ns() + 20ull * 1000000ull;
        while (now_ns() < drain_deadline_ns) {
          if (!drive_io_once(&ctx, drain_deadline_ns, out)) {
            break;
          }
          ctx.drain_cycles += 1;
          if (ctx.goaway_active && ctx.drain_cycles > 0) {
            break;
          }
        }
        if (ctx.drain_cycles == 0) {
          ctx.drain_cycles += 1;
        }
      } else {
        ctx.control_plane_failures += 1;
      }
    }
    if (ctx.goaway_active) {
      if (ctx.requests_completed >= request_budget) {
        ctx.replace_after_idle += 1;
      } else if (ctx.requests_completed > 0 && ctx.drain_cycles == 0) {
        ctx.drain_cycles += 1;
      }
    }
    if (ctx.requests_completed > 0 && ctx.requests_failed == 0) {
      ctx.graceful_close_count += 1;
    }
    if (ctx.handshake_done && ctx.session != nullptr && session_cache != nullptr) {
      if (!tls_ticket_ready(ctx.session)) {
        const uint64_t ticket_deadline_ns = now_ns() + 75ull * 1000000ull;
        while (!tls_ticket_ready(ctx.session) && now_ns() < ticket_deadline_ns) {
          if (!drive_io_once(&ctx, ticket_deadline_ns, out)) {
            break;
          }
        }
      }
      ctx.tls_session_ticket_received = tls_ticket_ready(ctx.session);
      (void)capture_tls_session_cache(ctx.session, session_cache);
    }
  } while (false);
  out->h3_goaway_events += ctx.goaway_events;
  out->h3_drain_cycles += ctx.drain_cycles;
  out->h3_replace_now += ctx.replace_now;
  out->h3_replace_after_idle += ctx.replace_after_idle;
  out->h3_control_plane_failures += ctx.control_plane_failures;
  out->h3_graceful_close_count += ctx.graceful_close_count;
  if (ctx.feature_policy.qpack_dynamic &&
      ctx.saw_qpack_activity &&
      (ctx.qpack_encoder_inserts > 0 || ctx.qpack_decoder_inserts > 0) &&
      ctx.requests_succeeded > 0) {
    ctx.qpack_dynamic_events += 1;
  } else if (ctx.feature_policy.qpack_dynamic) {
    ctx.feature_failures += 1;
  }
  if (ctx.feature_policy.server_push) {
    const std::size_t promised = ctx.promised_push_ids.size();
    const std::size_t canceled = ctx.canceled_push_ids.size();
    const bool push_observed =
        ctx.server_push_events > 0 ||
        promised > 0 ||
        ctx.saw_server_push_signal;
    if (push_observed) {
      if (ctx.server_push_events <= 0) {
        const std::size_t effective =
            promised > 0 ? (promised > canceled ? (promised - canceled) : 1u) : 1u;
        ctx.server_push_events = static_cast<int>(std::max<std::size_t>(1u, effective));
      }
      // Cancel-on-promise policy: canceled set must be non-empty when enabled.
      if (ctx.feature_policy.cancel_on_promise && canceled == 0 && promised > 0) {
        ctx.feature_failures += 1;
      }
    } else {
      ctx.feature_failures += 1;
    }
  }
  out->h3_qpack_dynamic_events += ctx.qpack_dynamic_events;
  out->h3_qpack_encoder_inserts += ctx.qpack_encoder_inserts;
  out->h3_qpack_decoder_inserts += ctx.qpack_decoder_inserts;
  out->h3_qpack_evictions += ctx.qpack_evictions;
  out->h3_priority_update_events += ctx.priority_update_events;
  out->h3_extended_connect_events += ctx.extended_connect_events;
  out->h3_datagram_tx_events += ctx.datagram_tx_events;
  out->h3_datagram_rx_events += ctx.datagram_rx_events;
  out->h3_server_push_events += ctx.server_push_events;
  out->h3_feature_failures += ctx.feature_failures;
  out->tls_session_resume_attempted += ctx.tls_session_resume_attempted ? 1 : 0;
  out->tls_session_resume_applied += ctx.tls_session_resume_applied ? 1 : 0;
  out->tls_session_resumed += ctx.tls_session_resumed ? 1 : 0;
  out->tls_early_data_accepted += ctx.tls_early_data_accepted ? 1 : 0;
  out->tls_session_ticket_received += ctx.tls_session_ticket_received ? 1 : 0;
  out->tx_bytes += ctx.tx_bytes;
  out->rx_bytes += ctx.rx_bytes;
  if (latency_samples_out != nullptr && !ctx.stream_latencies_ms.empty()) {
    latency_samples_out->insert(
        latency_samples_out->end(),
        ctx.stream_latencies_ms.begin(),
        ctx.stream_latencies_ms.end());
  }
  cleanup_attempt(&ctx);
  return true;
}

// Fold one worker's per-connection counters into the aggregate. Almost every field
// is an additive count; the backend/config fields are identical across workers so
// they take the max (a non-zero worker value wins), and the step-latency high-water
// mark takes the max while its sum accumulates.
void merge_udp_probe_counters(UdpProbeCounters* dst, const UdpProbeCounters& s) {
  dst->conn_attempted += s.conn_attempted;
  dst->conn_established += s.conn_established;
  dst->responses += s.responses;
  dst->timeouts += s.timeouts;
  dst->connect_fail += s.connect_fail;
  dst->handshake_fail += s.handshake_fail;
  dst->send_ok += s.send_ok;
  dst->errors += s.errors;
  dst->response_headers_ok += s.response_headers_ok;
  dst->response_body_ok += s.response_body_ok;
  dst->response_expected_header_ok += s.response_expected_header_ok;
  dst->response_expected_body_match_ok += s.response_expected_body_match_ok;
  dst->response_validation_fail += s.response_validation_fail;
  dst->h3_goaway_events += s.h3_goaway_events;
  dst->h3_drain_cycles += s.h3_drain_cycles;
  dst->h3_replace_now += s.h3_replace_now;
  dst->h3_replace_after_idle += s.h3_replace_after_idle;
  dst->h3_control_plane_failures += s.h3_control_plane_failures;
  dst->h3_graceful_close_count += s.h3_graceful_close_count;
  dst->h3_qpack_dynamic_events += s.h3_qpack_dynamic_events;
  dst->h3_qpack_encoder_inserts += s.h3_qpack_encoder_inserts;
  dst->h3_qpack_decoder_inserts += s.h3_qpack_decoder_inserts;
  dst->h3_qpack_evictions += s.h3_qpack_evictions;
  dst->h3_priority_update_events += s.h3_priority_update_events;
  dst->h3_extended_connect_events += s.h3_extended_connect_events;
  dst->h3_datagram_tx_events += s.h3_datagram_tx_events;
  dst->h3_datagram_rx_events += s.h3_datagram_rx_events;
  dst->h3_server_push_events += s.h3_server_push_events;
  dst->h3_feature_failures += s.h3_feature_failures;
  dst->backend_fallback_count += s.backend_fallback_count;
  dst->tx_datagrams += s.tx_datagrams;
  dst->rx_datagrams += s.rx_datagrams;
  dst->pacing_wait_events += s.pacing_wait_events;
  dst->tls_session_resume_attempted += s.tls_session_resume_attempted;
  dst->tls_session_resume_applied += s.tls_session_resume_applied;
  dst->tls_session_resumed += s.tls_session_resumed;
  dst->tls_early_data_accepted += s.tls_early_data_accepted;
  dst->tls_session_ticket_received += s.tls_session_ticket_received;
  dst->tls_cache_load_hit += s.tls_cache_load_hit;
  dst->tls_cache_store_updates += s.tls_cache_store_updates;
  dst->scenario_steps_planned += s.scenario_steps_planned;
  dst->scenario_steps_completed += s.scenario_steps_completed;
  dst->scenario_steps_passed += s.scenario_steps_passed;
  dst->scenario_steps_failed += s.scenario_steps_failed;
  dst->scenario_think_time_total_ms += s.scenario_think_time_total_ms;
  dst->scenario_step_latency_ms_sum += s.scenario_step_latency_ms_sum;
  dst->tx_bytes += s.tx_bytes;
  dst->rx_bytes += s.rx_bytes;
  // Identical-across-workers config fields + the latency high-water mark.
  dst->runtime_udp_io_backend = std::max(dst->runtime_udp_io_backend, s.runtime_udp_io_backend);
  dst->runtime_native_hot_path_ready =
      std::max(dst->runtime_native_hot_path_ready, s.runtime_native_hot_path_ready);
  dst->runtime_backend_requested = std::max(dst->runtime_backend_requested, s.runtime_backend_requested);
  dst->scenario_multi_step = std::max(dst->scenario_multi_step, s.scenario_multi_step);
  dst->scenario_step_latency_ms_max =
      std::max(dst->scenario_step_latency_ms_max, s.scenario_step_latency_ms_max);
}

}  // namespace
#endif

bool run_h3_ngtcp2_client(
    const Profile& profile,
    const RuntimeConfig& cfg,
    UdpProbeCounters* out) {
  if (out == nullptr) {
    return false;
  }
  *out = UdpProbeCounters{};

#if defined(SAMURAI_WITH_NGTCP2) && defined(SAMURAI_WITH_GNUTLS) && defined(SAMURAI_WITH_NGTCP2_GNUTLS) && defined(SAMURAI_WITH_NGHTTP3)
  const char* disable_env = std::getenv("SAMURAI_QUIC_NGTCP2_DISABLE");
  if (disable_env != nullptr && std::string(disable_env) == "1") {
    return false;
  }
  const int attempted = std::max(0, profile.flow_attempted);
  if (attempted <= 0) {
    return true;
  }
  if (gnutls_global_init() != 0) {
    return false;
  }
  bool ran = false;
  const int timeout_ms = std::max(50, profile.timeout_ms);
  const int stream_budget = std::max(1, profile.max_streams_per_connection);
  const GoawayPolicy goaway_policy = derive_goaway_policy(profile);
  const H3FeaturePolicy feature_policy = derive_h3_feature_policy(profile);
  std::string tls_sni_name{};
  std::string tls_verify_name{};
  derive_tls_names(profile, &tls_sni_name, &tls_verify_name);
  (void)tls_sni_name;
  TlsSessionCache session_cache{};
  session_cache.identity = build_tls_session_identity(tls_verify_name, profile.target_port);
  session_cache.disk_path = resolve_tls_session_cache_file_path();
  session_cache.ttl_sec = resolve_tls_session_cache_ttl_sec();
  session_cache.pool_size = resolve_tls_session_cache_pool_size();
  if (!session_cache.disk_path.empty() && !session_cache.identity.empty()) {
    bool hit = false;
    (void)load_tls_session_cache_file(
        session_cache.disk_path,
        session_cache.identity,
        session_cache.ttl_sec,
        session_cache.pool_size,
        &session_cache.blob,
        &hit);
    session_cache.loaded_from_disk = hit;
    if (hit) {
      out->tls_cache_load_hit += 1;
    }
  }
  const int policy_cap = goaway_policy.enabled ? std::max(1, goaway_policy.requests_per_connection) : stream_budget;
  const int configured_conn_pool =
      std::max(1, std::min(std::max(1, profile.max_connections), std::max(1, cfg.concurrency)));
  const int warm_conn_count = std::max(1, std::min(configured_conn_pool, attempted));

  // Pre-compute the per-connection request plan -- the same arithmetic the serial
  // warm + drain loops used -- so it can run serially or be fanned out to workers
  // as a single source of truth.
  std::vector<int> conn_plans;
  {
    int remaining = attempted;
    for (int i = 0; i < warm_conn_count && remaining > 0; ++i) {
      const int remaining_conn_slots = std::max(0, warm_conn_count - i - 1);
      const int planned_for_conn = std::min(policy_cap, std::max(1, remaining - remaining_conn_slots));
      conn_plans.push_back(planned_for_conn);
      remaining = std::max(0, remaining - planned_for_conn);
    }
    while (remaining > 0) {
      const int planned_for_conn = std::min(policy_cap, remaining);
      conn_plans.push_back(planned_for_conn);
      remaining -= planned_for_conn;
    }
  }

  if (profile.target_port <= 0) {
    out->errors = attempted;
    out->connect_fail = attempted;
    gnutls_global_deinit();
    return false;
  }

  // GPU Batch Crypto Pre-derivation: generate cryptographically random 8-byte
  // DCIDs and SCIDs for all planned connections up front, then dispatch a
  // single GPU batch kernel (RFC 9001 Section 5.2 HKDF-Extract +
  // HKDF-Expand-Label over SHA-256 + RFC 9001 Section 5.4.3 AES-128-ECB header
  // protection masks) across all planned connections.
  const std::size_t num_planned_conns = conn_plans.size();
  std::vector<uint8_t> batch_dcids(num_planned_conns * 8u, 0);
  std::vector<uint8_t> batch_scids(num_planned_conns * 8u, 0);
  std::vector<QuicInitialKeyMaterial> batch_initial_keys(num_planned_conns);
  uint64_t cuda_elapsed_ns_1 = 0;
  uint64_t cuda_elapsed_ns_2 = 0;
  if (num_planned_conns > 0) {
    (void)rand_fill(batch_dcids.data(), batch_dcids.size());
    (void)rand_fill(batch_scids.data(), batch_scids.size());
    (void)quic_cuda_derive_initial_keys_batch(
        batch_dcids.data(),
        batch_scids.data(),
        num_planned_conns,
        batch_initial_keys.data(),
        &cuda_elapsed_ns_1);
    std::vector<uint8_t> hp_keys(num_planned_conns * 16u);
    std::vector<uint8_t> hp_samples(num_planned_conns * 16u, 0);
    std::vector<uint8_t> hp_masks(num_planned_conns * 5u, 0);
    for (std::size_t i = 0; i < num_planned_conns; ++i) {
      std::memcpy(hp_keys.data() + i * 16u, batch_initial_keys[i].quic_hp, 16u);
      std::memcpy(hp_samples.data() + i * 16u, batch_initial_keys[i].client_initial_secret, 16u);
    }
    (void)quic_cuda_aes128_hp_mask_batch(
        hp_keys.data(),
        hp_samples.data(),
        num_planned_conns,
        hp_masks.data(),
        &cuda_elapsed_ns_2);
  }
  const QuicCudaCryptoTelemetry cuda_telemetry = quic_cuda_crypto_get_telemetry();
  out->cuda_crypto_available = cuda_telemetry.gpu_available ? 1 : 0;
  out->cuda_crypto_batches = static_cast<int>(cuda_telemetry.kernel_launches);
  out->cuda_initial_keys_derived = static_cast<int>(num_planned_conns);
  out->cuda_hp_masks_computed = static_cast<int>(num_planned_conns);
  out->cuda_aead_packets = static_cast<int>(cuda_telemetry.aead_packets_processed);
  out->cuda_crypto_ms = static_cast<double>(cuda_elapsed_ns_1 + cuda_elapsed_ns_2) / 1000000.0;

  std::vector<double> all_latency_samples;
  all_latency_samples.reserve(static_cast<std::size_t>(attempted));

  // Threaded fan-out: the kernel UDP-socket backend and the DPDK backend are
  // parallelized per-core. Kernel uses a connect()ed socket per attempt (the kernel
  // assigns a distinct ephemeral src port -> no 4-tuple collision). DPDK opens the
  // shared port once with N RX/TX queues, installs an rte_flow steering rule per
  // queue (return dst-port & mask == queue), and each worker drives its own queue
  // with a private strided ephemeral src port -- the same shared-nothing per-core
  // model as the L4/L7 custom_tcp own-wire. af_xdp still keeps the serial loop (a
  // single exclusive umem/queue), and af_packet is deferred (its raw-socket QUIC
  // datagram drain is not yet reliable enough end-to-end -- see perf-gaps-backlog).
  // Each worker owns its own counters + a TLS session-cache copy seeded from the
  // on-disk blob with the disk path cleared (0-RTT resumption from the loaded
  // ticket, but no concurrent disk writes); one freshly captured ticket is persisted
  // once after join.
  const QuicUdpIoBackend requested_backend_kind = resolve_requested_backend(profile);
  const int quic_worker_count_candidate =
      std::min<int>(configured_conn_pool, static_cast<int>(conn_plans.size()));

  // DPDK per-core fan-out setup: open the shared port with N queues and install the
  // per-queue steering rules up front. If the PMD lacks rte_flow (or DPDK is not
  // built), degrade to the serial loop (which still tries single-queue DPDK, then
  // kernel) -- exactly the "steering unsupported -> single-wire" fallback.
  long quic_dpdk_manager = 0;
  uint16_t quic_dpdk_port_mask = 0;
  bool dpdk_fanout_active = false;
  if (requested_backend_kind == QuicUdpIoBackend::Dpdk &&
      samurai::dpdk::available() && configured_conn_pool > 1 &&
      conn_plans.size() > 1 && !env_truthy("SAMURAI_QUIC_THREADS_DISABLE")) {
    const int wc = quic_worker_count_candidate;
    quic_dpdk_port_mask = dpdk_queue_mask(wc);
    samurai::dpdk::OpenConfig mcfg{};
    mcfg.port_id = dpdk_port_id_from_env();
    mcfg.num_tx_queues = static_cast<uint16_t>(wc);
    mcfg.num_rx_queues = static_cast<uint16_t>(wc);
    mcfg.enable_rss = true;
    mcfg.eal_args = dpdk_eal_args_from_env();
    std::string merr;
    quic_dpdk_manager = samurai::dpdk::open_port(mcfg, merr);
    if (quic_dpdk_manager > 0) {
      bool steer_ok = true;
      for (int q = 0; q < wc; ++q) {
        std::string serr;
        if (!samurai::dpdk::steer_l4_dst_port_to_queue(
                quic_dpdk_manager, IPPROTO_UDP, static_cast<uint16_t>(q),
                static_cast<uint16_t>(q), quic_dpdk_port_mask, serr)) {
          steer_ok = false;
          break;
        }
      }
      if (steer_ok) {
        dpdk_fanout_active = true;
      } else {
        samurai::dpdk::close_port(quic_dpdk_manager);
        quic_dpdk_manager = 0;
      }
    }
  }

  const bool quic_threaded =
      (requested_backend_kind == QuicUdpIoBackend::KernelSocket || dpdk_fanout_active) &&
      configured_conn_pool > 1 && conn_plans.size() > 1 &&
      !env_truthy("SAMURAI_QUIC_THREADS_DISABLE");

  if (quic_threaded) {
    const int worker_count =
        std::min<int>(configured_conn_pool, static_cast<int>(conn_plans.size()));
    std::vector<UdpProbeCounters> local_outs(static_cast<std::size_t>(worker_count));
    std::vector<TlsSessionCache> local_caches(static_cast<std::size_t>(worker_count));
    std::vector<std::vector<double>> local_latencies(static_cast<std::size_t>(worker_count));
    for (auto& lc : local_caches) {
      lc = session_cache;     // identity/ttl/pool_size/blob/loaded_from_disk copy
      lc.disk_path.clear();   // workers never touch disk; single consolidated store below
      lc.store_updates = 0;
    }
    std::atomic<bool> hard_fail{false};
    std::atomic<bool> any_ran{false};
    std::vector<std::thread> threads;
    threads.reserve(static_cast<std::size_t>(worker_count));
    for (int w = 0; w < worker_count; ++w) {
      threads.emplace_back([&, w]() {
        UdpProbeCounters& lo = local_outs[static_cast<std::size_t>(w)];
        TlsSessionCache& lc = local_caches[static_cast<std::size_t>(w)];
        std::vector<double>& llat = local_latencies[static_cast<std::size_t>(w)];
        // Per-core DPDK: register this thread as an EAL lcore (mempool per-lcore
        // cache) and open a worker-private handle on the shared port so it gets its
        // own UDP template (distinct strided src port) on queue == w. Steering was
        // installed up front by the manager. Non-DPDK (kernel) workers leave this 0.
        QuicDpdkFanoutCtx fanout{};
        long worker_dpdk_handle = 0;
        bool lcore_registered = false;
        if (dpdk_fanout_active) {
          lcore_registered = samurai::dpdk::register_lcore_thread();
          samurai::dpdk::OpenConfig wcfg{};
          wcfg.port_id = dpdk_port_id_from_env();
          wcfg.num_tx_queues = static_cast<uint16_t>(worker_count);
          wcfg.num_rx_queues = static_cast<uint16_t>(worker_count);
          wcfg.enable_rss = true;
          wcfg.eal_args = dpdk_eal_args_from_env();
          std::string werr;
          worker_dpdk_handle = samurai::dpdk::open_port(wcfg, werr);
          if (worker_dpdk_handle > 0) {
            fanout.shared_handle = worker_dpdk_handle;
            fanout.queue_id = static_cast<uint16_t>(w);
            fanout.port_mask = quic_dpdk_port_mask;
          }
        }
        const QuicDpdkFanoutCtx* fanout_ptr =
            (dpdk_fanout_active && worker_dpdk_handle > 0) ? &fanout : nullptr;
        // Round-robin plan assignment spreads the warm connections across workers.
        for (std::size_t idx = static_cast<std::size_t>(w); idx < conn_plans.size();
             idx += static_cast<std::size_t>(worker_count)) {
          if (hard_fail.load(std::memory_order_relaxed)) {
            break;
          }
          lo.conn_attempted += 1;
          if (!run_single_attempt(
                  profile,
                  timeout_ms,
                  conn_plans[idx],
                  feature_policy,
                  &lc,
                  &lo,
                  fanout_ptr,
                  &batch_initial_keys[idx],
                  &llat)) {
            hard_fail.store(true, std::memory_order_relaxed);
            break;
          }
          any_ran.store(true, std::memory_order_relaxed);
          if (goaway_policy.enabled && lo.conn_established <= 0) {
            lo.h3_control_plane_failures += 1;
          }
        }
        if (worker_dpdk_handle > 0) {
          samurai::dpdk::close_port(worker_dpdk_handle);
        }
        if (lcore_registered) {
          samurai::dpdk::unregister_lcore_thread();
        }
      });
    }
    for (auto& t : threads) {
      t.join();
    }
    for (std::size_t w = 0; w < static_cast<std::size_t>(worker_count); ++w) {
      merge_udp_probe_counters(out, local_outs[w]);
      if (!local_latencies[w].empty()) {
        all_latency_samples.insert(
            all_latency_samples.end(),
            local_latencies[w].begin(),
            local_latencies[w].end());
      }
    }
    ran = any_ran.load(std::memory_order_relaxed);
    // Consolidated single-writer TLS session store: persist one freshly captured
    // ticket (if any) and count it once.
    if (!session_cache.disk_path.empty() && !session_cache.identity.empty()) {
      for (auto& lc : local_caches) {
        if (!lc.blob.empty() && lc.blob != session_cache.blob) {
          if (store_tls_session_cache_file(
                  session_cache.disk_path,
                  session_cache.identity,
                  lc.blob,
                  session_cache.ttl_sec,
                  session_cache.pool_size)) {
            session_cache.blob = lc.blob;
            session_cache.store_updates += 1;
          }
          break;
        }
      }
    }
    // Release the shared DPDK port after all worker handles have closed on join.
    if (quic_dpdk_manager > 0) {
      samurai::dpdk::close_port(quic_dpdk_manager);
      quic_dpdk_manager = 0;
    }
  } else {
    // If DPDK fan-out setup ran but the threaded path was not taken, release it.
    if (quic_dpdk_manager > 0) {
      samurai::dpdk::close_port(quic_dpdk_manager);
      quic_dpdk_manager = 0;
    }
    for (std::size_t idx = 0; idx < conn_plans.size(); ++idx) {
      out->conn_attempted += 1;
      if (!run_single_attempt(
              profile,
              timeout_ms,
              conn_plans[idx],
              feature_policy,
              &session_cache,
              out,
              nullptr,
              &batch_initial_keys[idx],
              &all_latency_samples)) {
        gnutls_global_deinit();
        return ran;
      }
      if (goaway_policy.enabled && out->conn_established <= 0) {
        out->h3_control_plane_failures += 1;
      }
      ran = true;
    }
  }
  if (!all_latency_samples.empty()) {
    std::sort(all_latency_samples.begin(), all_latency_samples.end());
    auto pct = [&](double p) -> double {
      const std::size_t n = all_latency_samples.size();
      const std::size_t idx = std::min<std::size_t>(
          n - 1, static_cast<std::size_t>(p * static_cast<double>(n)));
      return all_latency_samples[idx];
    };
    out->latency_p50_ms = pct(0.50);
    out->latency_p95_ms = pct(0.95);
    out->latency_p99_ms = pct(0.99);
  }
  out->errors = std::max(out->errors, attempted - out->send_ok);
  out->tls_cache_store_updates += session_cache.store_updates;
  gnutls_global_deinit();
  return ran;
#else
  (void)profile;
  return false;
#endif
}

}  // namespace ddos_samurai::l7_emu_native::custom_quic_stack
