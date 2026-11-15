#include "samurai/telecom/core/fastpath_classifier.hpp"

#include <cstring>
#include <arpa/inet.h>

namespace samurai::telecom {

bool FastpathClassifier::Classify(const uint8_t* frame, size_t len, 
                                  PacketMetadata& meta, 
                                  TelcoFrameType& out_type) noexcept {
    out_type = TelcoFrameType::Unknown;
    if (!frame || len < 14) return false;

    // Reset metadata
    meta = PacketMetadata{};
    meta.raw_frame = frame;
    meta.raw_len = static_cast<uint16_t>(len);

    // MAC adreslerini kopyala
    std::memcpy(meta.dst_mac, frame, 6);
    std::memcpy(meta.src_mac, frame + 6, 6);

    size_t offset = 12;
    uint16_t ethertype = (static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1];
    offset += 2;

    // 802.1ad (QinQ Service Tag) - supports 0x88A8 and legacy 0x9100
    if ((ethertype == 0x88A8 || ethertype == 0x9100) && len >= offset + 4) {
        meta.outer_vlan = ((static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1]) & 0x0FFF;
        offset += 2;
        ethertype = (static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1];
        offset += 2;
    }

    // 802.1Q (Customer Tag)
    if (ethertype == 0x8100 && len >= offset + 4) {
        uint16_t vlan = ((static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1]) & 0x0FFF;
        if (meta.outer_vlan == 0) {
            meta.outer_vlan = vlan;
        } else {
            meta.inner_vlan = vlan;
        }
        offset += 2;
        ethertype = (static_cast<uint16_t>(frame[offset]) << 8) | frame[offset + 1];
        offset += 2;
    }

    meta.ether_type = ethertype;

    // Protokol sınıflandırma
    if (ethertype == 0x8863) { // PPPoE Discovery
        out_type = TelcoFrameType::PppoeDiscovery;
        meta.payload_ptr = frame + offset;
        meta.payload_len = static_cast<uint16_t>(len - offset);
        return true;
    }

    if (ethertype == 0x8864) { // PPPoE Session
        out_type = TelcoFrameType::PppoeSession;
        meta.payload_ptr = frame + offset;
        meta.payload_len = static_cast<uint16_t>(len - offset);
        return true;
    }

    if (ethertype == 0x0806 && len >= offset + 28) { // ARP (RFC 826 payload is 28 bytes)
        out_type = TelcoFrameType::Arp;
        meta.payload_ptr = frame + offset;
        meta.payload_len = static_cast<uint16_t>(len - offset);
        return true;
    }

    if (ethertype == 0x888E) { // 802.1X EAPOL
        out_type = TelcoFrameType::Eapol;
        meta.payload_ptr = frame + offset;
        meta.payload_len = static_cast<uint16_t>(len - offset);
        return true;
    }

    // IPv4
    if (ethertype == 0x0800 && len >= offset + 20) {
        const uint8_t* ip_hdr = frame + offset;
        if ((ip_hdr[0] >> 4) != 4) return false;

        uint8_t ihl = (ip_hdr[0] & 0x0F) * 4;
        if (ihl < 20 || len < offset + ihl) return false;

        size_t ip_start_offset = offset;
        uint16_t total_len = (static_cast<uint16_t>(ip_hdr[2]) << 8) | ip_hdr[3];
        if (total_len >= ihl && ip_start_offset + total_len <= len) {
            // Frame uzunluğunu IP total_length ile sınırla (Ethernet trailer padding'i kaldır)
            len = ip_start_offset + total_len;
        }

        // IPv4 Fragmentation Kontrolü (RFC 791)
        uint16_t frag_field = (static_cast<uint16_t>(ip_hdr[6]) << 8) | ip_hdr[7];
        uint16_t frag_offset = (frag_field & 0x1FFF) * 8;
        if (frag_offset > 0) {
            // İlk olmayan fragment; L4 başlığı içermez
            out_type = TelcoFrameType::Ipv4Data;
            offset += ihl;
            meta.payload_ptr = frame + offset;
            meta.payload_len = static_cast<uint16_t>(len - offset);
            return true;
        }

        uint8_t proto = ip_hdr[9];
        uint32_t src_ip = 0;
        uint32_t dst_ip = 0;
        std::memcpy(&src_ip, ip_hdr + 12, sizeof(src_ip));
        std::memcpy(&dst_ip, ip_hdr + 16, sizeof(dst_ip));
        meta.src_ip = ntohl(src_ip);
        meta.dst_ip = ntohl(dst_ip);

        offset += ihl;

        if (proto == 2) { // IGMP
            out_type = TelcoFrameType::Igmp;
            meta.payload_ptr = frame + offset;
            meta.payload_len = static_cast<uint16_t>(len - offset);
            return true;
        }

        if (proto == 132 && len >= offset + 12) { // SCTP
            const uint8_t* sctp_hdr = frame + offset;
            meta.src_port = (static_cast<uint16_t>(sctp_hdr[0]) << 8) | sctp_hdr[1];
            meta.dst_port = (static_cast<uint16_t>(sctp_hdr[2]) << 8) | sctp_hdr[3];
            offset += 12;
            meta.payload_ptr = frame + offset;
            meta.payload_len = static_cast<uint16_t>(len - offset);

            if (meta.dst_port == 3868 || meta.src_port == 3868) {
                out_type = TelcoFrameType::Diameter;
            } else {
                out_type = TelcoFrameType::Sctp;
            }
            return true;
        }

        if (proto == 6 && len >= offset + 20) { // TCP
            const uint8_t* tcp_hdr = frame + offset;
            meta.src_port = (static_cast<uint16_t>(tcp_hdr[0]) << 8) | tcp_hdr[1];
            meta.dst_port = (static_cast<uint16_t>(tcp_hdr[2]) << 8) | tcp_hdr[3];
            size_t tcp_hdr_len = ((tcp_hdr[12] >> 4) & 0x0F) * 4;
            if (tcp_hdr_len >= 20 && len >= offset + tcp_hdr_len) {
                offset += tcp_hdr_len;
                meta.payload_ptr = frame + offset;
                meta.payload_len = static_cast<uint16_t>(len - offset);

                if (meta.dst_port == 3868 || meta.src_port == 3868) {
                    out_type = TelcoFrameType::Diameter;
                    return true;
                }
                if (meta.dst_port == 5060 || meta.src_port == 5060) {
                    out_type = TelcoFrameType::Sip;
                    return true;
                }
            }
        }

        if (proto == 17 && len >= offset + 8) { // UDP
            const uint8_t* udp_hdr = frame + offset;
            uint16_t udp_len = (static_cast<uint16_t>(udp_hdr[4]) << 8) | udp_hdr[5];
            if (udp_len < 8) {
                return false; // RFC 768 geçersiz UDP header boyutu
            }
            meta.src_port = (static_cast<uint16_t>(udp_hdr[0]) << 8) | udp_hdr[1];
            meta.dst_port = (static_cast<uint16_t>(udp_hdr[2]) << 8) | udp_hdr[3];
            offset += 8;

            meta.payload_ptr = frame + offset;
            size_t avail = (len >= offset) ? (len - offset) : 0;
            meta.payload_len = static_cast<uint16_t>(std::min(static_cast<size_t>(udp_len - 8), avail));

            if (meta.dst_port == 67 || meta.dst_port == 68 || meta.src_port == 67 || meta.src_port == 68) {
                out_type = TelcoFrameType::Dhcp;
                return true;
            }
            if (meta.dst_port == 3784 || meta.dst_port == 3785) {
                out_type = TelcoFrameType::Bfd;
                return true;
            }
            if (meta.dst_port == 2152 || meta.src_port == 2152) { // 3GPP GTP-U
                out_type = TelcoFrameType::Gtpu;
                return true;
            }
            if (meta.dst_port == 8805 || meta.src_port == 8805) { // 3GPP PFCP
                out_type = TelcoFrameType::Pfcp;
                return true;
            }
            if (meta.dst_port == 5060 || meta.src_port == 5060) { // SIP
                out_type = TelcoFrameType::Sip;
                return true;
            }
            if ((meta.dst_port >= 10000 && meta.dst_port <= 20000) ||
                (meta.src_port >= 10000 && meta.src_port <= 20000)) { // RTP Audio
                if (meta.payload_len >= 12 && (meta.payload_ptr[0] >> 6) == 2) {
                    out_type = TelcoFrameType::Rtp;
                    return true;
                }
            }
        }

        out_type = TelcoFrameType::Ipv4Data;
        meta.payload_ptr = frame + offset;
        meta.payload_len = static_cast<uint16_t>(len - offset);
        return true;
    }

    // IPv6
    if (ethertype == 0x86DD && len >= offset + 40) {
        const uint8_t* ip6_hdr = frame + offset;
        if ((ip6_hdr[0] >> 4) != 6) return false;

        uint8_t next_header = ip6_hdr[6];
        offset += 40;

        // IPv6 Extension Headers traversal (RFC 8200)
        while (offset < len) {
            if (next_header == 0 || next_header == 43 || next_header == 60) {
                // Hop-by-Hop (0), Routing (43), Destination Options (60)
                if (len < offset + 2) break;
                uint8_t nxt = frame[offset];
                size_t ext_len = (static_cast<size_t>(frame[offset + 1]) + 1) * 8;
                if (len < offset + ext_len) break;
                next_header = nxt;
                offset += ext_len;
            } else if (next_header == 44) {
                // Fragment Header (RFC 8200 §4.5) - 8 bayt
                if (len < offset + 8) break;
                uint8_t nxt = frame[offset];
                uint16_t frag_off = (static_cast<uint16_t>(frame[offset + 2]) << 8) | frame[offset + 3];
                frag_off &= 0xFFF8;
                offset += 8;
                next_header = nxt;
                if (frag_off > 0) {
                    out_type = TelcoFrameType::Ipv6Data;
                    meta.payload_ptr = frame + offset;
                    meta.payload_len = static_cast<uint16_t>(len - offset);
                    return true;
                }
            } else {
                break;
            }
        }

        meta.payload_ptr = frame + offset;
        meta.payload_len = static_cast<uint16_t>(len - offset);

        if (next_header == 58) { // ICMPv6
            out_type = TelcoFrameType::Icmpv6Nd;
            return true;
        }
        if (next_header == 17 && len >= offset + 8) { // UDP
            const uint8_t* udp_hdr = frame + offset;
            uint16_t udp_len = (static_cast<uint16_t>(udp_hdr[4]) << 8) | udp_hdr[5];
            if (udp_len < 8) {
                return false;
            }
            meta.src_port = (static_cast<uint16_t>(udp_hdr[0]) << 8) | udp_hdr[1];
            meta.dst_port = (static_cast<uint16_t>(udp_hdr[2]) << 8) | udp_hdr[3];
            offset += 8;
            meta.payload_ptr = frame + offset;
            size_t avail = (len >= offset) ? (len - offset) : 0;
            meta.payload_len = static_cast<uint16_t>(std::min(static_cast<size_t>(udp_len - 8), avail));

            if (meta.dst_port == 546 || meta.dst_port == 547) {
                out_type = TelcoFrameType::Dhcp;
                return true;
            }
            if (meta.dst_port == 3784 || meta.dst_port == 3785) {
                out_type = TelcoFrameType::Bfd;
                return true;
            }
            if (meta.dst_port == 2152 || meta.src_port == 2152) { // 3GPP GTP-U over IPv6
                out_type = TelcoFrameType::Gtpu;
                return true;
            }
            if (meta.dst_port == 8805 || meta.src_port == 8805) { // 3GPP PFCP over IPv6
                out_type = TelcoFrameType::Pfcp;
                return true;
            }
        }

        out_type = TelcoFrameType::Ipv6Data;
        return true;
    }

    meta.payload_ptr = frame + offset;
    meta.payload_len = static_cast<uint16_t>(len > offset ? len - offset : 0);
    return true;
}

} // namespace samurai::telecom
