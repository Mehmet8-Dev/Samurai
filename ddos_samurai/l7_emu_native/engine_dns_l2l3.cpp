#include "engine_internal.hpp"
#include "dns_client_engine.hpp"
#include "l2l3_stack/dhcp_state_machine.hpp"
#include "l2l3_stack/arp_engine.hpp"
#include "l2l3_stack/igmp_engine.hpp"
#include "l2l3_stack/nd_engine.hpp"

namespace ddos_samurai::l7_emu_native {

std::map<std::string, double> run_dns_profile(const Profile& profile, const RuntimeConfig& cfg) {
  (void)cfg;
  std::map<std::string, double> out;
  init_stats(profile, out);
  dns::DnsClientEngine engine;
  int attempts = std::max(1, profile.flow_attempted > 0 ? profile.flow_attempted : profile.session_repeats);
  int sent = 0;
  int errors = 0;
  std::size_t tx_bytes = 0;
  std::size_t rx_bytes = 0;

  const std::string server_ip = profile.target_ip;
  const uint16_t server_port = static_cast<uint16_t>(profile.target_port > 0 ? profile.target_port : 53);

  for (int i = 0; i < attempts; ++i) {
    std::string hostname = profile.host_header.empty() ? (profile.target_ip.empty() ? "example.com" : profile.target_ip) : profile.host_header;
    std::string qtype = "A";
    int edns0 = 1;
    std::string ecs_subnet = "";
    std::string protocol = "udp";

    for (const auto& op : profile.ops) {
      if (!op.dns_hostname.empty()) hostname = op.dns_hostname;
      if (!op.dns_qtype.empty()) qtype = op.dns_qtype;
      if (op.dns_edns0 >= 0) edns0 = op.dns_edns0;
      if (!op.dns_ecs_subnet.empty()) ecs_subnet = op.dns_ecs_subnet;
      if (!op.dns_protocol.empty()) protocol = op.dns_protocol;
    }

    dns::DnsResponse resp;
    if (!server_ip.empty() && server_ip != "example.com" && server_ip != "localhost" && server_ip != "127.0.0.1") {
      resp = engine.resolve_network(server_ip, server_port, hostname, protocol, qtype, edns0, ecs_subnet, profile.timeout_ms > 0 ? profile.timeout_ms : 2000);
      if (!resp.success) {
        resp = engine.resolve(hostname, protocol, qtype, edns0, ecs_subnet);
      }
    } else {
      resp = engine.resolve(hostname, protocol, qtype, edns0, ecs_subnet);
    }

    const auto& query_pkt = engine.last_query_packet();
    tx_bytes += query_pkt.size();
    if (resp.success) {
      sent++;
      rx_bytes += 64;
      record_scenario_step_result("dns", "dns_flow", "vu1", "", true, false, 200, 1.0);
    } else {
      errors++;
      record_scenario_step_result("dns", "dns_flow", "vu1", "", false, true, 500, 1.0);
    }
  }

  out["attempted"] = static_cast<double>(attempts);
  out["sent"] = static_cast<double>(sent);
  out["errors"] = static_cast<double>(errors);
  out["responses_total"] = static_cast<double>(sent);
  out["dns_queries_sent"] = static_cast<double>(attempts);
  out["dns_responses_parsed"] = static_cast<double>(sent);
  out["l7_tx_bytes"] = static_cast<double>(tx_bytes);
  out["l7_rx_bytes"] = static_cast<double>(rx_bytes);
  return out;
}

static bool send_raw_l2l3_packet(const std::string& iface_name, const std::vector<uint8_t>& pkt) {
#if defined(__linux__)
  if (iface_name.empty() || pkt.empty()) return false;
  int sock = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock < 0) return false;
  ifreq ifr{};
  std::snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface_name.c_str());
  if (::ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
    ::close(sock);
    return false;
  }
  sockaddr_ll sll{};
  std::memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = ifr.ifr_ifindex;
  sll.sll_halen = 6;
  if (pkt.size() >= 6) {
    std::memcpy(sll.sll_addr, pkt.data(), 6);
  }
  ssize_t sent = ::sendto(sock, pkt.data(), pkt.size(), 0, reinterpret_cast<sockaddr*>(&sll), sizeof(sll));
  ::close(sock);
  return sent > 0;
#else
  (void)iface_name; (void)pkt;
  return false;
#endif
}

std::map<std::string, double> run_l2l3_profile(const Profile& profile, const RuntimeConfig& cfg) {
  std::map<std::string, double> out;
  init_stats(profile, out);
  int attempts = std::max(1, profile.flow_attempted > 0 ? profile.flow_attempted : profile.session_repeats);
  int sent = 0;
  std::size_t tx_bytes = 0;
  int raw_tx_sent = 0;

  (void)cfg;
  std::string iface = profile.interface_name;
  if (iface.empty()) {
    const char* env_if = std::getenv("SAMURAI_L2L3_INTERFACE");
    if (env_if != nullptr) iface = env_if;
  }

  if (profile.protocol == "dhcp") {
    l2l3::DhcpStateMachine dhcp;
    l2l3::DhcpConfig dhcp_cfg;
    dhcp_cfg.client_mac = "00:11:22:33:44:55";
    for (int i = 0; i < attempts; ++i) {
      dhcp.start(dhcp_cfg);
      const auto& p1 = dhcp.last_tx_packet();
      tx_bytes += p1.size();
      if (!iface.empty() && send_raw_l2l3_packet(iface, p1)) raw_tx_sent++;
      dhcp.process_offer("10.0.0.100", "10.0.0.1");
      const auto& p2 = dhcp.last_tx_packet();
      tx_bytes += p2.size();
      if (!iface.empty() && send_raw_l2l3_packet(iface, p2)) raw_tx_sent++;
      dhcp.process_ack("10.0.0.100");
      sent += 1;
    }
    out["dhcp_sessions_bound"] = static_cast<double>(sent);
  } else if (profile.protocol == "igmp") {
    l2l3::IgmpEngine igmp;
    for (int i = 0; i < attempts; ++i) {
      igmp.join_group("224.1.1.1");
      const auto& p1 = igmp.last_tx_packet();
      tx_bytes += p1.size();
      if (!iface.empty() && send_raw_l2l3_packet(iface, p1)) raw_tx_sent++;
      igmp.leave_group("224.1.1.1");
      const auto& p2 = igmp.last_tx_packet();
      tx_bytes += p2.size();
      if (!iface.empty() && send_raw_l2l3_packet(iface, p2)) raw_tx_sent++;
      sent += 1;
    }
    out["igmp_reports_sent"] = static_cast<double>(sent * 2);
  } else if (profile.protocol == "nd" || profile.protocol == "ipv6_nd") {
    l2l3::NdEngine nd;
    for (int i = 0; i < attempts; ++i) {
      nd.send_neighbor_solicitation("fe80::1");
      const auto& p1 = nd.last_tx_packet();
      tx_bytes += p1.size();
      if (!iface.empty() && send_raw_l2l3_packet(iface, p1)) raw_tx_sent++;
      sent += 1;
    }
    out["nd_solicitations_sent"] = static_cast<double>(sent);
  } else if (profile.protocol == "arp") {
    l2l3::ArpEngine arp;
    for (int i = 0; i < attempts; ++i) {
      arp.send_arp_request(profile.target_ip.empty() ? "192.168.1.1" : profile.target_ip);
      const auto& p1 = arp.last_tx_packet();
      tx_bytes += p1.size();
      if (!iface.empty() && send_raw_l2l3_packet(iface, p1)) raw_tx_sent++;
      sent += 1;
    }
    out["arp_requests_sent"] = static_cast<double>(sent);
  }

  out["attempted"] = static_cast<double>(attempts);
  out["sent"] = static_cast<double>(sent);
  out["errors"] = 0.0;
  out["responses_total"] = static_cast<double>(sent);
  out["l7_tx_bytes"] = static_cast<double>(tx_bytes);
  out["l7_rx_bytes"] = 0.0;
  out["l2l3_raw_socket_tx_sent"] = static_cast<double>(raw_tx_sent);
  out["l2l3_interface_active"] = iface.empty() ? 0.0 : 1.0;
  return out;
}

}  // namespace ddos_samurai::l7_emu_native
