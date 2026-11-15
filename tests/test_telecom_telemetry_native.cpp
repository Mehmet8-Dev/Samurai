#include "l2l3_stack/bfd_engine.hpp"
#include "l2l3_stack/arp_engine.hpp"
#include "l2l3_stack/dhcp_state_machine.hpp"
#include "l2l3_stack/nd_engine.hpp"
#include "l2l3_stack/igmp_engine.hpp"
#include "telecom/lockfree_l2l3_cache.hpp"
#include "telecom/l2l3_fastpath_wiring.hpp"
#include "telemetry/ipfix_types.hpp"
#include "telemetry/flow_cache.hpp"
#include "telemetry/packet_sampler.hpp"
#include "telemetry/ipfix_exporter.hpp"

#include <iostream>
#include <cassert>
#include <cstring>
#include <arpa/inet.h>

using namespace samurai;

void test_bfd_engine() {
  std::cout << "[TEST] Running BfdEngine verification..." << std::endl;

  l7_emu_native::l2l3::BfdSessionConfig cfg{};
  cfg.local_ip = "10.0.0.1";
  cfg.remote_ip = "10.0.0.2";
  cfg.local_mac = "00:11:22:33:44:55";
  cfg.remote_mac = "00:aa:bb:cc:dd:ee";
  cfg.desired_tx_interval_us = 10000;  // 10ms
  cfg.required_rx_interval_us = 10000; // 10ms
  cfg.detect_multiplier = 3;           // 30ms timeout
  cfg.local_disc = 0x11223344;

  l7_emu_native::l2l3::BfdEngine engine;
  engine.start_session(cfg);

  assert(engine.current_state() == l7_emu_native::l2l3::BfdState::Down);
  assert(!engine.is_up());
  assert(!engine.last_tx_packet().empty());

  // Verify generated BFD packet format
  l7_emu_native::l2l3::BfdControlHeader hdr{};
  uint32_t r_disc = 0;
  bool parsed = l7_emu_native::l2l3::BfdEngine::parse_bfd_control_packet(
      engine.last_tx_packet().data(), engine.last_tx_packet().size(), hdr, r_disc);
  assert(parsed);
  assert(r_disc == 0x11223344);

  // Simulate remote peer replying with Down -> Transition to Init
  auto remote_down_pkt = l7_emu_native::l2l3::BfdEngine::build_bfd_control_packet(
      cfg, l7_emu_native::l2l3::BfdState::Down, l7_emu_native::l2l3::BfdDiag::None,
      0x11223344, false, false);
  bool rx_ok = engine.process_rx_packet(remote_down_pkt.data(), remote_down_pkt.size(), 1000);
  assert(rx_ok);
  assert(engine.current_state() == l7_emu_native::l2l3::BfdState::Init);

  // Simulate remote peer transitioning to Up -> Transition to Up
  auto remote_up_pkt = l7_emu_native::l2l3::BfdEngine::build_bfd_control_packet(
      cfg, l7_emu_native::l2l3::BfdState::Up, l7_emu_native::l2l3::BfdDiag::None,
      0x11223344, false, false);
  rx_ok = engine.process_rx_packet(remote_up_pkt.data(), remote_up_pkt.size(), 2000);
  assert(rx_ok);
  assert(engine.current_state() == l7_emu_native::l2l3::BfdState::Up);
  assert(engine.is_up());
  assert(!engine.has_failed());

  // Simulate detection timeout (30ms = 30,000 us at 1GHz TSC)
  uint64_t tsc_hz = 1000000000ULL; // 1 GHz
  // Tick past 30ms without RX
  engine.step_timer(2000 + 35000000ULL, tsc_hz);
  assert(engine.current_state() == l7_emu_native::l2l3::BfdState::Down);
  assert(engine.has_failed()); // Failover triggered!

  std::cout << "  -> BfdEngine: SUCCESS" << std::endl;
}

void test_lockfree_cache() {
  std::cout << "[TEST] Running LockfreeL2L3Cache verification..." << std::endl;

  telecom::LockfreeArpTable arp_tbl;
  uint8_t mac_out[6] = {0};

  uint32_t ip1 = 0x0100000A; // 10.0.0.1
  assert(!arp_tbl.LookupMac(ip1, mac_out));

  uint8_t mac_in[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  arp_tbl.UpdateEntry(ip1, mac_in, 100, 12345);

  assert(arp_tbl.LookupMac(ip1, mac_out));
  assert(std::memcmp(mac_out, mac_in, 6) == 0);

  // Test invalidation
  arp_tbl.Invalidate(ip1);
  assert(!arp_tbl.LookupMac(ip1, mac_out));

  // IPv6 ND Table
  telecom::LockfreeNdTable nd_tbl;
  uint8_t ip6[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  assert(!nd_tbl.LookupMac(ip6, mac_out));

  nd_tbl.UpdateEntry(ip6, mac_in, 0, 12345);
  assert(nd_tbl.LookupMac(ip6, mac_out));
  assert(std::memcmp(mac_out, mac_in, 6) == 0);

  std::cout << "  -> LockfreeL2L3Cache: SUCCESS" << std::endl;
}

void test_flow_table_and_ipfix() {
  std::cout << "[TEST] Running FlowTableShard and IPFIX Exporter verification..." << std::endl;

  telemetry::FlowTableShard shard(1024);
  assert(shard.active_flow_count() == 0);

  telemetry::SamuraiFlowKey key{};
  key.src_ip = 0x0100000A;
  key.dst_ip = 0x0200000A;
  key.src_port = 50000;
  key.dst_port = 443;
  key.protocol = 6;
  key.vlan_id = 0;

  bool is_new = false;
  auto* rec = shard.LookupOrInsert(key, 1000, is_new);
  assert(rec != nullptr);
  assert(is_new);
  assert(shard.active_flow_count() == 1);

  // Lookup existing
  auto* rec2 = shard.LookupOrInsert(key, 1100, is_new);
  assert(rec2 == rec);
  assert(!is_new);

  // Update stats
  telemetry::FlowTableShard::UpdateStats(rec, 1400, 0x02 /* SYN */, 1100);
  assert(rec->packet_count == 1);
  assert(rec->byte_count == 1400);
  assert(rec->tcp_flags_or == 0x02);

  // Simulate timeout eviction
  std::vector<telemetry::SamuraiFlowRecord> evicted;
  size_t count = shard.EvictTimedOut(5000, 10000, 2000, evicted, 10);
  assert(count == 1);
  assert(evicted.size() == 1);
  assert(shard.active_flow_count() == 0);

  // Test IPFIX Exporter serialization
  telemetry::ExporterConfig exp_cfg{};
  exp_cfg.observation_domain_id = 42;
  exp_cfg.template_id = 256;
  exp_cfg.enable_netflow_v9 = false; // IPFIX

  telemetry::IpfixExporter exporter(exp_cfg);
  auto ipfix_pkt = exporter.BuildExportPacket(evicted.data(), evicted.size(), 1700000000, 50000, true);
  assert(!ipfix_pkt.empty());

  // Verify IPFIX header
  const auto* ipfix_hdr = reinterpret_cast<const telemetry::IpfixHeader*>(ipfix_pkt.data());
  assert(ntohs(ipfix_hdr->version) == 10);
  assert(ntohl(ipfix_hdr->observation_domain_id) == 42);

  // Test NetFlow v9 mode
  exp_cfg.enable_netflow_v9 = true;
  telemetry::IpfixExporter v9_exporter(exp_cfg);
  auto v9_pkt = v9_exporter.BuildExportPacket(evicted.data(), evicted.size(), 1700000000, 50000, true);
  assert(!v9_pkt.empty());
  const auto* v9_hdr = reinterpret_cast<const telemetry::NetFlowV9Header*>(v9_pkt.data());
  assert(ntohs(v9_hdr->version) == 9);

  std::cout << "  -> FlowTableShard & IpfixExporter: SUCCESS" << std::endl;
}

void test_fastpath_wiring() {
  std::cout << "[TEST] Running L2L3FastpathWiring verification..." << std::endl;

  telecom::L2L3FastpathWiring wiring;

  // Build raw ARP request
  auto arp_pkt = l7_emu_native::l2l3::ArpEngine::build_arp_request(
      "00:11:22:33:44:55", "192.168.1.100", "192.168.1.1");

  assert(telecom::L2L3FastpathWiring::IsControlFrame(arp_pkt.data(), arp_pkt.size()));
  assert(telecom::L2L3FastpathWiring::ClassifyFrame(arp_pkt.data(), arp_pkt.size()) == telecom::ControlFrameType::Arp);

  // Dispatch ARP packet
  bool dispatched = wiring.DispatchRxControlFrame(arp_pkt.data(), arp_pkt.size(), 1000);
  assert(dispatched);

  // Check lock-free ARP table was updated
  uint32_t sender_ip = 0;
  inet_pton(AF_INET, "192.168.1.100", &sender_ip);
  uint8_t mac_out[6] = {0};
  assert(wiring.ResolveIpv4Mac(sender_ip, mac_out));

  uint8_t expected_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
  assert(std::memcmp(mac_out, expected_mac, 6) == 0);

  std::cout << "  -> L2L3FastpathWiring: SUCCESS" << std::endl;
}

int main() {
  std::cout << "==========================================================" << std::endl;
  std::cout << "  Samurai Telecom & IPFIX/NetFlow Native Engine Test Suite" << std::endl;
  std::cout << "==========================================================" << std::endl;

  test_bfd_engine();
  test_lockfree_cache();
  test_flow_table_and_ipfix();
  test_fastpath_wiring();

  std::cout << "==========================================================" << std::endl;
  std::cout << "  ALL NATIVE TELECOM & TELEMETRY TESTS PASSED (100% OK)" << std::endl;
  std::cout << "==========================================================" << std::endl;
  return 0;
}
