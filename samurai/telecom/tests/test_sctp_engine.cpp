#include "samurai/telecom/protocols/stateful/sctp/sctp_engine.hpp"
#include "samurai/telecom/core/session_manager.hpp"
#include "samurai/telecom/core/hierarchical_timing_wheel.hpp"

#include <iostream>
#include <cassert>
#include <cstring>
#include <vector>
#include <arpa/inet.h>

using namespace samurai::telecom;
using namespace samurai::telecom::sctp;

void TestSctpHardwareCrc32c() {
    std::cout << "[TEST] 1. SCTP Castagnoli CRC32c (SSE4.2 Hardware Acceleration & RFC 3720 Vectors)..." << std::endl;

    // RFC 3720 Section B.4 test vectors:
    // 32 bytes of zeroes: 0x8a9136aa
    uint8_t zeroes[32] = {0};
    uint32_t crc_zeroes = SctpEngine::ComputeCrc32c(zeroes, sizeof(zeroes));
    assert(crc_zeroes == 0x8A9136AA);

    // 32 bytes of 0xFF: 0x62a8ab43
    uint8_t ones[32];
    std::memset(ones, 0xFF, sizeof(ones));
    uint32_t crc_ones = SctpEngine::ComputeCrc32c(ones, sizeof(ones));
    assert(crc_ones == 0x62A8AB43);

    // 32 bytes counting 0x00, 0x01, ..., 0x1F: 0x46dd794e
    uint8_t count_bytes[32];
    for (int i = 0; i < 32; ++i) count_bytes[i] = static_cast<uint8_t>(i);
    uint32_t crc_count = SctpEngine::ComputeCrc32c(count_bytes, sizeof(count_bytes));
    assert(crc_count == 0x46DD794E);

    std::cout << "  -> Hardware CRC32c RFC 3720 compliance verified: PASSED" << std::endl;
}

void TestSctpAssociationLifecycle() {
    std::cout << "[TEST] 2. SCTP 4-Way Handshake (INIT -> INIT-ACK -> COOKIE-ECHO -> COOKIE-ACK)..." << std::endl;

    SessionManager mgr(100);
    HierarchicalTimingWheel wheel(2400000000ULL);

    SctpEngine client_engine(mgr, &wheel);
    SctpEngine server_engine(mgr, &wheel);

    ProtocolConfig cfg{};
    cfg.retransmit_timeout_ms = 500;
    cfg.max_retries = 3;
    client_engine.Init(cfg);
    server_engine.Init(cfg);

    TelcoSessionContext* client_ctx = mgr.AcquireSession();
    assert(client_ctx != nullptr);

    SctpAssociationConfig assoc_cfg{};
    assoc_cfg.local_ip = 0x0A000001; // 10.0.0.1
    assoc_cfg.peer_ip = 0x0A000002;  // 10.0.0.2
    assoc_cfg.local_port = SCTP_PORT_NGAP;
    assoc_cfg.peer_port = SCTP_PORT_NGAP;
    assoc_cfg.my_vtag = 0x11223344;
    assoc_cfg.my_initial_tsn = 5000;

    // 1. Client sends INIT
    client_engine.StartAssociation(client_ctx, assoc_cfg);
    assert(client_engine.GetState(client_ctx) == SctpState::COOKIE_WAIT);
    const auto& init_pkt = client_engine.last_tx_packet();
    assert(!init_pkt.empty());

    // 2. Server processes INIT -> produces INIT_ACK
    bool ok = server_engine.ProcessRxFrame(init_pkt.data(), init_pkt.size(), 1000);
    assert(ok);
    const auto& init_ack_pkt = server_engine.last_tx_packet();
    assert(!init_ack_pkt.empty());

    // 3. Client processes INIT_ACK -> produces COOKIE_ECHO
    ok = client_engine.ProcessRxFrame(init_ack_pkt.data(), init_ack_pkt.size(), 1001);
    assert(ok);
    assert(client_engine.GetState(client_ctx) == SctpState::COOKIE_ECHOED);
    const auto& cookie_echo_pkt = client_engine.last_tx_packet();
    assert(!cookie_echo_pkt.empty());

    // 4. Server processes COOKIE_ECHO -> produces COOKIE_ACK
    ok = server_engine.ProcessRxFrame(cookie_echo_pkt.data(), cookie_echo_pkt.size(), 1002);
    assert(ok);
    const auto& cookie_ack_pkt = server_engine.last_tx_packet();
    assert(!cookie_ack_pkt.empty());

    // 5. Client processes COOKIE_ACK -> transitions to ESTABLISHED!
    ok = client_engine.ProcessRxFrame(cookie_ack_pkt.data(), cookie_ack_pkt.size(), 1003);
    assert(ok);
    assert(client_engine.GetState(client_ctx) == SctpState::ESTABLISHED);

    std::cout << "  -> 4-way association handshake to ESTABLISHED: PASSED" << std::endl;
}

void TestSctpHeartbeatAndKeepalive() {
    std::cout << "[TEST] 3. SCTP Path Management & Keepalive (HEARTBEAT / HEARTBEAT-ACK)..." << std::endl;

    SessionManager mgr(100);
    HierarchicalTimingWheel wheel(2400000000ULL);
    SctpEngine client_engine(mgr, &wheel);
    SctpEngine server_engine(mgr, &wheel);

    TelcoSessionContext* client_ctx = mgr.AcquireSession();
    assert(client_ctx != nullptr);
    client_engine.SetState(client_ctx, SctpState::ESTABLISHED);
    client_ctx->session_id = 0x11223344;
    client_ctx->ppp_magic_number = 0x55667788;
    client_ctx->client_ip = 0x0A000001;
    client_ctx->peer_ip = 0x0A000002;
    client_ctx->client_port = SCTP_PORT_S1AP;
    client_ctx->peer_port = SCTP_PORT_S1AP;
    mgr.Bind5Tuple(client_ctx, 0x0A000001, 0x0A000002, SCTP_PORT_S1AP, SCTP_PORT_S1AP, IP_PROTO_SCTP);

    TelcoSessionContext* server_ctx = mgr.AcquireSession();
    assert(server_ctx != nullptr);
    server_engine.SetState(server_ctx, SctpState::ESTABLISHED);
    server_ctx->session_id = 0x55667788;
    server_ctx->ppp_magic_number = 0x11223344;
    server_ctx->client_ip = 0x0A000002;
    server_ctx->peer_ip = 0x0A000001;
    server_ctx->client_port = SCTP_PORT_S1AP;
    server_ctx->peer_port = SCTP_PORT_S1AP;
    mgr.Bind5Tuple(server_ctx, 0x0A000002, 0x0A000001, SCTP_PORT_S1AP, SCTP_PORT_S1AP, IP_PROTO_SCTP);

    // 1. Client builds HEARTBEAT
    auto hb_pkt = client_engine.BuildHeartbeatPacket(client_ctx);
    assert(!hb_pkt.empty());

    // 2. Server receives HEARTBEAT -> produces HEARTBEAT_ACK
    bool ok = server_engine.ProcessRxFrame(hb_pkt.data(), hb_pkt.size(), 2000);
    assert(ok);
    const auto& hb_ack_pkt = server_engine.last_tx_packet();
    assert(!hb_ack_pkt.empty());

    // 3. Client receives HEARTBEAT_ACK -> keepalive verified
    ok = client_engine.ProcessRxFrame(hb_ack_pkt.data(), hb_ack_pkt.size(), 2001);
    assert(ok);
    assert(client_ctx->retry_count == 0);

    std::cout << "  -> SCTP Heartbeat keepalive roundtrip: PASSED" << std::endl;
}

void TestSctpDataChunking() {
    std::cout << "[TEST] 4. SCTP 5G NG-AP / 4G S1-AP DATA Chunking & Automatic SACK..." << std::endl;

    SessionManager mgr(100);
    HierarchicalTimingWheel wheel(2400000000ULL);
    SctpEngine client_engine(mgr, &wheel);
    SctpEngine server_engine(mgr, &wheel);

    TelcoSessionContext* client_ctx = mgr.AcquireSession();
    client_engine.SetState(client_ctx, SctpState::ESTABLISHED);
    client_ctx->session_id = 0x11223344;
    client_ctx->ppp_magic_number = 0x55667788;
    client_ctx->client_ip = 0x0A000001;
    client_ctx->peer_ip = 0x0A000002;
    client_ctx->client_port = SCTP_PORT_NGAP;
    client_ctx->peer_port = SCTP_PORT_NGAP;
    client_ctx->teid_uplink = 1000;
    mgr.Bind5Tuple(client_ctx, 0x0A000001, 0x0A000002, SCTP_PORT_NGAP, SCTP_PORT_NGAP, IP_PROTO_SCTP);

    TelcoSessionContext* server_ctx = mgr.AcquireSession();
    assert(server_ctx != nullptr);
    server_engine.SetState(server_ctx, SctpState::ESTABLISHED);
    server_ctx->session_id = 0x55667788;
    server_ctx->ppp_magic_number = 0x11223344;
    server_ctx->client_ip = 0x0A000002;
    server_ctx->peer_ip = 0x0A000001;
    server_ctx->client_port = SCTP_PORT_NGAP;
    server_ctx->peer_port = SCTP_PORT_NGAP;
    mgr.Bind5Tuple(server_ctx, 0x0A000002, 0x0A000001, SCTP_PORT_NGAP, SCTP_PORT_NGAP, IP_PROTO_SCTP);

    // NG-AP (PPID=60) PDU payload
    uint8_t ngap_pdu[] = {0x00, 0x0E, 0x00, 0x1B, 0x00, 0x00, 0x02, 0x00};
    auto data_pkt = client_engine.BuildDataPacket(client_ctx, SCTP_PPID_NGAP, ngap_pdu, sizeof(ngap_pdu));
    assert(!data_pkt.empty());

    // Server processes DATA chunk -> generates SACK
    bool ok = server_engine.ProcessRxFrame(data_pkt.data(), data_pkt.size(), 3000);
    assert(ok);
    const auto& sack_pkt = server_engine.last_tx_packet();
    assert(!sack_pkt.empty());

    // Client processes SACK
    ok = client_engine.ProcessRxFrame(sack_pkt.data(), sack_pkt.size(), 3001);
    assert(ok);

    std::cout << "  -> 5G NG-AP DATA transmission and SACK feedback: PASSED" << std::endl;
}

void TestSctpShutdownLifecycle() {
    std::cout << "[TEST] 5. SCTP Graceful Association Teardown (SHUTDOWN -> SHUTDOWN-ACK -> COMPLETE)..." << std::endl;

    SessionManager mgr(100);
    HierarchicalTimingWheel wheel(2400000000ULL);
    SctpEngine client_engine(mgr, &wheel);
    SctpEngine server_engine(mgr, &wheel);

    TelcoSessionContext* client_ctx = mgr.AcquireSession();
    client_engine.SetState(client_ctx, SctpState::ESTABLISHED);
    client_ctx->session_id = 0x11223344;
    client_ctx->ppp_magic_number = 0x55667788;
    client_ctx->client_ip = 0x0A000001;
    client_ctx->peer_ip = 0x0A000002;
    client_ctx->client_port = SCTP_PORT_NGAP;
    client_ctx->peer_port = SCTP_PORT_NGAP;
    mgr.Bind5Tuple(client_ctx, 0x0A000001, 0x0A000002, SCTP_PORT_NGAP, SCTP_PORT_NGAP, IP_PROTO_SCTP);

    TelcoSessionContext* server_ctx = mgr.AcquireSession();
    assert(server_ctx != nullptr);
    server_engine.SetState(server_ctx, SctpState::ESTABLISHED);
    server_ctx->session_id = 0x55667788;
    server_ctx->ppp_magic_number = 0x11223344;
    server_ctx->client_ip = 0x0A000002;
    server_ctx->peer_ip = 0x0A000001;
    server_ctx->client_port = SCTP_PORT_NGAP;
    server_ctx->peer_port = SCTP_PORT_NGAP;
    mgr.Bind5Tuple(server_ctx, 0x0A000002, 0x0A000001, SCTP_PORT_NGAP, SCTP_PORT_NGAP, IP_PROTO_SCTP);

    // 1. Client initiates shutdown
    client_engine.StopAssociation(client_ctx);
    assert(client_engine.GetState(client_ctx) == SctpState::SHUTDOWN_SENT);
    const auto& shutdown_pkt = client_engine.last_tx_packet();
    assert(!shutdown_pkt.empty());

    // 2. Server receives SHUTDOWN -> produces SHUTDOWN_ACK
    bool ok = server_engine.ProcessRxFrame(shutdown_pkt.data(), shutdown_pkt.size(), 4000);
    assert(ok);
    const auto& shutdown_ack_pkt = server_engine.last_tx_packet();
    assert(!shutdown_ack_pkt.empty());

    // 3. Client receives SHUTDOWN_ACK -> produces SHUTDOWN_COMPLETE and transitions to CLOSED
    ok = client_engine.ProcessRxFrame(shutdown_ack_pkt.data(), shutdown_ack_pkt.size(), 4001);
    assert(ok);
    assert(client_engine.GetState(client_ctx) == SctpState::CLOSED);
    const auto& complete_pkt = client_engine.last_tx_packet();
    assert(!complete_pkt.empty());

    std::cout << "  -> Graceful SHUTDOWN association teardown: PASSED" << std::endl;
}

void TestSctpCorruptedCrcRejection() {
    std::cout << "[TEST] 6. SCTP Corrupted CRC32c Packet Rejection..." << std::endl;

    SessionManager mgr(100);
    HierarchicalTimingWheel wheel(2400000000ULL);
    SctpEngine engine(mgr, &wheel);

    TelcoSessionContext* ctx = mgr.AcquireSession();
    ctx->client_ip = 0x0A000001;
    ctx->peer_ip = 0x0A000002;
    ctx->client_port = SCTP_PORT_NGAP;
    ctx->peer_port = SCTP_PORT_NGAP;

    auto valid_pkt = engine.BuildInitPacket(ctx);
    assert(!valid_pkt.empty());

    // Corrupt one byte of CRC
    auto corrupt_pkt = valid_pkt;
    size_t sctp_offset = 14 + 20; // Eth + IP
    corrupt_pkt[sctp_offset + 8] ^= 0xFF; // Invert first byte of CRC

    bool ok = engine.ProcessRxFrame(corrupt_pkt.data(), corrupt_pkt.size(), 5000);
    assert(!ok); // Must be strictly rejected

    std::cout << "  -> Corrupted CRC32c frame strictly rejected: PASSED" << std::endl;
}

void TestSctpMultihomingFailover() {
    std::cout << "[TEST] 7. SCTP Multihoming Multi-Path Probing & Automatic Failover (RFC 4960 §5.1.2 & §8)..." << std::endl;

    SessionManager mgr(100);
    HierarchicalTimingWheel wheel(2400000000ULL);
    SctpEngine client_engine(mgr, &wheel);
    SctpEngine server_engine(mgr, &wheel);

    ProtocolConfig cfg{};
    cfg.retransmit_timeout_ms = 500;
    cfg.max_retries = 3;
    client_engine.Init(cfg);
    server_engine.Init(cfg);

    TelcoSessionContext* client_ctx = mgr.AcquireSession();
    assert(client_ctx != nullptr);

    SctpAssociationConfig assoc_cfg{};
    assoc_cfg.local_ip = 0x0A000001; // 10.0.0.1
    assoc_cfg.peer_ip = 0x0A000002;  // 10.0.0.2 (Primary)
    assoc_cfg.local_port = SCTP_PORT_NGAP;
    assoc_cfg.peer_port = SCTP_PORT_NGAP;
    assoc_cfg.my_vtag = 0x11223344;
    assoc_cfg.peer_vtag = 0x55667788;
    assoc_cfg.my_initial_tsn = 5000;
    assoc_cfg.path_max_retrans = 3;
    assoc_cfg.peer_secondary_ips = {0x0A000003, 0x0A000004}; // Alternate paths

    client_engine.StartAssociation(client_ctx, assoc_cfg);
    assert(client_engine.GetPathCount(client_ctx) == 3);

    // Verify initial paths
    const auto* p0 = client_engine.GetPath(client_ctx, 0);
    const auto* p1 = client_engine.GetPath(client_ctx, 1);
    const auto* p2 = client_engine.GetPath(client_ctx, 2);
    assert(p0 != nullptr && p0->ip == 0x0A000002 && p0->is_primary && p0->status == SctpPathStatus::ACTIVE);
    assert(p1 != nullptr && p1->ip == 0x0A000003 && !p1->is_primary && p1->status == SctpPathStatus::UNCONFIRMED);
    assert(p2 != nullptr && p2->ip == 0x0A000004 && !p2->is_primary && p2->status == SctpPathStatus::UNCONFIRMED);

    // Setup Server session for testing
    TelcoSessionContext* server_ctx = mgr.AcquireSession();
    assert(server_ctx != nullptr);
    server_engine.SetState(server_ctx, SctpState::ESTABLISHED);
    server_ctx->session_id = 0x55667788;
    server_ctx->ppp_magic_number = 0x11223344;
    server_ctx->client_ip = 0x0A000002;
    server_ctx->peer_ip = 0x0A000001;
    server_ctx->client_port = SCTP_PORT_NGAP;
    server_ctx->peer_port = SCTP_PORT_NGAP;
    mgr.Bind5Tuple(server_ctx, 0x0A000002, 0x0A000001, SCTP_PORT_NGAP, SCTP_PORT_NGAP, IP_PROTO_SCTP);

    // 1. Probe Path 1 (10.0.0.3)
    bool ok = client_engine.ProbePathHeartbeat(client_ctx, 1, 1000);
    assert(ok);
    const auto& hb_pkt = client_engine.last_tx_packet();
    assert(!hb_pkt.empty());

    // Server receives HEARTBEAT and responds with HEARTBEAT_ACK
    ok = server_engine.ProcessRxFrame(hb_pkt.data(), hb_pkt.size(), 1001);
    assert(ok);
    const auto& hb_ack = server_engine.last_tx_packet();
    assert(!hb_ack.empty());

    // Client processes HEARTBEAT_ACK -> Path 1 status transitions to ACTIVE
    ok = client_engine.ProcessRxFrame(hb_ack.data(), hb_ack.size(), 1002);
    assert(ok);
    assert(client_engine.GetPath(client_ctx, 1)->status == SctpPathStatus::ACTIVE);

    // 2. Primary Path failure (error counter reaches threshold 3)
    assert(client_engine.GetActivePathIndex(client_ctx) == 0);
    client_engine.HandlePathError(client_ctx, 0);
    assert(client_engine.GetPath(client_ctx, 0)->error_counter == 1);
    client_engine.HandlePathError(client_ctx, 0);
    assert(client_engine.GetPath(client_ctx, 0)->error_counter == 2);
    client_engine.HandlePathError(client_ctx, 0);

    // Path 0 is now INACTIVE and automatic failover occurred to Path 1!
    assert(client_engine.GetPath(client_ctx, 0)->status == SctpPathStatus::INACTIVE);
    assert(client_engine.GetActivePathIndex(client_ctx) == 1);
    assert(client_ctx->peer_ip == 0x0A000003);
    assert(client_engine.GetActivePath(client_ctx)->ip == 0x0A000003);

    // 3. Verify DATA packets are routed to the failover path 10.0.0.3
    uint8_t ngap_payload[] = {0x00, 0x0E, 0x00, 0x1B, 0x00, 0x00, 0x02, 0x00};
    auto data_pkt = client_engine.BuildDataPacket(client_ctx, SCTP_PPID_NGAP, ngap_payload, sizeof(ngap_payload));
    assert(!data_pkt.empty());

    uint32_t dst_ip_net = 0;
    std::memcpy(&dst_ip_net, data_pkt.data() + 14 + 16, 4); // IPv4 Dst IP offset
    assert(ntohl(dst_ip_net) == 0x0A000003);

    std::cout << "  -> Multihoming Path Probing and Automatic Failover: PASSED" << std::endl;
}

void TestSctpPrSctpForwardTsn() {
    std::cout << "[TEST] 8. PR-SCTP Partial Reliability (RFC 3758 Timed Abandonment & FORWARD-TSN)..." << std::endl;

    SessionManager mgr(100);
    HierarchicalTimingWheel wheel(2400000000ULL);
    SctpEngine client_engine(mgr, &wheel);
    SctpEngine server_engine(mgr, &wheel);

    TelcoSessionContext* client_ctx = mgr.AcquireSession();
    client_engine.SetState(client_ctx, SctpState::ESTABLISHED);
    client_ctx->session_id = 0x11223344;
    client_ctx->ppp_magic_number = 0x55667788;
    client_ctx->client_ip = 0x0A000001;
    client_ctx->peer_ip = 0x0A000002;
    client_ctx->client_port = SCTP_PORT_NGAP;
    client_ctx->peer_port = SCTP_PORT_NGAP;
    client_ctx->teid_uplink = 1000;
    mgr.Bind5Tuple(client_ctx, 0x0A000001, 0x0A000002, SCTP_PORT_NGAP, SCTP_PORT_NGAP, IP_PROTO_SCTP);

    TelcoSessionContext* server_ctx = mgr.AcquireSession();
    server_engine.SetState(server_ctx, SctpState::ESTABLISHED);
    server_ctx->session_id = 0x55667788;
    server_ctx->ppp_magic_number = 0x11223344;
    server_ctx->client_ip = 0x0A000002;
    server_ctx->peer_ip = 0x0A000001;
    server_ctx->client_port = SCTP_PORT_NGAP;
    server_ctx->peer_port = SCTP_PORT_NGAP;
    server_ctx->teid_downlink = 999;
    mgr.Bind5Tuple(server_ctx, 0x0A000002, 0x0A000001, SCTP_PORT_NGAP, SCTP_PORT_NGAP, IP_PROTO_SCTP);

    // 1. Client sends timed DATA with 10ms lifetime
    uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF};
    uint64_t now_tsc = 100000ULL;
    auto data_pkt = client_engine.BuildTimedDataPacket(client_ctx, 1, SCTP_PPID_NGAP, payload, sizeof(payload), 10, now_tsc);
    assert(!data_pkt.empty());
    assert(client_ctx->teid_uplink == 1001);

    // Simulate drop: server never receives data_pkt!
    // Check before expiry does nothing
    auto early_check = client_engine.CheckTimedReliability(client_ctx, now_tsc + 1000);
    assert(early_check.empty());

    // Advance time beyond 10ms expiry
    uint64_t expired_tsc = now_tsc + 30000000ULL;
    auto fwd_tsn_pkt = client_engine.CheckTimedReliability(client_ctx, expired_tsc);
    assert(!fwd_tsn_pkt.empty());

    // Verify chunk type is FORWARD_TSN (0xC0)
    size_t sctp_offset = 14 + 20;
    uint8_t chunk_type = fwd_tsn_pkt[sctp_offset + 12];
    assert(chunk_type == static_cast<uint8_t>(SctpChunkType::FORWARD_TSN));

    // 2. Server receives FORWARD_TSN chunk
    bool ok = server_engine.ProcessRxFrame(fwd_tsn_pkt.data(), fwd_tsn_pkt.size(), expired_tsc);
    assert(ok);

    // Server cumulative TSN advanced from 999 to 1000
    assert(server_ctx->teid_downlink == 1000);

    // Server automatically generated SACK
    const auto& sack_pkt = server_engine.last_tx_packet();
    assert(!sack_pkt.empty());
    uint8_t sack_chunk_type = sack_pkt[sctp_offset + 12];
    assert(sack_chunk_type == static_cast<uint8_t>(SctpChunkType::SACK));

    // Client processes SACK
    ok = client_engine.ProcessRxFrame(sack_pkt.data(), sack_pkt.size(), expired_tsc + 1000);
    assert(ok);

    std::cout << "  -> PR-SCTP Timed Reliability and FORWARD-TSN cumulative advance: PASSED" << std::endl;
}

void TestSctpAsconfDynamicReconfiguration() {
    std::cout << "[TEST] 9. ASCONF Dynamic Address Reconfiguration (RFC 5061 Add/Set-Primary/Delete IP)..." << std::endl;

    SessionManager mgr(100);
    HierarchicalTimingWheel wheel(2400000000ULL);
    SctpEngine client_engine(mgr, &wheel);
    SctpEngine server_engine(mgr, &wheel);

    TelcoSessionContext* client_ctx = mgr.AcquireSession();
    client_engine.SetState(client_ctx, SctpState::ESTABLISHED);
    client_ctx->session_id = 0x11223344;
    client_ctx->ppp_magic_number = 0x55667788;
    client_ctx->client_ip = 0x0A000001;
    client_ctx->peer_ip = 0x0A000002;
    client_ctx->client_port = SCTP_PORT_NGAP;
    client_ctx->peer_port = SCTP_PORT_NGAP;
    mgr.Bind5Tuple(client_ctx, 0x0A000001, 0x0A000002, SCTP_PORT_NGAP, SCTP_PORT_NGAP, IP_PROTO_SCTP);

    TelcoSessionContext* server_ctx = mgr.AcquireSession();
    server_engine.SetState(server_ctx, SctpState::ESTABLISHED);
    server_ctx->session_id = 0x55667788;
    server_ctx->ppp_magic_number = 0x11223344;
    server_ctx->client_ip = 0x0A000002;
    server_ctx->peer_ip = 0x0A000001;
    server_ctx->client_port = SCTP_PORT_NGAP;
    server_ctx->peer_port = SCTP_PORT_NGAP;
    mgr.Bind5Tuple(server_ctx, 0x0A000002, 0x0A000001, SCTP_PORT_NGAP, SCTP_PORT_NGAP, IP_PROTO_SCTP);

    server_engine.AddPath(server_ctx, 0x0A000001, true);
    assert(server_engine.GetPathCount(server_ctx) == 1);

    // 1. Client sends ASCONF Add IP (10.0.0.5)
    uint32_t new_ip = 0x0A000005;
    auto add_ip_pkt = client_engine.BuildAsconfAddIpPacket(client_ctx, new_ip, 101);
    assert(!add_ip_pkt.empty());

    // Verify chunk type is ASCONF (0xC1)
    size_t sctp_offset = 14 + 20;
    assert(add_ip_pkt[sctp_offset + 12] == static_cast<uint8_t>(SctpChunkType::ASCONF));

    // Server processes ASCONF Add IP
    bool ok = server_engine.ProcessRxFrame(add_ip_pkt.data(), add_ip_pkt.size(), 5000);
    assert(ok);
    assert(server_engine.GetPathCount(server_ctx) == 2);
    assert(server_engine.GetPath(server_ctx, 1)->ip == new_ip);

    // Server generates ASCONF_ACK (0x80)
    const auto& ack_pkt = server_engine.last_tx_packet();
    assert(!ack_pkt.empty());
    assert(ack_pkt[sctp_offset + 12] == static_cast<uint8_t>(SctpChunkType::ASCONF_ACK));

    // Client processes ASCONF_ACK
    ok = client_engine.ProcessRxFrame(ack_pkt.data(), ack_pkt.size(), 5001);
    assert(ok);
    assert(client_engine.GetAsconfAckSerial(client_ctx) > 0);

    // 2. Client sends ASCONF Set Primary IP (10.0.0.5)
    auto set_primary_pkt = client_engine.BuildAsconfSetPrimaryIpPacket(client_ctx, new_ip, 102);
    assert(!set_primary_pkt.empty());

    ok = server_engine.ProcessRxFrame(set_primary_pkt.data(), set_primary_pkt.size(), 5002);
    assert(ok);
    assert(server_engine.GetPrimaryPath(server_ctx)->ip == new_ip);
    assert(server_engine.GetActivePath(server_ctx)->ip == new_ip);

    // 3. Client sends ASCONF Delete IP (10.0.0.1)
    auto del_ip_pkt = client_engine.BuildAsconfDeleteIpPacket(client_ctx, 0x0A000001, 103);
    assert(!del_ip_pkt.empty());

    ok = server_engine.ProcessRxFrame(del_ip_pkt.data(), del_ip_pkt.size(), 5003);
    assert(ok);
    assert(server_engine.GetPathCount(server_ctx) == 1);
    assert(server_engine.GetPath(server_ctx, 0)->ip == new_ip);

    std::cout << "  -> ASCONF Dynamic Address Reconfiguration (Add/Set-Primary/Delete IP): PASSED" << std::endl;
}

int main() {
    std::cout << "=================================================================" << std::endl;
    std::cout << "        SAMURAI SCTP (IP PROTO 132) VERIFICATION SUITE           " << std::endl;
    std::cout << "=================================================================" << std::endl;

    TestSctpHardwareCrc32c();
    TestSctpAssociationLifecycle();
    TestSctpHeartbeatAndKeepalive();
    TestSctpDataChunking();
    TestSctpShutdownLifecycle();
    TestSctpCorruptedCrcRejection();
    TestSctpMultihomingFailover();
    TestSctpPrSctpForwardTsn();
    TestSctpAsconfDynamicReconfiguration();

    std::cout << "=================================================================" << std::endl;
    std::cout << "  ALL SCTP ENGINE TESTS PASSED SUCCESSFULLY! (100% VERIFIED)     " << std::endl;
    std::cout << "=================================================================" << std::endl;
    return 0;
}
