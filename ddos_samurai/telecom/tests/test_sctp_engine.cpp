#include "ddos_samurai/telecom/protocols/stateful/sctp/sctp_engine.hpp"
#include "ddos_samurai/telecom/core/session_manager.hpp"
#include "ddos_samurai/telecom/core/hierarchical_timing_wheel.hpp"

#include <iostream>
#include <cassert>
#include <cstring>
#include <vector>

using namespace ddos_samurai::telecom;
using namespace ddos_samurai::telecom::sctp;

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

    std::cout << "=================================================================" << std::endl;
    std::cout << "  ALL SCTP ENGINE TESTS PASSED SUCCESSFULLY! (100% VERIFIED)     " << std::endl;
    std::cout << "=================================================================" << std::endl;
    return 0;
}
