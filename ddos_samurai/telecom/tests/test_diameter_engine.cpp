#include "ddos_samurai/telecom/protocols/stateful/diameter/diameter_engine.hpp"
#include "ddos_samurai/telecom/core/session_manager.hpp"
#include "ddos_samurai/telecom/core/hierarchical_timing_wheel.hpp"

#include <iostream>
#include <cassert>
#include <cstring>
#include <vector>

using namespace ddos_samurai::telecom;
using namespace ddos_samurai::telecom::diameter;

void TestDiameterAvpCodec() {
    std::cout << "[TEST] 1. Diameter AVP Encoding & 4-Byte Boundary Alignment..." << std::endl;

    std::vector<uint8_t> buf;

    // 1. String AVP (e.g. Origin-Host: 14 chars -> 8 header + 14 = 22 -> padded to 24)
    DiameterEngine::AppendAvpString(buf, AVP_ORIGIN_HOST, 0x40, "samurai.client");
    assert(buf.size() == 24);
    assert(buf.size() % 4 == 0);

    // 2. U32 AVP (8 header + 4 = 12 bytes)
    size_t prev_size = buf.size();
    DiameterEngine::AppendAvpU32(buf, AVP_AUTH_APPLICATION_ID, 0x40, APP_DIAMETER_CREDIT_CONTROL);
    assert(buf.size() - prev_size == 12);
    assert(buf.size() % 4 == 0);

    // 3. Vendor-Specific AVP (12 header + 4 data = 16 bytes)
    prev_size = buf.size();
    DiameterEngine::AppendAvpU32(buf, 1001, 0x80, 42, VENDOR_ID_3GPP);
    assert(buf.size() - prev_size == 16);
    assert(buf.size() % 4 == 0);

    std::cout << "  -> AVP serialization and 4-byte padding: PASSED" << std::endl;
}

void TestDiameterCapabilitiesExchange() {
    std::cout << "[TEST] 2. Diameter Peer Handshake (CER -> CEA -> OPEN)..." << std::endl;

    SessionManager mgr(100);
    HierarchicalTimingWheel wheel(2400000000ULL);
    DiameterEngine client_engine(mgr, &wheel);
    DiameterEngine server_engine(mgr, &wheel);

    ProtocolConfig cfg{};
    client_engine.Init(cfg);
    server_engine.Init(cfg);

    TelcoSessionContext* client_ctx = mgr.AcquireSession();
    assert(client_ctx != nullptr);

    DiameterPeerConfig peer_cfg{};
    peer_cfg.local_ip = 0x0A000001;
    peer_cfg.peer_ip = 0x0A000002;
    peer_cfg.origin_host = "client.samurai.epc";
    peer_cfg.origin_realm = "epc.mnc001.mcc001.3gppnetwork.org";

    // 1. Client starts session -> produces CER
    client_engine.StartPeerSession(client_ctx, peer_cfg);
    assert(client_engine.GetState(client_ctx) == DiameterPeerState::WAIT_I_CEA);
    const auto& cer_pkt = client_engine.last_tx_packet();
    assert(!cer_pkt.empty());

    // 2. Server receives CER -> produces CEA with DIAMETER_SUCCESS (2001)
    bool ok = server_engine.ProcessRxFrame(cer_pkt.data(), cer_pkt.size(), 1000);
    assert(ok);
    const auto& cea_pkt = server_engine.last_tx_packet();
    assert(!cea_pkt.empty());

    // 3. Client receives CEA -> transitions to OPEN
    ok = client_engine.ProcessRxFrame(cea_pkt.data(), cea_pkt.size(), 1001);
    assert(ok);
    assert(client_engine.GetState(client_ctx) == DiameterPeerState::OPEN);

    std::cout << "  -> Capabilities Exchange (CER/CEA) to OPEN: PASSED" << std::endl;
}

void TestDiameterDeviceWatchdog() {
    std::cout << "[TEST] 3. Diameter Device Watchdog Keepalive (DWR -> DWA)..." << std::endl;

    SessionManager mgr(100);
    HierarchicalTimingWheel wheel(2400000000ULL);
    DiameterEngine client_engine(mgr, &wheel);
    DiameterEngine server_engine(mgr, &wheel);

    TelcoSessionContext* client_ctx = mgr.AcquireSession();
    client_engine.SetState(client_ctx, DiameterPeerState::OPEN);
    client_ctx->client_ip = 0x0A000001;
    client_ctx->peer_ip = 0x0A000002;
    client_ctx->client_port = 13868;
    client_ctx->peer_port = DIAMETER_STANDARD_PORT;
    mgr.Bind5Tuple(client_ctx, 0x0A000001, 0x0A000002, 13868, DIAMETER_STANDARD_PORT, 6);

    TelcoSessionContext* server_ctx = mgr.AcquireSession();
    server_engine.SetState(server_ctx, DiameterPeerState::OPEN);
    server_ctx->client_ip = 0x0A000002;
    server_ctx->peer_ip = 0x0A000001;
    server_ctx->client_port = DIAMETER_STANDARD_PORT;
    server_ctx->peer_port = 13868;
    mgr.Bind5Tuple(server_ctx, 0x0A000002, 0x0A000001, DIAMETER_STANDARD_PORT, 13868, 6);

    // 1. Client builds DWR
    auto dwr_pkt = client_engine.BuildDwrPacket(client_ctx);
    assert(!dwr_pkt.empty());

    // 2. Server processes DWR -> produces DWA
    bool ok = server_engine.ProcessRxFrame(dwr_pkt.data(), dwr_pkt.size(), 2000);
    assert(ok);
    const auto& dwa_pkt = server_engine.last_tx_packet();
    assert(!dwa_pkt.empty());

    // 3. Client processes DWA -> watchdog reset
    ok = client_engine.ProcessRxFrame(dwa_pkt.data(), dwa_pkt.size(), 2001);
    assert(ok);
    assert(client_ctx->retry_count == 0);

    std::cout << "  -> Watchdog (DWR/DWA) keepalive: PASSED" << std::endl;
}

void TestDiameterCreditControlBilling() {
    std::cout << "[TEST] 4. Diameter 3GPP Ro / Gx Credit-Control (CCR -> CCA)..." << std::endl;

    SessionManager mgr(100);
    HierarchicalTimingWheel wheel(2400000000ULL);
    DiameterEngine client_engine(mgr, &wheel);
    DiameterEngine server_engine(mgr, &wheel);

    TelcoSessionContext* client_ctx = mgr.AcquireSession();
    client_engine.SetState(client_ctx, DiameterPeerState::OPEN);
    client_ctx->client_ip = 0x0A000001;
    client_ctx->peer_ip = 0x0A000002;
    client_ctx->client_port = 13868;
    client_ctx->peer_port = DIAMETER_STANDARD_PORT;
    mgr.Bind5Tuple(client_ctx, 0x0A000001, 0x0A000002, 13868, DIAMETER_STANDARD_PORT, 6);

    TelcoSessionContext* server_ctx = mgr.AcquireSession();
    server_engine.SetState(server_ctx, DiameterPeerState::OPEN);
    server_ctx->client_ip = 0x0A000002;
    server_ctx->peer_ip = 0x0A000001;
    server_ctx->client_port = DIAMETER_STANDARD_PORT;
    server_ctx->peer_port = 13868;
    mgr.Bind5Tuple(server_ctx, 0x0A000002, 0x0A000001, DIAMETER_STANDARD_PORT, 13868, 6);

    // 1. Client builds CCR INITIAL_REQUEST (Request Number: 0)
    auto ccr_pkt = client_engine.BuildCcrPacket(client_ctx, "sub-session-001", CcRequestType::INITIAL_REQUEST, 0);
    assert(!ccr_pkt.empty());

    // 2. Server processes CCR -> produces CCA (SUCCESS 2001)
    bool ok = server_engine.ProcessRxFrame(ccr_pkt.data(), ccr_pkt.size(), 3000);
    assert(ok);
    const auto& cca_pkt = server_engine.last_tx_packet();
    assert(!cca_pkt.empty());

    // 3. Client processes CCA
    ok = client_engine.ProcessRxFrame(cca_pkt.data(), cca_pkt.size(), 3001);
    assert(ok);

    std::cout << "  -> 3GPP Ro / Gx CCR/CCA credit control exchange: PASSED" << std::endl;
}

void TestDiameterDisconnectPeer() {
    std::cout << "[TEST] 5. Diameter Graceful Peer Disconnect (DPR -> DPA -> CLOSED)..." << std::endl;

    SessionManager mgr(100);
    HierarchicalTimingWheel wheel(2400000000ULL);
    DiameterEngine client_engine(mgr, &wheel);
    DiameterEngine server_engine(mgr, &wheel);

    TelcoSessionContext* client_ctx = mgr.AcquireSession();
    client_engine.SetState(client_ctx, DiameterPeerState::OPEN);
    client_ctx->client_ip = 0x0A000001;
    client_ctx->peer_ip = 0x0A000002;
    client_ctx->client_port = 13868;
    client_ctx->peer_port = DIAMETER_STANDARD_PORT;
    mgr.Bind5Tuple(client_ctx, 0x0A000001, 0x0A000002, 13868, DIAMETER_STANDARD_PORT, 6);

    TelcoSessionContext* server_ctx = mgr.AcquireSession();
    server_engine.SetState(server_ctx, DiameterPeerState::OPEN);
    server_ctx->client_ip = 0x0A000002;
    server_ctx->peer_ip = 0x0A000001;
    server_ctx->client_port = DIAMETER_STANDARD_PORT;
    server_ctx->peer_port = 13868;
    mgr.Bind5Tuple(server_ctx, 0x0A000002, 0x0A000001, DIAMETER_STANDARD_PORT, 13868, 6);

    // 1. Client initiates stop -> produces DPR
    client_engine.StopPeerSession(client_ctx);
    assert(client_engine.GetState(client_ctx) == DiameterPeerState::CLOSING);
    const auto& dpr_pkt = client_engine.last_tx_packet();
    assert(!dpr_pkt.empty());

    // 2. Server processes DPR -> produces DPA and transitions to CLOSED
    bool ok = server_engine.ProcessRxFrame(dpr_pkt.data(), dpr_pkt.size(), 4000);
    assert(ok);
    const auto& dpa_pkt = server_engine.last_tx_packet();
    assert(!dpa_pkt.empty());

    // 3. Client processes DPA -> transitions to CLOSED
    ok = client_engine.ProcessRxFrame(dpa_pkt.data(), dpa_pkt.size(), 4001);
    assert(ok);
    assert(client_engine.GetState(client_ctx) == DiameterPeerState::CLOSED);

    std::cout << "  -> Graceful Disconnect-Peer (DPR/DPA) to CLOSED: PASSED" << std::endl;
}

int main() {
    std::cout << "=================================================================" << std::endl;
    std::cout << "       SAMURAI DIAMETER (RFC 6733 / 3GPP) VERIFICATION SUITE     " << std::endl;
    std::cout << "=================================================================" << std::endl;

    TestDiameterAvpCodec();
    TestDiameterCapabilitiesExchange();
    TestDiameterDeviceWatchdog();
    TestDiameterCreditControlBilling();
    TestDiameterDisconnectPeer();

    std::cout << "=================================================================" << std::endl;
    std::cout << "  ALL DIAMETER ENGINE TESTS PASSED SUCCESSFULLY! (100% VERIFIED) " << std::endl;
    std::cout << "=================================================================" << std::endl;
    return 0;
}
