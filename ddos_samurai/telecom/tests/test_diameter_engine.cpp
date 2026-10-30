#include "ddos_samurai/telecom/protocols/stateful/diameter/diameter_engine.hpp"
#include "ddos_samurai/telecom/protocols/stateful/diameter/diameter_dictionary.hpp"
#include "ddos_samurai/telecom/core/session_manager.hpp"
#include "ddos_samurai/telecom/core/hierarchical_timing_wheel.hpp"

#include <iostream>
#include <cassert>
#include <cstring>
#include <vector>
#include <arpa/inet.h>

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

void TestDiameterDictionaryBuiltinSchema() {
    std::cout << "[TEST] 6. Diameter Carrier Built-in Schema Definitions..." << std::endl;

    DiameterDictionary dict;

    // Check RFC 6733 Base AVPs
    const auto* session_id = dict.FindAvp(263);
    assert(session_id != nullptr);
    assert(session_id->name == "Session-Id");
    assert(session_id->type == AvpDataType::UTF8_STRING);
    assert(session_id->flags & AVP_FLAG_MANDATORY);
    assert(session_id->vendor_id == 0);

    const auto* origin_host = dict.FindAvp(264);
    assert(origin_host != nullptr && origin_host->name == "Origin-Host");

    const auto* origin_realm = dict.FindAvp(296);
    assert(origin_realm != nullptr && origin_realm->name == "Origin-Realm");

    const auto* dest_realm = dict.FindAvp(283);
    assert(dest_realm != nullptr && dest_realm->name == "Destination-Realm");

    const auto* dest_host = dict.FindAvp(293);
    assert(dest_host != nullptr && dest_host->name == "Destination-Host");

    const auto* res_code = dict.FindAvp(268);
    assert(res_code != nullptr && res_code->type == AvpDataType::UNSIGNED32);

    const auto* auth_app = dict.FindAvp(258);
    assert(auth_app != nullptr && auth_app->type == AvpDataType::UNSIGNED32);

    const auto* term_cause = dict.FindAvp(295);
    assert(term_cause != nullptr && term_cause->type == AvpDataType::UNSIGNED32);

    // Check 3GPP Ro / Gx / Gy AVPs
    const auto* cc_type = dict.FindAvp(416);
    assert(cc_type != nullptr && cc_type->name == "CC-Request-Type");

    const auto* cc_num = dict.FindAvp(415);
    assert(cc_num != nullptr && cc_num->name == "CC-Request-Number");

    const auto* srv_ctx = dict.FindAvp(461);
    assert(srv_ctx != nullptr && srv_ctx->name == "Service-Context-Id");

    const auto* sub_id = dict.FindAvp(443);
    assert(sub_id != nullptr && sub_id->type == AvpDataType::GROUPED);
    assert(sub_id->children.size() == 2);
    assert(sub_id->children[0].code == 450); // Subscription-Id-Type
    assert(sub_id->children[1].code == 444); // Subscription-Id-Data

    const auto* mscc = dict.FindAvp(456);
    assert(mscc != nullptr && mscc->type == AvpDataType::GROUPED);
    assert(mscc->children.size() == 2);
    assert(mscc->children[0].code == 432); // Rating-Group
    assert(mscc->children[0].vendor_id == 10415);
    assert(mscc->children[1].code == 446); // Used-Service-Unit
    assert(mscc->children[1].type == AvpDataType::GROUPED);
    assert(mscc->children[1].children.size() == 1);
    assert(mscc->children[1].children[0].code == 421); // CC-Total-Octets

    const auto* rating_group = dict.FindAvp(432, 10415);
    assert(rating_group != nullptr);
    assert(rating_group->vendor_id == 10415);
    assert(rating_group->flags & AVP_FLAG_VENDOR);
    assert(rating_group->flags & AVP_FLAG_MANDATORY);

    const auto* rat_type = dict.FindAvp(1032, 10415);
    assert(rat_type != nullptr);
    assert(rat_type->vendor_id == 10415);
    assert(rat_type->flags & AVP_FLAG_VENDOR);

    // Check Lookups by name
    const auto* by_name_sub = dict.FindAvpByName("Subscription-Id");
    assert(by_name_sub != nullptr && by_name_sub->code == 443);

    const auto* by_name_rg = dict.FindAvpByName("Rating-Group");
    assert(by_name_rg != nullptr && by_name_rg->code == 432 && by_name_rg->vendor_id == 10415);

    // Check Commands
    const auto* ccr_ro = dict.FindCommand(272, 4, true);
    assert(ccr_ro != nullptr && ccr_ro->name == "Credit-Control-Request");
    assert(!ccr_ro->required_avps.empty());

    const auto* cca_ro = dict.FindCommand(272, 4, false);
    assert(cca_ro != nullptr && cca_ro->name == "Credit-Control-Answer");

    const auto* cer = dict.FindCommand(257, 0, true);
    assert(cer != nullptr && cer->name == "Capabilities-Exchange-Request");

    std::cout << "  -> Carrier built-in schema and 3GPP hierarchy: PASSED" << std::endl;
}

void TestDiameterDictionaryJsonLoader() {
    std::cout << "[TEST] 7. Diameter Dynamic Dictionary JSON Loader..." << std::endl;

    DiameterDictionary dict;
    size_t initial_avp_count = dict.AvpCount();
    size_t initial_cmd_count = dict.CommandCount();

    std::string json_schema = R"({
        "avps": [
            {
                "code": 9991,
                "vendor_id": 10415,
                "name": "Custom-Carrier-Token",
                "type": "UTF8_STRING",
                "flags": "MV"
            },
            {
                "code": 9992,
                "vendor_id": 0,
                "name": "Custom-Telemetry-Group",
                "type": "GROUPED",
                "flags": "M",
                "children": [
                    {
                        "code": 9993,
                        "vendor_id": 0,
                        "name": "Custom-Probe-ID",
                        "type": "UNSIGNED32",
                        "flags": "M"
                    }
                ]
            }
        ],
        "commands": [
            {
                "code": 888,
                "app_id": 16777216,
                "name": "Custom-Policy-Request",
                "is_request": true,
                "required_avps": [263, 9991],
                "optional_avps": [9992]
            },
            {
                "code": 888,
                "app_id": 16777216,
                "name": "Custom-Policy-Answer",
                "is_request": false,
                "required_avps": [263, 268],
                "optional_avps": []
            }
        ]
    })";

    std::string err;
    bool ok = dict.LoadFromJson(json_schema, &err);
    assert(ok);
    assert(err.empty());
    assert(dict.AvpCount() > initial_avp_count);
    assert(dict.CommandCount() > initial_cmd_count);

    // Verify parsed AVP
    const auto* token_avp = dict.FindAvp(9991, 10415);
    assert(token_avp != nullptr);
    assert(token_avp->name == "Custom-Carrier-Token");
    assert(token_avp->vendor_id == 10415);
    assert(token_avp->type == AvpDataType::UTF8_STRING);
    assert(token_avp->flags & AVP_FLAG_MANDATORY);
    assert(token_avp->flags & AVP_FLAG_VENDOR);

    // Lookup by name
    const auto* token_by_name = dict.FindAvpByName("Custom-Carrier-Token");
    assert(token_by_name != nullptr && token_by_name->code == 9991);

    // Verify Grouped AVP & child
    const auto* group_avp = dict.FindAvp(9992, 0);
    assert(group_avp != nullptr);
    assert(group_avp->type == AvpDataType::GROUPED);
    assert(group_avp->children.size() == 1);
    assert(group_avp->children[0].code == 9993);
    assert(group_avp->children[0].type == AvpDataType::UNSIGNED32);

    // Verify Commands
    const auto* cmd_req = dict.FindCommand(888, 16777216, true);
    assert(cmd_req != nullptr);
    assert(cmd_req->name == "Custom-Policy-Request");
    assert(cmd_req->required_avps.size() == 2);
    assert(cmd_req->required_avps[0] == 263);
    assert(cmd_req->required_avps[1] == 9991);
    assert(cmd_req->optional_avps.size() == 1);
    assert(cmd_req->optional_avps[0] == 9992);

    const auto* cmd_ans = dict.FindCommand(888, 16777216, false);
    assert(cmd_ans != nullptr);
    assert(cmd_ans->name == "Custom-Policy-Answer");

    // Invalid JSON error reporting
    std::string invalid_err;
    bool bad_ok = dict.LoadFromJson("{ malformed json }", &invalid_err);
    assert(!bad_ok);
    assert(!invalid_err.empty());

    std::cout << "  -> JSON schema loader for custom AVPs & Commands: PASSED" << std::endl;
}

void TestDiameterDynamicGroupedAvpCodec() {
    std::cout << "[TEST] 8. Diameter Dynamic Grouped & Primitive AVP Codec..." << std::endl;

    DiameterDictionary dict;

    // 1. Primitive Roundtrip: UTF8_STRING with padding
    {
        auto avp_str = DecodedAvp::CreateString(264, "diameter.ims.mnc001.mcc001.3gppnetwork.org");
        std::vector<uint8_t> buf;
        bool ok = dict.EncodeAvp(avp_str, buf);
        assert(ok);
        assert(buf.size() % 4 == 0);

        DecodedAvp decoded;
        size_t consumed = 0;
        ok = dict.DecodeAvp(buf.data(), buf.size(), decoded, consumed);
        assert(ok);
        assert(consumed == buf.size());
        assert(decoded.code == 264);
        assert(decoded.str_val == "diameter.ims.mnc001.mcc001.3gppnetwork.org");
    }

    // 2. Primitive Roundtrip: UNSIGNED64, INTEGER64, FLOAT32, FLOAT64, TIME, ADDRESS
    {
        std::vector<uint8_t> buf;

        // U64
        auto avp_u64 = DecodedAvp::CreateU64(421, 9876543210123456ULL);
        assert(dict.EncodeAvp(avp_u64, buf));

        // Address (IPv4: 192.168.10.55 = 0xC0A80A37)
        auto avp_ip = DecodedAvp::CreateAddressIpv4(8, 0xC0A80A37);
        assert(dict.EncodeAvp(avp_ip, buf));

        // Decode multi-AVP sequence
        std::vector<DecodedAvp> decoded_list;
        assert(dict.DecodeAvps(buf.data(), buf.size(), decoded_list));
        assert(decoded_list.size() == 2);
        assert(decoded_list[0].code == 421 && decoded_list[0].u64_val == 9876543210123456ULL);
        assert(decoded_list[1].code == 8 && decoded_list[1].ipv4_val == 0xC0A80A37);
    }

    // 3. Recursive Grouped AVP: MSCC -> Rating-Group + (Used-Service-Unit -> CC-Total-Octets)
    {
        auto rating_group = DecodedAvp::CreateU32(432, 500, AVP_FLAG_MANDATORY | AVP_FLAG_VENDOR, 10415);
        auto cc_total_octets = DecodedAvp::CreateU64(421, 52428800ULL);

        std::vector<DecodedAvp> usu_children;
        usu_children.push_back(cc_total_octets);
        auto usu = DecodedAvp::CreateGrouped(446, usu_children);

        std::vector<DecodedAvp> mscc_children;
        mscc_children.push_back(rating_group);
        mscc_children.push_back(usu);
        auto mscc = DecodedAvp::CreateGrouped(456, mscc_children);

        std::vector<uint8_t> mscc_buf;
        bool ok = dict.EncodeAvp(mscc, mscc_buf);
        assert(ok);
        assert(mscc_buf.size() % 4 == 0);

        DecodedAvp mscc_decoded;
        size_t consumed = 0;
        ok = dict.DecodeAvp(mscc_buf.data(), mscc_buf.size(), mscc_decoded, consumed);
        assert(ok);
        assert(consumed == mscc_buf.size());
        assert(mscc_decoded.code == 456);
        assert(mscc_decoded.type == AvpDataType::GROUPED);
        assert(mscc_decoded.grouped_val.size() == 2);

        // Child 1: Rating-Group
        const auto& c1 = mscc_decoded.grouped_val[0];
        assert(c1.code == 432);
        assert(c1.vendor_id == 10415);
        assert(c1.flags & AVP_FLAG_VENDOR);
        assert(c1.u32_val == 500);

        // Child 2: Used-Service-Unit
        const auto& c2 = mscc_decoded.grouped_val[1];
        assert(c2.code == 446);
        assert(c2.type == AvpDataType::GROUPED);
        assert(c2.grouped_val.size() == 1);

        // Grandchild: CC-Total-Octets
        const auto& gc = c2.grouped_val[0];
        assert(gc.code == 421);
        assert(gc.u64_val == 52428800ULL);
    }

    std::cout << "  -> Recursive Grouped and Primitive AVP Codec with RFC 6733 padding: PASSED" << std::endl;
}

void TestDiameterDictionaryValidation() {
    std::cout << "[TEST] 9. Diameter Schema Validation & Mandatory AVP Enforcement..." << std::endl;

    DiameterDictionary dict;

    // Build valid CCR list of AVPs
    std::vector<DecodedAvp> valid_ccr_avps;
    valid_ccr_avps.push_back(DecodedAvp::CreateString(263, "sess-1001@epc.mnc001.org"));
    valid_ccr_avps.push_back(DecodedAvp::CreateString(264, "pcrf.carrier.net"));
    valid_ccr_avps.push_back(DecodedAvp::CreateString(296, "carrier.net"));
    valid_ccr_avps.push_back(DecodedAvp::CreateString(283, "epc.mnc001.org"));
    valid_ccr_avps.push_back(DecodedAvp::CreateU32(258, 4)); // Auth-Application-Id
    valid_ccr_avps.push_back(DecodedAvp::CreateString(461, "32251@3gpp.org")); // Service-Context-Id
    valid_ccr_avps.push_back(DecodedAvp::CreateU32(416, 1)); // CC-Request-Type: INITIAL
    valid_ccr_avps.push_back(DecodedAvp::CreateU32(415, 0)); // CC-Request-Number

    // Valid Grouped AVP
    std::vector<DecodedAvp> sub_children;
    sub_children.push_back(DecodedAvp::CreateU32(450, 0)); // END_USER_E164
    sub_children.push_back(DecodedAvp::CreateString(444, "905321234567"));
    valid_ccr_avps.push_back(DecodedAvp::CreateGrouped(443, sub_children));

    std::string err;
    bool ok = dict.ValidateMessage(272, 4, true, valid_ccr_avps, err);
    assert(ok);
    assert(err.empty());

    // 1. Missing mandatory AVP (remove Auth-Application-Id)
    auto missing_avps = valid_ccr_avps;
    missing_avps.erase(missing_avps.begin() + 4); // Remove Auth-App-Id
    ok = dict.ValidateMessage(272, 4, true, missing_avps, err);
    assert(!ok);
    assert(err.find("Auth-Application-Id") != std::string::npos);

    // 2. Type mismatch (CC-Request-Number as string)
    auto bad_type_avps = valid_ccr_avps;
    bad_type_avps[7] = DecodedAvp::CreateString(415, "invalid-type-number");
    ok = dict.ValidateMessage(272, 4, true, bad_type_avps, err);
    assert(!ok);
    assert(err.find("mismatch") != std::string::npos);

    // 3. Missing mandatory child inside Grouped AVP
    std::vector<DecodedAvp> incomplete_sub;
    incomplete_sub.push_back(DecodedAvp::CreateU32(450, 0)); // Only type, missing data!
    auto incomplete_grouped = DecodedAvp::CreateGrouped(443, incomplete_sub);
    err.clear();
    ok = dict.ValidateAvp(incomplete_grouped, err);
    assert(!ok);
    assert(err.find("Subscription-Id-Data") != std::string::npos);

    // 4. Missing vendor flag on vendor-specific AVP
    auto bad_vendor_avp = DecodedAvp::CreateU32(432, 100, AVP_FLAG_MANDATORY, 10415); // Missing AVP_FLAG_VENDOR bit in flags!
    err.clear();
    ok = dict.ValidateAvp(bad_vendor_avp, err);
    assert(!ok);
    assert(err.find("Vendor flag missing") != std::string::npos);

    std::cout << "  -> Schema validation and mandatory AVP checking: PASSED" << std::endl;
}

void TestDiameterDictionaryDrivenCcrCca() {
    std::cout << "[TEST] 10. Diameter Dictionary-Driven CCR / CCA Synthesis & Verification..." << std::endl;

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

    // 1. Build complex 3GPP Ro / Gx CCR with nested Subscription-Id & MSCC
    std::vector<DecodedAvp> extra_ccr_avps;

    // Subscription-Id Grouped
    std::vector<DecodedAvp> sub_children;
    sub_children.push_back(DecodedAvp::CreateU32(450, 0)); // Subscription-Id-Type: END_USER_E164
    sub_children.push_back(DecodedAvp::CreateString(444, "441234567890")); // Subscription-Id-Data
    extra_ccr_avps.push_back(DecodedAvp::CreateGrouped(443, sub_children));

    // MSCC Grouped
    auto rating_group = DecodedAvp::CreateU32(432, 100, AVP_FLAG_MANDATORY | AVP_FLAG_VENDOR, 10415);
    auto usu_octets = DecodedAvp::CreateU64(421, 104857600ULL);
    std::vector<DecodedAvp> usu_children{usu_octets};
    auto usu = DecodedAvp::CreateGrouped(446, usu_children);
    std::vector<DecodedAvp> mscc_children{rating_group, usu};
    extra_ccr_avps.push_back(DecodedAvp::CreateGrouped(456, mscc_children));

    // Framed-IP-Address
    extra_ccr_avps.push_back(DecodedAvp::CreateAddressIpv4(8, 0x0A2D0016)); // 10.45.0.22

    // Synthesize CCR packet via DiameterEngine
    auto ccr_packet = client_engine.BuildDictionaryDrivenCcr(
        client_ctx, "session-ro-carrier-998877", CcRequestType::INITIAL_REQUEST, 0, extra_ccr_avps);
    assert(!ccr_packet.empty());
    assert(ccr_packet.size() > 54 + 20); // Eth + IP + TCP + DiameterHeader + AVPs

    // 2. Validate synthesized CCR packet wire layout
    size_t tcp_payload_offset = 14 + 20 + 20; // 54
    const auto* diam_hdr = reinterpret_cast<const DiameterHeader*>(ccr_packet.data() + tcp_payload_offset);
    assert(diam_hdr->version == 1);
    assert(diam_hdr->command_flags == 0x80); // R=1
    assert(ntohl(diam_hdr->application_id) == APP_DIAMETER_CREDIT_CONTROL);

    // Extract AVPs and validate against Ro schema
    const uint8_t* avp_bytes = ccr_packet.data() + tcp_payload_offset + sizeof(DiameterHeader);
    size_t avp_bytes_len = ccr_packet.size() - tcp_payload_offset - sizeof(DiameterHeader);

    std::vector<DecodedAvp> rx_ccr_avps;
    std::string rx_err;
    bool valid = server_engine.ValidateIncomingAvps(
        CMD_CREDIT_CONTROL, APP_DIAMETER_CREDIT_CONTROL, true,
        avp_bytes, avp_bytes_len, rx_ccr_avps, rx_err);
    assert(valid);
    assert(rx_err.empty());
    assert(rx_ccr_avps.size() >= 8); // At least required AVPs + extras

    // Verify parsed Subscription-Id in rx_ccr_avps
    bool found_sub = false;
    for (const auto& a : rx_ccr_avps) {
        if (a.code == 443 && a.type == AvpDataType::GROUPED) {
            found_sub = true;
            assert(a.grouped_val.size() == 2);
            assert(a.grouped_val[0].code == 450 && a.grouped_val[0].u32_val == 0);
            assert(a.grouped_val[1].code == 444 && a.grouped_val[1].str_val == "441234567890");
        }
    }
    assert(found_sub);

    // 3. Server builds CCA response
    uint32_t hop_id = ntohl(diam_hdr->hop_by_hop_id);
    uint32_t end_id = ntohl(diam_hdr->end_to_end_id);
    auto cca_packet = server_engine.BuildDictionaryDrivenCca(
        server_ctx, "session-ro-carrier-998877", RESULT_DIAMETER_SUCCESS,
        CcRequestType::INITIAL_REQUEST, 0, hop_id, end_id);
    assert(!cca_packet.empty());

    // 4. Client receives and validates CCA
    const auto* cca_diam_hdr = reinterpret_cast<const DiameterHeader*>(cca_packet.data() + tcp_payload_offset);
    assert(cca_diam_hdr->command_flags == 0x00); // R=0 (Answer)
    assert(ntohl(cca_diam_hdr->hop_by_hop_id) == hop_id);
    assert(ntohl(cca_diam_hdr->end_to_end_id) == end_id);

    const uint8_t* cca_avp_bytes = cca_packet.data() + tcp_payload_offset + sizeof(DiameterHeader);
    size_t cca_avp_bytes_len = cca_packet.size() - tcp_payload_offset - sizeof(DiameterHeader);

    std::vector<DecodedAvp> rx_cca_avps;
    std::string cca_err;
    bool cca_valid = client_engine.ValidateIncomingAvps(
        CMD_CREDIT_CONTROL, APP_DIAMETER_CREDIT_CONTROL, false,
        cca_avp_bytes, cca_avp_bytes_len, rx_cca_avps, cca_err);
    assert(cca_valid);
    assert(cca_err.empty());

    std::cout << "  -> Dictionary-driven CCR/CCA dynamic packet synthesis: PASSED" << std::endl;
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
    TestDiameterDictionaryBuiltinSchema();
    TestDiameterDictionaryJsonLoader();
    TestDiameterDynamicGroupedAvpCodec();
    TestDiameterDictionaryValidation();
    TestDiameterDictionaryDrivenCcrCca();

    std::cout << "=================================================================" << std::endl;
    std::cout << "  ALL DIAMETER ENGINE TESTS PASSED SUCCESSFULLY! (100% VERIFIED) " << std::endl;
    std::cout << "=================================================================" << std::endl;
    return 0;
}
