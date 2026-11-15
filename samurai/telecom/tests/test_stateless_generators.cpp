#include "samurai/telecom/protocols/stateless/gtpu_gen/stateless_gtpu_generator.hpp"
#include "samurai/telecom/protocols/stateless/qinq_sweep/qinq_generator.hpp"
#include "samurai/telecom/protocols/stateless/arp_gen/stateless_arp_generator.hpp"

#include "samurai/telecom/core/fastpath_classifier.hpp"
#include "samurai/telecom/protocols/stateful/mobile/gtpu_engine.hpp"

#include <iostream>
#include <cassert>
#include <vector>
#include <cstring>
#include <chrono>
#include <atomic>
#include <arpa/inet.h>

using namespace samurai::telecom;
using namespace samurai::telecom::stateless;

// =========================================================================
// Zero-Heap Allocation Tracker
// =========================================================================
static std::atomic<uint64_t> g_heap_allocations{0};
static thread_local bool g_track_allocations = false;

void* operator new(size_t size) {
    if (g_track_allocations) {
        g_heap_allocations.fetch_add(1, std::memory_order_relaxed);
    }
    void* ptr = std::malloc(size);
    if (!ptr) throw std::bad_alloc();
    return ptr;
}

void operator delete(void* ptr) noexcept {
    std::free(ptr);
}

void operator delete(void* ptr, size_t) noexcept {
    std::free(ptr);
}

// =========================================================================
// Test 1: Zero Dynamic Allocation on Packet Generation Loop
// =========================================================================
void TestZeroDynamicAllocation() {
    std::cout << "[TEST] 1. Zero Dynamic Allocation on Packet Generation Loops (100k Iterations)..." << std::endl;

    StatelessGtpuGenerator gtpu_gen;
    QinQGenerator qinq_gen;
    StatelessArpGenerator arp_gen;

    alignas(64) uint8_t pkt_buf[1536];

    // Ensure generators are warm
    gtpu_gen.GeneratePacket(pkt_buf, sizeof(pkt_buf));
    qinq_gen.GeneratePacket(pkt_buf, sizeof(pkt_buf));
    arp_gen.GeneratePacket(pkt_buf, sizeof(pkt_buf));

    // Start strict allocation tracking
    g_heap_allocations.store(0);
    g_track_allocations = true;

    // 1. GTP-U Packet Loop
    for (int i = 0; i < 100000; ++i) {
        uint32_t len = gtpu_gen.GeneratePacket(pkt_buf, sizeof(pkt_buf));
        assert(len > 0);
    }
    assert(g_heap_allocations.load() == 0 && "GTP-U packet generation triggered dynamic heap allocation!");

    // 2. QinQ Frame Loop
    for (int i = 0; i < 100000; ++i) {
        uint32_t len = qinq_gen.GeneratePacket(pkt_buf, sizeof(pkt_buf));
        assert(len > 0);
    }
    assert(g_heap_allocations.load() == 0 && "QinQ frame generation triggered dynamic heap allocation!");

    // 3. ARP Frame Loop
    for (int i = 0; i < 100000; ++i) {
        uint32_t len = arp_gen.GeneratePacket(pkt_buf, sizeof(pkt_buf));
        assert(len > 0);
    }
    assert(g_heap_allocations.load() == 0 && "ARP frame generation triggered dynamic heap allocation!");

    // 4. Toplu (Batch) üretim zero-heap testi
    uint8_t batch_store[64][256];
    uint8_t* out_ptrs[64];
    uint32_t out_lens[64];
    for (int i = 0; i < 64; ++i) {
        out_ptrs[i] = batch_store[i];
    }

    for (int b = 0; b < 1000; ++b) {
        uint32_t c1 = gtpu_gen.GenerateBatch(out_ptrs, out_lens, 64, 256);
        assert(c1 == 64);
        uint32_t c2 = qinq_gen.GenerateBatch(out_ptrs, out_lens, 64, 256);
        assert(c2 == 64);
        uint32_t c3 = arp_gen.GenerateBatch(out_ptrs, out_lens, 64, 256);
        assert(c3 == 64);
    }

    g_track_allocations = false;
    assert(g_heap_allocations.load() == 0 && "Batch generation triggered dynamic heap allocation!");
    std::cout << "  -> Zero heap allocation in hot-paths (300k single + 192k batch packets): PASSED" << std::endl;
}

// =========================================================================
// Test 2: Stateless GTP-U Wire-Format & TEID Cycling Verification
// =========================================================================
void TestStatelessGtpuWireFormatAndCycling() {
    std::cout << "[TEST] 2. Stateless GTP-U Wire-Format & TEID Cycling Verification..." << std::endl;

    GtpuGenConfig cfg;
    cfg.outer_src_ip = 0x0A000001; // 10.0.0.1
    cfg.outer_dst_ip = 0x0A000002; // 10.0.0.2
    cfg.outer_src_port = 2152;
    cfg.outer_dst_port = 2152;
    cfg.inner_src_ip = 0x0A2D0002; // 10.45.0.2
    cfg.inner_dst_ip = 0x08080808; // 8.8.8.8
    cfg.inner_proto = InnerProtocol::ICMP_ECHO;
    cfg.inner_payload_size = 16;
    cfg.teid_mode = TeidCycleMode::SEQUENTIAL;
    cfg.teid_start = 100;
    cfg.teid_end = 104;
    cfg.teid_step = 1;
    cfg.with_seq_num = false;

    StatelessGtpuGenerator gen(cfg);
    alignas(64) uint8_t pkt[512];

    // 1. Wire-Format Verification
    uint32_t len = gen.GeneratePacket(pkt, sizeof(pkt));
    assert(len > 0);

    GtpuGenVerification verif;
    bool ok = StatelessGtpuGenerator::VerifyFrame(pkt, len, verif);
    assert(ok);
    assert(verif.is_valid);
    assert(verif.outer_src_ip == 0x0A000001);
    assert(verif.outer_dst_ip == 0x0A000002);
    assert(verif.outer_src_port == 2152);
    assert(verif.outer_dst_port == 2152);
    assert(verif.gtpu_flags == 0x30);
    assert(verif.gtpu_msg_type == 255);
    assert(verif.teid == 100);
    assert(!verif.has_seq);
    assert(verif.inner_src_ip == 0x0A2D0002);
    assert(verif.inner_dst_ip == 0x08080808);
    assert(verif.inner_proto == 1); // ICMP

    // Verify FastpathClassifier correctly classifies the generated packet
    PacketMetadata meta{};
    TelcoFrameType frame_type = TelcoFrameType::Unknown;
    bool class_ok = FastpathClassifier::Classify(pkt, len, meta, frame_type);
    assert(class_ok);
    assert(frame_type == TelcoFrameType::Gtpu);
    assert(meta.dst_port == 2152);
    assert(meta.src_ip == 0x0A000001);
    assert(meta.dst_ip == 0x0A000002);

    // Verify stateful mobile core Decapsulate accepts and decapsulates the packet
    mobile::GtpuDecapInfo decap_info{};
    bool decap_ok = mobile::GtpuEngine::Decapsulate(pkt, len, decap_info);
    assert(decap_ok);
    assert(decap_info.teid == 100);
    assert(decap_info.msg_type == static_cast<uint8_t>(mobile::GtpuMessageType::GPdu));
    assert(decap_info.payload != nullptr);
    assert(decap_info.payload_len == 20 + 8 + 16); // 20B IPv4 + 8B ICMP + 16B dummy

    // 2. Sequential TEID Cycling & Wraparound
    // We already generated TEID 100.
    // Next should be 101, 102, 103, 104, then wrap around to 100!
    uint32_t expected_teids[] = {101, 102, 103, 104, 100, 101};
    for (uint32_t exp : expected_teids) {
        len = gen.GeneratePacket(pkt, sizeof(pkt));
        assert(len > 0);
        StatelessGtpuGenerator::VerifyFrame(pkt, len, verif);
        assert(verif.teid == exp);
    }
    assert(gen.GetStats().teid_wraparounds >= 1);

    // 3. Optional Sequence Number Verification
    cfg.with_seq_num = true;
    cfg.teid_start = 5000;
    cfg.teid_end = 6000;
    gen.Init(cfg);

    len = gen.GeneratePacket(pkt, sizeof(pkt));
    assert(len > 0);
    StatelessGtpuGenerator::VerifyFrame(pkt, len, verif);
    assert(verif.has_seq);
    assert(verif.seq_num == 1);
    assert(verif.gtpu_flags == 0x32); // Base flags (0x30) | S_FLAG (0x02)

    len = gen.GeneratePacket(pkt, sizeof(pkt));
    StatelessGtpuGenerator::VerifyFrame(pkt, len, verif);
    assert(verif.seq_num == 2);

    // 4. Pseudo-random TEID mode
    cfg.teid_mode = TeidCycleMode::PSEUDO_RANDOM;
    cfg.teid_start = 10000;
    cfg.teid_end = 10050;
    gen.Init(cfg);
    for (int i = 0; i < 50; ++i) {
        gen.GeneratePacket(pkt, sizeof(pkt));
        StatelessGtpuGenerator::VerifyFrame(pkt, len, verif);
        assert(verif.teid >= 10000 && verif.teid <= 10050);
    }

    // 5. Inner IP cycling
    cfg.cycle_inner_ip = true;
    cfg.inner_ip_start = 0x0A2D0001;
    cfg.inner_ip_end = 0x0A2D0004;
    cfg.inner_ip_step = 1;
    gen.Init(cfg);

    uint32_t expected_inner_ips[] = {0x0A2D0001, 0x0A2D0002, 0x0A2D0003, 0x0A2D0004, 0x0A2D0001};
    for (uint32_t exp_ip : expected_inner_ips) {
        gen.GeneratePacket(pkt, sizeof(pkt));
        StatelessGtpuGenerator::VerifyFrame(pkt, len, verif);
        assert(verif.inner_src_ip == exp_ip);
    }

    std::cout << "  -> GTP-U wire format, sequence numbers, TEID & inner IP cycling: PASSED" << std::endl;
}

// =========================================================================
// Test 3: Carrier Ethernet QinQ & VLAN Sweep Verification
// =========================================================================
void TestQinQSweepWireFormatAndVlanRanges() {
    std::cout << "[TEST] 3. Carrier Ethernet QinQ & VLAN Sweep Verification..." << std::endl;

    QinQGeneratorConfig cfg;
    cfg.s_tpid = ETHERTYPE_8021AD; // 0x88A8
    cfg.s_vlan_min = 10;
    cfg.s_vlan_max = 12;
    cfg.s_vlan_step = 1;
    cfg.s_pcp = 5; // Priority 5
    cfg.s_dei = true; // Drop eligible

    cfg.c_tpid = ETHERTYPE_8021Q; // 0x8100
    cfg.c_vlan_min = 100;
    cfg.c_vlan_max = 102;
    cfg.c_vlan_step = 1;
    cfg.c_pcp = 2; // Priority 2
    cfg.c_dei = false;

    cfg.sweep_mode = QinQSweepMode::S_THEN_C;
    cfg.cycle_src_mac = true;

    QinQGenerator gen(cfg);
    alignas(64) uint8_t frame[512];

    // S_THEN_C should step C-VLAN through 100..102 for each S-VLAN in 10..12:
    // (10, 100), (10, 101), (10, 102),
    // (11, 100), (11, 101), (11, 102),
    // (12, 100), (12, 101), (12, 102),
    // then wrap to (10, 100)
    struct ExpectedPair { uint16_t s; uint16_t c; };
    ExpectedPair expected_pairs[] = {
        {10, 100}, {10, 101}, {10, 102},
        {11, 100}, {11, 101}, {11, 102},
        {12, 100}, {12, 101}, {12, 102},
        {10, 100}
    };

    for (const auto& pair : expected_pairs) {
        uint32_t len = gen.GeneratePacket(frame, sizeof(frame));
        assert(len >= 64);

        QinQVerificationInfo verif;
        bool ok = QinQGenerator::VerifyFrame(frame, len, verif);
        assert(ok);
        assert(verif.is_valid);
        assert(verif.s_tpid == 0x88A8);
        assert(verif.s_vlan == pair.s);
        assert(verif.s_pcp == 5);
        assert(verif.s_dei == true);

        assert(verif.c_tpid == 0x8100);
        assert(verif.c_vlan == pair.c);
        assert(verif.c_pcp == 2);
        assert(verif.c_dei == false);

        assert(verif.inner_ethertype == 0x0800);

        // Verify MAC cycling
        assert(frame[10] == static_cast<uint8_t>((pair.s >> 8) & 0x0F));
        assert(frame[11] == static_cast<uint8_t>(pair.s & 0xFF));

        // Verify FastpathClassifier parses both outer and inner VLANs
        PacketMetadata meta{};
        TelcoFrameType ftype = TelcoFrameType::Unknown;
        bool c_ok = FastpathClassifier::Classify(frame, len, meta, ftype);
        assert(c_ok);
        assert(meta.outer_vlan == pair.s);
        assert(meta.inner_vlan == pair.c);
        assert(ftype == TelcoFrameType::Ipv4Data);
    }
    assert(gen.GetStats().sweep_cycles >= 1);

    // 2. C_THEN_S Sweep Mode
    cfg.sweep_mode = QinQSweepMode::C_THEN_S;
    gen.Init(cfg);
    ExpectedPair c_then_s_pairs[] = {
        {10, 100}, {11, 100}, {12, 100},
        {10, 101}, {11, 101}, {12, 101},
        {10, 102}, {11, 102}, {12, 102},
        {10, 100}
    };
    for (const auto& pair : c_then_s_pairs) {
        uint32_t len = gen.GeneratePacket(frame, sizeof(frame));
        QinQVerificationInfo verif;
        QinQGenerator::VerifyFrame(frame, len, verif);
        assert(verif.s_vlan == pair.s);
        assert(verif.c_vlan == pair.c);
    }

    // 3. Alternate legacy TPID (0x9100)
    cfg.s_tpid = ETHERTYPE_9100;
    gen.Init(cfg);
    uint32_t len = gen.GeneratePacket(frame, sizeof(frame));
    QinQVerificationInfo verif;
    QinQGenerator::VerifyFrame(frame, len, verif);
    assert(verif.s_tpid == 0x9100);

    // 4. Boundary values (VID 1 and 4094)
    cfg.s_vlan_min = 1;
    cfg.s_vlan_max = 4094;
    cfg.c_vlan_min = 1;
    cfg.c_vlan_max = 4094;
    cfg.sweep_mode = QinQSweepMode::FLAT_FIXED;
    gen.Init(cfg);
    len = gen.GeneratePacket(frame, sizeof(frame));
    QinQGenerator::VerifyFrame(frame, len, verif);
    assert(verif.s_vlan == 1);
    assert(verif.c_vlan == 1);

    std::cout << "  -> QinQ dual VLAN sweep, PCP/DEI bit encoding & classification: PASSED" << std::endl;
}

// =========================================================================
// Test 4: High-Frequency ARP Probe & Cache Scale Verification
// =========================================================================
void TestStatelessArpWireFormatAndModes() {
    std::cout << "[TEST] 4. High-Frequency ARP Probe & Cache Scale Verification..." << std::endl;

    // 1. Standard ARP Request Subnet Sweep
    ArpGeneratorConfig cfg;
    cfg.probe_mode = ArpProbeMode::ARP_REQUEST;
    cfg.sender_ip = 0x0A0000FE; // 10.0.0.254
    cfg.target_ip_start = 0x0A000001; // 10.0.0.1
    cfg.target_ip_end = 0x0A000005;   // 10.0.0.5
    cfg.target_ip_step = 1;
    cfg.ip_cycle_mode = ArpIpCycleMode::SEQUENTIAL;
    cfg.pad_to_min_frame = true;
    cfg.min_frame_size = 60;

    StatelessArpGenerator gen(cfg);
    alignas(64) uint8_t frame[256];

    uint32_t expected_target_ips[] = {0x0A000001, 0x0A000002, 0x0A000003, 0x0A000004, 0x0A000005, 0x0A000001};
    for (uint32_t exp_ip : expected_target_ips) {
        uint32_t len = gen.GeneratePacket(frame, sizeof(frame));
        assert(len == 60); // Padded to Ethernet minimum frame

        ArpVerificationInfo verif;
        bool ok = StatelessArpGenerator::VerifyFrame(frame, len, verif);
        assert(ok);
        assert(verif.is_valid);
        assert(!verif.has_vlan);
        assert(verif.opcode == 1); // Request
        assert(verif.sender_ip == 0x0A0000FE);
        assert(verif.target_ip == exp_ip);

        // Ethernet Dst must be broadcast FF:FF:FF:FF:FF:FF
        for (int i = 0; i < 6; ++i) {
            assert(verif.eth_dst_mac[i] == 0xFF);
            assert(verif.target_mac[i] == 0x00);
        }

        // Verify FastpathClassifier recognises it as ARP
        PacketMetadata meta{};
        TelcoFrameType ftype = TelcoFrameType::Unknown;
        bool c_ok = FastpathClassifier::Classify(frame, len, meta, ftype);
        assert(c_ok);
        assert(ftype == TelcoFrameType::Arp);
    }
    assert(gen.GetStats().ip_sweep_cycles >= 1);

    // 2. Gratuitous ARP Request (RFC 5227 / RFC 826)
    cfg.probe_mode = ArpProbeMode::GARP_REQUEST;
    cfg.target_ip_start = 0xC0A8000A; // 192.168.0.10
    cfg.target_ip_end = 0xC0A8000C;   // 192.168.0.12
    gen.Init(cfg);

    for (uint32_t exp_ip = 0xC0A8000A; exp_ip <= 0xC0A8000C; ++exp_ip) {
        uint32_t len = gen.GeneratePacket(frame, sizeof(frame));
        ArpVerificationInfo verif;
        StatelessArpGenerator::VerifyFrame(frame, len, verif);
        assert(verif.opcode == 1); // Request
        assert(verif.sender_ip == exp_ip);
        assert(verif.target_ip == exp_ip); // GARP: sender == target IP
        for (int i = 0; i < 6; ++i) {
            assert(verif.target_mac[i] == 0x00);
        }
    }

    // 3. Gratuitous ARP Reply / Announcement
    cfg.probe_mode = ArpProbeMode::GARP_REPLY;
    gen.Init(cfg);
    uint32_t len = gen.GeneratePacket(frame, sizeof(frame));
    ArpVerificationInfo verif;
    StatelessArpGenerator::VerifyFrame(frame, len, verif);
    assert(verif.opcode == 2); // Reply
    assert(verif.sender_ip == 0xC0A8000A);
    assert(verif.target_ip == 0xC0A8000A);
    assert(std::memcmp(verif.sender_mac, verif.target_mac, 6) == 0);

    // 4. ARP Reply Flood (Direct cache injection)
    cfg.probe_mode = ArpProbeMode::ARP_REPLY_FLOOD;
    uint8_t dut_mac[6] = {0x00, 0x1B, 0x21, 0x99, 0x88, 0x77};
    std::memcpy(cfg.target_mac, dut_mac, 6);
    std::memcpy(cfg.eth_dst_mac, dut_mac, 6);
    cfg.sender_ip = 0x0A000001; // Gateway IP
    cfg.target_ip_start = 0x0A000100;
    cfg.target_ip_end = 0x0A0001FF;
    cfg.mac_cycle_mode = ArpMacCycleMode::DERIVED_FROM_IP;
    gen.Init(cfg);

    len = gen.GeneratePacket(frame, sizeof(frame));
    StatelessArpGenerator::VerifyFrame(frame, len, verif);
    assert(verif.opcode == 2); // Reply
    assert(std::memcmp(verif.eth_dst_mac, dut_mac, 6) == 0);
    assert(std::memcmp(verif.target_mac, dut_mac, 6) == 0);
    assert(verif.target_ip == 0x0A000001);
    assert(verif.sender_ip == 0x0A000100);
    // Derived MAC: 00:50:56 + lower 3 bytes of 0x0A000100 (0x00, 0x01, 0x00)
    assert(verif.sender_mac[3] == 0x00);
    assert(verif.sender_mac[4] == 0x01);
    assert(verif.sender_mac[5] == 0x00);

    // 5. CIDR Subnet Helper
    gen.SetSubnetCidr(0xC0A80100, 24); // 192.168.1.0/24
    assert(gen.GetConfig().target_ip_start == 0xC0A80101);
    assert(gen.GetConfig().target_ip_end == 0xC0A801FE);

    // 6. Optional 802.1Q VLAN Tagged ARP
    cfg.enable_vlan = true;
    cfg.vlan_id = 300;
    cfg.vlan_pcp = 6;
    cfg.probe_mode = ArpProbeMode::ARP_REQUEST;
    gen.Init(cfg);

    len = gen.GeneratePacket(frame, sizeof(frame));
    StatelessArpGenerator::VerifyFrame(frame, len, verif);
    assert(verif.has_vlan);
    assert(verif.vlan_id == 300);
    assert(verif.vlan_pcp == 6);
    assert(verif.opcode == 1);

    PacketMetadata meta{};
    TelcoFrameType ftype = TelcoFrameType::Unknown;
    FastpathClassifier::Classify(frame, len, meta, ftype);
    assert(meta.outer_vlan == 300);
    assert(ftype == TelcoFrameType::Arp);

    std::cout << "  -> ARP requests, GARP (req/reply), flood injection & VLAN tagging: PASSED" << std::endl;
}

// =========================================================================
// Test 5: Boundary Values, Fuzz & Truncation Safety
// =========================================================================
void TestBoundaryFuzzAndTruncationSafety() {
    std::cout << "[TEST] 5. Boundary Values, Fuzz & Truncation Safety..." << std::endl;

    StatelessGtpuGenerator gtpu_gen;
    QinQGenerator qinq_gen;
    StatelessArpGenerator arp_gen;

    alignas(64) uint8_t tiny_buf[16];

    // 1. Buffer too small check
    assert(gtpu_gen.GeneratePacket(tiny_buf, sizeof(tiny_buf)) == 0);
    assert(qinq_gen.GeneratePacket(tiny_buf, sizeof(tiny_buf)) == 0);
    assert(arp_gen.GeneratePacket(tiny_buf, sizeof(tiny_buf)) == 0);

    // 2. Null buffer check
    assert(gtpu_gen.GeneratePacket(nullptr, 1500) == 0);
    assert(qinq_gen.GeneratePacket(nullptr, 1500) == 0);
    assert(arp_gen.GeneratePacket(nullptr, 1500) == 0);

    // 3. Batch boundary check
    uint8_t* null_ptrs[4] = {nullptr, nullptr, nullptr, nullptr};
    uint32_t out_lens[4] = {0};
    assert(gtpu_gen.GenerateBatch(null_ptrs, out_lens, 0, 1500) == 0);
    assert(qinq_gen.GenerateBatch(nullptr, out_lens, 4, 1500) == 0);
    assert(arp_gen.GenerateBatch(null_ptrs, nullptr, 4, 1500) == 0);

    // 4. Inverted ranges auto-correction during Init()
    GtpuGenConfig gcfg;
    gcfg.teid_start = 5000;
    gcfg.teid_end = 1000; // Inverted
    gcfg.teid_step = 0;   // Zero step
    gtpu_gen.Init(gcfg);
    assert(gtpu_gen.GetConfig().teid_start == 1000);
    assert(gtpu_gen.GetConfig().teid_end == 5000);
    assert(gtpu_gen.GetConfig().teid_step == 1);

    QinQGeneratorConfig qcfg;
    qcfg.s_vlan_min = 3000;
    qcfg.s_vlan_max = 2000; // Inverted
    qcfg.s_vlan_step = 0;   // Zero step
    qinq_gen.Init(qcfg);
    assert(qinq_gen.GetConfig().s_vlan_min == 2000);
    assert(qinq_gen.GetConfig().s_vlan_max == 3000);
    assert(qinq_gen.GetConfig().s_vlan_step == 1);

    ArpGeneratorConfig acfg;
    acfg.target_ip_start = 0x0A0000FE;
    acfg.target_ip_end = 0x0A000001; // Inverted
    acfg.target_ip_step = 0;
    arp_gen.Init(acfg);
    assert(arp_gen.GetConfig().target_ip_start == 0x0A000001);
    assert(arp_gen.GetConfig().target_ip_end == 0x0A0000FE);
    assert(arp_gen.GetConfig().target_ip_step == 1);

    // 5. Verification helpers with truncated buffers
    alignas(64) uint8_t valid_frame[512];
    uint32_t vlen = gtpu_gen.GeneratePacket(valid_frame, sizeof(valid_frame));
    assert(vlen > 0);

    for (size_t short_len = 0; short_len < 64; ++short_len) {
        GtpuGenVerification gv;
        assert(!StatelessGtpuGenerator::VerifyFrame(valid_frame, short_len, gv));
        QinQVerificationInfo qv;
        assert(!QinQGenerator::VerifyFrame(valid_frame, short_len, qv));
        ArpVerificationInfo av;
        assert(!StatelessArpGenerator::VerifyFrame(valid_frame, short_len, av));
    }

    // 6. Null frame pointer to verifier
    GtpuGenVerification gv;
    assert(!StatelessGtpuGenerator::VerifyFrame(nullptr, 100, gv));
    QinQVerificationInfo qv;
    assert(!QinQGenerator::VerifyFrame(nullptr, 100, qv));
    ArpVerificationInfo av;
    assert(!StatelessArpGenerator::VerifyFrame(nullptr, 100, av));

    std::cout << "  -> Zero-length, null buffer, inverted range & truncation fuzz safety: PASSED" << std::endl;
}

// =========================================================================
// Test 6: Hardened Edge Cases, Jumbo Frames & Full 32-bit PRNG Ranges
// =========================================================================
void TestHardenedEdgeCasesAndJumboFrames() {
    std::cout << "[TEST] 6. Hardened Edge Cases, Jumbo Frames & Full 32-bit PRNG Ranges..." << std::endl;

    // 1. Jumbo Frame Generation: GTP-U (8900B payload -> ~9000B frame)
    {
        GtpuGenConfig cfg;
        cfg.inner_payload_size = 8900;
        StatelessGtpuGenerator gen(cfg);
        alignas(64) uint8_t jumbo_buf[10240];
        uint32_t len = gen.GeneratePacket(jumbo_buf, sizeof(jumbo_buf));
        assert(len >= 8900 && len <= 10240);

        GtpuGenVerification verif;
        bool ok = StatelessGtpuGenerator::VerifyFrame(jumbo_buf, len, verif);
        assert(ok && verif.is_valid);
        assert(verif.frame_len == len);
    }

    // 2. Jumbo Frame Generation: QinQ (8900B payload)
    {
        QinQGeneratorConfig cfg;
        cfg.payload_size = 8900;
        QinQGenerator gen(cfg);
        alignas(64) uint8_t jumbo_buf[10240];
        uint32_t len = gen.GeneratePacket(jumbo_buf, sizeof(jumbo_buf));
        assert(len >= 8900 && len <= 10240);

        QinQVerificationInfo verif;
        bool ok = QinQGenerator::VerifyFrame(jumbo_buf, len, verif);
        assert(ok && verif.is_valid);
    }

    // 3. Padded Frame Generation: ARP (1500B MTU padding)
    {
        ArpGeneratorConfig cfg;
        cfg.pad_to_min_frame = true;
        cfg.min_frame_size = 1500;
        StatelessArpGenerator gen(cfg);
        alignas(64) uint8_t pad_buf[2048];
        uint32_t len = gen.GeneratePacket(pad_buf, sizeof(pad_buf));
        assert(len == 1500);

        ArpVerificationInfo verif;
        bool ok = StatelessArpGenerator::VerifyFrame(pad_buf, len, verif);
        assert(ok && verif.is_valid);
        assert(verif.frame_len == 1500);
    }

    // 4. Full 32-bit PRNG Sweep Overflow Safety (0..0xFFFFFFFF)
    {
        ArpGeneratorConfig acfg;
        acfg.target_ip_start = 0;
        acfg.target_ip_end = 0xFFFFFFFFU;
        acfg.ip_cycle_mode = ArpIpCycleMode::PSEUDO_RANDOM;
        StatelessArpGenerator agen(acfg);
        alignas(64) uint8_t buf[256];
        bool non_zero_seen = false;
        for (int i = 0; i < 20; ++i) {
            agen.GeneratePacket(buf, sizeof(buf));
            if (agen.GetCurrentTargetIp() != 0) non_zero_seen = true;
        }
        assert(non_zero_seen && "PRNG stuck at 0 due to 32-bit unsigned overflow!");

        GtpuGenConfig gcfg;
        gcfg.teid_start = 0;
        gcfg.teid_end = 0xFFFFFFFFU;
        gcfg.teid_mode = TeidCycleMode::PSEUDO_RANDOM;
        StatelessGtpuGenerator ggen(gcfg);
        non_zero_seen = false;
        for (int i = 0; i < 20; ++i) {
            ggen.GeneratePacket(buf, sizeof(buf));
            if (ggen.GetCurrentTeid() != 0) non_zero_seen = true;
        }
        assert(non_zero_seen && "TEID PRNG stuck at 0 due to 32-bit unsigned overflow!");
    }

    // 5. Inverted Inner IP Range Auto-Normalization
    {
        GtpuGenConfig cfg;
        cfg.cycle_inner_ip = true;
        cfg.inner_ip_start = 0x0A000005;
        cfg.inner_ip_end = 0x0A000001; // Inverted
        cfg.inner_ip_step = 0;         // Zero step
        StatelessGtpuGenerator gen(cfg);
        assert(gen.GetConfig().inner_ip_start == 0x0A000001);
        assert(gen.GetConfig().inner_ip_end == 0x0A000005);
        assert(gen.GetConfig().inner_ip_step == 1);

        alignas(64) uint8_t buf[512];
        GtpuGenVerification verif;
        gen.GeneratePacket(buf, sizeof(buf));
        StatelessGtpuGenerator::VerifyFrame(buf, gen.GetPacketSize(), verif);
        assert(verif.inner_src_ip == 0x0A000001);
        gen.GeneratePacket(buf, sizeof(buf));
        StatelessGtpuGenerator::VerifyFrame(buf, gen.GetPacketSize(), verif);
        assert(verif.inner_src_ip == 0x0A000002);
    }

    // 6. FastpathClassifier Legacy 0x9100 QinQ Demux
    {
        QinQGeneratorConfig cfg;
        cfg.s_tpid = ETHERTYPE_9100;
        cfg.s_vlan_min = 777;
        cfg.c_vlan_min = 888;
        cfg.sweep_mode = QinQSweepMode::FLAT_FIXED;
        QinQGenerator gen(cfg);

        alignas(64) uint8_t frame[512];
        uint32_t len = gen.GeneratePacket(frame, sizeof(frame));
        assert(len >= 64);

        PacketMetadata meta{};
        TelcoFrameType ftype = TelcoFrameType::Unknown;
        bool ok = FastpathClassifier::Classify(frame, len, meta, ftype);
        assert(ok);
        assert(meta.outer_vlan == 777);
        assert(meta.inner_vlan == 888);
        assert(ftype == TelcoFrameType::Ipv4Data);
    }

    // 7. Getter consistency with generated packet stats
    {
        GtpuGenConfig gcfg;
        gcfg.teid_start = 42;
        StatelessGtpuGenerator ggen(gcfg);
        alignas(64) uint8_t buf[512];
        ggen.GeneratePacket(buf, sizeof(buf));
        assert(ggen.GetCurrentTeid() == ggen.GetStats().current_teid);
        assert(ggen.GetCurrentTeid() == 42);

        QinQGeneratorConfig qcfg;
        qcfg.s_vlan_min = 100;
        qcfg.c_vlan_min = 200;
        qcfg.sweep_mode = QinQSweepMode::FLAT_FIXED;
        QinQGenerator qgen(qcfg);
        qgen.GeneratePacket(buf, sizeof(buf));
        assert(qgen.GetCurrentSVlan() == qgen.GetStats().current_s_vlan);
        assert(qgen.GetCurrentCVlan() == qgen.GetStats().current_c_vlan);
        assert(qgen.GetCurrentSVlan() == 100);
        assert(qgen.GetCurrentCVlan() == 200);

        ArpGeneratorConfig acfg;
        acfg.target_ip_start = 0x0A000009;
        StatelessArpGenerator agen(acfg);
        agen.GeneratePacket(buf, sizeof(buf));
        assert(agen.GetCurrentTargetIp() == agen.GetStats().current_target_ip);
        assert(agen.GetCurrentTargetIp() == 0x0A000009);
    }

    // 8. ProtocolConfig VLAN propagation for StatelessArpGenerator
    {
        ProtocolConfig pcfg;
        pcfg.enable_vlan_tagging = true;
        pcfg.base_vlan_s = 350;
        StatelessArpGenerator agen;
        bool ok = agen.Init(pcfg);
        assert(ok);
        alignas(64) uint8_t buf[256];
        uint32_t len = agen.GeneratePacket(buf, sizeof(buf));
        ArpVerificationInfo verif;
        StatelessArpGenerator::VerifyFrame(buf, len, verif);
        assert(verif.has_vlan);
        assert(verif.vlan_id == 350);
    }

    std::cout << "  -> Jumbo frames (9KB+), 32-bit overflow guards, 0x9100 demux & getters: PASSED" << std::endl;
}

// =========================================================================
// Test 7: Generator Throughput Benchmark (Honest CPU Memory Construction)
// =========================================================================
void TestStatelessThroughputBenchmark() {
    std::cout << "[TEST] 7. Stateless Generators In-Memory Construction Benchmark (1M Packets)..." << std::endl;

    constexpr uint32_t TOTAL_PACKETS = 1000000;
    alignas(64) uint8_t pkt_buf[1536];

    // 1. GTP-U Generator Benchmark
    {
        StatelessGtpuGenerator gen;
        auto start = std::chrono::high_resolution_clock::now();
        for (uint32_t i = 0; i < TOTAL_PACKETS; ++i) {
            gen.GeneratePacket(pkt_buf, sizeof(pkt_buf));
        }
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed_ms = end - start;

        double sec = elapsed_ms.count() / 1000.0;
        double mpps = (TOTAL_PACKETS / sec) / 1000000.0;
        size_t pkt_size = gen.GetPacketSize();
        // Wire bits includes 20 bytes Ethernet framing (preamble + SFD + IFG: 8 + 12 = 20B)
        double gbps = (mpps * 1e6 * (pkt_size + 20) * 8.0) / 1e9;

        std::cout << "  [BENCHMARK] GTP-U Generator: " << TOTAL_PACKETS << " pkts (" << pkt_size 
                  << "B) in " << elapsed_ms.count() << " ms -> " 
                  << mpps << " Mpps (" << gbps << " Gbps wire-equivalent)" << std::endl;
        assert(mpps > 2.0); // Minimum baseline sanity check on local hardware
    }

    // 2. QinQ VLAN Sweep Benchmark
    {
        QinQGenerator gen;
        auto start = std::chrono::high_resolution_clock::now();
        for (uint32_t i = 0; i < TOTAL_PACKETS; ++i) {
            gen.GeneratePacket(pkt_buf, sizeof(pkt_buf));
        }
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed_ms = end - start;

        double sec = elapsed_ms.count() / 1000.0;
        double mpps = (TOTAL_PACKETS / sec) / 1000000.0;
        size_t pkt_size = gen.GetPacketSize();
        double gbps = (mpps * 1e6 * (pkt_size + 20) * 8.0) / 1e9;

        std::cout << "  [BENCHMARK] QinQ Generator:  " << TOTAL_PACKETS << " pkts (" << pkt_size 
                  << "B) in " << elapsed_ms.count() << " ms -> " 
                  << mpps << " Mpps (" << gbps << " Gbps wire-equivalent)" << std::endl;
        assert(mpps > 2.0);
    }

    // 3. ARP Probe & Scale Benchmark
    {
        StatelessArpGenerator gen;
        auto start = std::chrono::high_resolution_clock::now();
        for (uint32_t i = 0; i < TOTAL_PACKETS; ++i) {
            gen.GeneratePacket(pkt_buf, sizeof(pkt_buf));
        }
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::milli> elapsed_ms = end - start;

        double sec = elapsed_ms.count() / 1000.0;
        double mpps = (TOTAL_PACKETS / sec) / 1000000.0;
        size_t pkt_size = gen.GetPacketSize();
        double gbps = (mpps * 1e6 * (pkt_size + 20) * 8.0) / 1e9;

        std::cout << "  [BENCHMARK] ARP Generator:   " << TOTAL_PACKETS << " pkts (" << pkt_size 
                  << "B) in " << elapsed_ms.count() << " ms -> " 
                  << mpps << " Mpps (" << gbps << " Gbps wire-equivalent)" << std::endl;
        assert(mpps > 2.0);
    }

    std::cout << "  [HONESTY NOTE] Benchmark measures in-memory CPU packet synthesis speed without NIC/PCIe I/O.\n"
              << "                 Physical line rate testing requires dedicated physical NICs (i40e/mlx5) with DPDK PMDs." << std::endl;
    std::cout << "  -> High-throughput zero-heap generator benchmark: PASSED" << std::endl;
}

// =========================================================================
// Main Runner
// =========================================================================
int main() {
    std::cout << "=================================================================" << std::endl;
    std::cout << "   SAMURAI STATELESS TELECOM GENERATORS VERIFICATION SUITE       " << std::endl;
    std::cout << "=================================================================" << std::endl;

    TestZeroDynamicAllocation();
    TestStatelessGtpuWireFormatAndCycling();
    TestQinQSweepWireFormatAndVlanRanges();
    TestStatelessArpWireFormatAndModes();
    TestBoundaryFuzzAndTruncationSafety();
    TestHardenedEdgeCasesAndJumboFrames();
    TestStatelessThroughputBenchmark();

    std::cout << "=================================================================" << std::endl;
    std::cout << "  ALL STATELESS GENERATOR TESTS PASSED SUCCESSFULLY! (100%)      " << std::endl;
    std::cout << "=================================================================" << std::endl;
    return 0;
}
