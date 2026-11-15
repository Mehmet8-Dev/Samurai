#pragma once

#include "samurai/telecom/core/session_manager.hpp"
#include "samurai/telecom/core/hierarchical_timing_wheel.hpp"
#include "samurai/telecom/protocols/stateful/mobile/pfcp_engine.hpp"
#include "samurai/telecom/protocols/stateful/mobile/pfcp_types.hpp"
#include "samurai/gpu_packet_cuda/zero_copy_dataplane_contract.cuh"

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <memory>
#include <mutex>

namespace samurai::telecom::cups {

struct CupsTunnelParams {
    uint32_t uplink_teid{1};
    uint32_t downlink_teid{1};
    uint32_t outer_src_ip{0xC0A80164}; // 192.168.1.100
    uint32_t outer_dst_ip{0xC0A80101}; // 192.168.1.1
    uint32_t ue_src_ip{0x0A3C0001};    // 10.60.0.1
    uint32_t inner_dst_ip{0x08080808}; // 8.8.8.8
    uint16_t inner_src_port{0};
    uint16_t inner_dst_port{80};
    uint16_t svlan_tci{0};
    uint16_t cvlan_tci{0};
    uint8_t  qfi{9};
    uint8_t  pdu_type{1};             // 1 = Uplink, 0 = Downlink
    uint8_t  inner_proto{17};         // 17 = UDP, 6 = TCP, 1 = ICMP
    uint8_t  vlan_depth{0};
    bool     with_seq{true};
    bool     with_qfi_ext{true};
    bool     echo_mode{false};
    uint8_t  outer_dst_mac[6]{0x00, 0x0F, 0x53, 0x21, 0x52, 0x01};
};

class DpuArmCupsSessionController {
public:
    explicit DpuArmCupsSessionController(
        samurai::telecom::SessionManager& session_mgr,
        samurai::telecom::mobile::PfcpEngine& pfcp_engine,
        uint32_t max_capacity = 65536);
    ~DpuArmCupsSessionController();

    DpuArmCupsSessionController(const DpuArmCupsSessionController&) = delete;
    DpuArmCupsSessionController& operator=(const DpuArmCupsSessionController&) = delete;

    // Shared memory setup (creates or connects to zero-copy contract file)
    bool InitializeSharedRegion(const std::string& shm_path, bool create_new = true);
    void DetachSharedRegion();

    // Control Plane: 3GPP TS 29.244 N4 Session Operations
    bool EstablishSubscriberSession(
        uint32_t subscriber_idx,
        uint64_t cp_seid,
        const CupsTunnelParams& params,
        std::vector<uint8_t>* out_pfcp_req = nullptr);

    bool ModifySubscriberSession(
        uint32_t subscriber_idx,
        uint8_t new_qfi,
        uint32_t new_teid,
        std::vector<uint8_t>* out_pfcp_req = nullptr);

    bool DeleteSubscriberSession(
        uint32_t subscriber_idx,
        std::vector<uint8_t>* out_pfcp_req = nullptr);

    // Inbound N4 PFCP Message Handler (UPF / CP response handling)
    bool ProcessInboundPfcpMessage(
        const uint8_t* frame, size_t len,
        std::vector<uint8_t>* out_response = nullptr);

    // Periodic heartbeat / timestamp update
    void UpdateHeartbeat(uint64_t now_ns);

    // Read per-tunnel TX metrics reported atomically by GPU user plane
    bool ReadTunnelTxMetrics(uint32_t subscriber_idx, uint32_t* out_packets, uint32_t* out_bytes) const;

    // Build ZMQ TELCO_TUNNEL_UPSERT wire payload for disaggregated DPU->GPU delivery
    std::vector<uint8_t> BuildZmqUpsertPayload(
        uint32_t start_slot, uint32_t count, uint32_t flags = 0) const;

    // Accessors
    const samurai::gpu_packet_cuda::zero_copy::DpuCupsSharedRegionHeaderV1* GetHeader() const;
    const samurai::gpu_packet_cuda::zero_copy::TelcoGpuTunnelEntryV1* GetTunnelEntry(uint32_t slot) const;
    uint32_t GetActiveSessions() const;
    uint32_t GetCapacity() const { return capacity_; }
    bool IsMapped() const { return shm_base_ != nullptr; }

private:
    void CommitTunnelEntry(uint32_t slot, const CupsTunnelParams& params, bool active);

    samurai::telecom::SessionManager& session_mgr_;
    samurai::telecom::mobile::PfcpEngine& pfcp_engine_;
    uint32_t capacity_{65536};

    int shm_fd_{-1};
    void* shm_base_{nullptr};
    size_t shm_bytes_{0};
    bool is_owner_{false};

    samurai::gpu_packet_cuda::zero_copy::DpuCupsSharedRegionHeaderV1* header_{nullptr};
    samurai::gpu_packet_cuda::zero_copy::TelcoGpuTunnelEntryV1* entries_{nullptr};

    mutable std::mutex mu_;
    uint32_t pfcp_seq_{1};
};

} // namespace samurai::telecom::cups
