#include "dpu_arm_cups_bridge.hpp"
#include "ddos_samurai/zmq/daemon/wire_protocol.h"

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <chrono>
#include <algorithm>

namespace samurai::telecom::cups {

using namespace ddos_samurai::gpu_packet_cuda::zero_copy;

namespace {

inline void SeqlockWriteBegin(volatile uint64_t* version_ptr) noexcept {
    uint64_t v = *version_ptr;
    if ((v & 1ull) != 0ull) {
        v += 1ull;
    }
    __atomic_store_n(version_ptr, v + 1ull, __ATOMIC_RELEASE);
#if defined(__aarch64__)
    asm volatile("dmb ishst" ::: "memory");
#endif
}

inline void SeqlockWriteCommit(volatile uint64_t* version_ptr) noexcept {
#if defined(__aarch64__)
    asm volatile("dmb ishst" ::: "memory");
#endif
    uint64_t v = *version_ptr;
    __atomic_store_n(version_ptr, v + 1ull, __ATOMIC_RELEASE);
}

inline bool SeqlockReadEntry(const TelcoGpuTunnelEntryV1& src, TelcoGpuTunnelEntryV1& dst) noexcept {
    for (int retry = 0; retry < 16; ++retry) {
        const uint64_t v1 = __atomic_load_n(&src.version, __ATOMIC_ACQUIRE);
        if ((v1 & 1ull) != 0ull) {
            continue;
        }
        std::memcpy(&dst, &src, sizeof(TelcoGpuTunnelEntryV1));
#if defined(__aarch64__)
        asm volatile("dmb ishld" ::: "memory");
#endif
        const uint64_t v2 = __atomic_load_n(&src.version, __ATOMIC_ACQUIRE);
        if (v1 == v2) {
            return true;
        }
    }
    return false;
}

} // namespace

DpuArmCupsSessionController::DpuArmCupsSessionController(
    ddos_samurai::telecom::SessionManager& session_mgr,
    ddos_samurai::telecom::mobile::PfcpEngine& pfcp_engine,
    uint32_t max_capacity)
    : session_mgr_(session_mgr),
      pfcp_engine_(pfcp_engine),
      capacity_(max_capacity > 0 ? max_capacity : 65536u) {}

DpuArmCupsSessionController::~DpuArmCupsSessionController() {
    DetachSharedRegion();
}

bool DpuArmCupsSessionController::InitializeSharedRegion(const std::string& shm_path, bool create_new) {
    std::lock_guard<std::mutex> lock(mu_);
    if (shm_base_ != nullptr) {
        return true;
    }

    const size_t page_sz = 4096;
    const size_t raw_bytes = sizeof(DpuCupsSharedRegionHeaderV1) + static_cast<size_t>(capacity_) * sizeof(TelcoGpuTunnelEntryV1);
    shm_bytes_ = ((raw_bytes + page_sz - 1) / page_sz) * page_sz;

    int flags = O_RDWR;
    if (create_new) {
        flags |= O_CREAT | O_TRUNC;
    }

    shm_fd_ = ::open(shm_path.c_str(), flags, 0666);
    if (shm_fd_ < 0) {
        return false;
    }

    if (create_new) {
        if (::ftruncate(shm_fd_, static_cast<off_t>(shm_bytes_)) != 0) {
            ::close(shm_fd_);
            shm_fd_ = -1;
            return false;
        }
        is_owner_ = true;
    } else {
        struct stat st{};
        if (::fstat(shm_fd_, &st) != 0 || static_cast<size_t>(st.st_size) < shm_bytes_) {
            ::close(shm_fd_);
            shm_fd_ = -1;
            return false;
        }
        is_owner_ = false;
    }

    shm_base_ = ::mmap(nullptr, shm_bytes_, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd_, 0);
    if (shm_base_ == MAP_FAILED || !shm_base_) {
        shm_base_ = nullptr;
        ::close(shm_fd_);
        shm_fd_ = -1;
        return false;
    }

    header_ = static_cast<DpuCupsSharedRegionHeaderV1*>(shm_base_);
    entries_ = reinterpret_cast<TelcoGpuTunnelEntryV1*>(
        static_cast<uint8_t*>(shm_base_) + sizeof(DpuCupsSharedRegionHeaderV1));

    if (create_new) {
        std::memset(shm_base_, 0, shm_bytes_);
        header_->magic = kDpuCupsSharedMagicV1;
        header_->version = kDpuCupsSharedVersionV1;
        header_->capacity = capacity_;
        header_->active_span = 0;
        header_->commit_epoch = 1;
        header_->dpu_heartbeat_ns = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
        header_->active_sessions = 0;
        header_->established_total = 0;
        header_->modified_total = 0;
        header_->deleted_total = 0;

        uint32_t arch_flags = static_cast<uint32_t>(DpuCupsArchFlags::kNone);
#if defined(__aarch64__)
        arch_flags |= static_cast<uint32_t>(DpuCupsArchFlags::kAarch64Host);
#if defined(__ARM_FEATURE_CRC32)
        arch_flags |= static_cast<uint32_t>(DpuCupsArchFlags::kHwCrc32);
#endif
#endif
        header_->arch_flags = arch_flags;
    } else {
        if (header_->magic != kDpuCupsSharedMagicV1 || header_->version != kDpuCupsSharedVersionV1) {
            DetachSharedRegion();
            return false;
        }
        capacity_ = header_->capacity;
    }

    return true;
}

void DpuArmCupsSessionController::DetachSharedRegion() {
    if (shm_base_) {
        ::munmap(shm_base_, shm_bytes_);
        shm_base_ = nullptr;
    }
    if (shm_fd_ >= 0) {
        ::close(shm_fd_);
        shm_fd_ = -1;
    }
    header_ = nullptr;
    entries_ = nullptr;
    shm_bytes_ = 0;
    is_owner_ = false;
}

void DpuArmCupsSessionController::CommitTunnelEntry(
    uint32_t slot, const CupsTunnelParams& params, bool active) {
    if (!entries_ || slot >= capacity_) {
        return;
    }

    auto& entry = entries_[slot];
    SeqlockWriteBegin(&entry.version);

    entry.uplink_teid = params.uplink_teid;
    entry.downlink_teid = params.downlink_teid;
    entry.outer_src_ip = params.outer_src_ip;
    entry.outer_dst_ip = params.outer_dst_ip;
    entry.ue_src_ip = params.ue_src_ip;
    entry.inner_dst_ip = params.inner_dst_ip;
    entry.svlan_tci = params.svlan_tci;
    entry.cvlan_tci = params.cvlan_tci;
    entry.inner_src_port = params.inner_src_port;
    entry.inner_dst_port = params.inner_dst_port;
    entry.qfi = params.qfi;
    entry.pdu_type = params.pdu_type;
    entry.inner_proto = params.inner_proto;
    entry.vlan_depth = params.vlan_depth;

    uint8_t flags = 0;
    if (active) flags |= static_cast<uint8_t>(TelcoGpuTunnelFlags::kActive);
    if (params.with_seq) flags |= static_cast<uint8_t>(TelcoGpuTunnelFlags::kWithSeq);
    if (params.with_qfi_ext) flags |= static_cast<uint8_t>(TelcoGpuTunnelFlags::kWithQfiExt);
    if (params.echo_mode) flags |= static_cast<uint8_t>(TelcoGpuTunnelFlags::kEchoMode);
    entry.flags = flags;

    for (int i = 0; i < 6; ++i) {
        entry.outer_dst_mac[i] = params.outer_dst_mac[i];
    }

    if (!active) {
        entry.tx_packets = 0;
        entry.tx_bytes = 0;
    }

    SeqlockWriteCommit(&entry.version);
}

bool DpuArmCupsSessionController::EstablishSubscriberSession(
    uint32_t subscriber_idx,
    uint64_t cp_seid,
    const CupsTunnelParams& params,
    std::vector<uint8_t>* out_pfcp_req) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!entries_ || !header_ || subscriber_idx >= capacity_) {
        return false;
    }

    auto* ctx = session_mgr_.GetSessionByIndex(subscriber_idx);
    if (!ctx) {
        ctx = session_mgr_.AcquireSession();
    }
    if (!ctx) {
        return false;
    }

    ctx->session_id = subscriber_idx + 1u;
    ctx->client_ip = params.ue_src_ip;
    ctx->peer_ip = params.inner_dst_ip;
    ctx->teid_uplink = params.uplink_teid;
    ctx->teid_downlink = params.downlink_teid;
    ctx->s_vlan = params.svlan_tci;
    ctx->c_vlan = params.cvlan_tci;
    ctx->state = ddos_samurai::telecom::SessionState::ESTABLISHED;

    session_mgr_.BindGtpuSession(ctx, params.uplink_teid);
    session_mgr_.BindPfcpSession(ctx, cp_seid);

    if (out_pfcp_req) {
        ddos_samurai::telecom::mobile::PfcpPdr pdr{};
        pdr.pdr_id = static_cast<uint16_t>(subscriber_idx + 1u);
        pdr.precedence = 100;
        pdr.source_interface = ddos_samurai::telecom::mobile::PfcpInterface::Access;
        pdr.teid = params.uplink_teid;
        pdr.ue_ip = params.ue_src_ip;
        pdr.far_id = static_cast<uint32_t>(subscriber_idx + 1u);

        ddos_samurai::telecom::mobile::PfcpFar far{};
        far.far_id = static_cast<uint32_t>(subscriber_idx + 1u);
        far.apply_action = ddos_samurai::telecom::mobile::PFCP_APPLY_ACTION_FORW;
        far.destination_interface = ddos_samurai::telecom::mobile::PfcpInterface::Core;
        far.outer_teid = params.downlink_teid;
        far.peer_upf_ip = params.outer_dst_ip;

        *out_pfcp_req = pfcp_engine_.BuildSessionEstablishmentRequest(
            ctx, pfcp_seq_++, cp_seid, pdr, far);
    }

    CommitTunnelEntry(subscriber_idx, params, true);

    header_->active_sessions++;
    header_->established_total++;
    header_->active_span = std::max<uint32_t>(header_->active_span, subscriber_idx + 1u);
    header_->commit_epoch++;
    header_->dpu_heartbeat_ns = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());

    return true;
}

bool DpuArmCupsSessionController::ModifySubscriberSession(
    uint32_t subscriber_idx,
    uint8_t new_qfi,
    uint32_t new_teid,
    std::vector<uint8_t>* out_pfcp_req) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!entries_ || !header_ || subscriber_idx >= capacity_) {
        return false;
    }

    auto* ctx = session_mgr_.GetSessionByIndex(subscriber_idx);
    if (!ctx) {
        return false;
    }

    const uint32_t old_teid = ctx->teid_uplink;
    ctx->teid_uplink = new_teid;

    if (old_teid != new_teid) {
        session_mgr_.UnbindGtpuSession(ctx);
        session_mgr_.BindGtpuSession(ctx, new_teid);
    }

    if (out_pfcp_req) {
        ddos_samurai::telecom::mobile::PfcpFar updated_far{};
        updated_far.far_id = static_cast<uint32_t>(subscriber_idx + 1u);
        updated_far.apply_action = ddos_samurai::telecom::mobile::PFCP_APPLY_ACTION_FORW;
        updated_far.destination_interface = ddos_samurai::telecom::mobile::PfcpInterface::Core;
        updated_far.outer_teid = new_teid;
        *out_pfcp_req = pfcp_engine_.BuildSessionModificationRequest(
            ctx, pfcp_seq_++, updated_far);
    }

    auto& entry = entries_[subscriber_idx];
    SeqlockWriteBegin(&entry.version);
    entry.qfi = new_qfi;
    entry.uplink_teid = new_teid;
    SeqlockWriteCommit(&entry.version);

    header_->modified_total++;
    header_->commit_epoch++;
    header_->dpu_heartbeat_ns = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());

    return true;
}

bool DpuArmCupsSessionController::DeleteSubscriberSession(
    uint32_t subscriber_idx,
    std::vector<uint8_t>* out_pfcp_req) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!entries_ || !header_ || subscriber_idx >= capacity_) {
        return false;
    }

    auto* ctx = session_mgr_.GetSessionByIndex(subscriber_idx);
    if (ctx) {
        if (out_pfcp_req) {
            *out_pfcp_req = pfcp_engine_.BuildSessionDeletionRequest(ctx, pfcp_seq_++);
        }
        session_mgr_.UnbindGtpuSession(ctx);
        session_mgr_.UnbindPfcpSession(ctx);
        ctx->state = ddos_samurai::telecom::SessionState::TERMINATING;
    }

    auto& entry = entries_[subscriber_idx];
    SeqlockWriteBegin(&entry.version);
    entry.flags &= ~static_cast<uint8_t>(TelcoGpuTunnelFlags::kActive);
    SeqlockWriteCommit(&entry.version);

    if (header_->active_sessions > 0) {
        header_->active_sessions--;
    }
    header_->deleted_total++;
    header_->commit_epoch++;
    header_->dpu_heartbeat_ns = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());

    return true;
}

bool DpuArmCupsSessionController::ProcessInboundPfcpMessage(
    const uint8_t* frame, size_t len,
    std::vector<uint8_t>* out_response) {
    if (!frame || len < 4) {
        return false;
    }

    ddos_samurai::telecom::mobile::PfcpDecapInfo info{};
    if (!ddos_samurai::telecom::mobile::PfcpEngine::ParsePfcpPacket(frame, len, info)) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mu_);
    auto msg_type = static_cast<ddos_samurai::telecom::mobile::PfcpMessageType>(info.msg_type);

    if (msg_type == ddos_samurai::telecom::mobile::PfcpMessageType::HeartbeatRequest) {
        if (out_response) {
            const uint32_t now_sec = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
            *out_response = pfcp_engine_.BuildHeartbeatResponse(info.seq_num, now_sec);
        }
        return true;
    }

    if (msg_type == ddos_samurai::telecom::mobile::PfcpMessageType::AssociationSetupRequest) {
        if (out_response) {
            *out_response = pfcp_engine_.BuildAssociationSetupResponse(
                info.seq_num, "DPU_ARM_UPF", 0xC0A80164, ddos_samurai::telecom::mobile::PfcpCause::RequestAccepted);
        }
        return true;
    }

    // Session Establishment Request (N4 UPF responder role)
    if (msg_type == ddos_samurai::telecom::mobile::PfcpMessageType::SessionEstablishmentRequest) {
        auto* session = session_mgr_.AcquireSession();
        if (!session) {
            if (out_response) {
                *out_response = pfcp_engine_.BuildSessionEstablishmentResponse(
                    nullptr, info.seq_num, info.seid, 0, ddos_samurai::telecom::mobile::PfcpCause::SystemFailure);
            }
            return false;
        }

        const uint32_t sub_idx = static_cast<uint32_t>(session_mgr_.GetSessionIndex(session));
        const uint64_t up_seid = static_cast<uint64_t>(sub_idx + 1000u);
        const uint32_t allocated_teid = 0x50000000u + sub_idx;

        CupsTunnelParams p{};
        p.uplink_teid = allocated_teid;
        p.downlink_teid = allocated_teid;
        p.qfi = 9;
        p.pdu_type = 1;

        CommitTunnelEntry(sub_idx, p, true);
        session_mgr_.BindGtpuSession(session, allocated_teid);
        session_mgr_.BindPfcpSession(session, info.seid);

        if (header_) {
            header_->active_sessions++;
            header_->established_total++;
            header_->active_span = std::max<uint32_t>(header_->active_span, sub_idx + 1u);
            header_->commit_epoch++;
        }

        if (out_response) {
            *out_response = pfcp_engine_.BuildSessionEstablishmentResponse(
                session, info.seq_num, info.seid, up_seid, ddos_samurai::telecom::mobile::PfcpCause::RequestAccepted);
        }
        return true;
    }

    // Pass through to PfcpEngine
    return pfcp_engine_.ProcessRxFrame(frame, len, nullptr);
}

void DpuArmCupsSessionController::UpdateHeartbeat(uint64_t now_ns) {
    std::lock_guard<std::mutex> lock(mu_);
    if (header_) {
        header_->dpu_heartbeat_ns = now_ns;
    }
}

bool DpuArmCupsSessionController::ReadTunnelTxMetrics(
    uint32_t subscriber_idx, uint32_t* out_packets, uint32_t* out_bytes) const {
    std::lock_guard<std::mutex> lock(mu_);
    if (!entries_ || subscriber_idx >= capacity_) {
        return false;
    }

    const auto& entry = entries_[subscriber_idx];
    if (out_packets) {
        *out_packets = __atomic_load_n(&entry.tx_packets, __ATOMIC_RELAXED);
    }
    if (out_bytes) {
        *out_bytes = __atomic_load_n(&entry.tx_bytes, __ATOMIC_RELAXED);
    }
    return true;
}

std::vector<uint8_t> DpuArmCupsSessionController::BuildZmqUpsertPayload(
    uint32_t start_slot, uint32_t count, uint32_t flags) const {
    std::lock_guard<std::mutex> lock(mu_);
    if (!entries_ || start_slot >= capacity_) {
        return {};
    }

    const uint32_t n = std::min<uint32_t>(count, capacity_ - start_slot);
    const size_t total_bytes = sizeof(samurai::wire::TelcoGpuTunnelUpsertV1) +
                               static_cast<size_t>(n) * sizeof(TelcoGpuTunnelEntryV1);

    std::vector<uint8_t> payload(total_bytes, 0);

    samurai::wire::TelcoGpuTunnelUpsertV1 hdr{};
    hdr.count = n;
    hdr.flags = flags;
    std::memcpy(payload.data(), &hdr, sizeof(hdr));

    auto* dst_entries = reinterpret_cast<TelcoGpuTunnelEntryV1*>(
        payload.data() + sizeof(hdr));

    for (uint32_t i = 0; i < n; ++i) {
        const auto& src = entries_[start_slot + i];
        (void)SeqlockReadEntry(src, dst_entries[i]);
    }

    return payload;
}

const DpuCupsSharedRegionHeaderV1* DpuArmCupsSessionController::GetHeader() const {
    std::lock_guard<std::mutex> lock(mu_);
    return header_;
}

const TelcoGpuTunnelEntryV1* DpuArmCupsSessionController::GetTunnelEntry(uint32_t slot) const {
    std::lock_guard<std::mutex> lock(mu_);
    if (!entries_ || slot >= capacity_) return nullptr;
    return &entries_[slot];
}

uint32_t DpuArmCupsSessionController::GetActiveSessions() const {
    std::lock_guard<std::mutex> lock(mu_);
    return header_ ? header_->active_sessions : 0u;
}

} // namespace samurai::telecom::cups
