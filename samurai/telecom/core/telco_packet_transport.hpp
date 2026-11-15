#pragma once

#include "samurai/dpdk/dpdk_core.hpp"

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <deque>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#ifndef AF_PACKET
#define AF_PACKET 17
#endif

namespace samurai::telecom {

enum class TelcoTransportBackend : uint8_t {
    AfPacketSocket = 0,
    DpdkDirect     = 1,
    LoopbackMemory = 2,
};

/**
 * Abstract Packet Transport Layer decoupling Telecom Protocol Engines &
 * Session/Timer state machines from the underlying wire I/O mechanism
 * (AF_PACKET raw socket, DPDK Poll-Mode Driver / P2P TX, or Loopback test bus).
 */
class ITelcoPacketTransport {
public:
    virtual ~ITelcoPacketTransport() = default;

    virtual bool Open(const std::string& target_spec) = 0;
    virtual void Close() = 0;
    virtual bool IsOpen() const noexcept = 0;
    virtual TelcoTransportBackend GetBackend() const noexcept = 0;
    virtual std::string_view GetBackendName() const noexcept = 0;

    virtual ssize_t Transmit(const uint8_t* data, size_t len) = 0;

    virtual size_t TransmitBurst(const uint8_t* const* frames,
                                 const uint16_t* lengths,
                                 size_t count) {
        size_t sent = 0;
        for (size_t i = 0; i < count; ++i) {
            if (frames[i] && lengths[i] > 0) {
                if (Transmit(frames[i], lengths[i]) > 0) {
                    ++sent;
                }
            }
        }
        return sent;
    }

    virtual ssize_t Receive(uint8_t* buffer, size_t max_len) = 0;
};

// ---------------------------------------------------------------------------
// 1. AF_PACKET Raw Socket Transport (Kernel Bypass Olmayan Commodity NIC Yolu)
// ---------------------------------------------------------------------------
class AfPacketTelcoTransport final : public ITelcoPacketTransport {
public:
    AfPacketTelcoTransport() = default;
    ~AfPacketTelcoTransport() override { Close(); }

    bool Open(const std::string& iface_name) override {
        Close();
        if (iface_name.empty()) return false;
        ifname_ = iface_name;

        const int fd = ::socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL));
        if (fd < 0) {
            std::cerr << "[TELCO_TRANSPORT][AF_PACKET] Raw socket open failed on '"
                      << iface_name << "': " << std::strerror(errno) << "\n";
            return false;
        }

        int buf_size = 16 * 1024 * 1024;
        (void)::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
        (void)::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));

#ifdef PACKET_IGNORE_OUTGOING
        int ignore_out = 1;
        (void)::setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ignore_out, sizeof(ignore_out));
#endif

        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        std::strncpy(ifr.ifr_name, iface_name.c_str(), IFNAMSIZ - 1);
        if (::ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
            std::cerr << "[TELCO_TRANSPORT][AF_PACKET] ioctl(SIOCGIFINDEX) failed for " << iface_name << "\n";
            ::close(fd);
            return false;
        }

        struct sockaddr_ll sll{};
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifr.ifr_ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);

        if (::bind(fd, reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll)) < 0) {
            std::cerr << "[TELCO_TRANSPORT][AF_PACKET] bind failed on " << iface_name << ": " << std::strerror(errno) << "\n";
            ::close(fd);
            return false;
        }

        fd_ = fd;
        ifindex_ = ifr.ifr_ifindex;
        return true;
    }

    void Close() override {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
            ifindex_ = -1;
        }
    }

    bool IsOpen() const noexcept override { return fd_ >= 0; }
    TelcoTransportBackend GetBackend() const noexcept override { return TelcoTransportBackend::AfPacketSocket; }
    std::string_view GetBackendName() const noexcept override { return "af_packet"; }

    ssize_t Transmit(const uint8_t* data, size_t len) override {
        if (fd_ < 0 || !data || len == 0) return -1;
        return ::send(fd_, data, len, MSG_DONTWAIT);
    }

    ssize_t Receive(uint8_t* buffer, size_t max_len) override {
        if (fd_ < 0 || !buffer || max_len == 0) return -1;
        return ::recv(fd_, buffer, max_len, MSG_DONTWAIT);
    }

private:
    int fd_{-1};
    int ifindex_{-1};
    std::string ifname_;
};

// ---------------------------------------------------------------------------
// 2. DPDK Poll-Mode Driver Transport (Direct Userspace PMD Fastpath)
// ---------------------------------------------------------------------------
class DpdkTelcoTransport final : public ITelcoPacketTransport {
public:
    DpdkTelcoTransport() = default;
    ~DpdkTelcoTransport() override { Close(); }

    bool Open(const std::string& target_spec) override {
        Close();
        if (!samurai::dpdk::available()) {
            std::cerr << "[TELCO_TRANSPORT][DPDK] Binary compiled without SAMURAI_WITH_DPDK; refusing silent fallback.\n";
            return false;
        }

        std::string eal_args = "--no-shconf";
        if (!target_spec.empty() && target_spec.rfind("net_", 0) == 0) {
            eal_args += " --vdev=" + target_spec + " --no-pci";
        }

        std::string err;
        if (!samurai::dpdk::ensure_eal(eal_args, err)) {
            std::cerr << "[TELCO_TRANSPORT][DPDK] EAL init failed for '" << target_spec << "': " << err << "\n";
            return false;
        }

        samurai::dpdk::OpenConfig cfg{};
        cfg.port_id = 0;
        if (!target_spec.empty() && target_spec[0] >= '0' && target_spec[0] <= '9') {
            cfg.port_id = static_cast<uint16_t>(std::stoul(target_spec));
        }
        cfg.num_tx_queues = 1;
        cfg.num_rx_queues = 1;
        cfg.burst_size = 64;
        cfg.mempool_size = 8192;
        cfg.eal_args = eal_args;

        const int64_t h = samurai::dpdk::open_port(cfg, err);
        if (h < 0) {
            std::cerr << "[TELCO_TRANSPORT][DPDK] Port open failed for port_id=" << cfg.port_id << ": " << err << "\n";
            return false;
        }

        port_handle_ = h;
        return true;
    }

    void Close() override {
        if (port_handle_ >= 0) {
            samurai::dpdk::close_port(port_handle_);
            port_handle_ = -1;
        }
        rx_staging_.clear();
    }

    bool IsOpen() const noexcept override { return port_handle_ >= 0; }
    TelcoTransportBackend GetBackend() const noexcept override { return TelcoTransportBackend::DpdkDirect; }
    std::string_view GetBackendName() const noexcept override { return "dpdk"; }

    ssize_t Transmit(const uint8_t* data, size_t len) override {
        if (port_handle_ < 0 || !data || len == 0 || len > 65535u) return -1;
        const auto res = samurai::dpdk::tx_burst(port_handle_, 0, data, static_cast<uint16_t>(len), 1);
        return (res.sent == 1) ? static_cast<ssize_t>(len) : -1;
    }

    size_t TransmitBurst(const uint8_t* const* frames,
                         const uint16_t* lengths,
                         size_t count) override {
        if (port_handle_ < 0 || !frames || !lengths || count == 0) return 0;
        size_t sent_total = 0;
        for (size_t i = 0; i < count; ++i) {
            if (frames[i] && lengths[i] > 0) {
                const auto res = samurai::dpdk::tx_burst(port_handle_, 0, frames[i], lengths[i], 1);
                sent_total += static_cast<size_t>(res.sent);
            }
        }
        return sent_total;
    }

    ssize_t Receive(uint8_t* buffer, size_t max_len) override {
        if (port_handle_ < 0 || !buffer || max_len == 0) return -1;
        if (rx_staging_.empty()) {
            static constexpr uint16_t kBurst = 32;
            static constexpr uint16_t kStride = 2048;
            std::vector<uint8_t> flat_frames(static_cast<size_t>(kBurst) * kStride);
            uint16_t lens[kBurst] = {0};
            const int got = samurai::dpdk::poll_rx(port_handle_, 0, kBurst, flat_frames.data(), kStride, lens);
            for (int i = 0; i < got; ++i) {
                const uint8_t* p = flat_frames.data() + static_cast<size_t>(i) * kStride;
                rx_staging_.emplace_back(p, p + lens[i]);
            }
        }
        if (rx_staging_.empty()) return -1;
        auto& front = rx_staging_.front();
        const size_t to_copy = std::min(max_len, front.size());
        std::memcpy(buffer, front.data(), to_copy);
        rx_staging_.pop_front();
        return static_cast<ssize_t>(to_copy);
    }

    int64_t GetPortHandle() const noexcept { return port_handle_; }

private:
    int64_t port_handle_{-1};
    std::deque<std::vector<uint8_t>> rx_staging_;
};

// ---------------------------------------------------------------------------
// 3. In-Memory Loopback Transport (Deterministic Test & Harness Verification)
// ---------------------------------------------------------------------------
class LoopbackTelcoTransport final : public ITelcoPacketTransport {
public:
    LoopbackTelcoTransport() = default;
    ~LoopbackTelcoTransport() override { Close(); }

    bool Open(const std::string& /*target_spec*/) override {
        is_open_ = true;
        return true;
    }

    void Close() override {
        is_open_ = false;
        queue_.clear();
    }

    bool IsOpen() const noexcept override { return is_open_; }
    TelcoTransportBackend GetBackend() const noexcept override { return TelcoTransportBackend::LoopbackMemory; }
    std::string_view GetBackendName() const noexcept override { return "loopback"; }

    ssize_t Transmit(const uint8_t* data, size_t len) override {
        if (!is_open_ || !data || len == 0) return -1;
        if (queue_.size() >= 4096) {
            queue_.pop_front();
        }
        queue_.emplace_back(data, data + len);
        return static_cast<ssize_t>(len);
    }

    ssize_t Receive(uint8_t* buffer, size_t max_len) override {
        if (!is_open_ || !buffer || max_len == 0 || queue_.empty()) return -1;
        auto& front = queue_.front();
        const size_t to_copy = std::min(max_len, front.size());
        std::memcpy(buffer, front.data(), to_copy);
        queue_.pop_front();
        return static_cast<ssize_t>(to_copy);
    }

private:
    bool is_open_{false};
    std::deque<std::vector<uint8_t>> queue_;
};

inline std::unique_ptr<ITelcoPacketTransport> CreateTelcoPacketTransport(const std::string& backend_str) {
    if (backend_str == "dpdk" || backend_str == "dpdk_direct") {
        return std::make_unique<DpdkTelcoTransport>();
    }
    if (backend_str == "loopback" || backend_str == "memory") {
        return std::make_unique<LoopbackTelcoTransport>();
    }
    return std::make_unique<AfPacketTelcoTransport>();
}

} // namespace samurai::telecom
