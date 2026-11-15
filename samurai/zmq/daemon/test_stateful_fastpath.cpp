// StatefulFastpathDriver in-process doğrulaması (NIC gerektirmez).
//
// LoopbackPeerShim, tcpdp'nin ürettiği çerçeveleri ayrıştırıp geçerli bir TCP
// akranı gibi yanıt üretir: SYN -> SYN-ACK. Böylece paylaşılan sürücü loop'u
// (RX->ingest -> poll -> peek->Send->consume) gerçek TcpDataplaneCore'a karşı
// uçtan uca sürülür ve 3'lü el sıkışmanın tamamlandığı (connect_established)
// doğrulanır. DPDK/AF_XDP shim'leri aynı arayüzü paylaştığı için bu test o ortak
// yolu kanıtlar.

#include <arpa/inet.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <vector>

#include "stateful_fastpath.hpp"

namespace {

void WriteBe16(std::uint8_t* p, std::uint16_t v) {
  p[0] = static_cast<std::uint8_t>(v >> 8);
  p[1] = static_cast<std::uint8_t>(v & 0xFF);
}
void WriteBe32(std::uint8_t* p, std::uint32_t v) {
  p[0] = static_cast<std::uint8_t>((v >> 24) & 0xFF);
  p[1] = static_cast<std::uint8_t>((v >> 16) & 0xFF);
  p[2] = static_cast<std::uint8_t>((v >> 8) & 0xFF);
  p[3] = static_cast<std::uint8_t>(v & 0xFF);
}
std::uint16_t ReadBe16(const std::uint8_t* p) {
  return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}
std::uint32_t ReadBe32(const std::uint8_t* p) {
  return (static_cast<std::uint32_t>(p[0]) << 24) |
         (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) |
         static_cast<std::uint32_t>(p[3]);
}

constexpr std::uint8_t kSyn = 0x02;
constexpr std::uint8_t kAck = 0x10;

// tcpdp BuildPacket düzeni: 14 L2 + 20 IPv4 + 20 TCP. Ethertype [12,13]=0x0800.
// IP src [26:30] dst [30:34] (ip_off 14 + 12/16). TCP src_port [34:36] dst_port
// [36:38] seq [38:42] ack [42:46] dataoff [46] flags [47] window [48:50].
struct LoopbackPeerShim : samurai::daemon::FastpathTxRxShim {
  std::deque<std::vector<std::uint8_t>> rx_queue;
  std::uint32_t peer_iss = 0x51000000u;

  int Send(const std::uint8_t* base, std::size_t psize, std::size_t stride,
           std::uint32_t count, std::string& err) override {
    (void)err;
    for (std::uint32_t i = 0; i < count; ++i) {
      const std::uint8_t* pkt = base + static_cast<std::size_t>(i) * stride;
      if (psize < 54) continue;
      if (ReadBe16(pkt + 12) != 0x0800) continue;
      if (pkt[23] != 6) continue;  // IP proto = TCP
      const std::uint8_t flags = pkt[47];
      // Yalnız SYN (SYN-ACK değil) gelen ilk pakete yanıt üret.
      if ((flags & kSyn) == 0 || (flags & kAck) != 0) continue;

      const std::uint32_t src_ip = ReadBe32(pkt + 26);
      const std::uint32_t dst_ip = ReadBe32(pkt + 30);
      const std::uint16_t src_port = ReadBe16(pkt + 34);
      const std::uint16_t dst_port = ReadBe16(pkt + 36);
      const std::uint32_t syn_seq = ReadBe32(pkt + 38);

      // SYN-ACK: tuple'ı ters çevir; ingest {dst,src,dport,sport} ile flow'a maplar.
      std::vector<std::uint8_t> resp(54, 0);
      WriteBe16(resp.data() + 12, 0x0800);
      resp[14] = 0x45;
      WriteBe16(resp.data() + 16, 40);  // IP total_len
      resp[22] = 64;                    // TTL
      resp[23] = 6;                     // proto TCP
      WriteBe32(resp.data() + 26, dst_ip);   // src = eski dst (target)
      WriteBe32(resp.data() + 30, src_ip);   // dst = eski src (biz)
      WriteBe16(resp.data() + 34, dst_port); // src_port = target port
      WriteBe16(resp.data() + 36, src_port); // dst_port = ephemeral
      WriteBe32(resp.data() + 38, ++peer_iss);
      WriteBe32(resp.data() + 42, syn_seq + 1);  // ack = SYN.seq + 1
      resp[46] = 0x50;                           // data offset
      resp[47] = static_cast<std::uint8_t>(kSyn | kAck);
      WriteBe16(resp.data() + 48, 65535);        // window
      rx_queue.push_back(std::move(resp));
    }
    return static_cast<int>(count);
  }

  int Recv(std::uint8_t* out, std::uint16_t stride, std::uint16_t* lens,
           std::uint16_t max, std::string& err) override {
    (void)err;
    int n = 0;
    while (n < static_cast<int>(max) && !rx_queue.empty()) {
      const auto& f = rx_queue.front();
      std::memcpy(out + static_cast<std::size_t>(n) * stride, f.data(), f.size());
      lens[n] = static_cast<std::uint16_t>(f.size());
      rx_queue.pop_front();
      ++n;
    }
    return n;
  }

  bool RxAvailable() const override { return true; }
};

std::uint32_t Ipv4(const char* s) {
  in_addr a{};
  inet_pton(AF_INET, s, &a);
  return ntohl(a.s_addr);
}

}  // namespace

int main() {
  LoopbackPeerShim shim;
  samurai::daemon::StatefulFastpathDriver driver(shim);

  samurai::daemon::FastpathParams p;
  p.dst_ip = Ipv4("10.0.0.3");
  p.dst_port = 80;
  p.src_ip = Ipv4("10.0.0.2");
  p.target_flows = 8;
  p.backend = "custom_tcp";
  p.max_duration_ms = 3000;
  p.drain_ms = 100;

  std::string err;
  if (!driver.Configure(p, err)) {
    std::fprintf(stderr, "FAIL: Configure: %s\n", err.c_str());
    return 1;
  }
  const std::uint32_t seeded = driver.SeedL4(p);
  if (seeded != p.target_flows) {
    std::fprintf(stderr, "FAIL: SeedL4 enqueued %u, expected %u\n", seeded, p.target_flows);
    return 1;
  }

  std::atomic<bool> stop{false};
  samurai::daemon::FastpathHooks hooks;  // emit'siz; sadece loop sürülüyor
  const samurai::daemon::FastpathResult res = driver.Run(p, {}, stop, hooks);

  std::printf(
      "connect_attempts=%llu connect_established=%llu tx_packets=%llu "
      "rx_frames=%llu retransmit_exhausted=%llu connect_timeout=%llu\n",
      static_cast<unsigned long long>(res.connect_attempts),
      static_cast<unsigned long long>(res.connect_established),
      static_cast<unsigned long long>(res.tx_packets),
      static_cast<unsigned long long>(res.rx_frames),
      static_cast<unsigned long long>(res.retransmit_exhausted),
      static_cast<unsigned long long>(res.connect_timeout));

  if (res.connect_established < p.target_flows) {
    std::fprintf(stderr, "FAIL: established %llu < target %u\n",
                 static_cast<unsigned long long>(res.connect_established), p.target_flows);
    return 1;
  }
  if (res.retransmit_exhausted != 0 || res.connect_timeout != 0) {
    std::fprintf(stderr, "FAIL: retransmit_exhausted=%llu connect_timeout=%llu (beklenen 0)\n",
                 static_cast<unsigned long long>(res.retransmit_exhausted),
                 static_cast<unsigned long long>(res.connect_timeout));
    return 1;
  }
  std::printf("ALL STATEFUL FASTPATH DRIVER TESTS PASSED\n");
  return 0;
}
