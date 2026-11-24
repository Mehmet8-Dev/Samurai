# Konfigürasyon Mimarisi ve Performans Mühendisliği Tuning Rehberi

Bu doküman, DDoSamurai'nin **3 katmanlı konfigürasyon mimarisini**, hangi parametrelerin CLI bayrağı (`--flag`), hangilerinin konfigürasyon dosyası (`samurai.conf`) ve hangilerinin ortam değişkeni (`SAMURAI_*`) üzerinden yönetilmesi gerektiğini, ayrıca yüksek PPS / düşük P99 gecikme için çekirdek ve dataplane ayarlarını açıklar.

---

## 1. 3 Katmanlı Konfigürasyon Öncelik Sırası (Precedence)

DDoSamurai ayarları şu öncelik sırasıyla çözümlenir (**en yüksek -> en düşük**):

1. **CLI Bayrakları (`--iface`, `--transport`, `--dpdk-port`, `--dpdk-queue`, `--log-level`, `--config`)**
   * Çalıştırma anında (per-run) verilen parametreler her şeyi ezer.
2. **Ortam Değişkenleri (`SAMURAI_*`)**
   * Normal kullanıcıların kabukta (`export SAMURAI_LOG_LEVEL=debug`), Docker konteynerlerinde (`-e SAMURAI_CLUSTER_SECRET=...`) veya CI/CD ortamlarında ayarladığı değişkenler `samurai.conf` dosyasını ezer.
   * **Neden env var desteği tamamen silinmedi?** Konfigürasyon dosyası `setenv(..., overwrite=0)` ile yüklenir; yani kullanıcının ortamında zaten tanımlı bir `SAMURAI_*` varsa korunur. Böylece konteyner/systemd/CI akışları bozulmazken normal CLI kullanımında env var ezberleme zorunluluğu ortadan kalkar.
3. **Konfigürasyon Dosyası (`samurai.conf`)**
   * Arama sırası: `--config PATH` → `$SAMURAI_CONFIG` → `./samurai.conf` → `~/.config/samurai/samurai.conf` → `/etc/samurai/samurai.conf`.
   * Örnek şablon: [config/samurai.conf.example](file:///home/mehmet/Masaüstü/Python/v11/DDoSamurai/config/samurai.conf.example).
4. **Derlenmiş Varsayılanlar (Compiled Defaults)**

---

## 2. Neyin Nerede Olması Gerektiği (Karar Matrisi)

| Kategori | Örnekler | Nerede Olmalı? | Gerekçe |
| :--- | :--- | :--- | :--- |
| **Çalıştırma / Hedef / Arayüz** | `--worker`, `--target`, `--iface`, `--transport`, `--dpdk-port`, `--dpdk-queue`, `--pin-cpu` | **CLI `--flag`** | Her testte değişen operasyonel parametreler; tekrar üretilebilir komut satırı geçmişi sağlar. |
| **Donanım & Kernel Dataplane Tuning** | `block_size_kb`, `frames_per_block`, `mlock_ring`, `qdisc_bypass`, `hugepage_mode`, `eal_args`, `initial_rto_ms`, `task_slots` | **`samurai.conf`** | Makineye/NIC'e/NUMA topolojisine bağlıdır; her komutta tekrar yazılmaz, bir kez kalibre edilir. |
| **Ortam / Gizli Bilgi / Konteyner Override** | `SAMURAI_CLUSTER_SECRET`, `SAMURAI_CURVE_SERVER_SECRET`, `SAMURAI_LOG_LEVEL`, `SAMURAI_CONFIG` | **Env Var (opsiyonel override)** | Secret'ların repoya/komut geçmişine (`ps aux`) düşmemesi ve container/systemd uyumluluğu için. |

---

## 3. Performans Mühendisliği Tuning Rehberi

### A. AF_PACKET TX_RING (Commodity NIC — Root / `CAP_NET_RAW`)
Kernel bypass olmayan ortamlarda en yüksek PPS ve en düşük CPU overhead'i için `[af_packet]` bölümünü NIC'in Halka/NUMA kapasitesine göre ayarlayın:

* **`mlock_ring = 1` & `prefault_ring = 1`**: Ring tamponunu RAM'e kilitler (`mlock`) ve trafik başlamadan tüm sayfaları dokunarak (`prefault`) sıcak döngüde **minor page fault** kaynaklı P99/P99.9 jitter sıçramalarını önler.
* **`qdisc_bypass = 1`**: `PACKET_QDISC_BYPASS` ile kernel `tc`/`fq_codel` kuyruğunu atlar ve paketleri doğrudan NIC sürücü halkasına yazar.
* **`block_size_kb = 1024`, `frames_per_block = 256`, `ring_target_mb = 64`**: `block_size_kb` değerini CPU L2/L3 önbellek veya 2 MiB hugepage sınırlarıyla hizalayın. Çok küçük bloklar sık `send()` syscall'ına, aşırı büyük ring ise TLB/cache thrashing'e yol açar.
* **`hugepage_mode = auto` (`2048` KB)**: TLB miss oranını düşürür. Sistemde 2 MiB hugepage ayrılmışsa (`vm.nr_hugepages`) otomatik kullanır.
* **`busy_poll_us = 50`, `txring_flush_mode = adaptive`**: Düşük gecikme için kısa busy-poll, yüksek throughput için adaptif batch flush.

**Önerilen Linux Sysctl Ayarları (Test Host):**
```bash
sudo sysctl -w net.core.rmem_max=67108864 net.core.wmem_max=67108864
sudo sysctl -w net.core.netdev_max_backlog=250000
sudo sysctl -w vm.nr_hugepages=512
```

### B. DPDK & NUMA Pinning (Line-Rate / Carrier Telco)
* **`--pin-cpu N` ve `[dpdk] base_core`, `eal_args`**: NIC'in bağlı olduğu PCIe root complex ile **aynı NUMA node** üzerindeki izole çekirdekleri (`isolcpus`, `nohz_full`, `rcu_nocbs`) kullanın. Cross-NUMA DMA trafiği QPI/UPI veri yolunu doyurur ve gecikmeyi 2–3x artırır.
* **`--dpdk-port` ve `--dpdk-queue`**: Çoklu worker çalıştırırken her worker'a ayrı TX queue atayın (`--dpdk-queue 0`, `--dpdk-queue 1`), böylece lock contention sıfırlanır.

### C. Pacing & Zamanlama (`[pacing]`)
* **`use_tsc = 1`**: `clock_gettime(CLOCK_MONOTONIC)` syscall/vDSO maliyetini ortadan kaldırıp donanım `RDTSC` sayacıyla nanosaniye çözünürlüklü hız sınırlama sağlar.
* **Not**: Sanal makinelerde `constant_tsc` ve `nonstop_tsc` CPU bayraklarını doğrulayın (`/proc/cpuinfo`).

### D. Custom Userspace TCP (`[custom_tcp]`)
* **`mode = auto | custom_tcp | kernel_socket | dpdk`**: L7 senaryolarında kernel `conntrack` ve `TIME_WAIT` sınırlarına takılmamak için `custom_tcp` kullanın.
* **`initial_rto_ms = 250`, `max_retransmits = 3`**: Agresif stres testlerinde ölü soketlerin belleği şişirmesini önlemek için RTO ve retry sayısını düşük tutun.
* **`busy_poll = 1`**: Event loop'un `epoll_wait` uyku gecikmesini ortadan kaldırır (100% çekirdek kullanımı karşılığında mikrosaniye seviyesi P99).

### E. GPU BAR1 P2P & BlueField DOCA (`[gpu_p2p]`, `[doca]`)
* **`gpu_bdf` / `nic_bdf`**: GPU ve NIC'in **aynı PCIe switch** altında (ideal olarak PLX/PCIe Gen4+ switch, CPU root complex üzerinden geçmeden) olduğundan `nvidia-smi topo -m` ile emin olun.
* **`doca.task_slots = 4096`**: Yüksek bant genişlikli akışlarda DOCA GPUNetIO kuyruğunun aç kalmasını önler.

---

## 4. Örnek Kullanım

```bash
# 1. Config dosyasını kopyalayıp makineye göre düzenleyin:
mkdir -p ~/.config/samurai
cp config/samurai.conf.example ~/.config/samurai/samurai.conf

# 2. Telco SCTP testi (artık env var gerekmez; CLI bayrakları doğrudan geçer):
sudo ./build/cli/samurai \
  --worker telco \
  --profile telco-sctp-flood \
  --iface eth0 \
  --transport af_packet \
  --target 10.0.0.10 \
  --telco-subscribers 500 \
  --telco-cps 200 \
  --telco-duration-ms 5000 \
  --confirm

# 3. Özel config ile DPDK çalıştırma:
sudo ./build/cli/samurai \
  --config /etc/samurai/prod-dpdk.conf \
  --worker telco \
  --profile telco-sctp-flood \
  --iface 0 \
  --transport dpdk \
  --dpdk-port 0 \
  --pin-cpu 4 \
  --target 10.0.0.10 \
  --confirm

# 4. Dağıtık Master/Slave + Scenario JSON + Mahoraga RL² çalıştırma:
./build/control/daemon/samurai_master \
  --worker scenario \
  --l7-profile-file my-api-scenario.json \
  --target 127.0.0.1 --port 8080 --count 5000 \
  --closed-loop --cl-strategy rl --rl-policy mahoraga-rl2.srlp
```

---

## 5. Mahoraga RL Ağırlıkları, Dağıtık Senaryo ve MCP Eşitlemesi

* **Paketli `.srlp` Politikaları:** Kanonik Mahoraga ağırlıkları (`artifacts/rl/mahoraga-*.srlp` ve Docker imajında `/usr/local/share/samurai/rl/`) otomatik çözümlenir (`ResolveRlPolicyPath`: önce verilen yol, sonra `$SAMURAI_RL_POLICY_DIR`, `./artifacts/rl/`, ikili dizini göreli `artifacts/rl/` ve `/usr/local/share/samurai/rl/`).
* **Dağıtık Scenario JSON Aktarımı:** `samurai_master` (`--l7-profile-file` / `--l7-profile-json`) ve MCP `samurai_cluster_run_job` (`scenario` / `scenario_file`) senaryo JSON içeriğini doğrudan ZMQ shard argümanlarıyla `samurai_slave` düğümlerine taşır; slave kendi geçici dosyasını oluşturup `samurai_scenario_worker`'a verir ve shard bitince temizler.
* **MCP Araç Eşitlemesi:** `samurai_run_benchmark`, `samurai_scenario_run`, `samurai_autopilot_run_window` ve `samurai_cluster_run_job` artık `iface`, `transport`, `config`, `dpdk_port`, `dpdk_queue`, `scenario` ve `host.docker.internal` IPv4 çözümlemesini doğrudan destekler.

