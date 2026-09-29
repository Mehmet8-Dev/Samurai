# 39 — RFC Benchmark Baseline Runbook (privileged setup + koşu)

> Durum: AKTİF · Oluşturma: 2026-08-19
> Amaç: Samurai'nin throughput/latency tavanını **TRex ile aynı dilde** (RFC 2544 /
> 3511 / 8219) ve **karşılaştırılabilir** biçimde ölçmek için gereken ayrıcalıklı
> ortamı kurup güncel bir baseline üretmek.

Bu belge, [`trex_path.md`](../trex_path.md) ve [`reports/runs/`](../reports/runs/)
altındaki **eski/ortam-kısıtlı** kayıtların yerini alacak taze baseline'ı üretir.
O eski "0 sent / all error" tabloları bir kod hatası değil, **yetkisiz ortam
artefaktıdır** (AF_XDP yok + `sender_fallback_policy=fail` + `noop` TX). Aşağıdaki
adımlar tam da o eksik ayrıcalıkları kurar.

---

## 0. Ön koşul: neden ayrıcalık gerekli

| Yol | Gereken yetenek | Neden |
|-----|-----------------|-------|
| AF_XDP (`samurai_afxdp_worker`) | `CAP_NET_RAW` + `CAP_NET_ADMIN` | XSK soketi + UMEM + NIC kuyruğuna bağlanma |
| Raw socket / L2-L3 TX | `CAP_NET_RAW` | `AF_PACKET` / raw gönderim |
| DPDK (`samurai_dpdk_worker`) | root + `vfio-pci` + hugepages | PMD, cihazı çekirdekten alır |
| Pacing hassasiyeti (`SYS_NICE`) | `CAP_SYS_NICE` | RT önceliği / CPU pinning, jitter için |

Yetkisiz bir dev makinede (bugünkü ortam gibi) bu yolların hiçbiri açılamaz →
sender `XDP_UNAVAILABLE` verir. Baseline **mutlaka** aşağıdaki ortamlardan birinde
alınmalı.

---

## 1. Build (native)

```bash
cmake -S ddos_samurai -B build-native -DCMAKE_BUILD_TYPE=Release
cmake --build build-native -j
# Beklenen hedefler: samurai (CLI), samurai_*_worker (8 daemon)
# AF_XDP için libbpf, DPDK için SAMURAI_WITH_DPDK=1 + libdpdk gerekir.
```

Opsiyonel backend'ler toolchain'e göre koşullu derlenir
([`ddos_samurai/optional/CMakeLists.txt`](../ddos_samurai/optional/CMakeLists.txt)):
`libgpu_packet_cuda.so` (nvcc), `dpdk_pmd_core.so`... yoksa temiz atlanır.

---

## 2. Ayrıcalık kurulumu — 3 seçenekten biri

### Seçenek A — `setcap` (kernel yolu: AF_XDP / raw socket, DPDK'sız)
En hafif; root'suz koşmak için binary'lere yetenek verir.

```bash
sudo setcap cap_net_raw,cap_net_admin,cap_sys_nice+ep build-native/.../samurai_afxdp_worker
sudo setcap cap_net_raw,cap_net_admin+ep            build-native/.../samurai_cpu_worker
# AF_XDP arayüzü/kuyruğu:
export SAMURAI_XDP_INTERFACE=enp2s0     # gerçek NIC (docs/08-config.md)
export SAMURAI_XDP_QUEUE_ID=0
```

### Seçenek B — DPDK (kernel-bypass, en yüksek pps)
Bkz. [`docs/34-dpdk-kurulum-ve-hazirlik-rehberi.md`](34-dpdk-kurulum-ve-hazirlik-rehberi.md).

```bash
# 1) Ortam doğrulama (blocker'ları listeler)
bash tools/check_dpdk_env.sh --report-only
# 2) Hugepages
echo 1024 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
# 3) NIC'i vfio-pci'ye bağla (cihaz koparılır — yönetim NIC'ini SEÇME!)
sudo dpdk-devbind.py --status
sudo dpdk-devbind.py --bind=vfio-pci 0000:3b:00.0
# 4) Build DPDK ile
SAMURAI_WITH_DPDK=1 cmake -S ddos_samurai -B build-native -DCMAKE_BUILD_TYPE=Release && \
  cmake --build build-native -j
```

### Seçenek C — Docker/K8s (izole)
`cap_add: [NET_ADMIN, NET_RAW, SYS_NICE]` ([`docs/11-docker.md`](11-docker.md)).
DPDK için ek olarak `/dev/vfio`, hugepage mount ve `--privileged` (veya `IPC_LOCK`).

---

## 3. Güvenlik / guardrail (ölçümü bloke etmesin)

`target_safety` public IP'leri varsayılan reddeder (RFC1918/loopback/CGNAT dışı).
Baseline'ı **izole bir lab hedefine** karşı koş; gerekiyorsa açıkça izin ver:

```bash
# Tercih: özel/lab IP hedefi (örn. 10.0.0.0/8 üstünde bir sink)
--allow-target 10.0.0.5
# Public hedef ZORUNLUYSA (yalnız yetkili/sözleşmeli ortam):
--allow-public-target
```

> ⚠️ Yalnızca **sahibi olduğun / yazılı izinli** altyapıya karşı çalıştır.
> Bir trafik sink'i (ör. ayrı bir makinede `iperf3 -s`, ya da NIC-to-NIC loopback)
> hedef olarak idealdir.

---

## 4. RFC baseline koşusu

```bash
mkdir -p reports/runs/$(date +%Y-%m)/baseline
OUT=reports/runs/$(date +%Y-%m)/baseline

# Tüm RFC paketi (2544 throughput/latency/loss, 3511 firewall, 8219 IPv6 geçiş)
sudo -E build-native/.../samurai \
  --run-rfc-suite all \
  --rfc-report-out $OUT/rfc_all.html \
  --target 10.0.0.5 --port 80 \
  --allow-target 10.0.0.5 \
  --report-json $OUT/rfc_all.json \
  --report-text $OUT/rfc_all.txt
```

Tekil profil isteniyorsa: `--run-rfc-suite rfc2544` (veya `rfc3511` / `rfc8219`).
İlgili CLI kancaları:
[`cli/args.cpp`](../ddos_samurai/cli/args.cpp) · [`cli/rfc_suite.cpp`](../ddos_samurai/cli/rfc_suite.cpp).

### Doğrulama koşusu (baseline'ın geçerli olduğunu kanıtla)
Baseline'ın **ortam-kısıtlı olmadığını** teyit için run raporunda şunları kontrol et:

| Alan | Beklenen (sağlıklı) | Eski hatalı kayıt |
|------|---------------------|-------------------|
| `sender_paths_used` | `{"XDP": …}` / `{"DPDK": …}` | `{"XDP_UNAVAILABLE": 1}` |
| `runtime_backend` | `native` / hot-path | `legacy` |
| `persistent_tx_backend` | gerçek iface | `noop` |
| `sent_total` | ≈ `attempted_total` | `0` |
| `effective_pps` | > 0 (hedef line-rate) | `0.0` |

---

## 5. TRex ile karşılaştırma

Aynı NIC/hedef üzerinde TRex STL/ASTF ile bir referans koşusu al, sonra RFC 2544
throughput/latency/loss'u **yan yana** koy:

| Metrik | TRex (ref) | Samurai (bu baseline) |
|--------|-----------:|----------------------:|
| Max no-drop rate (pps) | … | … |
| p99 latency (ns) | … | … |
| Loss @ line-rate (%) | … | … |

> Not: RFC 2544 metodolojisi her iki tarafta da aynı olduğundan bu tablo
> "elmayla elma" kıyastır — eski ~27k pps rakamı bu tabloya **girmez** (o,
> yetkisiz/no-op TX'ten geliyordu).

---

## 6. Baseline üretildikten sonra

1. `reports/runs/README.md`'yi yeni baseline yolunu gösterecek şekilde güncelle.
2. [`trex_path.md`](../trex_path.md) SUPERSEDED banner'ında yeni sayılara referans ver.
3. Eski `reports/runs/artifacts/live_run*` dosyalarını `reports/runs/_archive_pre_2026-08/`
   altına taşı (veya sil).
