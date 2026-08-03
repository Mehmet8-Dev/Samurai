# Samurai — Native Mimari Yeniden Yapılandırma Planı (Big Code Task)

> Durum: AKTİF · Hedef sürüm: `3.0.0` · Kod adı önerisi: `Musashi`
> Yön: **tam native (C/C++/CUDA)** — Python sarmalayıcı/orkestrasyon/CLI katmanı
> native'e taşınır; C/C++/CUDA monolitleri ZMQ worker mimarisi etrafında modülerleşir.

---

## 0. Hedef (kullanıcı direktifi)

1. **Bütün sistem C/C++/CUDA native olmalı.** Python "sarmalayıcı" katmanı
   (thin wrapper'lar), orkestratör ve CLI native karşılıklarına dönüşür; saf
   sarmalayıcı `.py` dosyaları kaldırılır.
2. **Legacy kaldırılır** — ama "legacy" kanıtla belirlenir (aşağıya bakın; ilk
   sezgiler yanlıştı).
3. **En önemlisi:** dev C/C++/CUDA monolit dosyaları **ZMQ yapısını kullanacak
   şekilde modüler** hale gelir.

---

## 1. Kritik Ortam Bulgusu — neyi doğrulayabiliyoruz

Bu geliştirme ortamı native kodun **bir kısmını** derleyebiliyor:

| Bileşen | Derlenebilir mi? | Not |
|---------|:---:|-----|
| ZMQ C++ worker daemon'ları (`zmq/daemon/*.cpp`) | ✅ EVET | `libzmq 4.3.5` kuruldu; **8/8 worker `zmq/CMakeLists.txt` ile derleniyor** |
| `cpu_native/`, `pacing_engine` (C) | ✅ EVET | CMake static lib olarak |
| CUDA `.cu` / `.cuh` (`host_api.cuh`, `gpu_packet_cuda_defense.cu`) | ❌ HAYIR | `nvcc` yok, GPU yok |
| DOCA backend (`doca_gpunetio_backend.cpp`) | ❌ HAYIR | DOCA SDK yok |
| DPDK worker native path | ⚠️ Kısmi | `libdpdk` yok; DPDK'sız derleniyor |

**Sonuç:** ZMQ worker katmanı ve CPU C++ tarafı **derleyerek doğrulanabiliyor**.
CUDA/DOCA monolitleri burada derlenemez → onların modülerleştirmesi yapısal
olarak yapılır ama **GPU/CUDA CI'da doğrulanması gerekir**. Büyük yeni C++'ı
derlemeden yazmak yerine strangler-fig yaklaşımı: her adım derlenip commit'lenir.

---

## 2. Legacy Analizi — DÜZELTİLMİŞ (kanıt tabanlı)

⚠️ İlk analiz "setup.py Extension listesinde yok = legacy" sezgisine dayanıyordu;
bu **yanlış**. Modern ZMQ worker'ları eski görünümlü C kütüphanelerini
**runtime'da `dlopen` ediyor**. Kanıtlanan durum:

| Dosya | Statü | Kanıt |
|-------|-------|-------|
| `xdp_sender.c` (4634) | **CANLI** | `zmq/daemon/afxdp_worker.cpp` `xdp_sender.so`'yu dlopen ediyor |
| root `gpu_packet_cuda.cu`+`.hpp` → `libgpu_packet_cuda.so` | **CANLI** | `gpu_worker.cpp:28`, `doca_gpunetio_worker.cpp:321` dlopen ediyor |
| `pacing_engine.c` (2789) + `xdp_core.c` | **CANLI** | resmi setup.py extension'ı |
| `gpu_packet.py` (506) | **CANLI** | `anomaly_packet.py` + 9 test import ediyor |
| `dataplane_core.c` (1479) | **ÖLÜ** | hiçbir build/`#include`/dlopen referansı yok |
| `fast_sender.c` (2497) → `fast_sender.so` | **ÖLÜ (runtime)** | hiçbir worker dlopen etmiyor; sadece Makefile + testler; `FAST_SENDER_AVAILABLE=False` sabit |

**Güvenle silinebilir (kanıtlı):** `dataplane_core.c`, `fast_sender.c` (+ ona bağlı
testler). Diğer "eski görünenler" modern runtime'ın parçası — **silinmez**.

---

## 3. Native Modülerleştirme — ZMQ worker çatısı

### 3.1 Tespit: worker'lar arası masif kod tekrarı
8 worker (`cpu/gpu/afxdp/dpdk/doca/l7/defense/scenario`, 387–1753 satır) aynı
ZMQ/wire/pacing/telemetri primitiflerini **birebir kopyala-yapıştır** taşıyordu
(`SendFrame`, `ReadFixed`, `JsonError`, `PacingFromEnvelope`, `BuildSnapshot`,
`SerializeSnapshot`, `OptionalIntFromWire`, `SendAck`, `JsonDone`, ...).

### 3.2 Yaklaşım
Ortak framework'ü tek yerde topla (`zmq/daemon/worker_common.hpp`), her worker
sadece kendi dataplane mantığını tutsun. `zmq_worker_base.hpp` (MakeHeader/
ReadJobId) + `worker_common.hpp` = paylaşılan ZMQ worker altyapısı.

### 3.3 İlerleme
- ✅ **Increment 1** — 5 birebir-aynı helper `worker_common.hpp`'ye (`ReadFixed`,
  `JsonError`, `PacingFromEnvelope`, `BuildSnapshot`, `SerializeSnapshot`).
  Net −354/+46. 8/8 worker derlendi.
- ✅ **Increment 2** — `SendFrame` (DOCA superset, `send_flags` defaultlu) +
  `OptionalIntFromWire`. Net −219/+50. 8/8 worker derlendi.
- ⏭️ **Sonraki** — `SendAck`/`JsonDone`/`ConfigFromEnvelope` varyantlarını
  birleştir (worker-özgü farkları parametreleştirerek); ortak main/event-loop
  iskeletini `WorkerBase` sınıfına çıkar.

---

## 4. Büyük Monolit Dosyaları — dekompozisyon hedefleri

| Dosya | Satır | Tür | Burada derlenir? | Yaklaşım |
|-------|------:|-----|:---:|----------|
| `gpu_packet_cuda/host_api.cuh` | 7766 | CUDA hdr | ❌ | tx/rx/feature/state API'larına böl; CI'da doğrula |
| `l7_emu_native/engine.cpp` | 4952 | C++ | ⚠️ test edilecek | connection/flow/expectation/metrics alt-motorları |
| `zmq/daemon/doca_gpunetio_worker.cpp` | 1753 | C++ | ✅ | worker_common + doca-özel modüller |
| `gpu_packet_cuda_defense.cu` | 1834 | CUDA | ❌ | kernel ailelerine böl; CI'da doğrula |
| `doca_gpunetio_backend.cpp` | 3144 | DOCA | ❌ | init/rx/tx ayır; DOCA CI |
| `zmq/daemon/gpu_worker.cpp` | 1108 | C++ | ✅ | worker_common + gpu-özel modüller |

**Öncelik:** önce ✅ (burada doğrulanabilir) worker monolitleri, sonra
⚠️/❌ (CI gerektiren) CUDA/DOCA dosyaları.

---

## 5. Python → Native Geçişi (strangler-fig)

Sıra: native karşılık kanıtlanmadan Python yol sökülmez.
1. **Thin sarmalayıcılar** (`zmq/*.py`, 15 satırlık worker giriş noktaları) →
   native worker binary'leri zaten var; Python launcher'lar native supervisor'a devredilir.
2. **Orkestratör** (`orchestrator.py`) → native worker yönetimi (spawn/health/IPC).
3. **CLI** (`cli/`) → native argparse + dispatch (C++ giriş binary'si).
4. Her adımda: native yol çalışır kanıtlanır → Python yol kaldırılır.

> Durum: `cli/` + `orchestrator.py` native'e geçti; `kpi_gate`/`reporting`
> native C++ (`cli/`); `utils.py` native `core/`'a taşındı (`live_metrics.py`
> kaldırıldı). Sıradaki: `control/` ve `licensing/` alt sistemleri native'e.
> ML/VAE (`models/vae`, torch) native önceliği dışında; kaderi ayrı kararlaştırılır.

---

## 6. Doğrulama & Guardrail'ler

- **ZMQ/CPU C++:** her commit `zmq/CMakeLists.txt` ile derlenmeli (8/8 worker).
- **CUDA/DOCA:** GPU'lu CI runner gerekli (`nvcc`, DOCA SDK). Bu ortamda değil.
- Native worker'lar için smoke test (IPC round-trip) eklenmeli.

---

## 7. Yapıldı / Sıradaki

- [x] Ortam doğrulama kapasitesi kuruldu (libzmq → 8/8 worker derleniyor)
- [x] Legacy analizi kanıtla düzeltildi
- [x] Increment 1: worker_common.hpp — 5 paylaşılan helper
- [x] Increment 2: SendFrame + OptionalIntFromWire paylaşıldı
- [x] Native orkestratör (`orchestrator/`) + CLI (`cli/`) → Python `cli/`/`orchestrator.py` kaldırıldı
- [x] `kpi_gate` + `reporting` native C++ olarak yeniden yaratıldı (`cli/`)
- [x] `xdp*.c` → `ddos_samurai/xdp/` altına taşındı
- [x] `utils.py` → native `core/` (log + net_utils + target_safety); `live_metrics.py` (orphan) kaldırıldı
- [x] JSON altyapısı → `core/json.*` (parser+serializer, insertion-order object'ler)
- [~] `control/` alt sistemi → native `samurai_control` (transport: ZMQ)
  - [x] Increment 1 (saf mantık): `shard` + `auth`(RBAC) + `autoscale`(karar makinesi) + `discovery`(manuel); selftest ile doğrulandı
  - [x] Increment 2: `jwt_claims` → `control/jwt.*` (OpenSSL HMAC-SHA256, core JSON); `telemetry` → `control/telemetry.*` (DistributedAggregator, saf rollup); `multimaster` → `control/multimaster.*` (KvStore soyutlaması + in-memory backend; hiredis-Redis ertelendi)
  - [~] Increment 3 (ZMQ transport — **KARAR: ZMQ, gRPC değil**; kod `control/` altında, `zmq/`'ye taşınmaz):
    - [x] 3a: transport çekirdeği — `control_wire` (JSON zarf), `control_auth` (interceptor: secret+JWT+RBAC+allowed-roles), `servicer` (8 RPC + worker registry), `control_server` (ZMQ ROUTER), `control_client` (ZMQ REQ, `Slave`/`Worker`); selftest'te uçtan-uca round-trip + RBAC doğrulandı
    - [ ] 3b: `slave`/`master` orkestrasyon döngüleri (register/heartbeat/shard yaşam döngüsü, dispatch)
    - [ ] 3c: `ha` (leader election/epoch) + `management_api` (HTTP) + RBAC audit zinciri
  - [ ] Parity'de Python `control/*.py` toptan kaldırılır (henüz networked Python modülleri duruyor)
- [ ] `licensing/` katmanı → native C/C++
- [ ] Increment 3: SendAck/JsonDone/ConfigFromEnvelope + WorkerBase event-loop
- [ ] `dataplane_core.c` + `fast_sender.c` (kanıtlı ölü) kaldırma
- [ ] doca/gpu worker .cpp monolit dekompozisyonu (burada doğrulanabilir)
- [ ] CUDA/DOCA monolitleri (CI gerektirir)
