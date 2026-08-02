# Samurai — Mimari Yeniden Yapılandırma Planı (Big Code Task)

> Durum: TASLAK / öneri · Hedef sürüm: `3.0.0` · Kod adı önerisi: `Musashi`
> Kapsam: `ddos_samurai/` çekirdek paketi + build sistemi + test iskeleti
> Bu doküman **uygulanacak işler listesidir**, yapılmış değişikliklerin kaydı değil.

---

## 0. Yönetici Özeti (Teşhis)

Proje AI-driven geliştirme sürecinde **domain sınırları kaybolmuş** bir hâle geldi.
Teknik olarak çalışıyor ama yapısal borç dört ana eksende birikmiş:

1. **Düz (flat) kök namespace** — `ddos_samurai/` altında doğrudan **24 `.py` + 9 `.c/.h`**
   dosya, 8+ farklı domaini karışık şekilde barındırıyor. Paket sınırı yok.
2. **Yarım kalmış "ZMQ-only" migrasyonu** — modern çalışma yolu (ZMQ worker daemon)
   ile legacy dataplane (`fast_sender.c`, `xdp_sender.c`, `dataplane_core.c`) yan yana
   yaşıyor. ~11.000 satır C kodu belirsiz statüde.
3. **Monolit dosyalar** — tek dosyada 2.000–7.766 satır (aşağıda envanter).
4. **Dört ayrı build sistemi** — `setup.py` (36 KB, custom compile hack'leri içeriyor),
   `build.py`, `ddos_samurai/Makefile`, `zmq/CMakeLists.txt`. Hangisinin otorite
   olduğu belirsiz.

**Kanıtlanmış "niyet-artığı" sinyali:** `cli/args.py:54` yorumu
`ddos_samurai.senders` paketine referans veriyor ama **böyle bir paket yok**.
Yani bir refactor bir kez planlanmış, yarıda kalmış. Bu plan onu tamamlıyor.

### Neyin sorun OLMADIĞI (yanlış alarmlar)
Analiz sırasında "duplikasyon gibi görünen ama aslında sağlıklı katmanlama" olan
yerleri de tespit ettik — bunlara dokunmuyoruz:

- `scenario_engine/` (Python facade) + `scenario_engine_native/` (C++ impl):
  `native.py` `_scenario_native`'e köprü kuruyor. Bu **doğru** bir facade/impl ayrımı.
- `zmq/*.py` worker'ları (her biri ~15 satır) → sadece `worker_prototype`/`dispatcher`'a
  delege eden ince giriş noktaları. Gerçek iş `zmq/daemon/*.cpp`'de. Duplikasyon değil.
- `licensing/` ve `cli/` zaten düzgün modülerleştirilmiş (referans alınacak örnekler).

---

## 1. Domain Haritası (Mevcut → Hedef)

Kod tabanı gerçekte **13 domain** barındırıyor. Şu an bunlar kök dizine saçılmış.

| # | Domain | Mevcut konum(lar) | Durum |
|---|--------|-------------------|-------|
| 1 | CLI / giriş | `cli/` | ✅ Sağlıklı, sadece `args.py` (1941) bölünmeli |
| 2 | Kontrol düzlemi (distributed) | `control/` | ✅ Sağlıklı |
| 3 | Çalışma substratı / IPC | `zmq/` (py) + `zmq/daemon/` (cpp) | 🟡 İsimlendirme + konum |
| 4 | Native dataplane (modern) | `cpu_native/`, `gpu_packet_cuda/`, `l4/`, `l7_emu_native/`, `dpdk/` | 🟡 Dağınık, tek çatı yok |
| 5 | Native dataplane (legacy) | kök: `fast_sender.c`, `xdp_sender.c`, `dataplane_core.c`, `xdp_core.c`, `xdp_prog.c`, `pacing_engine.c` | 🔴 Karantina/silme kararı |
| 6 | Scenario engine | `scenario_engine/` + `scenario_engine_native/` | ✅ Katmanlama OK, konum düzeltilecek |
| 7 | L7 (kontrol/emu/native) | `l7/`, `l7_emu/`, `l7_emu_native/` | 🟡 Üç katman, ilişki netleştirilmeli |
| 8 | GPU payload derleyici | `gpu_cuda_payload/` | 🟡 GPU dataplane'den ayrılmalı |
| 9 | Savunma / ML anomaly | `anomaly_packet.py` (1025), `models/vae/` | 🟡 Kök'ten pakete |
| 10 | Raporlama / metrik / telemetri | `reporting.py` (2045), `kpi_gate.py` (1014), `metrics*.py`, `live_metrics.py`, `loss_telemetry.py` | 🔴 Monolit + dağınık |
| 11 | Profiller | `workload_profiles.py`, `benchmark_profiles.py`, `profiles.py`, `profile_names.py` | 🟡 Kök'ten pakete |
| 12 | Lisanslama | `licensing/` | ✅ Sağlıklı |
| 13 | Test/PCAP araçları | `pcap_replay.py`, `gpu_pcap_gen.py`, `stealth.py`, `topology_native.py` | 🟡 `tools/`'a taşınmalı |

---

## 2. Monolit & Ölü Kod Envanteri

### 2.1 Bölünmesi gereken monolitler (>1000 satır)

| Dosya | Satır | Aksiyon |
|-------|------:|---------|
| `gpu_packet_cuda/host_api.cuh` | 7766 | Domain'lere böl (tx / rx / feature / state API'ları ayrı header) |
| `l7_emu_native/engine.cpp` | 4952 | Alt-motorlara böl (connection / flow / expectation / metrics) |
| `xdp_sender.c` | 4634 | → Faz 1 kararı (legacy) |
| `custom_quic_stack/h3_ngtcp2_client.cpp` | 4037 | İzole; QUIC alt-modül sınırı çiz |
| `gpu_packet_cuda/doca_gpunetio_backend.cpp` | 3144 | backend init / rx / tx ayır |
| `pacing_engine.c` | 2789 | → Faz 1 kararı (legacy) |
| `fast_sender.c` | 2497 | → Faz 1 kararı (legacy) |
| `reporting.py` | 2045 | `reporting/` paketi: model / render / export / kpi |
| `cli/args.py` | 1941 | argparse gruplarına göre böl (`args/` alt-paket) |
| `gpu_packet_cuda_defense.cu` | 1834 | kernel ailelerine göre ayır |
| `dataplane_core.c` | 1479 | → Faz 1 kararı (legacy) |
| `control/ha.py`, `control/master.py` | 1167 / 1091 | orta öncelik, davranış korunarak böl |
| `scenario_engine/runtime.py` | 1074 | VU/ramp/serialization ayrı modüller |

### 2.2 Legacy dataplane — KARAR GEREKTİREN

Aşağıdaki dosyalar setup.py'nin **ana `Extension` listesinde değil**; sadece
`build_ext` içindeki custom compile hack'leriyle (setup.py:247–338) derleniyorlar.
Commit geçmişi ("transition to ZMQ-only architecture and remove CPU packet engine
references", `53694d8`) bunların **kaldırılması** yönünde.

| Dosya | Satır | Modern muadili |
|-------|------:|----------------|
| `xdp_sender.c` | 4634 | `zmq/daemon/afxdp_worker.cpp` |
| `pacing_engine.c` | 2789 | `zmq/lib/pacing_engine.*` (şim) |
| `fast_sender.c` | 2497 | `zmq/daemon/cpu_worker.cpp` + `cpu_native/` |
| `dataplane_core.c` | 1479 | `l4/tcp_dataplane_core.cpp` |
| `gpu_packet.py` + `gpu_packet_cuda.cu/.hpp` (kök) | ~1095 | `gpu_packet_cuda/` (dizin) |
| `af_xdp_sender.py` | ~250 | kısmen canlı (GPU RX pipeline) — dikkat |

> ⚠️ **`af_xdp_sender.py` tam ölü değil:** `cli/runtime.py:240` (`run_gpu_rx_pipeline`)
> ve `cli/validation.py:802` hâlâ import ediyor. Silmeden önce bu iki fonksiyon
> modern yola taşınmalı.

**Karar noktası (Faz 1 gate):** Legacy dataplane
(a) tamamen silinecek mi, yoksa (b) `legacy/` altına karantinaya alınıp bir sürüm
deprecation ile mi çıkarılacak? Öneri: **(b) karantina → 1 sürüm sonra sil.**

### 2.3 Build sistemi dağınıklığı

- `setup.py` (36 KB): `Extension` listesi + **custom `build_ext`** (legacy C derlemesi
  ve `nvcc` çağrıları elle gömülü). Bakımı zor.
- `build.py`: ayrı orchestration script.
- `ddos_samurai/Makefile`: legacy C hedefleri.
- `zmq/CMakeLists.txt`: ZMQ daemon C++ derlemesi.

Hedef: **tek otoriteli build** — Python C-extension'ları için `setup.py`'i
sadeleştir (custom hack'leri kaldır), native daemon için **CMake**'i tek otorite yap.

---

## 3. Hedef Mimari

### 3.1 Katman modeli (bağımlılık yönü yukarıdan aşağı)

```
┌─────────────────────────────────────────────┐
│  cli/            (giriş, argparse, dispatch) │
├─────────────────────────────────────────────┤
│  control/        (distributed master/slave)  │
│  orchestration/  (run lifecycle, orchestrator)│
├─────────────────────────────────────────────┤
│  scenario/  ·  l7/  ·  defense/  ·  profiles/ │  (senaryo & trafik modeli)
├─────────────────────────────────────────────┤
│  runtime/        (ZMQ IPC + worker substratı) │
├─────────────────────────────────────────────┤
│  dataplane/      (cpu · gpu · l4 · l7 · dpdk · afxdp — native)│
├─────────────────────────────────────────────┤
│  core/           (metrics · telemetry · wire · utils — paylaşılan)│
└─────────────────────────────────────────────┘
```

**Kural:** Bir katman yalnızca altındaki katmanlara bağımlı olabilir. `core/` hiçbir
üst katmana bağımlı olamaz. Bu kural CI'da `import-linter` ile zorlanır (bkz. Faz 6).

### 3.2 Hedef dizin yapısı

```
ddos_samurai/
  cli/                     # (mevcut, args.py bölünür)
  control/                 # (mevcut) distributed control plane
  orchestration/           # orchestrator.py + run lifecycle
  core/
    metrics/               # metrics.py, live_metrics.py, metrics_schema.py, loss_telemetry.py, kpi_gate.py
    wire/                  # zmq/wire.py protokolü
    utils/                 # utils.py (bölünmüş)
  runtime/                 # (eski zmq/) IPC substratı
    ipc/                   # dispatcher, event_collector, runtime_manager, dpu_state
    workers/               # ince python worker giriş noktaları
    native/                # daemon/*.cpp + zmq_worker_base + wire_protocol.h
  dataplane/
    cpu/                   # cpu_native/
    gpu/                   # gpu_packet_cuda/ (dataplane) 
    gpu_payload/           # gpu_cuda_payload/ (template derleyici — ayrı concern)
    l4/                    # l4/
    l7/                    # l7_emu_native/ (+ custom_quic_stack/)
    dpdk/                  # dpdk/
    afxdp/                 # xdp_core.c, xdp_prog.c (BPF), afxdp glue
  scenario/                # scenario_engine/ + scenario_engine_native/ birleşik
  l7/                      # L7 kontrol düzlemi (l7/ + l7_emu/ facade)
  defense/                 # anomaly_packet.py + models/vae/
  reporting/               # reporting.py (bölünmüş)
  profiles/                # workload_profiles, benchmark_profiles, profiles, profile_names
  licensing/               # (mevcut)
  tools/                   # pcap_replay, gpu_pcap_gen, stealth, topology
  legacy/                  # (geçici) fast_sender, xdp_sender, dataplane_core, pacing_engine
```

---

## 4. Fazlı Yürütme Planı

Her faz **bağımsız derlenebilir + testler yeşil** kalacak şekilde tasarlandı.
Her faz kendi PR'ı. Sıra bağımlılık grafiğine göre; erken fazlar düşük riskli.

### FAZ 0 — Güvenlik ağı & taban çizgisi (1–2 gün) · risk: yok
- [ ] Mevcut testleri (`tests/`, 100 dosya) tam çalıştır, yeşil taban çizgisini kaydet.
- [ ] `pip install import-linter`; mevcut import grafiğini `.importlinter` ile dondur.
- [ ] `pydeps`/`grimp` ile mevcut bağımlılık grafiğini çıkar → `docs/deps-before.svg`.
- [ ] Coverage taban çizgisi al; refactor boyunca düşmeyecek.
- [ ] Public API yüzeyini (dışa `import` edilen semboller) bir teste sabitle
      (regresyon kalkanı).

### FAZ 1 — Legacy dataplane kararı & karantina (2–3 gün) · risk: orta
> **Gate:** §2.2 kararı (sil vs karantina) burada verilir. Öneri: karantina.
- [ ] `af_xdp_sender.py`'deki hâlâ canlı olan `run_gpu_rx_pipeline` +
      `get_interface_queue_count` fonksiyonlarını `dataplane/afxdp/`'ye taşı.
- [ ] `fast_sender.c`, `xdp_sender.c`, `dataplane_core.c`, `pacing_engine.c` (kök),
      kök `gpu_packet*` dosyalarını `legacy/`'ye taşı.
- [ ] `setup.py`'deki custom `build_ext` legacy compile hack'lerini (satır 247–338)
      kaldır; `legacy/` opsiyonel `SAMURAI_BUILD_LEGACY=1` bayrağı arkasına al.
- [ ] Legacy'e bağlı testleri (`test_fast_sender*.py`) `SAMURAI_BUILD_LEGACY`
      olmadan skip edilecek şekilde işaretle.
- [ ] `CHANGELOG.md` + README'de deprecation notu.

### FAZ 2 — `core/` paketini oluştur (2–3 gün) · risk: düşük
> Önce çekirdek çünkü diğer her şey buna bağlanacak.
- [ ] `core/metrics/` oluştur; `metrics.py`, `live_metrics.py`, `metrics_schema.py`,
      `loss_telemetry.py`, `kpi_gate.py` taşı.
- [ ] `core/wire/` = `zmq/wire.py`.
- [ ] `core/utils/` = `utils.py` (702 satır → alt-modüllere böl: net / time / logging / fs).
- [ ] Geriye dönük uyumluluk için kök seviyede **shim** modüller bırak
      (`utils.py` → `from .core.utils import *` + `DeprecationWarning`).
- [ ] Import'ları güncelle; testler yeşil.

### FAZ 3 — `runtime/` (ZMQ substratı) yeniden konumlandırma (3–4 gün) · risk: orta
- [ ] `zmq/` → `runtime/` yeniden adlandır (isim `zmq` protokolle karışıyor).
      `runtime/ipc/`, `runtime/workers/`, `runtime/native/` alt yapısını kur.
- [ ] `zmq/daemon/*.cpp` → `runtime/native/`; `CMakeLists.txt` yollarını güncelle.
- [ ] `orchestrator.py` → `orchestration/`; `start_worker_zmq` API'sini koru
      (`cli/runtime.py:501`, `cli/offline_modes.py:218` bağımlı).
- [ ] `zmq` → `runtime` shim'i geçici bırak.

### FAZ 4 — `dataplane/` çatısı (4–5 gün) · risk: orta
- [ ] `cpu_native/`, `gpu_packet_cuda/`, `l4/`, `l7_emu_native/`, `dpdk/`,
      `afxdp` glue'yu `dataplane/` altına taşı.
- [ ] `gpu_cuda_payload/`'u `dataplane/gpu_payload/` olarak ayrı tut (bu bir
      template derleyici, dataplane tx yolu değil — concern ayrımı).
- [ ] `setup.py` `Extension` `sources` yollarını + `zmq/CMakeLists.txt`'i güncelle.
- [ ] Monolit bölme (bu faz içinde, davranış koruyarak):
      `host_api.cuh` (7766), `l7_emu_native/engine.cpp` (4952),
      `doca_gpunetio_backend.cpp` (3144), `gpu_packet_cuda_defense.cu` (1834).

### FAZ 5 — Uygulama katmanı domainleri (3–4 gün) · risk: düşük
- [ ] `scenario_engine/` + `scenario_engine_native/` → `scenario/`.
- [ ] `l7/` + `l7_emu/` → `l7/` (kontrol düzlemi + emu facade netleştir; native artık
      `dataplane/l7/`'de). Üç katmanın rolünü `l7/README.md`'de belgele.
- [ ] `anomaly_packet.py` + `models/vae/` → `defense/`.
- [ ] `workload_profiles.py`, `benchmark_profiles.py`, `profiles.py`,
      `profile_names.py` → `profiles/`.
- [ ] `pcap_replay.py`, `gpu_pcap_gen.py`, `stealth.py`, `topology_native.py`
      → `tools/`.
- [ ] `reporting.py` (2045) → `reporting/` paketi: `model.py` / `render.py` /
      `export.py` / `kpi.py`.
- [ ] `cli/args.py` (1941) → `cli/args/` alt-paketi (argparse grup başına dosya).

### FAZ 6 — Guardrail'ler & temizlik (2–3 gün) · risk: yok
- [ ] `.importlinter` sözleşmelerini §3.1 katman kurallarına göre yaz; CI'a ekle.
      (örn: `core` → hiçbir üst katmana bağımlı olamaz; `dataplane` → `cli` import edemez.)
- [ ] `mypy.ini`'yi yeni paket sınırlarına göre sıkılaştır (paket bazında strict).
- [ ] Faz 2–3–5'te bırakılan tüm shim modüllerini kaldır (deprecation süresi doldu).
- [ ] Tek build otoritesi: `setup.py` (Python ext) + `CMake` (daemon). `build.py` ve
      `ddos_samurai/Makefile`'ı ya bunlara delege et ya da sil.
- [ ] `docs/deps-after.svg` üret; before/after karşılaştırmasını dokümante et.
- [ ] `.pytest_artifacts/`, `artifacts/` gibi commit'lenmemesi gereken çıktıları
      `.gitignore`'a al (repoda 356 KB artık var).

### FAZ 7 — Legacy silme (opsiyonel, 1 sürüm sonra) · risk: düşük
- [ ] `3.0.0` yayınlandıktan sonra `legacy/` dizinini ve `SAMURAI_BUILD_LEGACY`
      yolunu tamamen sil.

---

## 5. Sıralama & Bağımlılıklar

```
FAZ 0 (taban)
   └─> FAZ 1 (legacy karantina)  ─┐
   └─> FAZ 2 (core)              ─┤
                                  ├─> FAZ 3 (runtime) ─> FAZ 4 (dataplane) ─┐
                                  │                                          ├─> FAZ 6 (guardrail)
                                  └─────────────────> FAZ 5 (app domains) ──┘
                                                                             └─> FAZ 7 (sil)
```

- FAZ 2 (core) diğer her şeyin ön koşulu — önce yapılmalı.
- FAZ 4, FAZ 3'e bağımlı (runtime → dataplane yolu).
- FAZ 5, FAZ 2'ye bağımlı ama FAZ 3/4'ten bağımsız — paralel yürütülebilir.

---

## 6. Riskler & Azaltma

| Risk | Etki | Azaltma |
|------|------|---------|
| Native build yolları (setup.py/CMake) kırılır | Yüksek | Her faz sonunda `build_ext --inplace` + daemon CMake build CI'da zorunlu |
| Gizli import bağımlılıkları (dynamic import) | Orta | FAZ 0 public-API test kalkanı + shim'ler |
| `af_xdp_sender` gibi "yarı canlı" legacy | Orta | Silmeden önce canlı fonksiyonları taşı (§2.2 notu) |
| Büyük dosya bölme davranışı değiştirir | Orta | Bölme = saf taşıma; mantık değişikliği ayrı commit; testler her adımda |
| Refactor sürerken yeni feature çakışması | Düşük | Faz başına kısa ömürlü branch, hızlı merge |

---

## 7. Başarı Kriterleri (Tanım: "Bitti")

- [ ] Kök `ddos_samurai/` altında **doğrudan** `.py` dosyası yok (sadece `__init__.py`).
- [ ] Hiçbir kaynak dosya **1500 satırı** geçmiyor (native header istisnaları belgelenir).
- [ ] `import-linter` katman sözleşmeleri CI'da yeşil.
- [ ] Tek build komutu native + Python her şeyi kurabiliyor.
- [ ] Test coverage FAZ 0 taban çizgisinden düşük değil.
- [ ] `ddos_samurai.senders` gibi dangling referans kalmadı.
- [ ] Legacy dataplane karantinada (veya silinmiş), ana build'de değil.

---

## Ek A — Hızlı Kazanımlar (herhangi bir faz beklemeden)

Düşük riskli, bağımsız yapılabilecek temizlikler:
- `.pytest_artifacts/` ve `artifacts/`'ı `.gitignore`'a al, git'ten çıkar.
- `l4_state_engine.py` (116 satır shim) → gerçekten kullanılıyor mu, `l4/`'e taşı.
- `cli/args.py:54`'teki `ddos_samurai.senders` dangling yorumunu düzelt.
- `zmq/lib/pacing_engine.c` (88 satır şim) ile kök `pacing_engine.c` (2789)
  ilişkisini `README` ile netleştir.
