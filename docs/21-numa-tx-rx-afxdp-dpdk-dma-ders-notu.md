# 21 - NUMA, TX/RX Olcekleme, AF_XDP/DPDK, DMA (Proje Uzerinden Ders Notu)

Bu not, "kavram -> projedeki karsiligi -> uygulama" formatinda hazirlandi.
Amac: DDoSamurai'de performans mimarisini teknik olarak okuyabilmen, olcebilmen ve adim adim iyilestirebilmen.

---

## 0) Baslangic: Bu projede su an ne var?

Bu repoda:

- CPU native packet engine var: `ddos_samurai/cpu_packet_engine.py` + `ddos_samurai/_cpu_packet_engine_native`
- AF_XDP yolu var: `ddos_samurai/af_xdp_sender.py` + `ddos_samurai/xdp_sender.c`
- TX_RING / fast sender yolu var: `ddos_samurai/fast_sender.c`
- Dataplane config katmani var: `ddos_samurai/dataplane.py`
- Worker/queue/affinity dispatch'i orchestrator tarafinda: `ddos_samurai/orchestrator.py`
- DPDK runtime backend su an dogrudan entegre degil (belgelerde "gelecek/opsiyonel" konumda).

Ozet:
- "AF_XDP + TX_RING + native CPU engine" bugun aktif performans alanin.
- DPDK bugun "tasarlanabilir bir sonraki backend" olarak dusunulmeli.

---

## 1) Zihin modeli: Paket nasil gider?

Basit zincir:

1. Uretim (packet build): CPU native engine veya GPU tarafi
2. Kuyruklama (batch/ring): worker queue + backend queue
3. Gonderim (TX path): Python socket / C fast_sender / AF_XDP
4. NIC DMA: paket host memory'den NIC'e tasinir
5. Hat (wire): fiziksel cikis

Onemli nokta:
- Yuksek PPS sistemlerinde "hesaplama"dan cok "memory hareketi + queue uyumu + core pinning" belirleyici olur.

---

## 2) NUMA nedir ve neden kritik?

NUMA (Non-Uniform Memory Access): her CPU soketinin "yakina" bagli memory'si var.

- Local memory: dusuk latency, yuksek bant genisligi
- Remote memory: daha yavas, daha cok jitter

Network dataplane acisindan:
- Worker CPU bir NUMA node'da, NIC diger NUMA node'da ise throughput duser, jitter artar.

### Projedeki karsiligi

- Queue/affinity metadata orchestrator'da tasiniyor:
  - `dp_queue_id`
  - `dp_queue_strategy`
  - `dp_affinity_cpu`
- Dataplane secimleri:
  - `--dp-queue-strategy`
  - `--dp-queues`
  - `--dp-queue-map`
- CPU pinning:
  - `--pin-cpu` (pacing engine pinning)
  - orchestrator tarafinda worker affinity ayari

### Pratik prensip

- "Ayni worker core -> ayni NIC queue -> ayni NUMA node" hedeflenir.

---

## 3) TX/RX olcekleme nedir?

TX/RX olcekleme = tek queue yerine cok queue + cok core ile line-rate'e yakin davranmak.

Temel fikir:

- 1 queue / 1 core: basit ama sinirli
- N queue / N core: daha yuksek throughput ve daha iyi latency dagilimi

Kotu tasarim:
- 8 worker, 1 queue: lock contention, burst collapse
- queue map belirsiz: run-to-run degisen sonuclar (determinism kaybi)

### Projedeki karsiligi

- `--dp-queue-strategy rr|pin|map`
- `--dp-queues N`
- `--dp-queue-map "1:0,2:1,3:2,..."`
- `--xdp-queue-id` (tek queue senaryolari icin)

### Onerilen stratejiler

1. Baslangic: `rr`
2. Deterministik lab: `map`
3. Fixed topoloji: `pin`

---

## 4) Ring/Pool yerlesimi neden performansi belirler?

Yuksek hizda en pahali islerden biri:
- packet allocation/free
- kucuk-kucuk kopya islemleri

Bu yuzden:
- pre-allocated pool
- contiguous buffer
- uygun batch size
- backpressure kontrollu ring

Projedeki karsiliklar:
- native packet pool API (`generate_packet_pool`, `generate_packet_pool_owner`)
- orchestrator ring/backpressure metrikleri (`gpu_ring_depth_peak`, `gpu_ring_block_wait_ns`)
- TX_RING tuning parametreleri:
  - `--afpacket-ring-target-mb`
  - `--afpacket-block-size-kb`
  - `--afpacket-frame-size`
  - `--afpacket-frames-per-block`
  - `--afpacket-poll-timeout-ms`
  - `--afpacket-spin-limit`

---

## 5) DMA nasil dusunulmeli?

DMA = CPU her byte'i tek tek tasimadan NIC'in memory transfer yapmasi.

Gercek dunya etkisi:
- CPU cycle'lari packet copy yerine scheduling/pacing'e kalir.

Ama:
- "DMA var" tek basina yeterli degil.
- Buffer yerlesimi, queue dogrulugu, cache uyumu, zero-copy seviyesi daha belirleyicidir.

AF_XDP native mod ve TX_RING iyilestirmeleri bu noktada fark yaratir.

---

## 6) AF_XDP bu projede nasil konumlanir?

`af_xdp_sender.py` tarafinda:
- mode 0: SKB (en uyumlu)
- mode 1: Native (daha iyi performans potansiyeli)
- mode 2: Offload talebi (donanim bagimli)

Ayrica:
- capability probe var
- extension yoksa controlled fallback var

Bu, "tek bir ideal yol" yerine "ortama gore adaptif dataplane" tasarimi demek.

---

## 7) DPDK nereye oturur? (Mevcut + yol haritasi)

Mevcut durumda DPDK backend yok. Dogru yaklasim:

1. Su anki AF_XDP/TX_RING yolunu olgunlastir
2. Telemetry + deterministic benchmark disiplini kur
3. Sonra DPDK'yi yeni backend olarak ekle

DPDK eklenecekse mimari onerisi:

- Yeni backend secenegi: `--sender-backend dpdk` (veya `dataplane_core` altinda adapter)
- Ortak sender contract:
  - `send_buffer(packet_buffer, packet_size, count)`
  - `get_stats()`
  - `close()`
- Orchestrator ve rapor semasi degismeden kalmali (yalniz backend adlari artmali)

Hedef:
- DPDK eklense bile "ustteki kontrol duzlemi" ayni kalir.

---

## 8) Proje uzerinden adim adim calisma plani (ders + pekistirme)

## Asama A - Topolojiyi okuyup anlamak

Hedef: queue/core eslesmesini gormek.

Komut:

```bash
python3 -m ddos_samurai.cli \
  --target 127.0.0.1 --port 80 --protocol tcp \
  --count 10000 --workers 4 \
  --dp-queue-strategy rr --dp-queues 2 \
  --run-report --run-report-format both
```

Bakilacak alanlar (run report / worker stats):
- `dp_queue_id`
- `dp_queue_strategy`
- `dp_affinity_cpu`
- `sender_path`

Pekistirme sorusu:
- 4 worker + 2 queue neden bazen stabil, bazen jitter uretir?

## Asama B - Map ile deterministik queue dagitimi

```bash
python3 -m ddos_samurai.cli \
  --target 127.0.0.1 --port 80 --protocol tcp \
  --count 20000 --workers 4 \
  --dp-queue-strategy map \
  --dp-queues 4 \
  --dp-queue-map "1:0,2:1,3:2,4:3" \
  --run-report --run-report-format both
```

Kontrol:
- Her worker hep ayni queue'ya mi gidiyor?
- `fallback_count` sifira yakin mi?

## Asama C - TX_RING tuning

```bash
python3 -m ddos_samurai.cli \
  --target 127.0.0.1 --port 80 --protocol tcp \
  --sender-backend txring \
  --afpacket-ring-target-mb 128 \
  --afpacket-frames-per-block 128 \
  --afpacket-spin-limit 4000 \
  --count 50000 --workers 4 \
  --run-report --run-report-format both
```

Bak:
- `txring_tp_drops`
- `txring_flush_error_count`
- `txring_drop_ratio_pct`

Pekistirme:
- Ring buyuyunce neden her zaman performans artmaz?

## Asama D - AF_XDP mode karsilastirma

Mode 0 (SKB) ile basla, sonra mode 1 (native) dene.

```bash
python3 -m ddos_samurai.cli \
  --target <hedef_ip> --port 80 --protocol tcp \
  --xdp-enable --xdp-interface <iface> --xdp-mode 0 \
  --workers 4 --count 50000 \
  --run-report --run-report-format both
```

Ardindan:

```bash
python3 -m ddos_samurai.cli \
  --target <hedef_ip> --port 80 --protocol tcp \
  --xdp-enable --xdp-interface <iface> --xdp-mode 1 \
  --workers 4 --count 50000 \
  --run-report --run-report-format both
```

Karsilastir:
- sent/errors
- pps (rapor uzerinden)
- jitter/pacing alanlari (aktifse)

---

## 9) Benchmark disiplini (zorunlu)

Ayni konfigurasyonu en az 3 kez kos:
- median sonuc al
- sadece tek kosa bakip karar verme

Her kosuda kaydet:
- CPU modeli, core sayisi
- NIC modeli/driver
- kernel versiyonu
- queue sayisi, worker sayisi
- backend ve mode

Kural:
- "olcumlenmeyen optimizasyon", optimizasyon degildir.

---

## 10) SIK hatalar ve dogru refleksler

Hata 1:
- Worker sayisini cok artirmak = otomatik hiz artisi sanmak
- Cozum: queue/core/NUMA uyumunu once kur

Hata 2:
- Fallback oldugu halde benchmark'i "backend basarili" saymak
- Cozum: `sender_path` ve `fallback_count` zorunlu kontrol

Hata 3:
- Bir kez iyi sonuc alip kalici kabul etmek
- Cozum: tekrarli kosu + median + p95/p99 odakli karar

Hata 4:
- TX'i optimize edip RX/backpressure'i gormemek
- Cozum: drop/error/jitter metriklerini birlikte okumak

---

## 11) 30 gunluk ogrenme backlog'u (sana ozel)

1. Hafta:
- Queue stratejileri (rr/pin/map) + worker event okuma
- Her gun 2 benchmark

2. Hafta:
- TX_RING parametre taramasi
- "hangi parametre neyi degistiriyor?" tablo cikarma

3. Hafta:
- AF_XDP mode 0 vs mode 1 sistematik karsilastirma
- fallback kosullarini listeleme

4. Hafta:
- NUMA-aware mapping denemeleri
- "production profile" default seti olusturma

---

## 12) Bu dersin sonunda neyi biliyor olacaksin?

- NUMA'nin neden teorik degil, direkt PPS/jitter konusu oldugunu
- TX/RX olceklemenin queue/core eslesmesi oldugunu
- AF_XDP'nin "mode + capability + fallback" mantigini
- DPDK'yi bugun degil, dogru zamanda nasil sokacagini
- Projede hangi metric'e bakarak gercek performans karari verecegini

---

## Ek Okuma (repo ici)

- `docs/02-orchestrator.md`
- `docs/03-senders.md`
- `docs/06-af_xdp-fast_sender.md`
- `docs/18-afpacket-hugepage-policy.md`
- `docs/19-benchmark-profiles.md`
- `docs/20-env-cli-reference.md`
- `docs/17-gpu-ai-dataplane-research-validation-roadmap.md`

