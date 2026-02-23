# TRex Path (30 Gunluk Teknik Yol Haritasi)

Tarih: 2026-02-20  
Kapsam: `DDoSamurai` kod tabanini, TRex'e yakinlasacak sekilde performans/stabilite acisindan adim adim iyilestirmek.

## 1) Baslangic Durumu (Mevcut Kanitlar)

Kaynak raporlar:
- `reports/runs/soak_cpu_1h_no_fault.json`
- `reports/runs/soak_gpu_1h_no_fault.json`
- `reports/runs/analysis_selftest.json`
- `reports/perf/perf_audit_20260219T125454Z/summary_metrics.json`

Ozet:
- Self-test: `263` test, `0` fail, `0` error, `58` skip.
- GPU live run: `10,000,000` attempted / `10,000,000` sent / `0` error, efektif ~`26.9k pps`.
- CPU soak raporu: `10,000,000` attempted / `0` sent / `10,000,000` error.
- GPU pcap uretim varyansi dusuk (CV ~`0.22%-0.41%` araligi).

Yorum:
- Test kapsami genis, fakat runtime dataplane guvenilirligi CPU yolunda kritik zayif.
- Kodda birkac bloklayici hata oldugu icin line-rate hedeflere gitmeden once dogruluk katmani duzeltilmeli.

## 2) TRex'e Gore Hedeflenen Bosluklar

Bu 30 gunde hedeflenen bosluklar:
- Dogruluk: runtime hata ve yanlis metrik semantigini azaltmak.
- Determinism: pacing, backlog, worker status metriklerini guvenilir yapmak.
- Dataplane: fast path secimi/fallback davranisini olgunlastirmak.
- Olculebilirlik: benchmark ciktilarini karsilastirilabilir hale getirmek.

Bu 30 gunde hedeflenmeyenler:
- TRex'in mutlak line-rate seviyesine ulasmak.
- Butun NIC/driver kombinasyonlarinda ayni performansi garanti etmek.

## 3) Kuzey Yildizi KPI'lar (Gun 30)

- `send_success_ratio` (CPU basic, izinli lab): `>= 99.0%`
- `send_success_ratio` (GPU basic, izinli lab): `>= 99.5%`
- `worker_status_consistency`: `100%` (failed/ok statulerinin gercek sonucla uyumu)
- `self_test`: `0` fail, `0` error
- Pacing metrikleri: `actual_rps` raporlanabilir ve tutarli
- Run report kalitesi: her benchmark kosusunda JSON+MD+Prom artefakti

## 4) 30 Gunluk Plan (Hafta Bazli)

## Hafta 1 (Gun 1-7) - Kritik Dogruluk ve Bloklayici Bug'lar

Teslimatlar:
- HTTP/2 sender runtime hatasinin kapatilmasi.
- QUIC sender altindaki olu kodun temizlenmesi.
- API -> CLI arguman esleme hatasinin duzeltilmesi.
- Root kontrol mantiginin vektor-bazli hale getirilmesi.
- Worker status semantiginin dogru sonuclari yansitmasi.

Hedef dosyalar:
- `ddos_samurai/senders.py`
- `ddos_samurai/api.py`
- `ddos_samurai/saas_schemas.py`
- `ddos_samurai/cli.py`
- `ddos_samurai/orchestrator.py`
- `tests/test_orchestrator_cpu.py`
- `tests/test_sender_comprehensive.py`

Kabul kriteri:
- Yeni ve mevcut testler gecer.
- `--self-test` temiz gecer.
- Runtime'da `NameError`/`dead branch` kaynakli kritik hata kalmaz.

## Hafta 2 (Gun 8-14) - Dataplane Stabilizasyonu ve Fast Path

Teslimatlar:
- Raw sender yolunda path secimi ve fallback sebeplerinin net loglanmasi.
- Fast sender/TX_RING/L3 fallback olculerinin metriklestirilmesi.
- CPU packet sender icin hata siniflandirmasi (permission, socket, send error).
- Pacing fallback davranisinin test edilmesi.

Hedef dosyalar:
- `ddos_samurai/senders.py`
- `ddos_samurai/pacing.py`
- `ddos_samurai/reporting.py`
- `ddos_samurai/live_metrics.py`
- `tests/test_fast_sender.py`
- `tests/test_pacing_root.py`

Kabul kriteri:
- Her run raporunda hangi sender path'in kullanildigi acik.
- Hata oranlari kategori bazli gorulebilir.
- Pacing acik/kapali modlarinin metrikleri karsilastirilabilir.

## Hafta 3 (Gun 15-21) - GPU Pipeline ve PCAP Replay Olgunlastirma

Teslimatlar:
- GPU batch pipeline olcumleri (gpu->host copy, send wait, queue depth).
- `pcap_replay` timing davranisinin busy-wait agirliginin azaltilmasi.
- Template pool normalize/validation akisinin koruyucu testlerle guclendirilmesi.

Hedef dosyalar:
- `ddos_samurai/orchestrator.py`
- `ddos_samurai/gpu_packet.py`
- `ddos_samurai/pcap_replay.py`
- `tests/test_gpu_pcap_gen.py`
- `tests/test_pcap_replay.py`
- `tests/test_senders_gpu_detailed.py`

Kabul kriteri:
- GPU runlarda sent/error metrikleri tutarli.
- Replay timing modlari (`original`, `multiplier`, `rps`) regresyonsuz calisir.
- En az 3 benchmark kosusunda tekrar edilebilir rapor uretilir.

## Hafta 4 (Gun 22-30) - Hardening, Benchmark Paketi ve Dokumantasyon

Teslimatlar:
- TRex benchmark formatina benzer standart test protokolu.
- Docker/monitoring akisinda benchmark playbook.
- Yol haritasi ciktilarinin toplu raporu.

Hedef dosyalar:
- `docs/09-dev-testing.md`
- `docs/10-troubleshooting.md`
- `docs/11-docker.md`
- `monitoring/README.md`
- `reports/perf/*` (yeni benchmark artefaktlari)

Kabul kriteri:
- Tek komutla benchmark kosumu + rapor cikisi tanimli.
- Son raporda KPI karsilastirmasi var.
- Acik riskler ve bir sonraki 60 gunluk plan net.

## 5) Dosya Bazli Is Listesi (Oncelik Sirali)

1. ✅ `ddos_samurai/senders.py`  
   Gorev: `http2_sender` icindeki tanimsiz degiskenleri duzelt; response kod metriklerini saglamlastir.

2. ✅ `ddos_samurai/senders.py`  
   Gorev: `quic_sender` altindaki return sonrasi olu kodu temizle.

3. ✅ `ddos_samurai/api.py`  
   Gorev: `_build_test_command()` icinde `--ja3-profile` mapini `user_agent` yerine net profile alanina bagla.

4. ✅ `ddos_samurai/saas_schemas.py`  
   Gorev: `ja3_profile` alanini acik ekle; API contract'i netlestir.

5. ✅ `ddos_samurai/cli.py`  
   Gorev: root kontrolunu protokol bazli degil, gercekten raw socket gerektiren vektor bazli yap.

6. ✅ `ddos_samurai/orchestrator.py`  
   Gorev: worker `status` degerini, `sent/errors` sonucuna gore daha dogru belirle.

7. ✅ `ddos_samurai/senders.py`  
   Gorev: sender path kararini (TX_RING/L3/Python fallback) metrik olarak raporla.

8. ✅ `ddos_samurai/reporting.py`  
   Gorev: run report icine `sender_path`, `permission_error_count`, `fallback_count` alanlari ekle.

9. ✅ `ddos_samurai/live_metrics.py`  
   Gorev: textfile export'u icin path ve hata raporlamasini daha gorulebilir yap.

10. ✅ `ddos_samurai/pcap_replay.py`  
    Gorev: timing-aware kisimda asiri busy-wait yerine hibrit bekleme stratejisi uygula.

11. ✅ `ddos_samurai/gpu_packet.py`  
    Gorev: memory pool ve copy telemetrisi (copy latency, pool hit/miss) ekle.

12. `tests/test_orchestrator_cpu.py`  
    Gorev: worker status semantigi ve sender stat toplama testleri ekle.

13. `tests/test_sender_comprehensive.py`  
    Gorev: `http2_sender` ve `quic_sender` regresyon testleri ekle.

14. `tests/test_pcap_replay.py`  
    Gorev: timing modlari icin deterministic unit test seti ekle.

15. `tests/test_cli_parser.py`  
    Gorev: root gate ve API->CLI arg map regressions test et.

16. `docs/02-orchestrator.md`  
    Gorev: yeni status semantigini ve event alanlarini belgele.

17. `docs/03-senders.md`  
    Gorev: sender path secimi ve fallback karar agacini belgele.

18. `docs/13-api.md`  
    Gorev: `TestStartRequest` ve CLI mapping semasini netlestir.

## 6) Benchmark Protokolu (Gun 22+ standard)

Her degisiklik setinden sonra minimum su kosular alinacak:

1. Self-test:
```bash
./ven311/bin/python -m ddos_samurai.cli --self-test --confirm
```

2. Dry-run report:
```bash
./ven311/bin/python -m ddos_samurai.cli --dry-run --run-report --run-report-out dryrun_gate --target 127.0.0.1 --port 80 --confirm
```

3. CPU basic smoke (izinli lab):
```bash
./ven311/bin/python -m ddos_samurai.cli --target <lab_ip> --port 80 --attack-vector basic --compute-backend cpu --count 200000 --workers 1 --confirm --allow-public-target --run-report --run-report-out cpu_smoke
```

4. GPU basic smoke (izinli lab):
```bash
./ven311/bin/python -m ddos_samurai.cli --target <lab_ip> --port 80 --attack-vector basic --compute-backend cuda --count 200000 --workers 2 --confirm --allow-public-target --run-report --run-report-out gpu_smoke
```

5. PCAP replay smoke:
```bash
./ven311/bin/python -m ddos_samurai.cli --attack-vector pcap-replay --pcap-file test1.pcap --pcap-timing multiplier --pcap-speed 2.0 --target <lab_ip> --port 80 --confirm --allow-public-target --run-report --run-report-out pcap_smoke
```

Artefakt zorunlulugu:
- `*.json`, `*.md`, `*.metrics.json`, `*.metrics.prom`

## 7) Risk Kaydi

1. Risk: Root/capability farklari nedeniyle test ortami tutarsizligi.  
   Aksiyon: Docker ve host icin ayri benchmark profili tanimla.

2. Risk: GPU ortam farklari (driver/CUDA) performansi oynatir.  
   Aksiyon: benchmark raporuna environment fingerprint zorunlu.

3. Risk: Scapy unavailable durumda test kapsami yanlis guven verebilir.  
   Aksiyon: Scapy-bagli testleri acik etiketle ve raporda ayir.

4. Risk: Fallback mekanizmalari gercek hatayi maskeleyebilir.  
   Aksiyon: fallback nedenlerini metrik olarak export et.

## 8) Cikis Kriteri (Gun 30)

Asagidaki maddeler saglanirsa "TRex'e yaklasma Faz-1" tamamlanmis sayilir:
- Kritik runtime buglar kapali.
- CPU ve GPU smoke run'larinda `sent > 0` ve kabul edilebilir hata orani.
- Worker status ve run report semantigi teknik olarak tutarli.
- Standart benchmark paketi ve tekrar edilebilir artefakt uretiliyor.
- Sonuc raporu: TRex farklari + Faz-2 (60 gun) backlog'u net.

## 9) Faz-2 (60 Gun) Icin Hazir Backlog (Kisa)

- NUMA/core pinning stratejilerinin TRex benzeri optimize edilmesi.
- NIC queue/irq affinity tuning playbook'u.
- DPDK benzeri user-space path arastirmasi (opsiyonel track).
- L7 ve API katmanini dataplane'den daha net ayirma.

## 10) Faz-2 (Gun 31-90) Hedef Tanimi

Faz-2'nin amaci, Faz-1'de stabilize edilen runtime'i TRex'e yaklasacak sekilde
"deterministic dataplane + olculebilir performans + operasyonel tekrar edilebilirlik"
ucgeninde olgunlastirmaktir.

Ana eksenler:
- Dataplane ayristirma: kontrol katmani ile gonderim katmaninin net sinirlari.
- Donanim farkindaligi: CPU core pinning, NUMA, IRQ/queue affinities.
- Kopya ve gecikme azaltimi: GPU->host ve host->NIC yolunda daha az overhead.
- Benchmark disiplini: her release adayi icin ayni matris + ayni rapor semasi.

## 11) Faz-2 KPI'lar (Gun 90)

- `cpu_effective_pps_gain`: Faz-1 baseline'a gore en az `+150%`
- `gpu_effective_pps_gain`: Faz-1 baseline'a gore en az `+100%`
- `fallback_ratio`: toplam runlarin `%5` altinda
- `worker_status_false_ok`: `0` (yanlis "ok" raporu yok)
- `pacing_rate_accuracy_pct`: hedeflenen runlarda `>= 95%`
- `pcap_replay_timing_error_pct`: `<= 10%` (original/multiplier modlarinda)
- `benchmark_repeatability_cv_pct`: ayni profil 3 tekrar icin `<= 5%`

## 12) Faz-2 Sprint Plani (4 x 15 Gun)

## Sprint A (Gun 31-45) - Dataplane Refactor

Hedef:
- Packet generation, pacing ve sender path kararini daha moduler hale getirmek.

Teslimatlar:
- Sender pipeline karar agaci tek bir yerde toplansin.
- Orchestrator icindeki backend branch'leri sadelestirilsin.
- API/CLI run config semasi tek kaynak dogruya indirgensin.

Dosyalar:
- `ddos_samurai/orchestrator.py`
- `ddos_samurai/senders.py`
- `ddos_samurai/cli.py`
- `ddos_samurai/api.py`
- `ddos_samurai/saas_schemas.py`

## Sprint B (Gun 46-60) - CPU/NUMA/IRQ Optimizasyonu

Hedef:
- CPU path'te TRex benzeri cekirdek ve queue farkindaligi kazanmak.

Teslimatlar:
- Worker pinning politikasini configurable hale getirmek.
- NUMA node farkindaligi ve core map profile'lari eklemek.
- NIC queue / IRQ affinity icin operasyon playbook + script.

Dosyalar:
- `ddos_samurai/orchestrator.py`
- `ddos_samurai/pacing.py`
- `monitoring/bin/run_snapshot.sh`
- `docs/10-troubleshooting.md`
- `docs/11-docker.md`

## Sprint C (Gun 61-75) - Zero-Copy Yol ve Replay Iyilestirme

Hedef:
- TX path'te ekstra kopyalari azaltmak ve replay timing dogrulugunu arttirmak.

Teslimatlar:
- `raw_socket_sender` ve `paced_raw_socket_sender` icin buffer lifecycle iyilestirmesi.
- `pcap_replay` timing-aware path'te akilli sleep/spin dengesinin tuning'i.
- GPU pinned pool hit-rate ve copy latency metrikleri.

Dosyalar:
- `ddos_samurai/senders.py`
- `ddos_samurai/pcap_replay.py`
- `ddos_samurai/gpu_packet.py`
- `ddos_samurai/live_metrics.py`
- `ddos_samurai/reporting.py`

## Sprint D (Gun 76-90) - Benchmark Certification ve Release Hardening

Hedef:
- Faz-2 ciktilarini release-ready hale getirmek.

Teslimatlar:
- Standart benchmark matrix + otomatik rapor toplayici.
- "TRex parity gap report" dokumani.
- Opsiyonel canary run profilleri (cpu/gpu/pcap).

Dosyalar:
- `reports/perf/*`
- `reports/runs/*`
- `docs/09-dev-testing.md`
- `docs/03-senders.md`
- `docs/13-api.md`
- `monitoring/README.md`

## 13) Faz-2 Dosya Bazli Is Paketleri (Detay)

1. `ddos_samurai/orchestrator.py`  
   Is: backend dispatch'i "strategy map" yapisina gecir.

2. `ddos_samurai/orchestrator.py`  
   Is: worker event semasina `sender_path`, `fallback_reason`, `queue_backlog_peak` ekle.

3. `ddos_samurai/senders.py`  
   Is: raw/paced/xdp path kararlarini tek utility altinda birlestir.

4. `ddos_samurai/senders.py`  
   Is: toplu send hatalarini errno bazli siniflandir (`perm`, `net`, `timeout`, `other`).

5. `ddos_samurai/senders.py`  
   Is: memoryview ve pinned buffer reuse oranini olc.

6. `ddos_samurai/pcap_replay.py`  
   Is: rps ve multiplier modlarinda timing error olcumunu rapora yaz.

7. `ddos_samurai/pcap_replay.py`  
   Is: batch scheduler'i "time budget aware" hale getir.

8. `ddos_samurai/gpu_packet.py`  
   Is: pool stats'a copy_latency_us ve reuse_hit_count alanlari ekle.

9. `ddos_samurai/pacing.py`  
   Is: runtime capability snapshot'i report alanina entegre et.

10. `ddos_samurai/reporting.py`  
    Is: Faz-2 KPI alanlarini standard JSON/MD semasina ekle.

11. `ddos_samurai/live_metrics.py`  
    Is: live exporter'a sender_path/fallback gauges ekle.

12. `ddos_samurai/cli.py`  
    Is: benchmark profilleri icin preset flag gruplari ekle (`--perf-profile ...`).

13. `ddos_samurai/api.py`  
    Is: benchmark run tipleri icin request validation ve limit kurallari.

14. `tests/test_orchestrator_cpu.py`  
    Is: yeni event semasi ve status kurallari icin testler.

15. `tests/test_sender_comprehensive.py`  
    Is: sender_path secimi ve fallback coverage testleri.

16. `tests/test_pcap_replay.py`  
    Is: timing error regression testleri.

17. `tests/test_gpu_pcap_gen.py`  
    Is: gpu pool stats ve realism rapor genisletme testleri.

18. `tests/test_cli_parser.py`  
    Is: yeni perf profile ve run-report schema arguman testleri.

19. `docs/09-dev-testing.md`  
    Is: benchmark matrix calistirma rehberi.

20. `docs/10-troubleshooting.md`  
    Is: NUMA/IRQ/pinning kaynakli bozulmalar icin tanilama akisi.

21. `monitoring/bin/run_snapshot.sh`  
    Is: benchmark once/sonra otomatik metadata paketleme.

22. `monitoring/README.md`  
    Is: Faz-2 KPI panel mapping'i.

## 14) Faz-2 Benchmark Matrisi (Zorunlu)

Her release adayi icin asagidaki matris en az 3 tekrar kosulacak:

1. CPU basic (`workers=1`, `workers=nproc/2`, `workers=nproc-1`)
2. GPU basic (`batch=50k`, `100k`, `200k`)
3. Pacing (`rps`, `ipg`, `burst`) - ayni count ile
4. PCAP replay (`original`, `multiplier=2.0`, `rps`)
5. Soak mini (`15m`) - cpu ve gpu ayri

Toplanacak metrikler:
- `effective_pps`, `error_rate_pct`, `fallback_ratio`
- `pacing_rate_accuracy_pct`, `jitter_p99_ns`
- `rss_growth_mb`, `vram_growth_mb`, `pinned_growth_mb`
- `queue_backlog_peak`, `worker_status_distribution`

## 15) Faz-2 Milestone Kapilari (Go/No-Go)

Milestone M1 (Gun 45):
- Kritik refactor tamam.
- Self-test temiz.
- Run schema backward-compatible.

Milestone M2 (Gun 60):
- CPU/NUMA/pinning iyilestirmeleri benchmarkta olumlu etki gosteriyor.
- fallback_ratio trendi dusuyor.

Milestone M3 (Gun 75):
- Replay timing hatasi hedefe yakin.
- GPU copy/path metrikleri raporda gorunur.

Milestone M4 (Gun 90):
- Faz-2 KPI'larinin buyuk bolumu saglandi.
- "TRex parity gap report" yayinlandi.

## 16) Faz-2 Cikis Artefaktlari

Gun 90 sonunda asagidaki ciktilar zorunlu:
- `reports/perf/faz2_final/summary_metrics.json`
- `reports/perf/faz2_final/performance_report.md`
- `reports/perf/faz2_final/trex_parity_gap.md`
- `reports/runs/faz2_canary_cpu.json`
- `reports/runs/faz2_canary_gpu.json`
- `reports/runs/faz2_canary_pcap.json`

Bu artefaktlar uretildiginde Faz-3 (opsiyonel ileri dataplane) kararina gecilir.
