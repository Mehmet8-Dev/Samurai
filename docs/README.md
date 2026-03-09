# DDoSamurai Documentation Index

Bu dizin, kod tabanini "modul modul" ve gelistirici dostu sekilde anlatan ic dokumantasyondur.
Amac:

- Mimariyi hizli kavratmak (veri akisi, sorumluluklar, sinirlar)
- Degisiklik yaparken dogru dosyayi/katmani bulmayi kolaylastirmak
- Guvenlik ve calisma ortami gereksinimlerini netlestirmek

Onemli not:

- Bu proje yalnizca yetkili/test ortamlarinda kullanilmalidir.
- Dokumantasyon, mimari ve gelistirme odaklidir; operasyonel "saldiri nasil yapilir" tarzi yonlendirme amaclamaz.

## Icerik

1. `docs/00-overview.md`: Sistem genel bakis + veri akisi
2. `docs/01-cli.md`: CLI ve config birlestirme mantigi
3. `docs/02-orchestrator.md`: Worker modeli, backend secimi, vektor dispatch
4. `docs/03-senders.md`: CPU/L7 sender'lar, raw socket/fast path, XDP entegrasyonu
5. `docs/04-packet-builder.md`: Scapy tabanli paket ureti mi (CPU yolu)
6. `docs/05-gpu.md`: GPU paket/payload engine (CuPy/Numba) ve template pool yaklasimi
7. `docs/06-af_xdp-fast_sender.md`: AF_XDP ve fast_sender C eklentileri (konsept + entegrasyon)
8. `docs/07-safety.md`: Target safety, etik/uyari akisi, allowlist
9. `docs/08-config.md`: YAML config semasi ve arg precedence kurallari
10. `docs/09-dev-testing.md`: Gelistirme notlari, test stratejisi, sandbox farklari
11. `docs/10-troubleshooting.md`: SIK karsilasilan hatalar ve tanilama
12. `docs/11-docker.md`: Docker Compose ile uygulama (API + Dashboard + CLI runner)
13. `docs/12-dashboard.md`: Dashboard UI, env config (VITE_API_BASE_URL), log/stats modeli
14. `docs/13-api.md`: FastAPI katmani (ddos_samurai/api.py) endpoint semantigi
15. `docs/14-project-analysis-and-trex-comparison.md`: Detayli proje analizi + Cisco TRex karsilastirmasi ve puanlama
16. `docs/15-technology-maturity-and-trex-gap-analysis.md`: Teknoloji olgunlugu, urunlesme riski, TRex/Keysight gap analizi
17. `docs/16-l7-stateful-phase2-phase3-update.md`: Faz 2/3 stateful, H2 transport, WS scenario, PCAP flow-aware/L2 degisiklik ozeti
18. `docs/17-gpu-ai-dataplane-research-validation-roadmap.md`: GPU+AI dataplane icin research roadmap, maturity matrisi ve sistematik validation checklist'i
19. `docs/18-afpacket-hugepage-policy.md`: AF_PACKET/TX_RING HugePage policy, dedicated strict davranis, telemetry ve KPI gate baglantisi
20. `docs/19-benchmark-profiles.md`: Urunlestirilmis benchmark profilleri (`dev`, `ci_safe`, `dedicated_lab`), tek komut ve artifact standardi
21. `docs/20-env-cli-reference.md`: CLI argumanlari + `SAMURAI_*` environment degiskenleri icin detayli teknik referans
