# Samurai (Ronin) Documentation Index

Bu dizin, kod tabanini gelistirici odakli sekilde anlatir.
Amac:

- Mimariyi hizli kavratmak (veri akisi, sorumluluklar, sinirlar)
- Degisiklik yaparken dogru dosyayi/katmani bulmayi kolaylastirmak
- Calisan ve tarihsel (legacy) belgeleri ayirmak

Onemli not:

- Bu proje yalnizca yetkili/test ortamlarinda kullanilmalidir.
- Dokumantasyon, mimari ve gelistirme odaklidir.

Release notu:

- Mevcut release modeli: `Samurai (Ronin)`.

## Aktif Dokumanlar

1. `docs/00-overview.md`: Sistem genel bakis + veri akisi
2. `docs/01-cli.md`: CLI ve config birlestirme mantigi
3. `docs/02-orchestrator.md`: Worker modeli, backend secimi, vektor dispatch
4. `docs/03-senders.md`: `senders.py` strict facade modeli, `_senders/*` ic modul haritasi
5. `docs/04-packet-builder.md`: Scapy tabanli paket uretimi (CPU yolu)
6. `docs/05-gpu.md`: GPU paket/payload engine ve native CUDA path notlari
7. `docs/06-af_xdp-fast_sender.md`: AF_XDP ve fast_sender C entegrasyonu
8. `docs/07-safety.md`: Target safety, etik/uyari akisi, allowlist
9. `docs/08-config.md`: YAML config semasi ve arg precedence kurallari
10. `docs/09-dev-testing.md`: Gelistirme notlari, test stratejisi
11. `docs/10-troubleshooting.md`: SIK karsilasilan hatalar ve tanilama
12. `docs/18-afpacket-hugepage-policy.md`: AF_PACKET/TX_RING HugePage policy
13. `docs/19-benchmark-profiles.md`: Benchmark profilleri ve artifact standardi
14. `docs/20-env-cli-reference.md`: CLI + `SAMURAI_*` env referansi

## Tarihsel/Legacy Dokumanlar

Asagidaki dosyalar tarihsel icerik tutar; repodaki mevcut checkout ile bire bir ortusmeyebilir:

- `docs/11-docker.md`
- `docs/12-dashboard.md`
- `docs/13-api.md`
- `docs/14-project-analysis-and-trex-comparison.md`
- `docs/15-technology-maturity-and-trex-gap-analysis.md`
- `docs/16-l7-stateful-phase2-phase3-update.md`
- `docs/17-gpu-ai-dataplane-research-validation-roadmap.md`

Not: Bu checkout'ta `dashboard/` ve `ddos_samurai/api.py` bulunmadigindan UI/API odakli belgeler "aktif runtime" yerine "arsiv baglam" olarak degerlendirilmelidir.
