# Samurai Dokümantasyon İndeksi

Bu dizin, **2026-04-28 tarihinde kodla çapraz doğrulanmış** geliştirici dokümantasyonunu içerir.

## Amaç

- Kodun güncel davranışını belgelemek
- Mimari sorumlulukları net ayırmak
- Legacy içerikleri aktif akıştan ayırmak

## Aktif Belgeler

1. `00-overview.md` - Sistem genel bakış ve veri akışı
2. `01-cli.md` - CLI paketi, parse/validasyon/preflight akışı
3. `02-orchestrator.md` - Worker yaşam döngüsü ve dispatch
4. `03-senders.md` - Facade + `_senders/*` iç modül haritası
5. `05-gpu.md` - GPU packet/payload yolları
6. `07-safety.md` - Etik/target safety ilkeleri
7. `09-dev-testing.md` - Test yaklaşımı
8. `18-afpacket-hugepage-policy.md` - AF_PACKET hugepage politikası
9. `19-benchmark-profiles.md` - Benchmark profilleri
10. `20-env-cli-reference.md` - CLI/env referansı (güncel)
11. `22-cli-operational-playbook.md` - Operasyonel CLI akışları
12. `25-core-runtime-modules.md` - Kritik runtime modülleri
13. `26-cli-package-deep-map.md` - CLI paket derin haritası
14. `27-gpu-cuda-payload.md` - GPU CUDA payload paketi

## Legacy / Arşiv Belgeler

Aşağıdaki belgeler tarihsel bağlam içerir; güncel kodla birebir uyum garantisi yoktur:

- `11-docker.md`
- `12-dashboard.md`
- `13-api.md`
- `14-project-analysis-and-trex-comparison.md`
- `15-technology-maturity-and-trex-gap-analysis.md`
- `17-gpu-ai-dataplane-research-validation-roadmap.md`

## Kısa Okuma Sırası

1. `00-overview.md`
2. `01-cli.md`
3. `02-orchestrator.md`
4. `03-senders.md`
5. `05-gpu.md`
6. `20-env-cli-reference.md`
