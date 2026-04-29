# Orchestrator

Ana işlev: worker lifecycle, dağıtım, toplu istatistik ve hata/fallback yönetimi.

Dosya: `ddos_samurai/orchestrator.py`

## Sorumluluklar

- Worker başlatma/durdurma
- Count/paylaşım ve queue eşleme
- Sender çağrı zinciri ve live progress
- İstatistik birleştirme (`_add_stats`)
- Stateful/L7 yolları için akış kontrolü
