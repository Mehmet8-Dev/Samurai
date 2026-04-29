# Senders

Facade: `ddos_samurai/senders.py`

İç modüller: `ddos_samurai/_senders/*`

## Önemli Yollar

- `l2l3_entry.py`: XDP gönderim yolu
- `l2l3_raw.py`: raw/dataplane yolu
- `gpu_defense.py`: send-path classify bridge
- `context.py`: sender kaynak temizliği
- `stats_core.py`: ortak telemetri alanları
