# 20 - Env ve CLI Referansı (Güncel)

Bu belge `2026-04-28` tarihinde aşağıdaki kaynaklarla doğrulandı:

- `ddos_samurai/cli/args.py`
- `ddos_samurai/cli/app.py`
- `ddos_samurai/cli/env.py`
- `ddos_samurai/cli/runtime.py`

## Birincil Kural

CLI yüzeyi geniş ve değişken olduğu için tam argüman listesinde **tek otorite**:

```bash
python -m ddos_samurai.cli --help
```

## Config Önceliği

1. Parser default
2. `--config` ile gelen default override
3. Explicit CLI argümanı
4. Profile/preflight mutasyonları
5. Runtime env sync (`sync_runtime_env`)

## `sync_runtime_env` ile Yazılan Başlıca Env Anahtarları

- Loss: `SAMURAI_LOSS_*`
- GPU: `SAMURAI_GPU_*` (pool, ring, batch, stream, pipeline, kernel mode, stream api)
- Sender/dataplane: `SAMURAI_SENDER_*`, `SAMURAI_DATAPLANE_*`
- AF_PACKET: `SAMURAI_AF_PACKET_*`
- Queue/XDP: `SAMURAI_DP_*`, `SAMURAI_XDP_*`
- KPI/L7: `SAMURAI_KPI_*`, `SAMURAI_L7_*`
- Stateful/custom TCP: `SAMURAI_STATEFUL_RUNTIME_BACKEND`, `SAMURAI_CUSTOM_TCP_*`

## Kodla Doğrulanan Kritik Daraltmalar

- `--sender-backend`: yalnızca `xdp`
- `--sender-fallback-policy`: yalnızca `fail`
- `--stateful-runtime-backend`: yalnızca `afxdp`
- `--custom-tcp-backend`: yalnızca `af_xdp`

## Not

Eski dökümanlarda geçen bazı env/opsiyon kombinasyonları tarihsel olabilir. Çelişki durumunda `args.py` ve `env.py` güncel kaynak kabul edilmelidir.
