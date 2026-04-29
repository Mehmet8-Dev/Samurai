# CLI

Tek giriş noktası:

```bash
python -m ddos_samurai.cli
```

## Sık Kullanılan Komutlar

Self-test:

```bash
python -m ddos_samurai.cli --self-test
```

Dry-run:

```bash
python -m ddos_samurai.cli \
  --target 127.0.0.1 --port 8080 \
  --protocol tcp --attack-vector basic \
  --count 100 --dry-run --confirm
```

Native RX->GPU classify modu:

```bash
sudo python -m ddos_samurai.cli \
  --gpu-rx-pipeline on \
  --gpu-rx-iface eth0 \
  --gpu-rx-duration-s 15 \
  --gpu-rx-batch-size 256 \
  --gpu-rx-max-packets 200000 \
  --gpu-rx-snaplen 2048 \
  --gpu-defense-mode on \
  --gpu-classifier-runtime tensorrt \
  --gpu-classifier-engine-path /path/to/model.engine
```
