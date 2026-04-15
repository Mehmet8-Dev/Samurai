# External Monitoring (Prometheus + Grafana + Alertmanager)

Bu klasor, DDoSamurai icin uygulama-disindan calisan operasyonel gozlemlenebilirlik stack'ini saglar.

## Kapsam (Gelistirilmis)

- Host metrikleri: CPU, memory, filesystem, network throughput, drop/error
- Kernel softnet metrikleri: textfile collector + otomatik toplayici
- Container metrikleri: cAdvisor
- Attack metrikleri: `samurai_attack_*` ve `samurai_results_*`
- Alerting: Prometheus alert rules + Alertmanager route
- Dashboardlar: host + attack odakli operasyon panelleri

## Hizli Baslangic

```bash
cd monitoring
docker compose up -d
```

UI endpoint'leri:
- Prometheus: `http://localhost:9090`
- Alertmanager: `http://localhost:9093`
- Grafana: `http://localhost:3001` (default: `admin` / `admin`)
- cAdvisor: `http://localhost:8080`

Kapatma:

```bash
cd monitoring
docker compose down
```

## Mimari

- `prometheus`: scrape + recording rules + alert rules
- `alertmanager`: alert routing/grouping/inhibition
- `node-exporter`: host metrikleri + textfile collector (`monitoring/textfile`)
- `softnet-collector`: `/proc/net/softnet_stat` -> `samurai_softnet.prom` (5 sn loop)
- `cadvisor`: container CPU/memory/network metrikleri
- `grafana`: provisioned datasource + dashboards

## Kurallar ve Alertler

Prometheus config:
- `monitoring/prometheus/prometheus.yml`

Rules:
- `monitoring/prometheus/rules/samurai-recording.yml`
- `monitoring/prometheus/rules/samurai-alerts.yml`

Ornek alertler:
- hedef down (`up == 0`)
- yuksek host CPU/memory
- softnet drop burst
- yuksek attack error ratio
- dusuk send success ratio
- `wire_loss_status=fail`

## Dashboardlar

- `Host Overview` (`samurai-host-overview`)
- `Samurai Attack Overview` (`samurai-attack-overview`)

Host dashboard'i `instance` ve `device` degiskenleriyle hardcoded arayuz bagimliligini kaldirir.

## Softnet Collector (Manuel)

Otomatik collector zaten compose ile gelir. Manuel test icin:

```bash
python3 monitoring/bin/collect_softnet_textfile.py \
  --softnet-path /proc/net/softnet_stat \
  --out monitoring/textfile/samurai_softnet.prom \
  --prefix samurai
```

## Run Snapshot (Opsiyonel)

```bash
bash monitoring/bin/run_snapshot.sh my_run_001
sudo bash monitoring/bin/run_snapshot.sh my_run_001 --ethtool <iface>
```

Cikti: `reports/telemetry/<run_id>/<timestamp>/`

## Notlar

- `samurai_api` scrape target'i opsiyoneldir; API stack yoksa `down` gorunebilir.
- Grafana portu `GRAFANA_PORT` env ile degistirilebilir (default `3001`).
