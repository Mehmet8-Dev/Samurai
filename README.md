# Samurai (Shogun) — Native C++ Network Stress & Security Test Platform

Samurai (Sürüm 2.2+, Kod adı: **Shogun**), **yalnızca yetkili lab ve güvenlik testi ortamlarında** kullanılmak üzere geliştirilmiş, yüksek başarımlı (high-throughput), düşük gecikmeli (low-latency) ve modüler bir ağ stres ve dayanıklılık test platformudur.

Platform, Python bağımlılıklarından arındırılarak tamamen modern **C++ (C++17)**, **ZeroMQ (ZMQ) binary IPC wire protocol**, **Kernel-Bypass (AF_XDP, DPDK)**, **GPU/CUDA paket sentezi** ve **User-Space TCP/L7 motorları** ile çalışan native mimariye dönüştürülmüştür.

---

## Temel Özellikler

- **Saf Native C++ Çalışma Zamanı:** Sıfır Python çalışma zamanı gecikmesi; C++17 ile derlenen mikroservis mimarisi.
- **Native CLI Front-End (`samurai`):** Güçlü argüman doğrulama, KPI gate kontrolleri, RFC paket testleri ve profil yönetimi.
- **Dağıtık Control-Plane (`samurai_master` & `samurai_slave`):**
  - ZMQ ROUTER/DEALER tabanlı asenkron RPC haberleşmesi.
  - Dinamik iş parçalama (Sharding - eşit, kapasite, bölge bazlı).
  - High Availability (HA) lider seçimi (Static ve File-Lease).
  - Multi-Master & Multi-Region koordinatörü.
  - Saf POSIX soket tabanlı yerleşik HTTP REST Management API (`:8089`).
  - OpenSSL HMAC-SHA256 ile HS256 JWT ve RBAC yetkilendirme.
  - Tahrif edilemez (tamper-evident) SHA-256 denetim günlüğü (Audit Log).
- **Yüksek Başarımlı Dataplane Motorları:**
  - **L4 User-Space TCP Stack (`tcp_dataplane_core`):** 64-shard kilit şeritli (lock-striped) flow tablosu, out-of-order paket işleme, timer-wheel retransmit.
  - **AF_XDP (Kernel-Bypass):** Linux XSK / UMEM zero-copy ring bufferları üzerinden Mpps seviyesinde paket iletimi.
  - **DPDK:** PMD ring tabanlı donanım hızlandırma.
  - **GPU CUDA & DOCA GPUNetIO:** Donanım hızlandırmalı paket üretimi ve DPU akış yönetimi.
  - **L7 Emülasyon Native (`l7_emu_native`):** HTTP/1.1, HTTP/2 (nghttp2), QUIC / HTTP/3 (ngtcp2) ve DNS motorları (Kernel socket veya Custom TCP/AF_XDP modları).
  - **Scenario Engine Native (`scenario_engine_native`):** Web/Mobil persona tabanlı çok adımlı kullanıcı davranışları ve SLA denetleyicisi.
  - **CPU Native Packet Engine (`cpu_native`):** Raw socket / packet ring optimizasyonu, dinamik spoofing ve amplifikasyon jeneratörleri.

---

## Mimari Şema

```mermaid
graph TD
    subgraph Control Plane
        Master[samurai_master Daemon]
        MgmtAPI[Native HTTP Management API :8089]
        Master -->|ZMQ ROUTER :5099| Slave[samurai_slave Daemon]
    end

    subgraph Native CLI & Local Supervisor
        CLI[samurai CLI] -->|ZMQ IPC / Unix Sockets| Supervisor[Supervisor Engine]
    end

    Slave -->|Spawns / Manages| Supervisor

    subgraph ZMQ Native Workers
        Supervisor --> W_CPU[samurai_cpu_worker]
        Supervisor --> W_AFXDP[samurai_afxdp_worker]
        Supervisor --> W_DPDK[samurai_dpdk_worker]
        Supervisor --> W_GPU[samurai_gpu_worker]
        Supervisor --> W_DOCA[samurai_doca_worker]
        Supervisor --> W_L7[samurai_l7_worker]
        Supervisor --> W_SCENARIO[samurai_scenario_worker]
        Supervisor --> W_DEFENSE[samurai_defense_worker]
    end

    subgraph Hardware & Kernel Bypass Dataplane
        W_AFXDP -->|Zero-Copy UMEM| NIC[Ağ Kartı / NIC]
        W_DPDK -->|PMD Driver / VFIO| NIC
        W_GPU -->|CUDA Stream / GPUDirect| GPU[NVIDIA GPU]
        W_L7 -->|User-Space TCP Stack| W_AFXDP
    end
```

---

## Derleme (Build)

### Gereksinimler

- **İşletim Sistemi:** Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+)
- **Derleyici:** GCC 9+ veya Clang 10+ (C++17 standardı)
- **Yapı Sistemi:** CMake 3.16+ ve Make / Ninja
- **Kütüphaneler:** `libzmq3-dev`, `libssl-dev`, `pkg-config`, `build-essential`
- **Opsiyonel Kütüphaneler:**
  - AF_XDP için: `libbpf-dev`, `libelf-dev`
  - HTTP/2 & QUIC için: `libnghttp2-dev`, `libngtcp2-dev`
  - DPDK için: `libdpdk-dev`
  - CUDA için: NVIDIA CUDA Toolkit (12.x+)

### Derleme Adımları

```bash
# Bağımlılıkları yükleyin (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config libzmq3-dev libssl-dev libbpf-dev libelf-dev

# Derleme dizinini oluşturun ve derleyin
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

Derleme sonucunda `build/` altında aşağıdaki ikili dosyalar oluşur:
- `build/ddos_samurai/cli/samurai` (Ana CLI)
- `build/ddos_samurai/control/daemon/samurai_master` (Master Daemon)
- `build/ddos_samurai/control/daemon/samurai_slave` (Slave Daemon)
- `build/ddos_samurai/zmq/daemon/samurai_*_worker` (Tüm Dataplane Worker ikilileri)
- `build/ddos_samurai/*_selftest` (Bileşen birim testleri)

---

## Kullanım

### 1) Standart CLI ile Test Başlatma (`samurai`)

```bash
# CPU worker ile temel UDP flood testi
./build/ddos_samurai/cli/samurai \
  --worker cpu \
  --target 127.0.0.1 --port 8080 \
  --protocol udp --count 100000 \
  --confirm

# AF_XDP Kernel-Bypass ile ultra yüksek hızlı paket testi
sudo ./build/ddos_samurai/cli/samurai \
  --worker afxdp \
  --target 10.0.0.50 --port 80 \
  --protocol tcp --count 5000000 \
  --confirm

# L7 HTTP/2 Stres Testi
./build/ddos_samurai/cli/samurai \
  --worker l7 \
  --target 10.0.0.50 --port 443 \
  --protocol http2 --scheme https \
  --concurrency 100 --max-connections 50 \
  --count 200000 --confirm

# Scenario Engine ile Gerçekçi Kullanıcı Senaryosu
./build/ddos_samurai/cli/samurai \
  --worker scenario \
  --target 10.0.0.50 --port 443 \
  --scenario-payload-ref docs/scenario_web_mobile.yaml \
  --count 100000 --confirm
```

---

### 2) Dağıtık (Distributed) Master / Slave Modu

Farklı sunuculardaki kaynakları birleştirerek test yükünü yatayda ölçekleme:

#### **Master Düğümü (`samurai_master`):**
```bash
./build/ddos_samurai/control/daemon/samurai_master \
  --control-listen tcp://0.0.0.0:5099 \
  --count 10000000 \
  --target 10.0.0.50 \
  --port 443 \
  --protocol tcp \
  --expect-workers 4 \
  --cluster-secret "samurai-cluster-secret" \
  --management-listen 0.0.0.0:8089
```

#### **Slave Düğümleri (`samurai_slave`):**
Her worker sunucusunda çalıştırın:
```bash
./build/ddos_samurai/control/daemon/samurai_slave \
  --control-endpoints <MASTER_IP>:5099 \
  --worker afxdp \
  --worker-id "slave-node-01" \
  --worker-region "eu-central" \
  --cluster-secret "samurai-cluster-secret" \
  --heartbeat-interval-ms 2000
```

---

### 3) Docker Compose ile Dağıtık Çalıştırma

```bash
docker compose -f docker-compose.distributed.yml up --build --scale slave=4
```

---

## Worker Türleri Referansı

| Worker Adı (`--worker`) | Native Binary | Açıklama ve Yetenekler |
| :--- | :--- | :--- |
| `cpu` | `samurai_cpu_worker` | Standart CPU raw socket, paket halkası, dinamik spoofing |
| `afxdp` | `samurai_afxdp_worker` | Linux XDP/UMEM zero-copy kernel bypass |
| `dpdk` | `samurai_dpdk_worker` | DPDK PMD donanım kuyruğu tabanlı paket iletimi |
| `gpu` | `samurai_gpu_worker` | CUDA tabanlı GPU paralel paket sentezi |
| `doca` | `samurai_doca_worker` | NVIDIA DPU & GPUNetIO doğrudan bellek veri yolu |
| `l7` | `samurai_l7_worker` | HTTP/1.1, HTTP/2, QUIC/HTTP/3, DNS (Epoll / User-Space TCP) |
| `scenario` | `samurai_scenario_worker` | Çok adımlı web/mobil persona senaryo motoru |
| `defense` | `samurai_defense_worker` | VAE anomali doğrulama ve savunma bypass analizleri |

---

## Native Self-Testler (Doğrulama)

Tüm bileşenlerin sağlığını C++ birim testleriyle doğrulamak için:

```bash
./build/ddos_samurai/control/samurai_control_selftest
./build/ddos_samurai/l7_emu_native/samurai_l7_selftest
./build/ddos_samurai/scenario_engine_native/samurai_scenario_engine_selftest
./build/ddos_samurai/licensing/samurai_licensing_selftest
```

---

## Yasal ve Etik Bildirim

Bu yazılım yalnızca sistem yöneticilerinin, güvenlik araştırmacılarının ve ağ mühendislerinin kendi sahip oldukları veya açık yazılı izin aldıkları altyapılarda stres/dayanıklılık testleri yapabilmesi amacıyla tasarlanmıştır. İzin alınmamış hedeflere yönelik trafik üretilmesi yasa dışıdır. Tüm yasal sorumluluk kullanıcıya aittir.

---

## Detaylı Dokümantasyon İndeksi

Tüm alt modüllerin ayrıntılı teknik açıklamaları için [`docs/README.md`](docs/README.md) dizinini inceleyebilirsiniz.
