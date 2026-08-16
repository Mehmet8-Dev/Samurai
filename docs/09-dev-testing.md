# 09 - Geliştirme, CMake Derleme ve Native Testler

DDoSamurai'nin geliştirme ve test süreçleri CMake tabanlı C++17 derleme sistemi ve yerleşik C++ self-test ikilileri üzerinden yürütülür.

---

## 1. Projeyi Derleme

```bash
# 1. Derleme dizini oluşturun
mkdir -p build && cd build

# 2. CMake yapılandırmasını çalıştırın (Release veya Debug)
cmake .. -DCMAKE_BUILD_TYPE=Release

# 3. Tüm hedefleri paralel derleyin
make -j$(nproc)
```

---

## 2. Native C++ Self-Testleri Çalıştırma

Her ana alt sistem için ayrı bir self-test sürücüsü derlenir:

```bash
# 1. Control Plane ve Sharding Testleri
./build/ddos_samurai/control/samurai_control_selftest

# 2. L7 Emülasyon ve Custom TCP Testleri
./build/ddos_samurai/l7_emu_native/samurai_l7_selftest

# 3. Scenario Engine (DSL / Scheduler / SLA) Testleri
./build/ddos_samurai/scenario_engine_native/samurai_scenario_engine_selftest

# 4. Lisanslama ve Yetkilendirme Testleri
./build/ddos_samurai/licensing/samurai_licensing_selftest
```

---

## 3. Kod Standartları

- **Standart:** Modern C++17.
- **Kütüphaneler:** ZeroMQ (`libzmq`), OpenSSL (Kriptografi/JWT), POSIX Soketleri.
- **Performans:** Lock-free / Lock-striped veri yapıları, zero-copy tampon geçişleri, heap allocation minimizasyonu.
