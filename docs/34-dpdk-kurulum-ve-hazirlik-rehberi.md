# 34 - DPDK Kurulum ve Hazirlik Rehberi

Bu belge, DDoSamurai icin DPDK backend'ini (`ddos_samurai.dpdk_pmd_core`) hazirlamak isteyen ekipler icin pratik kurulum rehberidir.

Kapsam:

- Sistem gereksinimleri
- DPDK kurulum adimlari
- Hugepage + IOMMU + NIC binding
- Proje derleme ve calistirma
- Dogrulama ve hizli hata tespiti

Not:

- Yalnizca izinli/lab ortamlarda uygulanmalidir.
- Adimlar Ubuntu/Debian odaklidir; farkli dagitimlarda paket isimleri degisebilir.

## 1) Minimum Gereksinimler

1. Linux host (kernel 5.x+ onerilir)
2. DPDK-uyumlu NIC ve driver/PMD destegi
3. Root/sudo erisimi
4. `python3`, `gcc/g++`, `pkg-config`
5. Hugepage kullanimi icin host konfigurasyon yetkisi

Pratikte beklenen host ozellikleri:

- IOMMU aktif (`intel_iommu=on` veya `amd_iommu=on`)
- `vfio-pci` kullanilabilir
- Yeterli hugepage ayrilmis

## 2) DPDK Sistem Paketlerini Kur

Ubuntu/Debian icin tipik kurulum:

```bash
sudo apt update
sudo apt install -y build-essential pkg-config python3-dev \
  libnuma-dev libelf-dev meson ninja-build
```

DPDK paketleri dagitima gore farkli adla gelebilir. Once birini deneyin:

```bash
sudo apt install -y libdpdk-dev
```

Olmazsa alternatif:

```bash
sudo apt install -y dpdk dpdk-dev
```

Kurulum dogrulamasi:

```bash
pkg-config --modversion libdpdk || pkg-config --modversion dpdk
```

## 3) Hugepage Hazirligi

Anlik ayarlama (ornek: 2MB sayfalarda 1024 adet):

```bash
echo 1024 | sudo tee /proc/sys/vm/nr_hugepages
```

Hugetlbfs mount kontrolu:

```bash
grep hugetlbfs /proc/mounts
```

Kalici ayar icin `/etc/sysctl.conf` ve gerekirse `/etc/fstab` kullanin.

Kontrol:

```bash
cat /proc/sys/vm/nr_hugepages
cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
```

## 4) IOMMU ve VFIO Hazirligi

IOMMU aktifligini kontrol edin:

```bash
ls /sys/kernel/iommu_groups
```

`vfio` modullerini yukleyin:

```bash
sudo modprobe vfio
sudo modprobe vfio-pci
```

Kalici yukleme icin `/etc/modules-load.d/` altina kayit eklenebilir.

## 5) NIC Binding (Lab Ortami)

Onemli:

- Bagli oldugu NIC'i `vfio-pci`'ye almak host network'u etkileyebilir.
- Uzak baglanti ile calisiyorsaniz management NIC'i ayri tutun.

DPDK araclari ile mevcut durum:

```bash
sudo dpdk-devbind.py --status || sudo /usr/share/dpdk/usertools/dpdk-devbind.py --status
```

Ornek binding:

```bash
sudo dpdk-devbind.py --bind=vfio-pci 0000:3b:00.0
```

Geri alma ornegi:

```bash
sudo dpdk-devbind.py --bind=ixgbe 0000:3b:00.0
```

Not: Driver adi NIC'e gore `ixgbe`, `i40e`, `ice`, `mlx5_core` vb. olabilir.

## 6) DDoSamurai DPDK Extension Derleme

Proje kokunde:

```bash
SAMURAI_WITH_DPDK=1 python setup.py build_ext --inplace
```

DPDK build zorunlu olsun (CI/strict ortamlari):

```bash
SAMURAI_WITH_DPDK=1 SAMURAI_REQUIRE_DPDK_BUILD=1 python setup.py build_ext --inplace
```

Beklenen artefakt:

- `ddos_samurai/dpdk_pmd_core*.so`

## 7) Runtime Calistirma Ornegi

DPDK backend ile ornek:

```bash
python -m ddos_samurai.cli \
  --sender-backend dpdk \
  --dpdk-enable \
  --dpdk-port-id 0 \
  --dpdk-queue-id 0 \
  --dpdk-burst-size 64 \
  --dpdk-mempool-size 8192 \
  --dpdk-strict \
  --target 192.0.2.10 --port 443 --protocol tcp --count 1000 --confirm
```

Ihtiyaca gore EAL argumanlari:

```bash
--dpdk-eal-args "--log-level=eal,8"
```

## 8) Hazirlik Dogrulama (Tek Komut)

Repoda bulunan kontrol scripti:

```bash
bash tools/check_dpdk_env.sh
```

Rapor modu (exit code zorlamadan):

```bash
bash tools/check_dpdk_env.sh --report-only
```

Script su alanlari denetler:

1. Build bagimliliklari (`pkg-config`, `libdpdk`, headerlar, compiler)
2. Runtime bagimliliklari (hugepage, hugetlbfs, vfio, testpmd)
3. Proje entegrasyonu (`ddos_samurai.dpdk_pmd_core` import + `dpdk_available()`)

## 9) Hata Tespiti Hizli Rehber

1. `No module named ddos_samurai.dpdk_pmd_core`
- DPDK extension derlenmemis.
- `SAMURAI_WITH_DPDK=1` ile yeniden derleyin.

2. `pkg-config ... libdpdk not found`
- DPDK dev paketi eksik.
- `libdpdk-dev` / `dpdk-dev` paketlerini kurun.

3. `nr_hugepages is 0`
- Hugepage ayrilmamis.
- `vm.nr_hugepages` degerini arttirin.

4. `dpdk_no_ethdev` veya link/probe hatalari
- NIC DPDK tarafinda gorunmuyor.
- NIC binding ve driver durumunu kontrol edin.

5. `dpdk_eal_init_failed`
- EAL args uyumsuz veya host kaynaklari yetersiz.
- Daha sade EAL ile deneyin, kernel/driver/IOMMU durumunu tekrar kontrol edin.

## 10) Operasyon Notlari

1. DPDK testlerini once staging/lab ortaminda yapin.
2. Management ve trafik NIC'lerini ayri planlayin.
3. Queue/core pinning ve NUMA planlamasi olmadan benchmark sonucunu production karari olarak kullanmayin.
4. Run oncesi her zaman `bash tools/check_dpdk_env.sh` ve `python -m ddos_samurai.cli --self-test` calistirin.
