# 34 - DPDK Environment Setup & PMD Preparation Guide

This runbook guides engineers through configuring and tuning the DPDK Poll Mode Driver (PMD) backend (`samurai_dpdk_worker`) for Samurai in authorized laboratory environments.

![Samurai NUMA Topology & Kernel-Bypass Memory Architecture](assets/diagrams/samurai_numa_afxdp_dpdk.svg)

---

## 1. System Preconditions & Prerequisites

1. **Linux Operating System:** Kernel 5.4+ (Ubuntu 20.04/22.04 LTS or RHEL 8/9).
2. **DPDK-Compatible NIC:** Intel (e.g. i40e, ice, ixgbe) or Mellanox/NVIDIA (mlx5 ConnectX-5/6/7).
3. **IOMMU Hardware Virtualization:** Enabled in BIOS/UEFI (`intel_iommu=on iommu=pt` or `amd_iommu=on`).
4. **Hugepages:** Minimum 2GB allocated memory (2MB or 1GB pages).
5. **Privileges:** Root/sudo access for driver unbinding and VFIO configuration.

---

## 2. Installing DPDK Development Libraries

On Ubuntu/Debian:
```bash
sudo apt update && sudo apt install -y \
  build-essential pkg-config python3-dev \
  libnuma-dev libelf-dev meson ninja-build libdpdk-dev

# Verify DPDK installation
pkg-config --modversion libdpdk
```

---

## 3. Hugepages Allocation & Verification

Allocate 2048 x 2MB pages (4 GB total memory) on the local NUMA node:

```bash
# Allocate 2MB hugepages at runtime
echo 2048 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# Verify allocated hugepages
cat /proc/meminfo | grep -i hugepage

# Mount hugetlbfs if not already mounted
sudo mkdir -p /dev/hugepages
sudo mount -t hugetlbfs nodev /dev/hugepages
```

To make hugepage allocation persistent across reboots, add to `/etc/default/grub`:
```text
GRUB_CMDLINE_LINUX_DEFAULT="... default_hugepagesz=1G hugepagesz=1G hugepages=4 intel_iommu=on iommu=pt"
```

---

## 4. Kernel Module & NIC Driver Binding (`vfio-pci`)

1. Load the VFIO kernel module:
   ```bash
   sudo modprobe vfio-pci
   ```
2. Identify PCI address of the target benchmark interface:
   ```bash
   dpdk-devbind.py --status
   ```
3. Bind the network interface to `vfio-pci`:
   ```bash
   # Replace 0000:03:00.0 with your actual device PCI address
   sudo ip link set dev eth1 down
   sudo dpdk-devbind.py --bind=vfio-pci 0000:03:00.0
   ```

---

## 5. Compiling & Running the Samurai DPDK Worker

Re-run CMake to detect `libdpdk`:
```bash
cmake -B build -S samurai -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

Execute line-rate stress benchmarks via the native CLI:
```bash
# Run samurai with the hardware DPDK PMD worker
sudo ./build/cli/samurai \
  --worker dpdk \
  --target 10.0.0.50 \
  --port 443 \
  --protocol tcp \
  --count 50000000 \
  --confirm
```

---

## 6. Common Pitfalls & Diagnostics

- **`EAL: No free hugepages reported in hugepages-2048kB`**: Ensure `/dev/hugepages` is mounted and permissions allow read/write.
- **`Cannot bind to vfio-pci: Device is busy`**: Verify the network interface is brought down (`ip link set dev ... down`) before binding.
- **Cross-NUMA Bottleneck**: Ensure the worker threads run on CPU cores belonging to the identical NUMA socket managing the PCIe slot.
