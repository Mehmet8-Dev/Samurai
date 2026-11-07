# 06 - AF_XDP Kernel-Bypass & Zero-Copy Engine

AF_XDP (XSK - eXpress Data Path Sockets) is Linux's high-performance kernel-bypass technology that routes network frames directly into user-space memory buffers, bypassing the TCP/IP network stack.

![Samurai NUMA Topology & Kernel-Bypass Memory Architecture](assets/diagrams/samurai_numa_afxdp_dpdk.svg)

---

## 1. Operating Principles

1. **UMEM Memory Allocation:** Contiguous physical memory blocks (Hugepages or Paged memory) are pre-allocated in user-space and registered with the XSK socket.
2. **Circular Ring Buffers:** Zero-copy synchronization is achieved via four lock-free rings:
   - **Fill Ring:** Provides vacant memory chunks to the kernel.
   - **Rx Ring:** Receives packet frame pointers from the network card.
   - **Tx Ring:** Submits constructed packets directly to the NIC hardware ring.
   - **Completion Ring:** Notifies user-space when transmission is complete for buffer recycling.
3. **Zero Kernel Copies:** Frames are transferred directly over PCIe bus lanes via hardware DMA.

---

## 2. Samurai AF_XDP Worker (`samurai_afxdp_worker`)

[`afxdp_worker.cpp`](file://ddos_samurai/zmq/daemon/afxdp_worker.cpp) operates as an autonomous native C++ daemon:

- **ZMQ RPC Management:** Receives binary execution parameters (`JobEnvelopeV1`) via local IPC.
- **Strict Zero-Copy Mode:** Configures sockets in `XDP_ZEROCOPY` mode using `libbpf` and `libxdp`.
- **NUMA Socket Pinning:** Locks process threads and memory allocations to the specific NUMA node managing the physical network interface.

---

## 3. Operational Invocations

```bash
# Run with root privileges for raw network namespace access
sudo ./build/ddos_samurai/cli/samurai \
  --worker afxdp \
  --target 10.0.0.50 \
  --port 80 \
  --protocol tcp \
  --count 10000000 \
  --confirm
```
