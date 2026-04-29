#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include <cuda_runtime_api.h>

#if defined(SAMURAI_WITH_GPUDIRECT_RDMA)
#include <infiniband/verbs.h>
#endif

namespace ddos_samurai::gpu_packet_cuda::defense {

struct GpuDirectRdmaConfig {
  std::string ibv_device_name;
  int ib_port = 1;
  int gid_index = -1;
};

class GpuDirectRdmaAdapter {
 public:
  GpuDirectRdmaAdapter() = default;
  ~GpuDirectRdmaAdapter() { shutdown(); }

  GpuDirectRdmaAdapter(const GpuDirectRdmaAdapter&) = delete;
  GpuDirectRdmaAdapter& operator=(const GpuDirectRdmaAdapter&) = delete;

  bool init(const GpuDirectRdmaConfig& cfg, std::string* reason) {
    std::lock_guard<std::mutex> lk(mu_);
#if !defined(SAMURAI_WITH_GPUDIRECT_RDMA)
    (void)cfg;
    if (reason != nullptr) {
      *reason = "rdma_unavailable";
    }
    return false;
#else
    if (initialized_) {
      return true;
    }
    cfg_ = cfg;

    int dev_count = 0;
    dev_list_ = ibv_get_device_list(&dev_count);
    if (dev_list_ == nullptr || dev_count <= 0) {
      if (reason != nullptr) {
        *reason = "rdma_unavailable";
      }
      return false;
    }

    ibv_device* chosen = nullptr;
    if (!cfg_.ibv_device_name.empty()) {
      for (int i = 0; i < dev_count; ++i) {
        ibv_device* d = dev_list_[i];
        if (d != nullptr && cfg_.ibv_device_name == std::string(ibv_get_device_name(d))) {
          chosen = d;
          break;
        }
      }
    }
    if (chosen == nullptr) {
      chosen = dev_list_[0];
    }
    if (chosen == nullptr) {
      if (reason != nullptr) {
        *reason = "rdma_unavailable";
      }
      return false;
    }

    ctx_ = ibv_open_device(chosen);
    if (ctx_ == nullptr) {
      if (reason != nullptr) {
        *reason = "rdma_unavailable";
      }
      return false;
    }

    pd_ = ibv_alloc_pd(ctx_);
    if (pd_ == nullptr) {
      if (reason != nullptr) {
        *reason = "rdma_unavailable";
      }
      return false;
    }

    initialized_ = true;
    return true;
#endif
  }

  bool register_gpu_buffer(void* dptr, size_t nbytes, std::string* reason) {
    std::lock_guard<std::mutex> lk(mu_);
#if !defined(SAMURAI_WITH_GPUDIRECT_RDMA)
    (void)dptr;
    (void)nbytes;
    if (reason != nullptr) {
      *reason = "rdma_unavailable";
    }
    return false;
#else
    if (!initialized_ || pd_ == nullptr || dptr == nullptr || nbytes == 0) {
      if (reason != nullptr) {
        *reason = "rdma_unavailable";
      }
      return false;
    }

    cudaPointerAttributes attrs{};
    const cudaError_t st = cudaPointerGetAttributes(&attrs, dptr);
    if (st != cudaSuccess) {
      if (reason != nullptr) {
        *reason = "rdma_unavailable";
      }
      return false;
    }
#if CUDART_VERSION >= 10000
    if (attrs.type != cudaMemoryTypeDevice) {
#else
    if (attrs.memoryType != cudaMemoryTypeDevice) {
#endif
      if (reason != nullptr) {
        *reason = "rdma_unavailable";
      }
      return false;
    }

    const int access =
        IBV_ACCESS_LOCAL_WRITE |
        IBV_ACCESS_REMOTE_READ |
        IBV_ACCESS_REMOTE_WRITE |
        IBV_ACCESS_REMOTE_ATOMIC;

    ibv_mr* mr = ibv_reg_mr(pd_, dptr, nbytes, access);
    if (mr == nullptr) {
      if (reason != nullptr) {
        *reason = "rdma_unavailable";
      }
      return false;
    }

    regs_.push_back(RegisteredMr{dptr, nbytes, mr});
    return true;
#endif
  }

  void shutdown() {
    std::lock_guard<std::mutex> lk(mu_);
#if defined(SAMURAI_WITH_GPUDIRECT_RDMA)
    for (auto it = regs_.rbegin(); it != regs_.rend(); ++it) {
      if (it->mr != nullptr) {
        ibv_dereg_mr(it->mr);
      }
    }
    regs_.clear();

    if (pd_ != nullptr) {
      ibv_dealloc_pd(pd_);
      pd_ = nullptr;
    }
    if (ctx_ != nullptr) {
      ibv_close_device(ctx_);
      ctx_ = nullptr;
    }
    if (dev_list_ != nullptr) {
      ibv_free_device_list(dev_list_);
      dev_list_ = nullptr;
    }
#endif
    initialized_ = false;
  }

 private:
#if defined(SAMURAI_WITH_GPUDIRECT_RDMA)
  struct RegisteredMr {
    void* ptr = nullptr;
    size_t nbytes = 0;
    ibv_mr* mr = nullptr;
  };

  ibv_device** dev_list_ = nullptr;
  ibv_context* ctx_ = nullptr;
  ibv_pd* pd_ = nullptr;
  std::vector<RegisteredMr> regs_;
#endif
  GpuDirectRdmaConfig cfg_{};
  bool initialized_ = false;
  std::mutex mu_;
};

}  // namespace ddos_samurai::gpu_packet_cuda::defense
