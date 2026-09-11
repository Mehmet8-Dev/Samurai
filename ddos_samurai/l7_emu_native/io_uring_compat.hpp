#pragma once

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <atomic>
#include <vector>
#include <poll.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#if defined(__has_include)
#  if __has_include(<linux/io_uring.h>)
#    include <linux/io_uring.h>
#    define SAMURAI_HAS_LINUX_IO_URING 1
#  endif
#endif

namespace ddos_samurai::l7_emu_native {

#if defined(SAMURAI_HAS_LINUX_IO_URING) && defined(__NR_io_uring_setup)

enum class IoUringOp : uint8_t {
  None = 0,
  Connect = 1,
  Send = 2,
  Recv = 3,
  Close = 4,
};

inline uint64_t make_uring_user_data(uint32_t lane_idx, IoUringOp op, uint16_t gen = 0) {
  return (static_cast<uint64_t>(lane_idx) << 32) |
         (static_cast<uint64_t>(static_cast<uint8_t>(op)) << 16) |
         static_cast<uint64_t>(gen);
}

inline uint32_t uring_user_data_lane_idx(uint64_t ud) {
  return static_cast<uint32_t>(ud >> 32);
}

inline IoUringOp uring_user_data_op(uint64_t ud) {
  return static_cast<IoUringOp>((ud >> 16) & 0xFF);
}

inline uint16_t uring_user_data_gen(uint64_t ud) {
  return static_cast<uint16_t>(ud & 0xFFFF);
}

class SamuraiUring {
 public:
  int ring_fd{-1};
  unsigned sq_entries{0};
  unsigned cq_entries{0};
  uint32_t features{0};
  uint32_t active_flags{0};

  // SQ Ring pointers
  unsigned* sq_khead{nullptr};
  unsigned* sq_ktail{nullptr};
  unsigned* sq_kring_mask{nullptr};
  unsigned* sq_kflags{nullptr};
  unsigned* sq_array{nullptr};
  struct io_uring_sqe* sqes{nullptr};
  size_t sq_ring_sz{0};
  size_t sqes_sz{0};
  void* sq_ptr{nullptr};

  // CQ Ring pointers
  unsigned* cq_khead{nullptr};
  unsigned* cq_ktail{nullptr};
  unsigned* cq_kring_mask{nullptr};
  struct io_uring_cqe* cqes{nullptr};
  size_t cq_ring_sz{0};
  void* cq_ptr{nullptr};

  SamuraiUring() = default;
  ~SamuraiUring() { cleanup(); }

  SamuraiUring(const SamuraiUring&) = delete;
  SamuraiUring& operator=(const SamuraiUring&) = delete;

  SamuraiUring(SamuraiUring&& other) noexcept {
    move_from(std::move(other));
  }

  SamuraiUring& operator=(SamuraiUring&& other) noexcept {
    if (this != &other) {
      cleanup();
      move_from(std::move(other));
    }
    return *this;
  }

  static bool probe_kernel_support() {
    struct io_uring_params p;
    std::memset(&p, 0, sizeof(p));
    int fd = static_cast<int>(syscall(__NR_io_uring_setup, 1, &p));
    if (fd >= 0) {
      close(fd);
      return true;
    }
    return false;
  }

  bool init(unsigned entries, unsigned desired_flags = 0) {
    cleanup();
    struct io_uring_params p;
    std::memset(&p, 0, sizeof(p));
    p.flags = desired_flags;

    // Try desired flags (e.g. SINGLE_ISSUER | CQSIZE)
    ring_fd = static_cast<int>(syscall(__NR_io_uring_setup, entries, &p));
    if (ring_fd < 0 && (desired_flags != 0)) {
      // Graceful degradation for older kernels (e.g. Linux 5.10 without SINGLE_ISSUER)
      std::memset(&p, 0, sizeof(p));
      ring_fd = static_cast<int>(syscall(__NR_io_uring_setup, entries, &p));
    }
    if (ring_fd < 0) {
      return false;
    }

    sq_entries = p.sq_entries;
    cq_entries = p.cq_entries;
    features = p.features;
    active_flags = p.flags;

    sq_ring_sz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    cq_ring_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);

    if (features & IORING_FEAT_SINGLE_MMAP) {
      if (cq_ring_sz > sq_ring_sz) sq_ring_sz = cq_ring_sz;
      cq_ring_sz = sq_ring_sz;
    }

    sq_ptr = mmap(0, sq_ring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                  ring_fd, IORING_OFF_SQ_RING);
    if (sq_ptr == MAP_FAILED) {
      sq_ptr = nullptr;
      close(ring_fd);
      ring_fd = -1;
      return false;
    }

    if (features & IORING_FEAT_SINGLE_MMAP) {
      cq_ptr = sq_ptr;
    } else {
      cq_ptr = mmap(0, cq_ring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                    ring_fd, IORING_OFF_CQ_RING);
      if (cq_ptr == MAP_FAILED) {
        cq_ptr = nullptr;
        munmap(sq_ptr, sq_ring_sz);
        sq_ptr = nullptr;
        close(ring_fd);
        ring_fd = -1;
        return false;
      }
    }

    uint8_t* sq_base = static_cast<uint8_t*>(sq_ptr);
    sq_khead = reinterpret_cast<unsigned*>(sq_base + p.sq_off.head);
    sq_ktail = reinterpret_cast<unsigned*>(sq_base + p.sq_off.tail);
    sq_kring_mask = reinterpret_cast<unsigned*>(sq_base + p.sq_off.ring_mask);
    sq_kflags = reinterpret_cast<unsigned*>(sq_base + p.sq_off.flags);
    sq_array = reinterpret_cast<unsigned*>(sq_base + p.sq_off.array);

    sqes_sz = p.sq_entries * sizeof(struct io_uring_sqe);
    void* sqes_ptr = mmap(0, sqes_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                          ring_fd, IORING_OFF_SQES);
    if (sqes_ptr == MAP_FAILED) {
      if (cq_ptr != sq_ptr && cq_ptr != nullptr) munmap(cq_ptr, cq_ring_sz);
      munmap(sq_ptr, sq_ring_sz);
      sq_ptr = nullptr;
      cq_ptr = nullptr;
      close(ring_fd);
      ring_fd = -1;
      return false;
    }
    sqes = static_cast<struct io_uring_sqe*>(sqes_ptr);

    uint8_t* cq_base = static_cast<uint8_t*>(cq_ptr);
    cq_khead = reinterpret_cast<unsigned*>(cq_base + p.cq_off.head);
    cq_ktail = reinterpret_cast<unsigned*>(cq_base + p.cq_off.tail);
    cq_kring_mask = reinterpret_cast<unsigned*>(cq_base + p.cq_off.ring_mask);
    cqes = reinterpret_cast<struct io_uring_cqe*>(cq_base + p.cq_off.cqes);

    sq_last_submitted = 0;
    return true;
  }

  unsigned sq_last_submitted{0};

  struct io_uring_sqe* get_sqe() {
    if (sq_khead == nullptr || sq_ktail == nullptr) return nullptr;
    unsigned head = __atomic_load_n(sq_khead, __ATOMIC_ACQUIRE);
    unsigned tail = *sq_ktail;
    if (tail - head >= sq_entries) return nullptr;
    unsigned idx = tail & *sq_kring_mask;
    struct io_uring_sqe* sqe = &sqes[idx];
    std::memset(sqe, 0, sizeof(*sqe));
    sq_array[idx] = idx;
    *sq_ktail = tail + 1;
    return sqe;
  }

  int submit() {
    if (ring_fd < 0 || sq_ktail == nullptr) return -1;
    unsigned tail = *sq_ktail;
    __atomic_store_n(sq_ktail, tail, __ATOMIC_RELEASE);
    unsigned to_submit = tail - sq_last_submitted;
    if (to_submit == 0) return 0;
    int ret = static_cast<int>(syscall(__NR_io_uring_enter, ring_fd, to_submit, 0, 0, nullptr));
    if (ret > 0) {
      sq_last_submitted += static_cast<unsigned>(ret);
    }
    return ret;
  }

  int submit_and_wait(unsigned wait_nr, int timeout_ms = 0) {
    if (ring_fd < 0 || sq_ktail == nullptr) return -1;
    unsigned tail = *sq_ktail;
    __atomic_store_n(sq_ktail, tail, __ATOMIC_RELEASE);
    unsigned to_submit = tail - sq_last_submitted;
    if (to_submit > 0) {
      int ret = static_cast<int>(syscall(__NR_io_uring_enter, ring_fd, to_submit, 0, 0, nullptr));
      if (ret > 0) {
        sq_last_submitted += static_cast<unsigned>(ret);
      }
    }
    if (wait_nr > 0 && timeout_ms > 0) {
      struct pollfd pfd;
      pfd.fd = ring_fd;
      pfd.events = POLLIN;
      pfd.revents = 0;
      return ::poll(&pfd, 1, timeout_ms);
    }
    return 0;
  }

  int wait_event(int timeout_ms) {
    if (ring_fd < 0 || timeout_ms <= 0) return 0;
    struct pollfd pfd;
    pfd.fd = ring_fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    return ::poll(&pfd, 1, timeout_ms);
  }

  int peek_batch_cqe(struct io_uring_cqe** out_cqes, unsigned count) {
    if (cq_khead == nullptr || cq_ktail == nullptr) return 0;
    unsigned head = *cq_khead;
    unsigned tail = __atomic_load_n(cq_ktail, __ATOMIC_ACQUIRE);
    unsigned available = tail - head;
    if (available == 0) return 0;
    if (count > available) count = available;
    for (unsigned i = 0; i < count; ++i) {
      out_cqes[i] = &cqes[(head + i) & *cq_kring_mask];
    }
    return static_cast<int>(count);
  }

  void cq_advance(unsigned count) {
    if (cq_khead != nullptr && count > 0) {
      __atomic_store_n(cq_khead, *cq_khead + count, __ATOMIC_RELEASE);
    }
  }

  void cleanup() {
    if (sqes != nullptr) {
      munmap(sqes, sqes_sz);
      sqes = nullptr;
    }
    if (cq_ptr != nullptr && cq_ptr != sq_ptr) {
      munmap(cq_ptr, cq_ring_sz);
      cq_ptr = nullptr;
    }
    if (sq_ptr != nullptr) {
      munmap(sq_ptr, sq_ring_sz);
      sq_ptr = nullptr;
    }
    cq_ptr = nullptr;
    if (ring_fd >= 0) {
      close(ring_fd);
      ring_fd = -1;
    }
    sq_entries = 0;
    cq_entries = 0;
    sq_last_submitted = 0;
  }

  bool is_active() const {
    return ring_fd >= 0 && sqes != nullptr;
  }

 private:
  void move_from(SamuraiUring&& o) noexcept {
    ring_fd = o.ring_fd;
    sq_entries = o.sq_entries;
    cq_entries = o.cq_entries;
    sq_last_submitted = o.sq_last_submitted;
    features = o.features;
    active_flags = o.active_flags;
    sq_khead = o.sq_khead;
    sq_ktail = o.sq_ktail;
    sq_kring_mask = o.sq_kring_mask;
    sq_kflags = o.sq_kflags;
    sq_array = o.sq_array;
    sqes = o.sqes;
    sq_ring_sz = o.sq_ring_sz;
    sqes_sz = o.sqes_sz;
    sq_ptr = o.sq_ptr;
    cq_khead = o.cq_khead;
    cq_ktail = o.cq_ktail;
    cq_kring_mask = o.cq_kring_mask;
    cqes = o.cqes;
    cq_ring_sz = o.cq_ring_sz;
    cq_ptr = o.cq_ptr;

    o.ring_fd = -1;
    o.sq_ptr = nullptr;
    o.cq_ptr = nullptr;
    o.sqes = nullptr;
    o.sq_entries = 0;
    o.cq_entries = 0;
    o.sq_last_submitted = 0;
  }
};

// Helper: prep connect
inline void prep_uring_connect(struct io_uring_sqe* sqe, int fd, const struct sockaddr* addr, socklen_t addrlen, uint64_t user_data) {
  sqe->opcode = IORING_OP_CONNECT;
  sqe->fd = fd;
  sqe->addr = reinterpret_cast<uint64_t>(addr);
  sqe->off = addrlen;
  sqe->user_data = user_data;
}

// Helper: prep send
inline void prep_uring_send(struct io_uring_sqe* sqe, int fd, const void* buf, size_t len, int flags, uint64_t user_data) {
  sqe->opcode = IORING_OP_SEND;
  sqe->fd = fd;
  sqe->addr = reinterpret_cast<uint64_t>(buf);
  sqe->len = static_cast<uint32_t>(len);
  sqe->msg_flags = static_cast<uint32_t>(flags);
  sqe->user_data = user_data;
}

// Helper: prep recv
inline void prep_uring_recv(struct io_uring_sqe* sqe, int fd, void* buf, size_t len, int flags, uint64_t user_data) {
  sqe->opcode = IORING_OP_RECV;
  sqe->fd = fd;
  sqe->addr = reinterpret_cast<uint64_t>(buf);
  sqe->len = static_cast<uint32_t>(len);
  sqe->msg_flags = static_cast<uint32_t>(flags);
  sqe->user_data = user_data;
}

// Helper: prep close
inline void prep_uring_close(struct io_uring_sqe* sqe, int fd, uint64_t user_data) {
  sqe->opcode = IORING_OP_CLOSE;
  sqe->fd = fd;
  sqe->user_data = user_data;
}

#endif  // SAMURAI_HAS_LINUX_IO_URING && __NR_io_uring_setup

}  // namespace ddos_samurai::l7_emu_native
