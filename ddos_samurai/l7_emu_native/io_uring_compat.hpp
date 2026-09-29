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

// Enablement is driven by two signals kept in lockstep so the CMake STATUS
// messages actually reflect what gets compiled:
//   * SAMURAI_WITH_IO_URING / SAMURAI_WITH_LIBURING - defined by CMakeLists.txt
//     when it detects liburing or <linux/io_uring.h>.
//   * self-detection via __has_include - so unit-test and ad-hoc builds that do
//     not go through CMake still get the native ring.
// Either signal pulls in the header and defines SAMURAI_HAS_LINUX_IO_URING, the
// single macro the rest of the engine keys off.
#if defined(__has_include)
#  if __has_include(<linux/io_uring.h>)
#    include <linux/io_uring.h>
#    ifndef SAMURAI_HAS_LINUX_IO_URING
#      define SAMURAI_HAS_LINUX_IO_URING 1
#    endif
#  endif
#endif
#if defined(SAMURAI_WITH_IO_URING) && !defined(SAMURAI_HAS_LINUX_IO_URING)
#  include <linux/io_uring.h>
#  define SAMURAI_HAS_LINUX_IO_URING 1
#endif

namespace ddos_samurai::l7_emu_native {

#if defined(SAMURAI_HAS_LINUX_IO_URING) && defined(__NR_io_uring_setup)

// Setup flags that may be absent on the build kernel's headers: fold them to 0
// so masking/peeling logic stays valid without a thicket of #ifdefs.
#ifdef IORING_SETUP_SQPOLL
inline constexpr unsigned kUringSetupSqpoll = IORING_SETUP_SQPOLL;
#else
inline constexpr unsigned kUringSetupSqpoll = 0u;
#endif
#ifdef IORING_SETUP_CQSIZE
inline constexpr unsigned kUringSetupCqsize = IORING_SETUP_CQSIZE;
#else
inline constexpr unsigned kUringSetupCqsize = 0u;
#endif
#ifdef IORING_SETUP_SINGLE_ISSUER
inline constexpr unsigned kUringSetupSingleIssuer = IORING_SETUP_SINGLE_ISSUER;
#else
inline constexpr unsigned kUringSetupSingleIssuer = 0u;
#endif

enum class IoUringOp : uint8_t {
  None = 0,
  Connect = 1,
  Send = 2,
  Recv = 3,
  Close = 4,
  // Readiness poll used by the TLS/HTTP-2 and QUIC/HTTP-3 paths, where the data
  // transfer itself runs through SSL_read/write or the QUIC stack rather than
  // raw ring send/recv. The ring only delivers the wakeup.
  PollReadiness = 5,
  // HTTP/2 ring byte-path completions. Their lane_idx addresses the h2_sessions
  // vector (a different namespace from the H1 lane ops above), so the reactor
  // must dispatch these before the h1_lanes bound check.
  H2Send = 6,
  H2Recv = 7,
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

  // Provided buffer ring (kernel-selected buffers for multishot recv).
  struct io_uring_buf_ring* buf_ring{nullptr};
  void* buf_ring_mem{nullptr};
  size_t buf_ring_mem_sz{0};
  void* buf_pool{nullptr};
  size_t buf_pool_sz{0};
  unsigned buf_ring_entries{0};
  unsigned buf_ring_mask{0};
  size_t buf_entry_size{0};
  unsigned buf_tail{0};
  uint16_t buf_ring_bgid{0};
  bool buf_ring_registered{false};

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

  bool init(unsigned entries, unsigned desired_flags = 0, unsigned desired_cq_entries = 0) {
    cleanup();

    // IORING_SETUP_CQSIZE REQUIRES a non-zero cq_entries; the old code set the
    // flag but left cq_entries at 0, so the kernel rejected the first setup and
    // the single fallback dropped ALL flags at once (SINGLE_ISSUER included).
    // Instead peel one capability at a time so we keep the strongest feature set
    // the running kernel actually supports: SQPOLL first (needs privileges),
    // then CQSIZE, then SINGLE_ISSUER, finally a bare ring.
    const unsigned cq_req = desired_cq_entries != 0 ? desired_cq_entries : entries * 2;

    unsigned attempt_flags[4];
    unsigned attempt_cq[4];
    int attempts = 0;
    auto push_attempt = [&](unsigned f) {
      attempt_flags[attempts] = f;
      attempt_cq[attempts] = (f & kUringSetupCqsize) != 0 ? cq_req : 0u;
      ++attempts;
    };
    push_attempt(desired_flags);
    if ((desired_flags & kUringSetupSqpoll) != 0) {
      push_attempt(desired_flags & ~kUringSetupSqpoll);
    }
    if ((desired_flags & kUringSetupCqsize) != 0) {
      push_attempt(desired_flags & ~(kUringSetupSqpoll | kUringSetupCqsize));
    }
    if (desired_flags != 0) {
      push_attempt(0u);
    }

    struct io_uring_params p;
    bool created = false;
    for (int i = 0; i < attempts; ++i) {
      std::memset(&p, 0, sizeof(p));
      p.flags = attempt_flags[i];
      if ((attempt_flags[i] & kUringSetupCqsize) != 0) {
        p.cq_entries = attempt_cq[i];
      }
      ring_fd = static_cast<int>(syscall(__NR_io_uring_setup, entries, &p));
      if (ring_fd >= 0) {
        created = true;
        break;
      }
    }
    if (!created) {
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

  // With SQPOLL a kernel thread drains the SQ on its own; we only need to enter
  // to wake it when it has parked (IORING_SQ_NEED_WAKEUP). Returns false for the
  // common non-SQPOLL case.
  bool sqpoll_needs_wakeup() const {
    if ((active_flags & kUringSetupSqpoll) == 0 || sq_kflags == nullptr) {
      return false;
    }
    return (__atomic_load_n(sq_kflags, __ATOMIC_ACQUIRE) & IORING_SQ_NEED_WAKEUP) != 0;
  }

  int submit() {
    if (ring_fd < 0 || sq_ktail == nullptr) return -1;
    unsigned tail = *sq_ktail;
    __atomic_store_n(sq_ktail, tail, __ATOMIC_RELEASE);
    unsigned to_submit = tail - sq_last_submitted;

    if ((active_flags & kUringSetupSqpoll) != 0) {
      // The SQ poll thread consumes entries up to the tail we just published;
      // only enter (with SQ_WAKEUP) if it has gone to sleep.
      if (sqpoll_needs_wakeup()) {
        (void)syscall(__NR_io_uring_enter, ring_fd, 0, 0, IORING_ENTER_SQ_WAKEUP, nullptr);
      }
      sq_last_submitted = tail;
      return static_cast<int>(to_submit);
    }

    if (to_submit == 0) return 0;
    int ret = static_cast<int>(syscall(__NR_io_uring_enter, ring_fd, to_submit, 0, 0, nullptr));
    if (ret > 0) {
      sq_last_submitted += static_cast<unsigned>(ret);
    }
    return ret;
  }

  // Submit pending SQEs and block in the kernel until at least min_complete CQEs
  // are ready or timeout_ms elapses, in a single io_uring_enter(GETEVENTS) call
  // when the kernel advertises EXT_ARG. This replaces the submit()+poll()+peek
  // three-syscall dance with one syscall on the hot path. Falls back to the
  // poll()-based wait on older kernels.
  int submit_and_wait_cqes(unsigned min_complete, int timeout_ms) {
    int submitted = submit();
    if (ring_fd < 0) return submitted < 0 ? submitted : -1;
    if (min_complete == 0) return submitted;

    if ((features & IORING_FEAT_EXT_ARG) != 0 && timeout_ms >= 0) {
      struct __kernel_timespec ts;
      ts.tv_sec = timeout_ms / 1000;
      ts.tv_nsec = static_cast<long long>(timeout_ms % 1000) * 1000000LL;
      struct io_uring_getevents_arg arg;
      std::memset(&arg, 0, sizeof(arg));
      arg.ts = reinterpret_cast<uint64_t>(&ts);
      unsigned enter_flags = IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG;
      if (sqpoll_needs_wakeup()) {
        enter_flags |= IORING_ENTER_SQ_WAKEUP;
      }
      return static_cast<int>(syscall(__NR_io_uring_enter, ring_fd, 0u, min_complete,
                                      enter_flags, &arg, sizeof(arg)));
    }
    // Legacy fallback: poll the ring fd for readiness.
    return wait_event(timeout_ms);
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

  // ---- Provided buffer ring (for multishot recv) --------------------------
  // NOTE: IORING_REGISTER_PBUF_RING is an enumerator, not a macro, so it cannot
  // be probed with defined(). Gate on the recv-multishot / buffer-select MACROS
  // instead - a header new enough to define those also carries the PBUF_RING
  // enum and the io_uring_buf* structs (all landed together, Linux ~5.19-5.20).
#if defined(__NR_io_uring_register) && defined(IORING_RECV_MULTISHOT) && defined(IOSQE_BUFFER_SELECT)
  // Register a kernel buffer-selection ring of `entries` (must be a power of
  // two) buffers of `entry_size` bytes each under group id `bgid`. Once armed,
  // a BUFFER_SELECT recv lets the kernel pick a free buffer and report its id in
  // the CQE, which is what makes a single multishot recv able to fan a stream of
  // reads into distinct buffers without a per-read SQE.
  bool setup_buf_ring(uint16_t bgid, unsigned entries, size_t entry_size) {
    if (ring_fd < 0 || entries == 0 || (entries & (entries - 1)) != 0 || entry_size == 0) {
      return false;
    }
    const size_t ring_sz = static_cast<size_t>(entries) * sizeof(struct io_uring_buf);
    void* rmem = mmap(nullptr, ring_sz, PROT_READ | PROT_WRITE,
                      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (rmem == MAP_FAILED) {
      return false;
    }
    std::memset(rmem, 0, ring_sz);
    const size_t pool_sz = static_cast<size_t>(entries) * entry_size;
    void* pool = mmap(nullptr, pool_sz, PROT_READ | PROT_WRITE,
                      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (pool == MAP_FAILED) {
      munmap(rmem, ring_sz);
      return false;
    }

    struct io_uring_buf_reg reg;
    std::memset(&reg, 0, sizeof(reg));
    reg.ring_addr = reinterpret_cast<uint64_t>(rmem);
    reg.ring_entries = entries;
    reg.bgid = bgid;
    if (syscall(__NR_io_uring_register, ring_fd, IORING_REGISTER_PBUF_RING, &reg, 1) < 0) {
      munmap(rmem, ring_sz);
      munmap(pool, pool_sz);
      return false;
    }

    buf_ring = static_cast<struct io_uring_buf_ring*>(rmem);
    buf_ring_mem = rmem;
    buf_ring_mem_sz = ring_sz;
    buf_pool = pool;
    buf_pool_sz = pool_sz;
    buf_ring_entries = entries;
    buf_ring_mask = entries - 1;
    buf_entry_size = entry_size;
    buf_ring_bgid = bgid;
    buf_ring_registered = true;

    for (unsigned i = 0; i < entries; ++i) {
      struct io_uring_buf* b = &buf_ring->bufs[i & buf_ring_mask];
      b->addr = reinterpret_cast<uint64_t>(static_cast<uint8_t*>(buf_pool) +
                                           static_cast<size_t>(i) * entry_size);
      b->len = static_cast<uint32_t>(entry_size);
      b->bid = static_cast<uint16_t>(i);
    }
    buf_tail = entries;
    __atomic_store_n(&buf_ring->tail, static_cast<uint16_t>(buf_tail), __ATOMIC_RELEASE);
    return true;
  }

  bool buf_ring_active() const { return buf_ring_registered && buf_ring != nullptr; }

  void* buf_ring_addr(uint16_t bid) const {
    if (!buf_ring_registered || bid >= buf_ring_entries) return nullptr;
    return static_cast<uint8_t*>(buf_pool) + static_cast<size_t>(bid) * buf_entry_size;
  }

  // Hand a consumed buffer back to the kernel so a later recv can reuse it.
  void buf_ring_recycle(uint16_t bid) {
    if (!buf_ring_registered || bid >= buf_ring_entries) return;
    struct io_uring_buf* b = &buf_ring->bufs[buf_tail & buf_ring_mask];
    b->addr = reinterpret_cast<uint64_t>(buf_ring_addr(bid));
    b->len = static_cast<uint32_t>(buf_entry_size);
    b->bid = bid;
    ++buf_tail;
    __atomic_store_n(&buf_ring->tail, static_cast<uint16_t>(buf_tail), __ATOMIC_RELEASE);
  }

  static uint16_t cqe_buffer_id(const struct io_uring_cqe* cqe) {
    return static_cast<uint16_t>(cqe->flags >> IORING_CQE_BUFFER_SHIFT);
  }
  static bool cqe_has_buffer(const struct io_uring_cqe* cqe) {
    return (cqe->flags & IORING_CQE_F_BUFFER) != 0;
  }
  static bool cqe_has_more(const struct io_uring_cqe* cqe) {
    return (cqe->flags & IORING_CQE_F_MORE) != 0;
  }

  void teardown_buf_ring() {
    if (buf_ring_registered && ring_fd >= 0) {
      struct io_uring_buf_reg reg;
      std::memset(&reg, 0, sizeof(reg));
      reg.bgid = buf_ring_bgid;
      (void)syscall(__NR_io_uring_register, ring_fd, IORING_UNREGISTER_PBUF_RING, &reg, 1);
    }
    buf_ring_registered = false;
    buf_ring = nullptr;
    if (buf_ring_mem != nullptr) {
      munmap(buf_ring_mem, buf_ring_mem_sz);
      buf_ring_mem = nullptr;
    }
    if (buf_pool != nullptr) {
      munmap(buf_pool, buf_pool_sz);
      buf_pool = nullptr;
    }
    buf_ring_mem_sz = 0;
    buf_pool_sz = 0;
    buf_ring_entries = 0;
    buf_ring_mask = 0;
    buf_entry_size = 0;
    buf_tail = 0;
  }
#else
  bool setup_buf_ring(uint16_t, unsigned, size_t) { return false; }
  bool buf_ring_active() const { return false; }
  void* buf_ring_addr(uint16_t) const { return nullptr; }
  void buf_ring_recycle(uint16_t) {}
  static uint16_t cqe_buffer_id(const struct io_uring_cqe*) { return 0; }
  static bool cqe_has_buffer(const struct io_uring_cqe*) { return false; }
  static bool cqe_has_more(const struct io_uring_cqe* cqe) {
    return (cqe->flags & IORING_CQE_F_MORE) != 0;
  }
  void teardown_buf_ring() {}
#endif

  void cleanup() {
    teardown_buf_ring();
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

    buf_ring = o.buf_ring;
    buf_ring_mem = o.buf_ring_mem;
    buf_ring_mem_sz = o.buf_ring_mem_sz;
    buf_pool = o.buf_pool;
    buf_pool_sz = o.buf_pool_sz;
    buf_ring_entries = o.buf_ring_entries;
    buf_ring_mask = o.buf_ring_mask;
    buf_entry_size = o.buf_entry_size;
    buf_tail = o.buf_tail;
    buf_ring_bgid = o.buf_ring_bgid;
    buf_ring_registered = o.buf_ring_registered;

    o.ring_fd = -1;
    o.sq_ptr = nullptr;
    o.cq_ptr = nullptr;
    o.sqes = nullptr;
    o.sq_entries = 0;
    o.cq_entries = 0;
    o.sq_last_submitted = 0;

    o.buf_ring = nullptr;
    o.buf_ring_mem = nullptr;
    o.buf_ring_mem_sz = 0;
    o.buf_pool = nullptr;
    o.buf_pool_sz = 0;
    o.buf_ring_entries = 0;
    o.buf_ring_mask = 0;
    o.buf_entry_size = 0;
    o.buf_tail = 0;
    o.buf_ring_registered = false;
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

#if defined(IORING_RECV_MULTISHOT) && defined(IOSQE_BUFFER_SELECT)
// Helper: prep a multishot recv that draws buffers from a provided buffer ring
// (group bgid). One SQE keeps producing CQEs - each carrying the id of the
// buffer the kernel filled - until the stream ends or buffers are exhausted
// (-ENOBUFS), marking every continuation CQE with IORING_CQE_F_MORE. get_sqe()
// zeroes the SQE, so buffer selection and multishot are set from a clean slate.
inline void prep_uring_recv_multishot(struct io_uring_sqe* sqe, int fd, uint16_t bgid,
                                      uint64_t user_data) {
  sqe->opcode = IORING_OP_RECV;
  sqe->fd = fd;
  sqe->addr = 0;
  sqe->len = 0;
  sqe->msg_flags = 0;
  sqe->ioprio = IORING_RECV_MULTISHOT;
  sqe->flags = IOSQE_BUFFER_SELECT;
  sqe->buf_group = bgid;
  sqe->user_data = user_data;
}
#endif

// Helper: prep a readiness poll. Used to drive TLS/HTTP-2 sockets (SSL_read /
// SSL_write) and QUIC/HTTP-3 UDP sockets through the ring without moving their
// byte transfer onto raw send/recv SQEs. When multishot is requested the kernel
// keeps re-arming the poll and marks every intermediate CQE with
// IORING_CQE_F_MORE (see IORING_POLL_ADD_MULTI); the caller re-arms once a CQE
// arrives without F_MORE.
inline void prep_uring_poll_add(struct io_uring_sqe* sqe, int fd, uint32_t poll_mask,
                                bool multishot, uint64_t user_data) {
  sqe->opcode = IORING_OP_POLL_ADD;
  sqe->fd = fd;
  sqe->poll32_events = poll_mask;
#ifdef IORING_POLL_ADD_MULTI
  sqe->len = multishot ? IORING_POLL_ADD_MULTI : 0u;
#else
  (void)multishot;
  sqe->len = 0u;
#endif
  sqe->user_data = user_data;
}

// Helper: prep poll cancellation, keyed on the original poll's user_data.
inline void prep_uring_poll_remove(struct io_uring_sqe* sqe, uint64_t target_user_data,
                                   uint64_t user_data) {
  sqe->opcode = IORING_OP_POLL_REMOVE;
  sqe->addr = target_user_data;
  sqe->user_data = user_data;
}

// Helper: prep recvmsg (datagram receive for the QUIC/HTTP-3 UDP path).
inline void prep_uring_recvmsg(struct io_uring_sqe* sqe, int fd, struct msghdr* msg,
                               unsigned flags, uint64_t user_data) {
  sqe->opcode = IORING_OP_RECVMSG;
  sqe->fd = fd;
  sqe->addr = reinterpret_cast<uint64_t>(msg);
  sqe->len = 1;
  sqe->msg_flags = flags;
  sqe->user_data = user_data;
}

// Helper: prep sendmsg (datagram send for the QUIC/HTTP-3 UDP path).
inline void prep_uring_sendmsg(struct io_uring_sqe* sqe, int fd, const struct msghdr* msg,
                               unsigned flags, uint64_t user_data) {
  sqe->opcode = IORING_OP_SENDMSG;
  sqe->fd = fd;
  sqe->addr = reinterpret_cast<uint64_t>(msg);
  sqe->len = 1;
  sqe->msg_flags = flags;
  sqe->user_data = user_data;
}

#endif  // SAMURAI_HAS_LINUX_IO_URING && __NR_io_uring_setup

}  // namespace ddos_samurai::l7_emu_native
