#pragma once

#include <cstdint>
#include <cstddef>
#include <atomic>
#include <array>
#include <type_traits>

namespace ddos_samurai::telecom {

template <typename T, size_t Capacity = 4096>
class alignas(64) RingBufferShuttle {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity 2'nin tam kuvveti olmalidir!");
    static_assert(Capacity > 0, "Capacity 0'dan buyuk olmalidir!");

public:
    RingBufferShuttle() noexcept : head_(0), tail_(0) {}
    ~RingBufferShuttle() = default;

    RingBufferShuttle(const RingBufferShuttle&) = delete;
    RingBufferShuttle& operator=(const RingBufferShuttle&) = delete;

    // Fastpath producer ekleme işlemi (SPSC Lock-Free)
    bool Enqueue(const T& item) noexcept {
        const size_t current_tail = tail_.load(std::memory_order_relaxed);
        const size_t current_head = head_.load(std::memory_order_acquire);

        if ((current_tail - current_head) >= Capacity) {
            return false; // Kuyruk dolu
        }

        buffer_[current_tail & MASK] = item;
        tail_.store(current_tail + 1, std::memory_order_release);
        return true;
    }

    // Slowpath consumer çekme işlemi (SPSC Lock-Free)
    bool Dequeue(T& item) noexcept {
        const size_t current_head = head_.load(std::memory_order_relaxed);
        const size_t current_tail = tail_.load(std::memory_order_acquire);

        if (current_head == current_tail) {
            return false; // Kuyruk boş
        }

        item = buffer_[current_head & MASK];
        head_.store(current_head + 1, std::memory_order_release);
        return true;
    }

    // Toplu mbuf burst ekleme (Fastpath burst batch)
    size_t EnqueueBurst(const T* items, size_t count) noexcept {
        const size_t current_tail = tail_.load(std::memory_order_relaxed);
        const size_t current_head = head_.load(std::memory_order_acquire);
        const size_t available = Capacity - (current_tail - current_head);
        const size_t to_write = (count < available) ? count : available;

        for (size_t i = 0; i < to_write; ++i) {
            buffer_[(current_tail + i) & MASK] = items[i];
        }

        if (to_write > 0) {
            tail_.store(current_tail + to_write, std::memory_order_release);
        }
        return to_write;
    }

    // Toplu burst çekme (Slowpath FSM batch)
    size_t DequeueBurst(T* items, size_t max_count) noexcept {
        const size_t current_head = head_.load(std::memory_order_relaxed);
        const size_t current_tail = tail_.load(std::memory_order_acquire);
        const size_t available = current_tail - current_head;
        const size_t to_read = (max_count < available) ? max_count : available;

        for (size_t i = 0; i < to_read; ++i) {
            items[i] = buffer_[(current_head + i) & MASK];
        }

        if (to_read > 0) {
            head_.store(current_head + to_read, std::memory_order_release);
        }
        return to_read;
    }

    size_t Size() const noexcept {
        const size_t h = head_.load(std::memory_order_relaxed);
        const size_t t = tail_.load(std::memory_order_relaxed);
        return (t >= h) ? (t - h) : 0;
    }

    bool IsEmpty() const noexcept {
        return head_.load(std::memory_order_relaxed) == tail_.load(std::memory_order_relaxed);
    }

    bool IsFull() const noexcept {
        return Size() >= Capacity;
    }

    constexpr size_t GetCapacity() const noexcept {
        return Capacity;
    }

private:
    static constexpr size_t MASK = Capacity - 1;

    // Sahte paylaşımı (False sharing) engellemek için producer ve consumer
    // işaretçileri ayrı önbellek çizgilerine (alignas(64)) ayrılmıştır.
    alignas(64) std::atomic<size_t> tail_{0}; // Producer yazar
    alignas(64) std::atomic<size_t> head_{0}; // Consumer okur

    alignas(64) T buffer_[Capacity];
};

} // namespace ddos_samurai::telecom
