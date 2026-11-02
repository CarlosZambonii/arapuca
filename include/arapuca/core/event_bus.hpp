// Bounded queue between the producers (SSH sessions, HTTP handlers, the
// capture worker) and the single writer thread.
//
// The bound is the point. Under a flood, an unbounded queue turns an attacker
// into an out of memory condition on a 1 GB machine. Here the queue refuses
// the event, counts the drop, and the honeypot keeps serving. Dropped counts
// are themselves reported in the lifecycle event, so a gap in telemetry is
// visible rather than silent.
#pragma once

#include <arapuca/core/event.hpp>

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <vector>

namespace arapuca::core {

class EventBus {
public:
    explicit EventBus(std::size_t capacity);

    EventBus(const EventBus&) = delete;
    EventBus& operator=(const EventBus&) = delete;
    EventBus(EventBus&&) = delete;
    EventBus& operator=(EventBus&&) = delete;
    ~EventBus() = default;

    /// Enqueue an event. Returns false when the queue is full or closed, in
    /// which case the event is dropped and the drop counter is incremented.
    /// Never blocks: a session thread must not be slowed by the writer.
    bool publish(Event event);

    /// Wait for up to `timeout` and move at most `max_events` into `out`.
    /// Returns the number moved. Returns 0 when the bus is closed and empty.
    std::size_t consume(std::vector<Event>& out,
                        std::size_t max_events,
                        std::chrono::milliseconds timeout);

    /// Wake every waiter and refuse further publishes. Idempotent.
    void close();

    [[nodiscard]] bool closed() const;
    [[nodiscard]] std::size_t size() const;

    [[nodiscard]] std::size_t capacity() const {
        return capacity_;
    }

    /// Events refused since start. Reported in the lifecycle event.
    [[nodiscard]] std::uint64_t dropped() const;

private:
    mutable std::mutex mutex_;
    std::condition_variable not_empty_;
    std::deque<Event> queue_;
    std::size_t capacity_;
    std::uint64_t dropped_ = 0;
    bool closed_ = false;
};

}  // namespace arapuca::core
