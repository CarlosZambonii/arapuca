#include <arapuca/core/event_bus.hpp>

#include <utility>

namespace arapuca::core {

EventBus::EventBus(std::size_t capacity) : capacity_(capacity == 0 ? 1 : capacity) {}

bool EventBus::publish(Event event) {
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (closed_ || queue_.size() >= capacity_) {
            ++dropped_;
            return false;
        }
        queue_.push_back(std::move(event));
    }
    not_empty_.notify_one();
    return true;
}

std::size_t EventBus::consume(std::vector<Event>& out, std::size_t max_events,
                              std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    if (queue_.empty() && !closed_) {
        not_empty_.wait_for(lock, timeout, [this] { return !queue_.empty() || closed_; });
    }

    std::size_t moved = 0;
    while (moved < max_events && !queue_.empty()) {
        out.push_back(std::move(queue_.front()));
        queue_.pop_front();
        ++moved;
    }
    return moved;
}

void EventBus::close() {
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        closed_ = true;
    }
    not_empty_.notify_all();
}

bool EventBus::closed() const {
    const std::lock_guard<std::mutex> lock(mutex_);
    return closed_;
}

std::size_t EventBus::size() const {
    const std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}

std::uint64_t EventBus::dropped() const {
    const std::lock_guard<std::mutex> lock(mutex_);
    return dropped_;
}

}  // namespace arapuca::core
