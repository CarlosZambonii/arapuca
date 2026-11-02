#include <arapuca/core/event_sink.hpp>

#include <stdexcept>
#include <system_error>
#include <utility>

namespace arapuca::core {

JsonlFileSink::JsonlFileSink(std::filesystem::path path, std::size_t flush_every,
                             std::chrono::milliseconds flush_interval)
    : path_(std::move(path)),
      flush_every_(flush_every == 0 ? 1 : flush_every),
      flush_interval_(flush_interval),
      last_flush_(Clock::now()) {
    const std::lock_guard<std::mutex> lock(mutex_);
    open_locked();
}

JsonlFileSink::~JsonlFileSink() {
    const std::lock_guard<std::mutex> lock(mutex_);
    if (file_ != nullptr) {
        std::fflush(file_);
        std::fclose(file_);
        file_ = nullptr;
    }
}

void JsonlFileSink::open_locked() {
    if (file_ != nullptr) {
        std::fflush(file_);
        std::fclose(file_);
        file_ = nullptr;
    }

    const std::filesystem::path parent = path_.parent_path();
    if (!parent.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
    }

    // Append mode, so a concurrent reader such as the New Relic agent and a
    // logrotate `create` never truncate what has already been written.
    file_ = std::fopen(path_.c_str(), "ae");
    if (file_ == nullptr) {
        throw std::runtime_error("cannot open event log: " + path_.string());
    }
}

void JsonlFileSink::write(const Event& event) {
    const std::string line = event.to_jsonl();

    const std::lock_guard<std::mutex> lock(mutex_);
    if (file_ == nullptr) {
        return;
    }

    // One fwrite per event. The line is built before the lock is taken, so
    // serialization never happens inside the critical section.
    std::fwrite(line.data(), 1, line.size(), file_);
    ++written_;
    ++since_flush_;

    const auto now = Clock::now();
    if (since_flush_ >= flush_every_ || now - last_flush_ >= flush_interval_) {
        std::fflush(file_);
        since_flush_ = 0;
        last_flush_ = now;
    }
}

void JsonlFileSink::flush() {
    const std::lock_guard<std::mutex> lock(mutex_);
    if (file_ != nullptr) {
        std::fflush(file_);
        since_flush_ = 0;
        last_flush_ = Clock::now();
    }
}

void JsonlFileSink::reopen() {
    const std::lock_guard<std::mutex> lock(mutex_);
    open_locked();
    since_flush_ = 0;
    last_flush_ = Clock::now();
}

std::uint64_t JsonlFileSink::written() const {
    const std::lock_guard<std::mutex> lock(mutex_);
    return written_;
}

}  // namespace arapuca::core
