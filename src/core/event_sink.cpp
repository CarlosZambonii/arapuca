#include <arapuca/core/event_sink.hpp>
#include <arapuca/core/logging.hpp>

#include <stdexcept>
#include <system_error>
#include <utility>

namespace arapuca::core {

namespace detail {

void FileCloser::operator()(std::FILE* file) const noexcept {
    if (file == nullptr) {
        return;
    }
    if (std::fclose(file) != 0) {
        // Close is where buffered data is finally written, so a failure here
        // can mean events that were accepted never reached the disk. It cannot
        // be thrown from, but it must not be invisible either.
        log().error("closing the event log failed, buffered events may be lost");
    }
}

}  // namespace detail

JsonlFileSink::JsonlFileSink(std::filesystem::path path,
                             std::size_t flush_every,
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
    if (file_) {
        if (std::fflush(file_.get()) != 0) {
            log().error("final flush of the event log failed");
        }
        file_.reset();
    }
}

void JsonlFileSink::open_locked() {
    file_.reset();

    const std::filesystem::path parent = path_.parent_path();
    if (!parent.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
    }

    // Append mode, so a concurrent reader such as the New Relic agent and a
    // logrotate `create` never truncate what has already been written. The "e"
    // mode flag closes the descriptor on exec, which matters because this
    // process will later hold attacker data in it.
    file_.reset(std::fopen(path_.c_str(), "ae"));
    if (!file_) {
        throw std::runtime_error("cannot open event log: " + path_.string());
    }
}

void JsonlFileSink::write(const Event& event) {
    const std::string line = event.to_jsonl();

    const std::lock_guard<std::mutex> lock(mutex_);
    if (!file_) {
        return;
    }

    // One fwrite per event. The line is built before the lock is taken, so
    // serialization never happens inside the critical section.
    const std::size_t produced = std::fwrite(line.data(), 1, line.size(), file_.get());
    if (produced != line.size()) {
        // A short write is a truncated JSON line, which breaks the one event
        // per line contract the log shipper relies on. Count it, and say so
        // the first time and then rarely, so a full disk does not turn into a
        // second flood in the operator log.
        ++write_failures_;
        if (write_failures_ == 1 || write_failures_ % 1000 == 0) {
            log().error("short write to the event log ({} of {} bytes), {} failures so far",
                        produced,
                        line.size(),
                        write_failures_);
        }
        std::clearerr(file_.get());
        return;
    }

    ++written_;
    ++since_flush_;

    const auto now = Clock::now();
    if (since_flush_ >= flush_every_ || now - last_flush_ >= flush_interval_) {
        if (std::fflush(file_.get()) != 0) {
            ++write_failures_;
            log().error("flushing the event log failed");
        }
        since_flush_ = 0;
        last_flush_ = now;
    }
}

void JsonlFileSink::flush() {
    const std::lock_guard<std::mutex> lock(mutex_);
    if (file_) {
        if (std::fflush(file_.get()) != 0) {
            ++write_failures_;
            log().error("flushing the event log failed");
        }
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

std::uint64_t JsonlFileSink::write_failures() const {
    const std::lock_guard<std::mutex> lock(mutex_);
    return write_failures_;
}

}  // namespace arapuca::core
