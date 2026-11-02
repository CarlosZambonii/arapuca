// Where events end up: one JSON object per line, in a file the New Relic
// Infrastructure Agent tails.
//
// Rotation: the file is opened in append mode and can be reopened on demand.
// logrotate is configured with `create` plus a postrotate signal rather than
// `copytruncate`, because copytruncate races with an appending writer and can
// lose or duplicate the tail of the file. On the signal the sink calls
// reopen(), which closes the old descriptor and opens the path again.
#pragma once

#include <arapuca/core/event.hpp>

#include <cstdio>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>

namespace arapuca::core {

class EventSink {
public:
    EventSink() = default;
    EventSink(const EventSink&) = delete;
    EventSink& operator=(const EventSink&) = delete;
    EventSink(EventSink&&) = delete;
    EventSink& operator=(EventSink&&) = delete;
    virtual ~EventSink() = default;

    virtual void write(const Event& event) = 0;
    virtual void flush() = 0;
};

/// Appends one line per event to a file.
class JsonlFileSink final : public EventSink {
public:
    /// `flush_every` events, or every `flush_interval`, whichever comes first.
    /// A honeypot values not losing the last events before a crash more than
    /// it values write throughput, so the defaults are deliberately eager.
    JsonlFileSink(std::filesystem::path path,
                  std::size_t flush_every = 16,
                  std::chrono::milliseconds flush_interval = std::chrono::milliseconds{1000});
    ~JsonlFileSink() override;

    void write(const Event& event) override;
    void flush() override;

    /// Close and reopen the target path. Called after logrotate has moved the
    /// old file aside.
    void reopen();

    [[nodiscard]] const std::filesystem::path& path() const {
        return path_;
    }

    [[nodiscard]] std::uint64_t written() const;

private:
    void open_locked();

    mutable std::mutex mutex_;
    std::filesystem::path path_;
    std::FILE* file_ = nullptr;
    std::size_t flush_every_;
    std::chrono::milliseconds flush_interval_;
    std::size_t since_flush_ = 0;
    TimePoint last_flush_{};
    std::uint64_t written_ = 0;
};

}  // namespace arapuca::core
