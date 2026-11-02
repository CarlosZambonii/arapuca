// The worker that turns "an attacker typed wget" into a quarantined sample.
//
// It runs on its own thread with a bounded queue, and that separation is a
// security property rather than a performance one: a download that hangs for
// thirty seconds must not hold a session thread, because an attacker who can
// make the fake shell stall can measure it, and a honeypot that behaves
// differently from a real machine under load is a honeypot that got noticed.
//
// The pipeline is: refuse obvious nonsense, fetch with the isolated
// downloader, hash, quarantine, then look the hash up on VirusTotal. Every
// stage can fail, and every failure is an event.
#pragma once

#include <arapuca/capture/downloader.hpp>
#include <arapuca/capture/quarantine.hpp>
#include <arapuca/capture/virustotal.hpp>
#include <arapuca/core/config.hpp>
#include <arapuca/core/event_bus.hpp>
#include <arapuca/enrich/geoip.hpp>
#include <arapuca/enrich/mitre_mapper.hpp>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace arapuca::capture {

struct CaptureJob {
    std::string url;
    std::string session_id;
    std::string source_ip;
};

class CaptureEngine {
public:
    CaptureEngine(const core::Config& config,
                  core::EventBus& bus,
                  const enrich::MitreMapper& mitre);
    CaptureEngine(const CaptureEngine&) = delete;
    CaptureEngine& operator=(const CaptureEngine&) = delete;
    CaptureEngine(CaptureEngine&&) = delete;
    CaptureEngine& operator=(CaptureEngine&&) = delete;
    ~CaptureEngine();

    void start();
    void stop();

    /// Queue a URL. Never blocks and never fails loudly: a full queue drops
    /// the job and counts it, the same way the event bus does.
    bool submit(CaptureJob job);

    [[nodiscard]] std::size_t queued() const;

    [[nodiscard]] std::uint64_t dropped() const {
        return dropped_;
    }

    [[nodiscard]] std::uint64_t processed() const {
        return processed_;
    }

    /// Longest queue. A session loop could otherwise enqueue faster than the
    /// worker drains.
    static constexpr std::size_t kQueueCapacity = 256;

private:
    void worker_loop();
    void process(const CaptureJob& job);

    const core::Config* config_;
    core::EventBus* bus_;
    const enrich::MitreMapper* mitre_;

    Downloader downloader_;
    std::unique_ptr<Quarantine> quarantine_;
    std::unique_ptr<VirusTotalClient> virustotal_;

    mutable std::mutex mutex_;
    std::condition_variable work_;
    std::deque<CaptureJob> queue_;
    std::thread worker_;
    std::atomic<bool> running_{false};
    std::atomic<std::uint64_t> dropped_{0};
    std::atomic<std::uint64_t> processed_{0};
};

}  // namespace arapuca::capture
