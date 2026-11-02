#include <arapuca/capture/capture_engine.hpp>
#include <arapuca/capture/hashing.hpp>
#include <arapuca/core/ids.hpp>
#include <arapuca/core/limits.hpp>
#include <arapuca/core/logging.hpp>
#include <arapuca/util/redaction.hpp>

#include <chrono>
#include <utility>

namespace arapuca::capture {
namespace {

using core::Event;
using core::EventType;

std::string name_from_url(const std::string& url) {
    const auto slash = url.find_last_of('/');
    std::string name = slash == std::string::npos ? url : url.substr(slash + 1);
    const auto query = name.find('?');
    if (query != std::string::npos) {
        name.erase(query);
    }
    return name.empty() ? "index" : name;
}

}  // namespace

CaptureEngine::CaptureEngine(const core::Config& config,
                             core::EventBus& bus,
                             const enrich::MitreMapper& mitre)
    : config_(&config),
      bus_(&bus),
      mitre_(&mitre),
      downloader_(DownloadLimits{config.capture.max_sample_bytes,
                                 limits::kDownloadTimeoutSeconds,
                                 limits::kConnectTimeoutSeconds,
                                 limits::kMaxRedirects}) {
    if (config.capture.enabled) {
        QuarantineConfig quarantine_config;
        quarantine_config.directory = config.capture.quarantine_dir;
        quarantine_config.password = config.capture.zip_password;
        quarantine_config.max_total_bytes = config.capture.quarantine_max_total_bytes;
        quarantine_config.max_files = config.capture.quarantine_max_files;
        quarantine_ = std::make_unique<Quarantine>(std::move(quarantine_config));
        // A cap lowered in the configuration takes effect now rather than
        // waiting for the next sample to arrive.
        (void)quarantine_->enforce_limits();
    }

    if (config.capture.virustotal_enabled && !config.virustotal_api_key.empty()) {
        VirusTotalConfig vt;
        vt.api_key = config.virustotal_api_key;
        vt.requests_per_minute = config.capture.vt_requests_per_minute;
        vt.requests_per_day = config.capture.vt_requests_per_day;
        vt.state_file = config.capture.quarantine_dir / ".virustotal-budget.json";
        virustotal_ = std::make_unique<VirusTotalClient>(std::move(vt));
    }
}

CaptureEngine::~CaptureEngine() {
    stop();
}

void CaptureEngine::start() {
    if (running_.exchange(true)) {
        return;
    }
    worker_ = std::thread([this] { worker_loop(); });
}

void CaptureEngine::stop() {
    if (!running_.exchange(false)) {
        return;
    }
    work_.notify_all();
    if (worker_.joinable()) {
        worker_.join();
    }
}

bool CaptureEngine::submit(CaptureJob job) {
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.size() >= kQueueCapacity) {
            ++dropped_;
            return false;
        }
        queue_.push_back(std::move(job));
    }
    work_.notify_one();
    return true;
}

std::size_t CaptureEngine::queued() const {
    const std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
}

void CaptureEngine::worker_loop() {
    while (running_) {
        CaptureJob job;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            work_.wait_for(lock, std::chrono::milliseconds{200}, [this] {
                return !queue_.empty() || !running_;
            });
            if (queue_.empty()) {
                continue;
            }
            job = std::move(queue_.front());
            queue_.pop_front();
        }

        try {
            process(job);
        } catch (const std::exception& error) {
            core::log().warn("capture of {} failed: {}", job.url, error.what());
        }
        ++processed_;
    }
}

void CaptureEngine::process(const CaptureJob& job) {
    Event event = Event::make(EventType::CaptureDownload, config_->sensor_name);
    event.session_id = job.session_id;
    event.src_ip = job.source_ip;
    event.detail["url"] = util::sanitize(job.url, limits::kMaxCaptureUrl).text;
    event.mitre = mitre_->match(EventType::CaptureDownload, job.url);

    const DownloadResult download = downloader_.fetch(job.url);
    event.detail["outcome"] = std::string(to_string(download.outcome));
    event.detail["http_status"] = download.http_status;
    if (!download.content_type.empty()) {
        event.detail["content_type"] = util::sanitize(download.content_type, 256).text;
    }
    if (!download.final_url.empty() && download.final_url != job.url) {
        event.detail["final_url"] = util::sanitize(download.final_url, limits::kMaxCaptureUrl).text;
    }

    if (download.outcome == DownloadOutcome::BlockedAddress) {
        // The most interesting failure there is. An attacker aiming at
        // 169.254.169.254 was trying to make the honeypot fetch its own cloud
        // credentials, and that attempt is worth more than most samples.
        event.detail["blocked_range"] = std::string(to_string(download.blocked));
        event.detail["error"] = download.error;
        (void)bus_->publish(std::move(event));
        core::log().warn("refused a capture of {}: {}", job.url, download.error);
        return;
    }

    if (!download.ok()) {
        if (!download.error.empty()) {
            event.detail["error"] = util::sanitize(download.error, 512).text;
        }
        (void)bus_->publish(std::move(event));
        return;
    }

    event.detail["size_bytes"] = download.body.size();

    if (quarantine_ == nullptr) {
        event.detail["quarantined"] = false;
        (void)bus_->publish(std::move(event));
        return;
    }

    const StoreResult stored = quarantine_->store(download.body, name_from_url(job.url));
    event.detail["sha256"] = stored.sha256;
    event.detail["md5"] = stored.md5;
    event.detail["quarantined"] = stored.stored;
    event.detail["duplicate"] = stored.duplicate;
    event.detail["stored_bytes"] = stored.stored_bytes;
    if (stored.evicted > 0) {
        event.detail["evicted"] = stored.evicted;
    }
    if (!stored.error.empty()) {
        event.detail["error"] = stored.error;
    }
    if (stored.stored && !stored.duplicate) {
        event.detail["quarantine_path"] = stored.path.filename().string();
    }

    const std::string sha256 = stored.sha256;
    const std::string session = job.session_id;
    const std::string source = job.source_ip;
    (void)bus_->publish(std::move(event));

    // A duplicate has already been looked up once, and the free tier budget
    // is small enough that spending it twice on the same hash is wasteful.
    if (virustotal_ == nullptr || sha256.empty() || stored.duplicate) {
        return;
    }

    const VtReport report = virustotal_->lookup(sha256);

    Event vt_event = Event::make(EventType::CaptureVtLookup, config_->sensor_name);
    vt_event.session_id = session;
    vt_event.src_ip = source;
    vt_event.detail = {{"sha256", sha256},
                       {"vt_status", std::string(to_string(report.status))},
                       {"vt_detections", report.detections},
                       {"vt_total_engines", report.total_engines}};
    if (!report.popular_label.empty()) {
        vt_event.detail["vt_popular_label"] = report.popular_label;
    }
    if (!report.first_seen.empty()) {
        vt_event.detail["vt_first_seen"] = report.first_seen;
    }
    if (!report.error.empty()) {
        vt_event.detail["error"] = util::sanitize(report.error, 512).text;
    }
    (void)bus_->publish(std::move(vt_event));
}

}  // namespace arapuca::capture
