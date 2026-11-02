// Arapuca honeypot daemon.
//
// Safety invariant S1: this process never executes anything an attacker sends.
// There is no call to system(), exec*(), popen() or fork() of a shell anywhere
// in this codebase, and scripts/check_no_exec.sh enforces that in CI.
//
// This file is the wiring. Everything it does is create collaborators, hand
// them to each other, and wait for a signal.

#include <arapuca/capture/capture_engine.hpp>
#include <arapuca/core/config.hpp>
#include <arapuca/core/event_bus.hpp>
#include <arapuca/core/event_sink.hpp>
#include <arapuca/core/logging.hpp>
#include <arapuca/enrich/geoip.hpp>
#include <arapuca/enrich/mitre_mapper.hpp>
#include <arapuca/http/http_service.hpp>
#include <arapuca/ssh/auth_policy.hpp>
#include <arapuca/ssh/shell.hpp>
#include <arapuca/ssh/ssh_service.hpp>
#include <arapuca/ssh/vfs.hpp>
#include <arapuca/version.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

// Set by the signal handlers, read by the main loop. A signal handler may
// only touch a lock free atomic of this kind, so these cannot be wrapped in
// anything nicer without breaking that rule.
// NOLINTBEGIN(cppcoreguidelines-avoid-non-const-global-variables)
std::atomic<bool> g_stop{false};
std::atomic<bool> g_reopen{false};

// NOLINTEND(cppcoreguidelines-avoid-non-const-global-variables)

extern "C" void handle_stop(int /*signal*/) {
    g_stop = true;
}

extern "C" void handle_reopen(int /*signal*/) {
    // SIGHUP after logrotate has moved the file aside. The sink reopens its
    // path on the main thread, not here.
    g_reopen = true;
}

void print_usage(std::ostream& out) {
    out << "Arapuca, a medium interaction SSH and HTTP honeypot.\n"
           "\n"
           "Usage:\n"
           "  arapucad [options]\n"
           "\n"
           "Options:\n"
           "  -c, --config <path>   Path to arapuca.yaml (default: config/arapuca.yaml)\n"
           "  -v, --version         Print the version and exit\n"
           "  -h, --help            Print this help and exit\n"
           "\n"
           "Signals:\n"
           "  SIGHUP                Reopen the event log, for logrotate\n"
           "  SIGINT, SIGTERM       Shut down\n"
           "\n"
           "Arapuca records attacker interactions and never executes them.\n";
}

/// Drain the bus into the sink until stopped. Runs on its own thread so no
/// session thread ever waits on a disk write.
void writer_loop(arapuca::core::EventBus& bus, arapuca::core::JsonlFileSink& sink) {
    std::vector<arapuca::core::Event> batch;
    while (!bus.closed() || bus.size() > 0) {
        batch.clear();
        if (bus.consume(batch, 256, std::chrono::milliseconds{200}) == 0) {
            continue;
        }
        for (const auto& event : batch) {
            sink.write(event);
        }
    }
    sink.flush();
}

void publish_lifecycle(arapuca::core::EventBus& bus,
                       const arapuca::core::Config& config,
                       std::string_view phase,
                       const arapuca::core::JsonlFileSink* sink) {
    auto event =
        arapuca::core::Event::make(arapuca::core::EventType::HoneypotLifecycle, config.sensor_name);
    event.detail = {{"phase", std::string(phase)},
                    {"version", std::string(arapuca::kVersion)},
                    {"dropped_events", bus.dropped()}};
    if (sink != nullptr) {
        event.detail["written_events"] = sink->written();
        event.detail["write_failures"] = sink->write_failures();
    }
    (void)bus.publish(std::move(event));
}

}  // namespace

int main(int argc, char** argv) {
    const std::span<char*> raw(argv, static_cast<std::size_t>(argc));
    std::string config_path = "config/arapuca.yaml";

    for (std::size_t i = 1; i < raw.size(); ++i) {
        const std::string_view argument(raw[i]);
        if (argument == "-h" || argument == "--help") {
            print_usage(std::cout);
            return 0;
        }
        if (argument == "-v" || argument == "--version") {
            std::cout << arapuca::build_banner() << '\n';
            return 0;
        }
        if ((argument == "-c" || argument == "--config") && i + 1 < raw.size()) {
            config_path = raw[++i];
            continue;
        }
        std::cerr << "unknown option: " << argument << "\n";
        print_usage(std::cerr);
        return 2;
    }

    try {
        auto config = arapuca::core::Config::load(config_path);
        arapuca::core::init_logging(config.logging.level, config.logging.file);
        arapuca::core::log().info("{}", arapuca::build_banner());
        arapuca::core::log().info("configuration: {}", config_path);

        for (const auto& note : config.validate_and_clamp()) {
            arapuca::core::log().warn("configuration clamped: {}", note);
        }

        // --- the event pipeline ------------------------------------------
        arapuca::core::EventBus bus(config.events.bus_capacity);
        arapuca::core::JsonlFileSink sink(
            config.events.path, config.events.flush_every, config.events.flush_interval);
        std::thread writer([&bus, &sink] { writer_loop(bus, sink); });

        // Closes the bus and joins the writer on every path out of this
        // function, including an exception thrown by a service that fails to
        // start. A std::thread destroyed while still joinable calls
        // std::terminate, which turns a readable startup error into an abort
        // with no message, and that is exactly how this was found.
        std::unique_ptr<std::thread, std::function<void(std::thread*)>> writer_guard(
            &writer, [&bus](std::thread* thread) {
                bus.close();
                if (thread->joinable()) {
                    thread->join();
                }
            });

        // --- enrichment ---------------------------------------------------
        const auto mitre = arapuca::enrich::MitreMapper::from_file(config.mitre.rules_file);
        arapuca::core::log().info("loaded {} MITRE rules", mitre.size());

        const auto geo = arapuca::enrich::GeoIp::open(config.geo.city_db, config.geo.asn_db);

        // --- capture ------------------------------------------------------
        arapuca::capture::CaptureEngine capture(config, bus, mitre);
        if (config.capture.enabled) {
            capture.start();
            arapuca::core::log().info("capture engine started, quarantine at {}",
                                      config.capture.quarantine_dir.string());
        }

        // --- SSH ----------------------------------------------------------
        const auto registry = arapuca::ssh::CommandRegistry::standard();
        const auto credentials = arapuca::ssh::AuthPolicy::from_file(config.ssh.credentials_file);
        const auto filesystem = arapuca::ssh::Vfs::from_file(config.ssh.filesystem_file);
        arapuca::core::log().info("loaded {} credentials and {} filesystem nodes",
                                  credentials.size(),
                                  filesystem.node_count());

        arapuca::ssh::SshDependencies ssh_deps;
        ssh_deps.config = &config;
        ssh_deps.bus = &bus;
        ssh_deps.registry = &registry;
        ssh_deps.auth = &credentials;
        ssh_deps.filesystem = &filesystem;
        ssh_deps.mitre = &mitre;
        ssh_deps.geo = &geo;
        ssh_deps.on_capture = [&capture](arapuca::ssh::CaptureRequest request) {
            // Queued, never fetched here. A download that hangs must not hold
            // a session thread, because an attacker can measure that.
            (void)capture.submit({std::move(request.url),
                                  std::move(request.session_id),
                                  std::move(request.source_ip)});
        };

        arapuca::ssh::SshService ssh(std::move(ssh_deps));
        if (config.ssh.enabled) {
            ssh.start();
        }

        // --- HTTP ----------------------------------------------------------
        arapuca::http::HttpDependencies http_deps;
        http_deps.config = &config;
        http_deps.bus = &bus;
        http_deps.mitre = &mitre;
        http_deps.geo = &geo;

        arapuca::http::HttpService http(http_deps);
        if (config.http.enabled) {
            http.start();
        }

        // --- signals --------------------------------------------------------
        // The previous handler is of no interest: this process installs them
        // once, at startup, and never restores them.
        (void)std::signal(SIGINT, handle_stop);
        (void)std::signal(SIGTERM, handle_stop);
        (void)std::signal(SIGHUP, handle_reopen);
        (void)std::signal(SIGPIPE, SIG_IGN);  // a closed attacker socket is routine

        publish_lifecycle(bus, config, "start", &sink);
        arapuca::core::log().info("arapuca is running, send SIGTERM to stop");

        while (!g_stop) {
            std::this_thread::sleep_for(std::chrono::milliseconds{250});
            if (g_reopen.exchange(false)) {
                sink.reopen();
                arapuca::core::log().info("reopened the event log after rotation");
            }
        }

        arapuca::core::log().info("shutting down");
        publish_lifecycle(bus, config, "stop", &sink);

        http.stop();
        ssh.stop();
        capture.stop();

        // Run the guard now rather than at scope exit, so everything queued
        // is on disk before the counters below are read. Resetting leaves it
        // empty, so it does not run a second time.
        writer_guard.reset();

        arapuca::core::log().info("wrote {} events, dropped {}, write failures {}",
                                  sink.written(),
                                  bus.dropped(),
                                  sink.write_failures());
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "arapuca failed to start: " << error.what() << "\n";
        return 1;
    }
}
