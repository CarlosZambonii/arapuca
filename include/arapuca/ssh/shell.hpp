// The fake shell.
//
// It answers commands convincingly and executes nothing. Every response is
// produced from the in memory filesystem or from a fabricated string, and
// safety invariant S1 holds structurally rather than by review: there is no
// code path from here to a process.
//
// The design goal is a machine that rewards exploration. An attacker who
// reads /etc/passwd and then tries a user they found should get somewhere; one
// who runs `wget` should see a plausible download; one who types nonsense
// should get the same error bash gives. Anything that feels like a trap ends
// the session early and teaches us nothing.
#pragma once

#include <arapuca/ssh/command_line.hpp>
#include <arapuca/ssh/vfs.hpp>

#include <cstddef>
#include <functional>
#include <map>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace arapuca::ssh {

/// Everything one session knows about itself. Each session owns its own copy,
/// so a file an attacker creates is theirs alone and is gone afterwards.
struct ShellContext {
    std::string username = "root";
    std::string hostname = "srv-web-03";
    std::string cwd = "/root";
    Vfs vfs;
    std::vector<std::string> history;
    std::map<std::string, std::string> env;
    bool exit_requested = false;
    int last_status = 0;

    [[nodiscard]] std::string home() const;
    /// Resolve a path argument against the working directory.
    [[nodiscard]] std::string resolve(std::string_view path) const;
};

struct CommandOutcome {
    std::string output;
    int status = 0;
    /// False when no handler claimed the command, which is itself a high
    /// signal event: a command nobody has seen before is worth an alert.
    bool recognized = true;
    /// URLs the command referred to, handed to the capture engine. Extracting
    /// them here rather than re-parsing the line later keeps the knowledge of
    /// which arguments are URLs with the command that defines them.
    std::vector<std::string> urls;
};

using CommandHandler =
    std::function<CommandOutcome(ShellContext&, const std::vector<std::string>&)>;

class CommandRegistry {
public:
    /// Every command the fake shell knows.
    [[nodiscard]] static CommandRegistry standard();

    void add(std::string name, CommandHandler handler);
    [[nodiscard]] const CommandHandler* find(std::string_view name) const;
    [[nodiscard]] std::vector<std::string> names() const;

    [[nodiscard]] std::size_t size() const {
        return handlers_.size();
    }

private:
    std::unordered_map<std::string, CommandHandler> handlers_;
};

class Shell {
public:
    Shell(const CommandRegistry& registry, ShellContext context);

    struct Result {
        std::string output;
        /// The parsed line, kept for the transcript and for MITRE mapping.
        std::vector<Segment> segments;
        bool exit_requested = false;
        /// Commands no handler claimed.
        std::vector<std::string> unknown_commands;
        /// URLs seen anywhere in the line.
        std::vector<std::string> urls;
        int status = 0;
    };

    /// Run one line. Nothing is executed: this dispatches to handlers that
    /// fabricate output.
    Result execute(std::string_view line);

    [[nodiscard]] std::string prompt() const;

    [[nodiscard]] const ShellContext& context() const {
        return context_;
    }

    [[nodiscard]] ShellContext& context() {
        return context_;
    }

    /// Longest output returned for one line. A command that would produce more
    /// is cut, because the response is written to a socket the attacker
    /// controls the read side of.
    static constexpr std::size_t kMaxOutputBytes = std::size_t{64} * 1024;

private:
    const CommandRegistry* registry_;
    ShellContext context_;
};

/// The error a real bash gives, which is what makes an unknown command look
/// like a mistake rather than a trap.
[[nodiscard]] std::string command_not_found(std::string_view name);

}  // namespace arapuca::ssh
