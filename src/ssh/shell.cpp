#include <arapuca/ssh/shell.hpp>

#include <utility>

namespace arapuca::ssh {

std::string ShellContext::home() const {
    return username == "root" ? "/root" : "/home/" + username;
}

std::string ShellContext::resolve(std::string_view path) const {
    return Vfs::resolve(cwd, path).value_or(cwd);
}

void CommandRegistry::add(std::string name, CommandHandler handler) {
    handlers_.insert_or_assign(std::move(name), std::move(handler));
}

const CommandHandler* CommandRegistry::find(std::string_view name) const {
    const auto found = handlers_.find(std::string(name));
    return found == handlers_.end() ? nullptr : &found->second;
}

std::vector<std::string> CommandRegistry::names() const {
    std::vector<std::string> out;
    out.reserve(handlers_.size());
    for (const auto& [name, handler] : handlers_) {
        out.push_back(name);
    }
    return out;
}

std::string command_not_found(std::string_view name) {
    std::string message = "bash: ";
    message.append(name);
    message += ": command not found\n";
    return message;
}

/// BusyBox ash does not say "command not found": it says "not found", prefixed
/// with the shell's own argv[0], which on a logged in Telnet session is -sh.
/// The scripts that fingerprint an embedded device read exactly this.
std::string applet_not_found(std::string_view name) {
    std::string message = "-sh: ";
    message.append(name);
    message += ": not found\n";
    return message;
}

Shell::Shell(const CommandRegistry& registry, ShellContext context)
    : registry_(&registry), context_(std::move(context)) {
    if (context_.cwd.empty()) {
        context_.cwd = context_.home();
    }
    if (context_.env.empty()) {
        if (context_.persona == Persona::Busybox) {
            context_.env = {{"HOME", context_.cwd},
                            {"USER", context_.username},
                            {"SHELL", "/bin/sh"},
                            {"PATH", "/usr/sbin:/usr/bin:/sbin:/bin"},
                            {"PWD", context_.cwd}};
        } else {
            context_.env = {
                {"HOME", context_.home()},
                {"USER", context_.username},
                {"SHELL", "/bin/bash"},
                {"PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
                {"TERM", "xterm-256color"},
                {"LANG", "en_US.UTF-8"},
                {"PWD", context_.cwd}};
        }
    }
}

std::string Shell::prompt() const {
    const bool is_root = context_.username == "root";

    // BusyBox ash shows the working directory and a bare # or $, with none of
    // bash's user@host. It is the prompt a camera or a router gives, which is
    // what the Telnet persona is impersonating.
    if (context_.persona == Persona::Busybox) {
        std::string out = context_.cwd;
        out += is_root ? " # " : " $ ";
        return out;
    }

    std::string directory = context_.cwd;
    const std::string home = context_.home();
    if (directory == home) {
        directory = "~";
    } else if (directory.starts_with(home + "/")) {
        directory = "~" + directory.substr(home.size());
    }

    std::string out = context_.username;
    out += "@";
    out += context_.hostname;
    out += ":";
    out += directory;
    out += is_root ? "# " : "$ ";
    return out;
}

Shell::Result Shell::execute(std::string_view line) {
    Result result;

    const ParsedCommandLine parsed = parse_command_line(line);
    result.segments = parsed.segments;

    if (!parsed.segments.empty()) {
        context_.history.emplace_back(line);
        // The transcript is capped per session elsewhere; here the history
        // list is capped so a loop cannot grow it without bound.
        if (context_.history.size() > 1000) {
            context_.history.erase(context_.history.begin());
        }
    }

    for (const auto& segment : parsed.segments) {
        if (segment.argv.empty()) {
            continue;
        }

        // Separator semantics, as far as they are observable. && skips when
        // the previous command failed, || skips when it succeeded. Getting
        // this wrong is noticeable: a dropper that chains with && expects the
        // chain to stop.
        if (segment.separator == Separator::And && context_.last_status != 0) {
            continue;
        }
        if (segment.separator == Separator::Or && context_.last_status == 0) {
            continue;
        }

        const std::string& name = segment.argv.front();
        const CommandHandler* handler = registry_->find(name);

        CommandOutcome outcome;
        if (handler == nullptr) {
            outcome.output = context_.persona == Persona::Busybox ? applet_not_found(name)
                                                                  : command_not_found(name);
            outcome.status = 127;
            outcome.recognized = false;
            result.unknown_commands.push_back(name);
        } else {
            outcome = (*handler)(context_, segment.argv);
        }

        context_.last_status = outcome.status;
        result.status = outcome.status;

        for (auto& url : outcome.urls) {
            result.urls.push_back(std::move(url));
        }

        if (result.output.size() < kMaxOutputBytes) {
            const std::size_t room = kMaxOutputBytes - result.output.size();
            result.output.append(outcome.output, 0, room);
        }

        if (context_.exit_requested) {
            break;
        }
    }

    context_.env["PWD"] = context_.cwd;
    result.exit_requested = context_.exit_requested;
    return result;
}

}  // namespace arapuca::ssh
