#include <arapuca/telnet/busybox.hpp>

#include <string>
#include <string_view>
#include <vector>

namespace arapuca::telnet {

using ssh::CommandOutcome;
using ssh::CommandRegistry;
using ssh::ShellContext;

namespace {

std::string basename_of(std::string_view path) {
    const auto slash = path.find_last_of('/');
    return slash == std::string_view::npos ? std::string(path)
                                           : std::string(path.substr(slash + 1));
}

bool is_flag(const std::string& token) {
    return token.size() >= 2 && token[0] == '-';
}

// The Mirai fingerprint. A bot runs `/bin/busybox <TOKEN>` with a random token
// and reads the stream back for "<TOKEN>: applet not found", which is how a
// real BusyBox answers an applet it does not have. Getting this wrong is the
// single most likely way a bot decides the host is a decoy and leaves.
CommandOutcome cmd_busybox(ShellContext& /*context*/, const std::vector<std::string>& argv) {
    CommandOutcome outcome;
    if (argv.size() < 2) {
        outcome.output =
            "BusyBox v1.19.4 (2018-11-15 13:19:42 CST) multi-call binary.\n"
            "Usage: busybox [function [arguments]...]\n";
        return outcome;
    }
    const std::string& applet = argv[1];
    outcome.output = applet + ": applet not found\n";
    outcome.status = 127;
    return outcome;
}

// tftp -g -r <file> <host>, the other way Mirai pulls its payload. The scheme
// is not in the arguments, so the host and file are stitched into a tftp URL
// and handed to the same capture path wget uses.
CommandOutcome cmd_tftp(ShellContext& context, const std::vector<std::string>& argv) {
    CommandOutcome outcome;
    std::string remote;
    std::string host;
    for (std::size_t i = 1; i < argv.size(); ++i) {
        const std::string& token = argv[i];
        if (token == "-r" && i + 1 < argv.size()) {
            remote = argv[++i];
        } else if (token == "-g" || token == "-l" || token == "-p") {
            continue;
        } else if (!is_flag(token)) {
            host = token;  // the trailing operand is the server
        }
    }
    if (!host.empty() && !remote.empty()) {
        const std::string url = "tftp://" + host + "/" + remote;
        outcome.urls.push_back(url);
        (void)context.vfs.create_file(context.resolve(basename_of(remote)), "");
    }
    return outcome;
}

// ftpget host local remote, likewise.
CommandOutcome cmd_ftpget(ShellContext& context, const std::vector<std::string>& argv) {
    CommandOutcome outcome;
    std::vector<std::string> operands;
    for (std::size_t i = 1; i < argv.size(); ++i) {
        if (!is_flag(argv[i])) {
            operands.push_back(argv[i]);
        }
    }
    if (operands.size() >= 2) {
        const std::string& host = operands[0];
        const std::string& remote = operands.size() >= 3 ? operands[2] : operands[1];
        outcome.urls.push_back("ftp://" + host + "/" + remote);
        (void)context.vfs.create_file(context.resolve(basename_of(operands[1])), "");
    }
    return outcome;
}

// An embedded uname, so a bot that checks the kernel before fetching an
// architecture specific payload sees armv7l rather than an Ubuntu x86_64.
CommandOutcome cmd_uname(ShellContext& /*context*/, const std::vector<std::string>& argv) {
    CommandOutcome outcome;
    const bool all = argv.size() > 1;
    if (all) {
        outcome.output =
            "Linux router 3.10.14 #1 SMP PREEMPT Thu Nov 15 13:19:42 CST 2018 armv7l GNU/Linux\n";
    } else {
        outcome.output = "Linux\n";
    }
    return outcome;
}

// The bots try several ways to drop from the Telnet menu into a shell. On a
// device that already dropped them into one, these do nothing and succeed, so
// the script carries on to the download it was always going to attempt.
CommandOutcome cmd_noop_ok(ShellContext& /*context*/, const std::vector<std::string>& /*argv*/) {
    return CommandOutcome{};
}

}  // namespace

CommandRegistry busybox_registry() {
    // Start from the full command set so the ordinary reconnaissance a bot
    // does, ls and cat and ps, still answers, then replace the handlers an
    // embedded device gives differently.
    CommandRegistry registry = CommandRegistry::standard();

    registry.add("busybox", cmd_busybox);
    registry.add("/bin/busybox", cmd_busybox);
    registry.add("tftp", cmd_tftp);
    registry.add("ftpget", cmd_ftpget);
    registry.add("uname", cmd_uname);

    for (const char* escalation : {"enable", "system", "shell", "linuxshell"}) {
        registry.add(escalation, cmd_noop_ok);
    }

    return registry;
}

std::string busybox_shell_banner() {
    return "\r\nBusyBox v1.19.4 (2018-11-15 13:19:42 CST) built-in shell (ash)\r\n"
           "Enter 'help' for a list of built-in commands.\r\n\r\n";
}

}  // namespace arapuca::telnet
