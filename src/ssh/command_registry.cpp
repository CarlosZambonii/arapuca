// The commands the fake shell answers.
//
// Each handler fabricates output. None of them runs anything, reads a real
// file, or opens a socket. The wget and curl handlers record the URL they were
// given and hand it to the capture engine, which does the download later, in
// isolation, on another thread.
//
// Plausibility is a security property here. An attacker who senses a honeypot
// disconnects, and a session that ends at the first command is a session that
// taught us nothing.

#include <arapuca/ssh/shell.hpp>

#include <algorithm>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace arapuca::ssh {
namespace {

CommandOutcome ok(std::string output = {}) {
    CommandOutcome outcome;
    outcome.output = std::move(output);
    return outcome;
}

CommandOutcome fail(std::string output, int status = 1) {
    CommandOutcome outcome;
    outcome.output = std::move(output);
    outcome.status = status;
    return outcome;
}

/// Arguments that are not option flags.
std::vector<std::string> operands(const std::vector<std::string>& argv) {
    std::vector<std::string> out;
    for (std::size_t i = 1; i < argv.size(); ++i) {
        if (!argv[i].empty() && argv[i].front() != '-') {
            out.push_back(argv[i]);
        }
    }
    return out;
}

bool has_flag(const std::vector<std::string>& argv, char flag) {
    for (std::size_t i = 1; i < argv.size(); ++i) {
        const std::string& argument = argv[i];
        if (argument.size() >= 2 && argument[0] == '-' && argument[1] != '-' &&
            argument.find(flag) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool has_option(const std::vector<std::string>& argv, std::string_view option) {
    return std::any_of(argv.begin() + 1, argv.end(), [&](const std::string& argument) {
        return argument == option;
    });
}

bool looks_like_url(std::string_view token) {
    return token.starts_with("http://") || token.starts_with("https://") ||
           token.starts_with("ftp://") || token.starts_with("tftp://");
}

std::string basename_of(std::string_view path) {
    const auto slash = path.find_last_of('/');
    std::string name;
    if (slash == std::string_view::npos) {
        name = std::string(path);
    } else {
        name = std::string(path.substr(slash + 1));
    }
    if (name.empty()) {
        name = "index.html";
    }
    const auto query = name.find('?');
    if (query != std::string::npos) {
        name.erase(query);
    }
    return name.empty() ? "index.html" : name;
}

std::string uid_for(const std::string& username) {
    if (username == "root") {
        return "0";
    }
    if (username == "deploy") {
        return "1000";
    }
    if (username == "mdias") {
        return "1001";
    }
    return "1000";
}

/// One line of `ls -l`.
std::string long_entry(const VfsNode& node, const std::string& name) {
    std::string mode = node.mode;
    if (mode.empty()) {
        mode = node.is_directory ? "drwxr-xr-x" : "-rw-r--r--";
    }
    const std::string links =
        node.is_directory ? std::to_string(2 + node.children.size()) : std::string("1");

    std::ostringstream line;
    line << mode << " " << links << " " << node.owner << " " << node.group << " ";

    std::string size = std::to_string(node.size());
    while (size.size() < 6) {
        size.insert(size.begin(), ' ');
    }
    line << size << " " << node.mtime << " " << name;
    return line.str();
}

// --- individual commands --------------------------------------------------

CommandOutcome cmd_ls(ShellContext& context, const std::vector<std::string>& argv) {
    const auto targets = operands(argv);
    const std::string path = context.resolve(targets.empty() ? "." : targets.front());

    const VfsNode* node = context.vfs.find(path);
    if (node == nullptr) {
        return fail("ls: cannot access '" + (targets.empty() ? path : targets.front()) +
                        "': No such file or directory\n",
                    2);
    }

    const bool long_format = has_flag(argv, 'l');
    const bool show_hidden = has_flag(argv, 'a');

    if (!node->is_directory) {
        const std::string name = targets.empty() ? path : targets.front();
        return ok(long_format ? long_entry(*node, name) + "\n" : name + "\n");
    }

    std::ostringstream out;
    if (long_format) {
        std::size_t blocks = 0;
        for (const auto& [name, child] : node->children) {
            blocks += child.size() / 1024 + 1;
        }
        out << "total " << blocks << "\n";
    }

    std::vector<std::string> rendered;
    for (const auto& [name, child] : node->children) {
        if (!show_hidden && !name.empty() && name.front() == '.') {
            continue;
        }
        rendered.push_back(long_format ? long_entry(child, name) : name);
    }

    if (long_format) {
        for (const auto& line : rendered) {
            out << line << "\n";
        }
    } else {
        for (std::size_t i = 0; i < rendered.size(); ++i) {
            out << rendered[i] << (i + 1 == rendered.size() ? "\n" : "  ");
        }
        if (rendered.empty()) {
            out << "";
        }
    }
    return ok(out.str());
}

CommandOutcome cmd_cd(ShellContext& context, const std::vector<std::string>& argv) {
    const auto targets = operands(argv);
    const std::string requested = targets.empty() ? context.home() : targets.front();
    const std::string path = requested == "-" ? context.home() : context.resolve(requested);

    const VfsNode* node = context.vfs.find(path);
    if (node == nullptr) {
        return fail("bash: cd: " + requested + ": No such file or directory\n");
    }
    if (!node->is_directory) {
        return fail("bash: cd: " + requested + ": Not a directory\n");
    }
    context.cwd = path;
    return ok();
}

CommandOutcome cmd_pwd(ShellContext& context, const std::vector<std::string>& /*argv*/) {
    return ok(context.cwd + "\n");
}

CommandOutcome cmd_whoami(ShellContext& context, const std::vector<std::string>& /*argv*/) {
    return ok(context.username + "\n");
}

CommandOutcome cmd_id(ShellContext& context, const std::vector<std::string>& /*argv*/) {
    const std::string uid = uid_for(context.username);
    const std::string& user = context.username;
    if (user == "root") {
        return ok("uid=0(root) gid=0(root) groups=0(root)\n");
    }
    return ok("uid=" + uid + "(" + user + ") gid=" + uid + "(" + user + ") groups=" + uid + "(" +
              user + "),27(sudo)\n");
}

CommandOutcome cmd_uname(ShellContext& context, const std::vector<std::string>& argv) {
    const std::string kernel = "5.15.0-91-generic";
    const std::string full = "Linux " + context.hostname + " " + kernel +
                             " #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 "
                             "x86_64 GNU/Linux\n";
    if (has_flag(argv, 'a')) {
        return ok(full);
    }
    if (has_flag(argv, 'r')) {
        return ok(kernel + "\n");
    }
    if (has_flag(argv, 'm')) {
        return ok("x86_64\n");
    }
    if (has_flag(argv, 'n')) {
        return ok(context.hostname + "\n");
    }
    return ok("Linux\n");
}

CommandOutcome cmd_cat(ShellContext& context, const std::vector<std::string>& argv) {
    const auto targets = operands(argv);
    if (targets.empty()) {
        // A real cat would block on stdin. Returning nothing is the closest
        // thing that does not hang the session.
        return ok();
    }

    std::string out;
    int status = 0;
    for (const auto& target : targets) {
        const VfsNode* node = context.vfs.find(context.resolve(target));
        if (node == nullptr) {
            out += "cat: " + target + ": No such file or directory\n";
            status = 1;
            continue;
        }
        if (node->is_directory) {
            out += "cat: " + target + ": Is a directory\n";
            status = 1;
            continue;
        }
        out += node->content;
    }
    return status == 0 ? ok(std::move(out)) : fail(std::move(out), status);
}

CommandOutcome cmd_echo(ShellContext& /*context*/, const std::vector<std::string>& argv) {
    std::string out;
    const bool no_newline = argv.size() > 1 && argv[1] == "-n";
    for (std::size_t i = no_newline ? 2 : 1; i < argv.size(); ++i) {
        if (!out.empty()) {
            out += " ";
        }
        out += argv[i];
    }
    if (!no_newline) {
        out += "\n";
    }
    return ok(std::move(out));
}

CommandOutcome cmd_ps(ShellContext& context, const std::vector<std::string>& argv) {
    if (has_flag(argv, 'a') || has_option(argv, "aux") || has_flag(argv, 'e')) {
        return ok(
            "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root           1  0.0  0.6 168404 11820 ?        Ss   Oct28   0:24 /sbin/init\n"
            "root         412  0.0  0.4  61048  8104 ?        Ss   Oct28   0:03 "
            "/lib/systemd/systemd-journald\n"
            "root         655  0.0  0.2  15420  5332 ?        Ss   Oct28   0:01 sshd: "
            "/usr/sbin/sshd -D\n"
            "www-data    1104  0.0  1.1 214880 22440 ?        S    Oct28   0:12 nginx: worker "
            "process\n"
            "postgres    1210  0.0  2.3 398124 46512 ?        Ss   Oct28   1:47 "
            "/usr/lib/postgresql/14/bin/postgres\n"
            "deploy      2031  0.1  3.4 918244 68120 ?        Ssl  Oct28   4:02 "
            "/opt/app/bin/app --config /opt/app/.env\n"
            "root       41122  0.0  0.3  17204  6980 ?        Ss   03:11  0:00 sshd: " +
            context.username + " [priv]\n" +
            "deploy     41880  0.0  0.1   9284  3120 ?        S    06:25  0:00 "
            "/bin/sh /opt/app/scripts/sync.sh\n");
    }
    return ok(
        "    PID TTY          TIME CMD\n"
        "  41124 pts/0    00:00:00 bash\n"
        "  41190 pts/0    00:00:00 ps\n");
}

CommandOutcome cmd_top(ShellContext& /*context*/, const std::vector<std::string>& /*argv*/) {
    return ok(
        "top - 06:31:02 up 5 days,  3:14,  1 user,  load average: 0.08, 0.12, 0.09\n"
        "Tasks: 112 total,   1 running, 111 sleeping,   0 stopped,   0 zombie\n"
        "%Cpu(s):  1.3 us,  0.7 sy,  0.0 ni, 97.8 id,  0.2 wa,  0.0 hi,  0.0 si,  0.0 st\n"
        "MiB Mem :   3936.0 total,    793.3 free,   1102.4 used,   2040.3 buff/cache\n"
        "MiB Swap:      0.0 total,      0.0 free,      0.0 used.   2514.1 avail Mem\n"
        "\n"
        "    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n"
        "   2031 deploy    20   0  918244  68120  12044 S   0.7   1.7   4:02.11 app\n"
        "   1210 postgres  20   0  398124  46512  44120 S   0.3   1.2   1:47.80 postgres\n"
        "      1 root      20   0  168404  11820   8204 S   0.0   0.3   0:24.07 systemd\n");
}

CommandOutcome cmd_free(ShellContext& /*context*/, const std::vector<std::string>& argv) {
    if (has_flag(argv, 'h')) {
        return ok(
            "               total        used        free      shared  buff/cache   available\n"
            "Mem:           3.8Gi       1.1Gi       774Mi        12Mi       2.0Gi       2.5Gi\n"
            "Swap:             0B          0B          0B\n");
    }
    return ok(
        "               total        used        free      shared  buff/cache   available\n"
        "Mem:         4030400     1128848      792504       12544     2089048     2574592\n"
        "Swap:              0           0           0\n");
}

CommandOutcome cmd_df(ShellContext& /*context*/, const std::vector<std::string>& argv) {
    if (has_flag(argv, 'h')) {
        return ok(
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/vda1        79G   24G   52G  32% /\n"
            "tmpfs           1.9G     0  1.9G   0% /dev/shm\n"
            "tmpfs           394M  1.1M  393M   1% /run\n");
    }
    return ok(
        "Filesystem     1K-blocks     Used Available Use% Mounted on\n"
        "/dev/vda1       82437332 24518392  53728556  32% /\n"
        "tmpfs            2015200        0   2015200   0% /dev/shm\n");
}

CommandOutcome cmd_uptime(ShellContext& /*context*/, const std::vector<std::string>& /*argv*/) {
    return ok(" 06:31:02 up 5 days,  3:14,  1 user,  load average: 0.08, 0.12, 0.09\n");
}

CommandOutcome cmd_history(ShellContext& context, const std::vector<std::string>& argv) {
    if (has_option(argv, "-c")) {
        context.history.clear();
        return ok();
    }
    std::ostringstream out;
    std::size_t index = 1;
    for (const auto& entry : context.history) {
        out << "  " << index++ << "  " << entry << "\n";
    }
    return ok(out.str());
}

CommandOutcome cmd_which(ShellContext& /*context*/, const std::vector<std::string>& argv) {
    static const std::vector<std::pair<std::string, std::string>> kKnown = {
        {"bash", "/bin/bash"},
        {"sh", "/bin/sh"},
        {"ls", "/bin/ls"},
        {"cat", "/bin/cat"},
        {"wget", "/usr/bin/wget"},
        {"curl", "/usr/bin/curl"},
        {"python3", "/usr/bin/python3"},
        {"perl", "/usr/bin/perl"},
        {"gcc", "/usr/bin/gcc"},
        {"git", "/usr/bin/git"},
        {"docker", "/usr/bin/docker"},
        {"systemctl", "/usr/bin/systemctl"},
        {"crontab", "/usr/bin/crontab"},
        {"nc", "/usr/bin/nc"},
    };

    std::string out;
    int status = 0;
    for (const auto& target : operands(argv)) {
        const auto found = std::find_if(
            kKnown.begin(), kKnown.end(), [&](const auto& entry) { return entry.first == target; });
        if (found == kKnown.end()) {
            status = 1;
        } else {
            out += found->second + "\n";
        }
    }
    return status == 0 ? ok(std::move(out)) : fail(std::move(out), status);
}

/// wget and curl are the reason the capture engine exists. The URL is recorded
/// and handed upward. Nothing is fetched here: the download happens later, on
/// a worker thread, with its own timeouts, size caps and address checks.
CommandOutcome cmd_wget(ShellContext& context, const std::vector<std::string>& argv) {
    CommandOutcome outcome;
    std::string url;
    for (std::size_t i = 1; i < argv.size(); ++i) {
        if (looks_like_url(argv[i])) {
            url = argv[i];
            outcome.urls.push_back(url);
        }
    }

    if (url.empty()) {
        outcome.output =
            "wget: missing URL\nUsage: wget [OPTION]... [URL]...\n\n"
            "Try `wget --help' for more options.\n";
        outcome.status = 1;
        return outcome;
    }

    const std::string name = basename_of(url);
    const std::string saved = context.resolve(name);
    (void)context.vfs.create_file(saved, "");

    std::ostringstream out;
    out << "--2026-11-02 06:31:04--  " << url << "\n"
        << "Resolving host... 198.51.100.9\n"
        << "Connecting to host|198.51.100.9|:80... connected.\n"
        << "HTTP request sent, awaiting response... 200 OK\n"
        << "Length: 1894 (1.8K) [application/octet-stream]\n"
        << "Saving to: '" << name << "'\n\n"
        << name << "      100%[===================>]   1.85K  --.-KB/s    in 0s\n\n"
        << "2026-11-02 06:31:04 (112 MB/s) - '" << name << "' saved [1894/1894]\n\n";
    outcome.output = out.str();
    return outcome;
}

CommandOutcome cmd_curl(ShellContext& context, const std::vector<std::string>& argv) {
    CommandOutcome outcome;
    std::string url;
    for (std::size_t i = 1; i < argv.size(); ++i) {
        if (looks_like_url(argv[i])) {
            url = argv[i];
            outcome.urls.push_back(url);
        }
    }

    if (url.empty()) {
        outcome.output = "curl: try 'curl --help' for more information\n";
        outcome.status = 2;
        return outcome;
    }

    // -o and -O write a file, anything else writes to stdout, where a real
    // curl would print the body. Printing nothing is closer to a small script
    // than printing something invented.
    if (has_flag(argv, 'O') || has_flag(argv, 'o')) {
        const std::string name = basename_of(url);
        (void)context.vfs.create_file(context.resolve(name), "");
        if (!has_flag(argv, 's')) {
            outcome.output =
                "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  "
                "Current\n"
                "                                 Dload  Upload   Total   Spent    Left  "
                "Speed\n"
                "100  1894  100  1894    0     0  41234      0 --:--:-- --:--:-- --:--:-- "
                "42088\n";
        }
    }
    return outcome;
}

CommandOutcome cmd_chmod(ShellContext& context, const std::vector<std::string>& argv) {
    const auto targets = operands(argv);
    if (targets.size() < 2) {
        return fail("chmod: missing operand\n");
    }
    for (std::size_t i = 1; i < targets.size(); ++i) {
        if (!context.vfs.exists(context.resolve(targets[i]))) {
            return fail("chmod: cannot access '" + targets[i] + "': No such file or directory\n");
        }
    }
    return ok();
}

CommandOutcome cmd_rm(ShellContext& context, const std::vector<std::string>& argv) {
    const auto targets = operands(argv);
    const bool force = has_flag(argv, 'f');
    std::string out;
    int status = 0;
    for (const auto& target : targets) {
        if (!context.vfs.remove(context.resolve(target)) && !force) {
            out += "rm: cannot remove '" + target + "': No such file or directory\n";
            status = 1;
        }
    }
    return status == 0 ? ok(std::move(out)) : fail(std::move(out), status);
}

CommandOutcome cmd_mkdir(ShellContext& context, const std::vector<std::string>& argv) {
    std::string out;
    int status = 0;
    for (const auto& target : operands(argv)) {
        if (!context.vfs.create_directory(context.resolve(target))) {
            out += "mkdir: cannot create directory '" + target + "': File exists\n";
            status = 1;
        }
    }
    return status == 0 ? ok(std::move(out)) : fail(std::move(out), status);
}

CommandOutcome cmd_touch(ShellContext& context, const std::vector<std::string>& argv) {
    for (const auto& target : operands(argv)) {
        const std::string path = context.resolve(target);
        if (!context.vfs.exists(path)) {
            (void)context.vfs.create_file(path, "");
        }
    }
    return ok();
}

CommandOutcome cmd_crontab(ShellContext& context, const std::vector<std::string>& argv) {
    if (has_flag(argv, 'l')) {
        if (context.username == "root") {
            return ok("17 *    * * *   cd / && run-parts --report /etc/cron.hourly\n");
        }
        return fail("no crontab for " + context.username + "\n");
    }
    if (has_flag(argv, 'e')) {
        // A real crontab -e opens an editor. There is no terminal to hand to
        // one, and pretending otherwise would hang the session.
        return ok("crontab: installing new crontab\n");
    }
    if (has_flag(argv, 'r')) {
        return ok();
    }
    return ok("crontab: usage error: file name must be specified for replace\n");
}

CommandOutcome cmd_netstat(ShellContext& /*context*/, const std::vector<std::string>& /*argv*/) {
    return ok(
        "Active Internet connections (servers and established)\n"
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
        "tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN\n"
        "tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN\n"
        "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
        "tcp        0    312 10.0.3.14:22            198.51.100.23:51234     ESTABLISHED\n"
        "tcp6       0      0 :::22                   :::*                    LISTEN\n");
}

CommandOutcome cmd_ifconfig(ShellContext& /*context*/, const std::vector<std::string>& /*argv*/) {
    return ok(
        "ens3: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
        "        inet 10.0.3.14  netmask 255.255.255.0  broadcast 10.0.3.255\n"
        "        inet6 fe80::17ff:fe09:9267  prefixlen 64  scopeid 0x20<link>\n"
        "        ether 02:00:17:09:92:67  txqueuelen 1000  (Ethernet)\n"
        "        RX packets 8824119  bytes 2914884012 (2.9 GB)\n"
        "        TX packets 7120043  bytes 1884221904 (1.8 GB)\n"
        "\n"
        "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
        "        inet 127.0.0.1  netmask 255.0.0.0\n"
        "        loop  txqueuelen 1000  (Local Loopback)\n");
}

CommandOutcome cmd_ip(ShellContext& /*context*/, const std::vector<std::string>& argv) {
    const bool route = std::any_of(argv.begin() + 1, argv.end(), [](const std::string& a) {
        return a == "r" || a == "route";
    });
    if (route) {
        return ok(
            "default via 10.0.3.1 dev ens3 proto dhcp src 10.0.3.14 metric 100\n"
            "10.0.3.0/24 dev ens3 proto kernel scope link src 10.0.3.14\n");
    }
    return ok(
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default\n"
        "    inet 127.0.0.1/8 scope host lo\n"
        "2: ens3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n"
        "    link/ether 02:00:17:09:92:67 brd ff:ff:ff:ff:ff:ff\n"
        "    inet 10.0.3.14/24 brd 10.0.3.255 scope global dynamic ens3\n");
}

CommandOutcome cmd_apt(ShellContext& context, const std::vector<std::string>& argv) {
    const std::string action = argv.size() > 1 ? argv[1] : std::string();
    if (context.username != "root") {
        return fail(
            "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission "
            "denied)\nE: Unable to acquire the dpkg frontend lock, are you root?\n",
            100);
    }
    if (action == "update") {
        return ok(
            "Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease\n"
            "Get:2 http://security.ubuntu.com/ubuntu jammy-security InRelease [110 kB]\n"
            "Fetched 110 kB in 1s (142 kB/s)\n"
            "Reading package lists... Done\n");
    }
    if (action == "install" || action == "-y") {
        return ok(
            "Reading package lists... Done\n"
            "Building dependency tree... Done\n"
            "Reading state information... Done\n"
            "E: Unable to locate package\n");
    }
    return ok("apt 2.4.11 (amd64)\n");
}

CommandOutcome cmd_systemctl(ShellContext& /*context*/, const std::vector<std::string>& argv) {
    const std::string action = argv.size() > 1 ? argv[1] : std::string();
    if (action == "status") {
        return ok(
            "* ssh.service - OpenBSD Secure Shell server\n"
            "     Loaded: loaded (/lib/systemd/system/ssh.service; enabled; vendor preset: "
            "enabled)\n"
            "     Active: active (running) since Sat 2026-10-28 03:02:11 UTC; 5 days ago\n"
            "   Main PID: 655 (sshd)\n"
            "      Tasks: 1 (limit: 4617)\n");
    }
    if (action == "list-units" || action == "list-unit-files") {
        return ok(
            "UNIT FILE                 STATE    VENDOR PRESET\n"
            "ssh.service               enabled  enabled\n"
            "nginx.service             enabled  enabled\n"
            "postgresql.service        enabled  enabled\n");
    }
    return ok();
}

CommandOutcome cmd_service(ShellContext& /*context*/, const std::vector<std::string>& argv) {
    if (argv.size() >= 3) {
        return ok(" * " + argv[1] + " is running\n");
    }
    return ok();
}

CommandOutcome cmd_su(ShellContext& /*context*/, const std::vector<std::string>& /*argv*/) {
    // There is no terminal to prompt on and no password to check. The failure
    // a real su gives after a wrong password is the honest answer.
    return fail("su: Authentication failure\n");
}

CommandOutcome cmd_sudo(ShellContext& context, const std::vector<std::string>& argv) {
    if (argv.size() < 2) {
        return fail("usage: sudo [-u user] command\n", 1);
    }
    if (context.username == "root") {
        return ok();
    }
    return fail(context.username +
                " is not in the sudoers file. This incident will be "
                "reported.\n");
}

CommandOutcome cmd_exit(ShellContext& context, const std::vector<std::string>& /*argv*/) {
    context.exit_requested = true;
    return ok("logout\n");
}

CommandOutcome cmd_env(ShellContext& context, const std::vector<std::string>& /*argv*/) {
    std::string out;
    for (const auto& [key, value] : context.env) {
        out += key;
        out += "=";
        out += value;
        out += "\n";
    }
    return ok(std::move(out));
}

CommandOutcome cmd_export(ShellContext& context, const std::vector<std::string>& argv) {
    for (std::size_t i = 1; i < argv.size(); ++i) {
        const auto equals = argv[i].find('=');
        if (equals != std::string::npos && equals > 0) {
            context.env[argv[i].substr(0, equals)] = argv[i].substr(equals + 1);
        }
    }
    return ok();
}

CommandOutcome cmd_hostname(ShellContext& context, const std::vector<std::string>& /*argv*/) {
    return ok(context.hostname + "\n");
}

CommandOutcome cmd_date(ShellContext& /*context*/, const std::vector<std::string>& /*argv*/) {
    return ok("Mon Nov  2 06:31:02 UTC 2026\n");
}

CommandOutcome cmd_nproc(ShellContext& /*context*/, const std::vector<std::string>& /*argv*/) {
    return ok("2\n");
}

CommandOutcome cmd_w(ShellContext& context, const std::vector<std::string>& /*argv*/) {
    return ok(
        " 06:31:02 up 5 days,  3:14,  1 user,  load average: 0.08, 0.12, 0.09\n"
        "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n" +
        context.username +
        "     pts/0    198.51.100.23    06:30    0.00s  0.03s  0.00s "
        "-bash\n");
}

CommandOutcome cmd_head_tail(ShellContext& context,
                             const std::vector<std::string>& argv,
                             bool from_start) {
    const auto targets = operands(argv);
    if (targets.empty()) {
        return ok();
    }
    const VfsNode* node = context.vfs.find(context.resolve(targets.front()));
    if (node == nullptr) {
        return fail(std::string(from_start ? "head" : "tail") + ": cannot open '" +
                    targets.front() + "' for reading: No such file or directory\n");
    }

    std::vector<std::string> lines;
    std::istringstream input(node->content);
    std::string line;
    while (std::getline(input, line)) {
        lines.push_back(line);
    }

    constexpr std::size_t kCount = 10;
    std::string out;
    if (from_start) {
        for (std::size_t i = 0; i < lines.size() && i < kCount; ++i) {
            out += lines[i] + "\n";
        }
    } else {
        const std::size_t start = lines.size() > kCount ? lines.size() - kCount : 0;
        for (std::size_t i = start; i < lines.size(); ++i) {
            out += lines[i] + "\n";
        }
    }
    return ok(std::move(out));
}

CommandOutcome cmd_grep(ShellContext& context, const std::vector<std::string>& argv) {
    const auto targets = operands(argv);
    if (targets.size() < 2) {
        return fail("usage: grep [OPTION]... PATTERNS [FILE]...\n", 2);
    }

    const std::string& pattern = targets.front();
    std::string out;
    bool matched = false;
    for (std::size_t i = 1; i < targets.size(); ++i) {
        const VfsNode* node = context.vfs.find(context.resolve(targets[i]));
        if (node == nullptr) {
            out += "grep: " + targets[i] + ": No such file or directory\n";
            continue;
        }
        std::istringstream input(node->content);
        std::string line;
        while (std::getline(input, line)) {
            // Plain substring search, never a regular expression. The pattern
            // comes from the attacker, and a backtracking engine on attacker
            // input is a denial of service.
            if (line.find(pattern) != std::string::npos) {
                out += line + "\n";
                matched = true;
            }
        }
    }
    return matched ? ok(std::move(out)) : fail(std::move(out), 1);
}

CommandOutcome cmd_interpreter(ShellContext& /*context*/, const std::vector<std::string>& argv) {
    // python, perl and friends. Script content is never run, and a quiet exit
    // is what a short script usually looks like from the outside.
    if (argv.size() > 1 && argv[1] == "--version") {
        return ok(argv[0] == "python3" ? "Python 3.10.12\n" : "v5.34.0\n");
    }
    return ok();
}

}  // namespace

CommandRegistry CommandRegistry::standard() {
    CommandRegistry registry;

    registry.add("ls", cmd_ls);
    registry.add("dir", cmd_ls);
    registry.add("cd", cmd_cd);
    registry.add("pwd", cmd_pwd);
    registry.add("whoami", cmd_whoami);
    registry.add("id", cmd_id);
    registry.add("uname", cmd_uname);
    registry.add("cat", cmd_cat);
    registry.add("echo", cmd_echo);
    registry.add("ps", cmd_ps);
    registry.add("top", cmd_top);
    registry.add("htop", cmd_top);
    registry.add("free", cmd_free);
    registry.add("df", cmd_df);
    registry.add("uptime", cmd_uptime);
    registry.add("history", cmd_history);
    registry.add("which", cmd_which);
    registry.add("whereis", cmd_which);
    registry.add("wget", cmd_wget);
    registry.add("curl", cmd_curl);
    registry.add("chmod", cmd_chmod);
    registry.add("chown", cmd_chmod);
    registry.add("rm", cmd_rm);
    registry.add("mkdir", cmd_mkdir);
    registry.add("touch", cmd_touch);
    registry.add("crontab", cmd_crontab);
    registry.add("netstat", cmd_netstat);
    registry.add("ss", cmd_netstat);
    registry.add("ifconfig", cmd_ifconfig);
    registry.add("ip", cmd_ip);
    registry.add("apt", cmd_apt);
    registry.add("apt-get", cmd_apt);
    registry.add("systemctl", cmd_systemctl);
    registry.add("service", cmd_service);
    registry.add("su", cmd_su);
    registry.add("sudo", cmd_sudo);
    registry.add("exit", cmd_exit);
    registry.add("logout", cmd_exit);
    registry.add("env", cmd_env);
    registry.add("printenv", cmd_env);
    registry.add("export", cmd_export);
    registry.add("hostname", cmd_hostname);
    registry.add("date", cmd_date);
    registry.add("nproc", cmd_nproc);
    registry.add("w", cmd_w);
    registry.add("who", cmd_w);
    registry.add("grep", cmd_grep);

    registry.add("head", [](ShellContext& context, const std::vector<std::string>& argv) {
        return cmd_head_tail(context, argv, true);
    });
    registry.add("tail", [](ShellContext& context, const std::vector<std::string>& argv) {
        return cmd_head_tail(context, argv, false);
    });

    for (const char* interpreter : {"python", "python3", "perl", "sh", "bash", "php"}) {
        registry.add(interpreter, cmd_interpreter);
    }

    return registry;
}

}  // namespace arapuca::ssh
