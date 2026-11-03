#include <arapuca/ssh/vfs.hpp>

#include <gtest/gtest.h>

#include <string>

namespace {

using arapuca::ssh::split_path;
using arapuca::ssh::Vfs;
using arapuca::ssh::VfsError;

Vfs small() {
    return Vfs::from_yaml(R"(
etc:
  type: dir
  children:
    passwd:
      type: file
      content: "root:x:0:0:root:/root:/bin/bash\n"
    ssh:
      type: dir
      children:
        sshd_config:
          type: file
          content: "Port 22\n"
home:
  type: dir
  children:
    deploy:
      type: dir
      owner: deploy
tmp:
  type: dir
  mode: "drwxrwxrwt"
)");
}

TEST(SplitPath, DropsEmptyComponents) {
    const auto parts = split_path("//etc///ssh//");
    ASSERT_EQ(2U, parts.size());
    EXPECT_EQ("etc", parts[0]);
    EXPECT_EQ("ssh", parts[1]);
}

TEST(SplitPath, RootHasNoComponents) {
    EXPECT_TRUE(split_path("/").empty());
    EXPECT_TRUE(split_path("").empty());
}

TEST(Vfs, LoadsATree) {
    const auto vfs = small();
    EXPECT_TRUE(vfs.is_directory("/etc"));
    EXPECT_TRUE(vfs.exists("/etc/passwd"));
    EXPECT_FALSE(vfs.is_directory("/etc/passwd"));
    EXPECT_TRUE(vfs.is_directory("/etc/ssh"));
    EXPECT_FALSE(vfs.exists("/etc/nothing"));
}

TEST(Vfs, ReadsFileContent) {
    const auto vfs = small();
    const auto* node = vfs.find("/etc/passwd");
    ASSERT_NE(nullptr, node);
    EXPECT_NE(std::string::npos, node->content.find("root:x:0:0"));
}

TEST(Vfs, ListsSortedEntries) {
    const auto vfs = small();
    const auto entries = vfs.list("/etc");
    ASSERT_EQ(2U, entries.size());
    EXPECT_EQ("passwd", entries[0]);
    EXPECT_EQ("ssh", entries[1]);
}

TEST(Vfs, ListingAFileIsEmpty) {
    EXPECT_TRUE(small().list("/etc/passwd").empty());
}

TEST(Vfs, RootIsADirectory) {
    const auto vfs = small();
    EXPECT_TRUE(vfs.is_directory("/"));
    EXPECT_EQ(3U, vfs.list("/").size());
}

// --- Path resolution, the security sensitive part ------------------------

TEST(VfsResolve, AbsolutePathIsNormalized) {
    const auto vfs = small();
    EXPECT_EQ("/etc/ssh", Vfs::resolve("/", "//etc///ssh//"));
    EXPECT_EQ("/etc", Vfs::resolve("/home", "/etc"));
}

TEST(VfsResolve, RelativePathUsesTheWorkingDirectory) {
    const auto vfs = small();
    EXPECT_EQ("/etc/ssh", Vfs::resolve("/etc", "ssh"));
    EXPECT_EQ("/etc/ssh/sshd_config", Vfs::resolve("/etc/ssh", "sshd_config"));
}

TEST(VfsResolve, DotIsIgnored) {
    const auto vfs = small();
    EXPECT_EQ("/etc", Vfs::resolve("/etc", "."));
    EXPECT_EQ("/etc/ssh", Vfs::resolve("/etc", "./ssh"));
    EXPECT_EQ("/etc", Vfs::resolve("/", "./etc/./"));
}

TEST(VfsResolve, DotDotGoesUp) {
    const auto vfs = small();
    EXPECT_EQ("/", Vfs::resolve("/etc", ".."));
    EXPECT_EQ("/home", Vfs::resolve("/etc/ssh", "../../home"));
}

// The traversal every scanner tries. A real kernel treats /.. as /, and so
// does this, so no amount of leading ..  escapes the virtual root.
TEST(VfsResolve, CannotEscapeTheRoot) {
    const auto vfs = small();
    for (const auto* attempt : {"../../../../../../etc/passwd",
                                "/../../../etc/passwd",
                                "../../..",
                                "/..",
                                "/../..",
                                "a/../../../../etc/passwd"}) {
        const std::string resolved = Vfs::resolve("/home/deploy", attempt).value_or(std::string{});
        ASSERT_FALSE(resolved.empty()) << attempt;
        EXPECT_EQ('/', resolved.front()) << attempt;
        EXPECT_EQ(std::string::npos, resolved.find("..")) << attempt;
    }
    EXPECT_EQ("/etc/passwd", Vfs::resolve("/home/deploy", "../../../../etc/passwd"));
}

// Found by the fuzz target. The working directory was copied verbatim while
// only the path argument was normalised, so a `..` in the working directory
// survived into the result. Nothing in the shell could reach it, because the
// shell only ever stores an already resolved path, but the function promises
// more than that and has to keep the promise on its own.
TEST(VfsResolve, UnnormalisedWorkingDirectoryIsStillNormalised) {
    EXPECT_EQ("/etc", Vfs::resolve("/home/../etc", "."));
    EXPECT_EQ("/etc/passwd", Vfs::resolve("/a/b/../../etc", "passwd"));
    EXPECT_EQ("/", Vfs::resolve("/../../..", "."));

    const auto resolved = Vfs::resolve("../...././.", "../etc/passwd").value_or(std::string{});
    EXPECT_EQ(std::string::npos, resolved.find("/../")) << resolved;
    EXPECT_EQ('/', resolved.front());
}

TEST(VfsResolve, EmptyInputMeansTheWorkingDirectory) {
    EXPECT_EQ("/etc", Vfs::resolve("/etc", ""));
}

TEST(VfsResolve, DeepNestingIsRefusedNotTruncated) {
    const auto vfs = small();
    std::string deep;
    for (std::size_t i = 0; i < Vfs::kMaxDepth + 10; ++i) {
        deep += "a/";
    }
    EXPECT_FALSE(Vfs::resolve("/", deep).has_value());
}

TEST(VfsResolve, OverlongPathIsRefused) {
    const auto vfs = small();
    const std::string huge(Vfs::kMaxPathLength + 1, 'a');
    EXPECT_FALSE(Vfs::resolve("/", huge).has_value());
}

TEST(VfsResolve, PathOfNothingButDotsIsSafe) {
    const auto vfs = small();
    EXPECT_NO_THROW({ (void)Vfs::resolve("/", "............"); });
    EXPECT_NO_THROW({ (void)Vfs::resolve("/", "./././././././."); });
    EXPECT_EQ("/", Vfs::resolve("/", "../../../../.."));
}

// --- Session local mutation ----------------------------------------------

TEST(VfsMutate, CreateAndReadBack) {
    auto vfs = small();
    EXPECT_TRUE(vfs.create_file("/tmp/payload.sh", "#!/bin/sh\necho hi\n"));
    ASSERT_TRUE(vfs.exists("/tmp/payload.sh"));
    EXPECT_NE(std::string::npos, vfs.find("/tmp/payload.sh")->content.find("echo hi"));
}

TEST(VfsMutate, CreateInAMissingDirectoryFails) {
    auto vfs = small();
    EXPECT_FALSE(vfs.create_file("/nowhere/payload.sh", "x"));
}

TEST(VfsMutate, CreateDirectory) {
    auto vfs = small();
    EXPECT_TRUE(vfs.create_directory("/tmp/.hidden"));
    EXPECT_TRUE(vfs.is_directory("/tmp/.hidden"));
    EXPECT_FALSE(vfs.create_directory("/tmp/.hidden")) << "creating twice must fail";
}

TEST(VfsMutate, Remove) {
    auto vfs = small();
    EXPECT_TRUE(vfs.remove("/etc/passwd"));
    EXPECT_FALSE(vfs.exists("/etc/passwd"));
    EXPECT_FALSE(vfs.remove("/etc/passwd"));
}

TEST(VfsMutate, RootCannotBeRemoved) {
    auto vfs = small();
    EXPECT_FALSE(vfs.remove("/"));
    EXPECT_TRUE(vfs.is_directory("/"));
}

// An attacker in a loop must not be able to grow the session without bound.
TEST(VfsMutate, CreationIsCapped) {
    auto vfs = small();
    std::size_t created = 0;
    for (std::size_t i = 0; i < Vfs::kMaxCreatedNodes + 50; ++i) {
        if (vfs.create_file("/tmp/f" + std::to_string(i), "x")) {
            ++created;
        }
    }
    EXPECT_EQ(Vfs::kMaxCreatedNodes, created);
}

// Two sessions get their own copy, so what one attacker leaves behind is not
// visible to the next one.
TEST(VfsMutate, CopiesAreIndependent) {
    const auto original = small();
    Vfs first = Vfs::from_yaml("tmp:\n  type: dir\n");
    const Vfs second = Vfs::from_yaml("tmp:\n  type: dir\n");

    EXPECT_TRUE(first.create_file("/tmp/only-in-first", "x"));
    EXPECT_TRUE(first.exists("/tmp/only-in-first"));
    EXPECT_FALSE(second.exists("/tmp/only-in-first"));
}

// --- Loading errors -------------------------------------------------------

TEST(VfsLoad, EmptyDocumentIsAnEmptyRoot) {
    const auto vfs = Vfs::from_yaml("");
    EXPECT_TRUE(vfs.is_directory("/"));
    EXPECT_TRUE(vfs.list("/").empty());
}

TEST(VfsLoad, MalformedYamlIsRejected) {
    EXPECT_THROW({ (void)Vfs::from_yaml("etc: [unclosed\n"); }, VfsError);
}

TEST(VfsLoad, UnknownTypeIsRejected) {
    EXPECT_THROW({ (void)Vfs::from_yaml("x:\n  type: socket\n"); }, VfsError);
}

TEST(VfsLoad, FileWithChildrenIsRejected) {
    EXPECT_THROW(
        { (void)Vfs::from_yaml("x:\n  type: file\n  children:\n    y:\n      type: file\n"); },
        VfsError);
}

TEST(VfsLoad, InvalidEntryNameIsRejected) {
    EXPECT_THROW(
        {
            (void)Vfs::from_yaml("etc:\n  type: dir\n  children:\n    \"..\":\n      type: file\n");
        },
        VfsError);
    EXPECT_THROW({ (void)Vfs::from_yaml("\"a/b\":\n  type: dir\n"); }, VfsError);
}

TEST(VfsLoad, ShippedFilesystemLoadsAndLooksLikeAServer) {
    const auto vfs = Vfs::from_file(std::string(ARAPUCA_CONFIG_DIR) + "/filesystem.yaml");

    EXPECT_GT(vfs.node_count(), 30U);
    EXPECT_TRUE(vfs.is_directory("/etc"));
    EXPECT_TRUE(vfs.is_directory("/home/deploy"));
    EXPECT_TRUE(vfs.is_directory("/var/log"));

    const auto* passwd = vfs.find("/etc/passwd");
    ASSERT_NE(nullptr, passwd);
    EXPECT_NE(std::string::npos, passwd->content.find("root:x:0:0"));
    EXPECT_NE(std::string::npos, passwd->content.find("deploy"));

    // The decoy credentials an attacker is meant to find and take away.
    const auto* env = vfs.find("/opt/app/.env");
    ASSERT_NE(nullptr, env);
    EXPECT_NE(std::string::npos, env->content.find("DB_PASSWORD"));

    const auto* shadow = vfs.find("/etc/shadow");
    ASSERT_NE(nullptr, shadow);
    EXPECT_NE(std::string::npos, shadow->content.find("$6$"));
}

}  // namespace
