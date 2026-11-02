// The fake filesystem the fake shell walks.
//
// Everything here is in memory and described by YAML. Nothing touches the real
// filesystem, which is the point: safety invariant S1 says attacker input is
// never executed, and the matching rule for the filesystem is that an attacker
// can never name a real path. `cat /etc/shadow` reads a fabricated string from
// a map, and no syscall is involved.
//
// Path resolution is the security sensitive part of this file. An attacker
// will try `../../../../etc/passwd`, `//etc//passwd`, a path made of nothing
// but dots, and a path thousands of components long. Resolution is therefore
// purely textual, bounded, and cannot produce anything above the virtual root.
#pragma once

#include <cstddef>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace arapuca::ssh {

struct VfsNode {
    bool is_directory = false;
    /// File contents. Empty for directories.
    std::string content;
    std::string owner = "root";
    std::string group = "root";
    /// Rendered by `ls -l`, for example "-rw-r--r--".
    std::string mode;
    /// Rendered by `ls -l`. Fabricated, and stable across sessions so an
    /// attacker returning later sees a consistent machine.
    std::string mtime = "Nov  2 14:30";
    std::map<std::string, VfsNode> children;

    [[nodiscard]] std::size_t size() const;
};

class VfsError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class Vfs {
public:
    Vfs();

    [[nodiscard]] static Vfs from_yaml(const std::string& yaml_text);
    [[nodiscard]] static Vfs from_file(const std::filesystem::path& path);

    /// Resolve `input` against `cwd` into an absolute, normalized path.
    ///
    /// Returns nothing only when the input is unusable (empty, or longer than
    /// the limit). It never returns a path outside the virtual root: `..` at
    /// the root is absorbed, exactly as it is on a real system where
    /// /.. is /.
    /// Static because resolution is pure path arithmetic and never consults
    /// the tree. Whether a resolved path exists is a separate question, asked
    /// with exists() or find().
    [[nodiscard]] static std::optional<std::string> resolve(std::string_view cwd,
                                                            std::string_view input);

    [[nodiscard]] const VfsNode* find(std::string_view absolute_path) const;
    [[nodiscard]] bool exists(std::string_view absolute_path) const;
    [[nodiscard]] bool is_directory(std::string_view absolute_path) const;

    /// Entry names in a directory, sorted. Empty when the path is not a
    /// directory, which the caller distinguishes with is_directory().
    [[nodiscard]] std::vector<std::string> list(std::string_view absolute_path) const;

    /// Session local mutation. An attacker who writes a file sees it again
    /// later in the same session, and the next session starts clean, because
    /// each session holds its own copy of the tree.
    bool create_file(std::string_view absolute_path, std::string content);
    bool create_directory(std::string_view absolute_path);
    bool remove(std::string_view absolute_path);

    [[nodiscard]] std::size_t node_count() const;

    /// Longest path accepted, and deepest nesting resolved. Both bound the
    /// work an attacker can ask for with one command.
    static constexpr std::size_t kMaxPathLength = 4096;
    static constexpr std::size_t kMaxDepth = 64;
    /// Files an attacker may create in one session.
    static constexpr std::size_t kMaxCreatedNodes = 256;

private:
    [[nodiscard]] VfsNode* find_mutable(std::string_view absolute_path);
    [[nodiscard]] VfsNode* parent_of(std::string_view absolute_path, std::string& leaf);

    VfsNode root_;
    std::size_t created_ = 0;
};

/// Split an absolute path into components, dropping empties. Exposed because
/// the shell needs it too, and because it is worth testing on its own.
[[nodiscard]] std::vector<std::string_view> split_path(std::string_view path);

}  // namespace arapuca::ssh
