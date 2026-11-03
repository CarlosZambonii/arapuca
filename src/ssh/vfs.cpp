#include <arapuca/ssh/vfs.hpp>

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <fstream>
#include <sstream>
#include <utility>

namespace arapuca::ssh {
namespace {

// Recursion is how a tree is built. The depth argument bounds it, and the
// bound is checked on the first line.
// NOLINTNEXTLINE(misc-no-recursion)
void build_tree(const YAML::Node& node, VfsNode& target, std::size_t depth) {
    if (depth > Vfs::kMaxDepth) {
        throw VfsError("filesystem description nests deeper than the allowed limit");
    }
    if (!node.IsMap()) {
        throw VfsError("every filesystem entry must be a mapping");
    }

    const std::string type = node["type"] ? node["type"].as<std::string>() : "file";
    if (type == "dir" || type == "directory") {
        target.is_directory = true;
        target.mode = node["mode"] ? node["mode"].as<std::string>() : "drwxr-xr-x";
    } else if (type == "file") {
        target.is_directory = false;
        target.mode = node["mode"] ? node["mode"].as<std::string>() : "-rw-r--r--";
        if (node["content"]) {
            target.content = node["content"].as<std::string>();
        }
    } else {
        throw VfsError("unknown filesystem entry type '" + type + "'");
    }

    if (node["owner"]) {
        target.owner = node["owner"].as<std::string>();
    }
    if (node["group"]) {
        target.group = node["group"].as<std::string>();
    }
    if (node["mtime"]) {
        target.mtime = node["mtime"].as<std::string>();
    }

    if (const YAML::Node children = node["children"]) {
        if (!target.is_directory) {
            throw VfsError("a file entry cannot have children");
        }
        if (!children.IsMap()) {
            throw VfsError("children must be a mapping of name to entry");
        }
        for (const auto& child : children) {
            const auto name = child.first.as<std::string>();
            if (name.empty() || name == "." || name == ".." ||
                name.find('/') != std::string::npos) {
                throw VfsError("invalid entry name '" + name + "'");
            }
            build_tree(child.second, target.children[name], depth + 1);
        }
    }
}

/// Append the components of `path` to `parts`, resolving `.` and `..` as it
/// goes. Returns false when the result would pass the depth bound.
///
/// Used for both the working directory and the path argument. An earlier
/// version normalised only the argument and copied the working directory
/// verbatim, so a working directory containing `..` passed straight into the
/// result. The fake shell only ever stores an already resolved path there, so
/// nothing was reachable, but the function's contract says it never returns a
/// path outside the virtual root, and as written that was not true. The fuzz
/// target found it.
bool append_normalized(std::vector<std::string_view>& parts, std::string_view path) {
    for (const auto& component : split_path(path)) {
        if (component == ".") {
            continue;
        }
        if (component == "..") {
            // At the root this is a no op, which is what a real kernel does
            // with /.. and is what stops any traversal out of the tree.
            if (!parts.empty()) {
                parts.pop_back();
            }
            continue;
        }
        if (parts.size() >= Vfs::kMaxDepth) {
            return false;
        }
        parts.push_back(component);
    }
    return true;
}

}  // namespace

std::size_t VfsNode::size() const {
    return is_directory ? 4096 : content.size();
}

std::vector<std::string_view> split_path(std::string_view path) {
    std::vector<std::string_view> parts;
    std::size_t index = 0;
    while (index < path.size()) {
        while (index < path.size() && path[index] == '/') {
            ++index;
        }
        const std::size_t start = index;
        while (index < path.size() && path[index] != '/') {
            ++index;
        }
        if (index > start) {
            parts.push_back(path.substr(start, index - start));
        }
    }
    return parts;
}

Vfs::Vfs() {
    root_.is_directory = true;
    root_.mode = "drwxr-xr-x";
}

Vfs Vfs::from_yaml(const std::string& yaml_text) {
    Vfs vfs;

    YAML::Node root;
    try {
        root = YAML::Load(yaml_text);
    } catch (const YAML::Exception& error) {
        throw VfsError(std::string("cannot parse filesystem description: ") + error.what());
    }

    if (!root || root.IsNull()) {
        return vfs;
    }

    const YAML::Node tree = root.IsMap() && root["root"] ? root["root"] : root;
    if (!tree.IsMap()) {
        throw VfsError("filesystem description must be a mapping");
    }

    // The document describes the children of /, so a top level "root" key is
    // optional sugar rather than another level of nesting.
    if (tree["children"] || tree["type"]) {
        build_tree(tree, vfs.root_, 0);
        vfs.root_.is_directory = true;
    } else {
        for (const auto& child : tree) {
            const auto name = child.first.as<std::string>();
            if (name.empty() || name.find('/') != std::string::npos) {
                throw VfsError("invalid top level entry name '" + name + "'");
            }
            build_tree(child.second, vfs.root_.children[name], 1);
        }
    }

    return vfs;
}

Vfs Vfs::from_file(const std::filesystem::path& path) {
    const std::ifstream input(path);
    if (!input) {
        throw VfsError("cannot open filesystem description: " + path.string());
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return from_yaml(buffer.str());
}

std::optional<std::string> Vfs::resolve(std::string_view cwd, std::string_view input) {
    if (input.empty()) {
        // A bare `cd` means home, but that decision belongs to the shell. Here
        // an empty path simply resolves to the current directory.
        input = ".";
    }
    if (input.size() > kMaxPathLength || cwd.size() > kMaxPathLength) {
        return std::nullopt;
    }

    std::vector<std::string_view> parts;
    if (input.front() != '/') {
        if (!append_normalized(parts, cwd)) {
            return std::nullopt;
        }
    }
    if (!append_normalized(parts, input)) {
        return std::nullopt;
    }

    std::string out;
    out.reserve(input.size() + cwd.size() + 1);
    for (const auto& part : parts) {
        out.push_back('/');
        out.append(part);
    }
    if (out.empty()) {
        out = "/";
    }
    return out;
}

const VfsNode* Vfs::find(std::string_view absolute_path) const {
    const VfsNode* node = &root_;
    for (const auto& component : split_path(absolute_path)) {
        if (!node->is_directory) {
            return nullptr;
        }
        const auto child = node->children.find(std::string(component));
        if (child == node->children.end()) {
            return nullptr;
        }
        node = &child->second;
    }
    return node;
}

VfsNode* Vfs::find_mutable(std::string_view absolute_path) {
    VfsNode* node = &root_;
    for (const auto& component : split_path(absolute_path)) {
        if (!node->is_directory) {
            return nullptr;
        }
        const auto child = node->children.find(std::string(component));
        if (child == node->children.end()) {
            return nullptr;
        }
        node = &child->second;
    }
    return node;
}

VfsNode* Vfs::parent_of(std::string_view absolute_path, std::string& leaf) {
    const auto parts = split_path(absolute_path);
    if (parts.empty()) {
        return nullptr;  // the root has no parent
    }
    leaf = std::string(parts.back());

    VfsNode* node = &root_;
    for (std::size_t i = 0; i + 1 < parts.size(); ++i) {
        if (!node->is_directory) {
            return nullptr;
        }
        const auto child = node->children.find(std::string(parts[i]));
        if (child == node->children.end()) {
            return nullptr;
        }
        node = &child->second;
    }
    return node->is_directory ? node : nullptr;
}

bool Vfs::exists(std::string_view absolute_path) const {
    return find(absolute_path) != nullptr;
}

bool Vfs::is_directory(std::string_view absolute_path) const {
    const VfsNode* node = find(absolute_path);
    return node != nullptr && node->is_directory;
}

std::vector<std::string> Vfs::list(std::string_view absolute_path) const {
    std::vector<std::string> names;
    const VfsNode* node = find(absolute_path);
    if (node == nullptr || !node->is_directory) {
        return names;
    }
    names.reserve(node->children.size());
    for (const auto& [name, child] : node->children) {
        names.push_back(name);
    }
    return names;
}

bool Vfs::create_file(std::string_view absolute_path, std::string content) {
    if (created_ >= kMaxCreatedNodes) {
        return false;
    }
    std::string leaf;
    VfsNode* parent = parent_of(absolute_path, leaf);
    if (parent == nullptr || leaf.empty()) {
        return false;
    }

    VfsNode& node = parent->children[leaf];
    if (node.is_directory) {
        return false;
    }
    node.is_directory = false;
    node.content = std::move(content);
    if (node.mode.empty()) {
        node.mode = "-rw-r--r--";
    }
    ++created_;
    return true;
}

bool Vfs::create_directory(std::string_view absolute_path) {
    if (created_ >= kMaxCreatedNodes) {
        return false;
    }
    std::string leaf;
    VfsNode* parent = parent_of(absolute_path, leaf);
    if (parent == nullptr || leaf.empty()) {
        return false;
    }
    if (parent->children.contains(leaf)) {
        return false;
    }

    VfsNode& node = parent->children[leaf];
    node.is_directory = true;
    node.mode = "drwxr-xr-x";
    ++created_;
    return true;
}

bool Vfs::remove(std::string_view absolute_path) {
    std::string leaf;
    VfsNode* parent = parent_of(absolute_path, leaf);
    if (parent == nullptr || leaf.empty()) {
        return false;
    }
    return parent->children.erase(leaf) > 0;
}

std::size_t Vfs::node_count() const {
    std::size_t count = 0;
    // NOLINTNEXTLINE(misc-no-recursion)
    const auto walk = [&count](const VfsNode& node, auto&& self) -> void {
        ++count;
        for (const auto& [name, child] : node.children) {
            self(child, self);
        }
    };
    walk(root_, walk);
    return count;
}

}  // namespace arapuca::ssh
