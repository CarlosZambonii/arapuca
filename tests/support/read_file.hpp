// Reading a whole file into a string, for tests.
//
// Not the usual istreambuf_iterator pair. Under optimization GCC cannot prove
// the stream buffer is non null when constructing from those iterators and
// reports a potential null dereference, which this project treats as an
// error. The failure only appears in a release build, which is how it reached
// CI without being caught locally.
//
// Reading through the size is also what the tests actually mean: they want
// the bytes of a file that must exist, and an empty result when it does not.
#pragma once

#include <filesystem>
#include <fstream>
#include <string>

namespace arapuca::testing {

[[nodiscard]] inline std::string read_whole_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        return {};
    }

    const std::streamsize size = file.tellg();
    if (size <= 0) {
        return {};
    }
    file.seekg(0, std::ios::beg);

    std::string content(static_cast<std::size_t>(size), '\0');
    file.read(content.data(), size);
    content.resize(static_cast<std::size_t>(file.gcount()));
    return content;
}

}  // namespace arapuca::testing
