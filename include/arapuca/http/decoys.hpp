// The files an attacker is meant to find.
//
// A scanner that requests /.env and gets a 404 learns nothing and moves on. A
// scanner that gets a plausible .env with credentials in it takes them away,
// and whatever it does with them next is visible from somewhere else. The
// decoy hit is therefore one of the highest signal events this honeypot
// produces.
//
// Every credential in these files is fabricated and invalid. They are shaped
// to look real, including key lengths and prefixes, and none of them opens
// anything.
#pragma once

#include <filesystem>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace arapuca::http {

struct Decoy {
    std::string body;
    std::string content_type = "text/plain";
    /// Short name for the event, for example "env" or "git-config".
    std::string label;
};

class DecoyStore {
public:
    /// Load every file in `directory`. A missing directory is not an error:
    /// the honeypot still serves its admin panel and its catch all.
    [[nodiscard]] static DecoyStore from_directory(const std::filesystem::path& directory);

    /// Register a decoy under one or more request paths.
    void add(const std::string& path, Decoy decoy);

    [[nodiscard]] const Decoy* find(std::string_view path) const;

    [[nodiscard]] std::size_t size() const {
        return by_path_.size();
    }

    [[nodiscard]] std::vector<std::string> paths() const;

private:
    std::map<std::string, Decoy, std::less<>> by_path_;
};

/// The decoys the honeypot serves when no directory is configured. Built in
/// rather than required on disk, so a bare checkout is still a working trap.
[[nodiscard]] DecoyStore default_decoys();

}  // namespace arapuca::http
