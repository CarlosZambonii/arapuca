#include <arapuca/core/logging.hpp>
#include <arapuca/http/decoys.hpp>

#include <fstream>
#include <sstream>
#include <system_error>
#include <utility>

namespace arapuca::http {
namespace {

std::string read_file(const std::filesystem::path& path) {
    const std::ifstream input(path, std::ios::binary);
    if (!input) {
        return {};
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

/// Map a file name under the decoy directory to the request paths it answers.
/// Dots cannot start a file name in a repository checkout without being
/// awkward, so "dot-env" on disk answers "/.env" on the wire.
std::vector<std::string> request_paths_for(const std::string& filename) {
    if (filename == "dot-env") {
        return {"/.env", "/.env.local", "/.env.production", "/api/.env"};
    }
    if (filename == "git-config") {
        return {"/.git/config", "/.git/HEAD"};
    }
    if (filename == "backup.sql") {
        return {"/backup.sql", "/dump.sql", "/db.sql", "/database.sql"};
    }
    if (filename == "config.php") {
        return {"/config.php", "/wp-config.php", "/configuration.php"};
    }
    if (filename == "aws-credentials") {
        return {"/.aws/credentials", "/credentials"};
    }
    if (filename == "docker-compose.yml") {
        return {"/docker-compose.yml", "/docker-compose.yaml"};
    }
    return {"/" + filename};
}

std::string label_for(const std::string& filename) {
    if (filename == "dot-env") {
        return "env";
    }
    if (filename == "git-config") {
        return "git-config";
    }
    if (filename == "aws-credentials") {
        return "aws-credentials";
    }
    const auto dot = filename.find('.');
    return dot == std::string::npos ? filename : filename.substr(0, dot);
}

}  // namespace

void DecoyStore::add(const std::string& path, Decoy decoy) {
    by_path_.insert_or_assign(path, std::move(decoy));
}

const Decoy* DecoyStore::find(std::string_view path) const {
    const auto found = by_path_.find(path);
    return found == by_path_.end() ? nullptr : &found->second;
}

std::vector<std::string> DecoyStore::paths() const {
    std::vector<std::string> out;
    out.reserve(by_path_.size());
    for (const auto& [path, decoy] : by_path_) {
        out.push_back(path);
    }
    return out;
}

DecoyStore DecoyStore::from_directory(const std::filesystem::path& directory) {
    DecoyStore store = default_decoys();

    std::error_code ec;
    if (directory.empty() || !std::filesystem::is_directory(directory, ec)) {
        core::log().info("no decoy directory at {}, serving the built in set", directory.string());
        return store;
    }

    for (const auto& entry : std::filesystem::directory_iterator(directory, ec)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        const std::string filename = entry.path().filename().string();
        const std::string body = read_file(entry.path());
        if (body.empty()) {
            continue;
        }
        for (const auto& path : request_paths_for(filename)) {
            store.add(path, Decoy{body, "text/plain", label_for(filename)});
        }
    }

    return store;
}

DecoyStore default_decoys() {
    DecoyStore store;

    const Decoy env{
        "APP_ENV=production\n"
        "APP_DEBUG=false\n"
        "APP_KEY=base64:7Qx2VrNkDpLmS9fTgHjYwZ4cAeB6uI8oK1nM3bV5xC0=\n"
        "DB_CONNECTION=mysql\n"
        "DB_HOST=10.0.3.22\n"
        "DB_PORT=3306\n"
        "DB_DATABASE=appdb\n"
        "DB_USERNAME=appuser\n"
        "DB_PASSWORD=Pr0d-Db-9fK2mQ7x\n"
        "REDIS_HOST=10.0.3.23\n"
        "REDIS_PASSWORD=r3d1s-S3cr3t-88\n"
        "MAIL_HOST=smtp.mailtrap.io\n"
        "MAIL_USERNAME=a1b2c3d4e5f6\n"
        "MAIL_PASSWORD=smtp-Xk92LmQp\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        "text/plain",
        "env"};
    for (const auto* path : {"/.env", "/.env.local", "/.env.production", "/api/.env"}) {
        store.add(path, env);
    }

    const Decoy git{
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = true\n"
        "\tbare = false\n"
        "\tlogallrefupdates = true\n"
        "[remote \"origin\"]\n"
        "\turl = https://deploy:ghp_8kL2mNqR5tV9wX1yZ3aB6cD0eF4gH7@git.internal/app.git\n"
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        "[branch \"main\"]\n"
        "\tremote = origin\n"
        "\tmerge = refs/heads/main\n",
        "text/plain",
        "git-config"};
    store.add("/.git/config", git);
    store.add("/.git/HEAD", Decoy{"ref: refs/heads/main\n", "text/plain", "git-config"});

    const Decoy config_php{
        "<?php\n"
        "define('DB_NAME', 'appdb');\n"
        "define('DB_USER', 'appuser');\n"
        "define('DB_PASSWORD', 'Pr0d-Db-9fK2mQ7x');\n"
        "define('DB_HOST', '10.0.3.22');\n"
        "define('AUTH_KEY', 'q2ZnR8vT5xB1cE4gJ7mP0sV3yA6dG9jL');\n"
        "define('SECURE_AUTH_KEY', 'w5yB8eH1kN4qT7wZ0cF3iL6oR9uX2aD5');\n"
        "$table_prefix = 'wp_';\n"
        "define('WP_DEBUG', false);\n",
        "text/x-php",
        "config-php"};
    for (const auto* path : {"/config.php", "/wp-config.php", "/configuration.php"}) {
        store.add(path, config_php);
    }

    const Decoy backup{
        "-- MySQL dump 10.13  Distrib 8.0.35, for Linux (x86_64)\n"
        "--\n"
        "-- Host: 10.0.3.22    Database: appdb\n"
        "-- ------------------------------------------------------\n"
        "DROP TABLE IF EXISTS `users`;\n"
        "CREATE TABLE `users` (\n"
        "  `id` int NOT NULL AUTO_INCREMENT,\n"
        "  `email` varchar(255) NOT NULL,\n"
        "  `password_hash` varchar(255) NOT NULL,\n"
        "  `role` varchar(32) DEFAULT 'user',\n"
        "  PRIMARY KEY (`id`)\n"
        ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n"
        "INSERT INTO `users` VALUES\n"
        "(1,'admin@example.invalid','$2y$10$N9qo8uLOickgx2ZMRZoMye1J8kFqCZ0hFJ4mQ','admin'),\n"
        "(2,'deploy@example.invalid','$2y$10$abcdefghijklmnopqrstuv1234567890ABCDE','user');\n",
        "application/sql",
        "backup-sql"};
    for (const auto* path : {"/backup.sql", "/dump.sql", "/db.sql", "/database.sql"}) {
        store.add(path, backup);
    }

    const Decoy aws{
        "[default]\n"
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "region = sa-east-1\n",
        "text/plain",
        "aws-credentials"};
    store.add("/.aws/credentials", aws);

    store.add("/docker-compose.yml",
              Decoy{"services:\n"
                    "  web:\n"
                    "    image: registry.internal/app:1.8.2\n"
                    "    environment:\n"
                    "      - DB_PASSWORD=Pr0d-Db-9fK2mQ7x\n"
                    "    ports:\n"
                    "      - \"8000:8000\"\n",
                    "text/yaml",
                    "docker-compose"});

    store.add("/server-status",
              Decoy{"Apache Server Status for srv-web-03\n"
                    "Server Version: Apache/2.4.52 (Ubuntu)\n"
                    "Current Time: Monday, 02-Nov-2026 06:31:02 UTC\n"
                    "Restart Time: Saturday, 28-Oct-2026 03:02:11 UTC\n"
                    "Total accesses: 184221 - Total Traffic: 2.9 GB\n",
                    "text/plain",
                    "server-status"});

    return store;
}

}  // namespace arapuca::http
