# Dependencies

Arapuca targets **Ubuntu 24.04 LTS (noble) only**, on x86_64 and arm64. That is the base
image in the Dockerfile, the runner in CI and the operating system on the VPS. Ubuntu 22.04
and libssh 0.9.x are explicitly unsupported: libssh 0.9 is missing part of the server side
callback API this project relies on, and carrying both would mean version conditionals in the
most security sensitive file of the codebase.

## System packages

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build pkg-config \
    libssl-dev libcurl4-openssl-dev \
    libssh-dev libyaml-cpp-dev libmaxminddb-dev libminizip-dev
```

Optional, for the static analysis and sanitizer presets:

```bash
sudo apt-get install -y --no-install-recommends clang clang-tidy clang-format
```

| Package | Noble version | Used for | First needed in |
|---------|---------------|----------|-----------------|
| `libssl-dev` | 3.0.13 | SHA256 hashing, SSH host key generation | phase 0 |
| `libcurl4-openssl-dev` | 8.5.0 | isolated sample download, VirusTotal API | phase 0 |
| `libmaxminddb-dev` | 1.9.1 | GeoLite2 City and ASN lookups | phase 2 |
| `libssh-dev` | 0.10.6 | SSH server side protocol | phase 3 |
| `libyaml-cpp-dev` | 0.8.0 | configuration files | phase 3 |
| `libminizip-dev` | 1.3.dfsg | writing the password protected quarantine zip | phase 5 |

Each library becomes `REQUIRED` in `cmake/Dependencies.cmake` in the phase that first links
it, so a checkout at any commit builds with exactly the packages that commit needs.

## Fetched libraries

Header only dependencies are fetched by CMake and pinned to **an exact tag and the full
commit hash of that tag**. A branch name is never used, and a retagged upstream release
cannot change what is built without the hash changing in a reviewed commit.

| Library | Tag | Commit |
|---------|-----|--------|
| nlohmann/json | v3.12.0 | `65ee68451d8eb2b5f3a30b410476ab83deb3289b` |
| spdlog | v1.17.0 | `79524ddd08a4ec981b7fea76afd08ee05f83755d` |
| cpp-httplib | v0.64.0 | `24e58ce5b25d55045af4cd6f463e83a8082fbe6b` |
| GoogleTest | v1.18.0 | `063de7e9578f82b369302001269680b4b1553359` |

## Updates

* `github-actions`, `docker` (base images), `pip` (the IoC tooling) and `terraform` providers
  are watched by Dependabot, weekly, grouped into one pull request per ecosystem.
* Every GitHub Action is pinned to a full commit SHA, with the readable tag in a trailing
  comment, which is the standard supply chain practice for a public repository.
* The fetched C++ libraries are checked by a scheduled workflow that opens an issue when a
  pinned tag falls behind upstream, since Dependabot cannot read `FetchContent` declarations.
* No bump merges without a green CI run on both architectures.

## Why not vcpkg

A vcpkg manifest was considered. It is more reproducible, but it builds every dependency from
source, including OpenSSL and libssh, which takes roughly thirty minutes from cold. The arm64
container image is the deciding factor: distro packages keep that build in the minutes range.
Pinning exact apt versions in the Dockerfile recovers most of the reproducibility.
