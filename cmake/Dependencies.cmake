# Arapuca dependency policy
# =========================
#
# Compiled libraries come from Ubuntu 24.04 distro packages. Header only
# libraries are fetched by CMake and pinned to an exact tag AND the full commit
# hash of that tag, never to a branch, so a retagged upstream release cannot
# silently change what is built.
#
# Ubuntu 24.04 (noble) is the only supported base. See docs/DEPENDENCIES.md for
# the apt line and the rationale.

include(FetchContent)
set(FETCHCONTENT_QUIET OFF)

# ---------------------------------------------------------------------------
# System libraries
# ---------------------------------------------------------------------------
# Each entry becomes REQUIRED in the phase that first links it, so a fresh
# checkout always builds with exactly the packages the current code needs.
#
#   phase 0  Threads, OpenSSL, CURL
#   phase 2  libmaxminddb
#   phase 3  libssh (0.10.6, noble), yaml-cpp
#   phase 5  minizip-ng

find_package(Threads REQUIRED)
find_package(OpenSSL 3.0 REQUIRED)
find_package(CURL 8.0 REQUIRED)
find_package(yaml-cpp 0.8 REQUIRED)
find_package(libssh 0.10.6 REQUIRED)

# libmaxminddb ships no CMake config package, so it comes in through pkg-config.
find_package(PkgConfig REQUIRED)
pkg_check_modules(MAXMINDDB REQUIRED IMPORTED_TARGET libmaxminddb)

# ---------------------------------------------------------------------------
# Fetched header only libraries, pinned by tag and commit hash
# ---------------------------------------------------------------------------
set(ARAPUCA_JSON_TAG      "v3.12.0")
set(ARAPUCA_JSON_HASH     "65ee68451d8eb2b5f3a30b410476ab83deb3289b")
set(ARAPUCA_SPDLOG_TAG    "v1.17.0")
set(ARAPUCA_SPDLOG_HASH   "79524ddd08a4ec981b7fea76afd08ee05f83755d")
set(ARAPUCA_HTTPLIB_TAG   "v0.64.0")
set(ARAPUCA_HTTPLIB_HASH  "24e58ce5b25d55045af4cd6f463e83a8082fbe6b")
set(ARAPUCA_GTEST_TAG     "v1.18.0")
set(ARAPUCA_GTEST_HASH    "063de7e9578f82b369302001269680b4b1553359")

set(JSON_BuildTests OFF CACHE INTERNAL "")
set(JSON_Install OFF CACHE INTERNAL "")
FetchContent_Declare(nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        ${ARAPUCA_JSON_HASH}   # ${ARAPUCA_JSON_TAG}
    GIT_SHALLOW    OFF
    SYSTEM)

set(SPDLOG_BUILD_EXAMPLE OFF CACHE INTERNAL "")
set(SPDLOG_BUILD_TESTS OFF CACHE INTERNAL "")
set(SPDLOG_INSTALL OFF CACHE INTERNAL "")
set(SPDLOG_FMT_EXTERNAL OFF CACHE INTERNAL "")
FetchContent_Declare(spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG        ${ARAPUCA_SPDLOG_HASH}  # ${ARAPUCA_SPDLOG_TAG}
    GIT_SHALLOW    OFF
    SYSTEM)

set(HTTPLIB_COMPILE OFF CACHE INTERNAL "")
set(HTTPLIB_REQUIRE_OPENSSL ON CACHE INTERNAL "")
set(HTTPLIB_INSTALL OFF CACHE INTERNAL "")
FetchContent_Declare(httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG        ${ARAPUCA_HTTPLIB_HASH}  # ${ARAPUCA_HTTPLIB_TAG}
    GIT_SHALLOW    OFF
    SYSTEM)

FetchContent_MakeAvailable(nlohmann_json spdlog httplib)

if(ARAPUCA_BUILD_TESTS)
    set(BUILD_GMOCK ON CACHE INTERNAL "")
    set(INSTALL_GTEST OFF CACHE INTERNAL "")
    set(gtest_force_shared_crt ON CACHE INTERNAL "")
    FetchContent_Declare(googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        ${ARAPUCA_GTEST_HASH}  # ${ARAPUCA_GTEST_TAG}
        GIT_SHALLOW    OFF
        SYSTEM)
    FetchContent_MakeAvailable(googletest)
    include(GoogleTest)
endif()
