# ---------------------------------------------------------------------------
# arapuca_core: every piece of logic lives here so the test suite can link it.
# The executable is a thin shell around this library on purpose.
# ---------------------------------------------------------------------------
add_library(arapuca_core
    core/clock.cpp
    core/config.cpp
    core/event.cpp
    core/event_bus.cpp
    core/event_sink.cpp
    core/ids.cpp
    core/logging.cpp
    core/version.cpp
    enrich/geoip.cpp
    enrich/mitre_mapper.cpp
    enrich/session_classifier.cpp
    ssh/auth_policy.cpp
    ssh/command_line.cpp
    ssh/command_registry.cpp
    ssh/line_editor.cpp
    ssh/shell.cpp
    ssh/vfs.cpp
    util/redaction.cpp)

add_library(arapuca::core ALIAS arapuca_core)

target_include_directories(arapuca_core
    PUBLIC
        "${PROJECT_SOURCE_DIR}/include"
        "${PROJECT_BINARY_DIR}/generated")

target_link_libraries(arapuca_core
    PUBLIC
        nlohmann_json::nlohmann_json
        spdlog::spdlog
        yaml-cpp::yaml-cpp
        PkgConfig::MAXMINDDB
        Threads::Threads
    PRIVATE
        arapuca::warnings
        arapuca::hardening
        arapuca::sanitizers)

arapuca_apply_tidy(arapuca_core)

set_target_properties(arapuca_core PROPERTIES
    OUTPUT_NAME arapuca
    VERSION ${PROJECT_VERSION})

# ---------------------------------------------------------------------------
# arapucad: the honeypot daemon.
# ---------------------------------------------------------------------------
add_executable(arapucad main.cpp)

target_link_libraries(arapucad
    PRIVATE
        arapuca::core
        arapuca::warnings
        arapuca::hardening
        arapuca::sanitizers)

arapuca_apply_tidy(arapucad)

install(TARGETS arapucad RUNTIME DESTINATION bin)
