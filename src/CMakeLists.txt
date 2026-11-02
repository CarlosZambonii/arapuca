# ---------------------------------------------------------------------------
# arapuca_core: every piece of logic lives here so the test suite can link it.
# The executable is a thin shell around this library on purpose.
# ---------------------------------------------------------------------------
add_library(arapuca_core
    core/clock.cpp
    core/event.cpp
    core/event_bus.cpp
    core/event_sink.cpp
    core/ids.cpp
    core/logging.cpp
    core/version.cpp
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
        Threads::Threads
    PRIVATE
        arapuca::warnings
        arapuca::hardening
        arapuca::sanitizers)

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

install(TARGETS arapucad RUNTIME DESTINATION bin)
