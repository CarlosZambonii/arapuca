# Every test binary links arapuca::core and is registered with CTest through
# gtest_discover_tests, so a new TEST() shows up in `ctest` without edits here.

add_executable(arapuca_unit_tests
    unit/test_address_policy.cpp
    unit/test_auth_policy.cpp
    unit/test_capture.cpp
    unit/test_clock.cpp
    unit/test_command_line.cpp
    unit/test_config.cpp
    unit/test_event.cpp
    unit/test_event_bus.cpp
    unit/test_event_sink.cpp
    unit/test_geoip.cpp
    unit/test_http_request.cpp
    unit/test_ids.cpp
    unit/test_line_editor.cpp
    unit/test_logging.cpp
    unit/test_mitre_mapper.cpp
    unit/test_session_classifier.cpp
    unit/test_shell.cpp
    unit/test_telnet_protocol.cpp
    unit/test_telnet_shell.cpp
    unit/test_vfs.cpp
    unit/test_redaction.cpp
    unit/test_version.cpp)

target_link_libraries(arapuca_unit_tests
    PRIVATE
        arapuca::core
        arapuca::warnings
        arapuca::hardening
        arapuca::sanitizers
        arapuca::coverage
        GTest::gtest_main
        GTest::gmock)

target_compile_definitions(arapuca_unit_tests
    PRIVATE ARAPUCA_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
            ARAPUCA_CONFIG_DIR="${PROJECT_SOURCE_DIR}/config")

arapuca_apply_tidy(arapuca_unit_tests)

gtest_discover_tests(arapuca_unit_tests
    PROPERTIES LABELS unit
    DISCOVERY_TIMEOUT 30)

# ---------------------------------------------------------------------------
# Integration tests. These start a real server and drive it with a real
# client, so they catch the things a mock cannot: the channel policy as it
# behaves on the wire, the banner an attacker sees, the events a session
# actually produces.
# ---------------------------------------------------------------------------
add_executable(arapuca_integration_tests
    integration/test_http_server.cpp
    integration/test_ssh_server.cpp
    integration/test_telnet_server.cpp)

target_link_libraries(arapuca_integration_tests
    PRIVATE
        arapuca::core
        arapuca::warnings
        arapuca::hardening
        arapuca::sanitizers
        arapuca::coverage
        ssh
        httplib::httplib
        GTest::gtest_main)

target_compile_definitions(arapuca_integration_tests
    PRIVATE ARAPUCA_CONFIG_DIR="${PROJECT_SOURCE_DIR}/config")

arapuca_apply_tidy(arapuca_integration_tests)

gtest_discover_tests(arapuca_integration_tests
    PROPERTIES LABELS integration
    DISCOVERY_TIMEOUT 60)
