# Every test binary links arapuca::core and is registered with CTest through
# gtest_discover_tests, so a new TEST() shows up in `ctest` without edits here.

add_executable(arapuca_unit_tests
    unit/test_clock.cpp
    unit/test_event.cpp
    unit/test_event_bus.cpp
    unit/test_event_sink.cpp
    unit/test_ids.cpp
    unit/test_logging.cpp
    unit/test_redaction.cpp
    unit/test_version.cpp)

target_link_libraries(arapuca_unit_tests
    PRIVATE
        arapuca::core
        arapuca::warnings
        arapuca::hardening
        arapuca::sanitizers
        GTest::gtest_main
        GTest::gmock)

target_compile_definitions(arapuca_unit_tests
    PRIVATE ARAPUCA_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")

gtest_discover_tests(arapuca_unit_tests
    PROPERTIES LABELS unit
    DISCOVERY_TIMEOUT 30)
