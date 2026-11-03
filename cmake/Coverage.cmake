# Line and branch coverage, GCC only.
#
# Kept out of the sanitizer module deliberately: coverage is an instrumented
# build whose numbers are read by a person, not a check that fails on an
# illegal operation, and combining the two gives a slow build whose coverage
# is skewed by the sanitizer's own code paths.

add_library(arapuca_coverage INTERFACE)
add_library(arapuca::coverage ALIAS arapuca_coverage)

if(ARAPUCA_COVERAGE)
    if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        message(FATAL_ERROR
            "ARAPUCA_COVERAGE expects GCC. gcov notes from clang need "
            "llvm-cov gcov to read them, which is a different pipeline.")
    endif()
    message(STATUS "Coverage instrumentation enabled")
    target_compile_options(arapuca_coverage INTERFACE
        --coverage
        -fprofile-update=atomic   # the servers are threaded, counters must not race
        -O0
        -g)
    target_link_options(arapuca_coverage INTERFACE --coverage)
endif()
