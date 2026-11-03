cmake_minimum_required(VERSION 3.22)

project(arapuca
    VERSION 0.1.0
    DESCRIPTION "Medium interaction SSH, Telnet and HTTP honeypot"
    HOMEPAGE_URL "https://github.com/CarlosZambonii/arapuca"
    LANGUAGES CXX)

if(PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
    message(FATAL_ERROR "In source builds are not allowed. Use a build directory.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

option(ARAPUCA_BUILD_TESTS    "Build the unit and integration test suite" ON)
option(ARAPUCA_BUILD_FUZZERS  "Build the libFuzzer targets (clang only)"  OFF)
option(ARAPUCA_ENABLE_ASAN    "Build with AddressSanitizer"               OFF)
option(ARAPUCA_ENABLE_UBSAN   "Build with UndefinedBehaviorSanitizer"     OFF)
option(ARAPUCA_ENABLE_TSAN    "Build with ThreadSanitizer"                OFF)
option(ARAPUCA_COVERAGE       "Build instrumented for gcov coverage"      OFF)
option(ARAPUCA_WERROR         "Treat compiler warnings as errors"         ON)
option(ARAPUCA_CLANG_TIDY     "Run clang-tidy on Arapuca targets only"    OFF)

# clang-tidy is applied per target rather than through CMAKE_CXX_CLANG_TIDY,
# which would also analyse the fetched dependencies and report findings in
# third party code that cannot be fixed here.
if(ARAPUCA_CLANG_TIDY)
    find_program(ARAPUCA_CLANG_TIDY_EXE NAMES clang-tidy REQUIRED)
    set(ARAPUCA_TIDY_COMMAND "${ARAPUCA_CLANG_TIDY_EXE};--warnings-as-errors=*")
    message(STATUS "clang-tidy: ${ARAPUCA_CLANG_TIDY_EXE}")
endif()

function(arapuca_apply_tidy target)
    if(ARAPUCA_CLANG_TIDY)
        set_target_properties(${target} PROPERTIES CXX_CLANG_TIDY "${ARAPUCA_TIDY_COMMAND}")
    endif()
endfunction()

include(CompilerWarnings)
include(Sanitizers)
include(Coverage)
include(Dependencies)

# Hardening flags applied to every Arapuca target. This binary parses hostile
# input from the public internet, so these are not optional extras.
add_library(arapuca_hardening INTERFACE)
add_library(arapuca::hardening ALIAS arapuca_hardening)
target_compile_options(arapuca_hardening INTERFACE
    $<$<COMPILE_LANGUAGE:CXX>:-fstack-protector-strong>
    $<$<COMPILE_LANGUAGE:CXX>:-fno-common>
    $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<NOT:$<CONFIG:Debug>>>:-U_FORTIFY_SOURCE>
    $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<NOT:$<CONFIG:Debug>>>:-D_FORTIFY_SOURCE=3>)
target_link_options(arapuca_hardening INTERFACE
    -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)

configure_file(
    "${PROJECT_SOURCE_DIR}/include/arapuca/version.hpp.in"
    "${PROJECT_BINARY_DIR}/generated/arapuca/version.hpp"
    @ONLY)

add_subdirectory(src)

if(ARAPUCA_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
    add_subdirectory(tests/fuzz)
endif()

message(STATUS "")
message(STATUS "Arapuca ${PROJECT_VERSION}")
message(STATUS "  Build type .......... ${CMAKE_BUILD_TYPE}")
message(STATUS "  Compiler ............ ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  Tests ............... ${ARAPUCA_BUILD_TESTS}")
message(STATUS "  Fuzzers ............. ${ARAPUCA_BUILD_FUZZERS}")
message(STATUS "  ASan / UBSan / TSan . ${ARAPUCA_ENABLE_ASAN} / ${ARAPUCA_ENABLE_UBSAN} / ${ARAPUCA_ENABLE_TSAN}")
message(STATUS "  Coverage ............ ${ARAPUCA_COVERAGE}")
message(STATUS "")
