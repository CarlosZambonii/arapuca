# ---------------------------------------------------------------------------
# Fuzz targets.
#
# Built in two modes from the same source:
#
#   ARAPUCA_BUILD_FUZZERS with clang and its sanitizer runtime gives real
#   libFuzzer binaries.
#
#   Otherwise each target is built as a corpus replay binary and registered
#   with CTest, so the committed corpus and every past crash are exercised on
#   an ordinary build. A regression found once stays found.
# ---------------------------------------------------------------------------

set(ARAPUCA_FUZZ_TARGETS
    redaction        # 1
    command_line     # 2
    terminal_input   # 3
    vfs_path         # 4
    http_request     # 5
    config           # 6
    address_policy   # 7
    shell)           # 8

set(_index 0)
foreach(target ${ARAPUCA_FUZZ_TARGETS})
    math(EXPR _index "${_index} + 1")
    set(_name arapuca_fuzz_${target})

    add_executable(${_name} fuzz_targets.cpp)
    target_compile_definitions(${_name} PRIVATE ARAPUCA_FUZZ_TARGET=${_index})
    target_link_libraries(${_name}
        PRIVATE
            arapuca::core
            arapuca::warnings
            arapuca::hardening)

    if(ARAPUCA_BUILD_FUZZERS)
        if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
            message(FATAL_ERROR "ARAPUCA_BUILD_FUZZERS needs clang. Use the fuzz preset.")
        endif()
        target_compile_definitions(${_name} PRIVATE ARAPUCA_WITH_LIBFUZZER)
        # The sanitizers are not optional for a fuzz target: without them the
        # fuzzer finds inputs that corrupt memory and reports nothing.
        target_compile_options(${_name} PRIVATE -fsanitize=fuzzer,address,undefined)
        target_link_options(${_name} PRIVATE -fsanitize=fuzzer,address,undefined)
    else()
        target_link_libraries(${_name} PRIVATE arapuca::sanitizers)

        # Replay the corpus and every recorded crash. A crash file is a past
        # defect, and this is what stops it coming back.
        file(GLOB _corpus CONFIGURE_DEPENDS
             "${CMAKE_CURRENT_SOURCE_DIR}/corpus/${target}/*"
             "${CMAKE_CURRENT_SOURCE_DIR}/crashes/${target}/*")
        add_test(NAME fuzz_replay_${target} COMMAND ${_name} ${_corpus})
        set_tests_properties(fuzz_replay_${target} PROPERTIES LABELS fuzz-replay)
    endif()
endforeach()
