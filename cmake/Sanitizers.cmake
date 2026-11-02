# Sanitizer wiring. CI runs a dedicated ASan plus UBSan job, and the fuzzing
# targets always build with both.

add_library(arapuca_sanitizers INTERFACE)
add_library(arapuca::sanitizers ALIAS arapuca_sanitizers)

set(_arapuca_sanitizers "")

if(ARAPUCA_ENABLE_ASAN)
    list(APPEND _arapuca_sanitizers address)
endif()

if(ARAPUCA_ENABLE_UBSAN)
    list(APPEND _arapuca_sanitizers undefined)
endif()

if(ARAPUCA_ENABLE_TSAN)
    if(ARAPUCA_ENABLE_ASAN)
        message(FATAL_ERROR "ThreadSanitizer cannot be combined with AddressSanitizer.")
    endif()
    list(APPEND _arapuca_sanitizers thread)
endif()

if(_arapuca_sanitizers)
    list(JOIN _arapuca_sanitizers "," _arapuca_sanitizer_list)
    message(STATUS "Sanitizers enabled: ${_arapuca_sanitizer_list}")
    target_compile_options(arapuca_sanitizers INTERFACE
        -fsanitize=${_arapuca_sanitizer_list}
        -fno-omit-frame-pointer
        -fno-sanitize-recover=all
        -g)
    target_link_options(arapuca_sanitizers INTERFACE
        -fsanitize=${_arapuca_sanitizer_list})
endif()
