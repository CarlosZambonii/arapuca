# Warning configuration shared by every Arapuca target.
#
# The project is built only with GCC and Clang on Ubuntu 24.04, so there is no
# MSVC branch here on purpose.

add_library(arapuca_warnings INTERFACE)
add_library(arapuca::warnings ALIAS arapuca_warnings)

set(_arapuca_warnings
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wnon-virtual-dtor
    -Wold-style-cast
    -Wcast-align
    -Wunused
    -Woverloaded-virtual
    -Wconversion
    -Wsign-conversion
    -Wnull-dereference
    -Wdouble-promotion
    -Wformat=2
    -Wimplicit-fallthrough)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    list(APPEND _arapuca_warnings
        -Wmisleading-indentation
        -Wduplicated-cond
        -Wduplicated-branches
        -Wlogical-op
        -Wuseless-cast)
endif()

if(ARAPUCA_WERROR)
    list(APPEND _arapuca_warnings -Werror)
endif()

target_compile_options(arapuca_warnings INTERFACE ${_arapuca_warnings})
