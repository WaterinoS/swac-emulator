cmake_minimum_required(VERSION 3.20)
project(sw_ac_emu LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR
        "sw_ac_emu must be built as x86 (32-bit). "
        "GTA SA / SA-MP are 32-bit and te_sdk_rel.lib is x86. "
        "Use vcvarsall.bat x86 + 'NMake Makefiles', or VS generator with -A Win32.")
endif()

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")

# ---- te_sdk paths --------------------------------------------------------
set(TE_SDK_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/te_sdk")
set(TE_SDK_INC  "${CMAKE_CURRENT_SOURCE_DIR}/te_sdk_inc")
set(TE_SDK_LIB  "${TE_SDK_ROOT}/lib/te_sdk_rel.lib")
set(TE_SDK_DETOURS_LIB "${TE_SDK_INC}/Detours/detours_x86.lib")

if(NOT EXISTS "${TE_SDK_INC}/te-sdk.h")
    message(FATAL_ERROR
        "te_sdk_inc junction missing or stale: ${TE_SDK_INC}\n"
        "Run build.bat (it creates the junction), or manually:\n"
        "  mklink /J te_sdk_inc \"te_sdk\\#TE SDK\"")
endif()

# ---- MinHook (submodule, built inline) -----------------------------------
set(MINHOOK_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/external/minhook")
if(NOT EXISTS "${MINHOOK_ROOT}/src/hook.c")
    message(FATAL_ERROR
        "minhook submodule missing.\n"
        "Run: git submodule update --init --recursive")
endif()
add_library(minhook STATIC
    "${MINHOOK_ROOT}/src/buffer.c"
    "${MINHOOK_ROOT}/src/hook.c"
    "${MINHOOK_ROOT}/src/trampoline.c"
    "${MINHOOK_ROOT}/src/hde/hde32.c"
    "${MINHOOK_ROOT}/src/hde/hde64.c"
)
target_include_directories(minhook PUBLIC "${MINHOOK_ROOT}/include")
target_compile_definitions(minhook PRIVATE _CRT_SECURE_NO_WARNINGS)

if(NOT EXISTS "${TE_SDK_LIB}")
    message(FATAL_ERROR
        "te_sdk submodule missing: ${TE_SDK_LIB} not found.\n"
        "Run: git submodule update --init --recursive")
endif()

# ---- Target --------------------------------------------------------------
add_library(sw_ac_emu SHARED
    src/dllmain.cpp
    src/sender.cpp
    src/log.cpp
)

target_include_directories(sw_ac_emu PRIVATE
    "${TE_SDK_INC}"
    "${TE_SDK_INC}/FullRakNet"
)

target_link_libraries(sw_ac_emu PRIVATE
    "${TE_SDK_LIB}"
    "${TE_SDK_DETOURS_LIB}"
    minhook
    ws2_32
    winmm
)

target_compile_definitions(sw_ac_emu PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS
    _WINSOCK_DEPRECATED_NO_WARNINGS
)

if(MSVC)
    target_compile_options(sw_ac_emu PRIVATE
        /W3
        /MP
        /permissive-
        /EHsc
        /wd4244
        /wd4267
    )
endif()

# Output: sw_ac_emu.asi (picked up by ASI Loader)
set_target_properties(sw_ac_emu PROPERTIES
    PREFIX ""
    SUFFIX ".asi"
    OUTPUT_NAME "sw_ac_emu"
)

message(STATUS "sw_ac_emu configured for x86 / Release-MD")
message(STATUS "  TE SDK include : ${TE_SDK_INC}")
message(STATUS "  TE SDK lib     : ${TE_SDK_LIB}")
