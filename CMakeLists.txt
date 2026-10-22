cmake_minimum_required(VERSION 3.20)
project(aidbg C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

if(MSVC)
  add_compile_options(/W4 /permissive- /utf-8 /EHsc /Zc:__cplusplus)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
else()
  add_compile_options(-Wall -Wextra)
  add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

# ---------------------------------------------------------------------------
# Runtime linkage.
#
# Goal: the produced exe must not import MSVCP140.dll / VCRUNTIME140.dll /
# api-ms-win-crt-*.dll, so it runs without any Visual C++ Redistributable.
#
#  * /MT links the C++ standard library statically (drops msvcp140.dll).
#  * VC-LTL redirects the C runtime to the OS CRT, so vcruntime140.dll and the
#    api-ms-win-crt-* forwarding DLLs are replaced by ucrtbase.dll.
#
# VC-LTL is optional: without it we fall back to a fully static CRT, which also
# has no runtime DLL dependencies at all (only a larger binary).
# ---------------------------------------------------------------------------
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(VC_LTL_Root "D:/vc/VC-LTL-Binary" CACHE PATH "VC-LTL root directory")
if(EXISTS "${VC_LTL_Root}/_msvcrt.h")
  # ucrt mode on Windows 10 and later -> ucrtbase.dll
  set(WindowsTargetPlatformMinVersion "10.0.10240.0")
  set(SupportLTL "ucrt")
  # config.cmake auto-detects the platform, but that probe needs a generator
  # with an explicit -A arch (NMake has none). Set it ourselves - aidbg is x64
  # only, matching the debugger's own bitness.
  set(LTLPlatform "x64")
  include("${VC_LTL_Root}/VC-LTL helper for cmake.cmake")
  message(STATUS "aidbg: VC-LTL enabled (${VC_LTL_Root}, ucrt mode, x64)")
else()
  message(WARNING "aidbg: VC-LTL not found at '${VC_LTL_Root}', using pure static CRT (/MT)")
endif()

# ---- Zydis (disassembler, same engine used by x64dbg) ----
set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_MAN OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYCORE_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYCORE_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYCORE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/zydis EXCLUDE_FROM_ALL)

# ---- aidbg core ----
set(AIDBG_SOURCES
  src/util/json.cpp
  src/util/json_parse.cpp
  src/util/strutil.cpp
  src/output/output.cpp
  src/engine/expr.cpp
  src/engine/disasm.cpp
  src/engine/win_compat.cpp
  src/engine/breakpoints.cpp
  src/engine/symbols.cpp
  src/engine/types.cpp
  src/engine/snapshot.cpp
  src/engine/snapstore.cpp
  src/engine/cfg.cpp
  src/engine/exports.cpp
  src/engine/importfix.cpp
  src/engine/ntview.cpp
  src/engine/hide.cpp
  src/engine/notes.cpp
  src/engine/pedump.cpp
  src/engine/memory.cpp
  src/engine/registers.cpp
  src/engine/exceptions.cpp
  src/engine/engine.cpp
  src/cmd/commands.cpp
  src/mcp/mcp_server.cpp
  src/main.cpp
)

add_executable(aidbg ${AIDBG_SOURCES})
target_include_directories(aidbg PRIVATE src third_party/zydis/include third_party/zydis/dependencies/zycore/include)
target_link_libraries(aidbg PRIVATE Zydis dbghelp psapi advapi32 version cabinet)
if(MSVC)
  target_link_options(aidbg PRIVATE /INCREMENTAL:NO)
endif()
