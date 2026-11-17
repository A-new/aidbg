@echo off
rem Rebuild the test targets whose regressions resolve symbols that are NOT
rem exports. The executables are committed, but their PDBs are not (about
rem 7 MB each), so a clean checkout or a CI runner cannot resolve `accumulate`
rem / `Node` / `g_ticks` without this step. Tests that only need exports or
rem module-relative addresses keep using the committed binaries.
rem
rem Usage: tests\build_targets.bat   (rewrites tests\*.exe + matching *.pdb)
setlocal
set "TESTS=%~dp0."
set "OUT=%~dp0..\build\test_targets"

rem Same MSVC discovery as build.bat: prefer the documented install, then any
rem recent Visual Studio.
set "VCVARS=D:\Program Files\Microsoft Visual Studio\18\Professional\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
  for %%r in ("%ProgramFiles%" "%ProgramFiles(x86)%") do (
    for %%y in (18 2022 2019) do (
      for %%e in (Professional Community Enterprise BuildTools) do (
        if not defined FOUND_VS if exist "%%~r\Microsoft Visual Studio\%%y\%%e\VC\Auxiliary\Build\vcvars64.bat" (
          set "VCVARS=%%~r\Microsoft Visual Studio\%%y\%%e\VC\Auxiliary\Build\vcvars64.bat"
          set "FOUND_VS=1"
        )
      )
    )
  )
)
set "VCVARS32=%VCVARS:vcvars64.bat=vcvars32.bat%"
set VCVARS32Q="%VCVARS32%"
if not exist "%VCVARS%" (
  echo [error] vcvars64.bat not found; install the MSVC build tools or edit this script
  exit /b 1
)
if not exist "%OUT%" mkdir "%OUT%"

call "%VCVARS%" >nul 2>&1
if errorlevel 1 (
  echo [error] failed to initialize MSVC environment
  exit /b 1
)

rem /Z7 keeps compiler debug info in the object files, so the only PDB written
rem is the linker's - one per target.
set "CFLAGS=/nologo /O1 /MT /Z7 /W3 /utf-8 /D_CRT_SECURE_NO_WARNINGS"
set "LFLAGS=/link /DEBUG /INCREMENTAL:NO /SUBSYSTEM:CONSOLE"

rem x64 targets: accumulate (target), Node/g_head (types_test), g_ticks (tickpair)
for %%t in (target types_test tickpair) do (
  cl %CFLAGS% "%TESTS%\%%t.cpp" /Fo:"%OUT%\%%t.obj" /Fe:"%TESTS%\%%t.exe" /Fd:"%TESTS%\%%t.pdb" %LFLAGS%
  if errorlevel 1 (
    echo [error] failed to build %%t.exe
    exit /b 1
  )
)

rem the x86 target needs its own environment (the x64 one cannot link x86)
cmd /c "call %VCVARS32Q% >nul 2>&1 && cl %CFLAGS% ""%TESTS%\target.cpp"" /Fo:""%OUT%\target32.obj"" /Fe:""%TESTS%\target32.exe"" /Fd:""%TESTS%\target32.pdb"" %LFLAGS%"
if errorlevel 1 (
  echo [error] failed to build target32.exe
  exit /b 1
)

echo [ok] rebuilt symbol-carrying test targets
endlocal
