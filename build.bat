@echo off
rem Build aidbg with MSVC (VS 18 Professional). Usage: build.bat [Release|Debug]
setlocal
set BUILD_TYPE=%1
if "%BUILD_TYPE%"=="" set BUILD_TYPE=Release

rem NOTE: %~dp0 ends in a backslash, which would escape a closing quote. Use a
rem trailing dot so the quoted path stays well formed.
set "ROOT=%~dp0."
set "BUILDDIR=%~dp0build"

rem Preferred install (the one this project was developed with). When it is
rem missing, look for any recent MSVC installation instead of hard-failing:
rem the old script only worked on a machine with exactly this VS path.
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
rem quoted form, used inside the nested cmd /c line below
set VCVARS32Q="%VCVARS32%"
if not exist "%VCVARS%" (
  echo [error] vcvars64.bat not found; install the MSVC build tools or edit build.bat
  exit /b 1
)

call "%VCVARS%" >nul 2>&1
if errorlevel 1 (
  echo [error] failed to initialize MSVC environment
  exit /b 1
)

rem ---- embedded DLL-host stubs (both archs) -------------------------------
rem Used when the target is a DLL: aidbg extracts the matching stub from its
rem own resources and runs the DLL inside it. Built before the main target
rem because the resource script embeds these binaries.
if not exist "%BUILDDIR%\host" mkdir "%BUILDDIR%\host"
cl /nologo /O1 /MT /W3 "%ROOT%\src\host\dllhost.c" /Fo:"%BUILDDIR%\host\dllhost64.obj" /Fe:"%BUILDDIR%\host\dllhost64.exe" /link /SUBSYSTEM:CONSOLE
if errorlevel 1 (
  echo [error] failed to build the x64 DLL host
  exit /b 1
)
rem the x86 stub needs the 32-bit library paths, so it builds in its own vcvars32
rem environment (the x64 environment cannot link it)
cmd /c "call %VCVARS32Q% >nul 2>&1 && cl /nologo /O1 /MT /W3 ""%ROOT%\src\host\dllhost.c"" /Fo:""%BUILDDIR%\host\dllhost32.obj"" /Fe:""%BUILDDIR%\host\dllhost32.exe"" /link /SUBSYSTEM:CONSOLE >nul"
if errorlevel 1 (
  echo [error] failed to build the x86 DLL host
  exit /b 1
)

cmake -S "%ROOT%" -B "%BUILDDIR%" -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=%BUILD_TYPE%
if errorlevel 1 exit /b 1

cmake --build "%BUILDDIR%" --parallel
if errorlevel 1 exit /b 1

echo.
echo [ok] built: %BUILDDIR%\aidbg.exe
endlocal
