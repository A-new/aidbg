@echo off
rem Build aidbg with MSVC (VS 18 Professional). Usage: build.bat [Release|Debug]
setlocal
set BUILD_TYPE=%1
if "%BUILD_TYPE%"=="" set BUILD_TYPE=Release

rem NOTE: %~dp0 ends in a backslash, which would escape a closing quote. Use a
rem trailing dot so the quoted path stays well formed.
set "ROOT=%~dp0."
set "BUILDDIR=%~dp0build"

set VCVARS="D:\Program Files\Microsoft Visual Studio\18\Professional\VC\Auxiliary\Build\vcvars64.bat"
if not exist %VCVARS% (
  echo [error] vcvars64.bat not found at %VCVARS%
  exit /b 1
)

call %VCVARS% >nul 2>&1
if errorlevel 1 (
  echo [error] failed to initialize MSVC environment
  exit /b 1
)

cmake -S "%ROOT%" -B "%BUILDDIR%" -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=%BUILD_TYPE%
if errorlevel 1 exit /b 1

cmake --build "%BUILDDIR%" --parallel
if errorlevel 1 exit /b 1

echo.
echo [ok] built: %BUILDDIR%\aidbg.exe
endlocal
