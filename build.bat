@echo off
setlocal

rem ---- sw_ac_emu build script ----
rem Requires:
rem   * VS 2026 Community (toolset v145) at "C:\Program Files\Microsoft Visual Studio\18\Community"
rem   * CMake 4.x in PATH (or at "C:\Program Files\CMake\bin")
rem
rem Usage: build.bat            (Release, x86, output -> build\sw_ac_emu.asi)
rem        build.bat clean      (delete build dir first)

set "VS_ROOT=C:\Program Files\Microsoft Visual Studio\18\Community"
set "VCVARS=%VS_ROOT%\VC\Auxiliary\Build\vcvarsall.bat"
set "CMAKE=C:\Program Files\CMake\bin\cmake.exe"

if not exist "%VCVARS%" (
    echo [build.bat] vcvarsall.bat not found at "%VCVARS%"
    exit /b 1
)
if not exist "%CMAKE%" (
    where cmake >nul 2>&1 || (
        echo [build.bat] cmake.exe not found
        exit /b 1
    )
    set "CMAKE=cmake.exe"
)

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "BUILD=%ROOT%\build"

if /I "%~1"=="clean" (
    if exist "%BUILD%" rmdir /S /Q "%BUILD%"
)

if not exist "%ROOT%\te_sdk\lib\te_sdk_rel.lib" (
    echo [build.bat] te_sdk submodule not initialized.
    echo            Run: git submodule update --init --recursive
    exit /b 1
)

if not exist "%ROOT%\te_sdk_inc" (
    mklink /J "%ROOT%\te_sdk_inc" "%ROOT%\te_sdk\#TE SDK" >nul
    if errorlevel 1 (
        echo [build.bat] Failed to create junction te_sdk_inc -^> te_sdk\#TE SDK
        exit /b 1
    )
)

if not exist "%BUILD%" mkdir "%BUILD%"

call "%VCVARS%" x86 || exit /b 1

"%CMAKE%" -S "%ROOT%" -B "%BUILD%" -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release || exit /b 1
"%CMAKE%" --build "%BUILD%" --config Release || exit /b 1

echo.
echo [build.bat] Done. Output:
dir /B "%BUILD%\*.asi"
endlocal
