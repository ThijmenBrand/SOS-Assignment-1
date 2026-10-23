@echo off
rem ============================================================================
rem build.bat - build Task 4.1 on native Windows, without MSYS2 or MinGW.
rem
rem Needs only:
rem   * Visual Studio 2019/2022 (any edition) or the free "Build Tools for
rem     Visual Studio", with the "Desktop development with C++" workload
rem   * "Win64 OpenSSL v3.x" from https://slproweb.com/products/Win32OpenSSL.html
rem     (the full package - the "Light" one has no headers or import libraries)
rem
rem Then, from this directory:
rem
rem   build.bat              build task41enc.exe and task41dec.exe
rem   build.bat run-enc      build and run the encryptor
rem   build.bat run-dec      build and run the decryptor
rem   build.bat clean        remove binaries, objects and text.ct
rem
rem Anything you type after build.bat is handed to NMake, so an OpenSSL in an
rem unusual place can be pointed at directly:
rem
rem   build.bat OPENSSL_PREFIX="D:\libs\openssl-3"
rem ============================================================================

setlocal enabledelayedexpansion
cd /d "%~dp0"

rem --- 1. Make sure the MSVC toolchain is on the PATH -------------------------
rem Inside a "x64 Native Tools Command Prompt" it already is; from a plain
rem cmd.exe or Explorer it is not, so locate Visual Studio and set it up.

where cl.exe >nul 2>&1
if %ERRORLEVEL% equ 0 goto :have_compiler

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"

if not exist "%VSWHERE%" (
    echo.
    echo ERROR: Visual Studio was not found on this machine.
    echo.
    echo Install the free "Build Tools for Visual Studio" and tick the
    echo "Desktop development with C++" workload:
    echo     https://visualstudio.microsoft.com/downloads/
    echo.
    exit /b 1
)

set "VSPATH="
for /f "usebackq tokens=*" %%i in (`
    "%VSWHERE%" -latest -products * ^
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 ^
        -property installationPath
`) do set "VSPATH=%%i"

if not defined VSPATH (
    echo.
    echo ERROR: Visual Studio is installed, but without the C++ compiler.
    echo.
    echo Re-run the Visual Studio Installer, choose Modify, and tick
    echo "Desktop development with C++".
    echo.
    exit /b 1
)

set "VCVARS=%VSPATH%\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
    echo ERROR: expected the compiler setup script at:
    echo     %VCVARS%
    exit /b 1
)

echo Using Visual Studio at: %VSPATH%
call "%VCVARS%" >nul
if errorlevel 1 (
    echo ERROR: "%VCVARS%" failed.
    exit /b 1
)

:have_compiler

rem --- 2. Hand over to NMake --------------------------------------------------
rem Makefile.msvc finds OpenSSL, compiles, links and copies libcrypto next to
rem the executables. Everything after build.bat is passed straight through.

nmake /nologo /f Makefile.msvc %*
if errorlevel 1 (
    echo.
    echo Build FAILED.
    exit /b 1
)

echo.
echo Build OK.  Run the programs with:
echo     task41enc.exe
echo     task41dec.exe
exit /b 0
