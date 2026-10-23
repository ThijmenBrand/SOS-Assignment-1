@echo off
rem ============================================================================
rem install-deps.cmd - install the Windows build prerequisites for Task 4.1.
rem
rem A thin wrapper around install-deps.ps1 so that:
rem   * PowerShell's execution policy cannot block the script
rem   * it can be started by double-clicking, or by right-clicking and
rem     choosing "Run as administrator"
rem
rem   install-deps.cmd              check, ask, install, then build
rem   install-deps.cmd -Yes         do not ask for confirmation
rem   install-deps.cmd -SkipBuild   install only, do not run build.bat
rem
rem Installs: Visual Studio Build Tools (Desktop development with C++) and
rem Win64 OpenSSL v3. Both are skipped when already present.
rem ============================================================================

setlocal
cd /d "%~dp0"

if not exist "%~dp0install-deps.ps1" (
    echo ERROR: install-deps.ps1 is missing from this directory.
    goto :pause_and_exit_fail
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-deps.ps1" %*
set "RC=%ERRORLEVEL%"

rem Keep the window open when started from Explorer, where there is no shell
rem left to read the output in. %CMDCMDLINE% contains /c only in that case.
echo %CMDCMDLINE% | find /i "/c" >nul
if not errorlevel 1 pause

exit /b %RC%

:pause_and_exit_fail
echo %CMDCMDLINE% | find /i "/c" >nul
if not errorlevel 1 pause
exit /b 1
