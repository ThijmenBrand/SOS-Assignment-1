<#
.SYNOPSIS
    Install the build prerequisites for Task 4.1 on native Windows.

.DESCRIPTION
    Installs the two things build.bat needs and nothing else:

      1. Visual Studio Build Tools with the "Desktop development with C++"
         workload  (the compiler, linker and NMake)
      2. Win64 OpenSSL v3, full package  (headers + import libraries)

    Both steps are skipped when they are already present, so re-running the
    script is harmless. Installing software needs Administrator rights; the
    script asks for them itself when it has work to do.

    Nothing here touches the project sources. The GNU Makefile build on
    macOS/Linux/MSYS2 is unaffected.

.PARAMETER Yes
    Do not ask for confirmation before installing.

.PARAMETER SkipBuild
    Do not run build.bat once the prerequisites are in place.

.PARAMETER OpenSslUrl
    Install OpenSSL from this installer URL instead of through a package
    manager. Use when the machine has neither winget nor Chocolatey, e.g.
      -OpenSslUrl "https://slproweb.com/download/Win64OpenSSL-3_5_4.exe"

.EXAMPLE
    .\install-deps.ps1
    .\install-deps.ps1 -Yes -SkipBuild
#>

[CmdletBinding()]
param(
    [switch] $Yes,
    [switch] $SkipBuild,
    [string] $OpenSslUrl
)

# Deliberately NOT $ErrorActionPreference = 'Stop': vswhere, winget and choco
# all write harmless notices to stderr, which 'Stop' turns into terminating
# NativeCommandError exceptions. Every call below checks its own exit code.
$ErrorActionPreference = 'Continue'

# TLS 1.2 is not the default on older Windows 10 builds, and every download
# below is https.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    # Already fine on anything current; not worth failing over.
}

# --- Small output helpers ----------------------------------------------------

function Write-Step  ([string] $Text) { Write-Host ""; Write-Host "==> $Text" -ForegroundColor Cyan }
function Write-Ok    ([string] $Text) { Write-Host "    OK   $Text" -ForegroundColor Green }
function Write-Info  ([string] $Text) { Write-Host "    $Text" }
function Write-Warn  ([string] $Text) { Write-Host "    WARN $Text" -ForegroundColor Yellow }
function Write-Fail  ([string] $Text) { Write-Host "    FAIL $Text" -ForegroundColor Red }

# --- Detection ---------------------------------------------------------------

function Test-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-VsWherePath {
    # vswhere ships with every Visual Studio installer since 2017 and always
    # lands in the same place, whatever edition is installed.
    $roots = @(${env:ProgramFiles(x86)}, $env:ProgramFiles)
    foreach ($root in $roots) {
        if (-not $root) { continue }
        $c = Join-Path $root 'Microsoft Visual Studio\Installer\vswhere.exe'
        if (Test-Path -LiteralPath $c) { return $c }
    }
    return $null
}

function Get-VcToolsPath {
    # Returns the install path of a VS instance that actually has the C++
    # compiler, or $null. This is the same query build.bat uses.
    $vswhere = Get-VsWherePath
    if (-not $vswhere) { return $null }

    $found = & $vswhere -latest -products '*' `
                        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
                        -property installationPath 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }

    foreach ($line in @($found)) {
        $path = "$line".Trim()
        if ($path -and (Test-Path -LiteralPath (Join-Path $path 'VC\Auxiliary\Build\vcvars64.bat'))) {
            return $path
        }
    }
    return $null
}

function Get-OpenSslPrefix {
    # Mirrors the probe in Makefile.msvc: headers AND an import library, since
    # the "Light" installer ships the DLLs only.
    $prefixes = @(
        'C:\Program Files\OpenSSL-Win64',
        'C:\OpenSSL-Win64',
        'C:\Program Files\OpenSSL',
        (Join-Path $env:USERPROFILE 'vcpkg\installed\x64-windows'),
        'C:\vcpkg\installed\x64-windows'
    )
    $libs = @(
        'lib\VC\x64\MD\libcrypto.lib',
        'lib\VC\libcrypto64MD.lib',
        'lib\libcrypto.lib'
    )

    foreach ($prefix in $prefixes) {
        if (-not $prefix) { continue }
        if (-not (Test-Path -LiteralPath (Join-Path $prefix 'include\openssl\evp.h'))) { continue }
        foreach ($lib in $libs) {
            if (Test-Path -LiteralPath (Join-Path $prefix $lib)) { return $prefix }
        }
        Write-Warn "$prefix has OpenSSL headers but no import library (the ""Light"" package?)"
    }
    return $null
}

function Test-Command ([string] $Name) {
    $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

# --- Installers --------------------------------------------------------------

function Install-VcBuildTools {
    # The bootstrapper is used rather than a package manager because it both
    # installs Build Tools and adds the C++ workload to an existing install,
    # which is the common case on a machine that already has Visual Studio.
    $url = 'https://aka.ms/vs/17/release/vs_BuildTools.exe'
    $exe = Join-Path $env:TEMP 'vs_BuildTools.exe'

    Write-Info "Downloading the Visual Studio Build Tools bootstrapper..."
    try {
        Invoke-WebRequest -Uri $url -OutFile $exe -UseBasicParsing -ErrorAction Stop
    } catch {
        Write-Fail "Download failed: $($_.Exception.Message)"
        return $false
    }

    Write-Info "Running the installer. This downloads a few GB and takes a while;"
    Write-Info "it is silent on purpose, so no window will appear."

    $vsArgs = @(
        '--quiet', '--wait', '--norestart', '--nocache',
        '--add', 'Microsoft.VisualStudio.Workload.VCTools',
        '--includeRecommended'
    )
    $proc = Start-Process -FilePath $exe -ArgumentList $vsArgs -Wait -PassThru
    Remove-Item -LiteralPath $exe -Force -ErrorAction SilentlyContinue

    # 3010 means "installed, but Windows wants a reboot" - the compiler works.
    if ($proc.ExitCode -eq 0)    { return $true }
    if ($proc.ExitCode -eq 3010) { Write-Warn "Windows asks for a reboot, but the compiler is usable now."; return $true }

    Write-Fail "The Build Tools installer exited with code $($proc.ExitCode)."
    return $false
}

function Install-OpenSslFromUrl ([string] $Url) {
    $exe = Join-Path $env:TEMP 'Win64OpenSSL-setup.exe'

    Write-Info "Downloading $Url"
    try {
        Invoke-WebRequest -Uri $Url -OutFile $exe -UseBasicParsing -ErrorAction Stop
    } catch {
        Write-Fail "Download failed: $($_.Exception.Message)"
        return $false
    }

    # The slproweb installers are Inno Setup; /VERYSILENT is its quiet switch.
    Write-Info "Running the OpenSSL installer..."
    $proc = Start-Process -FilePath $exe `
                          -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-' `
                          -Wait -PassThru
    Remove-Item -LiteralPath $exe -Force -ErrorAction SilentlyContinue

    if ($proc.ExitCode -ne 0) {
        Write-Fail "The OpenSSL installer exited with code $($proc.ExitCode)."
        return $false
    }
    return $true
}

function Install-OpenSsl {
    if ($OpenSslUrl) {
        return (Install-OpenSslFromUrl $OpenSslUrl)
    }

    if (Test-Command 'winget') {
        # The package was split into .Dev (headers + libs) and .Light (DLLs
        # only) at some point, and older indexes have neither name, so try the
        # candidates in order of preference and take the first that resolves.
        foreach ($id in @('ShiningLight.OpenSSL.Dev', 'ShiningLight.OpenSSL')) {
            Write-Info "Trying winget package $id ..."
            & winget install --id $id --exact --silent `
                             --accept-source-agreements --accept-package-agreements 2>&1 |
                ForEach-Object { Write-Info $_ }
            if ($LASTEXITCODE -eq 0) { return $true }
        }
        Write-Warn "winget could not install OpenSSL."
    }

    if (Test-Command 'choco') {
        Write-Info "Trying Chocolatey (choco install openssl) ..."
        & choco install openssl --yes --no-progress 2>&1 | ForEach-Object { Write-Info $_ }
        if ($LASTEXITCODE -eq 0) { return $true }
        Write-Warn "Chocolatey could not install OpenSSL."
    }

    Write-Fail "No package manager could install OpenSSL on this machine."
    Write-Host ""
    Write-Host "    Install it by hand instead - pick ""Win64 OpenSSL v3.x"", the full" -ForegroundColor Yellow
    Write-Host "    package and not ""Light"", from:" -ForegroundColor Yellow
    Write-Host "        https://slproweb.com/products/Win32OpenSSL.html" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    Or re-run this script with the installer URL:" -ForegroundColor Yellow
    Write-Host "        .\install-deps.ps1 -OpenSslUrl ""https://slproweb.com/download/Win64OpenSSL-3_5_4.exe""" -ForegroundColor Yellow
    return $false
}

# --- Main --------------------------------------------------------------------

Write-Host ""
Write-Host "Task 4.1 - Windows build prerequisites" -ForegroundColor White
Write-Host "--------------------------------------"

Write-Step "Checking what is already installed"

$vcPath     = Get-VcToolsPath
$sslPrefix  = Get-OpenSslPrefix

if ($vcPath) { Write-Ok "C++ compiler      $vcPath" }
else         { Write-Info "MISSING  C++ compiler (Visual Studio Build Tools, VCTools workload)" }

if ($sslPrefix) { Write-Ok "OpenSSL 3         $sslPrefix" }
else            { Write-Info "MISSING  OpenSSL 3 development files" }

$todo = @()
if (-not $vcPath)    { $todo += 'Visual Studio Build Tools (Desktop development with C++, several GB)' }
if (-not $sslPrefix) { $todo += 'Win64 OpenSSL v3 (full package)' }

if ($todo.Count -eq 0) {
    Write-Step "Nothing to install"
} else {
    Write-Step "About to install"
    foreach ($item in $todo) { Write-Host "      - $item" }
    Write-Host ""

    if (-not $Yes) {
        $answer = Read-Host "    Continue? [y/N]"
        if ($answer -notmatch '^(y|yes)$') {
            Write-Host ""
            Write-Host "Nothing was installed." -ForegroundColor Yellow
            exit 1
        }
    }

    # Installers write to Program Files and the registry, so elevate now -
    # after the user has seen the list, so the UAC prompt is not a surprise.
    if (-not (Test-Administrator)) {
        Write-Step "Restarting as Administrator"
        Write-Info "Installing system-wide needs elevation. A UAC prompt follows, and"
        Write-Info "the work continues in the new window - watch that one, not this."

        $relaunch = @(
            '-NoExit', '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', "`"$PSCommandPath`"", '-Yes'
        )
        if ($SkipBuild) { $relaunch += '-SkipBuild' }
        if ($OpenSslUrl) { $relaunch += @('-OpenSslUrl', "`"$OpenSslUrl`"") }

        try {
            Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $relaunch | Out-Null
        } catch {
            Write-Fail "Elevation was refused. Right-click install-deps.cmd and pick ""Run as administrator""."
            exit 1
        }
        exit 0
    }

    if (-not $vcPath) {
        Write-Step "Installing the Visual Studio Build Tools"
        if (Install-VcBuildTools) {
            $vcPath = Get-VcToolsPath
            if ($vcPath) { Write-Ok "C++ compiler      $vcPath" }
            else         { Write-Fail "The installer finished but no C++ compiler was found." }
        }
    }

    if (-not $sslPrefix) {
        Write-Step "Installing OpenSSL 3"
        if (Install-OpenSsl) {
            $sslPrefix = Get-OpenSslPrefix
            if ($sslPrefix) { Write-Ok "OpenSSL 3         $sslPrefix" }
            else            { Write-Fail "The installer finished but no OpenSSL development files were found." }
        }
    }
}

# --- Result ------------------------------------------------------------------

Write-Step "Result"

$ready = $true
if ($vcPath)    { Write-Ok   "C++ compiler      $vcPath" }    else { Write-Fail "C++ compiler      missing"; $ready = $false }
if ($sslPrefix) { Write-Ok   "OpenSSL 3         $sslPrefix" } else { Write-Fail "OpenSSL 3         missing";  $ready = $false }

if (-not $ready) {
    Write-Host ""
    Write-Host "Prerequisites are incomplete - see the messages above." -ForegroundColor Red
    Write-Host "Building-Cross-OS.md has the manual steps." -ForegroundColor Yellow
    exit 1
}

if ($SkipBuild) {
    Write-Host ""
    Write-Host "Ready. Build the programs with:  build.bat" -ForegroundColor Green
    exit 0
}

# build.bat locates the compiler itself, so no shell restart is needed even
# though this session's PATH predates the install.
Write-Step "Building"

$buildBat = Join-Path $PSScriptRoot 'build.bat'
if (-not (Test-Path -LiteralPath $buildBat)) {
    Write-Warn "build.bat was not found next to this script; build it yourself."
    exit 0
}

& $buildBat
exit $LASTEXITCODE
