# Building the programs

The same C sources build on all three platforms; only the build driver differs.

| Platform            | Command     | Toolchain                     |
| ------------------- | ----------- | ----------------------------- |
| macOS               | `make`      | clang + Homebrew OpenSSL 3    |
| Linux / WSL         | `make`      | gcc + libssl-dev              |
| Windows             | `build.bat` | MSVC + Win64 OpenSSL 3        |
| Windows (MSYS2)     | `make`      | MinGW-w64 gcc + MSYS2 OpenSSL |

`Makefile` is the GNU make build (macOS, Linux, MinGW); it detects the platform
and sets the compiler, the OpenSSL location and the executable suffix itself.
`Makefile.msvc` is the NMake build for native Windows and `build.bat` is a
wrapper around it that locates Visual Studio first.

Either way the result is `task41enc` (encryptor) and `task41dec` (decryptor),
or `task41enc.exe` and `task41dec.exe` on Windows. The `clean` target removes
the binaries, the object files and `text.ct`.

## macOS

macOS ships LibreSSL without development headers, so OpenSSL 3 has to be
installed through Homebrew first:

```
brew install openssl@3
```

The Makefile looks for the keg in `/opt/homebrew/opt/openssl@3` (Apple Silicon)
and `/usr/local/opt/openssl@3` (Intel) and adds the include and library paths
automatically.

## Windows

There is no need for MSYS2, `pacman` or MinGW. The native route uses the
Microsoft toolchain and the official OpenSSL build, both of which are ordinary
Windows installers.

**1. Install the compiler.** Either Visual Studio 2019/2022 (any edition,
including Community) or the free standalone
[Build Tools for Visual Studio](https://visualstudio.microsoft.com/downloads/).
In the installer, tick the **Desktop development with C++** workload.

**2. Install OpenSSL.** Download **Win64 OpenSSL v3.x** from
[slproweb.com](https://slproweb.com/products/Win32OpenSSL.html) and run it with
the defaults. Take the *full* package, not the "Light" one: Light ships only the
runtime DLLs, without the headers and import libraries a build needs.

**3. Build.** Open a normal `cmd.exe` in this directory and run:

```
build.bat
```

That is the whole build. `build.bat` finds the compiler itself (through
`vswhere`, so no Developer Command Prompt is required), hands over to
`nmake /f Makefile.msvc`, and copies `libcrypto-3-x64.dll` next to the
executables so they also run when double-clicked from Explorer. It takes the
same targets as the Makefile:

```
build.bat run-enc
build.bat run-dec
build.bat clean
```

`Makefile.msvc` probes the usual OpenSSL install directories (the Win64
installer's default location, `C:\OpenSSL-Win64`, and vcpkg's
`x64-windows` tree). For anything else, name it; everything after `build.bat`
is passed straight to NMake:

```
build.bat OPENSSL_PREFIX="D:\libs\openssl-3"
```

Inside an *x64 Native Tools Command Prompt* the wrapper adds nothing, so NMake
can be called directly:

```
nmake /f Makefile.msvc
```

Two notes on the MSVC build. The programs are compiled `/MD`, which is not a
free choice: `fatal()` passes `stderr` to OpenSSL's `ERR_print_errors_fp()`, so
the program and `libcrypto` must share one C runtime, and the official OpenSSL
binaries are `/MD` against the UCRT. And `/std:c11` needs Visual Studio 2019
version 16.8 or newer; older compilers ignore the flag with a warning and still
build the code, which uses nothing newer than C99 in practice.

### Windows via MSYS2

Still supported, and the GNU `Makefile` handles it, if MSYS2 is already
installed:

```
pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-openssl make
make
```

Building from a plain `cmd.exe` with MinGW-w64 on the PATH also works, using
`mingw32-make` instead of `make`, and `OPENSSL_PREFIX` overrides the probe there
too.

### What differs in the source

Windows and POSIX differ in one place: switching terminal echo off while the
password is typed. `prompt_password()` in `common.c` therefore has two branches
behind `#ifdef _WIN32`, one using `SetConsoleMode()` and one using `termios`.
Everything else is identical on all platforms, and the MSVC build compiles the
same unmodified sources as the others.

## Linux (and WSL)

The system OpenSSL is used, so only the development package is needed:

```
sudo apt install build-essential libssl-dev
make
```
