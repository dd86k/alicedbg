# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Alice Debugger (alicedbg) is a cross-platform debugging and object inspection framework written entirely in D's BetterC mode. It targets Windows, Linux, and FreeBSD on x86, x86-64, Armv7, and AArch64. Pre-1.0 with unstable APIs.

## Build & Test Commands

The project uses DUB (D's package manager/build system). Supported compilers: DMD, LDC, GDC.

```sh
# Build the library
dub build

# Build subpackages (executables)
dub build :debugger    # builds alicedbg CLI
dub build :dumper      # builds alicedump CLI

# Run tests
dub test               # Run tests for library
dub test :debugger     # Test debugger subpackage
dub test :dumper       # Test dumper subpackage

# Run specific test configurations (run only if needed/related)
dub test -c threading       # OS threading tests
dub test -c easy-api        # Easy API integration tests (this needs the easy test target to be built)
dub test -c setjmp          # setjmp/longjmp tests (unstable on Win64)

# Build types (can be used with subpackages)
dub build -b debug          # debug mode
dub build -b release        # release mode
dub build -b trace          # extremely verbose tracing
dub build -b release-static # statically linked release

# Generate documentation
dub build -b docs
```

## Git Branches

- `marisa`: Main development branch. Use as PR target.
- `stable`: Last released branch.

## Architecture

Essentially, there are two sets of APIs: Easy API (`src/adbg/easy.d`) and Multi API (the rest).

### Library (`src/adbg/`)

The public API surface is defined in `src/adbg/package.d` and re-exports these core modules:

- **`debugger.d`** — Core debugging features: process spawning/attaching, pause/suspend/resume, event-driven via ptrace (POSIX) or Windows Debug API
- **`process/`** — Process management: threads, memory read/write, breakpoints, stack frames, exception info
- **`objectserver.d`** + **`objects/`** — Binary format parsing for 14+ formats (ELF, PE, Mach-O, PDB, COFF, AR, MZ, NE, LX, etc.)
- **`disassembler.d`** — Capstone 4.0.2 wrapper for multi-architecture disassembly (optional runtime dependency)
- **`scanner.d`** — Process memory pattern scanning
- **`error.d`** — Error handling via `adbg_oops()` (sets global error state, returns error codes)
- **`easy.d`** — High-level multithreaded debugging loop API using message-based mailboxes (WIP, `easyapi` branch)

### Internal utilities (`src/adbg/utils/`)

These are used within alicedbg internally, though sometimes the front-ends re-use these.

- **`bit.d`** — Bit operations.
- **`date.d`** — Date utilities.
- **`list.d`** — Provides a simple O(1) list interface to append and retrieve item.
- **`mailbox.d`** — Multithreading mailbox.
- **`math.d`** — Math functions.
- **`strings.d`** — String utilities: arguments, better string length, etc.
- **`uid.d`** — UUID/GUID utilities.

### OS Abstraction (`src/adbg/os/`)

Threads, mutexes, semaphores, file I/O, path utilities — abstracts platform differences between Windows and POSIX.

### C Bindings (`src/adbg/include/`)

Hand-written bindings organized by platform: `c/` (libc), `windows/`, `posix/`, `linux/`, `freebsd/`, `macos/`, `capstone/`.

### CLI Frontends

- **`debugger/`** — Interactive debugger shell (`shell.d` is the main REPL, ~32KB)
- **`dumper/`** — Object file dumper with per-format modules (`format_elf.d`, `format_pe.d`, etc.)
- **`common/`** — Shared CLI utilities (option parsing, terminal ops, error reporting). `sourceLibrary` type, linked into both frontends.

## BetterC Constraints

All code compiles with `-betterC`. This means:
- No garbage collector, no D runtime exceptions, no `Phobos` standard library
- No TypeInfo, no ModuleInfo, no classes, no built-in threading (core.thread)
- No Dynamic arrays (though slices of static arrays and pointers work)
- No Associative arrays
- No Exceptions
- No `synchronized` and core.sync
- No static module constructors and destructors
- Manual memory management (`malloc`/`calloc`/`free`)
- All functions interacting with C use `extern (C)`
- Error handling is return-code based via `adbg_oops()` in adbg.error

Many D features are retained:
- unittests, which are written in normal D for convencience.
- Unrestricted use of compile-time features
- Full metaprogramming facilities
- Nested functions, nested structs, delegates and lambdas
- Member functions, constructors, destructors, operating overloading, etc.
- The full module system
- Array slicing, and array bounds checking
- RAII
- scope(exit)
- Memory safety protections
- Interfacing to C++
- COM classes and C++ classes
- assert failures are directed to the C runtime library
- switch with strings
- final switch
- printf format validation

## Code Conventions

- Constants: `UPPER_SNAKE_CASE`
- Functions: `snake_case` (C-style)
- Enums: `PascalCase`
- Structs: Typically prefixed with `adbg_` and suffixed with `_t`
- Platform-specific code uses `version` guards (`version (Windows)`, `version (Posix)`, etc.)
- Code sections marked with `// ANCHOR Section Name` comments
- Module headers use triple-slash doc comments with Authors, Copyright, License
- D-Scanner config in `dscanner.ini` (style checks mostly disabled; code quality checks enabled)

## Optional Dependency

Capstone disassembly engine 4.0.2 is an optional runtime dependency. Install via system package manager (e.g., `libcapstone4` on Debian/Ubuntu 22.04+) or download DLL on Windows.

Assume for it to be installed for development purposes.

## Important Notes

### Debugger Process Control

Two distinct operations exist for stopping a running process:

- **Debug break** (`pause`): Interrupts the process and generates a `processPaused` debug event. The user calls `continue` to resume. Uses `DebugBreakProcess` on Windows, `kill(SIGSTOP)` on POSIX.
- **OS-level suspend** (`suspend`/`resume`): Freezes threads at OS level. On Windows uses `NtSuspendProcess`/`NtResumeProcess` (no debug event generated). On POSIX, functionally equivalent to pause since ptrace intercepts all signals.

### Windows

The Debugger API on Windows require all calls to be done by the thread that initially spawned or attached to the process.
