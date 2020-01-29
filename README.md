# Introduction

**Please note that this is still is very early development!**

The alicedbg project aims to be an easy-to-use, simple debugger.

_Why not just use GDB?_ One might ask.

_Why not make one myself?_ I asked myself.

## Support Matrix

| OS | CRT | Debugging core |
|---|---|---|
| Windows | Microsoft | ✔️ |
| Linux | Glibc | ✔️ |

| ABI | ~% | Disassembler status |
|---|---|---|
| x86-32 | 40 | Still adding |
| x86-64 | 0 | Waiting on x86-32 |
| arm | 0 | Waiting on x86-64 |
| aarch64 | 0 | Waiting on x86-64 |

## FAQ

### Why D?

I love the D programming language for so many reason I could go on forever
talking about it, so I'll just say that I love it for its practical approach.

### What about the GC?

The project is compiled with the BetterC mode, so no druntime and no GC. The
functions are also marked with a C extern so that hopefully C programs (or
others) use its functions as a library (static or dynamically).

# Usage

To debug an application, use -exec PATH, or to debug an existing process,
use -pid PROCESSID.

## User Interfaces

An user interface can be specified with the `-ui` option.

`-ui ?` outputs this list:

| UI | Description |
|---|---|
| `tui` (Default) | (WIP) Text UI |
| `loop` | Simple catch-try loop with no user input |
| `tcp-json` | (Planned feature) TCP+JSON API server |

### UI: tui

The Text UI is currently in development.

### UI: loop

The loop UI is the simplest implementation, featuring simple output on
exceptions. The UI continues automatically on exceptions and is not
interactive.

On exceptions, this is added to output:
```
* EXCEPTION #0
PID=4104  TID=2176
BREAKPOINT (80000003) at 77ABF146
Code: CC  (INT 3)
```

Which features the exception counter, process ID, thread ID (Windows-only),
exception messsage (with its OS-specific code), memory location, and a
brief disassembly (when available).

# Build Instructions

## With DUB

DUB is highly required to build the project. A compiler can be chosen with the
`--compiler=` switch. I try to support DMD, GDC, and LDC as much as possible.

Do note that the `betterC` mode is activated for normal builds and
documentation. Unittesting (and the rest) uses the druntime library so any
Phobos functions may be used.

| Build type | Command |
|---|---|
| Debug | `dub build` |
| Release | `dub build -b release-nobounds` |

## Without DUB

Without DUB, it's still possible to compile the project, but I believe you'll
have to reference every file (by module name is okay). The `-betterC` switch
is optional, but recommended.