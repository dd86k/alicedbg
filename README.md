# Introduction

**Please note that this is still is very early development!**

The alicedbg project aims to be an easy-to-use, simple debugger.

_Why not just use GDB?_ One might ask.

_Why not make one myself?_ I asked myself.

Personal Goals:

- [ ] Make a usable Text UI close to a professional debugger
- [ ] Debug an application on my Raspberry Pi 3B+ and my Purism Librem 5
- [ ] Disassemble ARM instructions with the Intel syntax
- [ ] Embed, as a library, into an embedded HTTP server to provide a local WebUI

## Support Matrix

### Feature Support

| Platform | OS | CRT | Debugging core |
|---|---|---|:-:|
| x86 | Windows 7 and up | Microsoft (including WOW64) | ✔️ |
| | Linux | Glibc | ✔️* |
| ARM | Windows 10 | Microsoft |  |
| | Linux | Glibc | Planned! |

\* Currently unstable

### Disassembler Progress

| Platform | ~% | Extensions or Version | Note |
|---|---|---|---|
| x86-32 | 50 | MMX, SSE | Still adding |
| x86-64 | 0 | | Waiting on x86-32 |
| arm-t32 | 0 | | Waiting on x86-64 |
| arm-a32 | 0 | | Waiting on x86-64 |
| arm-a64 | 0 | | Waiting on x86-64 |
| webasm | 0 | | Planned |

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

| Option | Possible values | Description |
|---|---|---|
| `-ui` | `tui`, `loop`, `tcp-json` | Use an user interface |
| `-dstyle` | `intel`, `nasm`, `att` | (Disassembler) Use syntax style |
| `-ddump` | File path | (Disassembler) Disassemble flat binary |

## User Interfaces

An user interface can be specified with the `-ui` option.

`-ui ?` outputs this list:

| UI | Description |
|---|---|
| `tui` (Default) | (WIP) Text UI |
| `loop` | Continue by default, show brief exception information |
| `tcp-json` | (Planned feature) TCP+JSON API server |

### UI: tui

The Text UI is currently in development.

### UI: loop

The loop UI is the simplest implementation, featuring simple output on
exceptions. The UI continues automatically on exceptions and is not
interactive.

Occuring exceptions are printed on screen:

```
-------------------------------------
* EXCEPTION #0: BREAKPOINT (0x80000003)
* PID=5876 TID=1748
> 7783F146 / cc / int3
     EIP=7783f147  EFLAGS=00000246
     EAX=00000000     EBX=00b5e000
     ECX=4c830000     EDX=00000000
     ESP=00cff318     EBP=00cff344
     ESI=01261be8     EDI=777a37ec
```

Which features the exception counter, process ID, thread ID (Windows-only),
exception messsage (with its OS-specific code), memory location, a brief
disassembly (when available), and register list (when available).

# Build Instructions

## With DUB

Using DUB is recommended to build the project. A compiler can be chosen with the
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