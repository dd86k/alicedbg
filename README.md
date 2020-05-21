# Alice Debugger Project

**Please note that this is still is very early development!**

The alicedbg project aims to be an easy-to-use, simple debugger, object dumper,
and profiler. Either as a stand-alone program or as a library.

_Why not just use GDB or LLDB?_ One might ask.

_Why not make one from scratch myself?_ I asked myself.

Personal Goals:

- [ ] Make a usable Text UI close to a professional debugger
- [ ] Debug an application on my Raspberry Pi 3B+ and my Purism Librem 5
- [ ] Disassemble ARM instructions with the Intel syntax
- [ ] Embed, as a library, into an embedded HTTP server to provide a local WebUI
- [ ] Make a disassembly as a service

Roadmap:

- 0.1: INIT
  - Disassembler: x86 and x86-64 disassembler
  - Dumper: PE support
  - Debug UI: loop
  - OS: Windows and Linux
- 0.2: Sup, World?
  - Dumper: ELF support
  - Symbols
  - alicedbg.1
- 0.3: Useful
  - alicedbg.3

## Support Matrix

### Debugger Support

| Platform | OS | CRT | Debugging core |
|---|---|---|:-:|
| x86 | Windows 7 and up | Microsoft (+WOW64) | ✔️ |
| | Linux | Glibc | ✔️* |
| ARM | Windows 10 | Microsoft |  |
| | Linux | Glibc | Planned! |

\* Currently unstable

### Disassembler Support

| Platform | ~% | Extensions | Notes |
|---|---|---|---|
| x86-32 | 60 | x87, MMX, SSE (2/3/4.1/4.2/4a), AES, SHA, VMX, SVM 1.0, SMX, WAITPKG | Still adding and fixing |
| x86-64 | 30 | See x86-32 | Still fixing |
| arm-t32 | 0 | | Waiting on x86-64 |
| arm-a32 | 0 | | Waiting on x86-64 |
| arm-a64 | 0 | | Waiting on x86-64 |
| riscv-32 | 1 | RVC 2.0, RV32I 2.1 | |
| riscv-64 | 0 | | Waiting on riscv-32 |
| riscv-128 | 0 | | Waiting on riscv-32 |
| powerpc-32 | 0 | | Planned |
| powerpc-64 | 0 | | Planned |
| webasm | 0 | | Planned |
| cil | 0 | | Planned |

### Object Dump Support

| Type | ~% | Extensions | Notes |
|---|---|---|---|
| Binary | 50 | | Far from perfect | 
| MZ | 0 | | |
| LE | 0 | | |
| NE | 0 | | |
| PE | 15 | PE32-ROM, PE32, PE32+ | |
| ELF | 0 | | |
| Mach-O | 0 | | |

## FAQ

### Why this?

I've always wanted to make a debugger. Don't get me wrong, GDB and LLDB, among
other stars like x64dbg and decompilers like Ghidra, are excellent tools.

However, making this project allowed me to learn further more about varying
aspects of the underlaying operating system and platform.

### Why D?

I love the D programming language for so many reason I could go on forever
talking about it, so I'll just say that I love it for its practical approach
and technical reasons. It gets the job well done.

### What about the GC?

The project is compiled with the BetterC mode, so no druntime and no GC. The
functions are also marked with a C extern so that hopefully C programs (or
others) use its functions as a library (static or dynamically).

# Usage

The command-line interface processes items from left to right and was inspired
from the ffmpeg project (`-option [value]`).

| Option | Possible values | Default | Description |
|---|---|---|---|
| `-mode` | `debugger`, `dump`, `profile` | `debugger` | Operating mode |
| `-exe` | File path | | Set mode to Debugger and next argument as `file` |
| `-pid` | Process ID | | Set mode to Debugger and next argument as `pid` |
| `-ui` | `loop`, `cmd`, `tui` | `loop` (for now!) | (Debugger) User interface, only `loop` is available |
| `-march` | See `-march ?` | Target dependant | (Disassembler) Set machine architecture |
| `-syntax` | `intel`, `nasm`, `att` | Platform dependant | (Disassembler) Syntax style |
| `-dump` | | | Enables dump operation mode |
| `-raw` | | | (Dumper) Skip file format detection and process as raw blob |
| `-show` | `A`,`h`,`s`,`i`,`d` | `h` | (Dumper) Include item(s) into output |

Default operating mode is set to the debugger, and the default UI is set to the
TUI type.

The only default argument sets the debug type to a file with a file path.
Example: `alicedbg putty.exe -dump -show s`

### UI: loop

The loop UI is the simplest implementation, featuring simple output on
exceptions. On an exception, a prompt asks if you wish to continue,
step, or quit.

```
-------------------------------------
* EXCEPTION #0: BREAKPOINT (0x80000003)
* PID=1768 TID=9288
> 7FF8B9FF2DBC / cc / int3
     RIP=00007ff8b9ff2dbd  RFLAGS=00000246
     RAX=0000000000000000     RBX=0000000000000010
     RCX=00007ff8b9fbfc04     RDX=0000000000000000
     RSP=000000445dcff0a0     RBP=0000000000000000
     RSI=00007ff8ba04d100     RDI=000000445dbaf000

Action [S=Step,C=Continue,Q=Quit]
```

Which features the exception counter, process ID, thread ID, short exception
messsage, OS-specific code, memory location, a brief disassembly (when
available), and register list (when available).

### UI: cmd

The command interpreter UI is currently in development, and is currently not ready for use.

### UI: tui

The Text UI is currently in development, and is currently not ready for use.

# Build Instructions

## With DUB

DUB often comes with a D compiler and is the recommended way to build the
project. A compiler can be chosen with the `--compiler=` option. I try to
support DMD, GDC, and LDC as much as possible.

Do note that the `betterC` mode is activated for normal builds and
documentation. Unittesting (and the rest) uses the druntime library so any
Phobos functions may be used.

| Build type | Command |
|---|---|
| Debug | `dub build` |
| Release | `dub build -b release-nobounds` |
| AFL Fuzz | `dub build -b afl --compiler=ldc2` |

## With make(1)

Planned.

## Manually

It's still possible to compile the project by referencing every source files.
The `-betterC` switch is optional, but recommended.

## Fuzzing with AFL

In order to preform a fuzz, ldc version 1.0.0 or newer and AFL 2.50 or newer
are required, additionally the LLVM version that ldc and the library
`afl-llvm-pass.so` have been built with must be the same.

To fuzz, export the environment variable `AFL_ROOT` to the location where
`afl-llvm-pass.so` is located, then build with `dub -d afl`.

Then create two directories, `findings` and `testcases`, after that populate
`testcases` with files you wish to test with. It takes the files in this
directory and applies various transformations to them in order to explore new
code paths and attempt to find crashes, so it's important that all of these
input files be valid and correct.

After that, to fuzz, simply run
`afl-fuzz -i testcases -o findings ./alicedbg --DRT-trapExceptions=0 <OPTIONS> @@`
where `<OPTIONS>` are the various alicedbg options you wish to test with.

## Fuzzing with zzuf

zzuf is a transparent application input fuzzer (source: man page). zzuf
remains a good tool for its deterministic behavior.

To use zzuf, you will require a valid binary program, either flat for the
disassembler or an image-type for the dumper. The main parameters are `-r`
(rate) and `-s` (seed). A basic one-time fuzz can be written as
`zzuf -r 0.10 -s 47289 ./alice -dump -raw -march x86 bin/x86`, zzuf will
automatically pick up the file opening operating and start fuzzing.

A way to automate this would be using a combination of `--seed=START:STOP`
(seed range, most important part) and `-j` (number of jobs), or perhaps
supplying $RANDOM as a seed number.

Recommended options

| Option | Value |
|---|---|
| `-r` | 0.10 (higher produces irrelevant instructions) |
| `-s` | $RANDOM (be sure to save it) |

## Profile builds (`-b profile`)

Profiling depends on special functions from druntime and D's main function (not
the main function externed as C), therefore making D's embedded profiling
feature unavailable to profile alicedbg internals.

For the time being, you will have to use existing profiling tools (ltrace,
strace, gdb, lldb, etc.). alicedbg's profiling feature (operation mode, not a
build type) is planned.

## Generating headers

Currently, D compilers are not the best suited to generate "headers" (.di,
D Import files), so there are some manual tweaks to do.

1. Generate headers: `dub build -b headers`
2. Navigate to `dinclude`: `cat * > adbg.di` (Windows: `type * > adbg.di`)
3. Match and remove "`module.+\n|//.+\n|.+import adbg.+\n|import adbg.+\n`"

# Homes

- https://git.dd86k.space/dd86k/alicedbg
- https://github.com/dd86k/alicedbg
