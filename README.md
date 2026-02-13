# alicedbg

Cross-platform debugging and binary inspection framework written in D (BetterC).

## Overview

alicedbg provides process debugging, binary format parsing, and disassembly
under a unified API. It targets Windows, Linux, and FreeBSD on x86, x86-64,
Armv7, and AArch64.

## Features

- **Debugging** -- spawn or attach to processes, set breakpoints, read/write
  memory, inspect threads and stack frames, handle exceptions via callbacks
- **Object inspection** -- parse 13 binary formats: ELF, PE, Mach-O, PDB,
  COFF, MS-COFF, AR, MZ, NE, LX, OMF, Minidump, DMP
- **Disassembly** -- multi-architecture disassembly via Capstone 4.0.2
  (optional runtime dependency)
- **Memory scanning** -- pattern scanning over process memory
- **Two API levels** -- Easy API (high-level, multithreaded) and Multi API
  (direct, granular control)

## CLI Tools

### alicedbg

Interactive debugger with a REPL shell.

```
$ alicedbg ./myapp
Process './easy-target' created
(adbg) go
*	Process 48239 stopped
	Reason  : ACCESS VIOLATION (11)
(adbg) 
```

### alicedump

Binary format dumper. Parses headers, sections, imports, exports, relocations,
and debug info.

```sh
$ ./alicedump --headers /usr/bin/ls
filename                    : /usr/bin/ls
filesize                    : 142312
type                        : Executable and Linkable Format
id                          : elf

# Header
e_ident[0]                  : 0x7f	(\x7f)
e_ident[1]                  : 0x45	(E)
e_ident[2]                  : 0x4c	(L)
e_ident[3]                  : 0x46	(F)
e_ident[EI_CLASS]           : 2	(ELF64)
e_ident[EI_DATA]            : 1	(LSB)
e_ident[EI_VERSION]         : 1
e_ident[EI_OSABI]           : 0	(No ABI)
e_ident[EI_ABIVERSION]      : 0
e_ident[9]                  : 0
e_ident[10]                 : 0
e_ident[11]                 : 0
e_ident[12]                 : 0
e_ident[13]                 : 0
e_ident[14]                 : 0
e_ident[15]                 : 0
e_type                      : 3	(DYN)
e_machine                   : 62	(AMD x86-64)
e_version                   : 1
...
```

## Library Usage

For an example using the Multi API, see `examples/simple.d`.

## Building

Requires [DUB](https://dub.pm/) and a D compiler (DMD, LDC, or GDC).

```sh
dub build            # library
dub build :debugger  # alicedbg CLI
dub build :dumper    # alicedump CLI
dub test             # run tests
```

Build types:

```sh
dub build -b release         # optimized
dub build -b release-static  # statically linked
dub build -b trace           # verbose tracing
```

## Capstone (Optional)

Disassembly requires [Capstone](http://www.capstone-engine.org/) 4.0.2 at
runtime. Without it, all other functionality remains available.

| Platform               | Package            |
|------------------------|--------------------|
| Debian, Ubuntu 22.04+  | `libcapstone4`     |
| RHEL                   | `capstone-devel`   |
| Alpine                 | `capstone-dev`     |
| Windows                | [capstone-4.0.2-win64.zip](https://github.com/capstone-engine/capstone/releases/tag/4.0.2) |

## Status

Pre-1.0. APIs are unstable and change between releases.

Development happens on the `marisa` branch.
The `stable` branch tracks the latest release.

Not currently accepting contributions, but feedback on features and bugs is
welcome.

## License

BSD-3-Clause-Clear
