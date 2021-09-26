# Alice Debugger Project

⚠️ **Early development!** ⚠️

⚠️ Currently not accepting Pull Requests ⚠️

The alicedbg project aims to be a simple debugger, object dumper, and system
tracer fully compatible with -betterC/-fno-druntime.

It is available as an application and as a DUB library.

The library supports:
- Debugging
  - Windows (msvcrt) and Linux (Glibc and Musl).
- Disassembly
  - Platforms: x86.
  - Syntaxes: Intel, NASM, and AT&T, Hyde Randall High Level Assembly, and Borland Turbo Assembler (enhanced mode).
- Supports the DMD, GDC, and LDC compilers.

The application supports:
- Debugging (default mode)
  - Interfaces: Loop and command-line (default)
- Dumping (`-D|--dump`)
  - PE32 and ELF images.
- Instruction analysis (`-A|--analyze`)
  - Base16 input.

Written from scratch for educational purposes.

# Documentation

The wiki contains user manuals and development notes.

| Home | Wiki |
|---|---|
| [Gitbucket](https://git.dd86k.space/dd86k/alicedbg) | [URL](https://git.dd86k.space/dd86k/alicedbg/wiki)
| [Github](https://github.com/dd86k/alicedbg) | [URL](https://github.com/dd86k/alicedbg/wiki)
| [Gitlab](https://gitlab.com/dd86k/alicedbg) | [URL](https://gitlab.com/dd86k/alicedbg/-/wikis/home)

Technical manual: TBA
