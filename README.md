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
  - Platforms: x86-16, x86-32, and x86-64.
  - Syntaxes: Intel, Nasm, and AT&T, HLA, and TASM.
- Compiles under DMD, GDC, and LDC.

The application supports:
- Debugging (default)
  - UIs: Loop and command-line
- Dumping (`-D|--dump`)
  - ELF and PE32 images.
- Instruction analysis (`-A|--analyze`)
  - Base16 input.

Written from scratch for education purposes.

# Documentation

The wiki contains user manuals and development notes.

| Home | Wiki |
|---|---|
| [Gitbucket](https://git.dd86k.space/dd86k/alicedbg) | [URL](https://git.dd86k.space/dd86k/alicedbg/wiki)
| [Github](https://github.com/dd86k/alicedbg) | [URL](https://github.com/dd86k/alicedbg/wiki)
| [Gitlab](https://gitlab.com/dd86k/alicedbg) | [URL](https://gitlab.com/dd86k/alicedbg/-/wikis/home)

Technical manual: TBA
