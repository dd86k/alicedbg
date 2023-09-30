# Alice Debugger Project

Aiming to be a simple cross-platform debugger, binary dumper, and memory
scanner.

Fully written in D's BetterC mode, and available as a DUB package.

Library features:
- Debugger
- Disassembler (using Capstone)
- Object server

Written from scratch for educational purposes.

## Warnings

**This is still lacking most features any debuggers should have.**

Long-term wishlist:
- Source debugging
- Windows kernel debugging
- Linux kernel debugging
- Support embedded platforms
- Just-In-Time debugging

Under consideration:
- TUI option
- Addon system (either Lua, Squirrel, DMDScript, or AngelScript)

There are currently no stable APIs. Every releases to the 0.x series can change
the API at any given time.

None of the functions are thread-safe.

## Application Usage

The application is split across a few modes.

### Debugger

The debugger is the default operating mode.

In this mode, the default option is to spawn a process with a file path.

To attach to a live process, use the `--pid PID` option, where PID is a
Process ID.

Examples:
- Spawn process
  - Windows: `alicedbg test.exe`
  - Posix: `alicedbg ./test`
- Attach to process: `alicedbg --pid 3428`

### Dumper

To invoke the object dumper, use `--dump PATH`, where PATH is a file path to a
binary image.

Examples:
- Dump headers: `alicedbg --dump alicedbg.exe`

## Documentation

For information about compilation, internal structures, support,
see the repository's Wiki for further information.

## License

This project is licensed under the BSD 3-Clause license.