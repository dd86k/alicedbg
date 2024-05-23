# Alice Debugger Project

Aiming to be a simple cross-platform debugger, binary dumper, and memory
scanner.

Fully written in D's BetterC mode, and available as a DUB package.

Features:
- Debugger
- Disassembler (using Capstone)
- Object server

Written from scratch for self-taught educational purposes.

## Warnings

⚠️ This is a toy debugger with barely any features ⚠️

There are currently no stable APIs. Every releases pre-1.0 will see frequent
changes to the API.

None of the functions are currently thread-safe.

# Usage

Usage for `alicedbg` (Debugger) and `alicedump` (Dumper) can be looked in the repo Wiki.

The disassembly feature is provided by Capstone 4.0.2.

For Windows, the dynamic library can be [downloaded here](https://github.com/capstone-engine/capstone/releases/tag/4.0.2).

For other platforms, package names are typically:
- Debian, Ubuntu 22.04, SUSE: `libcapstone4`
- Ubuntu 20.04: `libcapstone3` (4.0.1)
- RHEL: `capstone-devel`
- Alpine: `capstone-dev`

Capstone is licensed under the 3-clause BSD license.

# Documentation

For information about compilation, internal structures, support,
see the repository's Wiki for information.

# Contributing

Currently not looking for contributors, sorry. Feel free to provide suggestions
regarding contributor management.

# License

This project is licensed under the BSD 3-Clause Clear license.