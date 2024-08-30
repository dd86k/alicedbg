# Alice Debugger Project

Aiming to be a simple cross-platform framework for debugging and object inspection.

Fully written in D's [BetterC mode](https://dlang.org/spec/betterc.html),
and available as a DUB package.

Applications:
- alicedbg: Debugger
- alicedump: Object dumper

Facilities:
- Debugger: Exception handling
- Disassembler: Capstone back-end
- Object server: Right now, not so much

Written from scratch for educational purposes.

## Warnings

⚠️ This is a toy project with barely any features ⚠️

There are currently no stable APIs. Every releases pre-1.0 will see frequent
changes to the API.

None of the functions are currently thread-safe.

Compiling a static binary on one C runtime may not work on another due to
specific behaviors when using ptrace(2).

# Usage

Usage for `alicedbg` (debugger) and `alicedump` (dumper) can be looked in the
repository Wiki, or invoking the `--help` argument.

The disassembly feature is provided by Capstone 4.0.2 when it is available on
the system. For Windows, the dynamic library can be
[downloaded on GitHub](https://github.com/capstone-engine/capstone/releases/tag/4.0.2).

For other platforms, package names are typically:
- Debian, Ubuntu 22.04 and later, SUSE: `libcapstone4`
- Ubuntu 20.04: `libcapstone3` (4.0.1)
- RHEL: `capstone-devel`
- Alpine: `capstone-dev`

Capstone is licensed under the BSD 3-Clause license.

# Hacking

There are two main branches:
- `master`: Main development branch. Very unstable.
- `stable`: Last released branch.

This project primarily uses [DUB](https://dub.pm/cli-reference/dub/)
for compilation and unittesting.

Wiki contains more information on structure, features, and compilation
instructions.

# Contributing

Because I'm not very good at managing people and I tend to be a little too
pedantic, I am currently not looking for contributors, sorry.

However, feel free to provide feedback regarding contributor management,
features, enhancements, and fixes. It's appreciated.

# License

This project is licensed under the BSD 3-Clause Clear license.