# Alice Debugger Project

Aiming to be a simple cross-platform framework for debugging and object inspection.

Fully written in D's [BetterC mode](https://dlang.org/spec/betterc.html),
and available as a DUB package.

It is currently available for Windows, Linux, and FreeBSD, under x86, x86-64, Armv7, and AArch64.

Written from scratch for educational purposes.

## Warnings

⚠️ This is a toy project with barely any features! ⚠️

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
- `marisa`: Main development branch. Very unstable.
- `stable`: Last released branch.

This project primarily uses [DUB](https://dub.pm/cli-reference/dub/)
for compilation and unittesting.

Wiki contains more information on structure, features, and compilation
instructions.

## Nix

this project's flake exposes the following:

(note that all instances of `.#` can be replaced with `github:dd86k/alicedbg#` to do so without needing to have a local copy of the repository)

### DevShell

a devshell providing locked versions of `dub`, `gdc`, `ldc` and `dmd`, along with a nix lsp and formatter can be accessed with:

```
nix develop .
```

and will automatically be entered if you have `direnv` configured.

### Packages

packages built with locked versions of dependencies and toolchains are exposed and can be built using a common identifier:

given any combination of:

buildType:
- debug
- debugv
- release
- release-nobounds
- docs

config:
- debugger
- dumper
- simple
- library
- shared

compiler:
- ldc
- dmd
- gdc

then the appropriate output can be built with:

`nix build .#alicedbg-<buildType>-<config>-<compiler>`

with the results appearing in the `./result`

the default output is `alicedbg-release-debugger-ldc`

### Tests

running `nix flake check` will compile all combinations above with unittests turned on.

`nix flake check .#alicedbg-<buildType>-<config>-<compiler>` will do so for a single output

### Overlay

a nixos overlay is exposed as `.#overlays.default`, which can be used to build all outputs using your own toolchain and versions instead of the ones locked here, all packages are avaliable under `pkgs.alicedbg` with the above names.

### Updating

to update the dependencies nix uses, we must do the following:

```
dub upgrade --annotate  # generates dub.selections.json
dub-to-nix > dub-lock.json  # updates lockfile nix uses
```

also remember to update the `version` attribute on line 19 of `flake.nix` (within the `buildDubPackage` invocation)

the rest of the non-D dependencies can be updated with `nix flake update` which will update the checkout of nixpkgs used by the flake.

# Contributing

Because I'm not very good at managing people and I tend to be a little too
pedantic, I am currently not looking for contributors, sorry.

However, feel free to provide feedback regarding contributor management,
features, enhancements, and fixes. It's appreciated.

# License

This project is licensed under the BSD 3-Clause Clear license.
