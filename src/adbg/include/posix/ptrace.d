/// ptrace(3) bindings.
///
/// This module is only available where ptrace is available, and is currently
/// based on Glibc 2.25 and Musl 1.20.
///
/// x32 is not supported.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.include.posix.ptrace;

version (Posix):

version (linux)
	public import adbg.include.linux.ptrace;
else version (OSX)
	public import adbg.include.macos.ptrace;
else version (FreeBSD)
	public import adbg.include.freebsd.ptrace;