/// Fixing improper sys/wait.h definitions.
///
/// This is due to extern (D) tricking the compiler the function that is
/// external dispite the defined body.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.include.posix.sys.wait;

version (Posix):

public import core.sys.posix.sys.wait;

pragma(inline, true):

// Source:
// gdb/gdbsupport/gdb_wait.h

bool WIFEXITED(int status) {
	version (MinGW)	// (((w) & 0xC0000000) == 0)
		return (status & 0xC0000000) == 0;
	else	// (((w)&0377) == 0)
		return cast(ubyte)status == 0;
}

bool WIFSIGNALED(int status) {
	version (MinGW)	// (((w) & 0xC0000000) == 0xC0000000)
		return ((status) & 0xC0000000) == 0xC0000000;
	else	// (((w)&0377) != 0177 && ((w)&~0377) == 0)
		return cast(ubyte)status != 0x7f && cast(ubyte)(status >> 8) == 0;
}

bool WIFSTOPPED(int status) {
	version (RS6000)	// ((w)&0x40)
		return (status & 0x40) != 0;
	else	// (((w)&0377) == 0177)
		return cast(ubyte)status == 0x7f;
}

version (CRuntime_Glibc)
bool WIFCONTINUED(int status) {
	// ((s) == 0xffff)
	return cast(short)status == 0xffff;
}

int WEXITSTATUS(int status) {
	version (MinGW)	// ((w) & ~0xC0000000)
		return status & ~0xC0000000;
	else	// (((w) >> 8) & 0377) /* same as WRETCODE */
		return cast(ubyte)(status >> 8);
}

int WTERMSIG(int status) {
	// MinGW: extern int windows_status_to_termsig (unsigned long);
	return status & 0x7f;
}

// #define WSTOPSIG	WEXITSTATUS
alias WSTOPSIG = WEXITSTATUS;
