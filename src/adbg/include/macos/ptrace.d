/// ptrace(3) bindings for macOS.
///
/// Sources:
/// - https://github.com/apple-oss-distributions/xnu/blob/master/bsd/sys/ptrace.h
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.include.macos.ptrace;

version (OSX):

import core.sys.posix.unistd : pid_t;

alias caddr_t = void*;

extern (C):

enum {
	PT_TRACE_ME	= 0,	/// Child declares it's being traced
	PT_READ_I	= 1,	/// Read word in child's I space
	PT_READ_D	= 2,	/// Read word in child's D space
	PT_READ_U	= 3,	/// Read word in child's user structure
	PT_WRITE_I	= 4,	/// Write word in child's I space
	PT_WRITE_D	= 5,	/// Write word in child's D space
	PT_WRITE_U	= 6,	/// Write word in child's user structure
	PT_CONTINUE	= 7,	/// Continue the child
	PT_KILL		= 8,	/// Kill the child process
	PT_STEP		= 9,	/// Single step the child
	PT_DETACH	= 11,	/// Stop tracing a process
	PT_SIGEXC	= 12,	/// Signals as exceptions for current_proc
	PT_THUPDATE	= 13,	/// Signal for thread#
	PT_ATTACHEXC	= 14,	/// Attach to running process with signal exception

	PT_FORCEQUOTA	= 30,	/// Enforce quota for root
	PT_DENY_ATTACH	= 31,

	PT_FIRSTMACH	= 32,	/// For machine-specific requests
}

deprecated("PT_ATTACH is deprecated. See PT_ATTACHEXC")
enum PT_ATTACH	= 10;	/// Trace some running process

// Linux aliases
alias PT_TRACEME 	= PT_TRACE_ME;
alias PT_CONT 	= PT_CONTINUE;
alias PT_SINGLESTEP 	= PT_STEP;

int ptrace(int _request, pid_t _pid, caddr_t _addr, int _data);