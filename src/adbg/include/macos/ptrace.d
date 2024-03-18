/// ptrace(3) bindings for macOS.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.include.macos.ptrace;

version (OSX):

extern (C):

enum PT_TRACE_ME	= 0;	/// Child declares it's being traced
enum PT_READ_I	= 1;	/// Read word in child's I space
enum PT_READ_D	= 2;	/// Read word in child's D space
enum PT_READ_U	= 3;	/// Read word in child's user structure
enum PT_WRITE_I	= 4;	/// Write word in child's I space
enum PT_WRITE_D	= 5;	/// Write word in child's D space
enum PT_WRITE_U	= 6;	/// Write word in child's user structure
enum PT_CONTINUE	= 7;	/// Continue the child
enum PT_KILL		= 8;	/// Kill the child process
enum PT_STEP		= 9;	/// Single step the child
deprecated("PT_ATTACH is deprecated. See PT_ATTACHEXC")
enum PT_ATTACH	= 10;	/// Trace some running process
enum PT_DETACH	= 11;	/// Stop tracing a process
enum PT_SIGEXC	= 12;	/// Signals as exceptions for current_proc
enum PT_THUPDATE	= 13;	/// Signal for thread#
enum PT_ATTACHEXC	= 14;	/// Attach to running process with signal exception

enum PT_FORCEQUOTA	= 30;	/// Enforce quota for root
enum PT_DENY_ATTACH	= 31;

enum PT_FIRSTMACH	= 32;	/// For machine-specific requests

int ptrace(int _request, pid_t _pid, caddr_t _addr, int _data);