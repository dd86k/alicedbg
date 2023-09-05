/// ptrace(3) bindings for Linux.
///
/// This module is only available where ptrace is available, and is currently
/// based on Glibc 2.25 and Musl 1.20.
///
/// x32 is not supported.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.include.linux.ptrace;

version (linux):

import adbg.include.c.config;

extern (C):

enum {	// __ptrace_request
	/// Indicate that the process making this request should be traced.
	/// All signals received by this process can be intercepted by its
	/// parent, and its parent can use the other `ptrace' requests.
	PT_TRACEME = 0,
	/// Return the word in the process's text space at address ADDR.
	PT_PEEKTEXT = 1,
	/// Return the word in the process's data space at address ADDR.
	PT_PEEKDATA = 2,
	/// Return the word in the process's user area at offset ADDR.
	PT_PEEKUSER = 3,
	/// Write the word DATA into the process's text space at address ADDR.
	PT_POKETEXT = 4,
	/// Write the word DATA into the process's data space at address ADDR.
	PT_POKEDATA = 5,
	/// Write the word DATA into the process's user area at offset ADDR.
	PT_POKEUSER = 6,
	/// Continue the process.
	PT_CONT = 7,
	/// Kill the process. (deprecated)
	PT_KILL = 8,
	/// Single step the process.
	/// This is not supported on all machines.
	PT_SINGLESTEP = 9,
	/// Get all general purpose registers used by a processes.
	/// This is not supported on all machines.
	PT_GETREGS = 12,
	/// Set all general purpose registers used by a processes.
	/// This is not supported on all machines.
	PT_SETREGS = 13,
	/// Get all floating point registers used by a processes.
	/// This is not supported on all machines.
	PT_GETFPREGS = 14,
	/// Set all floating point registers used by a processes.
	/// This is not supported on all machines.
	PT_SETFPREGS = 15,
	/// Attach to a process that is already running.
	PT_ATTACH = 16,
	/// Detach from a process attached to with PT_ATTACH.
	PT_DETACH = 17,
	/// Get all extended floating point registers used by a processes.
	/// This is not supported on all machines.
	PT_GETFPXREGS = 18,
	/// Set all extended floating point registers used by a processes.
	/// This is not supported on all machines.
	PT_SETFPXREGS = 19,
	/// Continue and stop at the next (return from) syscall.
	PT_SYSCALL = 24,
	/// Set ptrace filter options.
	PT_SETOPTIONS = 0x4200,
	/// Get last ptrace message.
	PT_GETEVENTMSG = 0x4201,
	/// Get siginfo for process.
	PT_GETSIGINFO = 0x4202,
	/// Set new siginfo for process.
	PT_SETSIGINFO = 0x4203,
	/// Get register content.
	PT_GETREGSET = 0x4204,
	/// Set register content.
	PT_SETREGSET = 0x4205,
	/// Like PT_ATTACH, but do not force tracee to trap and do
	/// not affect signal or group stop state.
	PT_SEIZE = 0x4206,
	/// Trap seized tracee.
	PT_INTERRUPT = 0x4207,
	/// Wait for next group event.
	PT_LISTEN = 0x4208,
	/// 
	PT_PEEKSIGINFO = 0x4209,
	/// 
	PT_GETSIGMASK = 0x420a,
	/// 
	PT_SETSIGMASK = 0x420b,
	///
	PT_SECCOMP_GET_FILTER = 0x420c
}
enum {	// __ptrace_setoptions
	PT_O_TRACESYSGOOD	= 0x00000001,	/// mark upper bit when system call traps
	PT_O_TRACEFORK	= 0x00000002,	/// trace fork calls
	PT_O_TRACEVFORK	= 0x00000004,	/// trace vfork calls
	PT_O_TRACECLONE	= 0x00000008,	/// trace clone calls
	PT_O_TRACEEXEC	= 0x00000010,	/// trace exec calls
	PT_O_TRACEVFORKDONE = 0x00000020,	/// trace vfork_done events
	PT_O_TRACEEXIT	= 0x00000040,	/// trace exit calls
	PT_O_TRACESECCOMP	= 0x00000080,	/// trace seccomp calls
	PT_O_EXITKILL	= 0x00100000,	/// trace exit+kill calls
	PT_O_SUSPEND_SECCOMP	= 0x00200000,	/// syspend on seccomp
	PT_O_MASK	= 0x003000ff	/// mask
}
enum {	// __ptrace_eventcodes
	PT_EVENT_FORK	= 1,	/// fork event
	PT_EVENT_VFORK	= 2,	/// vfork event
	PT_EVENT_CLONE	= 3,	/// clone event
	PT_EVENT_EXEC	= 4,	/// exec event
	PT_EVENT_VFORK_DONE = 5,	/// vfork done event
	PT_EVENT_EXIT	= 6,	/// exit event
	PT_EVENT_SECCOMP  = 7	/// seccomp event
}

/// The ptrace() system call provides a means by which one process (the
/// "tracer") may observe and control the execution of another process
/// (the "tracee"), and examine and change the tracee's memory and
/// registers.  It is primarily used to implement breakpoint debugging
/// and system call tracing.
///
/// Although arguments to ptrace() are interpreted according to the
/// prototype given, glibc currently declares ptrace() as a variadic
/// function with only the request argument fixed.  It is recommended
/// to always supply four arguments, even if the requested operation
/// does not use them, setting unused/ignored arguments to 0L or
/// (void *) 0.
/// 
/// Params:
/// 	req = PTRACE request
/// 	pid = Process ID number
/// 	addr = Memory pointer
/// 	data = Data pointer
/// 
/// Returns: 0 on success; -1 on error. For PT_PEEK requests, check errno
/// first
c_long ptrace(int req, ...);