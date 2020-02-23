/**
 * ptrace(2) bindings, since the D stdlib lack them. This module is only
 * available on Posix systems where ptrace is available, and is currently
 * based on Glibc 2.25. Support for more runtimes will be implemented
 * here with time.
 */
module debugger.sys.ptrace;

version (Posix):

import core.stdc.config : c_long;

extern (C):

/// siginfo.h
struct siginfo_t {
	/// Signal number.
	int si_signo;
	/// If non-zero, an errno value associated with this signal,
	/// as defined in <errno.h>
	int si_errno;
	/// Signal code.
	int si_code;
	/// Sending process ID.
	int si_pid;
	/// Real user ID of sending process.
	int si_uid;
	/// Address of faulting instruction.
	void *si_addr;
	/// Exit value or signal.
	int si_status;
	/// Band event for SIGPOLL.
	int si_band;
	union {
		int sival_int;	/// Signal value
		void *sival_ptr;	/// Signal address
	}
}

/// Based on Glibc 2.25
version (CRuntime_Glibc) {
	version (linux) {
	enum {	// __ptrace_request
		/** Indicate that the process making this request should be traced.
		All signals received by this process can be intercepted by its
		parent, and its parent can use the other `ptrace' requests.  */
		PTRACE_TRACEME = 0,
		/** Return the word in the process's text space at address ADDR.  */
		PTRACE_PEEKTEXT = 1,
		/** Return the word in the process's data space at address ADDR.  */
		PTRACE_PEEKDATA = 2,
		/** Return the word in the process's user area at offset ADDR.  */
		PTRACE_PEEKUSER = 3,
		/** Write the word DATA into the process's text space at address ADDR.  */
		PTRACE_POKETEXT = 4,
		/** Write the word DATA into the process's data space at address ADDR.  */
		PTRACE_POKEDATA = 5,
		/** Write the word DATA into the process's user area at offset ADDR.  */
		PTRACE_POKEUSER = 6,
		/** Continue the process.  */
		PTRACE_CONT = 7,
		/** Kill the process.  */
		PTRACE_KILL = 8,
		/** Single step the process.
		This is not supported on all machines.  */
		PTRACE_SINGLESTEP = 9,
		/** Get all general purpose registers used by a processes.
		This is not supported on all machines.  */
		PTRACE_GETREGS = 12,
		/** Set all general purpose registers used by a processes.
		This is not supported on all machines.  */
		PTRACE_SETREGS = 13,
		/** Get all floating point registers used by a processes.
		This is not supported on all machines.  */
		PTRACE_GETFPREGS = 14,
		/** Set all floating point registers used by a processes.
		This is not supported on all machines.  */
		PTRACE_SETFPREGS = 15,
		/** Attach to a process that is already running. */
		PTRACE_ATTACH = 16,
		/** Detach from a process attached to with PTRACE_ATTACH.  */
		PTRACE_DETACH = 17,
		/** Get all extended floating point registers used by a processes.
		This is not supported on all machines.  */
		PTRACE_GETFPXREGS = 18,
		/** Set all extended floating point registers used by a processes.
		This is not supported on all machines.  */
		PTRACE_SETFPXREGS = 19,
		/** Continue and stop at the next (return from) syscall.  */
		PTRACE_SYSCALL = 24,
		/** Set ptrace filter options.  */
		PTRACE_SETOPTIONS = 0x4200,
		/** Get last ptrace message.  */
		PTRACE_GETEVENTMSG = 0x4201,
		/** Get siginfo for process.  */
		PTRACE_GETSIGINFO = 0x4202,
		/** Set new siginfo for process.  */
		PTRACE_SETSIGINFO = 0x4203,
		/** Get register content.  */
		PTRACE_GETREGSET = 0x4204,
		/** Set register content.  */
		PTRACE_SETREGSET = 0x4205,
		/** Like PTRACE_ATTACH, but do not force tracee to trap and do not affect
		signal or group stop state.  */
		PTRACE_SEIZE = 0x4206,
		/** Trap seized tracee.  */
		PTRACE_INTERRUPT = 0x4207,
		/** Wait for next group event.  */
		PTRACE_LISTEN = 0x4208,
		/** */
		PTRACE_PEEKSIGINFO = 0x4209,
		/** */
		PTRACE_GETSIGMASK = 0x420a,
		/** */
		PTRACE_SETSIGMASK = 0x420b,
		/** */
		PTRACE_SECCOMP_GET_FILTER = 0x420c
	}
	enum {	// __ptrace_setoptions
		/** */
		PTRACE_O_TRACESYSGOOD	= 0x00000001,
		/** */
		PTRACE_O_TRACEFORK	= 0x00000002,
		/** */
		PTRACE_O_TRACEVFORK	= 0x00000004,
		/** */
		PTRACE_O_TRACECLONE	= 0x00000008,
		/** */
		PTRACE_O_TRACEEXEC	= 0x00000010,
		/** */
		PTRACE_O_TRACEVFORKDONE = 0x00000020,
		/** */
		PTRACE_O_TRACEEXIT	= 0x00000040,
		/** */
		PTRACE_O_TRACESECCOMP	= 0x00000080,
		/** */
		PTRACE_O_EXITKILL	= 0x00100000,
		/** */
		PTRACE_O_SUSPEND_SECCOMP	= 0x00200000,
		/** */
		PTRACE_O_MASK	= 0x003000ff
	}
	enum {	// __ptrace_eventcodes
		/** */
		PTRACE_EVENT_FORK	= 1,
		/** */
		PTRACE_EVENT_VFORK	= 2,
		/** */
		PTRACE_EVENT_CLONE	= 3,
		/** */
		PTRACE_EVENT_EXEC	= 4,
		/** */
		PTRACE_EVENT_VFORK_DONE = 5,
		/** */
		PTRACE_EVENT_EXIT	= 6,
		/** */
		PTRACE_EVENT_SECCOMP  = 7
	}
	struct __ptrace_peeksiginfo_args {
		ulong off;	/// From which siginfo to start.
		uint flags;	/// Flags for peeksiginfo.
		uint nr;	/// How many siginfos to take.
	}
	enum {	// __ptrace_peeksiginfo_flags
		/// Read signals from a shared (process wide) queue.
		PTRACE_PEEKSIGINFO_SHARED = 1
	}
	} else
	version (AArch64) {
	enum {
		PT_TRACE_ME,	/// The only request of which a tracee can make
	}
	} else { // Generic
	enum {
		/** The only request of which a tracee can make */
		PT_TRACE_ME,
		/** */
		PTRACE_PEEKTEXT,
		/** */
		PTRACE_PEEKDATA,
		/** */
		PTRACE_PEEKUSER,
		/** */
		PTRACE_POKETEXT,
		/** */
		PTRACE_POKEDATA,
		/** */
		PTRACE_POKEUSER,
		/** */
		PTRACE_CONT,
		/** */
		PTRACE_KILL,
		/** */
		PTRACE_SINGLESTEP,
		/** */
		PTRACE_ATTACH,
		/** */
		PTRACE_DETACH,
		/** */
		PTRACE_GETREGS,
		/** */
		PTRACE_SETREGS,
		/** */
		PTRACE_GETFPREGS,
		/** */
		PTRACE_SETFPREGS,
		/** */
		PTRACE_READDATA,
		/** */
		PTRACE_WRITEDATA,
		/** */
		PTRACE_READTEXT,
		/** */
		PTRACE_WRITETEXT,
		/** */
		PTRACE_GETFPAREGS,
		/** */
		PTRACE_SETFPAREGS	
	}
	}
}

alias int pid_t;

/**
 * The ptrace() system call provides a means by which one process (the
 * "tracer") may observe and control the execution of another process
 * (the "tracee"), and examine and change the tracee's memory and
 * registers.  It is primarily used to implement breakpoint debugging
 * and system call tracing.
 * 
 * Params:
 * 	request = See __ptrace_request enumeration (PT_*)
 * 	pid = Process ID number
 * 	addr = Memory pointer
 * 	data = Data pointer
 * 
 * Returns: 0 on success; -1 on error. For PTRACE_PEEK requests, check errno
 * first
 */
c_long ptrace(int request, pid_t pid, void *addr, void *data);