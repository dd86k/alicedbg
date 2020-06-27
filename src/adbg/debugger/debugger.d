/**
 * Debugger core
 *
 * This is the core of the debugger API. It provides APIs to start a new
 * process, attach itself onto a process, manage breakpoints, etc.
 *
 * This is the only module that contains function names without its module
 * name.
 *
 * License: BSD 3-Clause
 */
module adbg.debugger.debugger;

import core.stdc.string : memset;
import core.stdc.errno : errno;
import adbg.debugger.exception;
import adbg.consts;

version (Windows) {
	import core.sys.windows.windows;
	import adbg.debugger.sys.wow64;
	//SymInitialize, GetFileNameFromHandle, SymGetModuleInfo64,
	//StackWalk64, SymGetSymFromAddr64, SymFromName
	private __gshared HANDLE g_tid;	/// Saved thread handle, DEBUG_INFO doesn't contain one
	private __gshared HANDLE g_pid;	/// Saved process handle
	version (Win64)
		private __gshared int processWOW64;
} else
version (Posix) {
	import core.sys.posix.sys.stat;
	import core.sys.posix.sys.wait : waitpid, SIGCONT, WUNTRACED;
	import core.sys.posix.signal : kill, SIGKILL, siginfo_t, raise;
	import core.sys.posix.sys.uio;
	import core.sys.linux.fcntl : open;
	import core.stdc.stdlib : exit, malloc, free;
	import core.stdc.stdio : snprintf;
	import adbg.debugger.sys.ptrace;
	import adbg.debugger.sys.user;
	private enum __WALL = 0x40000000;
	private __gshared pid_t g_pid;	/// Saved process ID
	private __gshared int g_mhandle;	/// Saved memory file handle
	version (CRuntime_Musl) {
		import core.sys.posix.unistd : fork, execve, pipe;
		extern (C) ssize_t pread(int, void *, size_t, off_t);
		extern (C) ssize_t pwrite(int, const void *, size_t, off_t);
	} else {
		import core.sys.posix.unistd : fork, execve, pread, pwrite, pipe;
	}
}

extern (C):

version (X86)
	private enum BREAKPOINT = 0xCC; // INT3
else version (X86_64)
	private enum BREAKPOINT = 0xCC; // INT3
else version (ARM_Thumb)
	version (BigEndian)
		private enum BREAKPOINT = 0xBEDD; // BKPT #221 (0xdd)
	else
		private enum BREAKPOINT = 0xDDBE; // BKPT #221 (0xdd)
else version (ARM) {
	version (BigEndian)
		private enum BREAKPOINT = 0xE1200D7D; // BKPT #221 (0xdd)
	else
		private enum BREAKPOINT = 0x7D0D20E1; // BKPT #221 (0xdd)
} else version (AArch64) {
	//NOTE: Checked under ODA, endianness seems to be moot
	version (BigEndian)
		private enum BREAKPOINT = 0xA01B20D4; // BKPT #221 (0xdd)
	else
		private enum BREAKPOINT = 0xA01B20D4; // BKPT #221 (0xdd)
} else
	static assert(0, "Missing BREAKPOINT value for target platform");

/// Actions that a user function handler may return
public
enum DebuggerAction {
	exit,	/// Cause the debugger to close the process and stop debugging
	proceed,	/// Continue debugging
	step,	/// Proceed with a single step
}

private
struct breakpoint_t {
	size_t address;
	union {
		ubyte  ou8;	/// Original instruction
		ushort ou16;	/// Original instruction
		int    ou32;	/// Original instruction
	}
}

private __gshared breakpoint_t [DEBUGGER_MAX_BREAKPOINTS]breakpoints;
private __gshared size_t breakpointindex;
private __gshared int function(exception_t*) user_function;

/**
 * Load executable image into the debugger.
 *
 * Loads an executable into the debugger, with optional null-terminated
 * argument list and null-terminated environment.
 * This does not start the process, nor the debugger.
 * On Posix systems, stat(2) is used to check if the file exists.
 * (Windows) Uses CreateProcessA (DEBUG_PROCESS).
 * (Posix) Uses stat(2), fork(2), ptrace(2) (PTRACE_TRACEME), and execve(2).
 * Params:
 * 	path = Command, path to executable
 * 	dir = New directory for the debuggee, null for current directory
 * 	argv = Argument vector, null-terminated, can be null
 * 	envp = Environment vector, null-terminated, can be null
 * 	flags = Reserved
 * Returns: Zero on success; Otherwise os error code is returned
 */
int adbg_load(const(char) *path, const(char) *dir, const(char) **argv, const(char) **envp, int flags) {
	if (path == null) return 1;

	version (Windows) {
		import core.stdc.stdlib : malloc, free;
		import core.stdc.stdio : snprintf;
		import adbg.utils.str : adbg_util_argv_flatten;
		int bs = 0x8000; // buffer size, 32,768 bytes
		ptrdiff_t bi;
		char *b = cast(char*)malloc(bs);
		//
		// Copy path into buffer
		//
		bi = snprintf(b, bs, "%s ", path);
		if (bi < 0) return 1;
		//
		// Flatten argv
		//
		if (argv)
			bi += adbg_util_argv_flatten(b + bi, bs, argv);
		//
		//TODO: Parse envp
		//
		
		//
		// Create process
		//
		STARTUPINFOA si = void;
		PROCESS_INFORMATION pi = void;
		memset(&si, 0, si.sizeof + pi.sizeof); // memset faster than _init functions
		si.cb = STARTUPINFOA.sizeof;
		// Not using DEBUG_ONLY_THIS_PROCESS because our posix
		// counterpart is using -1 (all children) for waitpid.
		if (CreateProcessA(null, b,
			null, null,
			FALSE, DEBUG_PROCESS,
			envp, null,
			&si, &pi) == 0)
			return GetLastError();
		g_tid = pi.hThread;
		g_pid = pi.hProcess;
		// Microsoft recommends getting function pointer with
		// GetProcAddress("kernel32", "IsWow64Process"), but so far
		// only 64-bit versions of Windows really have WOW64.
		// Nevertheless, required to support 32-bit processes under
		// 64-bit builds.
		version (Win64) {
			if (IsWow64Process(g_pid, &processWOW64))
				return GetLastError();
		}
		free(b);
	} else
	version (Posix) {
		// Verify if file exists and we has access to it
		stat_t st = void;
		if (stat(path, &st) == -1)
			return errno;
		// Proceed normally, execve performs executable checks
		g_pid = fork();
		if (g_pid < 0)
			return errno;
		if (g_pid == 0) {
			if (ptrace(PTRACE_TRACEME, 0, 0, 0))
				return errno;
			const(char)*[16] __argv = void;
			const(char)*[1]  __envp = void;
			//
			// Adjust argv
			//
			if (argv) {
				size_t i, __i = 1;
				while (argv[i] && __i < 15)
					__argv[__i++] = argv[i++];
				__argv[__i] = null;
			} else {
				__argv[1] = null;
			}
			__argv[0] = path;
			//
			// Adjust envp
			//
			if (envp == null) {
				envp = cast(const(char)**)&__envp;
				envp[0] = null;
			}
			version (CRuntime_Musl) {
				//TODO: Setup pipes
				//      musl doesn't seem to give the child
				//      the parents's stdin/stdout pipe, leading
				//      to a SIGPIPE (13)
				/*int[2] p = void;
				if (pipe(p) == -1)
					return errno;*/
				if (raise(SIGTRAP))
					return errno;
			}
			if (execve(path,
				cast(const(char)**)__argv,
				cast(const(char)**)__envp) == -1)
				return errno;
		}
	}
	return 0;
}

/**
 * Attach the debugger to a process ID.
 * (Windows) Uses DebugActiveProcess
 * (Posix) Uses ptrace(PTRACE_SEIZE)
 * Params:
 * 	pid = Process ID
 * 	flags = Reserved
 * Returns: Non-zero on error: (Posix) errno or (Windows) GetLastError
 */
int adbg_attach(int pid, int flags) {
	version (Windows) {
		if (DebugActiveProcess(pid) == FALSE)
			return GetLastError();
	} else
	version (Posix) {
		if (ptrace(PTRACE_SEIZE, pid, null, null) == -1)
			return errno;
	}
	return 0;
}

//TODO: adbg_debug_self()
//      Either a template (preferred) or a function that allows debugging D user code

/**
 * Set the user event handle for handling exceptions.
 * Params: f = Function pointer
 * Returns: Zero on success; Otherwise an error occured
 */
void adbg_userfunc(int function(exception_t*) f) {
	user_function = f;
}

/**
 * Enter the debugging loop. Continues execution of the process until a new
 * debug event occurs. When an exception occurs, the exception_t structure is
 * populated with debugging information.
 * (Windows) Uses WaitForDebugEvent, filters any but EXCEPTION_DEBUG_EVENT
 * (Posix) Uses ptrace(2) and waitpid(2), filters SIGCONT out
 * Returns: Zero on success; Otherwise an error occured
 */
int adbg_run() {
	if (user_function == null)
		return 4;

	exception_t e = void;

	version (Win64)
		adbg_ex_ctx_init(&e, processWOW64 ? InitPlatform.x86 : InitPlatform.Native);
	else
		adbg_ex_ctx_init(&e, InitPlatform.Native);

	version (Windows) {
		DEBUG_EVENT de = void;
L_DEBUG_LOOP:
		if (WaitForDebugEvent(&de, INFINITE) == FALSE)
			return 3;

		// Filter events
		switch (de.dwDebugEventCode) {
		case EXCEPTION_DEBUG_EVENT: break;
		case EXIT_PROCESS_DEBUG_EVENT: return 0;
		default:
			ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
			goto L_DEBUG_LOOP;
		}

		adbg_ex_dbg(&e, &de);

		CONTEXT ctx = void;
		version (Win64) {
			WOW64_CONTEXT ctxwow64 = void;
			if (processWOW64) {
				ctxwow64.ContextFlags = CONTEXT_ALL;
				Wow64GetThreadContext(g_tid, &ctxwow64);
				adbg_ex_ctx_win_wow64(&e, &ctxwow64);
			} else {
				ctx.ContextFlags = CONTEXT_ALL;
				GetThreadContext(g_tid, &ctx);
				adbg_ex_ctx(&e, &ctx);
			}
		} else {
			ctx.ContextFlags = CONTEXT_ALL;
			GetThreadContext(g_tid, &ctx);
			adbg_ex_ctx(&e, &ctx);
		}

		with (DebuggerAction)
		final switch (user_function(&e)) {
		case exit:
			//TODO: DebugActiveProcessStop if -pid was used
			ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_TERMINATE_PROCESS);
			return 0;
		case step:
			FlushInstructionCache(g_pid, null, 0);
			// Enable single-stepping via Trap flag
			version (Win64) {
				if (processWOW64) {
					ctxwow64.EFlags |= 0x100;
					Wow64SetThreadContext(g_tid, &ctxwow64);
				} else {
					ctx.EFlags |= 0x100;
					SetThreadContext(g_tid, &ctx);
				}
			} else {
				ctx.EFlags |= 0x100;
				SetThreadContext(g_tid, &ctx);
			}
			goto case;
		case proceed:
			if (ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE))
				goto L_DEBUG_LOOP;
			return GetLastError();
		}
	} else
	version (Posix) {
		int wstatus = void;
L_DEBUG_LOOP:
		g_pid = waitpid(-1, &wstatus, 0);

		if (g_pid == -1)
			return errno;

		// Bits  Description (Linux)
		// 6:0   Signo that caused child to exit
		//       0x7f if child stopped/continued
		//       or zero if child exited without signal
		//  7    Core dumped
		// 15:8  exit value (or returned main value)
		//       or signal that cause child to stop/continue
		int chld_signo = wstatus >> 8;

		// Only interested if child is continuing or stopped; Otherwise
		// it exited and there's nothing more we can do about it.
		// So return its status code
		if ((wstatus & 0x7F) != 0x7F)
			return chld_signo;

		// Signal filtering
		switch (chld_signo) {
		case SIGCONT: goto L_DEBUG_LOOP;
		// NOTE: si_addr is NOT populated under ptrace for SIGTRAP
		// 
		// - linux does not fill si_addr on a SIGTRAP from a ptrace event
		//   - see sigaction(2)
		// - linux *only* fills user_regs_struct for "user area"
		//   - see arch/x86/include/asm/user_64.h
		//   - "ptrace does not yet supply these.  Someday...."
		//   - So yeah, debug registers and "fault_address" not filled
		//     - No access to ucontext_t from ptrace either
		// - using EIP/RIP is NOT a good idea
		//   - IP ALWAYS point to NEXT instruction
		//   - First SIGTRAP does NOT contain int3
		//     - Windows does, though, and points to it
		// - gdbserver and lldb never attempt to do such thing anyway
		case SIGILL, SIGSEGV, SIGFPE, SIGBUS:
			siginfo_t sig = void;
			if (ptrace(PTRACE_GETSIGINFO, g_pid, null, &sig) < 0) {
				e.addr = null;
			} else {
				version (CRuntime_Glibc)
					e.addr = sig._sifields._sigfault.si_addr;
				else version (CRuntime_Musl)
					e.addr = sig.__si_fields.__sigfault.si_addr;
				else static assert(0, "hack me");
			}
			break;
//		case SIGINT, SIGTERM, SIGABRT: //TODO: Kill?
		default:
			e.addr = null;
		}

		adbg_ex_dbg(&e, g_pid, chld_signo);

		user_regs_struct u = void;
		if (ptrace(PTRACE_GETREGS, g_pid, null, &u) < 0)
			e.regcount = 0;
		else
			adbg_ex_ctx(&e, &u);

//		iovec v = void;
//		if (ptrace(PTRACE_GETREGSET, g_pid, NT_PRSTATUS, &v))
//			return errno;

		with (DebuggerAction)
		final switch (user_function(&e)) {
		case exit:
			kill(g_pid, SIGKILL); // PTRACE_KILL is deprecated
			return 0;
		case step:
			ptrace(PTRACE_SINGLESTEP, g_pid, null, null);
			goto L_DEBUG_LOOP;
		case proceed:
			ptrace(PTRACE_CONT, g_pid, null, null);
			goto L_DEBUG_LOOP;
		}
	}
}

//
// Breakpoint handling
//

int adbg_bp_add(size_t addr) {
	assert(0, "adbg_bp_add not implemented");
}
breakpoint_t* adbg_bp(int index) {
	assert(0, "adbg_bp not implemented");
}
breakpoint_t* adbg_bp_addr(size_t addr) {
	assert(0, "adbg_bp_addr not implemented");
}
uint adbg_bp_opcode(breakpoint_t* bp) {
	assert(0, "adbg_bp_opcode not implemented");
}
int adbg_bp_rm_addr(size_t addr) {
	assert(0, "adbg_bp_rm_addr not implemented");
}
int adbg_bp_rm_index(int index) {
	assert(0, "adbg_bp_rm_index not implemented");
}

//
// Memory
//

enum {	// adbg_mm flags
	// Flags
	MM_READ	= 0,	/// Read from memory to data pointer
	MM_WRITE	= 0x8000,	/// Write to memory from data pointer
}

/**
 * Read or write to a memory region from or to the opened debugee process.
 * This does not include subchildren processes.
 * Params:
 * 	addr = Memory address location
 * 	flags = See MM_ enumerations
 * 	data = Data pointer
 * Returns: Zero on success, oscode on error
 */
int adbg_mm(int op, size_t addr, void *data, uint size) {
	version (Windows) {
		if (op >= MM_WRITE) {
			if (WriteProcessMemory(g_pid, cast(void*)addr, data, size, null) == 0)
				return GetLastError();
		} else {
			if (ReadProcessMemory(g_pid, cast(void*)addr, data, size, null) == 0)
				return GetLastError();
		}
	} else
	version (linux) {
		//TODO: adbg_mm (linux)
		//      use open(2) and pread64/pwrite64(2)
		if (g_mhandle <= 0) {
			char* cb = cast(char*)malloc(4096);
			if (cb == null)
				return errno;
			int n = snprintf(cb, 4096, "/proc/%d/mem", g_pid);
			if (n < 0)
				return errno;
			open(cb, 0);
			free(cb);
		}
		// Let's not use process_vm_readv, okay?
		if (op >= MM_WRITE) {
			
		} else {
		}
	}

	return 0;
}