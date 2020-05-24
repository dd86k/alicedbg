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

extern (C):
__gshared:

version (Windows) {
	import core.sys.windows.windows;
	import adbg.debugger.sys.wow64;
	//SymInitialize, GetFileNameFromHandle, SymGetModuleInfo64,
	//StackWalk64, SymGetSymFromAddr64, SymFromName
	private HANDLE hthread; /// Saved thread handle, DEBUG_INFO doesn't contain one
	private HANDLE hprocess; /// Saved process handle
	version (Win64)
		private int processWOW64;
} else
version (Posix) {
	import core.sys.posix.sys.stat;
	import core.sys.posix.sys.wait :
		waitpid, SIGCONT, WUNTRACED;
	import core.sys.posix.unistd : fork, execve;
	import core.sys.posix.signal : kill, SIGKILL;
	import core.stdc.stdlib : exit;
	import adbg.debugger.sys.ptrace;
	import adbg.debugger.sys.user;
	private enum __WALL = 0x40000000;
	private pid_t hprocess; /// Saved process ID
}

version (X86)
	private enum BREAKPOINT = 0xCC; // INT3
else version (X86_64)
	private enum BREAKPOINT = 0xCC; // INT3
else
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

private __gshared
breakpoint_t [DEBUGGER_MAX_BREAKPOINTS]breakpoints;
private __gshared
size_t breakpointindex;

private __gshared
int function(exception_t*) user_function;

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
		hthread = pi.hThread;
		hprocess = pi.hProcess;
		// Microsoft recommends getting function pointer with
		// GetProcAddress("kernel32", "IsWow64Process"), but so far
		// only 64-bit versions of Windows really have WOW64.
		// Nevertheless, required to support 32-bit processes under
		// 64-bit builds.
		version (Win64) {
			if (IsWow64Process(hprocess, &processWOW64))
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
		hprocess = fork();
		if (hprocess < 0)
			return errno;
		if (hprocess == 0) {
			if (ptrace(PTRACE_TRACEME, 0, null, null))
				return errno;
			const(char)*[16] __argv = void;
			const(char)*[1]  __envp = void;
			// Adjust argv
			if (argv) {
				size_t i, __i = 1;
				while (argv[i] && __i < 15)
					__argv[__i++] = argv[i++];
				__argv[__i] = null;
			} else {
				__argv[1] = null;
			}
			__argv[0] = path;
			// Adjust envp
			if (envp == null) {
				envp = cast(const(char)**)&__envp;
				envp[0] = null;
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
 * (Posix) Uses ptrace(2) and waitpid(2), filters SIGCONT
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
				Wow64GetThreadContext(hthread, &ctxwow64);
				adbg_ex_ctx_win_wow64(&e, &ctxwow64);
			} else {
				ctx.ContextFlags = CONTEXT_ALL;
				GetThreadContext(hthread, &ctx);
				adbg_ex_ctx(&e, &ctx);
			}
		} else {
			ctx.ContextFlags = CONTEXT_ALL;
			GetThreadContext(hthread, &ctx);
			adbg_ex_ctx(&e, &ctx);
		}

		with (DebuggerAction)
		final switch (user_function(&e)) {
		case exit:
			//TODO: DebugActiveProcessStop if -pid was used
			ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_TERMINATE_PROCESS);
			return 0;
		case step:
			FlushInstructionCache(hprocess, null, 0);
			// Enable single-stepping via Trap flag
			version (Win64) {
				if (processWOW64) {
					ctxwow64.EFlags |= 0x100;
					Wow64SetThreadContext(hthread, &ctxwow64);
				} else {
					ctx.EFlags |= 0x100;
					SetThreadContext(hthread, &ctx);
				}
			} else {
				ctx.EFlags |= 0x100;
				SetThreadContext(hthread, &ctx);
			}
			goto case;
		case proceed:
			if (ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE) == 0)
				return GetLastError();
			goto L_DEBUG_LOOP;
		}
	} else
	version (Posix) {
		int wstatus = void;
L_DEBUG_LOOP:
		int pid = waitpid(-1, &wstatus, 0);

		if (pid == -1)
			return 3;

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
		// - gdbserver and lldb never attempts to do such a thing
		case SIGILL, SIGSEGV, SIGFPE, SIGBUS:
			siginfo_t sig = void;
			if (ptrace(PTRACE_GETSIGINFO, pid, null, &sig) == -1)
				return 5;
			e.addr = sig._sifields._sigfault.si_addr;
			break;
//		case SIGINT, SIGTERM, SIGABRT: //TODO: Kill?
		default:
			e.addr = null;
		}

		adbg_ex_dbg(&e, pid, chld_signo);

		user_regs_struct u = void;
		if (ptrace(PTRACE_GETREGS, pid, null, &u) == -1)
			return 6;
		adbg_ex_ctx(&e, &u);

		with (DebuggerAction)
		final switch (user_function(&e)) {
		case exit:
			kill(hprocess, SIGKILL); // PTRACE_KILL is deprecated
			return 0;
		case step:
			ptrace(PTRACE_SINGLESTEP, hprocess, null, null);
			goto L_DEBUG_LOOP;
		case proceed:
			ptrace(PTRACE_CONT, hprocess, null, null);
			goto L_DEBUG_LOOP;
		}
	}
}

//
// Breakpoint handling
//

int adbg_bp_add(size_t address) {
	assert(0, "adbg_bp_add not implemented");
}
breakpoint_t* adbg_bp_get(size_t address) {
	assert(0, "adbg_bp_get not implemented");
}
int adbg_bp_rm_addr(size_t address) {
	assert(0, "adbg_bp_rm_addr not implemented");
}
int adbg_bp_rm_index(int index) {
	assert(0, "adbg_bp_rm_index not implemented");
}

//
// Memory
//

enum {	// adbg_mm flags
	// Basic types
	MM_1B	= 0x0,	/// Move 1 byte (8 bits)
	MM_2B	= 0x1,	/// Move 2 bytes (16 bits)
	MM_4B	= 0x2,	/// Move 4 bytes (32 bits)
	MM_8B	= 0x3,	/// Move 8 bytes (64 bits)
	MM_16B	= 0x4,	/// Move 16 bytes (128 bits)
	MM_32B	= 0x5,	/// Move 32 bytes (256 bits)
	MM_64B	= 0x6,	/// Move 64 bytes (512 bits)
	MM_128B	= 0x7,	/// Move 128 bytes (1024 bits)
	MM_256B	= 0x8,	/// Move 256 bytes (2048 bits)
	MM_512B	= 0x9,	/// Move 512 bytes (4096 bits)
	MM_1KB	= 0xA,	/// Move 1 KiB bytes (8192 bits)
	MM_2KB	= 0xB,	/// Move 2 KiB bytes
	MM_4KB	= 0xC,	/// Move 4 KiB bytes
	MM_8KB	= 0xD,	/// Move 8 KiB bytes
	MM_16KB	= 0xE,	/// Move 16 KiB bytes
	MM_32KB	= 0xF,	/// Move 32 KiB bytes
	// Flags
	MM_READ	= 0,	/// Read from memory to data pointer
	MM_WRITE	= 0x0100,	/// Write to memory from data pointer
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
int adbg_mm(size_t addr, int flags, void *data) {
	size_t size = 1 << (flags & 15);

	version (Windows) {
		if (flags & MM_WRITE) {
			if (WriteProcessMemory(hprocess, cast(void*)addr, data, size, null) == 0)
				return GetLastError();
		} else {
			if (ReadProcessMemory(hprocess, cast(void*)addr, data, size, null) == 0)
				return GetLastError();
		}
	} else
	version (linux) {
		// use pread64
	}

	return 0;
}