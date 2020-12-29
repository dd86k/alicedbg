/**
 * Debugger core
 *
 * This is the core of the debugger API. It provides APIs to start a new
 * process, attach itself onto a process, manage breakpoints, etc.
 *
 * This is the only module that contains function names without its module
 * name.
 *
 * License: BSD 3-clause
 */
module adbg.debugger.debugger;

import core.stdc.string : memset;
import core.stdc.errno : errno;
import adbg.debugger.exception;
import adbg.platform;

version (Windows) {
	import core.sys.windows.windows;
	import adbg.sys.windows.wow64;
	//SymInitialize, GetFileNameFromHandle, SymGetModuleInfo64,
	//StackWalk64, SymGetSymFromAddr64, SymFromName
	package __gshared HANDLE g_tid;	/// Saved thread handle, DEBUG_INFO doesn't contain one
	package __gshared HANDLE g_pid;	/// Saved process handle
	version (Win64)
		package __gshared int processWOW64;
} else
version (Posix) {
	import core.sys.posix.sys.stat;
	import core.sys.posix.sys.wait : waitpid, SIGCONT, WUNTRACED;
	import core.sys.posix.signal : kill, SIGKILL, siginfo_t, raise;
	import core.sys.posix.sys.uio;
	import core.sys.linux.fcntl : open;
	import core.stdc.stdlib : exit, malloc, free;
	import core.stdc.stdio : snprintf;
	import adbg.sys.posix.mann;
	import adbg.sys.posix.ptrace;
	import adbg.sys.posix.unistd;
	import adbg.sys.linux.user;
	private enum __WALL = 0x40000000;
	package __gshared pid_t g_pid;	/// Saved process ID
	private __gshared int g_mhandle;	/// Saved memory file handle
}

version (linux)
	version = USE_CLONE;

extern (C):

version (X86)
	private enum opcode_t BREAKPOINT = 0xCC; // INT3
else version (X86_64)
	private enum opcode_t BREAKPOINT = 0xCC; // INT3
else version (ARM_Thumb)
	version (LittleEndian)
		private enum opcode_t BREAKPOINT = 0xDDBE; // BKPT #221 (0xdd)
	else
		private enum opcode_t BREAKPOINT = 0xBEDD; // BKPT #221 (0xdd)
else version (ARM) {
	version (LittleEndian)
		private enum opcode_t BREAKPOINT = 0x7D0D20E1; // BKPT #221 (0xdd)
	else
		private enum opcode_t BREAKPOINT = 0xE1200D7D; // BKPT #221 (0xdd)
} else version (AArch64) {
	//NOTE: Checked under ODA, endianness seems to be moot
	version (LittleEndian)
		private enum opcode_t BREAKPOINT = 0xA01B20D4; // BKPT #221 (0xdd)
	else
		private enum opcode_t BREAKPOINT = 0xA01B20D4; // BKPT #221 (0xdd)
} else
	static assert(0, "Missing BREAKPOINT value for target platform");

/// Actions that a user function handler may return
public
enum DebuggerAction {
	exit,	/// Cause the debugger to close the process and stop debugging
	proceed,	/// Continue debugging
	step,	/// Proceed with a single step
}

/// States the currently debugger state
public
enum DebuggerState {
	idle,	/// Waiting for input
	waiting,	/// Program loaded, waiting to run
	running,	/// Executing debuggee
	paused,	/// Exception occured
}

private
struct breakpoint_t {
	size_t address;
	align(2) opcode_t opcode;
}

version(USE_CLONE) private
struct __adbg_child_t {
	const(char) *dev;
	const(char) **argv, envp;
}

/// breakpoint opcode for platform
private __gshared immutable(opcode_t) g_bp_opcode = BREAKPOINT;
private __gshared breakpoint_t [ADBG_MAX_BREAKPOINTS]g_bp_list;
private __gshared size_t g_bp_index;
private __gshared int function(exception_t*) g_user_function;
private __gshared DebuggerState g_state;

/**
 * Load executable image into the debugger.
 *
 * Loads an executable into the debugger, with optional null-terminated
 * argument list and null-terminated environment.
 * This does not start the process, nor the debugger.
 * On Posix systems, stat(2) is used to check if the file exists.
 * Windows: CreateProcessA (DEBUG_PROCESS).
 * Posix: stat(2), fork(2) or clone(2), ptrace(2) (PTRACE_TRACEME), and execve(2).
 * Params:
 * 	 path = Command, path to executable
 * 	 dir = New directory for the debuggee, null for current directory
 * 	 argv = Argument vector, null-terminated, can be null
 * 	 envp = Environment vector, null-terminated, can be null
 * 	 flags = Reserved
 * Returns: Zero on success; Otherwise os error code is returned
 */
int adbg_load(const(char) *path, const(char) *dir = null,
	const(char) **argv = null, const(char) **envp = null,
	int flags = 0) {
	if (path == null) return 1;

	version (Windows) {
		import core.stdc.stdlib : malloc, free;
		import core.stdc.stdio : snprintf;
		import adbg.utils.str : adbg_util_argv_flatten;
		int bs = 0x4000; // buffer size, 16 KiB
		ptrdiff_t bi;
		char *b = cast(char*)malloc(bs); /// flat buffer
		//
		// Copy execultable path into buffer
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
		memset(&si, 0, si.sizeof); // memset faster than _init functions
		memset(&pi, 0, pi.sizeof); // memset faster than _init functions
		si.cb = STARTUPINFOA.sizeof;
		// Not using DEBUG_ONLY_THIS_PROCESS because our posix
		// counterpart is using -1 (all children) for waitpid.
		if (CreateProcessA(null, b,
			null, null,
			FALSE, DEBUG_PROCESS,
			envp, null,
			&si, &pi) == FALSE)
			return GetLastError();
		free(b);
		g_tid = pi.hThread;
		g_pid = pi.hProcess;
		// Microsoft recommends getting function pointer with
		// GetProcAddress("kernel32", "IsWow64Process"), but so far
		// only 64-bit versions of Windows really have WOW64.
		// Nevertheless, required to support 32-bit processes under
		// 64-bit builds.
		//TODO: GetProcAddress("kernel32", "IsWow64Process2")
		//      IsWow64Process: 32-bit proc. under aarch64 returns FALSE
		version (Win64)
		if (IsWow64Process(g_pid, &processWOW64) == FALSE)
			return GetLastError();
	} else
	version (Posix) {
		// Verify if file exists and we has access to it
		stat_t st = void;
		if (stat(path, &st) == -1)
			return errno;
		// Proceed normally, execve performs executable checks
		version (USE_CLONE) {
			void *chld_stack = mmap(null, ADBG_CHILD_STACK_SIZE,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
				-1, 0);
			if (chld_stack == MAP_FAILED)
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

			// Child struct and clone
			__adbg_child_t chld = void;
			chld.envp = cast(const(char)**)&__envp;
			chld.argv = cast(const(char)**)&__argv;
			g_pid = clone(&__adbg_chld,
				chld_stack + ADBG_CHILD_STACK_SIZE,
				CLONE_PTRACE,
				&chld); // tid
			if (g_pid < 0)
				return errno;
		} else { // fork(2) instead of clone(2)
			g_pid = fork();
			if (g_pid < 0)
				return errno;
			if (g_pid == 0) { // Child process
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
				if (ptrace(PTRACE_TRACEME, 0, 0, 0))
					return errno;
				version (CRuntime_Musl) {
					if (raise(SIGTRAP))
						return errno;
				}
				if (execve(path,
					cast(const(char)**)__argv,
					cast(const(char)**)__envp) == -1)
					return errno;
			}
		} // USE_CLONE
	}
	g_state = DebuggerState.waiting;
	return 0;
}

version (Posix)
version (USE_CLONE)
private int __adbg_chld(void* arg) {
	__adbg_child_t *c = cast(__adbg_child_t*)arg;
	if (ptrace(PTRACE_TRACEME, 0, 0, 0))
		return errno;
	execve(c.argv[0], c.argv, c.envp);
	return errno;
}

/**
 * Attach the debugger to a process ID.
 * Windows: Uses DebugActiveProcess
 * Posix: Uses ptrace(PTRACE_SEIZE)
 * Params:
 * 	pid = Process ID
 * 	flags = Reserved
 * Returns: Non-zero on error: (Posix) errno or (Windows) GetLastError
 */
int adbg_attach(int pid, int flags = 0) {
	version (Windows) {
		if (DebugActiveProcess(pid) == FALSE)
			return GetLastError();
	} else
	version (Posix) {
		if (ptrace(PTRACE_SEIZE, pid, null, null) == -1)
			return errno;
	}
	g_state = DebuggerState.paused;
	return 0;
}

/**
 * Get the debugger's current state.
 * Returns: DebuggerState enum
 */
DebuggerState adbg_state() {
	return g_state;
}

/**
 * Set the user event handle for handling exceptions.
 * Params: f = Function pointer
 * Returns: Zero on success; Otherwise an error occured
 */
void adbg_event_exception(int function(exception_t*) f) {
	g_user_function = f;
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
	if (g_user_function == null)
		return 1;

	exception_t e = void;
	adbg_context_init(&e.registers);

	version (Windows) {
		DEBUG_EVENT de = void;
L_DEBUG_LOOP:
		g_state = DebuggerState.running;
		if (WaitForDebugEvent(&de, INFINITE) == FALSE)
			return GetLastError();
		g_state = DebuggerState.paused;

		// Filter events
		switch (de.dwDebugEventCode) {
		case EXCEPTION_DEBUG_EVENT: break;
		case EXIT_PROCESS_DEBUG_EVENT: return 0;
		default:
			ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
			goto L_DEBUG_LOOP;
		}

		adbg_ex_dbg(&e, &de);
		
		CONTEXT winctx = void;
		version (Win64) {
			WOW64_CONTEXT winctxwow64 = void;
			if (processWOW64) {
				winctxwow64.ContextFlags = CONTEXT_ALL;
				Wow64GetThreadContext(g_tid, &winctxwow64);
				adbg_context_os_win_wow64(&e.registers, &winctxwow64);
			} else {
				winctx.ContextFlags = CONTEXT_ALL;
				GetThreadContext(g_tid, &winctx);
				adbg_context_os(&e.registers, &winctx);
			}
		} else {
			winctx.ContextFlags = CONTEXT_ALL;
			GetThreadContext(g_tid, &winctx);
			adbg_context_os(&e.registers, &winctx);
		}

		g_state = DebuggerState.paused;
		with (DebuggerAction)
		final switch (g_user_function(&e)) {
		case exit:
			//TODO: DebugActiveProcessStop if -pid was used
			ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_TERMINATE_PROCESS);
			return 0;
		case step:
			FlushInstructionCache(g_pid, null, 0);
			// Enable single-stepping via Trap flag
			version (Win64) {
				if (processWOW64) {
					winctxwow64.EFlags |= 0x100;
					Wow64SetThreadContext(g_tid, &winctxwow64);
				} else {
					winctx.EFlags |= 0x100;
					SetThreadContext(g_tid, &winctx);
				}
			} else {
				winctx.EFlags |= 0x100;
				SetThreadContext(g_tid, &winctx);
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
		g_state = DebuggerState.running;
		g_pid = waitpid(-1, &wstatus, 0);
		g_state = DebuggerState.paused;

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
			if (ptrace(PTRACE_GETSIGINFO, g_pid, null, &sig) >= 0) {
				version (CRuntime_Glibc)
					e.faultaddr = sig._sifields._sigfault.si_addr;
				else version (CRuntime_Musl)
					e.faultaddr = sig.__si_fields.__sigfault.si_addr;
				else static assert(0, "hack me");
			} else {
				e.faultaddr = null;
			}
			break;
//		case SIGINT, SIGTERM, SIGABRT: //TODO: Kill?
		default:
			e.faultaddr = null;
		}

		adbg_ex_dbg(&e, g_pid, chld_signo);

//		iovec v = void;
//		if (ptrace(PTRACE_GETREGSET, g_pid, NT_PRSTATUS, &v))
//			return errno;

		with (DebuggerAction)
		final switch (g_user_function(&e)) {
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
	if (g_bp_index >= ADBG_MAX_BREAKPOINTS - 1)
		return 2;
	breakpoint_t *bp = &g_bp_list[g_bp_index];
	if (adbg_mm(MM_READ, addr, &bp.opcode, cast(uint)opcode_t.sizeof))
		return 1;
	return adbg_mm(MM_WRITE, addr, cast(void*)&g_bp_opcode, cast(uint)opcode_t.sizeof);
}
breakpoint_t* adbg_bp_index(int index) {
	assert(0, "adbg_bp_index not implemented");
}
breakpoint_t* adbg_bp_addr(size_t addr) {
	assert(0, "adbg_bp_addr not implemented");
}
int adbg_bp_list(breakpoint_t [ADBG_MAX_BREAKPOINTS]*l, uint *n) {
	assert(0, "adbg_bp_list not implemented");
}
int adbg_bp_rm_index(int index) {
	assert(0, "adbg_bp_rm_index not implemented");
}
int adbg_bp_rm_addr(size_t addr) {
	assert(0, "adbg_bp_rm_addr not implemented");
}

//
// Memory handling
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
			g_mhandle = open(cb, 0);
			free(cb);
		}
		if (op >= MM_WRITE) {
			if (pwrite(g_mhandle, data, size, addr) == -1)
				return errno;
		} else {
			if (pread(g_mhandle, data, size, addr) == -1)
				return errno;
		}
	}

	return 0;
}