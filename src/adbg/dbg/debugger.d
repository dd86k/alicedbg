/**
 * Debugger core
 *
 * This is the core of the debugger API. It provides APIs to start a new
 * process, attach itself onto a process, manage breakpoints, etc.
 *
 * This is the only module that contains function names without its module
 * name.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2013 dd86k
 * License: BSD-3-Clause
 */
module adbg.dbg.debugger;

import core.stdc.config : c_long;
import core.stdc.string : memset;
public import adbg.dbg.exception;
import adbg.platform, adbg.error;

version (Windows) {
	import core.sys.windows.windows;
	import adbg.sys.windows.wow64;
} else
version (Posix) {
	import core.sys.posix.sys.stat;
	import core.sys.posix.sys.wait : waitpid, SIGCONT, WUNTRACED;
	import core.sys.posix.signal : kill, SIGKILL, siginfo_t, raise;
	import core.sys.posix.sys.uio;
	import core.sys.posix.fcntl : open;
	import core.stdc.stdlib : exit, malloc, free;
	import core.stdc.stdio : snprintf;
	import adbg.sys.posix.mann;
	import adbg.sys.posix.ptrace;
	import adbg.sys.posix.unistd;
	import adbg.sys.linux.user;
	private enum __WALL = 0x40000000;
}

version (linux)
	version = USE_CLONE;

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
	// NOTE: Checked under ODA, endianness seems to be moot
	version (LittleEndian)
		private enum opcode_t BREAKPOINT = 0xA01B20D4; // BKPT #221 (0xdd)
	else
		private enum opcode_t BREAKPOINT = 0xA01B20D4; // BKPT #221 (0xdd)
} else
	static assert(0, "Missing BREAKPOINT value for target platform");

extern (C):
__gshared:

/// Actions that a user function handler may return
public
enum AdbgAction {
	exit,	/// Close the process and stop debugging
//	close,	/// Close process or detach
//	stop,	/// Stop debugging
//	pause,	/// Pause debugging
	proceed,	/// Continue debugging
	step,	/// Proceed with a single step
}

/// States the currently debugger state
public
enum AdbgState {
	idle,	/// Waiting for input
	loaded,	/// Program loaded, waiting to run
	running,	/// Executing debuggee
	paused,	/// Exception occured
}

/// Debugger event
/+public
enum AdbgEvent {
	exception,
	processCreated,
	processExit,
	threadCreated,
	threadExit,
}

/// Debugger event structure
public
struct adbg_debugger_event_t {
	AdbgEvent event;
	public union {
		exception_t exception;
	}
}+/

private
struct debuggee_t {
	AdbgState state;
	breakpoint_t[ADBG_MAX_BREAKPOINTS] breakpoints;
	size_t bpindex;	/// breakpoint index
	bool attached;	/// if debuggee was attached to
	version (Windows) {
		HANDLE hpid;	/// Process handle
		HANDLE htid;	/// Thread handle
		int pid;	/// Process identificiation number
		int tid;	/// Thread identification number
		version (Win64) int wow64; /// If running under WoW64
	}
	version (Posix) {
		pid_t pid;	/// Process ID // @suppress(dscanner.suspicious.label_var_same_name)
		int mhandle;	/// Memory file handle
	}
}

private
struct breakpoint_t {
	size_t address;
	align(4) opcode_t opcode;
}

version(USE_CLONE)
private
struct __adbg_child_t {
	const(char) *dev;
	const(char) **argv, envp;
}

package debuggee_t g_debuggee;	/// Debuggee information
private int g_options;	/// Debugger options

//TODO: Load/Attach flags
//      - processOnly (only this process)
//      - useClone (linux only)

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
 * 	 argv = Argument vector, null-terminated, can be null
 * 	 dir = New directory for the debuggee, null for current directory
 * 	 envp = Environment vector, null-terminated, can be null
 * 	 flags = Reserved
 * Returns: Zero on success; Otherwise os error code is returned
 */
int adbg_load(const(char) *path, const(char) **argv = null,
	const(char) *dir = null, const(char) **envp = null,
	int flags = 0) {
	if (path == null)
		return adbg_error(AdbgError.invalidArgument);
	
	version (Windows) {
		import core.stdc.stdlib : malloc, free;
		import core.stdc.stdio : snprintf;
		import adbg.utils.str : adbg_util_argv_flatten;
		int bs = 0x4000; // buffer size, 16 KiB
		ptrdiff_t bi;
		char *b = cast(char*)malloc(bs); /// flat buffer
		
		// Copy execultable path into buffer
		bi = snprintf(b, bs, "%s ", path);
		if (bi < 0) return 1;
		
		// Flatten argv
		if (argv)
			bi += adbg_util_argv_flatten(b + bi, bs, argv);
		
		//TODO: Parse envp
		
		// Create process
		STARTUPINFOA si = void;
		PROCESS_INFORMATION pi = void;
		memset(&si, 0, si.sizeof); // memset faster than _init functions
		memset(&pi, 0, pi.sizeof); // memset faster than _init functions
		si.cb = STARTUPINFOA.sizeof;
		// Not using DEBUG_ONLY_THIS_PROCESS because our posix
		// counterpart is using -1 (all children) for waitpid.
		if (CreateProcessA(
			null,	// lpApplicationName
			b,	// lpCommandLine
			null,	// lpProcessAttributes
			null,	// lpThreadAttributes
			FALSE,	// bInheritHandles
			DEBUG_PROCESS,	// dwCreationFlags
			envp,	// lpEnvironment
			null,	// lpCurrentDirectory
			&si, &pi) == FALSE)
			return adbg_error_system;
		free(b);
		g_debuggee.hpid = pi.hProcess;
		g_debuggee.htid = pi.hThread;
		g_debuggee.pid = pi.dwProcessId;
		g_debuggee.tid = pi.dwThreadId;
		
		// Microsoft recommends getting function pointer with
		// GetProcAddress("kernel32", "IsWow64Process"), but so far
		// only 64-bit versions of Windows really have WOW64.
		// Nevertheless, required to support 32-bit processes under
		// 64-bit builds.
		//TODO: IsWow64Process2 support
		//      with GetProcAddress("kernel32", "IsWow64Process2")
		//      Introduced in Windows 10, version 1511
		//      IsWow64Process: 32-bit proc. under aarch64 returns FALSE
		version (Win64)
		if (IsWow64Process(g_debuggee.hpid, &g_debuggee.wow64) == FALSE)
			return adbg_error_system;
	} else
	version (Posix) {
		// Verify if file exists and we has access to it
		stat_t st = void;
		if (stat(path, &st) == -1)
			return adbg_error_system;
		// Proceed normally, execve performs executable checks
		version (USE_CLONE) { // clone(2)
			void *chld_stack = mmap(null, ADBG_CHILD_STACK_SIZE,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
				-1, 0);
			if (chld_stack == MAP_FAILED)
				return adbg_error_system;

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

			// Clone
			__adbg_child_t chld = void;
			chld.envp = cast(const(char)**)&__envp;
			chld.argv = cast(const(char)**)&__argv;
			g_debuggee.pid = clone(&__adbg_chld,
				chld_stack + ADBG_CHILD_STACK_SIZE,
				CLONE_PTRACE,
				&chld); // tid
			if (g_debuggee.pid < 0)
				return adbg_error_system;
		} else { // fork(2)
			g_debuggee.pid = fork();
			if (g_debuggee.pid < 0)
				return adbg_error_system;
			if (g_debuggee.pid == 0) { // Child process
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
				
				// Trace me
				if (ptrace(PTRACE_TRACEME, 0, 0, 0))
					return adbg_error_system;
				version (CRuntime_Musl) {
					if (raise(SIGTRAP))
						return adbg_error_system;
				}
				
				// Execute
				if (execve(path,
					cast(const(char)**)__argv,
					cast(const(char)**)__envp) == -1)
					return adbg_error_system;
			}
		} // USE_CLONE
	}
	
	g_debuggee.attached = false;
	g_debuggee.state = AdbgState.loaded;
	return 0;
}

version (Posix)
version (USE_CLONE)
private int __adbg_chld(void* arg) {
	__adbg_child_t *c = cast(__adbg_child_t*)arg;
	if (ptrace(PTRACE_TRACEME, 0, 0, 0))
		return adbg_error_system;
	execve(c.argv[0], c.argv, c.envp);
	return adbg_error_system;
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
			return adbg_error_system;
	} else
	version (Posix) {
		if (ptrace(PTRACE_SEIZE, pid, null, null) == -1)
			return adbg_error_system;
	}
	g_debuggee.attached = true;
	//TODO: Check if the process is really paused
	g_debuggee.state = AdbgState.paused;
	return 0;
}

/**
 * Get the debugger's current state.
 * Returns: AdbgState enum
 */
AdbgState adbg_state() {
	return g_debuggee.state;
}

/**
 * Enter the debugging loop. Continues execution of the process until a new
 * debug event occurs. When an exception occurs, the exception_t structure is
 * populated with debugging information.
 * (Windows) Uses WaitForDebugEvent, filters any but EXCEPTION_DEBUG_EVENT
 * (Posix) Uses ptrace(2) and waitpid(2), filters SIGCONT out
 * Params: userfunc = User function callback
 * Returns: Zero on success; Otherwise an error occured
 */
int adbg_run(int function(exception_t*) userfunc) {
	if (userfunc == null)
		return adbg_error(AdbgError.nullAddress);
	
	exception_t e = void;
	
	version (Windows) {
		DEBUG_EVENT de = void;
L_DEBUG_LOOP:
		g_debuggee.state = AdbgState.running;
		if (WaitForDebugEvent(&de, INFINITE) == FALSE)
			return adbg_error_system;
		g_debuggee.state = AdbgState.paused;
		
		// Filter events
		switch (de.dwDebugEventCode) {
		case EXCEPTION_DEBUG_EVENT: break;
		/*case CREATE_THREAD_DEBUG_EVENT:
		case CREATE_PROCESS_DEBUG_EVENT:
		case EXIT_THREAD_DEBUG_EVENT:
		//case EXIT_PROCESS_DEBUG_EVENT:
		case LOAD_DLL_DEBUG_EVENT:
		case UNLOAD_DLL_DEBUG_EVENT:
		case OUTPUT_DEBUG_STRING_EVENT:
		case RIP_EVENT:
			goto default;*/
		case EXIT_PROCESS_DEBUG_EVENT: return 0;
		default:
			ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
			goto L_DEBUG_LOOP;
		}
		
		adbg_ex_dbg(&e, &de);
		
		g_debuggee.state = AdbgState.paused;
		with (AdbgAction)
		final switch (userfunc(&e)) {
		case exit:
			if (g_debuggee.attached)
				DebugActiveProcessStop(g_debuggee.pid);
			else
				ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_TERMINATE_PROCESS);
			g_debuggee.state = AdbgState.idle;
			return 0;
		case step:
			// Enable single-stepping via Trap flag
			version (Win64) {
				CONTEXT winctx = void;
				WOW64_CONTEXT winctxwow64 = void;
				if (g_debuggee.wow64) {
					winctxwow64.ContextFlags = CONTEXT_CONTROL;
					Wow64GetThreadContext(g_debuggee.htid, &winctxwow64);
					FlushInstructionCache(g_debuggee.hpid, null, 0);
					winctxwow64.EFlags |= 0x100;
					Wow64SetThreadContext(g_debuggee.htid, &winctxwow64);
				} else {
					winctx.ContextFlags = CONTEXT_CONTROL;
					GetThreadContext(g_debuggee.htid, &winctx);
					FlushInstructionCache(g_debuggee.hpid, null, 0);
					winctx.EFlags |= 0x100;
					SetThreadContext(g_debuggee.htid, &winctx);
				}
			} else {
				CONTEXT winctx = void;
				winctx.ContextFlags = CONTEXT_ALL;
				GetThreadContext(g_debuggee.htid, &winctx);
				FlushInstructionCache(g_debuggee.hpid, null, 0);
				winctx.EFlags |= 0x100;
				SetThreadContext(g_debuggee.htid, &winctx);
			}
			goto case;
		case proceed:
			if (ContinueDebugEvent(
				de.dwProcessId, de.dwThreadId, DBG_CONTINUE) == FALSE) {
				g_debuggee.state = AdbgState.idle;
				return adbg_error_system;
			}
			goto L_DEBUG_LOOP;
		}
	} else
	version (Posix) {
		int wstatus = void;
L_DEBUG_LOOP:
		g_debuggee.state = AdbgState.running;
		g_debuggee.pid = waitpid(-1, &wstatus, 0);
		
		if (g_debuggee.pid == -1) {
			g_debuggee.state = AdbgState.idle;
			return adbg_error_system;
		}
		
		g_debuggee.state = AdbgState.paused;
		
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
		if ((wstatus & 0x7F) != 0x7F) {
			g_debuggee.state = AdbgState.idle;
			return chld_signo;
		}
		
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
			if (ptrace(PTRACE_GETSIGINFO, g_debuggee.pid, null, &sig) >= 0) {
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
		
		adbg_ex_dbg(&e, g_debuggee.pid, chld_signo);
		
		with (AdbgAction)
		switch (userfunc(&e)) {
		case exit:
			g_debuggee.state = AdbgState.idle; // in either case
			// Because PTRACE_KILL is deprecated
			if (kill(g_debuggee.pid, SIGKILL) == -1)
				return adbg_error_system;
			return 0;
		case step:
			if (ptrace(PTRACE_SINGLESTEP, g_debuggee.pid, null, null) == -1) {
				g_debuggee.state = AdbgState.idle;
				return adbg_error_system;
			}
			goto L_DEBUG_LOOP;
		case proceed:
			if (ptrace(PTRACE_CONT, g_debuggee.pid, null, null) == -1) {
				g_debuggee.state = AdbgState.idle;
				return adbg_error_system;
			}
			goto L_DEBUG_LOOP;
		default: assert(0);
		}
	}
}

//
// Breakpoint handling
//

int adbg_bp_add(size_t addr) {
	if (g_debuggee.bpindex >= ADBG_MAX_BREAKPOINTS - 1)
		return 2;
	breakpoint_t *bp = &g_debuggee.breakpoints[g_debuggee.bpindex];
	assert(0);
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

/// Read memory from debuggee child.
/// Params:
/// 	addr = Memory address (within the children address space)
/// 	data = Pointer to data
/// 	size = Size of data
/// Returns: Non-zero on error
int adbg_mm_cread(size_t addr, void *data, uint size) {
	version (Windows) {
		if (ReadProcessMemory(g_debuggee.hpid, cast(void*)addr, data, size, null) == 0)
			return adbg_error_system;
	} else { // Mostly taken from https://www.linuxjournal.com/article/6100
		import core.stdc.string : memcpy;
		
		c_long *user = cast(c_long*)data;	/// user data pointer
		int i;	/// offset index
		int j = size / c_long.sizeof;	/// number of "blocks" to process
		
		for (; i < j; ++i, ++user)
			*user = ptrace(PTRACE_PEEKDATA, g_debuggee.pid,
				addr + (i * c_long.sizeof), null);
		
		j = size % c_long.sizeof;
		if (j) {
			c_long r = ptrace(PTRACE_PEEKDATA, g_debuggee.pid,
				addr + (i * c_long.sizeof), null);
			memcpy(user, &r, j);
		}
	}
	return 0;
}

/// Write memory to debuggee child.
/// Params:
/// 	addr = Memory address (within the children address space)
/// 	data = Pointer to data
/// 	size = Size of data
/// Returns: Non-zero on error
int adbg_mm_cwrite(size_t addr, void *data, uint size) {
	version (Windows) {
		if (WriteProcessMemory(g_debuggee.hpid, cast(void*)addr, data, size, null) == 0)
			return adbg_error_system;
	} else { // Mostly taken from https://www.linuxjournal.com/article/6100
		import core.stdc.string : memcpy;
		
		c_long *user = cast(c_long*)data;	/// user data pointer
		int i;	/// offset index
		int j = size / c_long.sizeof;	/// number of "blocks" to process
		
		for (; i < j; ++i, ++user)
			ptrace(PTRACE_POKEDATA, g_debuggee.pid,
				addr + (i * c_long.sizeof), user);
		
		j = size % c_long.sizeof;
		if (j)
			ptrace(PTRACE_POKEDATA, g_debuggee.pid,
				addr + (i * c_long.sizeof), user);
	}
	return 0;
}
