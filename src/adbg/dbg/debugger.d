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
 * Copyright: © 2019-2022 dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module adbg.dbg.debugger;

import core.stdc.config : c_long;
import core.stdc.string : memset;
import adbg.etc.c.stdlib : malloc, free;
public import adbg.dbg.exception;
import adbg.platform, adbg.error;

version (Windows) {
    pragma(lib, "Psapi.lib"); // for core.sys.windows.psapi
	
	import core.sys.windows.windows;
	import adbg.sys.windows.wow64;
	import core.sys.windows.psapi : GetProcessImageFileNameA;
} else version (Posix) {
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

/// Debugger status
public
enum AdbgStatus {
	idle,	/// Waiting for input
	ready,	/// Program loaded, waiting to run
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
	AdbgStatus status;
	breakpoint_t[ADBG_MAX_BREAKPOINTS] breakpoints;
	size_t bpindex;	/// breakpoint index
	/// Set when debuggee was attached to rather than created.
	/// This is used in the debugger loop.
	bool attached;
	version (Windows) {
		HANDLE hpid;	/// Process handle
		HANDLE htid;	/// Thread handle
		int pid;	/// Process identificiation number
		int tid;	/// Thread identification number
		char[MAX_PATH] execpath;	/// 
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

package __gshared debuggee_t g_debuggee;	/// Debuggee information
private __gshared int g_options;	/// Debugger options

//TODO: adbg_create seems more of an appropriate name...

//TODO: Consider adbg_create(const(char) *path, ...)
//      ADBG_CREATE_OPT_ARGS - const(char) *args
//      ADBG_CREATE_OPT_ARGV - const(char) **argv
//      ADBG_CREATE_OPT_ENVP - const(char) **argv
//      ADBG_CREATE_OPT_DIR  - const(char) *args
//      ADBG_CREATE_OPT_DONTSTOP
//        Make debuggee run as soon as possible
//      ADBG_CREATE_OPT_CLONE
//        (Linux) Use clone(2) instead of forking
//        Shouldn't this stay a compile flag?
//      ADBG_CREATE_OPT_PROCESS_ONLY
//        Debug this process only

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
		return adbg_oops(AdbgError.invalidArgument);
	
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
			return adbg_oops(AdbgError.os);
		free(b);
		g_debuggee.hpid = pi.hProcess;
		g_debuggee.htid = pi.hThread;
		g_debuggee.pid = pi.dwProcessId;
		g_debuggee.tid = pi.dwThreadId;
		
		// Microsoft recommends getting function pointer with
		// GetProcAddress("kernel32", "IsWow64Process"), but so far
		// all 64-bit versions of Windows have WOW64 (does Embedded too?).
		// Nevertheless, required to support 32-bit processes under
		// 64-bit builds.
		//TODO: IsWow64Process2 support
		//      with GetProcAddress("kernel32", "IsWow64Process2")
		//      Introduced in Windows 10, version 1511
		//      IsWow64Process: 32-bit proc. under aarch64 returns FALSE
		version (Win64)
		if (IsWow64Process(g_debuggee.hpid, &g_debuggee.wow64) == FALSE)
			return adbg_oops(AdbgError.os);
		
		if (GetProcessImageFileNameA(g_debuggee.hpid, g_debuggee.execpath.ptr, MAX_PATH) == FALSE)
			return adbg_oops(AdbgError.os);
	} else version (Posix) {
		// Verify if file exists and we has access to it
		stat_t st = void;
		if (stat(path, &st) == -1)
			return adbg_oops(AdbgError.os);
		// Proceed normally, execve performs executable checks
		version (USE_CLONE) { // clone(2)
			void *chld_stack = mmap(null, ADBG_CHILD_STACK_SIZE,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
				-1, 0);
			if (chld_stack == MAP_FAILED)
				return adbg_oops(AdbgError.os);

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
				return adbg_oops(AdbgError.os);
		} else { // fork(2)
			g_debuggee.pid = fork();
			if (g_debuggee.pid < 0)
				return adbg_oops(AdbgError.os);
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
	g_debuggee.status = AdbgStatus.ready;
	return 0;
}

version (Posix)
version (USE_CLONE)
private int __adbg_chld(void* arg) {
	__adbg_child_t *c = cast(__adbg_child_t*)arg;
	if (ptrace(PTRACE_TRACEME, 0, 0, 0))
		return adbg_oops(AdbgError.os);
	execve(c.argv[0], c.argv, c.envp);
	return adbg_oops(AdbgError.os);
}

enum {
	/// Stop debuggee when attached.
	ADBG_ATTACH_OPT_STOP = 1,
	/// Don't kill debuggee when debugger exits.
	ADBG_ATTACH_OPT_EXITKILL = 1 << 1,
}

/**
 * Attach the debugger to a process ID.
 * Windows: Uses DebugActiveProcess
 * Posix: Uses ptrace(PTRACE_SEIZE)
 * Params:
 * 	pid = Process ID
 * 	flags = Reserved
 * Returns: OS error code on error
 */
int adbg_attach(int pid, int flags = 0) {
	bool stop = (flags & ADBG_ATTACH_OPT_STOP) != 0;
	bool exitkill = (flags & ADBG_ATTACH_OPT_EXITKILL) != 0;
	version (Windows) {
		// Creates events:
		// - CREATE_PROCESS_DEBUG_EVENT
		// - CREATE_THREAD_DEBUG_EVENT
		if (DebugActiveProcess(pid) == FALSE)
			return adbg_oops(AdbgError.os);
		
		g_debuggee.pid = cast(DWORD)pid;
		g_debuggee.hpid = OpenProcess(
			PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			FALSE,
			cast(DWORD)pid);
		
		// Default is TRUE
		if (exitkill == false)
			DebugSetProcessKillOnExit(FALSE);
		
		// DebugActiveProcess stops debuggee when attached
		if (stop == false) {
			DEBUG_EVENT e = void;
			
			wait: while (WaitForDebugEvent(&e, 100)) {
				switch (e.dwDebugEventCode) {
				case CREATE_PROCESS_DEBUG_EVENT:
				case CREATE_THREAD_DEBUG_EVENT:
					continue;
				case EXCEPTION_DEBUG_EVENT:
					ContinueDebugEvent(e.dwProcessId, e.dwThreadId, DBG_CONTINUE);
					continue;
				default:
					break wait;
				}
			}
			
			// This was my second attempt, but, could be useful later...
			/*import core.sys.windows.tlhelp32 :
				CreateToolhelp32Snapshot, Thread32First, Thread32Next,
				THREADENTRY32, TH32CS_SNAPTHREAD;
			
			// CreateToolhelp32Snapshot ignores th32ProcessID for TH32CS_SNAPTHREAD
			HANDLE h_thread_snapshot =  CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
			if (h_thread_snapshot == INVALID_HANDLE_VALUE)
				return adbg_oops(AdbgError.os);
			
			THREADENTRY32 te32 = void;
			te32.dwSize = THREADENTRY32.sizeof;
			
			// If the first fails, all successive ones will fail
			if (Thread32First(h_thread_snapshot, &te32) == FALSE)
			{
				CloseHandle(h_thread_snapshot);
				return adbg_oops(AdbgError.os);
			}
			
			do {
				if (te32.th32OwnerProcessID == pid) {
					ContinueDebugEvent(pid, te32.th32ThreadID, DBG_CONTINUE);
				}
			} while (Thread32Next(h_thread_snapshot, &te32));*/
		}
	} else version (Posix) {
		if (ptrace(stop ? PTRACE_ATTACH : PTRACE_SEIZE, pid, null, null) == -1)
			return adbg_oops(AdbgError.os);
		
		g_debuggee.pid = cast(pid_t)pid;
		
		if (exitkill)
			if (ptrace(PTRACE_SETOPTIONS, pid, null, PTRACE_O_EXITKILL) == -1)
				return adbg_oops(AdbgError.os);
	}
	
	g_debuggee.attached = true;
	g_debuggee.status = stop ? AdbgStatus.paused : AdbgStatus.running;
	return 0;
}

/// Detach debugger from current process.
int adbg_detach() {
	version (Windows) {
		if (DebugActiveProcessStop(g_debuggee.pid) == FALSE)
			return adbg_oops(AdbgError.os);
	} else version (Posix) {
		if (ptrace(PTRACE_DETACH, g_debuggee.pid, null, null) == -1)
			return adbg_oops(AdbgError.os);
	}
	return 0;
}

/**
 * Get the debugger's current status.
 * Returns: AdbgStatus enum
 */
AdbgStatus adbg_status() {
	return g_debuggee.status;
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
		return adbg_oops(AdbgError.nullAddress);
	
	exception_t e = void;
	
	version (Windows) {
		DEBUG_EVENT de = void;
L_DEBUG_LOOP:
		g_debuggee.status = AdbgStatus.running;
		if (WaitForDebugEvent(&de, INFINITE) == FALSE)
			return adbg_oops(AdbgError.os);
		g_debuggee.status = AdbgStatus.paused;
		
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
		
		g_debuggee.status = AdbgStatus.paused;
		with (AdbgAction)
		final switch (userfunc(&e)) {
		case exit:
			if (g_debuggee.attached)
				DebugActiveProcessStop(g_debuggee.pid);
			else
				ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_TERMINATE_PROCESS);
			g_debuggee.status = AdbgStatus.idle;
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
				g_debuggee.status = AdbgStatus.idle;
				return adbg_oops(AdbgError.os);
			}
			goto L_DEBUG_LOOP;
		}
	} else version (Posix) {
		int wstatus = void;
L_DEBUG_LOOP:
		g_debuggee.status = AdbgStatus.running;
		g_debuggee.pid = waitpid(-1, &wstatus, 0);
		
		if (g_debuggee.pid == -1) {
			g_debuggee.status = AdbgStatus.idle;
			return adbg_oops(AdbgError.os);
		}
		
		g_debuggee.status = AdbgStatus.paused;
		
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
			g_debuggee.status = AdbgStatus.idle;
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
					e.fault.raw = sig._sifields._sigfault.si_addr;
				else version (CRuntime_Musl)
					e.fault.raw = sig.__si_fields.__sigfault.si_addr;
				else static assert(0, "hack me");
			} else {
				e.fault.raw = null;
			}
			break;
//		case SIGINT, SIGTERM, SIGABRT: //TODO: Kill?
		default:
			e.fault.raw = null;
		}
		
		adbg_ex_dbg(&e, g_debuggee.pid, chld_signo);
		
		with (AdbgAction)
		switch (userfunc(&e)) {
		case exit:
			g_debuggee.status = AdbgStatus.idle; // in either case
			// Because PTRACE_KILL is deprecated
			if (kill(g_debuggee.pid, SIGKILL) == -1)
				return adbg_oops(AdbgError.os);
			return 0;
		case step:
			if (ptrace(PTRACE_SINGLESTEP, g_debuggee.pid, null, null) == -1) {
				g_debuggee.status = AdbgStatus.idle;
				return adbg_oops(AdbgError.os);
			}
			goto L_DEBUG_LOOP;
		case proceed:
			if (ptrace(PTRACE_CONT, g_debuggee.pid, null, null) == -1) {
				g_debuggee.status = AdbgStatus.idle;
				return adbg_oops(AdbgError.os);
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
	return adbg_oops(AdbgError.notImplemented);
	/*if (g_debuggee.bpindex >= ADBG_MAX_BREAKPOINTS - 1)
		return 2;
	breakpoint_t *bp = &g_debuggee.breakpoints[g_debuggee.bpindex];
	assert(0);*/
}
breakpoint_t* adbg_bp_index(int index) {
	return null;
}
breakpoint_t* adbg_bp_addr(size_t addr) {
	return null;
}
int adbg_bp_list(breakpoint_t [ADBG_MAX_BREAKPOINTS]*l, uint *n) {
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_bp_rm_index(int index) {
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_bp_rm_addr(size_t addr) {
	return adbg_oops(AdbgError.notImplemented);
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
int adbg_mm_read(size_t addr, void *data, uint size) {
	version (Windows) {
		if (ReadProcessMemory(g_debuggee.hpid, cast(void*)addr, data, size, null) == 0)
			return adbg_oops(AdbgError.os);
	} else { // Based on https://www.linuxjournal.com/article/6100
		c_long *d = cast(c_long*)data;	/// destination
		int r = size / c_long.sizeof;	/// number of "long"s to read
		
		for (; r > 0; --r, ++d, addr += c_long.sizeof)
			*d = ptrace(PTRACE_PEEKDATA, g_debuggee.pid, addr, null);
		
		r = size % c_long.sizeof;
		if (r) {
			c_long c = ptrace(PTRACE_PEEKDATA, g_debuggee.pid, addr, null);
			ubyte* dest8 = cast(ubyte*)d, src8 = cast(ubyte*)&c;
			for (; r; --r) *dest8++ = *src8++; // inlined memcpy
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
int adbg_mm_write(size_t addr, void *data, uint size) {
	version (Windows) {
		if (WriteProcessMemory(g_debuggee.hpid, cast(void*)addr, data, size, null) == 0)
			return adbg_oops(AdbgError.os);
	} else { // Mostly taken from https://www.linuxjournal.com/article/6100
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

enum {
	ADBG_MM_OPT_PROCESS_ONLY = 1,
}

struct adbg_mm_map {
	const(char) *name;
	void *base;
	size_t size;
}

int adbg_mm_maps(adbg_mm_map **maps, size_t *count, int flags = 0) {
	version (Windows) {
		import core.sys.windows.psapi :
			GetModuleInformation,
			EnumProcessModules,
			MODULEINFO;
		
		if (g_debuggee.pid == 0) {
			return adbg_oops(AdbgError.notAttached);
		}
		if (maps == null || count == null) {
			return adbg_oops(AdbgError.nullArgument);
		}
		
		enum SIZE = 512 * HMODULE.sizeof;
		HMODULE *mods = cast(HMODULE*)malloc(SIZE);
		DWORD needed = void;
		if (EnumProcessModules(g_debuggee.hpid, mods, SIZE, &needed) == FALSE)
			return adbg_oops(AdbgError.os);
		
		DWORD modcount = needed / HMODULE.sizeof;
		
		*maps = cast(adbg_mm_map*)malloc(modcount * adbg_mm_map.sizeof);
		
		size_t mi;
		for (DWORD i; i < modcount; ++i) {
			HMODULE hmod = mods[i];
			
			MODULEINFO minfo = void;
			if (GetModuleInformation(g_debuggee.hpid, hmod, &minfo, MODULEINFO.sizeof) == FALSE) {
				continue;
			}
			
			(*maps)[mi].base = minfo.EntryPoint;
			(*maps)[mi].size = minfo.SizeOfImage;
			
			++mi;
		}
		*count = mi;
	} else version (Posix) {
		//TODO: Prase /proc/{pid}/maps
	}
	return 0;
}

enum {
	/// 
	ADBG_SCAN_OPT_UNALIGNED = 1,
	/// 
	ADBG_SCAN_OPT_PROGRESS_CB = 1 << 16,
}

/// Scan debuggee process for a specific value
int adbg_mm_scan(void* data, size_t size, size_t* addr, ...) {
	
	
	
	return adbg_oops(AdbgError.notImplemented); // done scanning
}
