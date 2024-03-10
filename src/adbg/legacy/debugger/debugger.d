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
 * Copyright: © dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module adbg.legacy.debugger.debugger;

import adbg.include.c.stdlib : malloc, free;
import adbg.include.c.stdio;
import core.stdc.config : c_long;
import core.stdc.string : memset;
import adbg.platform, adbg.error;
import adbg.utils.strings : adbg_util_argv_flatten;
public import adbg.legacy.debugger.exception;

version (Windows) {
	import adbg.include.windows.wow64apiset;
	import adbg.include.windows.psapi_dyn;
	import adbg.include.windows.winnt;
	import core.sys.windows.winbase;
} else version (Posix) {
	import core.sys.posix.sys.stat;
	import core.sys.posix.sys.wait : waitpid, SIGCONT, WUNTRACED;
	import core.sys.posix.sys.uio;
	import core.sys.posix.fcntl : open;
	import core.stdc.stdlib : exit, malloc, free;
	import adbg.include.posix.mann;
	import adbg.include.posix.ptrace;
	import adbg.include.posix.unistd;
	import adbg.include.posix.signal;
	import adbg.include.linux.user;
	private enum __WALL = 0x40000000;
}

version (linux)
	version = USE_CLONE;

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

package
struct debuggee_t {
	AdbgStatus status;
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
 * Posix: stat(2), fork(2) or clone(2), ptrace(2) (PT_TRACEME), and execve(2).
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
				if (ptrace(PT_TRACEME, 0, 0, 0))
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
	if (ptrace(PT_TRACEME, 0, 0, 0))
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
 * Posix: Uses ptrace(PT_SEIZE)
 * Params:
 * 	pid = Process ID
 * 	flags = Reserved
 * Returns: OS error code on error
 */
int adbg_attach_(int pid, int flags = 0) {
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
		if (ptrace(stop ? PT_ATTACH : PT_SEIZE, pid, null, null) == -1)
			return adbg_oops(AdbgError.os);
		
		g_debuggee.pid = cast(pid_t)pid;
		
		if (exitkill)
			if (ptrace(PT_SETOPTIONS, pid, null, PT_O_EXITKILL) == -1)
				return adbg_oops(AdbgError.os);
	}
	
	g_debuggee.attached = true;
	g_debuggee.status = stop ? AdbgStatus.paused : AdbgStatus.running;
	return 0;
}

/// Detach debugger from current process.
int adbg_detach_() {
	version (Windows) {
		if (DebugActiveProcessStop(g_debuggee.pid) == FALSE)
			return adbg_oops(AdbgError.os);
	} else version (Posix) {
		if (ptrace(PT_DETACH, g_debuggee.pid, null, null) == -1)
			return adbg_oops(AdbgError.os);
	}
	return 0;
}

/// Insert a debuggee break.
//TODO: bool checkDebugger = false
//      POSIX: https://stackoverflow.com/a/24969863
void adbg_break_() {
	version (Windows) {
		DebugBreak();
	} else version (Posix) {
		ptrace(PT_TRACEME, 0, null, null);
	}
}

/**
 * Get the debugger's current status.
 * Returns: AdbgStatus enum
 */
AdbgStatus adbg_state() {
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
		return adbg_oops(AdbgError.nullArgument);
	
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
					GetThreadContext(g_debuggee.htid, cast(LPCONTEXT)&winctx);
					FlushInstructionCache(g_debuggee.hpid, null, 0);
					winctx.EFlags |= 0x100;
					SetThreadContext(g_debuggee.htid, cast(LPCONTEXT)&winctx);
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
			if (ptrace(PT_GETSIGINFO, g_debuggee.pid, null, &sig) < 0) {
				e.fault.raw = null;
				break;
			}
			e.fault.raw = sig._sifields._sigfault.si_addr;
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
			// Because PT_KILL is deprecated
			if (kill(g_debuggee.pid, SIGKILL) == -1)
				return adbg_oops(AdbgError.os);
			return 0;
		case step:
			if (ptrace(PT_SINGLESTEP, g_debuggee.pid, null, null) == -1) {
				g_debuggee.status = AdbgStatus.idle;
				return adbg_oops(AdbgError.os);
			}
			goto L_DEBUG_LOOP;
		case proceed:
			if (ptrace(PT_CONT, g_debuggee.pid, null, null) == -1) {
				g_debuggee.status = AdbgStatus.idle;
				return adbg_oops(AdbgError.os);
			}
			goto L_DEBUG_LOOP;
		default: assert(0);
		}
	}
}


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
			*d = ptrace(PT_PEEKDATA, g_debuggee.pid, addr, null);
		
		r = size % c_long.sizeof;
		if (r) {
			c_long c = ptrace(PT_PEEKDATA, g_debuggee.pid, addr, null);
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
			ptrace(PT_POKEDATA, g_debuggee.pid,
				addr + (i * c_long.sizeof), user);
		
		j = size % c_long.sizeof;
		if (j)
			ptrace(PT_POKEDATA, g_debuggee.pid,
				addr + (i * c_long.sizeof), user);
	}
	return 0;
}

// adbg_mm_maps options
enum {
	/// Only get the memory regions for this process
	ADBG_MM_OPT_PROCESS_ONLY = 1,
	// With given Process ID instead
	// Permission issues may be raised
	//ADBG_MM_OPT_PID = 2,
}

private enum MM_MAP_NAME_LEN = 512;

enum {
	ADBG_ACCESS_R = 1,
	ADBG_ACCESS_W = 1 << 1,
	ADBG_ACCESS_X = 1 << 2,
	ADBG_ACCESS_P = 1 << 8,
	ADBG_ACCESS_S = 1 << 9,
}

/// Represents a mapped memory region
struct adbg_mm_map {
	/// Base memory region address.
	void *base;
	/// Size of region.
	size_t size;
	/// Access permissions.
	/// 
	int access;
	/// 
	char[MM_MAP_NAME_LEN] name;
}

/// Obtain the memory maps for the current process
int adbg_mm_maps(adbg_mm_map **mmaps, size_t *mcount, ...) {
	version (Windows) {
		if (__dynlib_psapi_load())
			return adbg_errno();
		
		if (g_debuggee.pid == 0) {
			return adbg_oops(AdbgError.notAttached);
		}
		if (mmaps == null || mcount == null) {
			return adbg_oops(AdbgError.nullArgument);
		}
		
		enum SIZE = 512 * HMODULE.sizeof;
		HMODULE *mods = cast(HMODULE*)malloc(SIZE);
		DWORD needed = void;
		if (EnumProcessModules(g_debuggee.hpid, mods, SIZE, &needed) == FALSE) {
			free(mods);
			return adbg_oops(AdbgError.os);
		}
		
		DWORD modcount = needed / HMODULE.sizeof;
		
		adbg_mm_map *map = *mmaps = cast(adbg_mm_map*)malloc(modcount * adbg_mm_map.sizeof);
		
		size_t i; /// (user) map index
		for (DWORD mod_i; mod_i < modcount; ++mod_i) {
			HMODULE mod = mods[mod_i];
			MODULEINFO minfo = void;
			if (GetModuleInformation(g_debuggee.hpid, mod, &minfo, MODULEINFO.sizeof) == FALSE) {
				continue;
			}
			// \Device\HarddiskVolume5\xyz.dll
			if (GetMappedFileNameA(g_debuggee.hpid, minfo.lpBaseOfDll, map.name.ptr, MM_MAP_NAME_LEN) == FALSE) {
				// xyz.dll
				if (GetModuleBaseNameA(g_debuggee.hpid, mod, map.name.ptr, MM_MAP_NAME_LEN) == FALSE) {
					map.name[0] = 0;
				}
			}
			
			MEMORY_BASIC_INFORMATION mem = void;
			VirtualQuery(minfo.lpBaseOfDll, &mem, MEMORY_BASIC_INFORMATION.sizeof);
			
			// Needs a bit for Copy-on-Write?
			if (mem.AllocationProtect & PAGE_EXECUTE_WRITECOPY)
				map.access = ADBG_ACCESS_R | ADBG_ACCESS_X;
			else if (mem.AllocationProtect & PAGE_EXECUTE_READWRITE)
				map.access = ADBG_ACCESS_R | ADBG_ACCESS_W | ADBG_ACCESS_X;
			else if (mem.AllocationProtect & PAGE_EXECUTE_READ)
				map.access = ADBG_ACCESS_R | ADBG_ACCESS_X;
			else if (mem.AllocationProtect & PAGE_EXECUTE)
				map.access = ADBG_ACCESS_X;
			else if (mem.AllocationProtect & PAGE_READONLY)
				map.access = ADBG_ACCESS_R;
			else if (mem.AllocationProtect & PAGE_READWRITE)
				map.access = ADBG_ACCESS_R | ADBG_ACCESS_W;
			else if (mem.AllocationProtect & PAGE_WRITECOPY)
				map.access = ADBG_ACCESS_R;
			else
				map.access = 0;
			
			map.access |= mem.Type == MEM_PRIVATE ? ADBG_ACCESS_P : ADBG_ACCESS_S;
			
			map.base = minfo.lpBaseOfDll;
			map.size = minfo.SizeOfImage;
			
			++i; ++map;
		}
		
		free(mods);
		*mcount = i;
		return 0;
	} else version (linux) {
		// Inspired by libscanmem
		// https://github.com/scanmem/scanmem/blob/main/maps.c
		import core.stdc.config : c_long;
		import core.stdc.stdlib : malloc, free;
		import core.sys.linux.unistd : readlink;
		import adbg.utils.strings : adbg_util_getline, adbg_util_getlinef;
		import core.sys.linux.unistd : read, close;
		import core.sys.linux.fcntl : open, O_RDONLY;
		
		if (g_debuggee.pid == 0) {
			return adbg_oops(AdbgError.notAttached);
		}
		if (mmaps == null || mcount == null) {
			return adbg_oops(AdbgError.nullArgument);
		}
		
		*mcount = 0;
		
		// Formulate proc map path
		enum PROC_MAPS_LEN = 32;
		char[PROC_MAPS_LEN] proc_maps = void;
		snprintf(proc_maps.ptr, PROC_MAPS_LEN, "/proc/%u/maps", g_debuggee.pid);
		version (Trace) trace("maps: %s", proc_maps.ptr);
		
		// Open process maps
		int fd_maps = open(proc_maps.ptr, O_RDONLY);
		if (fd_maps == -1)
			return adbg_oops(AdbgError.os);
		
		// Formulate proc exe path
		enum PROC_EXE_LEN = 32;
		char[PROC_EXE_LEN] proc_exe = void;
		snprintf(proc_exe.ptr, PROC_EXE_LEN, "/proc/%u/exe", g_debuggee.pid);
		
		// Read link from proc exe for process path (e.g., /usr/bin/cat)
		enum EXE_PATH_LEN = 256;
		char[EXE_PATH_LEN] exe_path = void;
		version (Trace) trace("exe: %s", proc_exe.ptr);
		ssize_t linksz = readlink(proc_exe.ptr, exe_path.ptr, EXE_PATH_LEN);
		if (linksz > 0) {
			exe_path[linksz] = 0;
		} else { // Fail or empty
			exe_path[0] = 0;
		}
		
		// Allocate 4 MiB for input maps buffer
		// WebKit has about 164K worth of maps, for example
		// And then read as much as possible (not possible with fread)
		enum READSZ = 4 * 1024 * 1024;
		//TODO: Consider mmap(2)
		char *procbuf = cast(char*)malloc(READSZ);
		if (procbuf == null) {
			version (Trace) trace("malloc failed");
			close(fd_maps);
			return adbg_oops(AdbgError.crt);
		}
		ssize_t readsz = read(fd_maps, procbuf, READSZ);
		if (readsz == -1) {
			version (Trace) trace("read failed");
			free(procbuf);
			close(fd_maps);
			return adbg_oops(AdbgError.os);
		}
		version (Trace) trace("flen=%zu", readsz);
		
		// Count number of newlines for number of items to allocate
		// Cut lines don't have newlines, so no worries here
		size_t itemcnt;
		for (size_t i; i < readsz; ++i)
			if (procbuf[i] == '\n') ++itemcnt;
		
		// Allocate map items
		version (Trace) trace("allocating %zu items", itemcnt);
		adbg_mm_map *map = *mmaps = cast(adbg_mm_map*)malloc(itemcnt * adbg_mm_map.sizeof);
		if (map == null) {
			free(procbuf);
			close(fd_maps);
			return adbg_oops(AdbgError.crt);
		}
		
		// Go through each entry, which may look like this (without header):
		// Address                   Perm Offset   Dev   inode      Path
		// 55adaf007000-55adaf009000 r--p 00000000 08:02 1311130    /usr/bin/cat
		// Perms: r=read, w=write, x=execute, s=shared or p=private (CoW)
		// Path: Path or [stack], [stack:%id] (3.4 to 4.4), [heap]
		//       [vdso]: https://lwn.net/Articles/615809/
		//       [vvar]: Stores a "mirror" of kernel variables required by virt syscalls
		//       [vsyscall]: Legacy user-kernel (jump?) tables for some syscalls
		enum LINE_LEN = 256;
		char[LINE_LEN] line = void;
		size_t linesz = void; /// line size
		size_t srcidx; /// maps source buffer index
		size_t i; /// maps index
		while (adbg_util_getline(line.ptr, LINE_LEN, &linesz, procbuf, &srcidx)) {
			size_t range_start = void;
			size_t range_end   = void;
			char[4] perms      = void; // rwxp
			uint offset        = void;
			uint dev_major     = void;
			uint dev_minor     = void;
			uint inode         = void;
			//char[512] path     = void;
			
			if (sscanf(line.ptr, "%zx-%zx %4s %x %x:%x %u %512s",
				&range_start, &range_end,
				perms.ptr, &offset, &dev_major, &dev_minor, &inode, map.name.ptr) < 8) {
				continue;
			}
			
			// ELF load address regions
			//
			// When the ELF loader loads an executable or library image into
			// memory, there is one memory region per section created:
			// .text (r-x), .rodata (r--), .data (rw-), and .bss (rw-).
			//
			// The 'x' permission of .text is used to detect the load address
			// (start of memory region) and the end of the ELF file in memory.
			//
			// .bss section:
			// - Except for the .bss section, all memory sections typically
			//   have the same filename of the executable image.
			// - Empty filenames typically indicates .bss memory regions, and
			//   may be consecutive with .data memory regions.
			// - With some ELF images, .bss and .rodata may not be present.
			//
			// Resources:
			// http://en.wikipedia.org/wiki/Executable_and_Linkable_Format
			// http://wiki.osdev.org/ELF
			// http://lwn.net/Articles/531148/
			
			//TODO: Adjust memory region permissions like libscanmem does
			
			version (Trace) trace("entry: %zx %s", range_start, map.name.ptr);
			
			map.base = cast(void*)range_start;
			map.size = range_end - range_start;
			
			map.access = perms[3] == 'p' ? ADBG_ACCESS_P : ADBG_ACCESS_S;
			if (perms[0] == 'r') map.access |= ADBG_ACCESS_R;
			if (perms[1] == 'w') map.access |= ADBG_ACCESS_W;
			if (perms[2] == 'x') map.access |= ADBG_ACCESS_X;
			
			++i; ++map;
		}
		
		*mcount = i;
		free(procbuf);
		return 0;
	} else
		// FreeBSD: procstat(1)
		// - https://man.freebsd.org/cgi/man.cgi?query=vm_map
		// - https://github.com/freebsd/freebsd-src/blob/main/lib/libutil/kinfo_getvmmap.c
		// - args[0] = CTL_KERN
		// - args[1] = KERN_PROC
		// - args[2] = KERN_PROC_VMMAP
		// - args[3] = pid
		// NetBSD: pmap(1)
		// OpenBSD: procmap(1)
		return adbg_oops(AdbgError.notImplemented);
}
