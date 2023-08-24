/// Debug a process.
///
/// This is the core of the debugger API. It provides APIs to start a new
/// process, attach itself onto a process, manage breakpoints, etc.
///
/// This is the only module that contains function names without its module
/// name.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.v2.debugger.process;

import adbg.include.c.stdlib : malloc, free;
import adbg.include.c.stdio;
import adbg.include.c.stdarg;
import core.stdc.config : c_long;
import core.stdc.string : memset;
import adbg.platform, adbg.error;
import adbg.utils.string : adbg_util_argv_flatten;
import adbg.v2.debugger.exception;

//TODO: alloc process function?

version (Windows) {
	import core.sys.windows.windows;
	import adbg.include.windows.wow64;
} else version (Posix) {
	import core.sys.posix.sys.stat;
	import core.sys.posix.sys.wait : waitpid, SIGCONT, WUNTRACED;
	import core.sys.posix.signal;
	import core.sys.posix.sys.uio;
	import core.sys.posix.fcntl : open, O_RDONLY;
	import core.sys.posix.unistd : read, close, execve;
	import core.stdc.stdlib : exit, malloc, free;
	import adbg.include.posix.mann;
	import adbg.include.posix.ptrace;
	import adbg.include.posix.unistd : clone, CLONE_PTRACE;
	import adbg.include.linux.user;
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
	unloaded,	/// No No tracee is loaded.
	idle = unloaded,	/// Old v1 alias for unloaded.
	unknown = unloaded,	/// Alias for idle
	standby,	/// Tracee is loaded and waiting to run.
	ready = standby,	/// Old v1 alias for standby.
	running,	/// Tracee is running.
	paused,	/// Tracee is paused due to an exception.
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

enum AdbgCreation {
	unloaded,
	attached,
	spawned,
}

struct adbg_process_t {
	version (Windows) {
		int pid;	/// Process identificiation number
		int tid;	/// Thread identification number
		HANDLE hpid;	/// Process handle
		HANDLE htid;	/// Thread handle
		version (Win64) int wow64; /// If running under WoW64
	}
	version (Posix) {
		pid_t pid;	/// Process ID // @suppress(dscanner.suspicious.label_var_same_name)
		int mhandle;	/// Memory file handle
	}
	/// Current process status.
	AdbgStatus status;
	/// List of breakpoints.
	breakpoint_t[ADBG_MAX_BREAKPOINTS] bp_list;
	/// Breakpoint index.
	size_t bp_index;
	/// Set when debuggee was attached to rather than created.
	/// This is used in the debugger loop.
	deprecated bool attached;
	/// 
	AdbgCreation creation;
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

/// Options for adbg_spawn.
enum AdbgSpawnOpt {
	/// Pass args line to tracee.
	/// Type: const(char) *args
	args	= 1,
	/// Pass argv lines to tracee.
	/// Type: const(char) **argv
	argv	= 2,
	/// Set start directory.
	/// Type: const(char) *args
	/// Default: Current directory of debugger.
	startDir	= 3,
	// Pass environment table to tracee.
	//environment	= 4,
	// Continue after spawning process.
	//continue_	= 5,
	// Tell debugger to use the shell instead of the OS interface.
	//useShell	= 6,
	// Tell debugger to use clone(2) instead of fork(2).
	//useClone	= 7,
}

private
struct adbg_options_spawn_t {
	const(char) *args;
	const(char) *dir;
	const(char) **envp;
	const(char) **argv;
	int flags;
}

/*int adbg_spawn_options(adbg_options_spawn_t *opts, ...) {
	if (opts == null)
		return adbg_oops(AdbgError.nullArgument);
	
	va_list list = void;
	va_start(list, opts);
	
	return adbg_spawn_optionsv(opts, list);
}*/
private
int adbg_spawn_optionsv(adbg_options_spawn_t *opts, va_list list) {
	if (opts == null)
		return adbg_oops(AdbgError.nullArgument);
	
	memset(opts, 0, adbg_options_spawn_t.sizeof);
	
L_OPTION:
	switch (va_arg!int(list)) {
	case AdbgSpawnOpt.args:
		opts.args = va_arg!(const(char)*)(list);
		goto L_OPTION;
	case AdbgSpawnOpt.argv:
		opts.argv = va_arg!(const(char)**)(list);
		goto L_OPTION;
	case AdbgSpawnOpt.startDir:
		opts.dir = va_arg!(const(char)*)(list);
		goto L_OPTION;
	default:
	}
	
	return 0;
}

/// Load executable image into the debugger.
///
/// Loads an executable into the debugger, with optional null-terminated
/// argument list and null-terminated environment.
/// This does not start the process, nor the debugger.
/// On Posix systems, stat(2) is used to check if the file exists.
/// Windows: CreateProcessA (DEBUG_PROCESS).
/// Posix: stat(2), fork(2) or clone(2), ptrace(2) (PT_TRACEME), and execve(2).
/// Params:
/// 	tracee = Reference to tracee object.
/// 	path = Command, path to executable.
/// 	... = Options
/// Returns: Error code.
int adbg_spawn(adbg_process_t *tracee, const(char) *path, ...) {
	if (tracee == null || path == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	version (Trace) trace("path=%s", path);
	va_list list = void;
	va_start(list, path);
	
	return adbg_spawnv(tracee, path, list);
}
private
int adbg_spawnv(adbg_process_t *tracee, const(char) *path, va_list list) {
	if (tracee == null || path == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	adbg_options_spawn_t opts = void;
	int e = adbg_spawn_optionsv(&opts, list);
	if (e) return e;
	
	return adbg_spawn2(tracee, path, &opts);
}
private
int adbg_spawn2(adbg_process_t *tracee, const(char) *path, adbg_options_spawn_t *opts) {
	if (tracee == null || path == null || opts == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	version (Windows) {
		int bs = 0x4000; // buffer size, 16 KiB
		char *b = cast(char*)malloc(bs); /// flat buffer
		if (b == null)
			return adbg_oops(AdbgError.crt);
		
		// Copy execultable path into buffer
		ptrdiff_t bi = snprintf(b, bs, "%s ", path);
		if (bi < 0)
			return adbg_oops(AdbgError.crt);
		
		// Flatten argv
		if (opts.argv)
			bi += adbg_util_argv_flatten(b + bi, bs, opts.argv);
		
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
			null,	// lpEnvironment
			null,	// lpCurrentDirectory
			&si, &pi) == FALSE)
			return adbg_oops(AdbgError.os);
		free(b); //TODO: Verify CreateProcessA copies lpCommandLine/etc.
		tracee.hpid = pi.hProcess;
		tracee.htid = pi.hThread;
		tracee.pid = pi.dwProcessId;
		tracee.tid = pi.dwThreadId;
		
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
		if (IsWow64Process(tracee.hpid, &tracee.wow64) == FALSE)
			return adbg_oops(AdbgError.os);
	} else version (Posix) {
		// Verify if file exists and we has access to it
		stat_t st = void;
		if (stat(path, &st) == -1)
			return adbg_oops(AdbgError.os);
		
		const(char)*[16] __argv = void;
		const(char)*[1]  __envp = void;
		
		// Proceed normally, execve performs executable checks
		version (USE_CLONE) { // clone(2)
			//TODO: get default stack size (glibc constant or function)
			void *chld_stack = mmap(null, ADBG_CHILD_STACK_SIZE,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
				-1, 0);
			if (chld_stack == MAP_FAILED)
				return adbg_oops(AdbgError.os);

			// Adjust argv
			if (opts.argv) {
				size_t i0, i1 = 1;
				while (opts.argv[i0] && i1 < 15)
					__argv[i1++] = opts.argv[i0++];
				__argv[i1] = null;
			} else {
				__argv[1] = null;
			}
			__argv[0] = path;

			// Adjust envp
			//TODO: Is this still valid?
			if (opts.envp == null) {
				opts.envp = cast(const(char)**)&__envp;
				opts.envp[0] = null;
			}

			// Clone
			__adbg_child_t chld = void;
			chld.envp = cast(const(char)**)&__envp;
			chld.argv = cast(const(char)**)&__argv;
			tracee.pid = clone(&adbg_linux_child,
				chld_stack + ADBG_CHILD_STACK_SIZE,
				CLONE_PTRACE,
				&chld); // tid
			if (tracee.pid < 0)
				return adbg_oops(AdbgError.os);
		} else { // fork(2)
			tracee.pid = fork();
			if (tracee.pid < 0)
				return adbg_oops(AdbgError.os);
			if (tracee.pid == 0) { // Child process
				// Adjust argv
				if (opts.argv) {
					size_t i0, i1 = 1;
					while (opts.argv[i0] && i1 < 15)
						__argv[i1++] = opts.argv[i0++];
					__argv[i1] = null;
				} else {
					__argv[1] = null;
				}
				__argv[0] = path;
				
				// Adjust envp
				if (opts.envp == null) {
					opts.envp = cast(const(char)**)&__envp;
					opts.envp[0] = null;
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
	
	tracee.status = AdbgStatus.standby;
	tracee.creation = AdbgCreation.spawned;
	return 0;
}

version (USE_CLONE)
private int adbg_linux_child(void* arg) {
	__adbg_child_t *c = cast(__adbg_child_t*)arg;
	if (ptrace(PT_TRACEME, 0, 0, 0))
		return adbg_oops(AdbgError.os);
	execve(c.argv[0], c.argv, c.envp);
	return adbg_oops(AdbgError.os);
}

enum {
	/// Continue execution when attached.
	/// Type: none
	/// Default: false
	ADBG_ATTACH_OPT_CONTINUE = 1,
	/// Kill tracee when debugger exits.
	/// Type: none
	/// Default: false
	ADBG_ATTACH_OPT_EXITKILL = 2,
	// Only accept these exceptions.
	//ADBG_ATTACH_OPT_FILTER = 3
}

/// Attach the debugger to a process ID.
///
/// Params:
/// 	tracee = Tracee reference.
/// 	pid = Process ID.
/// 	... = Options. Pass 0 for none or to end list.
///
/// Returns: Error code.
int adbg_attach(adbg_process_t *tracee, int pid, ...) {
	if (tracee == null)
		return adbg_oops(AdbgError.nullArgument);
	
	bool continue_;	// continue execution after attaching
	bool exitkill;	// kill child if debugger quits
	
	va_list list = void;
	va_arg(list, pid);
	
L_OPTION:
	switch (va_arg!int(list)) {
	case ADBG_ATTACH_OPT_CONTINUE:
		continue_ = true;
		goto L_OPTION;
	case ADBG_ATTACH_OPT_EXITKILL:
		exitkill = true;
		goto L_OPTION;
	default:
	}
	
	tracee.attached = false;
	
	version (Windows) {
		// Creates events:
		// - CREATE_PROCESS_DEBUG_EVENT
		// - CREATE_THREAD_DEBUG_EVENT
		if (DebugActiveProcess(pid) == FALSE)
			return adbg_oops(AdbgError.os);
		
		tracee.pid = cast(DWORD)pid;
		tracee.hpid = OpenProcess(
			PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			FALSE,
			cast(DWORD)pid);
		
		// Default is TRUE on Windows
		if (exitkill == false)
			DebugSetProcessKillOnExit(FALSE);
		
		// DebugActiveProcess stops debuggee when attached
		if (continue_) {
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
		if (ptrace(continue_ ? PT_SEIZE : PT_ATTACH, pid, null, null) < 0)
			return adbg_oops(AdbgError.os);
		
		tracee.pid = cast(pid_t)pid;
		
		if (exitkill && ptrace(PT_SETOPTIONS, pid, null, PT_O_EXITKILL) < 0)
			return adbg_oops(AdbgError.os);
	}
	
	tracee.attached = true;
	tracee.status = continue_ ? AdbgStatus.running : AdbgStatus.paused;
	return 0;
}

/// Detach debugger from current process.
int adbg_detach(adbg_process_t *tracee) {
	if (tracee == null)
		return adbg_oops(AdbgError.nullArgument);
	
	tracee.status = AdbgStatus.idle;
	version (Windows) {
		if (DebugActiveProcessStop(tracee.pid) == FALSE)
			return adbg_oops(AdbgError.os);
	} else version (Posix) {
		if (ptrace(PT_DETACH, tracee.pid, null, null) == -1)
			return adbg_oops(AdbgError.os);
	}
	tracee.attached = false;
	return 0;
}

/// Is this process being debugged?
/// Returns: true if a debugger is attached.
bool adbg_is_debugged() {
	version (Windows) {
		return IsDebuggerPresent() == TRUE;
	} else version (linux) { // https://stackoverflow.com/a/24969863
		import core.stdc.string : strstr;
		
		// Linux 5.10 example status for cat(1) is 1392 Bytes
		char[4096] buf = void;

		const int status_fd = open("/proc/self/status", O_RDONLY);
		if (status_fd == -1)
			return false;

		const ssize_t num_read = read(status_fd, buf.ptr, buf.sizeof - 1);
		close(status_fd);

		if (num_read <= 0)
			return false;

		buf[num_read] = 0;
		static immutable const(char) *tracerPidString = "TracerPid:";
		const(char)* strptr = strstr(buf.ptr, tracerPidString);
		if (strptr == null)
			return false;
		
		// Example: "TracerPid:\t0\n"
		// "TracerPid:": 10 chars
		// ulong.max (18446744073709551615): 20 chars
		// spacing is either one tab or a few spaces: 1-8
		// So max search lenght at 40 is a decent guess.
		// Search starts at pos 10, at the spacing.
		for (size_t i = 10; i < 40; ++i) {
			switch (strptr[i]) {
			case '0', '\t', ' ': continue; // spacing
			case '\n', '\r', 0: return false; // EOL/EOF
			default: return true; // non-zero digit
			}
		}

		return false;
	} else static assert(0, "adbg_debug_me: Implement me");
}

//TODO: unittest for adbg_is_debugged that loads the executable
//      Or in tests/

/// Insert a tracee break.
void adbg_break() {
	version (Windows) {
		DebugBreak();
	} else version (Posix) {
		ptrace(PT_TRACEME, 0, null, null);
	} else static assert(0, "adbg_debug_me: Implement me");
}

/// Get the debugger's current state.
/// Returns: Debugger status.
AdbgStatus adbg_status(adbg_process_t *tracee) pure {
	if (tracee == null) return AdbgStatus.unknown;
	return tracee.status;
}

/// Enter the debugging loop. Continues execution of the process until a new
/// debug event occurs. When an exception occurs, the exception_t structure is
/// populated with debugging information.
///
/// Windows: Uses WaitForDebugEvent, filters anything but EXCEPTION_DEBUG_EVENT.
/// Posix: Uses ptrace(2) and waitpid(2), filters SIGCONT out.
///
/// Params:
/// 	tracee = Tracee instance.
/// 	userfunc = User function callback.
/// 	... = Options, pass 0 for no options and assume defaults.
/// Returns: Error code.
int adbg_start(adbg_process_t *tracee, int function(adbg_exception_t*) userfunc, ...) {
	if (tracee == null || userfunc == null)
		return adbg_oops(AdbgError.nullAddress);
	
	adbg_exception_t exception = void;
	
	version (Windows) {
		DEBUG_EVENT de = void;
L_DEBUG_LOOP:
		tracee.status = AdbgStatus.running;
		if (WaitForDebugEvent(&de, INFINITE) == FALSE)
			return adbg_oops(AdbgError.os);
		tracee.status = AdbgStatus.paused;
		
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
		
		adbg_exception_translate(&exception, &de, null);
		
		tracee.status = AdbgStatus.paused;
		with (AdbgAction)
		switch (userfunc(&exception)) {
		case exit:
			if (tracee.creation == AdbgCreation.attached)
				return adbg_detach(tracee);
			
			ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_TERMINATE_PROCESS);
			tracee.status = AdbgStatus.idle;
			return 0;
		case step:
			// Enable single-stepping via Trap flag
			version (Win64) {
				if (tracee.wow64) {
					WOW64_CONTEXT winctxwow64 = void;
					winctxwow64.ContextFlags = CONTEXT_CONTROL;
					Wow64GetThreadContext(tracee.htid, &winctxwow64);
					FlushInstructionCache(tracee.hpid, null, 0);
					winctxwow64.EFlags |= 0x100;
					Wow64SetThreadContext(tracee.htid, &winctxwow64);
				} else {
					CONTEXT winctx = void;
					winctx.ContextFlags = CONTEXT_CONTROL;
					GetThreadContext(tracee.htid, &winctx);
					FlushInstructionCache(tracee.hpid, null, 0);
					winctx.EFlags |= 0x100;
					SetThreadContext(tracee.htid, &winctx);
				}
			} else {
				CONTEXT winctx = void;
				winctx.ContextFlags = CONTEXT_ALL;
				GetThreadContext(tracee.htid, &winctx);
				FlushInstructionCache(tracee.hpid, null, 0);
				winctx.EFlags |= 0x100;
				SetThreadContext(tracee.htid, &winctx);
			}
			goto case;
		case proceed:
			if (ContinueDebugEvent(
				de.dwProcessId, de.dwThreadId, DBG_CONTINUE) == FALSE) {
				tracee.status = AdbgStatus.idle;
				return adbg_oops(AdbgError.os);
			}
			goto L_DEBUG_LOOP;
		default:
			return adbg_oops(AdbgError.invalidAction);
		}
	} else version (Posix) {
		int wstatus = void;
L_DEBUG_LOOP:
		tracee.status = AdbgStatus.running;
		tracee.pid = waitpid(-1, &wstatus, 0);
		
		// Something bad happened
		if (tracee.pid == -1) {
			tracee.status = AdbgStatus.idle;
			return adbg_oops(AdbgError.os);
		}
		
		tracee.status = AdbgStatus.paused;
		
		//TODO: Check waitpid status for BSDs
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
			tracee.status = AdbgStatus.idle;
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
			if (ptrace(PT_GETSIGINFO, tracee.pid, null, &sig) < 0) {
				exception.fault.raw = null;
				break;
			}
			version (CRuntime_Glibc)
				exception.fault.raw = sig._sifields._sigfault.si_addr;
			else version (CRuntime_Musl)
				exception.fault.raw = sig.__si_fields.__sigfault.si_addr;
			else static assert(0, "hack me");
			break;
//		case SIGINT, SIGTERM, SIGABRT: //TODO: Kill?
		default:
			exception.fault.raw = null;
		}
		
		adbg_exception_translate(&exception, &tracee.pid, &chld_signo);
		
		switch (userfunc(&exception)) with (AdbgAction) {
		case exit:
			tracee.status = AdbgStatus.idle; // in either case
			if (kill(tracee.pid, SIGKILL) == -1) // PT_KILL is deprecated
				return adbg_oops(AdbgError.os);
			return 0;
		case step:
			if (ptrace(PT_SINGLESTEP, tracee.pid, null, null) == -1) {
				tracee.status = AdbgStatus.idle;
				return adbg_oops(AdbgError.os);
			}
			goto L_DEBUG_LOOP;
		case proceed:
			if (ptrace(PT_CONT, tracee.pid, null, null) == -1) {
				tracee.status = AdbgStatus.idle;
				return adbg_oops(AdbgError.os);
			}
			goto L_DEBUG_LOOP;
		default:
			return adbg_oops(AdbgError.invalidAction);
		}
	}
}

//
// Breakpoint handling
//

int adbg_breakpoint_add(adbg_process_t *tracee, size_t addr) {
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_breakpoint_get(adbg_process_t *tracee, breakpoint_t *bp, int index) {
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_breakpoint_present_at(adbg_process_t *tracee, breakpoint_t *bp, size_t addr) {
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_breakpoint_list(adbg_process_t *tracee, breakpoint_t **l, uint *n) {
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_breakpoint_rm(adbg_process_t *tracee, int index) {
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_breakpoint_rm_at(adbg_process_t *tracee, size_t addr) {
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_breakpoint_rm_all(adbg_process_t *tracee) {
	return adbg_oops(AdbgError.notImplemented);
}
