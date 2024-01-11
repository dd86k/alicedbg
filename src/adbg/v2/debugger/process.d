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

//TODO: Process Pause/Resume
//      Windows: NtSuspendProcess/NtResumeProcess or SuspendThread/ResumeThread
//      Linux: Send SIGSTOP/SIGCONT signals via kill(2)
//TODO: List threads of process

import adbg.include.c.stdlib; // malloc, calloc, free, exit;
import adbg.include.c.stdio;  // snprintf;
import adbg.include.c.stdarg;
import adbg.platform;
import adbg.error;
import adbg.utils.strings : adbg_util_argv_flatten;
import adbg.v2.debugger.exception : adbg_exception_t, adbg_exception_translate;
import adbg.v2.debugger.breakpoint : adbg_breakpoint_t;
import adbg.v2.object.machines;
import core.stdc.string : memset;

version (Windows) {
	import adbg.include.windows.wow64;
	import adbg.include.windows.psapi_dyn;
	import adbg.include.windows.winnt;
	import core.sys.windows.basetsd;
	import core.sys.windows.winbase;
	import core.sys.windows.tlhelp32;
} else version (Posix) {
	import adbg.include.posix.mann;
	import adbg.include.posix.ptrace;
	import adbg.include.posix.unistd : clone, CLONE_PTRACE;
	import core.sys.posix.sys.stat;
	import core.sys.posix.sys.wait : waitpid, SIGCONT, WUNTRACED;
	import core.sys.posix.signal;
	import core.sys.posix.sys.uio;
	import core.sys.posix.fcntl : open, O_RDONLY;
	import core.sys.posix.unistd : read, close, execve;
	
	version (linux) {
		import adbg.include.linux.user;
		private enum __WALL = 0x40000000;
	}
}

version (linux)
	version = USE_CLONE;

extern (C):

//TODO: Deprecate debugger status and replace with process status
//      In a way, it's already the case, but it's not being presented as such
//      adbg_status -> adbg_process_status
/// Debugger status
enum AdbgStatus : ubyte {
	unloaded,	/// Process is not unloaded.
	unknown = unloaded,	/// Alias for idle.
	standby,	/// Process is loaded and waiting to run.
	running,	/// Process is running.
	paused,	/// Process is paused due to an exception or by the debugger.
	idle = unloaded,	/// Old v1 alias for unloaded.
	ready = standby,	/// Old v1 alias for standby.
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

/// Process creation source.
enum AdbgCreation : ubyte {
	unloaded,
	attached,
	spawned,
}

enum ADBG_PROCESS_NAME_LENGTH = 256;

/// Represents an instance of a process.
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
	/// Process' creation source.
	AdbgCreation creation;
	/// Process base module name.
	char[ADBG_PROCESS_NAME_LENGTH] name;
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
// experimental internal call to judge if "building" the options will be useful
// to someone in the future
private
int adbg_spawn_optionsv(adbg_options_spawn_t *opts, va_list list) {
	if (opts == null)
		return adbg_oops(AdbgError.nullArgument);
	
	memset(opts, 0, adbg_options_spawn_t.sizeof);
	
L_OPTION:
	switch (va_arg!int(list)) {
	case 0: break;
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
		return adbg_oops(AdbgError.invalidOption);
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
			//TODO: Get default stack size
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

enum AdbgAttachOpt {
	/// When set, stop execution when attached.
	/// Note: Currently not supported on Windows. Will always stop.
	/// Type: int
	/// Default: 0
	stop = 1,
	/// When set, kill tracee when debugger exits.
	/// Type: int
	/// Default: 0
	exitkill = 2,
	// Filter exception or stop only on these exceptions
	//filter = 3,
}

/// Attach the debugger to a process ID.
///
/// Params:
/// 	tracee = Tracee reference.
/// 	pid = Process ID.
/// 	... = Options. Pass 0 for none or to end list.
/// Returns: Error code.
int adbg_attach(adbg_process_t *tracee, int pid, ...) {
	if (tracee == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (pid <= 0)
		return adbg_oops(AdbgError.invalidArgument);
	
	va_list list = void;
	va_start(list, pid);
	int stop;
	int exitkill;
L_OPTION:
	switch (va_arg!int(list)) {
	case 0: break;
	case AdbgAttachOpt.stop:
		stop = va_arg!int(list);
		goto L_OPTION;
	case AdbgAttachOpt.exitkill:
		exitkill = va_arg!int(list);
		goto L_OPTION;
	default:
		return adbg_oops(AdbgError.invalidOption);
	}
	
	version (Trace) trace("pid=%d stop=%d exitkill=%d", pid, stop, exitkill);
	
	tracee.creation = AdbgCreation.attached;
	
	version (Windows) {
		//TODO: Integrate ObRegisterCallbacks?
		//      https://blog.xpnsec.com/anti-debug-openprocess/
		
		// NOTE: Emulate ProcessIdToHandle
		//       Uses NtOpenProcess with ClientId.UniqueProcess=PID
		//       Uses PROCESS_ALL_ACCESS, but let's start with the basics
		tracee.pid = cast(DWORD)pid;
		tracee.hpid = OpenProcess(
			PROCESS_VM_OPERATION |
			PROCESS_VM_WRITE |
			PROCESS_VM_READ |
			PROCESS_SUSPEND_RESUME |
			PROCESS_QUERY_INFORMATION,
			FALSE,
			cast(DWORD)pid);
		if (tracee.hpid == null)
			return adbg_oops(AdbgError.os);
		
		// Check if process already has an attached debugger
		BOOL dbgpresent = void;
		if (CheckRemoteDebuggerPresent(tracee.hpid, &dbgpresent) == FALSE)
			return adbg_oops(AdbgError.os);
		if (dbgpresent)
			return adbg_oops(AdbgError.debuggerPresent);
		
		// Breaks into remote process and initiates break-in
		if (DebugActiveProcess(tracee.pid) == FALSE)
			return adbg_oops(AdbgError.os);
		
		// DebugActiveProcess, by default, kills the process on exit.
		if (exitkill == false)
			DebugSetProcessKillOnExit(FALSE);
	} else version (Posix) {
		version (Trace) if (stop) trace("Sending break...");
		if (ptrace(stop ? PT_ATTACH : PT_SEIZE, pid, null, null) < 0)
			return adbg_oops(AdbgError.os);
		
		tracee.pid = cast(pid_t)pid;
		
		if (exitkill && ptrace(PT_SETOPTIONS, pid, null, PT_O_EXITKILL) < 0)
			return adbg_oops(AdbgError.os);
	}
	
	tracee.creation = AdbgCreation.attached;
	tracee.status = stop ? AdbgStatus.paused : AdbgStatus.running;
	return 0;
}

/// Detach debugger from current process.
int adbg_detach(adbg_process_t *tracee) {
	if (tracee == null)
		return adbg_oops(AdbgError.nullArgument);
	if (tracee.creation != AdbgCreation.attached)
		return adbg_oops(AdbgError.debuggerInvalidAction);
	
	tracee.creation = AdbgCreation.unloaded;
	tracee.status = AdbgStatus.idle;
	
	version (Windows) {
		if (DebugActiveProcessStop(tracee.pid) == FALSE)
			return adbg_oops(AdbgError.os);
	} else version (Posix) {
		if (ptrace(PT_DETACH, tracee.pid, null, null) < 0)
			return adbg_oops(AdbgError.os);
	}
	
	return 0;
}

/// Is this process being debugged?
/// Returns: True if a debugger is attached to this process.
bool adbg_self_is_debugged() {
	version (Windows) {
		return IsDebuggerPresent() == TRUE;
	} else version (linux) { // https://stackoverflow.com/a/24969863
		import core.stdc.string : strstr;
		
		// Linux 5.10 example status for cat(1) is 1392 Bytes
		enum BUFFERSZ = 4096;
		
		char *buffer = cast(char*)malloc(BUFFERSZ);
		if (buffer == null)
			return false;

		scope(exit) free(buffer);

		const int status_fd = open("/proc/self/status", O_RDONLY);
		if (status_fd == -1)
			return false;

		const ssize_t num_read = read(status_fd, buffer, BUFFERSZ - 1);
		close(status_fd);

		if (num_read <= 0)
			return false;

		buffer[num_read] = 0;
		const(char)* strptr = strstr(buffer, "TracerPid:");
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

/// Insert a tracee break.
void adbg_self_break() {
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

/// Enter the debugging loop.
///
/// Continues execution of the process until a new
/// debug event occurs. When an exception occurs, the exception_t structure is
/// populated with debugging information.
///
/// This call is blocking.
///
/// Windows: Uses WaitForDebugEvent, filters anything but EXCEPTION_DEBUG_EVENT.
/// Posix: Uses ptrace(2) and waitpid(2), filters SIGCONT out.
///
/// Params:
/// 	tracee = Tracee instance.
/// 	userfunc = User function callback.
/// Returns: Error code.
int adbg_wait(adbg_process_t *tracee, void function(adbg_exception_t*) userfunc) {
	if (tracee == null || userfunc == null)
		return adbg_oops(AdbgError.nullArgument);
	if (tracee.creation == AdbgCreation.unloaded)
		return adbg_oops(AdbgError.debuggerUnattached);
	
	adbg_exception_t exception = void;
	
	version (Windows) {
		DEBUG_EVENT de = void;
L_DEBUG_LOOP:
		// Something bad happened
		if (WaitForDebugEvent(&de, INFINITE) == FALSE) {
			tracee.status = AdbgStatus.unloaded;
			tracee.creation = AdbgCreation.unloaded;
			return adbg_oops(AdbgError.os);
		}
		
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
		case EXIT_PROCESS_DEBUG_EVENT:
			goto L_UNLOADED;
		default:
			ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
			goto L_DEBUG_LOOP;
		}
		
		tracee.status = AdbgStatus.paused;
		adbg_exception_translate(&exception, &de, null);
	} else version (Posix) {
		int wstatus = void;
L_DEBUG_LOOP:
		tracee.pid = waitpid(-1, &wstatus, 0);
		
		// Something bad happened
		if (tracee.pid < 0) {
			tracee.status = AdbgStatus.unloaded;
			tracee.creation = AdbgCreation.unloaded;
			return adbg_oops(AdbgError.crt);
		}
		
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
		if ((wstatus & 0x7F) != 0x7F)
			goto L_UNLOADED;
		
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
		// - RIP-1 (x86) could *maybe* point to int3 or similar.
		// NOTE: Newer D compilers fixed siginfo_t as a whole
		//       for version (linux). Noticed on DMD 2.103.1.
		//       Old glibc: ._sifields._sigfault.si_addr
		//       Old musl: .__si_fields.__sigfault.si_addr
		//       New: ._sifields._sigfault.si_addr & .si_addr()
		// NOTE: .si_addr() emits linker errors on Musl platforms.
		case SIGILL, SIGSEGV, SIGFPE, SIGBUS:
			siginfo_t sig = void;
			if (ptrace(PT_GETSIGINFO, tracee.pid, null, &sig) < 0) {
				exception.fault_address = 0;
				break;
			}
			exception.fault_address = cast(size_t)sig._sifields._sigfault.si_addr;
			break;
//		case SIGINT, SIGTERM, SIGABRT: //TODO: Killed?
		default:
			exception.fault_address = 0;
		}
		
		tracee.status = AdbgStatus.paused;
		adbg_exception_translate(&exception, &tracee.pid, &chld_signo);
	}
	
	userfunc(&exception);
	return 0;

L_UNLOADED:
	tracee.status = AdbgStatus.unloaded;
	tracee.creation = AdbgCreation.unloaded;
	return 0;
}


int adbg_stop(adbg_process_t *tracee) {
	if (tracee == null)
		return adbg_oops(AdbgError.nullArgument);
	if (tracee.creation == AdbgCreation.unloaded)
		return adbg_oops(AdbgError.debuggerUnattached);
	
	return tracee.creation == AdbgCreation.attached ?
		adbg_detach(tracee) : adbg_terminate(tracee);
}


int adbg_terminate(adbg_process_t *tracee) {
	if (tracee == null)
		return adbg_oops(AdbgError.nullArgument);
	if (tracee.creation == AdbgCreation.unloaded)
		return adbg_oops(AdbgError.debuggerUnattached);
	
	tracee.status = AdbgStatus.unloaded; // exited in any case
	tracee.creation = AdbgCreation.unloaded;
	
	version (Windows) {
		if (ContinueDebugEvent(tracee.pid, tracee.tid, DBG_TERMINATE_PROCESS) == FALSE)
			return adbg_oops(AdbgError.os);
	} else {
		if (kill(tracee.pid, SIGKILL) < 0) // PT_KILL is deprecated
			return adbg_oops(AdbgError.os);
	}
	return 0;
}


int adbg_continue(adbg_process_t *tracee) {
	if (tracee == null)
		return adbg_oops(AdbgError.nullArgument);
	if (tracee.creation == AdbgCreation.unloaded)
		return adbg_oops(AdbgError.debuggerUnattached);
	if (tracee.status != AdbgStatus.paused)
		return 0;
	
	tracee.status = AdbgStatus.running;
	
	version (Windows) {
		if (ContinueDebugEvent(tracee.pid, tracee.tid, DBG_CONTINUE) == FALSE) {
			tracee.status = AdbgStatus.idle;
			return adbg_oops(AdbgError.os);
		}
	} else {
		if (ptrace(PT_CONT, tracee.pid, null, null) < 0) {
			tracee.status = AdbgStatus.idle;
			return adbg_oops(AdbgError.os);
		}
	}
	
	return 0;
}

/// Performs an instruction step for the debuggee process.
/// Params: tracee = Process being debugged.
/// Returns: Error code.
int adbg_stepi(adbg_process_t *tracee) {
	if (tracee == null)
		return adbg_oops(AdbgError.nullArgument);
	if (tracee.creation == AdbgCreation.unloaded)
		return adbg_oops(AdbgError.debuggerUnattached);
	
	enum EFLAGS_TF = 0x100;
	
	version (Windows) {
		// Enable single-stepping via Trap flag
		version (Win64) {
			if (tracee.wow64) {
				WOW64_CONTEXT winctxwow64 = void;
				winctxwow64.ContextFlags = CONTEXT_CONTROL;
				Wow64GetThreadContext(tracee.htid, &winctxwow64);
				winctxwow64.EFlags |= EFLAGS_TF;
				Wow64SetThreadContext(tracee.htid, &winctxwow64);
				FlushInstructionCache(tracee.hpid, null, 0);
			} else {
				CONTEXT winctx = void;
				winctx.ContextFlags = CONTEXT_CONTROL;
				GetThreadContext(tracee.htid, &winctx);
				winctx.EFlags |= EFLAGS_TF;
				SetThreadContext(tracee.htid, &winctx);
				FlushInstructionCache(tracee.hpid, null, 0);
			}
		} else {
			CONTEXT winctx = void;
			winctx.ContextFlags = CONTEXT_ALL;
			GetThreadContext(tracee.htid, &winctx);
			winctx.EFlags |= EFLAGS_TF;
			SetThreadContext(tracee.htid, &winctx);
			FlushInstructionCache(tracee.hpid, null, 0);
		}
		
		return adbg_continue(tracee);
	} else {
		if (ptrace(PT_SINGLESTEP, tracee.pid, null, null) < 0) {
			tracee.status = AdbgStatus.idle;
			return adbg_oops(AdbgError.os);
		}
		
		return 0;
	}
}

/// Get the process' ID;
/// Params: tracee = Debuggee process.
/// Returns: PID or 0 on error.
int adbg_process_get_pid(adbg_process_t *tracee) {
	if (tracee == null) return 0;
	return tracee.pid;
}

//TODO: bool commandline: Include command-line arguments
/// Get the process file path.
/// Params:
/// 	pid = Process ID.
/// 	buffer = Buffer.
/// 	bufsize = Size of the buffer.
/// 	basename = Request for basename; Otherwise full file path.
/// Returns: Error code.
int adbg_process_get_name(int pid, char *buffer, size_t bufsize, bool basename) {
	if (pid <= 0 || buffer == null || bufsize == 0)
		return adbg_oops(AdbgError.nullArgument);
	
	version (Windows) {
		HANDLE hand = OpenProcess(
			PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			FALSE, pid);
		if (hand == null)
			return adbg_oops(AdbgError.os);
		scope(exit) CloseHandle(hand);
		
		uint bf = cast(uint)bufsize;
		uint r = basename ?
			GetModuleBaseNameA(hand, null, buffer, bf) :
			GetModuleFileNameA(hand, buffer, bf);
		buffer[r] = 0;
		if (r == 0)
			return adbg_oops(AdbgError.os);
		return 0;
	} else version (linux) {
		enum TBUFSZ = 32;
		char[TBUFSZ] pathbuf = void; // Path buffer
		ssize_t r;
		
		snprintf(pathbuf.ptr, TBUFSZ, "/proc/%d/cmdline", pid);
		int cmdlinefd = open(pathbuf.ptr, O_RDONLY);
		if (cmdlinefd > 0) {
			r = read(cmdlinefd, buffer, bufsize);
			buffer[r] = 0;
			close(cmdlinefd);
		}
		
		// Error reading /cmdline, retry with /comm
		if (r <= 0) {
			snprintf(pathbuf.ptr, TBUFSZ, "/proc/%d/comm", pid);
			int commfd = open(pathbuf.ptr, O_RDONLY);
			if (commfd == -1)
				return adbg_oops(AdbgError.os);
			scope(exit) close(commfd);
			r = read(commfd, buffer, bufsize);
			if (r < 0)
				return adbg_oops(AdbgError.os);
			buffer[r - 1] = 0; // Delete newline
		}
		
		// Basename requested but was given full path
		// e.g. /usr/bin/cat to cat
		if (basename && buffer[0] == '/') {
			ssize_t i = r;
			while (--i >= 0) {
				if (buffer[i] == '/') break;
			}
			if (i < 0) // Nothing to do
				return 0;
			size_t s = i + 1; // Start of substring
			size_t l = r - s; // Length
			for (size_t e; e < l; ++e, ++s)
				buffer[e] = buffer[s];
		} 
		//TODO: Name is not absolute, search in PATH
		/* else if (basename == false && buffer[0] != '/') {
			
		}*/
	
		return 0;
	} else
		return adbg_oops(AdbgError.unimplemented);
}

/// Get the current runtime machine platform.
///
/// This is useful when the debugger is dealing with a process running
/// under a subsystem such as WoW or lib32-on-linux64 programs.
/// Params: tracee = Debuggee process.
/// Returns: Machine platform.
AdbgMachine adbg_process_get_machine(adbg_process_t *tracee) {
	AdbgMachine mach;
	
	if (tracee == null) return mach;
	
	version (Win64) version (X86_64) // Windows + x86-64
		mach = tracee.wow64 ? AdbgMachine.x86 : AdbgMachine.amd64;
	
	return mach;
}

/// Options for adbg_process_enumerate.
enum AdbgProcessEnumerateOption {
	/// Set the size of the dynamic buffer for the list of processes.
	/// Default: 1000
	/// Type: uint
	capcity = 1,
	/// This option is not yet implemented.
	sort = 2,
}
/// Sort option for AdbgProcessEnumerateOption.sort.
enum AdbgProcessEnumerateSort {
	/// Sort processes by system (Windows' default).
	system,
	/// Sort processes by ID (Linux's default).
	id,
	/// Sort processes by basename.
	process,
}

/// Structure used with `adbg_process_enumerate`.
///
/// This holds the list of processes and a count.
struct adbg_process_list_t {
	/// Allocated list of processes.
	adbg_process_t *processes;
	/// Number of processes.
	size_t count;
}

//TODO: Redo adbg_process_enumerate
//      int adbg_process_list(adbg_process_list_t*)
//      - List of PIDs instead, use adbg_process_get_name for file path.

// NOTE: For the C vararg to work, list is a parameter instead of a return value.
/// Enumerate running processes.
///
/// This function allocates memory. The list passed will need to be closed
/// using `adbg_process_enumerate_close`.
///
/// On Windows, the list is populated by system order using `EnumProcesses`.
/// On Linux, the list is populated by process ID using procfs.
///
/// Params:
/// 	list = Process list structure instance.
/// 	... = Options, terminated by 0.
/// Returns: Zero for success; Or error code.
int adbg_process_enumerate(adbg_process_list_t *list, ...) {
	if (list == null)
		return adbg_oops(AdbgError.nullArgument);
	
	/// Default fixed buffer size.
	enum DEFAULT_CAPACITY = 1000;
	
	va_list options = void;
	va_start(options, list);
	uint capacity = DEFAULT_CAPACITY;
L_OPTION:
	switch (va_arg!int(options)) {
	case 0: break;
	case AdbgProcessEnumerateOption.capcity:
		capacity = va_arg!uint(options);
		if (capacity <= 0)
			return adbg_oops(AdbgError.invalidOptionValue);
		goto L_OPTION;
	default:
		return adbg_oops(AdbgError.invalidOption);
	}
	
	// Allocate main buffer
	list.processes = cast(adbg_process_t*)malloc(capacity * adbg_process_t.sizeof);
	if (list.processes == null)
		return adbg_oops(AdbgError.crt);
	
	version (Windows) {
		if (__dynlib_psapi_load()) {
			free(list.processes);
			return adbg_errno();
		}
		
		// Allocate temp PID buffer
		uint hsize = cast(uint)(capacity * HMODULE.sizeof);
		DWORD *pidlist = cast(DWORD*)malloc(hsize);
		if (pidlist == null) {
			free(list.processes);
			return adbg_oops(AdbgError.crt);
		}
		scope(exit) free(pidlist);
		
		// Enumerate processes
		// Note that "needed" is reusable after getting the count
		DWORD needed = void;
		if (EnumProcesses(pidlist, hsize, &needed) == FALSE) {
			free(pidlist);
			return adbg_oops(AdbgError.os);
		}
		DWORD proccount = needed / DWORD.sizeof;
		size_t count; /// Final count
		for (DWORD i; i < proccount && count < capacity; ++i) {
			int pid = pidlist[i];
			
			HANDLE procHandle = OpenProcess(
				PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
				FALSE, pid);
			if (procHandle == null)
				continue;
			
			adbg_process_t *proc = &list.processes[count++];
			proc.pid = pid;
			proc.hpid = procHandle;
			proc.tid = 0;
			
			//TODO: Is EnumProcessModules really necessary?
			HMODULE hmod = void;
			if (EnumProcessModules(procHandle, &hmod, hmod.sizeof, &needed)) {
				proc.hpid = hmod;
				
				DWORD len = GetModuleBaseNameA(
					procHandle, hmod, proc.name.ptr, ADBG_PROCESS_NAME_LENGTH);
				if (len > 0) {
					proc.name[len] = 0;
				} else {
					goto L_NONAME;
				}
			} else {
				import core.stdc.string : strcpy;
			L_NONAME:
				strcpy(proc.name.ptr, "<unknown>");
				proc.hpid = null;
			}
			
			CloseHandle(procHandle);
		}
		list.count = count;
		return 0;
	} else version (linux) {
		import core.stdc.ctype : isdigit;
		import core.stdc.stdlib : atoi;
		import core.stdc.string : strcpy;
		import core.sys.posix.dirent : opendir, readdir, dirent, DIR, DT_DIR;
		import core.sys.posix.libgen : basename;
		import adbg.utils.math : MIN;
		
		//TODO: Consider pre-running /proc to get initial count
		size_t count;
		DIR *procfd = opendir("/proc");
		for (dirent *procent = void; (procent = readdir(procfd)) != null;) {
			// If not directory starting with a digit, skip entry
			if (procent.d_type != DT_DIR)
				continue;
			if (isdigit(procent.d_name[0]) == 0)
				continue;
			
			/// Minimum read size, avoid overwriting
			enum READSZ = MIN!(adbg_process_t.name.sizeof, dirent.d_name.sizeof);
			
			// Set PID
			adbg_process_t *proc = &list.processes[count++];
			proc.pid = atoi(procent.d_name.ptr);
			
			// Read /cmdline into process.name buffer
			enum TBUFSZ = 32;
			char[TBUFSZ] proc_comm = void; // Path buffer
			snprintf(proc_comm.ptr, TBUFSZ, "/proc/%s/cmdline", procent.d_name.ptr);
			int cmdlinefd = open(proc_comm.ptr, O_RDONLY);
			if (cmdlinefd == -1)
				continue;
			scope(exit) close(cmdlinefd);
			ssize_t r = read(cmdlinefd, proc.name.ptr, READSZ);
			
			// Get a baseline from /cmdline or /comm
			if (procent.d_name[0] && r > 0) { // /cmdline populated
				// NOTE: Yes, dangerous, but works under Glibc and musl.
				//TODO: Test under Bionic, uClibc, etc.
				strcpy(proc.name.ptr, basename(proc.name.ptr));
			} else { // /cmdline empty, retrying with /comm
				snprintf(proc_comm.ptr, TBUFSZ, "/proc/%s/comm", procent.d_name.ptr);
				int commfd = open(proc_comm.ptr, O_RDONLY);
				if (commfd == -1)
					continue;
				scope(exit) close(commfd);
				r = read(commfd, proc.name.ptr, READSZ);
				if (r < 0)
					continue;
				proc.name[r - 1] = 0; // Delete newline
			}
		}
		list.count = count;
		return 0;
	} else {
		return adbg_oops(AdbgError.unimplemented);
	}
}

unittest {
	adbg_process_list_t list = void;
	assert(adbg_process_enumerate(&list, 0) == 0);
	version (TestVerbose) {
		import core.stdc.stdio : printf;
		foreach (adbg_process_t proc; list.processes[0..list.count]) {
			printf("%5u %s\n",
				adbg_process_get_pid(&proc),
				proc.name.ptr);
		}
	}
	assert(list.count);
	adbg_process_enumerate_close(&list);
}

void adbg_process_enumerate_close(adbg_process_list_t *list) {
	if (list == null) return;
	if (list.processes) free(list.processes);
}
