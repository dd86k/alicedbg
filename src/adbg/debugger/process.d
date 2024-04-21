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
/// License: BSD-3-Clause-Clear
module adbg.debugger.process;

//TODO: Process Pause/Resume
//      Windows: NtSuspendProcess/NtResumeProcess or SuspendThread/ResumeThread
//      Linux: Send SIGSTOP/SIGCONT signals via kill(2)
//TODO: List threads of process (maybe in a module called threading.d)
//TODO: Has remote debugger attached?

import adbg.include.c.stdlib; // malloc, calloc, free, exit;
import adbg.include.c.stdio;  // snprintf;
import adbg.include.c.stdarg;
import adbg.platform : ADBG_CHILD_STACK_SIZE;
import adbg.error;
import adbg.utils.strings : adbg_util_argv_flatten;
import adbg.debugger.exception : adbg_exception_t, adbg_exception_translate;
import adbg.machines;
import core.stdc.string;

version (Windows) {
	import adbg.include.windows.wow64apiset;
	import adbg.include.windows.psapi_dyn;
	import adbg.include.windows.winnt;
	import core.sys.windows.basetsd;
	import core.sys.windows.winbase;
} else version (Posix) {
	import adbg.include.posix.mann;
	import adbg.include.posix.ptrace;
	import adbg.include.posix.unistd;
	import adbg.include.posix.sys.wait;
	import adbg.utils.math;
	import core.stdc.ctype : isdigit;
	import core.sys.posix.fcntl : open, O_RDONLY, stat, stat_t;
	import core.sys.posix.dirent;
	import core.sys.posix.libgen : basename;
}

// I can't remember why, but problably Musl moment
version (linux)
	version = USE_CLONE;

extern (C):

/// Debugging events
enum AdbgEvent {
	exception,
}

/// Process status
enum AdbgProcStatus : ubyte {
	unknown,	/// Process status is not known.
	unloaded = unknown,	/// Process is unloaded.
	standby,	/// Process is loaded and waiting to run.
	running,	/// Process is running.
	paused,	/// Process is paused due to an exception or by the debugger.
}

//TODO: Rename to AdbgDebuggerRelation
/// Process creation source.
enum AdbgCreation : ubyte {
	unattached,
	unloaded = unattached, // Older alias
	attached,
	spawned,
}

//TODO: Deprecate and remove static buffer in process struct
enum ADBG_PROCESS_NAME_LENGTH = 256;

/// Represents an instance of a process.
struct adbg_process_t {
	version (Windows) { // Original identifiers; Otherwise informal
		int pid;	/// Process identificiation number
		int tid;	/// Thread identification number
		HANDLE hpid;	/// Process handle
		HANDLE htid;	/// Thread handle
		//TODO: Deprecate and remove wow64 field
		//      Promote AdbgMachine enum
		version (Win64) int wow64; /// If running under WoW64
	}
	version (Posix) {
		pid_t pid;	/// Process ID // @suppress(dscanner.suspicious.label_var_same_name)
	}
	version (linux) {
		int mhandle;	/// Internal memory file handle to /mem
		int memfailed;	/// Set if we fail to open /mem
	}
	/// Last known process status.
	AdbgProcStatus status;
	/// Process' creation source.
	AdbgCreation creation;
	//TODO: Deprecate and remove static buffer in process struct
	/// Process base module name.
	char[ADBG_PROCESS_NAME_LENGTH] name;
}

version(USE_CLONE)
private
struct __adbg_child_t {
	const(char) *dev;
	const(char) **argv, envp;
}

//TODO: Stream redirection options (FILE* and os handle options)
//TODO: "start suspended" option
//      Windows: CREATE_SUSPENDED
//      Posix:
/// Options for adbg_spawn.
enum AdbgSpawnOpt {
	/// Pass args line to tracee.
	/// Type: const(char)*
	/// Default: null
	args	= 1,
	/// Pass argv lines to tracee.
	/// Type: const(char)**
	/// Default: null
	argv	= 2,
	/// Set start directory.
	/// Type: const(char)*
	/// Default: Current directory of debugger.
	startDir	= 3,
	/// Pass environment table to tracee.
	/// Type: const(char)**
	/// Default: null
	environment	= 4,
	// Continue after spawning process.
	//continue_	= 5,
	// Tell debugger to use the shell instead of the OS interface.
	//useShell	= 6,
	// Tell debugger to use clone(2) instead of fork(2).
	//useClone	= 7,
	/// Debug child processes that the target process spawns.
	/// Type: int
	/// Default: 0
	debugChildren    = 10,
}

/// Load executable image into the debugger.
///
/// By default, only debugs the target process.
/// Loads an executable into the debugger, with optional null-terminated
/// argument list and null-terminated environment.
///
/// Windows: CreateProcessA with DEBUG_PROCESS.
/// Posix: stat(2), fork(2) or clone(2), ptrace(2) with PT_TRACEME, and execve(2).
/// Params:
/// 	path = Command, path to executable.
/// 	... = Options, with zero ending them.
/// Returns: Process instance; Or null on error.
adbg_process_t* adbg_debugger_spawn(const(char) *path, ...) {
	if (path == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	
	enum {
		OPT_DEBUG_ALL = 1,
	}
	
	va_list list = void;
	va_start(list, path);
	
	const(char)  *args;
	const(char) **argv;
	const(char)  *dir;
	const(char) **envp;
	int options;
LOPT:
	switch (va_arg!int(list)) {
	case 0: break;
	case AdbgSpawnOpt.args:
		args = va_arg!(const(char)*)(list);
		goto LOPT;
	case AdbgSpawnOpt.argv:
		argv = va_arg!(const(char)**)(list);
		goto LOPT;
	case AdbgSpawnOpt.startDir:
		dir = va_arg!(const(char)*)(list);
		goto LOPT;
	case AdbgSpawnOpt.environment:
		envp = va_arg!(const(char)**)(list);
		goto LOPT;
	case AdbgSpawnOpt.debugChildren:
		if (va_arg!(int)(list)) options |= OPT_DEBUG_ALL;
		goto LOPT;
	default:
		adbg_oops(AdbgError.invalidOption);
		return null;
	}
	
	adbg_process_t *proc = cast(adbg_process_t*)calloc(1, adbg_process_t.sizeof);
	if (proc == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
version (Windows) {
	// NOTE: CreateProcessW modifies lpCommandLine
	
	// Add argv is specified, we'll have to cram it into args
	if (argv) {
		// Make temporary buffer for lpCommandline
		// NOTE: lpCommandLine is max 32,767 including null Unicode character
		enum TBUFSZ = 8 * 1024; // temporary command buffer size
		char *tbuf = cast(char*)malloc(TBUFSZ); /// flat buffer
		if (tbuf == null) {
			free(proc);
			adbg_oops(AdbgError.crt);
			return null;
		}
		//TODO: Verify CreateProcessA copies buffers.
		scope(exit) free(tbuf);
		
		// Flatten argv
		size_t o = adbg_util_argv_flatten(tbuf, TBUFSZ, argv);
		if (o == 0) {
			free(proc);
			adbg_oops(AdbgError.assertion);
			return null;
		}
		
		// Fuse argv with args with a space in-between
		if (args) {
			strncpy(tbuf + o, " ", TBUFSZ - o);
			++o;
			strncpy(tbuf + o, args, TBUFSZ - o);
		}
		
		args = tbuf;
	}
	
	//TODO: Parse envp
	
	// Setup process info
	STARTUPINFOA si = void;
	PROCESS_INFORMATION pi = void;
	memset(&si, 0, si.sizeof);
	memset(&pi, 0, pi.sizeof);
	si.cb = STARTUPINFOA.sizeof;
	
	DWORD flags = options & OPT_DEBUG_ALL ? DEBUG_PROCESS : DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS;
	
	flags |= CREATE_DEFAULT_ERROR_MODE;
	
	if (CreateProcessA(
		path,	// lpApplicationName
		cast(char*)args,	// lpCommandLine
		null,	// lpProcessAttributes
		null,	// lpThreadAttributes
		FALSE,	// bInheritHandles
		flags,	// dwCreationFlags
		null,	// lpEnvironment
		null,	// lpCurrentDirectory
		&si, &pi) == FALSE) {
		free(proc);
		adbg_oops(AdbgError.os);
		return null;
	}
	
	proc.hpid = pi.hProcess;
	proc.htid = pi.hThread;
	proc.pid = pi.dwProcessId;
	proc.tid = pi.dwThreadId;
	
	// Microsoft recommends getting function pointer with
	// GetProcAddress("kernel32", "IsWow64Process"), but so far
	// all 64-bit versions of Windows have WOW64 (does Embedded too?).
	// Nevertheless, required to support 32-bit processes under
	// 64-bit builds.
	//TODO: IsWow64Process2 support
	//      with GetProcAddress("kernel32", "IsWow64Process2")
	//      Introduced in Windows 10, version 1511
	//      IsWow64Process: 32-bit proc. under aarch64 returns FALSE
	// NOTE: Could be moved to adbg_process_get_machine
	version (Win64) {
		if (IsWow64Process(proc.hpid, &proc.wow64) == FALSE) {
			free(proc);
			adbg_oops(AdbgError.os);
			return null;
		}
	}
} else version (Posix) {
	// Verify if file exists and we has access to it
	stat_t st = void;
	if (stat(path, &st) == -1) {
		free(proc);
		adbg_oops(AdbgError.os);
		return null;
	}
	
	const(char)*[16] __argv = void;
	const(char)*[1]  __envp = void;
	
	// Proceed normally, execve performs executable checks
	version (USE_CLONE) { // clone(2)
		//TODO: get default stack size (glibc constant or function)
		void *chld_stack = mmap(null, ADBG_CHILD_STACK_SIZE,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
			-1, 0);
		if (chld_stack == MAP_FAILED) {
			free(proc);
			adbg_oops(AdbgError.os);
			return null;
		}

		// Adjust argv
		if (argv) {
			size_t i0, i1 = 1;
			while (argv[i0] && i1 < 15)
				__argv[i1++] = argv[i0++];
			__argv[i1] = null;
		} else {
			__argv[1] = null;
		}
		__argv[0] = path;

		// Adjust envp
		//TODO: Is this still valid?
		if (envp == null) {
			envp = cast(const(char)**)&__envp;
			envp[0] = null;
		}

		// Clone
		//TODO: Get default stack size
		__adbg_child_t chld = void;
		chld.envp = cast(const(char)**)&__envp;
		chld.argv = cast(const(char)**)&__argv;
		proc.pid = clone(&adbg_linux_child,
			chld_stack + ADBG_CHILD_STACK_SIZE,
			CLONE_PTRACE,
			&chld); // tid
		if (proc.pid < 0) {
			free(proc);
			adbg_oops(AdbgError.os);
			return null;
		}
	} else { // fork(2)
		proc.pid = fork();
		if (proc.pid < 0)
			return adbg_oops(AdbgError.os);
		if (proc.pid == 0) { // Child process
			// Adjust argv
			if (argv) {
				size_t i0, i1 = 1;
				while (argv[i0] && i1 < 15)
					__argv[i1++] = argv[i0++];
				__argv[i1] = null;
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
			if (ptrace(PT_TRACEME, 0, 0, 0)) {
				free(proc);
				adbg_oops(AdbgError.os);
				return null;
			}
			version (CRuntime_Musl) {
				if (raise(SIGTRAP)) {
					free(proc);
					adbg_oops(AdbgError.os);
					return null;
				}
			}
			
			// Execute
			if (execve(path,
				cast(const(char)**)__argv,
				cast(const(char)**)__envp) == -1) {
				free(proc);
				adbg_oops(AdbgError.os);
				return null;
			}
		}
	} // fork(2)
} // version (Posix)
	
	proc.status = AdbgProcStatus.standby;
	proc.creation = AdbgCreation.spawned;
	return proc;
}

version (USE_CLONE)
private int adbg_linux_child(void* arg) {
	__adbg_child_t *c = cast(__adbg_child_t*)arg;
	if (ptrace(PT_TRACEME, 0, 0, 0))
		return adbg_oops(AdbgError.os);
	execve(c.argv[0], c.argv, c.envp);
	return adbg_oops(AdbgError.os);
}

/// Debugger process attachment options
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
/// 	pid = Process ID.
/// 	... = Options. Pass 0 for none or to end list.
/// Returns: Error code.
adbg_process_t* adbg_debugger_attach(int pid, ...) {
	if (pid <= 0) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	
	enum {
		OPT_STOP = 1,
		OPT_EXITKILL = 2,
	}
	
	va_list list = void;
	va_start(list, pid);
	int options;
L_OPTION:
	switch (va_arg!int(list)) {
	case 0: break;
	case AdbgAttachOpt.stop:
		if (va_arg!int(list)) options |= OPT_STOP;
		goto L_OPTION;
	case AdbgAttachOpt.exitkill:
		if (va_arg!int(list)) options |= OPT_EXITKILL;
		goto L_OPTION;
	default:
		adbg_oops(AdbgError.invalidOption);
		return null;
	}
	
	version (Trace) trace("pid=%d options=%#x", pid, options);
	
	adbg_process_t *proc = cast(adbg_process_t*)calloc(1, adbg_process_t.sizeof);
	if (proc == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	proc.creation = AdbgCreation.attached;
	
version (Windows) {
	//TODO: Integrate ObRegisterCallbacks?
	//      https://blog.xpnsec.com/anti-debug-openprocess/
	
	// NOTE: Emulate ProcessIdToHandle
	//       Uses NtOpenProcess with ClientId.UniqueProcess=PID
	//       Uses PROCESS_ALL_ACCESS, but let's start with the basics
	proc.pid = cast(DWORD)pid;
	proc.hpid = OpenProcess(
		PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE |
		PROCESS_VM_READ |
		PROCESS_SUSPEND_RESUME |
		PROCESS_QUERY_INFORMATION,
		FALSE,
		cast(DWORD)pid);
	if (proc.hpid == null) {
		free(proc);
		adbg_oops(AdbgError.os);
		return null;
	}
	
	// Check if process already has an attached debugger
	BOOL dbgpresent = void;
	if (CheckRemoteDebuggerPresent(proc.hpid, &dbgpresent) == FALSE) {
		free(proc);
		adbg_oops(AdbgError.os);
		return null;
	}
	if (dbgpresent) {
		free(proc);
		adbg_oops(AdbgError.debuggerPresent);
		return null;
	}
	
	// Breaks into remote process and initiates break-in
	//TODO: try NtContinue for continue option
	if (DebugActiveProcess(proc.pid) == FALSE) {
		free(proc);
		adbg_oops(AdbgError.os);
		return null;
	}
	
	// DebugActiveProcess, by default, kills the process on exit.
	// Set exitkill unconditionalled
	// Default: on
	if (DebugSetProcessKillOnExit(options & OPT_EXITKILL) == FALSE) {
		free(proc);
		adbg_oops(AdbgError.os);
		return null;
	}
} else version (Posix) {
	version (Trace) if (options & OPT_STOP) trace("Sending break...");
	if (ptrace(options & OPT_STOP ? PT_ATTACH : PT_SEIZE, pid, null, null) < 0) {
		free(proc);
		adbg_oops(AdbgError.os);
		return null;
	}
	
	// Set exitkill on if specified
	// Default: off
	if (options & OPT_EXITKILL && ptrace(PT_SETOPTIONS, pid, null, PT_O_EXITKILL) < 0) {
		free(proc);
		adbg_oops(AdbgError.os);
		return null;
	}
	
	proc.pid = cast(pid_t)pid;
} // version (Posix)
	
	proc.creation = AdbgCreation.attached;
	proc.status = options & OPT_STOP ? AdbgProcStatus.paused : AdbgProcStatus.running;
	return proc;
}

/// Detach debugger from current process.
int adbg_debugger_detach(adbg_process_t *tracee) {
	if (tracee == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (tracee.creation != AdbgCreation.attached)
		return adbg_oops(AdbgError.debuggerInvalidAction);
	
	tracee.creation = AdbgCreation.unloaded;
	tracee.status = AdbgProcStatus.unloaded;
	scope(exit) free(tracee);
	
version (Windows) {
	if (DebugActiveProcessStop(tracee.pid) == FALSE)
		return adbg_oops(AdbgError.os);
} else version (Posix) {
	if (ptrace(PT_DETACH, tracee.pid, null, null) < 0)
		return adbg_oops(AdbgError.os);
}
	return 0;
}

//TODO: Check process debugged remotely
//bool adbg_process_debugged(int pid) {

/// Get the debugger's current state.
/// Returns: Debugger status.
AdbgProcStatus adbg_process_status(adbg_process_t *tracee) pure {
	if (tracee == null) return AdbgProcStatus.unknown;
	return tracee.status;
}

/// Wait for a debug event.
///
/// Continues execution of the process until a new debug event occurs. When an
/// exception occurs, the exception_t structure is populated with debugging information.
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
int adbg_debugger_wait(adbg_process_t *tracee,
	void function(adbg_process_t*, int, void*) userfunc) {
	if (tracee == null || userfunc == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (tracee.creation == AdbgCreation.unloaded)
		return adbg_oops(AdbgError.debuggerUnattached);
	
	//TODO: Urgent: The process instance should ideally not be modified
	//      Changing process information (e.g., PID) can in turn
	//      be bad news for other API functions (e.g., breakpoints).
	//
	//      Children processes should be allocated and attached to exception
	//      (via adbg_exception_get_process?).
	
	adbg_exception_t exception = void;
	
version (Windows) {
	DEBUG_EVENT de = void;
L_DEBUG_LOOP:
	// Something bad happened
	if (WaitForDebugEvent(&de, INFINITE) == FALSE) {
		tracee.status = AdbgProcStatus.unloaded;
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
	
	// Fixes access to debugger, thread context functions.
	// Especially when attaching, but should be standard with spawned-in processes too.
	tracee.tid  = de.dwThreadId;
	tracee.htid = OpenThread(
		THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
		FALSE, de.dwThreadId);
	tracee.status = AdbgProcStatus.paused;
	adbg_exception_translate(&exception, &de, null);
} else version (Posix) {
	int wstatus = void;
	int stopsig = void;
L_DEBUG_LOOP:
	tracee.pid = waitpid(-1, &wstatus, 0);
	
	// Something bad happened
	if (tracee.pid < 0) {
		tracee.status = AdbgProcStatus.unloaded;
		tracee.creation = AdbgCreation.unloaded;
		return adbg_oops(AdbgError.crt);
	}
	
	version (Trace) trace("wstatus=%08x", wstatus);
	
	// If exited or killed by signal, it's gone.
	if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus))
		goto L_UNLOADED;
	
	// Skip glibc "continue" signals.
	version (CRuntime_Glibc)
	if (WIFCONTINUED(wstatus))
		goto L_DEBUG_LOOP;
	
	//TODO: Check waitpid status for BSDs
	// Bits  Description (Linux)
	// 6:0   Signo that caused child to exit
	//       0x7f if child stopped/continued
	//       or zero if child exited without signal
	//  7    Core dumped
	// 15:8  exit value (or returned main value)
	//       or signal that cause child to stop/continue
	stopsig = WEXITSTATUS(wstatus);
	
	// Get fault address
	switch (stopsig) {
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
	
	tracee.status = AdbgProcStatus.paused;
	adbg_exception_translate(&exception, &tracee.pid, &stopsig);
}
	
	userfunc(tracee, AdbgEvent.exception, &exception);
	return 0;

L_UNLOADED:
	tracee.status = AdbgProcStatus.unloaded;
	tracee.creation = AdbgCreation.unloaded;
	return 0;
}


int adbg_debugger_stop(adbg_process_t *tracee) {
	if (tracee == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (tracee.creation == AdbgCreation.unloaded)
		return adbg_oops(AdbgError.debuggerUnattached);
	
	return tracee.creation == AdbgCreation.attached ?
		adbg_debugger_detach(tracee) : adbg_debugger_terminate(tracee);
}


int adbg_debugger_terminate(adbg_process_t *tracee) {
	if (tracee == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (tracee.creation == AdbgCreation.unloaded)
		return adbg_oops(AdbgError.debuggerUnattached);
	
	tracee.status = AdbgProcStatus.unloaded; // exited in any case
	tracee.creation = AdbgCreation.unloaded;
	scope(exit) free(tracee);
	
version (Windows) {
	if (ContinueDebugEvent(tracee.pid, tracee.tid, DBG_TERMINATE_PROCESS) == FALSE)
		return adbg_oops(AdbgError.os);
} else {
	if (kill(tracee.pid, SIGKILL) < 0) // PT_KILL is deprecated
		return adbg_oops(AdbgError.os);
}
	
	return 0;
}


int adbg_debugger_continue(adbg_process_t *tracee) {
	if (tracee == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (tracee.creation == AdbgCreation.unloaded)
		return adbg_oops(AdbgError.debuggerUnattached);
	if (tracee.status != AdbgProcStatus.paused)
		return 0;
	
	tracee.status = AdbgProcStatus.running;
	
version (Windows) {
	if (ContinueDebugEvent(tracee.pid, tracee.tid, DBG_CONTINUE) == FALSE) {
		tracee.status = AdbgProcStatus.unknown;
		return adbg_oops(AdbgError.os);
	}
} else {
	if (ptrace(PT_CONT, tracee.pid, null, null) < 0) {
		tracee.status = AdbgProcStatus.unknown;
		return adbg_oops(AdbgError.os);
	}
}
	
	return 0;
}

/// Performs an instruction step for the debuggee process.
/// Params: tracee = Process being debugged.
/// Returns: Error code.
int adbg_debugger_stepi(adbg_process_t *tracee) {
	if (tracee == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (tracee.creation == AdbgCreation.unloaded)
		return adbg_oops(AdbgError.debuggerUnattached);
	
version (Windows) {
	enum EFLAGS_TF = 0x100;
	
	// Enable single-stepping via Trap flag
	version (Win64) 
	if (tracee.wow64) {
		WOW64_CONTEXT winctxwow64 = void;
		winctxwow64.ContextFlags = CONTEXT_CONTROL;
		Wow64GetThreadContext(tracee.htid, &winctxwow64);
		winctxwow64.EFlags |= EFLAGS_TF;
		Wow64SetThreadContext(tracee.htid, &winctxwow64);
		FlushInstructionCache(tracee.hpid, null, 0);
		
		return adbg_debugger_continue(tracee);
	}
	
	// X86, AMD64
	CONTEXT winctx = void;
	winctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(tracee.htid, cast(LPCONTEXT)&winctx);
	winctx.EFlags |= EFLAGS_TF;
	SetThreadContext(tracee.htid, cast(LPCONTEXT)&winctx);
	FlushInstructionCache(tracee.hpid, null, 0);
	
	return adbg_debugger_continue(tracee);
} else {
	if (ptrace(PT_SINGLESTEP, tracee.pid, null, null) < 0) {
		tracee.status = AdbgProcStatus.idle;
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

//TODO: Last parameter could be an enum
//      AdbgProcNameInclude
//      - program basename (only)
//      - program full path
//      - program full path and command-line arguments
/// Get the process file path.
///
/// The string is null-terminated.
/// Bug: On Windows, GetModuleFileNameA causes a crash with MSVC malloc buffers.
/// Params:
/// 	pid = Process ID.
/// 	buffer = Buffer.
/// 	bufsize = Size of the buffer.
/// 	absolute = Request for absolute path; Otherwise base filename.
/// Returns: String length; Or zero on error.
size_t adbg_process_get_name(int pid, char *buffer, size_t bufsize, bool absolute) {
	version (Trace)
		trace("pid=%d buffer=%p bufsize=%zd base=%d", pid, buffer, bufsize, absolute);
	
	if (pid <= 0 || buffer == null || bufsize == 0) {
		adbg_oops(AdbgError.invalidArgument);
		return 0;
	}
	
version (Windows) {
	if (__dynlib_psapi_load()) // Sets error
		return 0;
	
	// Get process handle
	HANDLE procHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (procHandle == null) {
		adbg_oops(AdbgError.os);
		return 0;
	}
	scope(exit) CloseHandle(procHandle);
	
	//TODO: Try with the following?
	//      1. 
	//      GetProcessImageFileNameA + GetModuleHandleA
	//      + GetModuleBaseNameA <- base=true
	//      + GetModuleFileNameA <- base=false
	//      2. 
	//      GetProcessImageFileNameA
	//      + cut string manually <- base=true
	//      + PathGetDriveNumberA <- base=false
	
	DWORD needed = void;
	DWORD pidlist = void;
	if (EnumProcesses(&pidlist, DWORD.sizeof, &needed) == FALSE) {
		adbg_oops(AdbgError.os);
		return 0;
	}
	HMODULE hmod = void;
	if (absolute == false && EnumProcessModules(procHandle, &hmod, hmod.sizeof, &needed)) {
		adbg_oops(AdbgError.os);
		return 0;
	}
	
	// NOTE: GetModuleFileNameA requires module handle
	// NOTE: GetProcessImageFileNameA returns native path (not Win32 path)
	// NOTE: QueryFullProcessImageNameA is Vista and later
	// Get filename or basename
	uint bf = cast(uint)bufsize;
	uint r = absolute ?
		GetModuleFileNameA(hmod, buffer, bf) :
		GetModuleBaseNameA(procHandle, hmod, buffer, bf);
	buffer[r] = 0;
	if (r == 0) adbg_oops(AdbgError.os);
	return r;
} else version (linux) {
	enum PATHBFSZ = 32; // int.min is "-2147483648", 11 chars
	char[PATHBFSZ] pathbuf = void; // Path buffer
	
	// NOTE: readlink does not append null, this is done later
	snprintf(pathbuf.ptr, PATHBFSZ, "/proc/%d/exe", pid);
	ssize_t r = readlink(pathbuf.ptr, buffer, bufsize);
	
	// NOTE: cmdline arguments end with one null byte, and an extra null byte at the very end
	/*snprintf(pathbuf.ptr, PATHBFSZ, "/proc/%d/cmdline", pid);
	int cmdlinefd = open(pathbuf.ptr, O_RDONLY);
	if (cmdlinefd > 0) {
		r = read(cmdlinefd, buffer, bufsize);
		if (r <= 0) {
			adbg_oops(AdbgError.os);
			return 0;
		}
		buffer[r] = 0;
		close(cmdlinefd);
	}*/
	
	// Error reading /cmdline, retry with /comm
	// e.g., kthread
	// NOTE: comm strings can only be up to 16 characters
	if (r <= 0) {
		snprintf(pathbuf.ptr, PATHBFSZ, "/proc/%d/comm", pid);
		int commfd = open(pathbuf.ptr, O_RDONLY);
		if (commfd == -1) {
			adbg_oops(AdbgError.os);
			return 0;
		}
		scope(exit) close(commfd);
		
		// Read into buffer
		size_t rdsize = min(bufsize, 16); // Can only read up to 16 chars
		r = read(commfd, buffer, rdsize);
		if (r < 0) {
			adbg_oops(AdbgError.os);
			return 0;
		}
		buffer[r - 1] = 0; // Delete newline
		
		// Return now since comm values aren't worth path manipulation
		return r;
	}
	
	// Base path requested and got absolute instead
	// e.g. /usr/bin/cat to cat
	if (absolute == false && buffer[0] == '/') {
		// Find the last occurance of '/'
		char *last = strrchr(buffer, '/');
		if (last == null) {
			adbg_oops(AdbgError.assertion);
			return 0;
		}
		++last; // We're looking past '/'
		
		// Write into buffer
		for (r = 0; last[r]; ++r)
			buffer[r] = last[r];
	} 
	//TODO: Name is not absolute, search in PATH
	/* else if (absolute && buffer[0] != '/') {
		
	}*/

	buffer[r < bufsize ? r : r - 1] = 0;
	return r;
} else {
	adbg_oops(AdbgError.unimplemented);
	return 0;
}
}
unittest {
	//TODO: Test one character buffers
}

/// Get the current runtime machine platform.
///
/// This is useful when the debugger is dealing with a process running
/// under a subsystem such as WoW or lib32-on-linux64 programs.
/// Params: tracee = Debuggee process.
/// Returns: Machine platform.
AdbgMachine adbg_process_get_machine(adbg_process_t *tracee) {
	if (tracee == null)
		return AdbgMachine.unknown;
	
		//TODO: There's probably a way to remotely check this
		//      Windows: IsWow64Process/IsWow64Process2 with process handle
	version (Win64) {
		if (tracee.wow64) return AdbgMachine.x86;
	}
	
	return adbg_machine_default();
}

/// Get a list of process IDs running.
///
/// This function allocates memory. The list passed will need to be closed
/// using `free(3)`. To get the name of a process, call `adbg_process_get_name`.
///
/// Windows: The list is populated by system order using `EnumProcesses`.
/// Linux: The list is populated by process ID using procfs.
///
/// Params:
/// 	count = Process list structure instance.
/// 	... = Options, terminated by 0.
/// Returns: List of PIDs; Or null on error.
int* adbg_process_list(size_t *count, ...) {
	if (count == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	
	enum CAPACITY = 5_000; // * 4 = ~20K
	
	int *plist = void;
	
version (Windows) {
	if (__dynlib_psapi_load())
		return null;
	
	// Allocate temp PID buffer
	uint hsize = cast(uint)(CAPACITY * HMODULE.sizeof);
	DWORD *pidlist = cast(DWORD*)malloc(hsize);
	if (pidlist == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	scope(exit) free(pidlist);
	
	// Enumerate processes
	// Note that "needed" is reusable after getting the count
	//TODO: Adjust temporary buffer after calling this
	DWORD needed = void;
	if (EnumProcesses(pidlist, hsize, &needed) == FALSE) {
		adbg_oops(AdbgError.os);
		return null;
	}
	DWORD proccount = needed / DWORD.sizeof;
	
	plist = cast(int*)malloc(proccount * int.sizeof);
	if (plist == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	// Skip PID 0 (idle) and 4 (system)
	enum SKIP = 2;
	memcpy(plist, pidlist + SKIP, (proccount * DWORD.sizeof) - (SKIP * DWORD.sizeof));
	*count = proccount - SKIP;
} else version (linux) {
	// Count amount of entries to allocate
	size_t cnt; // minimum amount of entries
	DIR *procfd = opendir("/proc");
	if (procfd == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	scope (exit) closedir(procfd);
	
	for (dirent *procent = void; (procent = readdir(procfd)) != null;) {
		// If not directory starting with a digit, skip entry
		if (procent.d_type != DT_DIR)
			continue;
		if (isdigit(procent.d_name[0]) == 0)
			continue;
		
		++cnt;
	}
	
	// Allocate list
	plist = cast(int*)malloc(cnt * int.sizeof);
	if (plist == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	*count = cnt;
	
	// Populate list
	rewinddir(procfd);
	size_t i;
	for (dirent *procent = void; (procent = readdir(procfd)) != null;) {
		// If not directory starting with a digit, skip entry
		if (procent.d_type != DT_DIR)
			continue;
		if (isdigit(procent.d_name[0]) == 0)
			continue;
		
		// Set PID
		plist[i++] = atoi(procent.d_name.ptr);
	}
}

	return plist;
}

//TODO: Deprecate process enumeration routines

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
	// NOTE: KEEP THIS FUNCTION AROUND AND DO NOT TOUCH IT
	//
	//       This function *must* be kept around until I understand why both
	//       GetModuleBaseNameA and GetModuleFileNameA work here but not
	//       when used separaterely from EnumProcesses/EnumProcessModules.
	//
	//       Also, on Linux, this somehow gets the comm value, while
	//       the new function does not.
	
	if (list == null)
		return adbg_oops(AdbgError.invalidArgument);
	
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
			return adbg_oops(AdbgError.invalidValue);
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
			L_NONAME:
				strcpy(proc.name.ptr, "<unknown>");
				proc.hpid = null;
			}
			
			CloseHandle(procHandle);
		}
		list.count = count;
		return 0;
	} else version (linux) {
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
