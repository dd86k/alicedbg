/// Provides debugging API.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.debugger;

// TODO: adbg_debugger_spawn: Get default child stack size

public import adbg.process.base;
import adbg.process.exception;
import adbg.error;
import adbg.include.c.stdarg;
import adbg.include.c.stdlib;
import core.stdc.string;
import adbg.utils.strings;

version (Windows) {
	import adbg.include.windows.wow64apiset;
	import adbg.include.windows.psapi_dyn;
	import adbg.include.windows.winnt;
	import core.sys.windows.winbase;
} else version (Posix) {
	import adbg.include.posix.ptrace;
	import adbg.include.posix.unistd;
	import adbg.include.posix.sys.wait;
	import adbg.utils.math;
	import core.stdc.ctype : isdigit;
	import core.stdc.errno;
	import core.sys.posix.fcntl;
	import core.sys.posix.dirent;
	import core.sys.posix.libgen : basename;
	import adbg.include.c.stdio;  // snprintf;
	import adbg.platform : ADBG_CHILD_STACK_SIZE;
}

version (linux) {
	//version (CRuntime_Glibc)
		//version = USE_CLONE;
}

extern (C):

/// Debugging events
enum AdbgEvent {
	exception,
}

version (Posix)
private struct __adbg_child_t {
	const(char) **argv, envp;
	const(char) *dir;
}
//TODO: Stream redirection options (FILE* and os handle options)
//TODO: "start suspended" option
//      Windows: CREATE_SUSPENDED
//      Posix:
//TODO: Stack size in KiB
//      Default should still be 8 MiB (Windows and Linux)
/// Options for adbg_spawn.
enum AdbgSpawnOpt {
	/// Pass args line to tracee.
	/// Type: const(char)*
	/// Default: null
	args	= 1,
	/// Pass argv lines to tracee. Vector must terminate with NULL.
	/// Type: const(char)**
	/// Default: null
	argv	= 2,
	/// Set start directory. String must terminate with NULL.
	/// Type: const(char)*
	/// Default: Current directory of debugger.
	directory	= 3,
	/// Pass environment table to tracee. Vector must terminate with NULL.
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
	// Temporary until reworked
	/*case AdbgSpawnOpt.args:
		args = va_arg!(const(char)*)(list);
		version (Trace) trace("args=%p", args);
		goto LOPT;*/
	case AdbgSpawnOpt.argv:
		argv = va_arg!(const(char)**)(list);
		version (Trace) trace("argv=%p", argv);
		goto LOPT;
	// Temporary until implemented
	case AdbgSpawnOpt.directory:
		dir = va_arg!(const(char)*)(list);
		version (Trace) trace("dir=%p", dir);
		goto LOPT;
	// Temporary until reworked
	/*case AdbgSpawnOpt.environment:
		envp = va_arg!(const(char)**)(list);
		version (Trace) trace("envp=%p", envp);
		goto LOPT;*/
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
	// NOTE: lpCommandLine is maximum 32,767 bytes including null Unicode character
	// NOTE: When given arguments, both lpApplicationName and lpCommandLine
	//       need to be filled. If the former is null, this acts as a shell, and
	//       Windows will search for the external command, which is unwanted.
	
	// Add argv is specified, we'll have to cram it into args
	if (argv && *argv) {
		// Get minimum total buffer size required
		int argc;
		size_t commlen = strlen(path);
		size_t argslen;
		while (argv[argc])
			argslen += strlen(argv[argc++]);
		
		// Allocate argument line space
		size_t minlen = commlen + 2 + argslen + argc + 1; // + quotes and spaces
		proc.args = cast(char*)malloc(minlen);
		if (proc.args == null) {
			adbg_process_free(proc);
			adbg_oops(AdbgError.crt);
			return null;
		}
		
		// Place path into argv[0] with quotes
		size_t i;
		proc.args[i++] = '"';
		memcpy(proc.args + i, path, commlen); i += commlen;
		proc.args[i++] = '"';
		proc.args[i++] = ' ';
		
		// Flatten arguments
		int cl = cast(int)minlen - cast(int)i; // Buffer space left
		if (cl <= 0) {
			adbg_process_free(proc);
			adbg_oops(AdbgError.assertion);
			return null;
		}
		size_t o = adbg_strings_flatten(proc.args + i, cl, argc, argv, 1);
		if (o == 0) {
			adbg_process_free(proc);
			adbg_oops(AdbgError.assertion);
			return null;
		}
		version(Trace) trace("args='%s'", proc.args);
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
	
	// Create process
	if (CreateProcessA(
		path,	// lpApplicationName
		proc.args,	// lpCommandLine
		null,	// lpProcessAttributes
		null,	// lpThreadAttributes
		FALSE,	// bInheritHandles
		flags,	// dwCreationFlags
		envp,	// lpEnvironment
		dir,	// lpCurrentDirectory
		&si, &pi) == FALSE) {
		adbg_process_free(proc);
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
	version (Win64)
	if (IsWow64Process(proc.hpid, &proc.wow64) == FALSE) {
		adbg_process_free(proc);
		adbg_oops(AdbgError.os);
		return null;
	}
	
	proc.status = AdbgProcStatus.standby;
	proc.creation = AdbgCreation.spawned;
	return proc;
} else version (Posix) {
	// NOTE: Don't remember this check, but I think it was because of
	//       an ambiguous error message
	// Verify if file exists and we has access to it
	stat_t st = void;
	if (stat(path, &st) < 0) {
		adbg_process_free(proc);
		adbg_oops(AdbgError.os);
		return null;
	}
	
	// Allocate arguments, include space for program and null terminator
	int argc;
	while (argv[argc]) ++argc;
	version(Trace) trace("argc=%d", argc);
	proc.argv = cast(char**)malloc((argc + 2) * size_t.sizeof);
	if (proc.argv == null) {
		version(Trace) trace("mmap=%s", strerror(errno));
		adbg_process_free(proc);
		adbg_oops(AdbgError.os);
		return null;
	}
	proc.argv[0] = cast(char*)path;
	if (argc && argv && *argv)
		memcpy(proc.argv + 1, argv, argc * size_t.sizeof);
	proc.argv[argc + 1] = null;
	
version (USE_CLONE) { // clone(2)
	void *stack = mmap(null, ADBG_CHILD_STACK_SIZE,
		PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
		-1, 0);
	if (stack == MAP_FAILED) {
		adbg_process_free(proc);
		adbg_oops(AdbgError.os);
		return null;
	}
	// Assume stack grows downward
	void *stacktop = stack + ADBG_CHILD_STACK_SIZE;
	
	// Clone
	__adbg_child_t chld = void;
	chld.argv = cast(const(char)**)proc.argv;
	chld.envp = envp;
	chld.dir  = dir;
	proc.pid = clone(&__adbg_exec_child, stacktop, CLONE_PTRACE | CLONE_VFORK, &chld);
	if (proc.pid < 0) {
		adbg_process_free(proc);
		adbg_oops(AdbgError.os);
		return null;
	}
} else { // fork(2)
	switch (proc.pid = fork()) {
	case -1: // Error
		version(Trace) trace("fork=%s", strerror(errno));
		adbg_process_free(proc);
		adbg_oops(AdbgError.os);
		return null;
	case 0: // New child process
		version(Trace) for (int i; i < argc + 2; ++i)
			trace("argv[%d]=%s", i, proc.argv[i]);
		
		__adbg_child_t chld = void;
		chld.argv = cast(const(char)**)proc.argv;
		chld.envp = envp;
		chld.dir  = dir;
		__adbg_exec_child(&chld); // If returns at all, error
		adbg_process_free(proc);
		_exit(errno);
		return null; // Make compiler happy
	default: // This parent process
	} // switch(fork(2))
} // clone(2)/fork(2)
	
	proc.status = AdbgProcStatus.standby;
	proc.creation = AdbgCreation.spawned;
	return proc;
} else {
	adbg_oops(AdbgError.unimplemented);
	return null;
}
}

version (Posix)
private int __adbg_exec_child(void* arg) {
	__adbg_child_t *chld = cast(__adbg_child_t*)arg;
	
	// Baby, Please Trace Me
	version (Trace) trace("PT_TRACEME...");
version (linux) {
	if (ptrace(PT_TRACEME, 0, null, null) < 0) {
		version (Trace) trace("ptrace=%s", strerror(errno));
		goto Lexit;
	}
} else {
	if (ptrace(PT_TRACEME, 0, null, 0) < 0) {
		version (Trace) trace("ptrace=%s", strerror(errno));
		goto Lexit;
	}
}
	version (Trace) trace("done");
	
	// If start directory requested, change to it
	if (chld.dir && chdir(chld.dir) < 0) {
		version (Trace) trace("ptrace=%s", strerror(errno));
		goto Lexit;
	}
	
	// Start specified process
	version (Trace) trace("execve...");
	if (execve(*chld.argv, chld.argv, chld.envp) < 0) {
		version (Trace) trace("execve=%s", strerror(errno));
		goto Lexit;
	}
	version (Trace) trace("done");
	
Lexit:
	return -1;
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
		adbg_oops(AdbgError.os);
		free(proc);
		return null;
	}
	
	// Check if process already has an attached debugger
	BOOL dbgpresent = void;
	if (CheckRemoteDebuggerPresent(proc.hpid, &dbgpresent) == FALSE) {
		adbg_oops(AdbgError.os);
		adbg_process_free(proc);
		return null;
	}
	if (dbgpresent) {
		adbg_oops(AdbgError.debuggerPresent);
		adbg_process_free(proc);
		return null;
	}
	
	// Breaks into remote process and initiates break-in
	//TODO: try NtContinue for continue option
	if (DebugActiveProcess(proc.pid) == FALSE) {
		adbg_oops(AdbgError.os);
		adbg_process_free(proc);
		return null;
	}
	
	// DebugActiveProcess, by default, kills the process on exit.
	// Set exitkill unconditionalled
	// Default: on
	if (DebugSetProcessKillOnExit(options & OPT_EXITKILL) == FALSE) {
		adbg_oops(AdbgError.os);
		adbg_process_free(proc);
		return null;
	}
} else version (linux) {
	version (Trace) if (options & OPT_STOP) trace("Sending break...");
	if (ptrace(options & OPT_STOP ? PT_ATTACH : PT_SEIZE, pid, null, null) < 0) {
		adbg_oops(AdbgError.os);
		adbg_process_free(proc);
		return null;
	}
	
	// Set exitkill on if specified
	// Default: off
	if (options & OPT_EXITKILL && ptrace(PT_SETOPTIONS, pid, null, PT_O_EXITKILL) < 0) {
		adbg_oops(AdbgError.os);
		adbg_process_free(proc);
		return null;
	}
	
	proc.status = options & OPT_STOP ? AdbgProcStatus.paused : AdbgProcStatus.running;
	proc.pid = cast(pid_t)pid;
} else version (FreeBSD) {
	version (Trace) if (options & OPT_STOP) trace("Sending break...");
	if (ptrace(PT_ATTACH, pid, null, 0) < 0) {
		adbg_oops(AdbgError.os);
		adbg_process_free(proc);
		return null;
	}
	
	proc.status = AdbgProcStatus.paused;
	proc.pid = cast(pid_t)pid;
}
	
	proc.creation = AdbgCreation.attached;
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
	
version (Windows) {
	if (DebugActiveProcessStop(tracee.pid) == FALSE) {
		adbg_process_free(tracee);
		return adbg_oops(AdbgError.os);
	}
} else version (Posix) {
	if (ptrace(PT_DETACH, tracee.pid, null, 0) < 0) {
		adbg_process_free(tracee);
		return adbg_oops(AdbgError.os);
	}
}
	return 0;
}

/// Continue execution of the process until a new debug event occurs.
///
/// This call is blocking.
///
/// Windows: Uses WaitForDebugEvent.
/// Posix: Uses ptrace(2) and waitpid(2), filters SIGCONT out.
///
/// Params:
/// 	tracee = Tracee instance.
/// 	userfunc = User function callback on event.
/// 	udata = User data passed to callback. Can be used to identify requests, for example.
/// Returns: Error code.
int adbg_debugger_wait(adbg_process_t *tracee,
	void function(adbg_process_t *proc, int type, void *data, void *user) userfunc,
	void *udata) {
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
Lwait:
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
	case LOAD_DLL_DEBUG_EVENT:
	case UNLOAD_DLL_DEBUG_EVENT:
	case OUTPUT_DEBUG_STRING_EVENT:
	case RIP_EVENT:
		goto default;*/
	case EXIT_PROCESS_DEBUG_EVENT:
		goto Lexited;
	default:
		ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
		goto Lwait;
	}
	
	// Fixes access to debugger, thread context functions.
	// Especially when attaching, but should be standard with spawned-in processes too.
	// NOTE: There is no such 'CloseThread'
	tracee.tid  = de.dwThreadId;
	tracee.htid = OpenThread(
		THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
		FALSE, de.dwThreadId);
	tracee.status = AdbgProcStatus.paused;
	adbg_exception_translate(&exception, &de, null);
} else version (Posix) {
	int wstatus = void;
	int stopsig = void;
Lwait:
	tracee.pid = waitpid(-1, &wstatus, 0);
	
	version (Trace) trace("wstatus=%#x", wstatus);
	
	// Something bad happened
	if (tracee.pid < 0) {
		tracee.status = AdbgProcStatus.unloaded;
		tracee.creation = AdbgCreation.unloaded;
		return adbg_oops(AdbgError.crt);
	}
	
	// If exited or killed by signal, it's gone.
	if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus))
		goto Lexited;
	
	// Skip glibc "continue" signals.
	version (CRuntime_Glibc)
	if (WIFCONTINUED(wstatus))
		goto Lwait;
	
	// Bits  Description (Linux)
	// 6:0   Signo that caused child to exit
	//       0x7f if child stopped/continued
	//       or zero if child exited without signal
	//  7    Core dumped
	// 15:8  exit value (or returned main value)
	//       or signal that cause child to stop/continue
	stopsig = WEXITSTATUS(wstatus);
	
	// Get fault address
	version (linux) switch (stopsig) {
	case SIGCONT: goto Lwait;
	// NOTE: si_addr is NOT populated under ptrace for SIGTRAP
	//       - linux does not fill si_addr on a SIGTRAP from a ptrace event
	//         - see sigaction(2)
	//       - linux *only* fills user_regs_struct for "user area"
	//         - see arch/x86/include/asm/user_64.h
	//         - "ptrace does not yet supply these.  Someday...."
	//         - So yeah, debug registers and "fault_address" not filled
	//           - No access to ucontext_t from ptrace either
	//       - using EIP/RIP is NOT a good idea
	//         - IP ALWAYS point to NEXT instruction
	//         - First SIGTRAP does NOT contain int3
	//           - Windows does, though, and points to it
	//       - gdbserver and lldb never attempt to do such thing anyway
	//       - RIP-1 (x86) could *maybe* point to int3 or similar.
	//       - User area might have DR3, it does have "fault_address"
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
//	case SIGINT, SIGTERM, SIGABRT: //TODO: Killed?
	default:
		exception.fault_address = 0;
	}
	else exception.fault_address = 0;
	
	tracee.status = AdbgProcStatus.paused;
	adbg_exception_translate(&exception, &tracee.pid, &stopsig);
} else version (Posix) {
	int wstatus = void;
	int stopsig = void;
Lwait:
	tracee.pid = waitpid(-1, &wstatus, 0);
	
	version (Trace) trace("wstatus=%#x", wstatus);
	
	// Something bad happened
	if (tracee.pid < 0) {
		tracee.status = AdbgProcStatus.unloaded;
		tracee.creation = AdbgCreation.unloaded;
		return adbg_oops(AdbgError.crt);
	}
	
	// If exited or killed by signal, it's gone.
	if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus))
		goto Lexited;
	
	//TODO: Check waitpid status for BSDs
	stopsig = WEXITSTATUS(wstatus);

	exception.fault_address = 0;	
	tracee.status = AdbgProcStatus.paused;
	adbg_exception_translate(&exception, &tracee.pid, &stopsig);
}
	
	userfunc(tracee, AdbgEvent.exception, &exception, udata);
	return 0;

Lexited:
	tracee.status = AdbgProcStatus.unloaded;
	tracee.creation = AdbgCreation.unloaded;
	return 0;
}

/// Disconnect and terminate the debuggee process.
/// Params: tracee = Process.
/// Returns: Error code.
int adbg_debugger_terminate(adbg_process_t *tracee) {
	if (tracee == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (tracee.creation == AdbgCreation.unloaded || tracee.pid == 0)
		return adbg_oops(AdbgError.debuggerUnattached);
	
version (Windows) {
	// NOTE: ContinueDebugEvent
	//       Before using TerminateProcess,
	//       ContinueDebugEvent(pid, tid, DBG_TERMINATE_PROCESS)
	//       was used instead. I forgot where I saw that example. MSDN does not feature it.
	if (TerminateProcess(tracee.hpid, DBG_TERMINATE_PROCESS) == FALSE)
		return adbg_oops(AdbgError.os);
} else {
	if (kill(tracee.pid, SIGKILL) < 0) // PT_KILL is deprecated on Linux
		return adbg_oops(AdbgError.os);
}
	adbg_process_free(tracee);
	return 0;
}

/// Make the debuggee process continue from its currently stopped state.
/// Params: tracee = Process.
/// Returns: Error code.
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
} else version (linux) {
	if (ptrace(PT_CONT, tracee.pid, null, null) < 0) {
		tracee.status = AdbgProcStatus.unknown;
		return adbg_oops(AdbgError.os);
	}
} else {
	if (ptrace(PT_CONTINUE, tracee.pid, null, 0) < 0) {
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
} else version (linux) {
	if (ptrace(PT_SINGLESTEP, tracee.pid, null, null) < 0) {
		tracee.status = AdbgProcStatus.unknown;
		return adbg_oops(AdbgError.os);
	}
	
	return 0;
} else {
	if (ptrace(PT_STEP, tracee.pid, null, 0) < 0) {
		tracee.status = AdbgProcStatus.unknown;
		return adbg_oops(AdbgError.os);
	}
	
	return 0;
}
}