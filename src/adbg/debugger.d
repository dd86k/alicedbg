/// Provides debugging API.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.debugger;

// TODO: adbg_debugger_spawn: Get/set default child stack size
// TODO: High-level disassembly functions (e.g., from exception, etc.)

/*
version (linux) {
	version (CRuntime_Glibc)
		version = USE_CLONE;
}
*/

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
	import adbg.machines;
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
	
	version (USE_CLONE)
		import adbg.include.posix.mann;
}

extern (C):

/// Debugging events
enum AdbgEvent {
	exception,
	processExit,
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
	
	// Add argv is specified, and first item is set,
	// we'll have to cram it into args
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
	// CREATE_DEFAULT_ERROR_MODE
	//   The new process should not inherit the error mode of the caller.
	DWORD flags = DEBUG_PROCESS | CREATE_DEFAULT_ERROR_MODE;
	if (options & OPT_DEBUG_ALL) flags |= DEBUG_ONLY_THIS_PROCESS;
	
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
		adbg_oops(AdbgError.os);
		adbg_process_free(proc);
		return null;
	}
	proc.hpid = pi.hProcess;
	proc.htid = pi.hThread;
	proc.pid = pi.dwProcessId;
	proc.tid = pi.dwThreadId;
	
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
	if (argv) while (argv[argc]) ++argc;
	version(Trace) trace("argc=%d", argc);
	proc.argv = cast(char**)malloc((argc + 2) * size_t.sizeof);
	if (proc.argv == null) {
		version(Trace) trace("mmap=%s", strerror(errno));
		adbg_oops(AdbgError.os);
		adbg_process_free(proc);
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
/// Params: proc = Process instance being debugged.
/// Returns: Error code.
int adbg_debugger_detach(adbg_process_t *proc) {
	if (proc == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (proc.creation != AdbgCreation.attached)
		return adbg_oops(AdbgError.debuggerInvalidAction);
	
	proc.creation = AdbgCreation.unloaded;
	proc.status = AdbgProcStatus.unloaded;
	
version (Windows) {
	if (DebugActiveProcessStop(proc.pid) == FALSE)
		return adbg_oops(AdbgError.os);
} else version (Posix) {
	if (ptrace(PT_DETACH, proc.pid, null, 0) < 0)
		return adbg_oops(AdbgError.os);
}
	return 0;
}

private struct adbg_debugger_event_t {
	AdbgEvent type;
	union {
		adbg_exception_t exception;
		int exitcode;
	}
}

adbg_exception_t* adbg_debugger_event_exception(void *edata) {
	if (edata == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	adbg_debugger_event_t *event = cast(adbg_debugger_event_t*)edata;
	if (event.type != AdbgEvent.exception) {
		adbg_oops(AdbgError.invalidValue);
		return null;
	}
	
	return &event.exception;
}

int* adbg_debugger_event_process_exitcode(void *edata) {
	if (edata == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	adbg_debugger_event_t *event = cast(adbg_debugger_event_t*)edata;
	if (event.type != AdbgEvent.processExit) {
		adbg_oops(AdbgError.invalidValue);
		return null;
	}
	
	return &event.exitcode;
}

/// Continue execution of the process until a new debug event occurs.
///
/// This call is blocking.
///
/// It is highly recommended to use the callback's process instance for
/// debugging services, and to not call this function within the callback.
///
/// After the callback, this function returns.
///
/// Windows: Uses WaitForDebugEvent.
/// Posix: Uses waitpid(2) and ptrace(2), filters SIGCONT out.
/// Params:
/// 	proc = Tracee instance.
/// 	ufunc = User function callback on event.
/// 	udata = User data passed to callback. Can be used to identify requests, for example.
/// Returns: Error code.
int adbg_debugger_wait(adbg_process_t *proc,
	void function(adbg_process_t*, int, void*, void*) ufunc, void *udata) {
	version(Trace) trace("proc=%p ufunc=%p udata=%p", proc, ufunc, udata);
	
	if (proc == null || ufunc == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (proc.creation == AdbgCreation.unloaded)
		return adbg_oops(AdbgError.debuggerUnattached);
	
	adbg_process_t tracee = void;
	adbg_debugger_event_t event = void;
	
	memset(&tracee, 0, adbg_process_t.sizeof);
	tracee.creation = proc.creation;
	
version (Windows) {
	DEBUG_EVENT de = void;
Lwait:
	// Something bad happened
	if (WaitForDebugEvent(&de, INFINITE) == FALSE) {
		tracee.status = AdbgProcStatus.unloaded;
		return adbg_oops(AdbgError.os);
	}
	
	version(Trace) trace("EventCode=%#x", de.dwDebugEventCode);
	
	// Filter events
	switch (de.dwDebugEventCode) {
	case EXCEPTION_DEBUG_EVENT:
		event.type = AdbgEvent.exception;
		tracee.status = AdbgProcStatus.paused;
		adbg_exception_translate(&event.exception, &de, null);
		break;
	case EXIT_PROCESS_DEBUG_EVENT:
		event.type = AdbgEvent.processExit;
		tracee.status = AdbgProcStatus.unknown;
		event.exitcode = de.ExitProcess.dwExitCode;
		break;
	/*case CREATE_THREAD_DEBUG_EVENT:
	case CREATE_PROCESS_DEBUG_EVENT:
	case EXIT_THREAD_DEBUG_EVENT:
	case LOAD_DLL_DEBUG_EVENT:
	case UNLOAD_DLL_DEBUG_EVENT:
	case OUTPUT_DEBUG_STRING_EVENT:
	case RIP_EVENT:
		goto default;*/
	default:
		ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
		goto Lwait;
	}
	
	tracee.pid = de.dwProcessId;
	tracee.tid = de.dwThreadId;
	
	// TODO: Get rid of hack to help multiprocess support
	//       By opening/closing process+thread handles per debugger function that need it:
	//       - Help with leaking handles
	//       - Permissions, since each OS function need different permissions
	// HACK: To have access to debugger API
	tracee.hpid = proc.hpid;
	tracee.htid = proc.htid;
	
} else version (Posix) {
	int wstatus = void;
Lwait:
	tracee.pid = waitpid(-1, &wstatus, 0);
	
	// Something terrible happened
	if (tracee.pid < 0)
		return adbg_oops(AdbgError.crt);
	
	version(Trace) trace("wstatus=%#x", wstatus);
	
	if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) { // Process exited or killed
		event.type = AdbgEvent.processExit;
		event.exitcode = WTERMSIG(wstatus);
	} else if (WIFSTOPPED(wstatus)) { // Process stopped by signal
		event.type = AdbgEvent.exception;
		tracee.status = AdbgProcStatus.paused;
		int sig = WSTOPSIG(wstatus);
		adbg_exception_translate(&event.exception, &tracee.pid, &sig);
	/*
	} else if (WIFCONTINUED(wstatus)) { // Process continues, ignore these
		goto Lwait;
	*/
	} else {
		version (Trace) if (!WIFCONTINUED(wstatus)) trace("Unknown status code");
		goto Lwait;
	}
} else static assert(0, "Implement adbg_debugger_wait");

	ufunc(&tracee, event.type, &event, udata);
	return 0;
}

/// Disconnect and terminate the debuggee process.
/// Params: proc = Process.
/// Returns: Error code.
int adbg_debugger_terminate(adbg_process_t *proc) {
	if (proc == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (proc.creation == AdbgCreation.unloaded || proc.pid == 0)
		return adbg_oops(AdbgError.debuggerUnattached);
	
version (Windows) {
	// NOTE: ContinueDebugEvent
	//       Before using TerminateProcess,
	//       ContinueDebugEvent(pid, tid, DBG_TERMINATE_PROCESS)
	//       was used instead. I forgot where I saw that example. MSDN does not feature it.
	if (TerminateProcess(proc.hpid, DBG_TERMINATE_PROCESS) == FALSE)
		return adbg_oops(AdbgError.os);
} else version (Posix) {
	if (kill(proc.pid, SIGKILL) < 0) // PT_KILL is deprecated on Linux
		return adbg_oops(AdbgError.os);
} else static assert(0, "Implement adbg_debugger_terminate");

	proc.status = AdbgProcStatus.unknown;
	proc.creation = AdbgCreation.unloaded;
	return 0;
}

/// Make the debuggee process continue from its currently stopped state.
/// Params: proc = Process.
/// Returns: Error code.
int adbg_debugger_continue(adbg_process_t *proc) {
	version(Trace) trace("proc=%p", proc);
	if (proc == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	version(Trace) trace("pid=%d state=%d", proc.pid, proc.status);
	if (proc.creation == AdbgCreation.unloaded)
		return adbg_oops(AdbgError.debuggerUnattached);
	
	switch (proc.status) with (AdbgProcStatus) {
	case loaded, paused: break;
	default: return adbg_oops(AdbgError.debuggerUnpaused);
	}
	
version (Windows) {
	if (ContinueDebugEvent(proc.pid, proc.tid, DBG_CONTINUE) == FALSE) {
		proc.status = AdbgProcStatus.unknown;
		return adbg_oops(AdbgError.os);
	}
} else version (linux) {
	if (ptrace(PT_CONT, proc.pid, null, null) < 0) {
		proc.status = AdbgProcStatus.unknown;
		return adbg_oops(AdbgError.os);
	}
} else version (Posix) {
	if (ptrace(PT_CONTINUE, proc.pid, null, 0) < 0) {
		proc.status = AdbgProcStatus.unknown;
		return adbg_oops(AdbgError.os);
	}
} else static assert(0, "Implement adbg_debugger_continue");
	
	proc.status = AdbgProcStatus.running;
	return 0;
}

/// Performs an instruction step for the debuggee process.
/// Params: proc = Process being debugged.
/// Returns: Error code.
int adbg_debugger_stepi(adbg_process_t *proc) {
	if (proc == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (proc.creation == AdbgCreation.unloaded)
		return adbg_oops(AdbgError.debuggerUnattached);
	
version (Windows) {
	enum EFLAGS_TF = 0x100;
	
	// Enable single-stepping via Trap flag
	version (Win64) 
	if (adbg_process_machine(proc) == AdbgMachine.i386) {
		WOW64_CONTEXT winctxwow64 = void;
		winctxwow64.ContextFlags = CONTEXT_CONTROL;
		Wow64GetThreadContext(proc.htid, &winctxwow64);
		winctxwow64.EFlags |= EFLAGS_TF;
		Wow64SetThreadContext(proc.htid, &winctxwow64);
		FlushInstructionCache(proc.hpid, null, 0);
		
		return adbg_debugger_continue(proc);
	}
	
	// X86, AMD64
	CONTEXT winctx = void;
	winctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(proc.htid, cast(LPCONTEXT)&winctx);
	winctx.EFlags |= EFLAGS_TF;
	SetThreadContext(proc.htid, cast(LPCONTEXT)&winctx);
	FlushInstructionCache(proc.hpid, null, 0);
	
	return adbg_debugger_continue(proc);
} else version (linux) {
	if (ptrace(PT_SINGLESTEP, proc.pid, null, null) < 0) {
		proc.status = AdbgProcStatus.unknown;
		return adbg_oops(AdbgError.os);
	}
	
	return 0;
} else version (Posix) {
	if (ptrace(PT_STEP, proc.pid, null, 0) < 0) {
		proc.status = AdbgProcStatus.unknown;
		return adbg_oops(AdbgError.os);
	}
	
	return 0;
} else {
	return adbg_oops(AdbgError.unimplemented);
}
}