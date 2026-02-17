/// Provides debugging API.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.debugger;

// TODO: adbg_debugger_spawn: Get/set default child stack size

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
	// NOTE: winbase also imports ExceptionRecord, conflicting with our winnt module
	import core.sys.windows.winbase;
	import adbg.include.windows.wow64apiset;
	import adbg.include.windows.winnt;
	import adbg.include.windows.ntdll;
	import adbg.machines;
	
	version (X86)	version = WinTel;
	version (X86_64)	version = WinTel;
	
	version (Thumb)	version = WinArm;
	version (ARM)	version = WinArm;
	version (AArch64)	version = WinArm;
} else version (Posix) {
	import adbg.include.posix.ptrace;
	import adbg.include.posix.unistd;
	import adbg.include.posix.sys.wait;
	import adbg.include.posix.signal;
	import core.stdc.errno;
	import core.sys.posix.fcntl;
	
	version (USE_CLONE)
		import adbg.include.posix.mann;
	
	version (FreeBSD) {
		// pragma(mangle, "stat@FBSD_1.5")
		// leads to incorrect linked version
		extern (C) int stat(const scope char*, stat_t*);
	}
}

extern (C):

/// Debugging events
/// Used in both filtering and identification for wait function.
enum AdbgEvent {
	/// An exception occurred.
	exception,
	// A process was created.
	processCreated,
	/// A process exited, or has been killed.
	processExit,
	/// A process continued.
	processContinue,
	/// A process was paused or suspended.
	processPaused,
}

/// Represents a debugger event.
///
/// This fixes a few issues with the past wait model:
/// - Having callbacks on a blocking function makes the practice pretty pointless.
///   It only increased data management for user code (and Easy API), hiding nothing
///   of value because all of it was performed on a single thread.
///   Instead, callbacks have been brought to Easy API, since it actually features
///   a multithreaded message-based debugging loop.
/// - Process instance storage. Reduce reliance on hacks (bring those here instead!)
///   Instead, the affected process structure instance can comfortable live here,
///   versus having to check DIFFERENT handles for both debugger-related handles
///   and populating fake PIDs.
/// - Having the wait function accept an event instance retains flexibility in terms
///   of storage allocation, versus forcing it in global or TLS memory.
/// - "Getter" functions can be use to get structure instances from this without
///   punishing callbacks with specific types. They SHOULD be specific structures.
struct adbg_event_t {
	/// Event type.
	AdbgEvent type;
	
	adbg_process_t process;
	
	union {
	int exitcode;
	adbg_exception_t exception;
	}
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
//      Default should still be 8192 KiB (recent Windows and Linux defaults)
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
	/// Debug all sub processes that the target process spawns.
	/// Type: int
	/// Default: 0
	debugAll	= 10,
	/// Alias to debugAll
	debugChildren	= debugAll,
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
/// 	... = Zero-terminated list of options.
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
	
	const(char)  *oargs;
	const(char) **oargv;
	const(char)  *odir;
	const(char) **oenvp;
	int options;
Loption:
	switch (va_arg!int(list)) {
	case 0: break;
	// Temporary until reworked
	/*case AdbgSpawnOpt.args:
		args = va_arg!(const(char)*)(list);
		version (Trace) trace("args=%p", oargs);
		goto Loption;*/
	case AdbgSpawnOpt.argv:
		oargv = va_arg!(const(char)**)(list);
		version (Trace) trace("argv=%p", oargv);
		goto Loption;
	// Temporary until implemented
	case AdbgSpawnOpt.directory:
		odir = va_arg!(const(char)*)(list);
		version (Trace) trace("dir=%p", odir);
		goto Loption;
	// Temporary until reworked
	/*case AdbgSpawnOpt.environment:
		envp = va_arg!(const(char)**)(list);
		version (Trace) trace("envp=%p", envp);
		goto Loption;*/
	case AdbgSpawnOpt.debugAll:
		if (va_arg!(int)(list)) options |= OPT_DEBUG_ALL;
		goto Loption;
	default:
		adbg_oops(AdbgError.invalidOption);
		return null;
	}
	
	adbg_process_t *process = cast(adbg_process_t*)calloc(1, adbg_process_t.sizeof);
	if (process == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	version(Trace) trace("spawn path='%s' argv=%p dir='%s' o=%#x",
		path, oargv, odir, options);
	
version (Windows) {
	// Verify if file exists and we has access to it
	// This is to avoid a confusing error message ("Invalid descriptor")
	DWORD fflags = GetFileAttributesA(path);
	if (fflags == INVALID_FILE_ATTRIBUTES) {
		adbg_oops(AdbgError.os);
		free(process);
		return null;
	}
	if (fflags & FILE_ATTRIBUTE_DIRECTORY) {
		adbg_oops(AdbgError.debuggerNeedFile);
		free(process);
		return null;
	}
	
	// NOTE: CreateProcessW modifies lpCommandLine, copy it!
	// NOTE: lpCommandLine is maximum 32,767 bytes including null Unicode character
	// NOTE: When given arguments, both lpApplicationName and lpCommandLine
	//       need to be filled. If the former is null, this acts as a shell, and
	//       Windows will search for the external command, which is unwanted.
	
	// Add argv is specified, and first item is set,
	// we'll have to cram it into args
	if (oargv && *oargv) {
		// Get minimum total buffer size required
		int argc;
		size_t commlen = strlen(path);
		size_t argslen;
		while (oargv[argc])
			argslen += strlen(oargv[argc++]);
		
		// Allocate argument line space
		size_t minlen = commlen + 2 + argslen + argc + 1; // + quotes and spaces
		process.orig_args = cast(char*)malloc(minlen);
		if (process.orig_args == null) {
			adbg_process_free(process);
			adbg_oops(AdbgError.crt);
			return null;
		}
		
		// Place path into argv[0] with quotes
		size_t i;
		process.orig_args[i++] = '"';
		memcpy(process.orig_args + i, path, commlen); i += commlen;
		process.orig_args[i++] = '"';
		process.orig_args[i++] = ' ';
		
		// Flatten arguments
		int cl = cast(int)minlen - cast(int)i; // Buffer space left
		if (cl <= 0) {
			adbg_process_free(process);
			adbg_oops(AdbgError.assertion);
			return null;
		}
		size_t o = adbg_strings_flatten(process.orig_args + i, cl, argc, oargv, 1);
		if (o == 0) {
			adbg_process_free(process);
			adbg_oops(AdbgError.assertion);
			return null;
		}
		version(Trace) trace("args='%s'", process.orig_args);
	}
	
	// TODO: Parse envp
	
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
		process.orig_args,	// lpCommandLine
		null,	// lpProcessAttributes
		null,	// lpThreadAttributes
		FALSE,	// bInheritHandles
		flags,	// dwCreationFlags
		oenvp,	// lpEnvironment
		odir,	// lpCurrentDirectory
		&si, &pi) == FALSE) {
		adbg_oops(AdbgError.os);
		adbg_process_free(process);
		return null;
	}
	process.orig_handle = pi.hProcess;
	process.orig_pid = process.pid = pi.dwProcessId;
	
	process.status = ADBG_PROCESS_ATTACHED;
	process.option_timeout = INFINITE;
	return process;
} else version (Posix) {
	// Verify if file exists and we has access to it
	// This is to avoid a confusing error message
	stat_t st = void;
	if (stat(path, &st) < 0) {
		adbg_oops(AdbgError.os);
		adbg_process_free(process);
		return null;
	}
	if (st.st_mode & S_IFDIR) {
		adbg_oops(AdbgError.debuggerNeedFile);
		adbg_process_free(process);
		return null;
	}
	
	// Allocate arguments, include space for program and null terminator
	int argc;
	if (oargv) while (oargv[argc]) ++argc;
	version(Trace) trace("argc=%d", argc);
	process.orig_argv = cast(char**)malloc((argc + 2) * size_t.sizeof);
	if (process.orig_argv == null) {
		version(Trace) trace("mmap=%s", strerror(errno));
		adbg_oops(AdbgError.os);
		adbg_process_free(process);
		return null;
	}
	process.orig_argv[0] = cast(char*)path;
	if (argc && oargv && *oargv)
		memcpy(process.orig_argv + 1, oargv, argc * size_t.sizeof);
	process.orig_argv[argc + 1] = null;
	
version (USE_CLONE) { // Use clone(2) for subprocess
	// TODO: Assign stack to process for cleanup
	void *stack = mmap(null, ADBG_CHILD_STACK_SIZE,
		PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
		-1, 0);
	if (stack == MAP_FAILED) {
		adbg_process_free(process);
		adbg_oops(AdbgError.os);
		return null;
	}
	// Assume stack grows downward
	void *stacktop = stack + ADBG_CHILD_STACK_SIZE;
	
	// Clone
	__adbg_child_t chld = void;
	chld.argv = cast(const(char)**)process.argv;
	chld.envp = envp;
	chld.dir  = dir;
	process.orig_pid =
		process.pid = clone(&__adbg_exec_child, stacktop, CLONE_PTRACE | CLONE_VFORK, &chld);
	if (process.pid < 0) {
		adbg_process_free(process);
		adbg_oops(AdbgError.os);
		return null;
	}
} else { // Use fork(2) for subprocess
	pid_t pid = fork();
	if (pid < 0) { // error
		version(Trace) trace("fork=%s", strerror(errno));
		adbg_oops(AdbgError.os);
		adbg_process_free(process);
		return null;
	}
	
	if (pid == 0) { // sub process
		version(Trace) for (int i; i < argc + 2; ++i)
			trace("argv[%d]=%s", i, process.orig_argv[i]);
		
		__adbg_child_t chld = void;
		chld.argv = cast(const(char)**)process.orig_argv;
		chld.envp = oenvp;
		chld.dir  = odir;
		if (__adbg_exec_child(&chld) < 0)
			adbg_process_free(process);
		version(Trace) trace("fork=%s", strerror(errno));
		_exit(errno);
	}
	
	process.orig_pid = process.pid = pid;
} // clone(2)/fork(2)
	
	version(Trace) trace("pid=%d", process.pid);
	process.status = ADBG_PROCESS_ATTACHED;
	return process;
} else {
	adbg_oops(AdbgError.unimplemented);
	return null;
}
}

version (Posix)
private int __adbg_exec_child(void* arg) {
	__adbg_child_t *chld = cast(__adbg_child_t*)arg;
	assert(chld, "chld is null");
	assert(chld.argv, "argv is null");
	assert(*chld.argv, "argv[0] is null");
	
	// TODO: Can use pause() here if launching process paused option was given
	
	// Baby, Please Trace Me
	version (Trace) with (chld) trace("chld=%p argv=%p dir=%p envp=%p", argv, dir, envp);
version (linux) {
	if (ptrace(PTRACE_TRACEME, 0, null, null) < 0) {
		version (Trace) trace("ptrace=%s", strerror(errno));
		return -1;
	}
} else {
	if (ptrace(PT_TRACE_ME, 0, null, 0) < 0) {
		version (Trace) trace("ptrace=%s", strerror(errno));
		return -1;
	}
}
	// If start directory requested, change to it
	if (chld.dir && chdir(chld.dir) < 0) {
		version (Trace) trace("ptrace=%s", strerror(errno));
		return -1;
	}
	
	// Start specified process
	if (execve(*chld.argv, chld.argv, chld.envp) < 0) {
		version (Trace) trace("execve=%s", strerror(errno));
		return -1;
	}
	
	return 0;
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
Loption:
	switch (va_arg!int(list)) {
	case 0: break;
	case AdbgAttachOpt.stop:
		if (va_arg!int(list)) options |= OPT_STOP;
		goto Loption;
	case AdbgAttachOpt.exitkill:
		if (va_arg!int(list)) options |= OPT_EXITKILL;
		goto Loption;
	default:
		adbg_oops(AdbgError.invalidOption);
		return null;
	}
	
	version (Trace) trace("pid=%d options=%#x", pid, options);
	adbg_process_t *process = cast(adbg_process_t*)calloc(1, adbg_process_t.sizeof);
	if (process == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	process.status = ADBG_PROCESS_ATTACHED;
	
version (Windows) {
	//TODO: Integrate ObRegisterCallbacks?
	//      https://blog.xpnsec.com/anti-debug-openprocess/
	
	process.orig_pid = process.pid = cast(DWORD)pid;
	process.orig_handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, cast(DWORD)pid);
	if (process.orig_handle == null) {
		switch (GetLastError()) {
		case ERROR_INVALID_PARAMETER: // Must be invalid PID
			adbg_oops(AdbgError.unfindable);
			break;
		default: // ERROR_ACCESS_DENIED is a clear message
			adbg_oops(AdbgError.os);
		}
		free(process);
		return null;
	}
	
	// Check if process already has an attached debugger
	BOOL dbgpresent = void;
	if (CheckRemoteDebuggerPresent(process.orig_handle, &dbgpresent) == FALSE) {
		adbg_oops(AdbgError.os);
		adbg_process_free(process);
		return null;
	}
	if (dbgpresent) {
		adbg_oops(AdbgError.debuggerPresent);
		adbg_process_free(process);
		return null;
	}
	
	// Breaks into remote process and initiates break-in
	if (DebugActiveProcess(process.pid) == FALSE) {
		adbg_oops(AdbgError.os);
		adbg_process_free(process);
		return null;
	}
	
	// DebugActiveProcess, the default kills the process on exit.
	if (DebugSetProcessKillOnExit(options & OPT_EXITKILL) == FALSE) {
		adbg_oops(AdbgError.os);
		adbg_process_free(process);
		return null;
	}
	
	process.option_timeout = INFINITE;
	// TODO: Continue process on OPT_STOP
} else version (linux) {
	version (Trace) if (options & OPT_STOP) trace("Sending break...");
	if (ptrace(options & OPT_STOP ? PTRACE_ATTACH : PTRACE_SEIZE, pid, null, null) < 0) {
		adbg_oops(AdbgError.os);
		adbg_process_free(process);
		return null;
	}
	
	// Set exitkill on if specified, it is off by default
	if (options & OPT_EXITKILL && ptrace(PTRACE_SETOPTIONS, pid, null, PTRACE_O_EXITKILL) < 0) {
		adbg_oops(AdbgError.os);
		adbg_process_free(process);
		return null;
	}
	
	if (options & OPT_STOP)
		process.status |= ADBG_PROCESS_STOPPED;
	
	process.orig_pid = process.pid = cast(pid_t)pid;
} else version (Posix) { // BSDs, macOS
	if (ptrace(PT_ATTACH, pid, null, 0) < 0) {
		adbg_oops(AdbgError.os);
		adbg_process_free(process);
		return null;
	}
	
	process.orig_pid = process.pid = cast(pid_t)pid;
}
	
	return process;
}

/// Detach debugger from current process.
/// Params: process = Process instance being debugged.
/// Returns: Error code.
int adbg_debugger_detach(adbg_process_t *process) {
	if (process == null)
		return adbg_oops(AdbgError.invalidArgument);
	if ((process.status & ADBG_PROCESS_ATTACHED) == 0)
		return adbg_oops(AdbgError.debuggerInvalidAction);
	
	process.status = 0;
	
version (Windows) {
	if (DebugActiveProcessStop(process.pid) == FALSE)
		return adbg_oops(AdbgError.os);
} else version (linux) {
	if (ptrace(PTRACE_DETACH, process.pid, null, null) < 0)
		return adbg_oops(AdbgError.os);
} else version (Posix) {
	if (ptrace(PT_DETACH, process.pid, null, 0) < 0)
		return adbg_oops(AdbgError.os);
}
	return 0;
}

/// Attach user data when an event occurs.
/// 
/// User data is sent to event callback functions, for example, useful to
/// personally identify debugger requests.
/// Params:
/// 	process = Process instance.
/// 	udata = User data pointer. Passing null clears it.
/// Returns: Error code.
int adbg_debugger_udata(adbg_process_t *process, void *udata) {
	if (process == null)
		return adbg_oops(AdbgError.invalidArgument);
	process.udata = udata;
	return 0;
}

// NOTE: This is a hack, which might be removed later
/// Sets a timeout when waiting for a debug event to occur.
/// 
/// This function is only effective for adbg_debugger_wait on Windows.
/// Params:
/// 	process = Process instance.
/// 	ms = Timeout in milliseconds. 0 for infinite.
/// Returns: Error code.
int adbg_debugger_option_wait_timeout(adbg_process_t *process, uint ms) {
	if (process == null)
		return adbg_oops(AdbgError.invalidArgument);
version (Windows) {
	process.option_timeout = ms == 0 ? INFINITE : ms;
	return 0;
} else {
	return adbg_oops(AdbgError.unimplemented);
}
}

// NOTE: Wait function: Keep it simple!
//
//       The process and event parameters are absolute minimum.
//       A timeout option is only useful on Windows (no timeout option for
//       ptrace.2/wait.2 anyway).
//       A "filter" parameter only increases complexity pointlessly (user code
//       can filter these events itself).

/// Wait until a new debug event occurs. This call is blocking.
///
/// The process instance returned corresponds to the debugging event.
///
/// Windows: Uses WaitForDebugEvent. Needs to be on the same thread as other debugger calls.
/// POSIX: Uses waitpid.2 and ptrace.2 for further information.
///
/// Params: process = Process instance created by debugger.
/// Returns: Affected process instance by debugging event. Or null on error.
adbg_process_t* adbg_debugger_wait(adbg_process_t *process, adbg_event_t *event) {
	version(Trace) trace("process=%p", process);
	
	if (process == null || event == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if ((process.status & ADBG_PROCESS_ATTACHED) == 0) {
		adbg_oops(AdbgError.debuggerUnattached);
		return null;
	}
	
version (Windows) {
	DEBUG_EVENT de = void;
Lwait:
	if (WaitForDebugEvent(&de, process.option_timeout) == FALSE) {
		adbg_oops(AdbgError.os);
		return null;
	}
	
	process.status |= ADBG_PROCESS_STOPPED;
	
	event.process.pid = de.dwProcessId;
	event.process.status = process.status;
	event.process.option_timeout = process.option_timeout;
	
	// Filter events
	switch (de.dwDebugEventCode) {
	case EXCEPTION_DEBUG_EVENT:
		version(Trace) trace("Exception pid=%d tid=%d code=%#x",
			de.dwProcessId, de.dwThreadId,
			de.Exception.ExceptionRecord.ExceptionCode);
	
		process.status |= ADBG_PROCESS_STOPPED;
		
		event.type = AdbgEvent.exception;
		
		event.process.status = process.status;
		
		adbg_translate_exception(&event.exception, process, &de);
		// HACK: fill up thread details for exception
		event.exception.thread.id      = de.dwThreadId;
		event.exception.thread.process = process;
		event.exception.thread.status  = 0;

		// Detect DebugBreakProcess: EXCEPTION_BREAKPOINT with PAUSED flag set
		if (de.Exception.ExceptionRecord.ExceptionCode == STATUS_BREAKPOINT
				&& (process.status & ADBG_PROCESS_PAUSED)) {
			event.type = AdbgEvent.processPaused;
			process.status &= ~ADBG_PROCESS_PAUSED; // no longer paused if something happens
		}

		return &event.process;

		//goto Lcontinue; // auto-continue
	case EXIT_PROCESS_DEBUG_EVENT:
		version(Trace) trace("ProcExit pid=%d tid=%d code=%u",
			de.dwProcessId, de.dwThreadId, de.ExitProcess.dwExitCode);
		
		event.type = AdbgEvent.processExit;
		event.exitcode = cast(int)de.ExitProcess.dwExitCode;
		
		process.status |= ADBG_PROCESS_EXITED;
		
		event.process.status = process.status;
			
		return &event.process; // can't wait on a dead process
	/*case CREATE_THREAD_DEBUG_EVENT:
	case CREATE_PROCESS_DEBUG_EVENT:
	case EXIT_THREAD_DEBUG_EVENT:
	case LOAD_DLL_DEBUG_EVENT:
	case UNLOAD_DLL_DEBUG_EVENT:
	case OUTPUT_DEBUG_STRING_EVENT:
	case RIP_EVENT:
		goto default;*/
	default:
		version(Trace) trace("Unknown event=%u pid=%d tid=%d",
			de.dwDebugEventCode, de.dwProcessId, de.dwThreadId);
	}
	ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
	goto Lwait;
} else version (Posix) {
	version (linux) enum WBASE = __WALL; // all threads
	else            enum WBASE = 0;
	int wstatus = void;
Lwait:
	// TODO: Check process flag to debug all subprocesses instead of -1
	// NOTE: WCONTINUED does not work on Linux, even when sending SIGCONT
	//       ptrace(2) manpage states that setting WCONTINUED is not recommended
	pid_t pid = waitpid(-1, &wstatus, WBASE);
	if (pid < 0) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	// HACK: To allow thread services, we assume that the TID is equal to PID.
	//       This is partially true, the initial TID on Linux is the same as
	//       of the PID, and while Linux ptrace calls refer to the TID,
	//       this holds up for the moment being, but will fall short when
	//       multiple processes and threads come into play.
	event.process.pid = pid;
	
	if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) { // exited or killed
		version (Trace) trace("Exit/Signal status=%#x pid=%d", wstatus, process.pid);
		
		event.type = AdbgEvent.processExit;
		event.exitcode = WTERMSIG(wstatus);
		
		process.status |= ADBG_PROCESS_EXITED;
		event.process.status = process.status;
	/*} else if (WIFCONTINUED(wstatus)) { // SIGCONT (from a previous pause.2, not ptrace.2)
		version (Trace) trace("Continued status=%#x pid=%d", wstatus, process.pid);
		
		process.state = AdbgProcessState.running; // just in case
		
		if (process.event_process_continued)
			process.event_process_continued(process, udata);*/
	} else if (WIFSTOPPED(wstatus)) { // stopped by signal
		version (Trace) trace("Stopped status=%#x pid=%d", wstatus, process.pid);

		process.status |= ADBG_PROCESS_STOPPED;
		event.process.status = process.status;

		int signo = WSTOPSIG(wstatus);

		// Detect pause/suspend: SIGSTOP with PAUSED flag set
		if (signo == SIGSTOP && (process.status & (ADBG_PROCESS_PAUSED | ADBG_PROCESS_SUSPENDED))) {
			event.type = AdbgEvent.processPaused;
			process.status &= ~ADBG_PROCESS_PAUSED; // no longer paused
			return &event.process;
		}

		event.type = AdbgEvent.exception;

		adbg_translate_exception(&event.exception, &event.process, cast(void*)&signo);

		// HACK: fill up thread details for exception
		event.exception.thread.process = &event.process;
		event.exception.thread.id      = event.process.pid;
		event.exception.thread.status  = 0;
		return &event.process;

		//int e = adbg_debugger_continue(process, process.pid);
		//if (e) return null;
		//goto Lwait;
	} else {
		version (Trace) trace("Unknown status=%d", wstatus);
		goto Lwait;
	}
	
	return &event.process;
} else static assert(0, "Implement adbg_debugger_wait");
}

// Used internally to translate OS codes into exception
private
void adbg_translate_exception(adbg_exception_t *exception, adbg_process_t *process, void *osevent) {
version (Windows) {
	assert(osevent);
	DEBUG_EVENT *event = cast(DEBUG_EVENT*)osevent;
	
	// While the first ExceptionInformation used to be more interesting for
	// EXCEPTION_IN_PAGE_ERROR and EXCEPTION_ACCESS_VIOLATION,
	// it might be interesting to unconditionally send it for future interests.
	// HACK: The cast hack is to force select adbg.include.windows.winnt.EXCEPTION_RECORD.
	//       Otherwise, compiler tries to use core.sys.windows.winbase.EXCEPTION_RECORD.
	EXCEPTION_RECORD *rec = cast(.EXCEPTION_RECORD*)&event.Exception.ExceptionRecord;
	exception.type = adbg_exception_from_os(rec.ExceptionCode, cast(uint)rec.ExceptionInformation[0]);
	exception.fault_address = cast(ulong)rec.ExceptionAddress;
	exception.oscode = rec.ExceptionCode;
	
	// HACK: fill up thread details for exception
	exception.thread.id = event.dwThreadId;
	exception.thread.process = process;
	exception.thread.status = 0;
} else version (linux) {
	assert(process);
	assert(osevent);
	int signo = *cast(int*)osevent;
	int si_code = void;
	
	// Get subcode and fault address if available
	siginfo_t siginfo = void;
	if (ptrace(PTRACE_GETSIGINFO, process.pid, null, &siginfo) < 0) {
		si_code = 0;
		exception.fault_address = 0;
	} else {
		si_code = siginfo.si_code;
		switch (signo) { // Get fault address
		case SIGILL, SIGSEGV, SIGFPE, SIGBUS:
			// NOTE: .si_addr() emits linker errors on Musl platforms.
			exception.fault_address = cast(ulong)siginfo._sifields._sigfault.si_addr;
			break;
		default:
			exception.fault_address = 0;
		}
	}
	
	exception.type = adbg_exception_from_os(signo, si_code);
	exception.oscode = signo;
	
	// HACK: fill up thread details for exception
	exception.thread.id = process.pid;
	exception.thread.process = process;
	exception.thread.status = 0;
} else version (FreeBSD) {
	assert(process);
	assert(osevent);
	int signo = *cast(int*)osevent;
	int si_code = void;
	
	// Get subcode fault address if available
	ptrace_lwpinfo lwp = void;
	if (ptrace(PT_LWPINFO, process.pid, &lwp, 0) < 0) {
		si_code = 0;
		exception.fault_address = 0;
	} else {
		si_code = lwp.pl_siginfo.si_code;
		exception.fault_address = cast(ulong)lwp.pl_siginfo.si_addr;
	}
	
	exception.type = adbg_exception_from_os(signo, si_code);
	exception.oscode = signo;
	
	// HACK: fill up thread details for exception
	exception.thread.id = de.dwThreadId;
	exception.thread.process = process;
	exception.thread.status = 0;
} else {
	static assert(false, "Implement exception translation code");
}
}

/// Disconnect and terminate the debuggee process.
/// Params: process = Process.
/// Returns: Error code.
int adbg_debugger_terminate(adbg_process_t *process) {
	if (process == null)
		return adbg_oops(AdbgError.invalidArgument);
	if ((process.status & ADBG_PROCESS_ATTACHED) == 0)
		return adbg_oops(AdbgError.debuggerUnattached);
	
version (Windows) {
	HANDLE phandle = OpenProcess(PROCESS_TERMINATE, FALSE, cast(DWORD)process.pid);
	if (phandle == null)
		return adbg_oops(AdbgError.os);
	scope(exit) CloseHandle(phandle);
	// NOTE: ContinueDebugEvent
	//       Before using TerminateProcess,
	//       ContinueDebugEvent(pid, tid, DBG_TERMINATE_PROCESS)
	//       was used instead. I forgot where I saw that example.
	//       MSDN does not feature it.
	if (TerminateProcess(phandle, DBG_TERMINATE_PROCESS) == FALSE)
		return adbg_oops(AdbgError.os);
} else version (Posix) {
	// PT_KILL is deprecated on Linux, and likely everywhere else too
	if (kill(process.pid, SIGKILL) < 0)
		return adbg_oops(AdbgError.os);
} else static assert(0, "Implement adbg_debugger_terminate");

	process.status = ADBG_PROCESS_EXITED; // Neither attached or stopped anyway!
	return 0;
}

/// Make the debuggee process continue from its currently stopped state.
/// Params:
/// 	process = Process instance.
/// 	tid = Thread or process ID.
/// Returns: Error code.
int adbg_debugger_continue(adbg_process_t *process, long tid) {
	if (process == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	// Needs to be attached
	if ((process.status & ADBG_PROCESS_ATTACHED) == 0)
		return adbg_oops(AdbgError.debuggerUnattached);
	
version (Windows) {
	version(Trace) trace("pid=%d tid=%lld status=%d", process.pid, tid, process.status);
	// HACK: Created processes are not in a "stopped" state
	//       But will continue at the next wait call
	if (ContinueDebugEvent(process.pid, cast(DWORD)tid, DBG_CONTINUE) == FALSE) {
		return adbg_oops(AdbgError.os);
	}
} else version (linux) {
	version(Trace) trace("pid=%d status=0x%x", process.pid, process.status);
	if ((process.status & ADBG_PROCESS_STOPPED) == 0)
		return adbg_oops(AdbgError.debuggerUnpaused);
	
	if (ptrace(PTRACE_CONT, process.pid, null, null) < 0) {
		version (Trace) trace("ptrace=%s", strerror(errno));
		return adbg_oops(AdbgError.os);
	}
} else version (Posix) {
	version(Trace) trace("pid=%d status=0x%x", process.pid, process.status);
	// TODO: Test HACK on NetBSD, OpenBSD
	// HACK: FreeBSD: PT_TRACEME and stop state.
	//       Because the PT_TRACEME does not seem to mark the tracee
	//       as stopped, calling PT_CONTINUE after execve will return
	//       errno=13 (Device Busy). raise(SIGSTOP) does nothing.
	//       This workaround forces waiting through a stop state.
	if ((process.status & ADBG_PROCESS_STOPPED) == 0) {
		int w = void;
		waitpid(cast(pid_t)tid, &w, 0);
	}
	
	// NOTE: FreeBSD/NetBSD/OpenBSD PT_CONTINUE
	//       addr can be an address to resume at, or 1
	//       data can be a signal number, or 0
	if (ptrace(PT_CONTINUE, cast(pid_t)tid, cast(caddr_t)1, 0) < 0) {
		version (Trace) trace("ptrace=%s", strerror(errno));
		process.state = AdbgProcessState.unknown;
		return adbg_oops(AdbgError.os);
	}
} else static assert(0, "Implement adbg_debugger_continue");
	
	process.status &= ~ADBG_PROCESS_STOPPED;
	return 0;
}

/// Debug break: interrupt the process and generate a debug event.
///
/// The event loop will report a `processPaused` event.
/// Call `adbg_debugger_continue` to resume after a debug break.
/// Windows: Uses DebugBreakProcess which injects a breakpoint exception.
/// POSIX: Sends SIGSTOP which is intercepted by ptrace.
/// Params: process = Process instance.
/// Returns: Error code.
int adbg_debugger_pause(adbg_process_t *process) {
	if (process == null)
		return adbg_oops(AdbgError.invalidArgument);
	if ((process.status & ADBG_PROCESS_ATTACHED) == 0)
		return adbg_oops(AdbgError.debuggerUnattached);
	if (process.status & (ADBG_PROCESS_PAUSED | ADBG_PROCESS_SUSPENDED))
		return adbg_oops(AdbgError.debuggerInvalidAction);

	process.status |= ADBG_PROCESS_PAUSED; // set before so wait catches it

version (Windows) {
	HANDLE phandle = OpenProcess(PROCESS_CREATE_THREAD, FALSE, cast(DWORD)process.pid);
	if (phandle == null) {
		process.status &= ~ADBG_PROCESS_PAUSED;
		return adbg_oops(AdbgError.os);
	}
	scope(exit) CloseHandle(phandle);
	if (DebugBreakProcess(phandle) == FALSE) {
		process.status &= ~ADBG_PROCESS_PAUSED;
		return adbg_oops(AdbgError.os);
	}
} else version (Posix) {
	if (kill(process.pid, SIGSTOP) < 0) {
		process.status &= ~ADBG_PROCESS_PAUSED;
		return adbg_oops(AdbgError.os);
	}
}
	return 0;
}

/// Suspend the process at OS level.
///
/// On Windows, uses NtSuspendProcess. This does NOT generate a debug event.
/// On POSIX, sends SIGSTOP (same as pause; ptrace intercepts everything).
/// Call `adbg_debugger_resume` to resume from a suspend.
/// Params: process = Process instance.
/// Returns: Error code.
int adbg_debugger_suspend(adbg_process_t *process) {
	if (process == null)
		return adbg_oops(AdbgError.invalidArgument);
	if ((process.status & ADBG_PROCESS_ATTACHED) == 0)
		return adbg_oops(AdbgError.debuggerUnattached);
	if (process.status & (ADBG_PROCESS_PAUSED | ADBG_PROCESS_SUSPENDED))
		return adbg_oops(AdbgError.debuggerInvalidAction);

version (Windows) {
	if (__dynlib_ntdll_load())
		return adbg_oops(AdbgError.unimplemented);
	HANDLE phandle = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, cast(DWORD)process.pid);
	if (phandle == null)
		return adbg_oops(AdbgError.os);
	scope(exit) CloseHandle(phandle);
	if (NtSuspendProcess(phandle) != 0)
		return adbg_oops(AdbgError.os);
} else version (Posix) {
	// On POSIX, ptrace intercepts SIGSTOP the same as pause
	process.status |= ADBG_PROCESS_PAUSED; // for wait() correlation
	if (kill(process.pid, SIGSTOP) < 0) {
		process.status &= ~ADBG_PROCESS_PAUSED;
		return adbg_oops(AdbgError.os);
	}
}
	process.status |= ADBG_PROCESS_SUSPENDED;
	return 0;
}

/// Resume the process from an OS-level suspend.
///
/// On Windows, uses NtResumeProcess.
/// On POSIX, uses PTRACE_CONT (Linux) or PT_CONTINUE (FreeBSD).
/// Params: process = Process instance.
/// Returns: Error code.
int adbg_debugger_resume(adbg_process_t *process) {
	if (process == null)
		return adbg_oops(AdbgError.invalidArgument);
	if ((process.status & ADBG_PROCESS_ATTACHED) == 0)
		return adbg_oops(AdbgError.debuggerUnattached);
	if ((process.status & ADBG_PROCESS_SUSPENDED) == 0)
		return adbg_oops(AdbgError.debuggerInvalidAction);

version (Windows) {
	if (__dynlib_ntdll_load())
		return adbg_oops(AdbgError.unimplemented);
	HANDLE phandle = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, cast(DWORD)process.pid);
	if (phandle == null)
		return adbg_oops(AdbgError.os);
	scope(exit) CloseHandle(phandle);
	if (NtResumeProcess(phandle) != 0)
		return adbg_oops(AdbgError.os);
} else version (linux) {
	if (ptrace(PTRACE_CONT, process.pid, null, null) < 0)
		return adbg_oops(AdbgError.os);
} else version (Posix) {
	if (ptrace(PT_CONTINUE, process.pid, cast(caddr_t)1, 0) < 0)
		return adbg_oops(AdbgError.os);
}
	process.status &= ~(ADBG_PROCESS_SUSPENDED | ADBG_PROCESS_STOPPED | ADBG_PROCESS_PAUSED);
	return 0;
}

/// Performs an instruction step for thread.
///
/// This will trigger a step exception.
/// Params:
/// 	process = Process instance.
/// 	tid = Thread or process ID, typically from a stopped event.
/// Returns: Error code.
int adbg_debugger_step_instruction(adbg_process_t *process, long tid) {
	if (process == null)
		return adbg_oops(AdbgError.invalidArgument);
	if ((process.status & ADBG_PROCESS_ATTACHED) == 0)
		return adbg_oops(AdbgError.debuggerUnattached);
	
version (WinTel) {
	enum EFLAGS_TF = 0x100;
	
	HANDLE thandle = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT, FALSE, cast(DWORD)tid);
	if (thandle == null)
		return adbg_oops(AdbgError.os);
	scope(exit) CloseHandle(thandle);

	HANDLE phandle = OpenProcess(PROCESS_SET_INFORMATION, FALSE, cast(DWORD)process.pid);
	if (phandle == null)
		return adbg_oops(AdbgError.os);
	scope(exit) CloseHandle(phandle);
	
	// AMD64 with a 32-bit process
	// Enable single-stepping via Trap flag
	version (X86_64)
	if (adbg_process_machine(process) == AdbgMachine.i386) {
		WOW64_CONTEXT wow64ctx = void;
		wow64ctx.ContextFlags = CONTEXT_CONTROL;
		if (Wow64GetThreadContext(thandle, &wow64ctx) == FALSE)
			return adbg_oops(AdbgError.os);
		wow64ctx.EFlags |= EFLAGS_TF;
		if (Wow64SetThreadContext(thandle, &wow64ctx) == FALSE)
			return adbg_oops(AdbgError.os);
		if (FlushInstructionCache(phandle, null, 0) == FALSE)
			return adbg_oops(AdbgError.os);
		
		return adbg_debugger_continue(process, tid);
	}
	
	// X86, AMD64
	// Enable single-stepping via Trap flag
	CONTEXT ctx = void;
	ctx.ContextFlags = CONTEXT_CONTROL;
	if (GetThreadContext(thandle, cast(LPCONTEXT)&ctx) == FALSE)
		return adbg_oops(AdbgError.os);
	ctx.EFlags |= EFLAGS_TF;
	if (SetThreadContext(thandle, cast(LPCONTEXT)&ctx) == FALSE)
		return adbg_oops(AdbgError.os);
	if (FlushInstructionCache(phandle, null, 0) == FALSE)
		return adbg_oops(AdbgError.os);
	
	return adbg_debugger_continue(process, tid);
} else version (WinArm) {
	enum PSTATE_SS = 0x200000;
	
	// TODO: Confirm Cpsr |= PSTATE_SS is correct
	
	HANDLE thandle = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT, FALSE, cast(DWORD)tid);
	if (thandle == null)
		return adbg_oops(AdbgError.os);
	scope(exit) CloseHandle(thandle);

	HANDLE phandle = OpenProcess(PROCESS_SET_INFORMATION, FALSE, cast(DWORD)process.pid);
	if (phandle == null)
		return adbg_oops(AdbgError.os);
	scope(exit) CloseHandle(phandle);
	
	// AArch64 with a 32-bit process
	// Enable single-stepping via SS bit
	version (AArch64)
	switch (adbg_process_machine(process)) with (AdbgMachine) {
	case arm, thumb, thumb32:
		WOW64_CONTEXT wow64ctx = void;
		wow64ctx.ContextFlags = CONTEXT_CONTROL;
		if (Wow64GetThreadContext(thandle, &wow64ctx) == FALSE)
			return adbg_oops(AdbgError.os);
		wow64ctx.Cpsr |= PSTATE_SS;
		if (Wow64SetThreadContext(thandle, &wow64ctx) == FALSE)
			return adbg_oops(AdbgError.os);
		if (FlushInstructionCache(phandle, null, 0) == FALSE)
			return adbg_oops(AdbgError.os);
		
		return adbg_debugger_continue(process, tid);
	}
	
	// AArch64, AArch32
	// Enable single-stepping via SS bit
	CONTEXT ctx = void;
	ctx.ContextFlags = CONTEXT_CONTROL;
	if (GetThreadContext(thandle, cast(LPCONTEXT)&ctx) == FALSE)
		return adbg_oops(AdbgError.os);
	ctx.Cpsr |= PSTATE_SS;
	if (SetThreadContext(thandle, cast(LPCONTEXT)&ctx) == FALSE)
		return adbg_oops(AdbgError.os);
	if (FlushInstructionCache(phandle, null, 0) == FALSE)
		return adbg_oops(AdbgError.os);
	
	return adbg_debugger_continue(process, tid);
} else version (linux) {
	if (ptrace(PTRACE_SINGLESTEP, tid, null, null) < 0) {
		return adbg_oops(AdbgError.os);
	}
	
	return 0;
} else version (Posix) {
	// HACK: See HACK in continue function.
	if ((process.status & ADBG_PROCESS_STOPPED) == 0) {
		int w = void;
		waitpid(cast(pid_t)tid, &w, 0);
	}
	
	if (ptrace(PT_STEP, cast(pid_t)tid, null, 0) < 0) {
		process.state = AdbgProcessState.unknown;
		return adbg_oops(AdbgError.os);
	}
	
	return 0;
} else {
	return adbg_oops(AdbgError.unimplemented);
}
}