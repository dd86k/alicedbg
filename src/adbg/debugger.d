/// Provides debugging API.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.debugger;

// TODO: adbg_debugger_spawn: Get/set default child stack size
// TODO: High-level disassembly functions (e.g., from exception, process, etc.)
// TODO: Check process creation
//       Calls to fork/vfork/clone/etc.

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
	import adbg.include.windows.winnt;
	import core.sys.windows.winbase;
	import adbg.machines;

	version (X86)
		version = WINTEL;
	version (X86_64)
		version = WINTEL;
	version (WINTEL)
		private enum EFLAGS_TF = 0x100;
} else version (Posix) {
	import adbg.include.posix.ptrace;
	import adbg.include.posix.unistd;
	import adbg.include.posix.sys.wait;
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
enum AdbgEvent {
	/// An exception occurred.
	exception,
	/// A process was created.
	processCreated,
	/// A process exited, or has been killed.
	processExit,
	/// A process continued.
	processContinue,
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
	debugAll    = 10,
	/// Alias to debugAll
	debugChildren = debugAll,
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
	
	adbg_process_t *proc = cast(adbg_process_t*)calloc(1, adbg_process_t.sizeof);
	if (proc == null) {
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
		free(proc);
		return null;
	}
	if (fflags & FILE_ATTRIBUTE_DIRECTORY) {
		adbg_oops(AdbgError.debuggerNeedFile);
		free(proc);
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
		size_t o = adbg_strings_flatten(proc.args + i, cl, argc, oargv, 1);
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
		oenvp,	// lpEnvironment
		odir,	// lpCurrentDirectory
		&si, &pi) == FALSE) {
		adbg_oops(AdbgError.os);
		adbg_process_free(proc);
		return null;
	}
	proc.hproc = pi.hProcess;
	proc.hthread = pi.hThread;
	proc.orig_pid = proc.pid = pi.dwProcessId;
	proc.tid = pi.dwThreadId;
	
	proc.status = AdbgProcessState.standby;
	proc.creation = AdbgCreation.spawned;
	return proc;
} else version (Posix) {
	// Verify if file exists and we has access to it
	// This is to avoid a confusing error message
	stat_t st = void;
	if (stat(path, &st) < 0) {
		adbg_oops(AdbgError.os);
		adbg_process_free(proc);
		return null;
	}
	if (st.st_mode & S_IFDIR) {
		adbg_oops(AdbgError.debuggerNeedFile);
		adbg_process_free(proc);
		return null;
	}
	
	// Allocate arguments, include space for program and null terminator
	int argc;
	if (oargv) while (oargv[argc]) ++argc;
	version(Trace) trace("argc=%d", argc);
	proc.argv = cast(char**)malloc((argc + 2) * size_t.sizeof);
	if (proc.argv == null) {
		version(Trace) trace("mmap=%s", strerror(errno));
		adbg_oops(AdbgError.os);
		adbg_process_free(proc);
		return null;
	}
	proc.argv[0] = cast(char*)path;
	if (argc && oargv && *oargv)
		memcpy(proc.argv + 1, oargv, argc * size_t.sizeof);
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
	proc.orig_pid =
		proc.pid = clone(&__adbg_exec_child, stacktop, CLONE_PTRACE | CLONE_VFORK, &chld);
	if (proc.pid < 0) {
		adbg_process_free(proc);
		adbg_oops(AdbgError.os);
		return null;
	}
} else { // fork(2)
	pid_t pid = fork();
	if (pid < 0) { // error
		version(Trace) trace("fork=%s", strerror(errno));
		adbg_oops(AdbgError.os);
		adbg_process_free(proc);
		return null;
	}
	
	if (pid == 0) { // sub process
		version(Trace) for (int i; i < argc + 2; ++i)
			trace("argv[%d]=%s", i, proc.argv[i]);
		
		__adbg_child_t chld = void;
		chld.argv = cast(const(char)**)proc.argv;
		chld.envp = oenvp;
		chld.dir  = odir;
		if (__adbg_exec_child(&chld) < 0)
			adbg_process_free(proc);
		version(Trace) trace("fork=%s", strerror(errno));
		_exit(errno);
	}
	
	proc.orig_pid = proc.pid = pid;
} // clone(2)/fork(2)
	
	version(Trace) trace("pid=%d", proc.pid);
	proc.status = AdbgProcessState.standby;
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
	assert(chld, "chld is null");
	assert(chld.argv, "argv is null");
	assert(*chld.argv, "argv[0] is null");
	
	// TODO: Can use pause() here if launching process paused option was given
	
	// Baby, Please Trace Me
	version (Trace) with (chld) trace("chld=%p argv=%p dir=%p envp=%p", argv, dir, envp);
version (linux) {
	if (ptrace(PT_TRACEME, 0, null, null) < 0) {
		version (Trace) trace("ptrace=%s", strerror(errno));
		return -1;
	}
} else {
	if (ptrace(PT_TRACEME, 0, null, 0) < 0) {
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
	proc.hproc = OpenProcess(
		PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE |
		PROCESS_VM_READ |
		PROCESS_SUSPEND_RESUME |
		PROCESS_QUERY_INFORMATION,
		FALSE,
		cast(DWORD)pid);
	// TODO: Better error message on invalid PID number
	//       On an invalid PID, we get "Invalid parameter", which is confusing
	//       Filter by ERROR_INVALID_PARAMETER/ERROR_ACCESS_DENIED?
	if (proc.hproc == null) {
		adbg_oops(AdbgError.os);
		free(proc);
		return null;
	}
	
	// Check if process already has an attached debugger
	BOOL dbgpresent = void;
	if (CheckRemoteDebuggerPresent(proc.hproc, &dbgpresent) == FALSE) {
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
	
	proc.status = options & OPT_STOP ? AdbgProcessState.paused : AdbgProcessState.running;
	proc.pid = cast(pid_t)pid;
} else version (FreeBSD) {
	if (ptrace(PT_ATTACH, pid, null, 0) < 0) {
		adbg_oops(AdbgError.os);
		adbg_process_free(proc);
		return null;
	}
	
	proc.status = AdbgProcessState.paused;
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
	proc.status = AdbgProcessState.unloaded;
	
version (Windows) {
	if (DebugActiveProcessStop(proc.pid) == FALSE)
		return adbg_oops(AdbgError.os);
} else version (Posix) {
	if (ptrace(PT_DETACH, proc.pid, null, 0) < 0)
		return adbg_oops(AdbgError.os);
}
	return 0;
}

private alias cbexeception = void function(adbg_process_t*, void*, adbg_exception_t*);
//private alias cbproccreate = void function(adbg_process_t*, void*);
private alias cbprocexited = void function(adbg_process_t*, void*, int);
private alias cbproccontinued = void function(adbg_process_t*, void*);

/// Set an event handler for a particular debugging event for this process.
///
/// Except for a few conditions, these are particularly called within the
/// `adbg_debugger_wait` function.
///
/// ### Exception
///
/// When a process stops to an exception.
/// 
/// If there are no handlers, the process will automatically continue.
///
/// Callback: void function(adbg_process_t *process, void *userdata, adbg_exception_t *exception)
/// 
/// ### ProcessCreated
///
/// Currently not implemented.
///
/// ### Process Exit
///
/// When a process exited.
///
/// Callback: void function(adbg_process_t *process, void *userdata, int exitcode)
///
/// ### ProcessContinue
///
/// When a process continues to being debugged.
///
/// Callback: void function(adbg_process_t *process, void *userdata)
///
/// Params:
/// 	on = Debug event.
/// 	proc = Process instance. It must be spawned or attached by the debugger.
/// 	handler = Event handler. Setting it to `null` disables it, skipping it.
/// Returns: Error code.
int adbg_debugger_on(adbg_process_t *proc, AdbgEvent on, void *handler) {
	if (proc == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	// NOTE: The weird casting done here is due to usage of `extern` in struct.
	switch (on) with (AdbgEvent) {
	case exception:
		extern (C) cbexeception h = cast(cbexeception)handler;
		proc.event_exception = h;
		break;
	/*case processCreated:
		extern (C) cbproccreate h = cast(cbproccreate)handler;
		proc.event_process_created = h;
		break;*/
	case processExit:
		extern (C) cbprocexited h = cast(cbprocexited)handler;
		proc.event_process_exited = h;
		break;
	case processContinue:
		extern (C) cbproccontinued h = cast(cbproccontinued)handler;
		proc.event_process_continued = h;
		break;
	default:
		return adbg_oops(AdbgError.invalidOption);
	}
	return 0;
}

/// Attach user data when an event occurs.
///
/// This is useful to identify requests, for example.
/// Params:
/// 	proc = Process instance.
/// 	udata = User data pointer. Passing null clears it.
/// Returns: Error code.
int adbg_debugger_udata(adbg_process_t *proc, void *udata) {
	if (proc == null)
		return adbg_oops(AdbgError.invalidArgument);
	proc.udata = udata;
	return 0;
}

/// Wait until a new debug event occurs. This call is blocking.
///
/// The lifetime of the event callback parameters are not guaranteed.
/// To keep a reference, use the proper duplicate function.
///
/// Windows: Uses WaitForDebugEvent.
/// POSIX: Uses waitpid(2) and ptrace(2).
///
/// Params: proc = Process instancied by the debugger.
/// Returns: Error code.
int adbg_debugger_wait(adbg_process_t *proc) {
	version(Trace) trace("proc=%p udata=%p", proc, udata);
	
	if (proc == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (proc.creation == AdbgCreation.unloaded)
		return adbg_oops(AdbgError.debuggerUnattached);
	
version (Windows) {
	DEBUG_EVENT de = void;
Lwait:
	if (WaitForDebugEvent(&de, INFINITE) == FALSE) {
		proc.status = AdbgProcessState.unknown;
		return adbg_oops(AdbgError.os);
	}
	
	proc.pid = de.dwProcessId;
	proc.tid = de.dwThreadId;
	
	// TODO: Get rid of hack to help multiprocess support
	//       By opening/closing process+thread handles per debugger function that need it:
	//       - Help with leaking handles
	//       - Permissions, since each OS function need different permissions
	// HACK: To have access to Debug API
	proc.hproc = proc.hproc;
	proc.hthread = proc.hthread;
	
	// Filter events
	switch (de.dwDebugEventCode) {
	case EXCEPTION_DEBUG_EVENT:
		version(Trace) trace("Exception pid=%d tid=%d code=%#x",
			de.dwProcessId, de.dwThreadId,
			de.Exception.ExceptionRecord.ExceptionCode);
		
		proc.status = AdbgProcessState.stopped;
		
		if (proc.event_exception == null)
			goto Lcontinue;
		
		adbg_exception_t exception = void;
		adbg_translate_exception(&exception, proc, &de);
		proc.event_exception(proc, proc.udata, &exception);
		break;
	case EXIT_PROCESS_DEBUG_EVENT:
		version(Trace) trace("ProcExit pid=%d tid=%d code=%u",
			de.dwProcessId, de.dwThreadId, de.ExitProcess.dwExitCode);
		
		proc.status = AdbgProcessState.unknown;
		
		if (proc.event_process_exited == null)
			goto Lcontinue;
		
		proc.event_process_exited(proc, proc.udata, cast(int)de.ExitProcess.dwExitCode);
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
		version(Trace) trace("Unknown event=%u pid=%d tid=%d",
			de.dwDebugEventCode, de.dwProcessId, de.dwThreadId);
	Lcontinue: // To bypass trace call
		ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
		goto Lwait;
	}
} else version (Posix) {
	version (linux) enum WBASE = __WALL; // all threads
	else            enum WBASE = WTRAPPED | WSTOPPED | WEXITED;
	int wstatus = void;
Lwait:
	// TODO: Check process flag to debug all subprocesses instead of -1
	if ((proc.pid = waitpid(-1, &wstatus, WBASE)) < 0) {
		proc.status = AdbgProcessState.unknown;
		return adbg_oops(AdbgError.crt);
	}
	
	// HACK: To allow thread services, we assume that the TID is equal to PID.
	//       This is partially true, the initial TID on Linux is the same as
	//       of the PID, and while Linux ptrace calls refer to the TID,
	//       this holds up for the moment being, but will fall short when
	//       multiple processes and threads come into play.
	proc.tid = proc.pid;
	
	if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) { // exited or killed
		version (Trace) trace("Exit/Signal status=%#x pid=%d", wstatus, proc.pid);
		
		proc.status = AdbgProcessState.unknown;
		
		if (proc.event_process_exited)
			proc.event_process_exited(proc, proc.udata, WTERMSIG(wstatus));
	// NOTE: WCONTINUED is not recommended
	/*} else if (WIFCONTINUED(wstatus)) { // continuing
		version (Trace) trace("Continued status=%#x pid=%d", wstatus, proc.pid);
		
		proc.status = AdbgProcessState.running; // just in case
		
		if (proc.event_process_continued)
			proc.event_process_continued(proc, udata);*/
	} else if (WIFSTOPPED(wstatus)) { // stopped by signal
		version (Trace) trace("Stopped status=%#x pid=%d", wstatus, proc.pid);
		
		proc.status = AdbgProcessState.stopped;
		
		if (proc.event_exception == null) {
			if (adbg_debugger_continue(proc))
				return adbg_errno();
			goto Lwait;
		}
		
		int sig = WSTOPSIG(wstatus);
		adbg_exception_t exception = void;
		adbg_translate_exception(&exception, proc, &sig);
		proc.event_exception(proc, proc.udata, &exception);
	} else {
		version (Trace) trace("Unknown status=%d", wstatus);
		goto Lwait;
	}
} else static assert(0, "Implement adbg_debugger_wait");

	return 0;
}

// Used internally to translate OS codes into exception
private
void adbg_translate_exception(adbg_exception_t *exception, adbg_process_t *proc, void *osevent) {
version (Windows) {
	assert(osevent);
	DEBUG_EVENT *event = cast(DEBUG_EVENT*)osevent;
	
	exception.fault_address = cast(ulong)event.Exception.ExceptionRecord.ExceptionAddress;
	exception.oscode = event.Exception.ExceptionRecord.ExceptionCode;
	
	switch (exception.oscode) {
	case EXCEPTION_IN_PAGE_ERROR, EXCEPTION_ACCESS_VIOLATION:
		exception.type = adbg_exception_from_os(exception.oscode,
			cast(uint)event.Exception.ExceptionRecord.ExceptionInformation[0]);
		break;
	default:
		exception.type = adbg_exception_from_os(exception.oscode);
	}
} else version (linux) {
	assert(proc);
	assert(osevent);
	int signo = *cast(int*)osevent;
	int si_code = void;
	
	siginfo_t siginfo = void;
	if (ptrace(PT_GETSIGINFO, proc.pid, null, &siginfo) < 0) {
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
	
	exception.oscode = signo;
	exception.type = adbg_exception_from_os(signo, si_code);
} else version (FreeBSD) {
	assert(proc);
	assert(osevent);
	int signo = *cast(int*)osevent;
	int si_code = void;
	
	ptrace_lwpinfo lwp = void;
	if (ptrace(PT_LWPINFO, proc.pid, &lwp, 0) < 0) {
		si_code = 0;
		exception.fault_address = 0;
	} else {
		si_code = lwp.pl_siginfo.si_code;
		exception.fault_address = cast(ulong)lwp.pl_siginfo.si_addr;
	}
	
	exception.oscode = signo;
	exception.type = adbg_exception_from_os(signo, si_code);
} else {
	static assert(false, "Implement exception translation code");
}
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
	//       was used instead. I forgot where I saw that example.
	//       MSDN does not feature it.
	if (TerminateProcess(proc.hproc, DBG_TERMINATE_PROCESS) == FALSE)
		return adbg_oops(AdbgError.os);
} else version (Posix) {
	// PT_KILL is deprecated on Linux, and likely elsewhere too
	if (kill(proc.pid, SIGKILL) < 0)
		return adbg_oops(AdbgError.os);
} else static assert(0, "Implement adbg_debugger_terminate");

	proc.status = AdbgProcessState.unknown;
	proc.creation = AdbgCreation.unloaded;
	return 0;
}

/// Make the debuggee process continue from its currently stopped state.
/// Params: proc = Process.
/// Returns: Error code.
int adbg_debugger_continue(adbg_process_t *proc) {
	if (proc == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (proc.creation == AdbgCreation.unloaded)
		return adbg_oops(AdbgError.debuggerUnattached);
	
version (Windows) {
	version(Trace) trace("pid=%d tid=%d state=%d", proc.pid, proc.tid, proc.status);
	switch (proc.status) with (AdbgProcessState) {
	// HACK: Created processes are not in a "stopped" state
	//       But will continue at the next wait call
	case created: break;
	case stopped:
		if (ContinueDebugEvent(proc.pid, proc.tid, DBG_CONTINUE) == FALSE) {
			proc.status = AdbgProcessState.unknown;
			return adbg_oops(AdbgError.os);
		}
		break;
	default: return adbg_oops(AdbgError.debuggerUnpaused);
	}
	
	if (proc.event_process_continued)
		proc.event_process_continued(proc, proc.udata);
} else version (linux) {
	version(Trace) trace("pid=%d state=%d", proc.pid, proc.status);
	switch (proc.status) with (AdbgProcessState) {
	case created, stopped:
		if (ptrace(PT_CONT, proc.pid, null, cast(void*)SIGCONT) < 0) {
			version (Trace) trace("ptrace=%s", strerror(errno));
			proc.status = AdbgProcessState.unknown;
			return adbg_oops(AdbgError.os);
		}
		if (proc.event_process_continued)
			proc.event_process_continued(proc, proc.udata);
		break;
	default: return adbg_oops(AdbgError.debuggerUnpaused);
	}
} else version (Posix) {
	version(Trace) trace("pid=%d state=%d", proc.pid, proc.status);
	switch (proc.status) with (AdbgProcessState) {
	case created:
		// TODO: Test HACK on NetBSD, OpenBSD
		// HACK: FreeBSD: PT_TRACEME and stop state.
		//       Because the PT_TRACEME does not seem to mark the tracee
		//       as stopped, calling PT_CONTINUE after execve will return
		//       errno=13 (Device Busy). raise(SIGSTOP) does nothing.
		//       This workaround forces waiting a stop state.
		int w = void;
		waitpid(proc.pid, &w, 0);
		goto case;
	case stopped:
		// NOTE: FreeBSD/NetBSD/OpenBSD PT_CONTINUE
		//       addr can be an address to resume at, or 1
		//       data can be a signal number, or 0
		if (ptrace(PT_CONTINUE, proc.pid, cast(caddr_t)1, SIGCONT) < 0) {
			version (Trace) trace("ptrace=%s", strerror(errno));
			proc.status = AdbgProcessState.unknown;
			return adbg_oops(AdbgError.os);
		}
		if (proc.event_process_continued)
			proc.event_process_continued(proc, proc.udata);
		break;
	default: return adbg_oops(AdbgError.debuggerUnpaused);
	}
} else static assert(0, "Implement adbg_debugger_continue");
	
	proc.status = AdbgProcessState.running;
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
	
version (WINTEL) {
	// Enable single-stepping via Trap flag
	
	// AMD64 with a 32-bit process
	version (Win64)
	if (adbg_process_machine(proc) == AdbgMachine.i386) {
		WOW64_CONTEXT wow64ctx = void;
		wow64ctx.ContextFlags = CONTEXT_CONTROL;
		if (Wow64GetThreadContext(proc.hthread, &wow64ctx) == FALSE)
			return adbg_oops(AdbgError.os);
		wow64ctx.EFlags |= EFLAGS_TF;
		if (Wow64SetThreadContext(proc.hthread, &wow64ctx) == FALSE)
			return adbg_oops(AdbgError.os);
		if (FlushInstructionCache(proc.hproc, null, 0) == FALSE)
			return adbg_oops(AdbgError.os);
		
		return adbg_debugger_continue(proc);
	}
	
	// X86, AMD64
	CONTEXT ctx = void;
	ctx.ContextFlags = CONTEXT_CONTROL;
	if (GetThreadContext(proc.hthread, cast(LPCONTEXT)&ctx) == FALSE)
		return adbg_oops(AdbgError.os);
	ctx.EFlags |= EFLAGS_TF;
	if (SetThreadContext(proc.hthread, cast(LPCONTEXT)&ctx) == FALSE)
		return adbg_oops(AdbgError.os);
	if (FlushInstructionCache(proc.hproc, null, 0) == FALSE)
		return adbg_oops(AdbgError.os);
	
	return adbg_debugger_continue(proc);
} else version (linux) {
	if (ptrace(PT_SINGLESTEP, proc.pid, null, null) < 0) {
		proc.status = AdbgProcessState.unknown;
		return adbg_oops(AdbgError.os);
	}
	
	return 0;
} else version (Posix) {
	switch (proc.status) with (AdbgProcessState) {
	case created:
		// HACK: See HACK in continue function.
		int w = void;
		waitpid(proc.pid, &w, 0);
		break;
	default:
	}
	
	if (ptrace(PT_STEP, proc.pid, null, 0) < 0) {
		proc.status = AdbgProcessState.unknown;
		return adbg_oops(AdbgError.os);
	}
	
	return 0;
} else {
	return adbg_oops(AdbgError.unimplemented);
}
}