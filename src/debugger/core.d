module debugger.core;

import core.stdc.string : memset;
import core.stdc.errno : errno;
import debugger.exception;

extern (C):
__gshared:

version (Windows) {
	import core.sys.windows.windows;
	//SymInitialize, GetFileNameFromHandle, SymGetModuleInfo64,
	//StackWalk64, SymGetSymFromAddr64, SymFromName
	private HANDLE hthread; /// Saved thread handle, DEBUG_INFO doesn't contain one
	private HANDLE hprocess; /// Saved process handle
} else
version (Posix) {
	import core.sys.posix.sys.stat;
	import core.sys.posix.sys.wait :
		waitpid, SIGCONT, WUNTRACED;
	import core.sys.posix.unistd : fork, execve;
	import core.sys.posix.signal : kill, SIGKILL;
	import core.stdc.stdlib : exit;
	import debugger.sys.ptrace;
	private enum __WALL = 0x40000000;
	private pid_t hprocess; /// Saved process ID
}

/// Actions that a user function handler may return
public
enum DebuggerAction {
	exit,	/// Cause the debugger to close the process and stop debugging
	proceed,	/// Continue debugging
	step,	/// Proceed with a single step
}

private
int function(exception_t*) user_function;

/**
 * Load executable image to debug, its starting argument, and starting folder.
 * This does not start the process. On Posix system, stat(2) is used to
 * determine if the file exists beforehand.
 * (Windows) Uses CreateProcessA with DEBUG_ONLY_THIS_PROCESS.
 * (Posix) Uses stat(2), fork(2), ptrace(2) (as PTRACE_TRACEME), and execve(2)
 * Params:
 * 	cmd = Command
 * Returns: Zero on success; Otherwise os error code is returned
 */
int dbg_file(const(char) *cmd) {
	version (Windows) {
		STARTUPINFOA si = void;
		PROCESS_INFORMATION pi = void;
		memset(&si, 0, si.sizeof);
		memset(&pi, 0, pi.sizeof);
		si.cb = STARTUPINFOA.sizeof;
		// DEBUG_ONLY_THIS_PROCESS is recommended over DEBUG_PROCESS
		// because it may create child processes/threads that
		// we probably don't want to catch possible child exceptions
		if (CreateProcessA(cmd, null,
			null, null,
			FALSE, DEBUG_ONLY_THIS_PROCESS,
			null, null,
			&si, &pi) == 0) {
			return GetLastError();
		}
		hthread = pi.hThread;
		hprocess = pi.hProcess;
	} else
	version (Posix) {
		// Verify if file exists and program has access to it
		stat_t st = void;
		if (stat(cmd, &st) == -1)
			return errno;
		// Proceed normally
		hprocess = fork();
		if (hprocess == -1)
			return errno;
		if (hprocess == 0) {
			if (ptrace(PTRACE_TRACEME, 0, null, null))
				return errno;
			int e = execve(cmd, null, null);
			if (e == -1)
				return errno;
			exit(e);
		}
	}
	return 0;
}

/**
 * Attach the debugger to a process ID.
 * (Windows) Uses DebugActiveProcess
 * (Posix) Uses ptrace(PTRACE_SEIZE)
 * Params: pid = Process ID
 * Returns: Non-zero on error: (Posix) errno or (Windows) GetLastError
 */
int dbg_attach(int pid) {
	version (Windows) {
		if (DebugActiveProcess(pid) == FALSE)
			return GetLastError();
	} else
	version (Posix) {
		if (ptrace(PTRACE_SEIZE, pid, null, null) == -1)
			return errno;
	}
	return 0;
}

/**
 * Set the user event handle for handling exceptions.
 * Params: f = Function pointer
 * Returns: Zero on success; Otherwise an error occured
 */
int dbg_sethandle(int function(exception_t *) f) {
	user_function = f;
	return 0;
}

/**
 * Continues the execution of the thread (and/or process) until a new debug
 * event occurs. When an exception occurs, the exception_t structure is
 * populated with debugging information.
 * (Windows) Uses WaitForDebugEvent, filters any but EXCEPTION_DEBUG_EVENT
 * (Posix) Uses ptrace(2) and waitpid(2), filters SIGCONT
 * Returns: Zero on success; Otherwise an error occured
 */
int dbg_loop() {
	if (user_function == null)
		return 4;

	exception_t e = void;
	exception_reg_init(e);

	version (Windows) {
		DEBUG_EVENT de = void;
L_DEBUG_LOOP:
		if (WaitForDebugEvent(&de, INFINITE) == FALSE)
			return 3;

		// Filter events
		switch (de.dwDebugEventCode) {
		case EXCEPTION_DEBUG_EVENT: break;
		case EXIT_PROCESS_DEBUG_EVENT: return 0;
		default:
			ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
			goto L_DEBUG_LOOP;
		}

		exception_tr_windows(e, de);

		CONTEXT c = void;
		c.ContextFlags = CONTEXT_ALL;
		GetThreadContext(hthread, &c);
		exception_ctx_windows(e, c);

		with (DebuggerAction)
		final switch (user_function(&e)) {
		case exit:
			ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_TERMINATE_PROCESS);
			return 0;
		case step:
			version (X86) {
			//	if (de.Exception.dwFirstChance)
			//		--c.Eip;
				c.EFlags |= 0x100;	// Trap Flag, enable single-stepping
			} else
			version (X86_64) {
			//	if (de.Exception.dwFirstChance)
			//		--c.Rip;
				c.EFlags |= 0x100;	// Trap Flag, enable single-stepping
			}
			FlushInstructionCache(hprocess, null, 0);
			SetThreadContext(hthread, &c);
			goto case;
		case proceed:
			ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
			goto L_DEBUG_LOOP;
		}
	} else
	version (Posix) {
		siginfo_t sig = void;
		int wstatus = void;
		int pid = void;
L_DEBUG_LOOP:
		pid = waitpid(hprocess, &wstatus, 0);

		if (pid == -1)
			return 3;

		if (ptrace(PTRACE_GETSIGINFO, pid, null, &sig) == -1)
			return 5;

		// Filter events
		/*switch (sig.si_signo) {
		case SIGSEGV, SIGFPE, SIGILL, SIGBUS, SIGTRAP:
		case SIGINT, SIGTERM, SIGABRT: //TODO: Kill?
			break;
		default: goto L_DEBUG_LOOP; // e.g. SIGCONT
		}*/

		exception_tr_siginfo(e, sig);

		user u = void;
		if (ptrace(PTRACE_GETREGS, pid, null, &u) != -1)
			exception_ctx_user(e, u);

		with (DebuggerAction)
		final switch (user_function(&e)) {
		case exit:
			//TODO: See if ptrace(PTRACE_CONT, pid, null, SIGKILL); is a better choice
			kill(hprocess, SIGKILL); // PTRACE_KILL is deprecated
			return 0;
		case step:
			ptrace(PTRACE_SINGLESTEP, hprocess, null, null);
			goto L_DEBUG_LOOP;
		case proceed:
			ptrace(PTRACE_CONT, hprocess, null, null);
			goto L_DEBUG_LOOP;
		}
	}
}