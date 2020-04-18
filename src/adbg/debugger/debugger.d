/**
 * Debugger core
 *
 * License: BSD 3-Clause
 */
module adbg.debugger.debugger;

import core.stdc.string : memset;
import core.stdc.errno : errno;
import adbg.debugger.exception;

extern (C):
__gshared:

version (Windows) {
	import core.sys.windows.windows;
	import adbg.debugger.sys.wow64;
	//SymInitialize, GetFileNameFromHandle, SymGetModuleInfo64,
	//StackWalk64, SymGetSymFromAddr64, SymFromName
	private HANDLE hthread; /// Saved thread handle, DEBUG_INFO doesn't contain one
	private HANDLE hprocess; /// Saved process handle
	version (Win64)
		private int processWOW64;
} else
version (Posix) {
	import core.sys.posix.sys.stat;
	import core.sys.posix.sys.wait :
		waitpid, SIGCONT, WUNTRACED;
	import core.sys.posix.unistd : fork, execve;
	import core.sys.posix.signal : kill, SIGKILL;
	import core.stdc.stdlib : exit;
	import debugger.sys.ptrace;
	import debugger.sys.user;
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

private __gshared
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
int adbg_load(const(char) *cmd) {
	version (Windows) {
		STARTUPINFOA si = void;
		PROCESS_INFORMATION pi = void;
		memset(&si, 0, si.sizeof); // D init fields might NOT BE zero
		memset(&pi, 0, pi.sizeof); // Might also be faster to memset
		si.cb = STARTUPINFOA.sizeof;
		// Not using DEBUG_ONLY_THIS_PROCESS because our posix
		// counterpart is using -1 (all children) for waitpid.
		if (CreateProcessA(cmd, null,
			null, null,
			FALSE, DEBUG_PROCESS,
			null, null, &si, &pi) == 0)
			return GetLastError();
		hthread = pi.hThread;
		hprocess = pi.hProcess;
		// Microsoft recommends getting function pointer with
		// GetProcAddress("kernel32", "IsWow64Process"), but so far
		// only 64-bit versions of Windows really have WOW64.
		// Nevertheless, required to support 32-bit processes under
		// 64-bit builds.
		version (Win64) {
			if (IsWow64Process(hprocess, &processWOW64))
				return GetLastError();
		}
	} else
	version (Posix) {
		// Verify if file exists and we has access to it
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
			if (execve(cmd, null, null) == -1)
				return errno;
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
int adbg_attach(int pid) {
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
int adbg_sethandler(int function(exception_t*) f) {
	user_function = f;
	return 0;
}

/**
 * Enter debugging loop. Continues execution of the process until a new debug
 * event occurs. When an exception occurs, the exception_t structure is
 * populated with debugging information.
 * (Windows) Uses WaitForDebugEvent, filters any but EXCEPTION_DEBUG_EVENT
 * (Posix) Uses ptrace(2) and waitpid(2), filters SIGCONT
 * Returns: Zero on success; Otherwise an error occured
 */
int adbg_enterloop() {
	if (user_function == null)
		return 4;

	exception_t e = void;

	version (Win64) {
		adbg_ex_reg_init(&e, processWOW64 ? InitPlatform.x86 : InitPlatform.Native);
	} else
		adbg_ex_reg_init(&e, InitPlatform.Native);

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

		e.pid = de.dwProcessId;
		e.tid = de.dwThreadId;
		e.addr = de.Exception.ExceptionRecord.ExceptionAddress;
		e.oscode = de.Exception.ExceptionRecord.ExceptionCode;
		switch (e.oscode) {
		case EXCEPTION_IN_PAGE_ERROR:
		case EXCEPTION_ACCESS_VIOLATION:
			e.type = adbg_ex_oscode(
				de.Exception.ExceptionRecord.ExceptionCode,
				cast(uint)de.Exception.ExceptionRecord.ExceptionInformation[0]);
			break;
		default:
			e.type = adbg_ex_oscode(
				de.Exception.ExceptionRecord.ExceptionCode);
		}

		CONTEXT ctx = void;
		version (Win64) {
			WOW64_CONTEXT ctxwow64 = void;
			if (processWOW64) {
				ctxwow64.ContextFlags = CONTEXT_ALL;
				Wow64GetThreadContext(hthread, &ctxwow64);
				adbg_ex_ctx_win_wow64(&e, &ctxwow64);
			} else {
				ctx.ContextFlags = CONTEXT_ALL;
				GetThreadContext(hthread, &ctx);
				adbg_ex_ctx_win(&e, &ctx);
			}
		} else {
			ctx.ContextFlags = CONTEXT_ALL;
			GetThreadContext(hthread, &ctx);
			adbg_ex_ctx_win(&e, &ctx);
		}

		with (DebuggerAction)
		final switch (user_function(&e)) {
		case exit:
			ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_TERMINATE_PROCESS);
			return 0;
		case step:
			// Enable single-stepping via Trap flag
			version (X86) {
				ctx.EFlags |= 0x100;
			} else
			version (X86_64) {
				if (processWOW64)
					ctxwow64.EFlags |= 0x100;
				else
					ctx.EFlags |= 0x100;
			}
			FlushInstructionCache(hprocess, null, 0);
			version (Win64) {
				if (processWOW64) {
					Wow64SetThreadContext(hthread, &ctxwow64);
				} else {
					SetThreadContext(hthread, &ctx);
				}
			} else {
				SetThreadContext(hthread, &ctx);
			}
			goto case;
		case proceed:
			if (ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE) == 0)
				return GetLastError();
			goto L_DEBUG_LOOP;
		}
	} else
	version (Posix) {
		int wstatus = void;
L_DEBUG_LOOP:
		int pid = waitpid(-1, &wstatus, 0);

		if (pid == -1)
			return 3;

		// Bits  Desc
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
		if ((wstatus & 0x7F) != 0x7F)
			return chld_signo;

		// Filter signals
		//switch (sig.si_signo) {
		switch (chld_signo) {
//		case SIGSEGV, SIGFPE, SIGILL, SIGBUS, SIGTRAP:
//		case SIGINT, SIGTERM, SIGABRT: //TODO: Kill?
//			break;
		case SIGCONT: goto L_DEBUG_LOOP;
		default:
		}

		e.pid = pid;
		e.tid = 0;
		e.oscode = chld_signo;
		e.type = adbg_ex_oscode(chld_signo);

		user_regs_struct u = void;
		if (ptrace(PTRACE_GETREGS, pid, null, &u) == -1)
			return 6;

		adbg_ex_ctx_user(&e, &u);

		if (chld_signo == SIGTRAP) {
			//TODO: Find a way to find the fault address
			// And make it readable (via mprotect?)
			// - linux does not fill si_addr on a SIGTRAP from a ptrace event
			//   - see sigaction(2)
			// - linux *only* fills user_regs_struct for "user area"
			//   - see arch/x86/include/asm/user_64.h
			// - using EIP/RIP is NOT a good idea
			//   - IP ALWAYS point to NEXT instruction
			//   - First SIGTRAP does NOT contain int3 (Windows does, though)
			e.addr = null;
		} else {
			siginfo_t sig = void;
			if (ptrace(PTRACE_GETSIGINFO, pid, null, &sig) == -1)
				return 5;
			e.addr = sig._sifields._sigfault.si_addr;
		}

		with (DebuggerAction)
		final switch (user_function(&e)) {
		case exit:
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