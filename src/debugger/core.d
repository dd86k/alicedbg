module debugger.core;

import core.stdc.string : memset;
import debugger.exception;

extern (C):
__gshared:

version (Windows) {
import core.sys.windows.windows;
//SymInitialize, GetFileNameFromHandle, SymGetModuleInfo64,
//StackWalk64, SymGetSymFromAddr64, SymFromName
private HANDLE hthread; /// Saved thread handle, DEBUG_INFO doesn't contain one
private HANDLE hprocess; /// 
} else
version (Posix) {
private import debugger.sys.ptrace;
private import core.sys.posix.signal, core.sys.posix.sys.wait;
private import core.sys.linux.unistd;
import debugger.sys.user : user;
private enum __WALL = 0x40000000;
// temp
import core.stdc.stdio, core.stdc.stdlib;
private pid_t hprocess;
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
 * This does not start the process.
 * (Windows) Uses CreateProcessA with DEBUG_ONLY_THIS_PROCESS.
 * (Posix) Uses fork(2), ptrace(PTRACE_TRACEME), and execl(2)
 * Params:
 * 	cmd = Command
 * Returns: Zero on success; Otherwise an error occured
 */
int dbg_file(const(char) *cmd) {
	version (Windows) {
		// LoadLibrary or LoadLibraryEx or CreateProcess+ResumeThread
		// if ResumeThread alone doesn't work, try DEBUG_PROCESS+WaitForDebugEvent
		STARTUPINFOA si = void;
		PROCESS_INFORMATION pi = void;
		memset(&si, 0, si.sizeof);
		memset(&pi, 0, pi.sizeof);
		si.cb = STARTUPINFOA.sizeof;
		// DEBUG_ONLY_THIS_PROCESS is recommended over DEBUG_PROCESS
		// because it may create child processes/threads that
		// we probably don't want to catch possible child exceptions
		if (CreateProcessA(cast(char*)cmd, null,
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
		hprocess = fork();
		if (hprocess == -1)
			return 1;
		if (hprocess == 0) {
			if (ptrace(PTRACE_TRACEME, 0, null, null))
				return 2;
			exit(execl(cmd, null, null));
		}
	}
	return 0;
}

/**
 * Attach the debugger to a process ID.
 * (Windows) Uses DebugActiveProcess
 * (Posix) Uses ptrace(PTRACE_SEIZE)
 * Params:
 * 	pid = Process ID
 * Returns: Zero on success; Otherwise an error (Windows) Returns GetLastError
 */
int dbg_attach(int pid) {
	version (Windows) {
		if (DebugActiveProcess(pid) == FALSE)
			return GetLastError();
	} else
	version (Posix) {
		if (ptrace(PTRACE_SEIZE, pid, null, null) == -1)
			return 2;
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
 * (Windows) Uses WaitForDebugEvent, filters for EXCEPTION_DEBUG_EVENT
 * (Otherwise executes ContinueDebugEvent)
 * (Posix) Uses ptrace(2) and waitid(2)
 * Returns: Zero on success; Otherwise an error occured
 */
int dbg_loop() {
	exception_t e = void;
	version (Windows) {
		DEBUG_EVENT de = void;
L_DEBUG_LOOP:
		if (WaitForDebugEvent(&de, INFINITE) == FALSE)
			return 3;

		// Filter necessary, may add EXIT_PROCESS_DEBUG_EVENT later
		switch (de.dwDebugEventCode) {
		case EXCEPTION_DEBUG_EVENT:
			prep_ex_debug(e, de.Exception);
			break;
		case EXIT_PROCESS_DEBUG_EVENT: return 0;
		default:
			ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
			goto L_DEBUG_LOOP;
		}

		e.pid = de.dwProcessId;
		e.tid = de.dwThreadId;

		CONTEXT c = void;
		c.ContextFlags = CONTEXT_ALL;
		GetThreadContext(hthread, &c);
		prep_ex_context(e, c);

		with (DebuggerAction)
		final switch (user_function(&e)) {
		case exit:
			ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_TERMINATE_PROCESS);
			return 0;
		case step:
			version (X86) {
				if (de.Exception.dwFirstChance)
					--c.Eip;
				c.EFlags |= 0x100;	// Trap Flag, enable single-stepping
			} else
			version (X86_64) {
				if (de.Exception.dwFirstChance)
					--c.Rip;
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
L_DEBUG_LOOP:
		// Linux examples use __WALL and is supposed to imply (but does
		// not include) WEXITED | WSTOPPED but does not act like it
		// waitid(2) returns 0 or -1 so it's pointless to verify its value
		int id = waitid(idtype_t.P_ALL, 0, &sig, WEXITED | WSTOPPED);
		if (id == -1)
			return 3;
		if (sig._sifields._sigchld.si_status == SIGCONT)
			goto L_DEBUG_LOOP;
		
		prep_ex_sig(e, sig);
		
		user u;
		ptrace(PTRACE_GETREGS, hprocess, null, &u);
		prep_ex_regs(e, u);
		
		e.pid = sig._sifields._kill.si_pid;
		e.tid = 0;
		
		with (DebuggerAction)
		final switch (user_function(&e)) {
		case exit:
			ptrace(PTRACE_KILL, hprocess, null, null);
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

private:

//
// Exception preparing functions
// OS specific
//

version (Windows) {
int prep_ex_debug(ref exception_t e, ref EXCEPTION_DEBUG_INFO di) {
	e.addr = di.ExceptionRecord.ExceptionAddress;
	e.oscode = di.ExceptionRecord.ExceptionCode;
	switch (e.oscode) {
	case EXCEPTION_IN_PAGE_ERROR:
	case EXCEPTION_ACCESS_VIOLATION:
		e.type = codetype(di.ExceptionRecord.ExceptionCode,
			cast(uint)di.ExceptionRecord.ExceptionInformation[0]);
		break;
	default:
		e.type = codetype(di.ExceptionRecord.ExceptionCode);
	}
	return 0;
}
int prep_ex_context(ref exception_t e, ref CONTEXT c) {
	version (X86) {
		e.registers[0].name = "EAX";
		e.registers[0].u32 = c.Eax;
		e.registers[0].type = RegisterType.U32;
	} else
	version (X86_64) {
		e.registers[0].name = "RAX";
		e.registers[0].u64 = c.Rax;
		e.registers[0].type = RegisterType.U64;
	}
	return 0;
}
} else // version Windows
version (Posix) {
int prep_ex_sig(ref exception_t e, ref siginfo_t si) {
	e.tid = 0;
	e.addr = si._sifields._sigfault.si_addr;
	e.oscode = si._sifields._sigchld.si_status;
	e.type = codetype(si._sifields._sigchld.si_status, si.si_code);
	return 0;
}
int prep_ex_regs(ref exception_t e, ref user u) {
	version (X86) {
		e.registers[0].name = "EAX";
		e.registers[0].u32 = u.regs.eax;
		e.registers[0].type = RegisterType.U32;
	} else
	version (X86_64) {
		e.registers[0].name = "RAX";
		e.registers[0].u64 = u.regs.rax;
		e.registers[0].type = RegisterType.U64;
	}
	return 0;
}
} // version Posix