module debugger.core;

import core.stdc.string : memset;
import debugger.exception;

extern (C):
__gshared:

version (Windows) {
import core.sys.windows.windows;
//SymInitialize, GetFileNameFromHandle, SymGetModuleInfo64,
//StackWalk64, SymGetSymFromAddr64
//SymFromName
//EXIT_PROCESS_DEBUG_EVENT -> TerminateProcess
//HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug
//HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug
/*
lcContext.Eip--;
lcContext.EFlags |= 0x100; // Set trap flag, which raises "single-step" exception
SetThreadContext(m_cProcessInfo.hThread,&lcContext);
*/
private HANDLE hthread; /// Saved thread handle, DEBUG_INFO doesn't contain one
private HANDLE hprocess; /// 
} else
version (Posix) {
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
 * (Windows) This calls CreateProcessA with DEBUG_ONLY_THIS_PROCESS.
 * (Posix) 
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
			return 1;
		}
		hthread = pi.hThread;
		hprocess = pi.hProcess;
	} else
	version (Posix) {
		// fork
		// execve
	}
	return 0;
}

/**
 * Attach the debugger to a process ID.
 * (Windows) This uses DebugActiveProcess
 * (Posix)
 * Params:
 * 	pid = Process ID
 * Returns: Zero on success; Otherwise an error occured
 */
int dbg_attach(int pid) {
	version (Windows) {
		//TODO: DebugActiveProcess
	} else
	version (Posix) {
		//TODO: ptrace PTRACE_ATTACH
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
 * (Otherwise executes ContinueDebugEvent), calls user function, and longjmp.
 * (Posix) Uses ptrace(2)
 * Returns: Zero on success; Otherwise an error occured
 */
int dbg_continue() {
	version (Windows) {
		DEBUG_EVENT de = void;
L_DEBUG_LOOP:
		if (WaitForDebugEvent(&de, INFINITE) == FALSE)
			return 3;

		exception_t e = void;

		// Filter necessary, may add EXIT_PROCESS_DEBUG_EVENT later
		switch (de.dwDebugEventCode) {
		case EXCEPTION_DEBUG_EVENT:
			prep_exception_debug(e, de.Exception);
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
		prep_exception_context(e, c);

		with (DebuggerAction)
		final switch (user_function(&e)) {
		case exit:
			ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_TERMINATE_PROCESS);
			return 0;
		case step:
			version (X86) {
				//--c.Eip;
				c.EFlags |= 0x100;	// Trap Flag, enable single-stepping
			} else
			version (X86_64) {
				//--c.Rip;
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
L_DEBUG_LOOP:
		// ptrace(2)
		// waitpid(2)
		
		with (DebuggerAction)
		final switch (user_function(&e)) {
		case exit: //TODO: Close handles/process
			return 0;
		case step:
		
			goto case;
		case proceed:
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
int prep_exception_debug(ref exception_t e, ref EXCEPTION_DEBUG_INFO di) {
	e.addr = di.ExceptionRecord.ExceptionAddress;
	e.oscode = di.ExceptionRecord.ExceptionCode;
	switch (e.oscode) {
	case EXCEPTION_IN_PAGE_ERROR:
	case EXCEPTION_ACCESS_VIOLATION:
		e.type = di.ExceptionRecord.ExceptionCode.codetype(
			cast(uint)
			di.ExceptionRecord.ExceptionInformation[0]);
		break;
	default:
		e.type = di.ExceptionRecord.ExceptionCode.codetype;
	}
	return 0;
}
int prep_exception_context(ref exception_t e, ref CONTEXT c) {
	version (X86) {
		e.registers[0].name = "EAX";
		e.registers[0].u32 = c.Eax;
	} else
	version (X86_64) {
		e.registers[0].name = "RAX";
		e.registers[0].u64 = c.Rax;
	}
	return 0;
}
} // version Windows

version (Posix) {
int prep_ex_debug(ref exception_t e, ref sigaction_t sa) {
}
} // version Posix