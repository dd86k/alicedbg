/// Runtime utilities for self diagnosis.
/// 
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.self;

import adbg.include.c.stdlib; // malloc, calloc, free, exit;
import adbg.error;
import adbg.process.base;
import adbg.process.exception;

//TODO: (Windows) Consider using RtlInstallFunctionTableCallback and RtlAddFunctionTable

version (Windows) {
	import adbg.include.windows.winnt;
	import core.sys.windows.winbase;

	private alias void* LPTOP_LEVEL_EXCEPTION_FILTER;

	/// The system does not display the critical-error-handler message box.
	/// Instead, the system sends the error to the calling process. 
	private enum SEM_FAILCRITICALERRORS	= 0x0001;
	/// The system does not display the Windows Error Reporting dialog.
	private enum SEM_NOGPFAULTERRORBOX	= 0x0002;
	/// The OpenFile function does not display a message box when it fails to find
	/// a file. Instead, the error is returned to the caller. This error mode
	/// overrides the OF_PROMPT flag. 
	private enum SEM_NOOPENFILEERRORBOX	= 0x8000;

	private extern (Windows) {
		LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER);
		BOOL SetThreadErrorMode(DWORD, LPDWORD);
		PVOID AddVectoredExceptionHandler(ULONG, PVECTORED_EXCEPTION_HANDLER);
	}
} else version (Posix) {
	import adbg.include.posix.unistd;
	import adbg.include.posix.ptrace;
	import core.stdc.string : strstr;
	import core.sys.posix.signal;
	import core.sys.posix.ucontext;
	import core.sys.posix.fcntl;
	
	private enum NO_SIGACTION = cast(sigaction_t*)0;
}

extern (C):

adbg_process_t* adbg_self_process() {
	__gshared adbg_process_t proc;
	proc.creation = AdbgCreation.unloaded;
	proc.status = AdbgProcStatus.running;
version (Windows) {
	proc.hpid = GetCurrentProcess();
	proc.htid = GetCurrentThread();
	proc.pid = GetCurrentProcessId();
	proc.tid = GetCurrentThreadId();
} else version (Posix) {
	proc.pid = getpid();
}
	return &proc;
}

/// Insert a tracee break.
void adbg_self_break() {
version (Windows) {
	DebugBreak();
} else version (Posix) {
	ptrace(PT_TRACEME, 0, null, null);
	raise(SIGSTOP);
} else static assert(0, "Implement me");
}

/// Is this process being debugged?
/// Returns: True if a debugger is attached to this process.
bool adbg_self_is_debugged() {
version (Windows) {
	return IsDebuggerPresent() == TRUE;
} else version (linux) { // https://stackoverflow.com/a/24969863
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
} else
	static assert(0, "Implement me");
}

/// Set a custom crash handler.
///
/// This is useful for catching critical exceptions gracefully before
/// closing the application, such as writing a crash log or minidump.
///
/// Note: Not respected by some exceptions, like buffer overruns.
/// Params: func = User handler function.
/// Returns: Zero on success; Non-zero on error.
int adbg_self_set_crashhandler(void function(adbg_process_t*, adbg_exception_t*) func) {
	if (func == null)
		return adbg_oops(AdbgError.invalidArgument);
	
version (Windows) {
	if (SetThreadErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX, null) == 0 ||
		SetUnhandledExceptionFilter(cast(void*)&adbg_internal_handler) == null)
		return adbg_oops(AdbgError.os);
} else version (Posix) {
	sigaction_t sa = void;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = &adbg_internal_handler;
	
	static immutable int[5] __ossignals = [
		SIGSEGV, SIGTRAP, SIGFPE, SIGILL, SIGBUS
	];
	foreach (sig; __ossignals) {
		if (sigaction(sig, &sa, NO_SIGACTION) < 0)
			return adbg_oops(AdbgError.os);
	}
} // version (Posix)
	
	__ufunction = func;
	return 0;
}

private:

__gshared void function(adbg_process_t*, adbg_exception_t*) __ufunction;

version (Windows)
extern (Windows)
uint adbg_internal_handler(EXCEPTION_POINTERS *e) {
	// Setup exception info
	adbg_exception_t ex = void;
	ex.oscode = e.ExceptionRecord.ExceptionCode;
	ex.faultz = cast(size_t)e.ExceptionRecord.ExceptionAddress;
	ex.pid = GetCurrentProcessId();
	ex.tid = GetCurrentThreadId();
	with (e.ExceptionRecord) switch (ex.oscode) {
	case EXCEPTION_IN_PAGE_ERROR:
	case EXCEPTION_ACCESS_VIOLATION:
		ex.type = adbg_exception_from_os(ExceptionCode, cast(uint)ExceptionInformation[0]);
		break;
	default:
		ex.type = adbg_exception_from_os(ExceptionCode);
	}
	
	// Call user function
	__ufunction(adbg_self_process(), &ex);
	return EXCEPTION_EXECUTE_HANDLER;
}

/// See http://man7.org/linux/man-pages/man2/sigaction.2.html
version (Posix)
void adbg_internal_handler(int sig, siginfo_t *si, void *p) {
	ucontext_t *uctx = cast(ucontext_t*)p;
	mcontext_t *mctx = &uctx.uc_mcontext;

	// Setup exception info
	adbg_exception_t ex = void;
	ex.oscode = sig;
	ex.type = adbg_exception_from_os(si.si_signo, si.si_code);
	ex.pid = getpid();
	ex.tid = 0; // NOTE: gettid(2) is only available on Linux
	switch (sig) {
	case SIGILL, SIGSEGV, SIGFPE, SIGBUS:
		ex.fault_address = cast(size_t)si._sifields._sigfault.si_addr;
		break;
	default:
		ex.fault_address = 0;
	}
	
	// Setup register info
	//adbg_registers_t regs = void;
	//adbg_registers_config(&regs, adbg_machine_default());
	
	__ufunction(adbg_self_process(), &ex);
	
	/+adbg_ctx_init(&mexception.registers);
	version (X86) {
		mexception.registers.count = 10;
		version (CRuntime_Glibc) {
			mexception.registers.items[0].u32 = m.gregs[REG_EIP];
			mexception.registers.items[1].u32 = m.gregs[REG_EFL];
			mexception.registers.items[2].u32 = m.gregs[REG_EAX];
			mexception.registers.items[3].u32 = m.gregs[REG_EBX];
			mexception.registers.items[4].u32 = m.gregs[REG_ECX];
			mexception.registers.items[5].u32 = m.gregs[REG_EDX];
			mexception.registers.items[6].u32 = m.gregs[REG_ESP];
			mexception.registers.items[7].u32 = m.gregs[REG_EBP];
			mexception.registers.items[8].u32 = m.gregs[REG_ESI];
			mexception.registers.items[9].u32 = m.gregs[REG_EDI];
			/*
			m.gregs[REG_CS], m.gregs[REG_DS], m.gregs[REG_ES],
			m.gregs[REG_FS], m.gregs[REG_GS], m.gregs[REG_SS],
			*/
		} else version (CRuntime_Musl) {
			mexception.registers.items[0].u32 = m.__space[REG_EIP];
			mexception.registers.items[1].u32 = m.__space[REG_EFL];
			mexception.registers.items[2].u32 = m.__space[REG_EAX];
			mexception.registers.items[3].u32 = m.__space[REG_EBX];
			mexception.registers.items[4].u32 = m.__space[REG_ECX];
			mexception.registers.items[5].u32 = m.__space[REG_EDX];
			mexception.registers.items[6].u32 = m.__space[REG_ESP];
			mexception.registers.items[7].u32 = m.__space[REG_EBP];
			mexception.registers.items[8].u32 = m.__space[REG_ESI];
			mexception.registers.items[9].u32 = m.__space[REG_EDI];
		}
	} else version (X86_64) {
		mexception.registers.count = 18;
		version (CRuntime_Glibc) {
			mexception.registers.items[0].u64 = m.gregs[REG_RIP];
			mexception.registers.items[1].u32 = cast(uint)m.gregs[REG_EFL];
			mexception.registers.items[2].u64 = m.gregs[REG_RAX];
			mexception.registers.items[3].u64 = m.gregs[REG_RBX];
			mexception.registers.items[4].u64 = m.gregs[REG_RCX];
			mexception.registers.items[5].u64 = m.gregs[REG_RDX];
			mexception.registers.items[6].u64 = m.gregs[REG_RSP];
			mexception.registers.items[7].u64 = m.gregs[REG_RBP];
			mexception.registers.items[8].u64 = m.gregs[REG_RSI];
			mexception.registers.items[9].u64 = m.gregs[REG_RDI];
			mexception.registers.items[10].u64 = m.gregs[REG_R8];
			mexception.registers.items[11].u64 = m.gregs[REG_R9];
			mexception.registers.items[12].u64 = m.gregs[REG_R10];
			mexception.registers.items[13].u64 = m.gregs[REG_R11];
			mexception.registers.items[14].u64 = m.gregs[REG_R12];
			mexception.registers.items[15].u64 = m.gregs[REG_R13];
			mexception.registers.items[16].u64 = m.gregs[REG_R14];
			mexception.registers.items[17].u64 = m.gregs[REG_R15];
			/*
			cast(ushort)m.gregs[REG_CSGSFS],
			cast(ushort)(m.gregs[REG_CSGSFS] >> 16),
			cast(ushort)(m.gregs[REG_CSGSFS] >> 32),
			*/
		} else version (CRuntime_Musl) {
			mexception.registers.items[0].u64 = m.__space[16];
			mexception.registers.items[1].u32 = cast(uint)m.__space[17];
			mexception.registers.items[2].u64 = m.__space[13];
			mexception.registers.items[3].u64 = m.__space[11];
			mexception.registers.items[4].u64 = m.__space[14];
			mexception.registers.items[5].u64 = m.__space[12];
			mexception.registers.items[6].u64 = m.__space[15];
			mexception.registers.items[7].u64 = m.__space[10];
			mexception.registers.items[8].u64 = m.__space[9];
			mexception.registers.items[9].u64 = m.__space[8];
			mexception.registers.items[10].u64 = m.__space[0];
			mexception.registers.items[11].u64 = m.__space[1];
			mexception.registers.items[12].u64 = m.__space[2];
			mexception.registers.items[13].u64 = m.__space[3];
			mexception.registers.items[14].u64 = m.__space[4];
			mexception.registers.items[15].u64 = m.__space[5];
			mexception.registers.items[16].u64 = m.__space[6];
			mexception.registers.items[17].u64 = m.__space[7];
		}
	}+/
}
