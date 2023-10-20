/// (Work in progress) Structued Exception Handling wrapper.
/// 
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.v2.debugger.seh;

//TODO: adbg_seh_unset
//TODO: Would be cool to have try/catch mechanic
//      setjmp is broken on Win64 :(

import adbg.error;

version (Windows) {
	import adbg.v2.debugger.exception;
	import adbg.include.windows.windef;
	import adbg.include.c.setjmp;
	
	private enum SEM = SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX;

	private alias void* LPTOP_LEVEL_EXCEPTION_FILTER;
	private alias _CONTEXT* PCONTEXT;
	private alias _EXCEPTION_RECORD* PEXCEPTION_RECORD;

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
	import adbg.v2.debugger.exception;
	import adbg.include.c.setjmp;
	import core.sys.posix.signal;
	import core.sys.posix.ucontext;
	
	private enum NO_SIGACTION = cast(sigaction_t*)0;
}

extern (C):

version (none) // Disabled until setjmp works on Win64
public int adbg_seh_enable(int function(adbg_exception_t*) func) {
	if (func == null)
		return adbg_oops(AdbgError.nullArgument);
	
	version (Windows) {
		if (checkpoint.enabled == false) {
			if (SetThreadErrorMode(SEM, null) == 0)
				return adbg_oops(AdbgError.os);
			if (SetUnhandledExceptionFilter(cast(void*)&adbg_seh_catch) == null)
				return adbg_oops(AdbgError.os);
			checkpoint.enabled = true;
		}
	} else version (Posix) {
		import core.stdc.string : memcpy;
		if (checkpoint.enabled == false) {
			sigaction_t sa = void;
			sigemptyset(&sa.sa_mask);
			sa.sa_flags = SA_SIGINFO;
			sa.sa_sigaction = &adbg_seh_catch;
			if (sigaction(SIGSEGV, &sa, NO_SIGACTION) == -1 ||
				sigaction(SIGTRAP, &sa, NO_SIGACTION) == -1 ||
				sigaction(SIGFPE, &sa, NO_SIGACTION) == -1 ||
				sigaction(SIGILL, &sa, NO_SIGACTION) == -1 ||
				sigaction(SIGBUS, &sa, NO_SIGACTION) == -1) {
				return adbg_oops(AdbgError.os); // Well, crt, but you know
			}
			checkpoint.enabled = true;
		}
//		memcpy(&mjbuf, &c.buffer, jmp_buf.sizeof);
//		if ((c.value = setjmp(mjbuf)) != 0)
//			memcpy(&c.exception, &mexception, exception_t.sizeof);
	}
	
	checkpoint.user = func;
	return 0;
}

private:

struct adbg_checkpoint_t {
	adbg_exception_t exception;
	int function(adbg_exception_t*) user;
	bool enabled;
}

__gshared adbg_checkpoint_t checkpoint;

version (Windows)
extern (Windows)
uint adbg_seh_catch(_EXCEPTION_POINTERS *e) {
	import core.sys.windows.winbase :
		EXCEPTION_IN_PAGE_ERROR, EXCEPTION_ACCESS_VIOLATION;
	
	checkpoint.exception.oscode = e.ExceptionRecord.ExceptionCode;
	checkpoint.exception.faultz = cast(size_t)e.ExceptionRecord.ExceptionAddress;
	checkpoint.exception.pid = checkpoint.exception.tid = 0;
	
	switch (checkpoint.exception.oscode) {
	case EXCEPTION_IN_PAGE_ERROR:
	case EXCEPTION_ACCESS_VIOLATION:
		checkpoint.exception.type = adbg_exception_from_os(
			e.ExceptionRecord.ExceptionCode,
			cast(uint)e.ExceptionRecord.ExceptionInformation[0]);
		break;
	default:
		checkpoint.exception.type = adbg_exception_from_os(
			e.ExceptionRecord.ExceptionCode);
	}
	
	//TODO: Call user function
	
//	adbg_ctx_init(&mcheckpoint.exception.registers);
//	adbg_ctx_os(&mcheckpoint.exception.registers, cast(CONTEXT*)e.ContextRecord);
//	longjmp(mcheckpoint.buffer, 1);
	return EXCEPTION_EXECUTE_HANDLER;
}

/// See http://man7.org/linux/man-pages/man2/sigaction.2.html
version (Posix)
void adbg_seh_catch(int sig, siginfo_t *si, void *p) {
	ucontext_t *ctx = cast(ucontext_t*)p;
	mcontext_t *m = &ctx.uc_mcontext;

	checkpoint.exception.oscode = sig;
	// HACK: Missing ref'd D bindings to Musl
	/*version (CRuntime_Glibc)
		checkpoint.exception.fault_address = cast(ulong)si._sifields._sigfault.si_addr;
	else version (CRuntime_Musl)
		checkpoint.exception.fault_address = cast(ulong)si.__si_fields.__sigfault.si_addr;
	else static assert(0, "hack me");*/

	/+mexception.pid = mexception.tid = 0;
	adbg_ctx_init(&mexception.registers);
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
		} else
		version (CRuntime_Musl) {
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
	} else
	version (X86_64) {
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
		} else
		version (CRuntime_Musl) {
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

	//TODO: Call user function
}
