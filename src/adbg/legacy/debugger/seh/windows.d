/**
 * SEH wrapper for Windows
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module adbg.legacy.debugger.seh.windows;

version (Windows):

import adbg.legacy.debugger.exception;
import adbg.include.windows.windef;
import adbg.include.c.setjmp;

struct checkpoint_t {
	jmp_buf buffer;
	int value;
	exception_t exception;
}

extern (C)
public checkpoint_t* adbg_seh_enable_() {
	import core.stdc.string : memcpy;
	if (sehinit == false) {
		if (SetThreadErrorMode(SEM, null) == 0)
			return null; // 1
		if (SetUnhandledExceptionFilter(cast(void*)&adbg_seh_handle) == null)
			return null; // 2
		sehinit = true;
	}
	mcheckpoint.value = setjmp(mcheckpoint.buffer);
	return &mcheckpoint;
}

private:

enum SEM = SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX;

__gshared checkpoint_t mcheckpoint;
__gshared bool sehinit;

alias void* LPTOP_LEVEL_EXCEPTION_FILTER;
alias _CONTEXT* PCONTEXT;
alias _EXCEPTION_RECORD* PEXCEPTION_RECORD;

/// The system does not display the critical-error-handler message box.
/// Instead, the system sends the error to the calling process. 
enum SEM_FAILCRITICALERRORS	= 0x0001;
/// The system does not display the Windows Error Reporting dialog.
enum SEM_NOGPFAULTERRORBOX	= 0x0002;
/// The OpenFile function does not display a message box when it fails to find
/// a file. Instead, the error is returned to the caller. This error mode
/// overrides the OF_PROMPT flag. 
enum SEM_NOOPENFILEERRORBOX	= 0x8000;

extern (Windows) {
	LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER);
	BOOL SetThreadErrorMode(DWORD, LPDWORD);
	PVOID AddVectoredExceptionHandler(ULONG, PVECTORED_EXCEPTION_HANDLER);
}

extern (Windows)
uint adbg_seh_handle(_EXCEPTION_POINTERS *e) {
	import core.sys.windows.winbase :
		EXCEPTION_IN_PAGE_ERROR, EXCEPTION_ACCESS_VIOLATION;
	mcheckpoint.exception.oscode = e.ExceptionRecord.ExceptionCode;
	mcheckpoint.exception.fault.raw = e.ExceptionRecord.ExceptionAddress;
	mcheckpoint.exception.pid = mcheckpoint.exception.tid = 0;
	switch (mcheckpoint.exception.oscode) {
	case EXCEPTION_IN_PAGE_ERROR:
	case EXCEPTION_ACCESS_VIOLATION:
		mcheckpoint.exception.type = adbg_exception_os(
			e.ExceptionRecord.ExceptionCode,
			cast(uint)e.ExceptionRecord.ExceptionInformation[0]);
		break;
	default:
		mcheckpoint.exception.type = adbg_exception_os(
			e.ExceptionRecord.ExceptionCode);
	}
	
//	adbg_ctx_init(&mcheckpoint.exception.registers);
//	adbg_ctx_os(&mcheckpoint.exception.registers, cast(CONTEXT*)e.ContextRecord);
//	longjmp(mcheckpoint.buffer, 1);
	return EXCEPTION_EXECUTE_HANDLER;
}