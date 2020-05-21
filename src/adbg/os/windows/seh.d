/**
 * SEH wrapper for Windows
 *
 * License: BSD 3-Clause
 */
module adbg.os.windows.seh;

version (Windows):

import adbg.debugger.exception;
import adbg.os.windows.def;
import adbg.os.setjmp;

//TODO: adbg_seh_set (Windows)

struct checkpoint_t {
	jmp_buf buffer;
	int value;
	exception_t exception;
}

extern (C)
public checkpoint_t* adbg_seh_set() {
	import core.stdc.string : memcpy;
	if (sehinit == false) {
		if (SetThreadErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX, null) == 0)
			return null; // 1
		if (SetUnhandledExceptionFilter(cast(void*)&adbg_seh_handle) == null)
			return null; // 2
		sehinit = true;
	}
//	mcheckpoint.value = setjmp(mcheckpoint.buffer);
	return &mcheckpoint;
}

private:

__gshared checkpoint_t mcheckpoint;
__gshared bool sehinit;

alias void* LPTOP_LEVEL_EXCEPTION_FILTER;
alias _CONTEXT* PCONTEXT;
alias _EXCEPTION_RECORD* PEXCEPTION_RECORD;

enum SEM_FAILCRITICALERRORS	= 0x0001;
enum SEM_NOGPFAULTERRORBOX	= 0x0002;
enum SEM_NOOPENFILEERRORBOX	= 0x8000;

extern (Windows) {
	LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER);
	BOOL SetThreadErrorMode(DWORD, LPDWORD);
	PVOID AddVectoredExceptionHandler(ULONG, PVECTORED_EXCEPTION_HANDLER);
}

extern (Windows)
uint adbg_seh_handle(_EXCEPTION_POINTERS *e) {
	import core.stdc.stdio : puts;
	import core.sys.windows.winbase :
		EXCEPTION_IN_PAGE_ERROR, EXCEPTION_ACCESS_VIOLATION;
	mcheckpoint.exception.oscode = e.ExceptionRecord.ExceptionCode;
	mcheckpoint.exception.addr = e.ExceptionRecord.ExceptionAddress;
	mcheckpoint.exception.pid = mcheckpoint.exception.tid = 0;
	switch (mcheckpoint.exception.oscode) {
	case EXCEPTION_IN_PAGE_ERROR:
	case EXCEPTION_ACCESS_VIOLATION:
		mcheckpoint.exception.type = adbg_ex_oscode(
			e.ExceptionRecord.ExceptionCode,
			cast(uint)e.ExceptionRecord.ExceptionInformation[0]);
		break;
	default:
		mcheckpoint.exception.type = adbg_ex_oscode(
			e.ExceptionRecord.ExceptionCode);
	}
	adbg_ex_ctx_init(&mcheckpoint.exception, InitPlatform.Native);
	adbg_ex_ctx(&mcheckpoint.exception, cast(CONTEXT*)e.ContextRecord);
//	longjmp(mcheckpoint.buffer, 1);
	return EXCEPTION_EXECUTE_HANDLER;
}

// https://docs.microsoft.com/en-us/windows/desktop/api/WinNT/ns-winnt-_exception_record
struct _EXCEPTION_POINTERS {
	PEXCEPTION_RECORD ExceptionRecord;
	PCONTEXT          ContextRecord;
}

struct _EXCEPTION_RECORD {
	DWORD ExceptionCode;
	DWORD ExceptionFlags;
	_EXCEPTION_RECORD *ExceptionRecord;
	PVOID ExceptionAddress;
	DWORD NumberParameters;
	DWORD [EXCEPTION_MAXIMUM_PARAMETERS]ExceptionInformation;
}

version (X86) {
	struct _WOW64_FLOATING_SAVE_AREA {
		DWORD ControlWord;
		DWORD StatusWord;
		DWORD TagWord;
		DWORD ErrorOffset;
		DWORD ErrorSelector;
		DWORD DataOffset;
		DWORD DataSelector;
		BYTE [WOW64_SIZE_OF_80387_REGISTERS]RegisterArea;
		DWORD Cr0NpxState;
	}
	/// Win32 _CONTEXT
	struct _CONTEXT {
		DWORD ContextFlags;
		//
		// Debug registers
		//
		DWORD Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
		//
		// Float
		//
		_WOW64_FLOATING_SAVE_AREA FloatSave;
		//
		// Segments
		//
		DWORD SegGs, SegFs, SegEs, SegDs;
		//
		// General registers
		//
		DWORD Edi, Esi, Ebx, Edx, Ecx, Eax, Ebp, Eip, SegCs;
		//
		// Flags
		//
		DWORD EFlags, Esp, SegSs;
		BYTE [WOW64_MAXIMUM_SUPPORTED_EXTENSION]ExtendedRegisters;
	}
} else
version (X86_64) {
	align(16) struct _XSAVE_FORMAT {
		WORD  ControlWord;
		WORD  StatusWord;
		BYTE  TagWord;
		BYTE  Reserved1;
		WORD  ErrorOpcode;
		DWORD ErrorOffset;
		WORD  ErrorSelector;
		WORD  Reserved2;
		DWORD DataOffset;
		WORD  DataSelector;
		WORD  Reserved3;
		DWORD MxCsr;
		DWORD MxCsr_Mask;
		M128A [8]FloatRegisters;
		M128A [16]XmmRegisters;
		BYTE  [96]Reserved4;
	}
	/// Win64 _CONTEXT
	align(16) struct _CONTEXT {
		//
		// Register parameter home addresses.
		//
		// N.B. These fields are for convience - they could be used to
		//      extend the context record in the future.
		//
		DWORD64 P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
		//
		// Control flags.
		//
		DWORD ContextFlags;
		DWORD MxCsr;
		//
		// Segment Registers and processor flags.
		//
		WORD SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
		DWORD EFlags;
		//
		// Debug registers
		//
		DWORD64 Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
		//
		// Integer registers.
		//
		DWORD64 Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi,
			R8, R9, R10, R11, R12, R13, R14, R15;
		//
		// Program counter.
		//
		DWORD64 Rip;
		//
		// Floating point state.
		//
		union {
			_XSAVE_FORMAT FltSave;
			struct {
				M128A [2]Header;
				M128A [8]Legacy;
				M128A [16]Xmm; // Originally called Xmm0 to Xmm15
			}
		}
		//
		// Vector registers.
		//
		M128A	[26]VectorRegister;
		DWORD64 VectorControl;
		//
		// Special debug control registers.
		//
		DWORD64 DebugControl, LastBranchToRip, LastBranchFromRip,
			LastExceptionToRip, LastExceptionFromRip;
	}
}

struct M128A { align(1):
	ulong low; ulong high;
}