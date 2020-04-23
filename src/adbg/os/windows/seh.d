/**
 * SEH wrapper for Windows
 *
 * License: BSD 3-Clause
 */
module adbg.os.windows.seh;

version (Windows):
__gshared:

import core.stdc.stdio : printf, puts;
//import os.setjmp;
import adbg.debugger.exception : exception_t;
import adbg.os.windows.def;

/// 
/// 
/// 
extern (C)
public int adbg_seh_init(void function(exception_t*) f) {
	if (SetUnhandledExceptionFilter(cast(void*)&adbg_seh_action) == null)
		return 1;
	adbg_seh_ehandler = f;
	return 0;
}

private:

extern (C)
void function(exception_t*) adbg_seh_ehandler;

alias void* LPTOP_LEVEL_EXCEPTION_FILTER;
alias _CONTEXT* PCONTEXT;
alias _EXCEPTION_RECORD* PEXCEPTION_RECORD;

extern (Windows) LPTOP_LEVEL_EXCEPTION_FILTER
	SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER);

extern (Windows)
uint adbg_seh_action(_EXCEPTION_POINTERS *e) {
	version (X86)
	printf(
	"\n"~
	"*************\n" ~
	"* EXCEPTION *\n" ~
	"*************\n" ~
	"Code: %08X  Address: %08X\n" ~
	"EIP=%08X  EFLAG=%08X\n" ~
	"EAX=%08X  EBX=%08X  ECX=%08X  EDX=%08X\n" ~
	"EDI=%08X  ESI=%08X  EBP=%08X  ESP=%08X\n" ~
	"CS=%04X  DS=%04X  ES=%04X  FS=%04X  GS=%04X  SS=%04X\n",
	e.ExceptionRecord.ExceptionCode, e.ExceptionRecord.ExceptionAddress,
	e.ContextRecord.Eip, e.ContextRecord.EFlags,
	e.ContextRecord.Eax, e.ContextRecord.Ebx,
	e.ContextRecord.Ecx, e.ContextRecord.Edx,
	e.ContextRecord.Edi, e.ContextRecord.Esi,
	e.ContextRecord.Ebp, e.ContextRecord.Esp,
	e.ContextRecord.SegCs, e.ContextRecord.SegDs, e.ContextRecord.SegEs,
	e.ContextRecord.SegFs, e.ContextRecord.SegGs, e.ContextRecord.SegSs
	);
	else
	version (X86_64)
	printf(
	"\n"~
	"*************\n" ~
	"* EXCEPTION *\n" ~
	"*************\n" ~
	"Code: %08X  Address: %llX\n" ~
	"RIP=%016llX  EFLAG=%08X\n" ~
	"RAX=%016llX  RBX=%016llX  RCX=%016llX  RDX=%016llX\n" ~
	"RDI=%016llX  RSI=%016llX  RBP=%016llX  RSP=%016llX\n" ~
	" R8=%016llX   R9=%016llX  R10=%016llX  R11=%016llX\n" ~
	"R12=%016llX  R13=%016llX  R14=%016llX  R15=%016llX\n" ~
	"CS=%04X  DS=%04X  ES=%04X  FS=%04X  GS=%04X  SS=%04X\n",
	e.ExceptionRecord.ExceptionCode, e.ExceptionRecord.ExceptionAddress,
	e.ContextRecord.Rip, e.ContextRecord.EFlags,
	e.ContextRecord.Rax, e.ContextRecord.Rbx, e.ContextRecord.Rcx, e.ContextRecord.Rdx,
	e.ContextRecord.Rdi, e.ContextRecord.Rsi, e.ContextRecord.Rbp, e.ContextRecord.Rsp,
	e.ContextRecord.R8,  e.ContextRecord.R9,  e.ContextRecord.R10, e.ContextRecord.R11,
	e.ContextRecord.R12, e.ContextRecord.R13, e.ContextRecord.R14, e.ContextRecord.R15,
	e.ContextRecord.SegCs, e.ContextRecord.SegDs, e.ContextRecord.SegEs,
	e.ContextRecord.SegFs, e.ContextRecord.SegGs, e.ContextRecord.SegSs
	);

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
	struct _XSAVE_FORMAT { align(16):
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

		version (Win64) {
			M128A [16]XmmRegisters;
			BYTE  [96]Reserved4;
		} else {
			M128A [8]XmmRegisters;
			BYTE  [224]Reserved4;
		}
	}
	/// Win64 _CONTEXT
	struct _CONTEXT { // DECLSPEC_ALIGN(16) is a lie
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
				M128A Xmm0, Xmm1, Xmm2, Xmm3, Xmm4, Xmm5, Xmm6,
					Xmm7, Xmm8, Xmm9, Xmm10, Xmm11, Xmm12,
					Xmm13, Xmm14, Xmm15;
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