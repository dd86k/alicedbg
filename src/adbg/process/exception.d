/// Exception structure and helpers.
///
/// Windows: um/minwinbase.h
///
/// Linux: include/uapi/asm-generic/siginfo.h
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.process.exception;

import adbg.error;
import adbg.process.thread : adbg_process_thread_t;

version (Windows) {
	import core.sys.windows.winbase;
	private enum {
		// ntstatus.h
		// Missing WoW64 status codes
		STATUS_WX86_UNSIMULATE	= 0x4000001C,	/// WOW64 exception code
		STATUS_WX86_CONTINUE	= 0x4000001D,	/// Ditto
		STATUS_WX86_SINGLE_STEP	= 0x4000001E,	/// Ditto
		STATUS_WX86_BREAKPOINT	= 0x4000001F,	/// Ditto
		STATUS_WX86_EXCEPTION_CONTINUE	= 0x40000020,	/// Ditto
		STATUS_WX86_EXCEPTION_LASTCHANCE	= 0x40000021,	/// Ditto
		STATUS_WX86_EXCEPTION_CHAIN	= 0x40000022,	/// Ditto
		// Thread Information Block?
		STATUS_WX86_CREATEWX86TIB	= 0x40000028,	/// Ditto
		STATUS_WX86_INTERNAL_ERROR	= 0xC000026F,	/// Ditto
		STATUS_WX86_FLOAT_STACK_CHECK	= 0xC0000270,	/// Ditto
		// See https://devblogs.microsoft.com/oldnewthing/20190108-00/?p=100655
		// tl;dr: Soft stack overflow (with a cookie on stack) within MSCRT,
		// for prevention measures. Implies /GS (MSVC)
		STATUS_STACK_BUFFER_OVERRUN	= 0xC0000409,	/// Soft stack overflow
		STATUS_EMULATION_BREAKPOINT	= 0x40000038,	/// ARM64EC Breakpoint
	}
} else version (Posix) {
	import core.sys.posix.signal;
	import adbg.include.posix.ptrace;
	
	private enum SEGV_BNDERR = 3;
	
	version (linux)
		import adbg.include.linux.user;
	version (FreeBSD)
		import adbg.include.freebsd.reg;
}

extern (C):

/// Unhandled exception type of process/program
enum AdbgException {
	Unknown,	/// Unknown exception type.
	Breakpoint,	/// A software breakpoint was hint.
	Step,	/// Single step was performed.
	AccessViolation,	/// An access violations or segmentation fault occured.
	BoundExceeded,	/// Array bounds exceeded.
	Misalignment,	/// Data type misaligned.
	IllegalInstruction,	/// Illegal opcode.
	ZeroDivision,	/// Integer divide by zero.
	PageError,	/// In-page error. (Windows: Disk demand-page failed)
	IntOverflow,	/// Integer overflow.
	StackOverflow,	/// Stack overflow.
	PrivilegedOpcode,	/// Priviled instruction.
	// FPU
	FPUDenormal,	/// Denormal value too small to represent a FP, e.g. operand.
	FPUZeroDivision,	/// Floating/Decimal divide by zero.
	FPUInexact,	/// Inexact value/result is not exact in decimal.
	FPUIllegal,	/// Invalid operation.
	FPUOverflow,	/// Overflow in FPU operation.
	FPUUnderflow,	/// FPU's stack overflow.
	FPUStackOverflow,	/// FPU's stack overflowed.
}

/// Represents an exception. Upon creation, these are populated depending on
/// the platform with their respective function.
struct adbg_exception_t {
	/// Exception type, see the ExceptionType enumeration.
	AdbgException type;
	/// Original OS code (exception or signal value).
	uint oscode;
	/// Faulting address, if available; Otherwise zero.
	ulong fault_address;
	/// Associated thread.
	adbg_process_thread_t thread;
}

/// Internal usage.
///
/// Used to translate OS status codes to an AdbgException enum value.
///
/// Windows: Uses `ExceptionCode` and `ExceptionInformation[0]`.
/// Posix: Signal number `si_signo` and its code `si_code`.
///
/// Params:
/// 	code = OS code.
/// 	subcode = OS sub-code.
/// Returns: AdbgException enumeration value.
AdbgException adbg_exception_from_os(uint code, uint subcode) {
version (Windows) {
	// NOTE: Prefer STATUS over EXCEPTION names when possible
	switch (code) with (AdbgException) {
	// NOTE: A step may also indicate a trace operation
	case STATUS_SINGLE_STEP, STATUS_WX86_SINGLE_STEP:
		return Step;
	// Instruction
	case STATUS_BREAKPOINT, STATUS_WX86_BREAKPOINT, STATUS_EMULATION_BREAKPOINT:
		return Breakpoint;
	case STATUS_ILLEGAL_INSTRUCTION:
		return IllegalInstruction;
	// Memory
	case STATUS_ACCESS_VIOLATION, STATUS_GUARD_PAGE_VIOLATION:
		return AccessViolation;
	case STATUS_IN_PAGE_ERROR: // no similar sigcode for sub-operation
		// NOTE: The third array element specifies the underlying
		//       NTSTATUS code that resulted in the exception.
		return PageError;
	case STATUS_ARRAY_BOUNDS_EXCEEDED:	return BoundExceeded;
	case STATUS_DATATYPE_MISALIGNMENT:	return Misalignment;
	// Arithmetic
	case EXCEPTION_INT_DIVIDE_BY_ZERO:	return ZeroDivision;
	case EXCEPTION_INT_OVERFLOW:	return IntOverflow;
	case EXCEPTION_PRIV_INSTRUCTION:	return PrivilegedOpcode;
	// Stack
	case STATUS_STACK_OVERFLOW, STATUS_STACK_BUFFER_OVERRUN:
		return StackOverflow;
	// FPU
	case EXCEPTION_FLT_DENORMAL_OPERAND:	return FPUDenormal;
	case EXCEPTION_FLT_DIVIDE_BY_ZERO:	return FPUZeroDivision;
	case EXCEPTION_FLT_INEXACT_RESULT:	return FPUInexact;
	case EXCEPTION_FLT_INVALID_OPERATION:	return FPUIllegal;
	case EXCEPTION_FLT_OVERFLOW:	return FPUOverflow;
	case EXCEPTION_FLT_STACK_CHECK:	return FPUStackOverflow;
	case EXCEPTION_FLT_UNDERFLOW:	return FPUUnderflow;
	case STATUS_WX86_FLOAT_STACK_CHECK:	return FPUOverflow;
	default:
	}
} else {
	switch (code) with (AdbgException) {
	case SIGILL:
		return IllegalInstruction;
	case SIGFPE:
		switch (subcode) {
		case FPE_INTDIV: return ZeroDivision;
		case FPE_INTOVF: return FPUOverflow;
		case FPE_FLTDIV: return FPUZeroDivision;
		case FPE_FLTOVF: return FPUOverflow;
		case FPE_FLTUND: return FPUUnderflow;
		case FPE_FLTRES: return FPUInexact;
		case FPE_FLTINV: return FPUIllegal;
		case FPE_FLTSUB: return FPUDenormal;
		default: return FPUIllegal;
		}
	case SIGSEGV:
		switch (subcode) {
		case SEGV_BNDERR: return BoundExceeded;
		default:
		}
		return AccessViolation;
	case SIGBUS:
		switch (subcode) {
		case BUS_ADRALN: return Misalignment;
		default:
		}
		break;
	case SIGTRAP:
		return Breakpoint;
	case SIGCHLD:
		switch (subcode) {
		case CLD_TRAPPED: return Breakpoint;
		default:
		}
		break;
	// Because Windows' DebugBreak uses a regular breakpoint (int3)
	case SIGSTOP: return Breakpoint;
	default:
	}
} // Posix
	
	return AdbgException.Unknown;
}

/// Get the translated exception code.
/// Params: exception = Exception instance.
/// Returns: Exception value, or AdbgException.Unknown on error.
AdbgException adbg_exception_type(adbg_exception_t *exception) {
	if (exception == null) return AdbgException.Unknown;
	return exception.type;
}

/// Get a short descriptive string for an exception type value.
/// Params: exception = Exception instance.
/// Returns: String or null on error.
const(char)* adbg_exception_name(adbg_exception_t *exception) {
	if (exception == null) return null;
	final switch (exception.type) with (AdbgException) {
	case Breakpoint:	return "BREAKPOINT";
	case Step:	return "INSTRUCTION STEP";
	case AccessViolation:	return "ACCESS VIOLATION";
	case BoundExceeded:	return "OUT OF BOUND";
	case Misalignment:	return "DATA MISALIGNMENT";
	case IllegalInstruction:	return "ILLEGAL INSTRUCTION";
	case ZeroDivision:	return "ZERO DIVISION";
	case PageError:	return "PAGE ERROR";
	case IntOverflow:	return "INTEGER OVERFLOW";
	case StackOverflow:	return "STACK OVERFLOW";
	case PrivilegedOpcode:	return "PRIVILEGED INSTRUCTION";
	case FPUDenormal:	return "FPU: DEFORMAL";
	case FPUZeroDivision:	return "FPU: ZERO DIVISION";
	case FPUInexact:	return "FPU: INEXACT";
	case FPUIllegal:	return "FPU: ILLEGAL";
	case FPUOverflow:	return "FPU: OVERFLOW";
	case FPUUnderflow:	return "FPU: UNDERFLOW";
	case FPUStackOverflow:	return "FPU: STACK OVERFLOW";
	case Unknown:	return "UNKNOWN";
	}
}

/// Get the address where the exception happened.
///
/// Due to system limitations, like the type of exception,
/// the memory address can be zero.
/// Params: exception = Exception instance.
/// Returns: Memory address, or zero if unavailable.
ulong adbg_exception_fault_address(adbg_exception_t *exception) {
	if (exception == null) return 0;
	return exception.fault_address;
}

/// Get the original system error code from the exception.
/// Params: exception = Exception instance.
/// Returns: System code.
int adbg_exception_orig_code(adbg_exception_t *exception) {
	if (exception == null) return 0;
	return exception.oscode;
}

/// Get the associated thread for this exception.
///
/// The lifetime of the thread instance is only valid for the duration
/// of the event handler.
/// Params: exception = Exception instance.
/// Returns: Thread instance, or null on error or if unavailable.
adbg_process_thread_t* adbg_exception_thread(adbg_exception_t *exception) {
	if (exception == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	return &exception.thread;
}
