/// Exception structure and helpers.
///
/// Windows: um/minwinbase.h
///
/// Linux: include/uapi/asm-generic/siginfo.h
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.debugger.exception;

version (Windows) {
	import core.sys.windows.winbase;
	private enum {	// missing values for WoW64 (NTSTATUS, winbase.h)
		STATUS_WX86_UNSIMULATE	= 0x4000001C,	/// WOW64 exception code
		STATUS_WX86_CONTINUE	= 0x4000001D,	/// WOW64 exception code
		STATUS_WX86_SINGLE_STEP	= 0x4000001E,	/// WOW64 exception code
		STATUS_WX86_BREAKPOINT	= 0x4000001F,	/// WOW64 exception code
		STATUS_WX86_EXCEPTION_CONTINUE	= 0x40000020,	/// WOW64 exception code
		STATUS_WX86_EXCEPTION_LASTCHANCE	= 0x40000021,	/// WOW64 exception code
		STATUS_WX86_EXCEPTION_CHAIN	= 0x40000022,	/// WOW64 exception code
		// See https://devblogs.microsoft.com/oldnewthing/20190108-00/?p=100655
		// tl;dr: Soft stack overflow (with a cookie on stack) within MSCRT,
		// for prevention measures. Implies /GS (MSVC)
		STATUS_STACK_BUFFER_OVERRUN	= 0xC0000409,	/// Soft stack overflow
	}
} else version (Posix) {
	import core.sys.posix.signal;
	
	private enum SEGV_BNDERR = 3;
	
	version (linux)
		import adbg.include.linux.user; // For USER area
	else
		static assert(0, "Include user area for POSIX environment");
}

extern (C):

/// Unhandled exception type of process/program
enum AdbgException {
	Unknown,	/// Unknown exception type.
	Exit,	/// Program was terminated, typically by the user.
	Breakpoint,	/// A software breakpoint was hint.
	Step,	/// Single step was performed.
	Fault,	/// An access violations or segmentation fault occured.
	BoundExceeded,	/// Array bounds exceeded.
	Misalignment,	/// Data type misaligned.
	IllegalInstruction,	/// Illegal opcode.
	ZeroDivision,	/// Integer divide by zero.
	DivZero = ZeroDivision,	/// Old alias for ZeroDivision.
	PageError,	/// In-page error. (Windows: Disk demand-page failed)
	IntOverflow,	/// Integer overflow.
	StackOverflow,	/// Stack overflow.
	PrivilegedOpcode,	/// Priviled instruction.
	// FPU
	FPUDenormal,	/// Denormal value too small to represent a FP, e.g. operand.
	FPUZeroDivision,	/// Floating/Decimal divide by zero.
	FPUDivZero = FPUZeroDivision,	/// Old alias for FPUZeroDivision
	FPUInexact,	/// Inexact value/result is not exact in decimal.
	FPUIllegal,	/// Invalid operation.
	FPUOverflow,	/// Overflow in FPU operation.
	FPUUnderflow,	/// FPU's stack overflow.
	FPUStackOverflow,	/// FPU's stack overflowed.
	// OS specific-ish
	Disposition,	/// OS reports invalid disposition to exception handler. Internal error.
	NoContinue,	/// Debugger tried to continue on after non-continuable error.
}

//TODO: Severity levels depending on exception type
//      Essentially it'll be for a "can or cannot continue"
//      This would also allow the removal of Disposition/NoContinue
//      OR
//      Focus on providing "Exit" translations, which debugger should rely upon
//TODO: Redo some of the codes (Disposition, NoContinue, PageError)
//      - While POSIX environments have no such notion, it should still be
//        translated in some other form.
//      - It could be posible to provide a "second chance" system translating
//        some of the signals (e.g., faults aren't illigeable, but page errors could).
//      - Rename PageError to something else like IoError, or Paging
//        Maybe some SIGBUS and SIGIO subcodes are meant for this

/// Represents an exception. Upon creation, these are populated depending on
/// the platform with their respective function.
struct adbg_exception_t {
	/// Exception type, see the ExceptionType enumeration.
	AdbgException type;
	/// Original OS code (exception or signal value).
	uint oscode;
	//TODO: Attach process instead of dedicated pid/tid.
	/// Process ID.
	int pid;
	/// Thread ID, if available; Otherwise zero.
	int tid;
	union {
		/// Faulting address, if available; Otherwise zero.
		ulong fault_address;
		/// 32-bit Faulting address, if available; Otherwise zero.
		/// Useful for LP32 environments.
		uint fault_address32;
		/// Used internally.
		size_t faultz;
	}
}

/// (Internal) Translate an oscode to an ExceptionType enum value.
///
/// Windows: `DEBUG_INFO.Exception.ExceptionRecord.ExceptionCode` and
/// `cast(uint)de.Exception.ExceptionRecord.ExceptionInformation[0]` in certain
/// cases.
/// Posix: Signal number (`si_signo`) and its code (`si_code`) in certain cases.
///
/// Params:
/// 	code = OS code.
/// 	subcode = OS sub-code.
///
/// Returns: Adjusted exception type.
AdbgException adbg_exception_from_os(uint code, uint subcode = 0) {
version (Windows) {
	// NOTE: Prefer STATUS over EXCEPTION names when possible
	switch (code) with (AdbgException) {
	// NOTE: A step may also indicate a trace operation
	case STATUS_SINGLE_STEP, STATUS_WX86_SINGLE_STEP:
		return Step;
	// Instruction breakpoint
	case STATUS_BREAKPOINT, STATUS_WX86_BREAKPOINT:
		return Breakpoint;
	case STATUS_ILLEGAL_INSTRUCTION:
		return IllegalInstruction;
	// Memory access violation
	case STATUS_ACCESS_VIOLATION: // no similar sigcode for sub-operation
		return Fault;
	// Specifically to swap
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
	case EXCEPTION_FLT_DIVIDE_BY_ZERO:	return FPUDivZero;
	case EXCEPTION_FLT_INEXACT_RESULT:	return FPUInexact;
	case EXCEPTION_FLT_INVALID_OPERATION:	return FPUIllegal;
	case EXCEPTION_FLT_OVERFLOW:	return FPUOverflow;
	case EXCEPTION_FLT_STACK_CHECK:	return FPUStackOverflow;
	case EXCEPTION_FLT_UNDERFLOW:	return FPUUnderflow;
	// Misc
	case STATUS_INVALID_DISPOSITION:	return Disposition;
	case STATUS_NONCONTINUABLE_EXCEPTION:	return NoContinue;
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
		case FPE_FLTDIV: return FPUDivZero;
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
		return Fault;
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
		case CLD_EXITED: return Exit;
		case CLD_KILLED: return Exit;
		case CLD_DUMPED: return Unknown;
		case CLD_TRAPPED: return Breakpoint;
		case CLD_STOPPED: return Unknown;
		case CLD_CONTINUED: return Unknown;
		default:
		}
		break;
	// Because Windows' DebugBreak uses a regular breakpoint (int3)
	case SIGSTOP: return Breakpoint;
	case SIGKILL: return Exit;
	default:
	}
} // Posix
	
	return AdbgException.Unknown;
}

/// Get a short descriptive string for an exception type value.
/// Params: ex = Exception.
/// Returns: String or null. Names are uppercased.
const(char) *adbg_exception_name(adbg_exception_t *ex) {
	if (ex == null) return null;
	switch (ex.type) with (AdbgException) {
	case Unknown:	return "UNKNOWN";
	case Exit:	return "TERMINATED";
	case Breakpoint:	return "BREAKPOINT";
	case Step:	return "INSTRUCTION STEP";
	// NOTE: Also known as a segmentation fault,
	//       "access violation" remains a better term.
	case Fault:	return "ACCESS VIOLATION";
	case BoundExceeded:	return "INDEX OUT OF BOUNDS";
	case Misalignment:	return "DATA MISALIGNMENT";
	case IllegalInstruction:	return "ILLEGAL INSTRUCTION";
	case DivZero:	return "ZERO DIVISION";
	case PageError:	return "PAGE ERROR";
	case IntOverflow:	return "INTEGER OVERFLOW";
	case StackOverflow:	return "STACK OVERFLOW";
	case PrivilegedOpcode:	return "PRIVILEGED INSTRUCTION";
	case FPUDenormal:	return "FPU: DEFORMAL";
	case FPUDivZero:	return "FPU: ZERO DIVISION";
	case FPUInexact:	return "FPU: INEXACT";
	case FPUIllegal:	return "FPU: ILLEGAL";
	case FPUOverflow:	return "FPU: OVERFLOW";
	case FPUUnderflow:	return "FPU: UNDERFLOW";
	case FPUStackOverflow:	return "FPU: STACK OVERFLOW";
	case Disposition:	return "OS: DISPOSITION";
	case NoContinue:	return "OS: COULD NOT CONTINUE";
	default:	return "UNKNOWN";
	}
}

// Used internally for debugger
package
void adbg_exception_translate(adbg_exception_t *exception, void *os1, void *os2) {
version (Windows) {
	DEBUG_EVENT *de = cast(DEBUG_EVENT*)os1;
	
	exception.pid = de.dwProcessId;
	exception.tid = de.dwThreadId;
	exception.faultz = cast(size_t)de.Exception.ExceptionRecord.ExceptionAddress;
	exception.oscode = de.Exception.ExceptionRecord.ExceptionCode;
	
	switch (exception.oscode) {
	case EXCEPTION_IN_PAGE_ERROR:
	case EXCEPTION_ACCESS_VIOLATION:
		exception.type = adbg_exception_from_os(exception.oscode,
			cast(uint)de.Exception.ExceptionRecord.ExceptionInformation[0]);
		break;
	default:
		exception.type = adbg_exception_from_os(exception.oscode);
	}
} else {
	int pid = *cast(int*)os1;
	int signo = *cast(int*)os2;
	
	exception.pid = exception.tid = pid;
	exception.tid = 0;
	exception.oscode = signo;
	exception.type = adbg_exception_from_os(signo);
}
}
