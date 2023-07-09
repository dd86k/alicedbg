/// Exception structure and helpers.
///
/// Windows: um/minwinbase.h
///
/// Linux: include/uapi/asm-generic/siginfo.h
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.v2.debugger.exception;

import adbg.platform : adbg_address_t;

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
	import adbg.include.linux.user;
	import core.sys.posix.signal;
	private enum SEGV_BNDERR = 3;
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
	Illegal,	/// Illegal opcode.
	DivZero,	/// Integer divide by zero.
	PageError,	/// In-page error.
	IntOverflow,	/// Integer overflow.
	StackOverflow,	/// Stack overflow.
	PrivilegedOpcode,	/// Priviled instruction.
	// FPU
	FPUDenormal,	/// Denormal value too small to represent a FP, e.g. operand.
	FPUDivZero,	/// Floating/Decimal divide by zero.
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

/// Represents an exception. Upon creation, these are populated depending on
/// the platform with their respective function.
struct adbg_exception_t {
	/// Exception type, see the ExceptionType enumeration.
	AdbgException type;
	/// Original OS code (exception or signal value).
	uint oscode;
	/// Process ID.
	int pid;
	/// Thread ID, if available; Otherwise zero.
	int tid;
	adbg_address_t fault;	/// Memory address pointer for fault. Otherwise null.
}

/// (Internal) Translate an oscode to an ExceptionType enum value.
///
/// Windows: `DEBUG_INFO.Exception.ExceptionRecord.ExceptionCode` and
/// `cast(uint)de.Exception.ExceptionRecord.ExceptionInformation[0]` in certain
/// cases.
/// Posix: Signal number (`si_signo`) and its code `si_code` in certain cases.
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
		// Instruction
		case STATUS_BREAKPOINT, STATUS_WX86_BREAKPOINT:
			return Breakpoint;
		case STATUS_ILLEGAL_INSTRUCTION:	return Illegal;
		// Memory
		case STATUS_ACCESS_VIOLATION:
			// no similar sigcode for sub-operation
			/*switch (subcode) {
			case 0: // Read access error
				return Fault;
			case 1: // Write access error
				return Fault;
			case 8: // DEP violation
				return Fault;
			default: return Unknown;
			}*/
			return Fault;
		case STATUS_ARRAY_BOUNDS_EXCEEDED:	return BoundExceeded;
		case STATUS_DATATYPE_MISALIGNMENT:	return Misalignment;
		case STATUS_IN_PAGE_ERROR:
			// no similar sigcode for sub-operation
			/*switch (subcode) {
			case 0: // Read access error
				return PageError;
			case 1: // Write access error
				return PageError;
			case 8: // DEP violation
				return PageError;
			default: return PageError;
			}*/
			return PageError;
		// Arithmetic
		case EXCEPTION_INT_DIVIDE_BY_ZERO:	return DivZero;
		case EXCEPTION_INT_OVERFLOW:	return IntOverflow;
		case STATUS_INVALID_DISPOSITION:	return Disposition;
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
		case STATUS_NONCONTINUABLE_EXCEPTION:	return NoContinue;
		default:	return Unknown;
		}
	} else {
		switch (code) with (AdbgException) {
		case SIGILL:
			/*
			switch (subcode) {
			case ILL_ILLOPC: opcode
			case ILL_ILLOPN: operand
			case ILL_ILLADR: address mode
			case ILL_ILLTRP: trap
			case ILL_PRVOPC: priv code
			case ILL_PRVREG: priv register
			case ILL_COPROC: co-processor error
			case ILL_BADSTK: internal stack error.
			}*/
			return Illegal;
		case SIGFPE:
			switch (subcode) {
			case FPE_INTDIV: return FPUDivZero;
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
			case SEGV_MAPERR: return Fault;
			case SEGV_ACCERR: return Fault;
			case SEGV_BNDERR: return BoundExceeded;
			//case SEGV_PKUERR: return 
			default: return Fault;
			}
		case SIGBUS:
			switch (subcode) {
			case BUS_ADRALN: return Misalignment;
			case BUS_ADRERR: return Unknown;
			case BUS_OBJERR: return Unknown;
			//case BUS_MCEERR_AR:
			//case BUS_MCEERR_AO:
			default: return Unknown;
			}
		case SIGTRAP:
			/*switch (subcode) {
			case TRAP_BRKPT: return Breakpoint;
			case TRAP_TRACE:
			case TRAP_DTRACE:
			case TRAP_RWATCH:
			case TRAP_WWATCH:
			case TRAP_XWATCH:
			default: return Breakpoint;
			}*/
			return Breakpoint;
		case SIGCHLD:
			switch (subcode) {
			case CLD_EXITED: return Exit;
			case CLD_KILLED: return Exit;
			case CLD_DUMPED: return Unknown;
			case CLD_TRAPPED: return Breakpoint;
			case CLD_STOPPED: return Unknown;
			case CLD_CONTINUED: return Unknown;
			default: return Unknown;
			}
		case /*SIGIO, */SIGPOLL:
			switch (subcode) {
			case POLL_IN: return Unknown;
			case POLL_OUT: return Unknown;
			case POLL_MSG: return Unknown;
			case POLL_ERR: return Unknown;
			case POLL_PRI: return Unknown;
			case POLL_HUP: return Unknown;
			default: return Unknown;
			}
		case SIGSTOP: return Breakpoint;
		case SIGSYS: return Unknown;	// SYS_SECCOMP
		//TODO: case SIGKILL:
		default: return Unknown;
		}
	}
}

/// Get a short descriptive string for an exception type value.
///
/// The names are uppercased.
///
/// Params: code = ExceptionType
///
/// Returns: String
const(char) *adbg_exception_name(AdbgException code) {
	switch (code) with (AdbgException) {
	case Unknown:	return "UNKNOWN";
	case Exit:	return "TERMINATED";
	case Breakpoint:	return "BREAKPOINT";
	case Step:	return "SINGLE STEP";
	case Fault:
		version (Windows) return "ACCESS VIOLATION";
		else return "SEGMENTATION FAULT";
	case BoundExceeded:	return "OUT OF BOUNDS";
	case Misalignment:	return "MISALIGNMENT";
	case Illegal:	return "ILLEGAL INSTRUCTION";
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
		exception.fault.raw = de.Exception.ExceptionRecord.ExceptionAddress;
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
