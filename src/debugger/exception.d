/**
 * Exception structure and helpers.
 *
 * The ExceptionType enumeration has its own unique values because taking the
 * native exception OS values would make transmitting the information outside
 * of the debugger difficult for the client program (e.g. client would have
 * to distinguish an exception type of Fault as EXCEPTION_ACCESS_VIOLATION
 * (0xC00000005) AND SIGSEGV. That'd be hell!). So a "translater" (see function
 * `codetype`) converts those codes to our enumeration.
 */
module debugger.exception;

version (Windows) {
	import core.sys.windows.winbase;
} else
version (Posix) {
	version (linux)
		import core.sys.posix.signal;
	import core.sys.posix.signal;
}

import consts;

extern (C):

/// 
enum REG_COUNT = 32;

/// Register size
enum RegisterType {
	Unknown, U8, I8, U16, I16, U32, I32, U64, I64, F32, F64
}

/// Unhandled exception type of process/program
enum ExceptionType {
	Unknown,	/// Unknown type
	Exit,	/// Program terminated (Windows) CTRL+C (linux) SIGINT, SIGTSTP, SIGQUIT
	Breakpoint,	/// (x86) INT 3
	Step,	/// Single step
	Fault,	/// Access violations and segmentation faults
	BoundExceeded,	/// Array bounds exceeded
	Misalignment,	/// Data type misaligned
	Illegal,	/// Illegal opcode
	DivZero,	/// Integer divide by zero
	PageError,	/// In-page error
	Overflow,	/// Integer overflow
	StackOverflow,	/// Stack overflow
	PrivilegedOpcode,	/// Priviled instruction
	// FPU
	FPUDenormal,	/// Denormal value too small to represent a FP, e.g. operand
	FPUDivZero,	/// Floating/Decimal divide by zero
	FPUInexact,	/// Inexact value/result is not exact in decimal
	FPUIllegal,	/// Invalid operation
	FPUOverflow,	/// Overflow in FPU operation
	FPUUnderflow,	/// FPU's stack overflow
	FPUStackOverflow,	/// FPU's stack overflowed
	// OS specific-ish
	Disposition,	/// OS reports invalid disposition to exception handler
	NoContinue,	/// Debugger tried to continue on after non-continuable error
//	OSError,	/// OS error (WaitForDebugEvent returned FALSE or waitid returned -1)
}

/// Filtered exception structure after goinng through the platform-dependant
/// handler.
struct exception_t {
	ExceptionType type;	/// Exception type
	uint oscode;	/// Original OS code or signal for hardware exception
	uint ecode;	/// (Windows) Original OS event code
	uint pid;	/// Process ID
	uint tid;	/// Thread ID if available
	union {
		size_t addrv;	/// Memory address value
		void *addr;	/// Memory address pointer
	}
	register_t [REG_COUNT]registers;	/// Registers 
}

/// Register structure, designs a single register for UI ends to understand
struct register_t {
	RegisterType type;	/// Register type (size)
	union {
		ubyte u8;	/// Register alias: ubyte (u8)
		byte  i8;	/// Register alias: byte (i8)
		ushort u16;	/// Register alias: ushort (u16)
		short  i16;	/// Register alias: short (i16)
		uint u32;	/// Register alias: uint (u32)
		int  i32;	/// Register alias: int (i32)
		ulong u64;	/// Register alias: ulong (u64)
		long  i64;	/// Register alias: long (i64)
		float f32;	/// Register alias: float (f32)
		double f64;	/// Register alias: double (f64)
	}
	const(char) *name;	/// Register name
}



// Windows: Mostly covered in winbase.h or winnt.h
// - Include\shared\winnt.h (at least for x86, amd64)
// - Include\shared\ntstatus.h (winnt: #ifndef WIN32_NO_STATUS || UMDF_USING_NTSTATUS)
// - Include\shared\ksarm.h (ARM: ARMv6, ARMv7)
// - Include\shared\ksarm64.h (ARM64: ARMv8)
// Linux: see sigaction(2)

/**
 * (Internal) Translate an oscode to a universal exception type.
 *
 * Subcode: (Windows) See `EXCEPTION_RECORD.ExceptionInformation`. (Posix) Via
 * `sigaction_t.si_code`.
 * Params:
 * 	code = OS code
 * 	subcode = OS sub-code
 * Returns: ExceptionType (enum)
 */
ExceptionType codetype(uint code, uint subcode = 0) {
	version (Windows) {
		with (ExceptionType)
		switch (code) {
		case EXCEPTION_ACCESS_VIOLATION:
			switch (subcode) {
			case 0: // Read access error
				return Fault;
			case 1: // Write access error
				return Fault;
			case 8: // DEP violation
				return Fault;
			default: return Unknown;
			}
		case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:	return BoundExceeded;
		case EXCEPTION_BREAKPOINT:	return Breakpoint;
		case EXCEPTION_SINGLE_STEP:	return Step;
		case EXCEPTION_DATATYPE_MISALIGNMENT:	return Misalignment;
		case EXCEPTION_ILLEGAL_INSTRUCTION:	return Illegal;
		case EXCEPTION_IN_PAGE_ERROR:
			switch (subcode) {
			case 0: // Read access error
				return PageError;
			case 1: // Write access error
				return PageError;
			case 8: // DEP violation
				return PageError;
			default: return PageError;
			}
		case EXCEPTION_INT_DIVIDE_BY_ZERO:	return DivZero;
		case EXCEPTION_INT_OVERFLOW:	return Overflow;
		case EXCEPTION_INVALID_DISPOSITION:	return Disposition;
		case EXCEPTION_NONCONTINUABLE_EXCEPTION:	return NoContinue;
		case EXCEPTION_PRIV_INSTRUCTION:	return PrivilegedOpcode;
		case EXCEPTION_STACK_OVERFLOW:	return StackOverflow;
		// FPU
		case EXCEPTION_FLT_DENORMAL_OPERAND:	return FPUDenormal;
		case EXCEPTION_FLT_DIVIDE_BY_ZERO:	return FPUDivZero;
		case EXCEPTION_FLT_INEXACT_RESULT:	return FPUInexact;
		case EXCEPTION_FLT_INVALID_OPERATION:	return FPUIllegal;
		case EXCEPTION_FLT_OVERFLOW:	return FPUOverflow;
		case EXCEPTION_FLT_STACK_CHECK:	return FPUStackOverflow;
		case EXCEPTION_FLT_UNDERFLOW:	return FPUUnderflow;
		default:	return Unknown;
		}
	} else {
		with (ExceptionType)
		switch (code) {
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
			//case SEGV_BNDERR: return BoundExceeded;
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
			// Getting 4 instead of 1? Odd
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
			case CLD_KILLED: return Unknown;
			case CLD_DUMPED: return Unknown;
			case CLD_TRAPPED: return Unknown;
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
		case SIGSYS: return Unknown;	// SYS_SECCOMP
		default: return Unknown;
		}
	}
}

/**
 * Get a very short descriptive string for a ExceptionType value in all
 * uppercase. UI or client may want to lowercase if they want, but I'm keeping
 * the uppercase.
 * Params: code = ExceptionType
 * Returns: String
 */
const(char) *typestr(ExceptionType code) {
	// A final switch is preferred over an array as the final switch will
	// verify, at compile-time, if all enum members are used, and we do
	// not need the extra performance
	with (ExceptionType)
	final switch (code) {
	case Unknown:	return "UNKNOWN";
	case Exit:	return "TERMINATED";
	case Breakpoint:	return "BREAKPOINT";
	case Step:	return "SINGLE STEP";
	case Fault:
		version (Windows) return "ACCESS VIOLATION";
		else return "SEGMENTATION FAULT";
	case BoundExceeded:	return "OUT OF BOUNDS";
	case Misalignment:	return "MISALIGNMENT";
	case Illegal:	return "ILLEGAL OPCODE";
	case DivZero:	return "ZERO DIVISION";
	case PageError:	return "PAGE ERROR";
	case Overflow:	return "INTEGER OVERFLOW";
	case StackOverflow:	return "STACK OVERFLOW";
	case PrivilegedOpcode:	return "PRIVILEGED OPCODE";
	case FPUDenormal:	return "FPU: DEFORMAL";
	case FPUDivZero:	return "FPU: ZERO DIVISION";
	case FPUInexact:	return "FPU: INEXACT";
	case FPUIllegal:	return "FPU: ILLEGAL";
	case FPUOverflow:	return "FPU: OVERFLOW";
	case FPUUnderflow:	return "FPU: UNDERFLOW";
	case FPUStackOverflow:	return "FPU: STACK OVERFLOW";
	case Disposition:	return "OS: DISPOSITION";
	case NoContinue:	return "OS: NO CONTINUE";
	}
}