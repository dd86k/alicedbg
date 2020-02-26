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
	import core.sys.windows.windows;
} else
version (Posix) {
	import debugger.sys.user : user;
	import debugger.sys.ptrace : siginfo_t;
	import core.sys.posix.signal;
}

import consts;

extern (C):

/// Register array size, may vary on target platform
enum REG_COUNT = 32;

/// Register size
enum RegisterType {
	Unknown, U8, U16, U32, U64, F32, F64
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
	/// Exception type, see ExceptionType enumeration.
	ExceptionType type;
	/// Original OS code or signal for hardware exception.
	uint oscode;
	/// (Windows) Original OS event code.
	uint ecode;
	/// Process ID.
	uint pid;
	/// Thread ID if available.
	uint tid;
	union {
		/// Memory address value
		size_t addrv;
		/// Memory address pointer
		void *addr;
	}
	/// Register population, this may depend on the OS and CRT
	register_t [REG_COUNT]registers;
	/// Register count in registers field, populated by
	/// exception_reg_init.
	size_t regcount;
}

/// Register structure, designs a single register for UI ends to understand
struct register_t {
	RegisterType type;	/// Register type (size)
	union {
		ubyte  u8;	/// Register alias: ubyte (u8)
		ushort u16;	/// Register alias: ushort (u16)
		uint   u32;	/// Register alias: uint (u32)
		ulong  u64;	/// Register alias: ulong (u64)
		float  f32;	/// Register alias: float (f32)
		double f64;	/// Register alias: double (f64)
	}
	const(char) *name;	/// Register name from exception_reg_init
}

// Windows: Mostly covered in winbase.h or winnt.h
// - Include\shared\winnt.h (at least for x86, amd64)
// - Include\shared\ntstatus.h (winnt: #ifndef WIN32_NO_STATUS || UMDF_USING_NTSTATUS)
// - Include\shared\ksarm.h (ARM: ARMv6, ARMv7)
// - Include\shared\ksarm64.h (ARM64: ARMv8)
// Linux: see sigaction(2)

/**
 * (Internal) Translate an oscode to a universal exception type.
 * - Windows: `DEBUG_INFO.Exception.ExceptionRecord.ExceptionCode` and
 * `cast(uint)de.Exception.ExceptionRecord.ExceptionInformation[0]` in certain
 * cases.
 * - Posix: Signal number (`siginfo_t.si_signo`) and `si_code`.
 * Params:
 * 	code = OS code
 * 	subcode = OS sub-code
 * Returns: ExceptionType (enum)
 */
ExceptionType exception_type_code(uint code, uint subcode = 0) {
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

/// Get a very short descriptive string for a ExceptionType value in all
/// uppercase. UI or client may want to lowercase if they want, but I'm keeping
/// the uppercase.
/// Params: code = ExceptionType
/// Returns: String
const(char) *exception_type_str(ExceptionType code) {
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

/// Format a register depending on their type as a zero-padded number.
/// Params: reg = register_t structure
/// Returns: 
const(char) *exception_reg_fhex(ref register_t reg) {
	import utils.str : strf;
	with (RegisterType)
	switch (reg.type) {
	case U8:  return strf("%02x", reg.u8);
	case U16: return strf("%04x", reg.u16);
	case U32, F32: return strf("%08x", reg.u32);
	case U64, F64: return strf("%016llx", reg.u64);
	default: return "??";
	}
}
/*
const(char) *exception_reg_fval(ref register_t reg) {
	import utils.str : strf;
	
}*/

package:

void exception_reg_init(ref exception_t e) {
	version (X86) {
		e.regcount = 10;
		e.registers[0].name = "EIP";
		e.registers[0].type = RegisterType.U32;
		e.registers[1].name = "EFLAGS";
		e.registers[1].type = RegisterType.U32;
		e.registers[2].name = "EAX";
		e.registers[2].type = RegisterType.U32;
		e.registers[3].name = "EBX";
		e.registers[3].type = RegisterType.U32;
		e.registers[4].name = "ECX";
		e.registers[4].type = RegisterType.U32;
		e.registers[5].name = "EDX";
		e.registers[5].type = RegisterType.U32;
		e.registers[6].name = "ESP";
		e.registers[6].type = RegisterType.U32;
		e.registers[7].name = "EBP";
		e.registers[7].type = RegisterType.U32;
		e.registers[8].name = "ESI";
		e.registers[8].type = RegisterType.U32;
		e.registers[9].name = "EDI";
		e.registers[9].type = RegisterType.U32;
	} else
	version (X86_64) {
		e.regcount = 10;
		e.registers[0].name = "RIP";
		e.registers[0].type = RegisterType.U64;
		e.registers[1].name = "RFLAGS";
		e.registers[1].type = RegisterType.U32;
		e.registers[2].name = "RAX";
		e.registers[2].type = RegisterType.U64;
		e.registers[3].name = "RBX";
		e.registers[3].type = RegisterType.U64;
		e.registers[4].name = "RCX";
		e.registers[4].type = RegisterType.U64;
		e.registers[5].name = "RDX";
		e.registers[5].type = RegisterType.U64;
		e.registers[6].name = "RSP";
		e.registers[6].type = RegisterType.U64;
		e.registers[7].name = "RBP";
		e.registers[7].type = RegisterType.U64;
		e.registers[8].name = "RSI";
		e.registers[8].type = RegisterType.U64;
		e.registers[9].name = "RDI";
		e.registers[9].type = RegisterType.U64;
	}
}

version (Windows) {

/// Translate Windows' DEBUG_EVENT to an exception_t
int exception_tr_windows(ref exception_t e, ref DEBUG_EVENT de) {
	e.pid = de.dwProcessId;
	e.tid = de.dwThreadId;
	e.addr = de.Exception.ExceptionRecord.ExceptionAddress;
	e.oscode = de.Exception.ExceptionRecord.ExceptionCode;
	switch (e.oscode) {
	case EXCEPTION_IN_PAGE_ERROR:
	case EXCEPTION_ACCESS_VIOLATION:
		e.type = exception_type_code(
			de.Exception.ExceptionRecord.ExceptionCode,
			cast(uint)de.Exception.ExceptionRecord.ExceptionInformation[0]);
		break;
	default:
		e.type = exception_type_code(de.Exception.ExceptionRecord.ExceptionCode);
	}
	return 0;
}
/// Populate exception_t.registers array from Windows' CONTEXT
int exception_ctx_windows(ref exception_t e, ref CONTEXT c) {
	version (X86) {
		e.registers[0].u32 = c.Eip;
		e.registers[1].u32 = c.EFlags;
		e.registers[2].u32 = c.Eax;
		e.registers[3].u32 = c.Ebx;
		e.registers[4].u32 = c.Ecx;
		e.registers[5].u32 = c.Edx;
		e.registers[6].u32 = c.Esp;
		e.registers[7].u32 = c.Ebp;
		e.registers[8].u32 = c.Esi;
		e.registers[9].u32 = c.Edi;
	} else
	version (X86_64) {
		e.registers[0].u64 = c.Rip;
		e.registers[1].u32 = c.EFlags;
		e.registers[2].u64 = c.Rax;
		e.registers[3].u64 = c.Rbx;
		e.registers[4].u64 = c.Rcx;
		e.registers[5].u64 = c.Rdx;
		e.registers[6].u64 = c.Rsp;
		e.registers[7].u64 = c.Rbp;
		e.registers[8].u64 = c.Rsi;
		e.registers[9].u64 = c.Rdi;
	}
	return 0;
}

} else // version Windows
version (Posix) {
	
/// Translate Posix's siginfo_t to an exception_t
int exception_tr_siginfo(ref exception_t e, ref siginfo_t si) {
	e.pid = si.si_pid;
	e.tid = 0;
	e.addr = si.si_addr;
	e.oscode = si.si_signo;
	e.type = exception_type_code(si.si_signo, si.si_code);
	return 0;
}
/// Populate exception_t.registers array from Glibc's user
int exception_ctx_user(ref exception_t e, ref user u) {
	version (X86) {
//		e.addrv = u.regs.eip;
		e.registers[0].u32 = u.regs.eip;
		e.registers[1].u32 = u.regs.eflags;
		e.registers[2].u32 = u.regs.eax;
		e.registers[3].u32 = u.regs.ebx;
		e.registers[4].u32 = u.regs.ecx;
		e.registers[5].u32 = u.regs.edx;
		e.registers[6].u32 = u.regs.esp;
		e.registers[7].u32 = u.regs.ebp;
		e.registers[8].u32 = u.regs.esi;
		e.registers[9].u32 = u.regs.edi;
	} else
	version (X86_64) {
		printf("r: %zX\n", u.regs.rip);
//		e.addrv = u.regs.rip;
		e.registers[0].u64 = u.regs.rip;
		e.registers[1].u32 = cast(uint)u.regs.eflags;
		e.registers[2].u64 = u.regs.rax;
		e.registers[3].u64 = u.regs.rbx;
		e.registers[4].u64 = u.regs.rcx;
		e.registers[5].u64 = u.regs.rdx;
		e.registers[6].u64 = u.regs.rsp;
		e.registers[7].u64 = u.regs.rbp;
		e.registers[8].u64 = u.regs.rsi;
		e.registers[9].u64 = u.regs.rdi;
	}
	return 0;
}

} // version Posix