/**
 * Exception structure and helpers.
 *
 * The ExceptionType enumeration has its own unique values because taking the
 * native exception OS values would make transmitting the information outside
 * of the debugger difficult for the client program (e.g. client would have
 * to distinguish an exception type of Fault as EXCEPTION_ACCESS_VIOLATION
 * (0xC00000005) AND SIGSEGV. That'd be hell!). So a "translater" (see function
 * `codetype`) converts those codes to our enumeration.
 *
 * License: BSD 3-Clause
 */
module debugger.exception;

version (Windows) {
	import core.sys.windows.windows;
	import debugger.sys.wow64;
	enum { // NTSTATUS missing D bindings (WOW64)
		STATUS_WX86_UNSIMULATE = 0x4000001C,	/// WOW64 exception code
		STATUS_WX86_CONTINUE = 0x4000001D,	/// WOW64 exception code
		STATUS_WX86_SINGLE_STEP = 0x4000001E,	/// WOW64 exception code
		STATUS_WX86_BREAKPOINT = 0x4000001F,	/// WOW64 exception code
		STATUS_WX86_EXCEPTION_CONTINUE = 0x40000020,	/// WOW64 exception code
		STATUS_WX86_EXCEPTION_LASTCHANCE = 0x40000021,	/// WOW64 exception code
		STATUS_WX86_EXCEPTION_CHAIN = 0x40000022,	/// WOW64 exception code
	}
} else
version (Posix) {
	import debugger.sys.user;
	import debugger.sys.ptrace : siginfo_t;
	import core.sys.posix.signal;
}

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

/// Represents an exception. Upon creation, these are populated depending on
/// the platform with their respective function.
struct exception_t {
	/// Exception type, see the ExceptionType enumeration.
	ExceptionType type;
	/// Original OS code (exception or signal value).
	uint oscode;
	/// Process ID.
	uint pid;
	/// Thread ID, if available; Otherwise zero.
	uint tid;
	union {
		/// Memory address value
		size_t addrv;
		/// Memory address pointer
		void *addr;
	}
	/// Register count in registers field, populated by
	/// exception_reg_init.
	size_t regcount;
	/// Register population, this may depend on the OS and CRT
	register_t [REG_COUNT]registers;
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
 * (Internal) Translate an oscode to an ExceptionType enum value.
 * - Windows: `DEBUG_INFO.Exception.ExceptionRecord.ExceptionCode` and
 * `cast(uint)de.Exception.ExceptionRecord.ExceptionInformation[0]` in certain
 * cases.
 * - Posix: Signal number (`si_signo`) and its code `si_code` in certain cases.
 * Params:
 * 	code = OS code
 * 	subcode = OS sub-code
 * Returns: ExceptionType enum value
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
		case EXCEPTION_BREAKPOINT, STATUS_WX86_BREAKPOINT:
			return Breakpoint;
		case EXCEPTION_SINGLE_STEP, STATUS_WX86_SINGLE_STEP:
			return Step;
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
const(char) *exception_reg_fhex(register_t *reg) {
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
const(char) *exception_reg_fval(register_t *reg) {
	import utils.str : strf;
	
}*/

package:

// This is only here due to Windows' WOW64
enum InitPlatform {
	Native,
	x86,
	x86_64
}

// Thanks, Windows, for your silly WOW64
void exception_reg_init(exception_t *e, InitPlatform plat) {
	if (plat == InitPlatform.Native) {
		version (X86)
			plat = InitPlatform.x86;
		else version (X86_64)
			plat = InitPlatform.x86_64;
	}
	with (InitPlatform)
	switch (plat) {
	case x86:
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
		return;
	case x86_64:
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
		return;
	default:
	}
}

version (Windows) {

/// Populate exception_t.registers array from Windows' CONTEXT
int exception_ctx_windows(exception_t *e, CONTEXT *c) {
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

version (Win64)
int exception_ctx_windows_wow64(exception_t *e, WOW64_CONTEXT *c) {
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
	return 0;
}

} else // version Windows
version (Posix) {

/// Populate exception_t.registers array from user_regs_struct
int exception_ctx_user(exception_t *e, user_regs_struct *u) {
	version (X86) {
//		e.addrv = u.regs.eip;
		e.registers[0].u32 = u.eip;
		e.registers[1].u32 = u.eflags;
		e.registers[2].u32 = u.eax;
		e.registers[3].u32 = u.ebx;
		e.registers[4].u32 = u.ecx;
		e.registers[5].u32 = u.edx;
		e.registers[6].u32 = u.esp;
		e.registers[7].u32 = u.ebp;
		e.registers[8].u32 = u.esi;
		e.registers[9].u32 = u.edi;
	} else
	version (X86_64) {
//		e.addrv = u.regs.rip;
		e.registers[0].u64 = u.rip;
		e.registers[1].u32 = cast(uint)u.eflags;
		e.registers[2].u64 = u.rax;
		e.registers[3].u64 = u.rbx;
		e.registers[4].u64 = u.rcx;
		e.registers[5].u64 = u.rdx;
		e.registers[6].u64 = u.rsp;
		e.registers[7].u64 = u.rbp;
		e.registers[8].u64 = u.rsi;
		e.registers[9].u64 = u.rdi;
	}
	return 0;
}

} // version Posix