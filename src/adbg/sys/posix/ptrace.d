/**
 * ptrace(2) bindings, since the D stdlib lack them. This module adbg.is only
 * available on Posix systems where ptrace is available, and is currently
 * based on Glibc 2.25. Support for more runtimes will be implemented
 * here with time.
 *
 * License: BSD 3-Clause
 */
module adbg.debugger.sys.ptrace;

version (Posix):

import core.stdc.config : c_long;
import core.sys.posix.time : clock_t;
import core.sys.posix.sys.types : pid_t, uid_t;

extern (C):

version (CRuntime_Glibc) { // 2.25
	public import core.sys.posix.signal :
		siginfo_t,
		SIGSEGV, SIGFPE, SIGILL, SIGINT, SIGTERM, SIGABRT,
		SIGTRAP, SIGBUS;
	version (linux) {
		enum {	// __ptrace_request
			/// Indicate that the process making this request should be traced.
			/// All signals received by this process can be intercepted by its
			/// parent, and its parent can use the other `ptrace' requests.
			PTRACE_TRACEME = 0,
			/// Return the word in the process's text space at address ADDR.
			PTRACE_PEEKTEXT = 1,
			/// Return the word in the process's data space at address ADDR.
			PTRACE_PEEKDATA = 2,
			/// Return the word in the process's user area at offset ADDR.
			PTRACE_PEEKUSER = 3,
			/// Write the word DATA into the process's text space at address ADDR.
			PTRACE_POKETEXT = 4,
			/// Write the word DATA into the process's data space at address ADDR.
			PTRACE_POKEDATA = 5,
			/// Write the word DATA into the process's user area at offset ADDR.
			PTRACE_POKEUSER = 6,
			/// Continue the process.
			PTRACE_CONT = 7,
			/// Kill the process. (deprecated)
			PTRACE_KILL = 8,
			/// Single step the process.
			/// This is not supported on all machines.
			PTRACE_SINGLESTEP = 9,
			/// Get all general purpose registers used by a processes.
			/// This is not supported on all machines.
			PTRACE_GETREGS = 12,
			/// Set all general purpose registers used by a processes.
			/// This is not supported on all machines.
			PTRACE_SETREGS = 13,
			/// Get all floating point registers used by a processes.
			/// This is not supported on all machines.
			PTRACE_GETFPREGS = 14,
			/// Set all floating point registers used by a processes.
			/// This is not supported on all machines.
			PTRACE_SETFPREGS = 15,
			/// Attach to a process that is already running.
			PTRACE_ATTACH = 16,
			/// Detach from a process attached to with PTRACE_ATTACH.
			PTRACE_DETACH = 17,
			/// Get all extended floating point registers used by a processes.
			/// This is not supported on all machines.
			PTRACE_GETFPXREGS = 18,
			/// Set all extended floating point registers used by a processes.
			/// This is not supported on all machines.
			PTRACE_SETFPXREGS = 19,
			/// Continue and stop at the next (return from) syscall.
			PTRACE_SYSCALL = 24,
			/// Set ptrace filter options.
			PTRACE_SETOPTIONS = 0x4200,
			/// Get last ptrace message.
			PTRACE_GETEVENTMSG = 0x4201,
			/// Get siginfo for process.
			PTRACE_GETSIGINFO = 0x4202,
			/// Set new siginfo for process.
			PTRACE_SETSIGINFO = 0x4203,
			/// Get register content.
			PTRACE_GETREGSET = 0x4204,
			/// Set register content.
			PTRACE_SETREGSET = 0x4205,
			/// Like PTRACE_ATTACH, but do not force tracee to trap and do
			/// not affect signal or group stop state.
			PTRACE_SEIZE = 0x4206,
			/// Trap seized tracee.
			PTRACE_INTERRUPT = 0x4207,
			/// Wait for next group event.
			PTRACE_LISTEN = 0x4208,
			/// 
			PTRACE_PEEKSIGINFO = 0x4209,
			/// 
			PTRACE_GETSIGMASK = 0x420a,
			/// 
			PTRACE_SETSIGMASK = 0x420b,
			///
			PTRACE_SECCOMP_GET_FILTER = 0x420c
		}
		enum {	// __ptrace_setoptions
			PTRACE_O_TRACESYSGOOD	= 0x00000001,	/// mark upper bit when system call traps
			PTRACE_O_TRACEFORK	= 0x00000002,	/// trace fork calls
			PTRACE_O_TRACEVFORK	= 0x00000004,	/// trace vfork calls
			PTRACE_O_TRACECLONE	= 0x00000008,	/// trace clone calls
			PTRACE_O_TRACEEXEC	= 0x00000010,	/// trace exec calls
			PTRACE_O_TRACEVFORKDONE = 0x00000020,	/// trace vfork_done events
			PTRACE_O_TRACEEXIT	= 0x00000040,	/// trace exit calls
			PTRACE_O_TRACESECCOMP	= 0x00000080,	/// trace seccomp calls
			PTRACE_O_EXITKILL	= 0x00100000,	/// trace exit+kill calls
			PTRACE_O_SUSPEND_SECCOMP	= 0x00200000,	/// syspend on seccomp
			PTRACE_O_MASK	= 0x003000ff	/// mask
		}
		enum {	// __ptrace_eventcodes
			PTRACE_EVENT_FORK	= 1,	/// fork event
			PTRACE_EVENT_VFORK	= 2,	/// vfork event
			PTRACE_EVENT_CLONE	= 3,	/// clone event
			PTRACE_EVENT_EXEC	= 4,	/// exec event
			PTRACE_EVENT_VFORK_DONE = 5,	/// vfork done event
			PTRACE_EVENT_EXIT	= 6,	/// exit event
			PTRACE_EVENT_SECCOMP  = 7	/// seccomp event
		}
		struct __ptrace_peeksiginfo_args {
			ulong off;	/// From which siginfo to start.
			uint flags;	/// Flags for peeksiginfo.
			uint nr;	/// How many siginfos to take.
		}
		enum {	// __ptrace_peeksiginfo_flags
			/// Read signals from a shared (process wide) queue.
			PTRACE_PEEKSIGINFO_SHARED = 1
		}
	} else
	version (AArch64) {
		enum {
			PTRACE_TRACE_ME,	/// The only request of which a tracee can make

		}
	} else { // Generic
		enum {
			PTRACE_TRACE_ME,	///
			PTRACE_PEEKTEXT,	///
			PTRACE_PEEKDATA,	///
			PTRACE_PEEKUSER,	///
			PTRACE_POKETEXT,	///
			PTRACE_POKEDATA,	///
			PTRACE_POKEUSER,	///
			PTRACE_CONT,	///
			PTRACE_KILL,	///
			PTRACE_SINGLESTEP,	///
			PTRACE_ATTACH,	///
			PTRACE_DETACH,	///
			PTRACE_GETREGS,	///
			PTRACE_SETREGS,	///
			PTRACE_GETFPREGS,	///
			PTRACE_SETFPREGS,	///
			PTRACE_READDATA,	///
			PTRACE_WRITEDATA,	///
			PTRACE_READTEXT,	///
			PTRACE_WRITETEXT,	///
			PTRACE_GETFPAREGS,	///
			PTRACE_SETFPAREGS	///
		}
	} // version linux
} else
version (CRuntime_Musl) { // 1.20
	enum SIGHUP	= 1;	/// 
	enum SIGINT	= 2;	/// 
	enum SIGQUIT	= 3;	/// 
	enum SIGILL	= 4;	/// 
	enum SIGTRAP	= 5;	/// 
	enum SIGABRT	= 6;	/// 
	enum SIGIOT	= SIGABRT;	/// 
	enum SIGBUS	= 7;	/// 
	enum SIGFPE	= 8;	/// 
	enum SIGKILL	= 9;	/// 
	enum SIGUSR1	= 10;	/// 
	enum SIGSEGV	= 11;	/// 
	enum SIGUSR2	= 12;	/// 
	enum SIGPIPE	= 13;	/// 
	enum SIGALRM	= 14;	/// 
	enum SIGTERM	= 15;	/// 
	enum SIGSTKFLT	= 16;	/// 
	enum SIGCHLD	= 17;	/// 
	enum SIGCONT	= 18;	/// 
	enum SIGSTOP	= 19;	/// 
	enum SIGTSTP	= 20;	/// 
	enum SIGTTIN	= 21;	/// 
	enum SIGTTOU	= 22;	/// 
	enum SIGURG	= 23;	/// 
	enum SIGXCPU	= 24;	/// 
	enum SIGXFSZ	= 25;	/// 
	enum SIGVTALRM	= 26;	/// 
	enum SIGPROF	= 27;	/// 
	enum SIGWINCH	= 28;	/// 
	enum SIGIO	= 29;	/// 
	enum SIGPOLL	= 29;	/// 
	enum SIGPWR	= 30;	/// 
	enum SIGSYS	= 31;	/// 
	enum SIGUNUSED	= SIGSYS;	/// 

	enum _NSIG = 65;

	enum PTRACE_TRACEME	= 0;	/// 
	enum PTRACE_PEEKTEXT	= 1;	/// 
	enum PTRACE_PEEKDATA	= 2;	/// 
	enum PTRACE_PEEKUSER	= 3;	/// 
	enum PTRACE_POKETEXT	= 4;	/// 
	enum PTRACE_POKEDATA	= 5;	/// 
	enum PTRACE_POKEUSER	= 6;	/// 
	enum PTRACE_CONT	= 7;	/// 
	enum PTRACE_KILL	= 8;	/// 
	enum PTRACE_SINGLESTEP	= 9;	/// 
	enum PTRACE_GETREGS	= 2;	/// 
	enum PTRACE_SETREGS	= 3;	/// 
	enum PTRACE_GETFPREGS	= 4;	/// 
	enum PTRACE_SETFPREGS	= 5;	/// 
	enum PTRACE_ATTACH	= 6;	/// 
	enum PTRACE_DETACH	= 7;	/// 
	enum PTRACE_GETFPXREGS	= 8;	/// 
	enum PTRACE_SETFPXREGS	= 9;	/// 
	enum PTRACE_SYSCALL	= 4;	/// 
	enum PTRACE_SETOPTIONS	= 0x420;	/// 
	enum PTRACE_GETEVENTMSG	= 0x421;	/// 
	enum PTRACE_GETSIGINFO	= 0x422;	/// 
	enum PTRACE_SETSIGINFO	= 0x423;	/// 
	enum PTRACE_GETREGSET	= 0x424;	/// 
	enum PTRACE_SETREGSET	= 0x425;	/// 
	enum PTRACE_SEIZE	= 0x426;	/// 
	enum PTRACE_INTERRUPT	= 0x427;	/// 
	enum PTRACE_LISTEN	= 0x428;	/// 
	enum PTRACE_PEEKSIGINFO	= 0x429;	/// 
	enum PTRACE_GETSIGMASK	= 0x42a;	/// 
	enum PTRACE_SETSIGMASK	= 0x42b;	/// 
	enum PTRACE_SECCOMP_GET_FILTER	= 0x42c;	/// 
	enum PTRACE_SECCOMP_GET_METADATA	= 0x42d;	/// 
	enum PTRACE_GET_SYSCALL_INFO	= 0x42e;	/// 

	enum PTRACE_O_TRACESYSGOOD	= 0x00000001;	/// 
	enum PTRACE_O_TRACEFORK	= 0x00000002;	/// 
	enum PTRACE_O_TRACEVFORK	= 0x00000004;	/// 
	enum PTRACE_O_TRACECLONE	= 0x00000008;	/// 
	enum PTRACE_O_TRACEEXEC	= 0x00000010;	/// 
	enum PTRACE_O_TRACEVFORKDONE	= 0x00000020;	/// 
	enum PTRACE_O_TRACEEXIT	= 0x00000040;	/// 
	enum PTRACE_O_TRACESECCOMP	= 0x00000080;	/// 
	enum PTRACE_O_EXITKILL	= 0x00100000;	/// 
	enum PTRACE_O_SUSPEND_SECCOMP	= 0x00200000;	/// 
	enum PTRACE_O_MASK	= 0x003000ff;	/// 

	enum PTRACE_EVENT_FORK	= 1;	/// 
	enum PTRACE_EVENT_VFORK	= 2;	/// 
	enum PTRACE_EVENT_CLONE	= 3;	/// 
	enum PTRACE_EVENT_EXEC	= 4;	/// 
	enum PTRACE_EVENT_VFORK_DONE	= 5;	/// 
	enum PTRACE_EVENT_EXIT	= 6;	/// 
	enum PTRACE_EVENT_SECCOMP	= 7;	/// 
	enum PTRACE_EVENT_STOP	= 128;	/// 

	enum PTRACE_PEEKSIGINFO_SHARED	= 1;	/// 

	enum PTRACE_SYSCALL_INFO_NONE	= 0;	/// 
	enum PTRACE_SYSCALL_INFO_ENTRY	= 1;	/// 
	enum PTRACE_SYSCALL_INFO_EXIT	= 2;	/// 
	enum PTRACE_SYSCALL_INFO_SECCOMP	= 3;	/// 
} else
static assert(0, "Missing ptrace definitions");

//
// elf.h values off musl 1.20
//

enum NT_PRSTATUS	= 1;	/// 
enum NT_PRFPREG	= 2;	/// 
enum NT_FPREGSET	= 2;	/// 
enum NT_PRPSINFO	= 3;	/// 
enum NT_PRXREG	= 4;	/// 
enum NT_TASKSTRUCT	= 4;	/// 
enum NT_PLATFORM	= 5;	/// 
enum NT_AUXV	= 6;	/// 
enum NT_GWINDOWS	= 7;	/// 
enum NT_ASRS	= 8;	/// 
enum NT_PSTATUS	= 10;	/// 
enum NT_PSINFO	= 13;	/// 
enum NT_PRCRED	= 14;	/// 
enum NT_UTSNAME	= 15;	/// 
enum NT_LWPSTATUS	= 16;	/// 
enum NT_LWPSINFO	= 17;	/// 
enum NT_PRFPXREG	= 20;	/// 
enum NT_SIGINFO	= 0x53494749;	/// 
enum NT_FILE	= 0x46494c45;	/// 
enum NT_PRXFPREG	= 0x46e62b7f;	/// 
enum NT_PPC_VMX	= 0x100;	/// 
enum NT_PPC_SPE	= 0x101;	/// 
enum NT_PPC_VSX	= 0x102;	/// 
enum NT_PPC_TAR	= 0x103;	/// 
enum NT_PPC_PPR	= 0x104;	/// 
enum NT_PPC_DSCR	= 0x105;	/// 
enum NT_PPC_EBB	= 0x106;	/// 
enum NT_PPC_PMU	= 0x107;	/// 
enum NT_PPC_TM_CGPR	= 0x108;	/// 
enum NT_PPC_TM_CFPR	= 0x109;	/// 
enum NT_PPC_TM_CVMX	= 0x10a;	/// 
enum NT_PPC_TM_CVSX	= 0x10b;	/// 
enum NT_PPC_TM_SPR	= 0x10c;	/// 
enum NT_PPC_TM_CTAR	= 0x10d;	/// 
enum NT_PPC_TM_CPPR	= 0x10e;	/// 
enum NT_PPC_TM_CDSCR	= 0x10f;	/// 
enum NT_386_TLS	= 0x200;	/// 
enum NT_386_IOPERM	= 0x201;	/// 
enum NT_X86_XSTATE	= 0x202;	/// 
enum NT_S390_HIGH_GPRS	= 0x300;	/// 
enum NT_S390_TIMER	= 0x301;	/// 
enum NT_S390_TODCMP	= 0x302;	/// 
enum NT_S390_TODPREG	= 0x303;	/// 
enum NT_S390_CTRS	= 0x304;	/// 
enum NT_S390_PREFIX	= 0x305;	/// 
enum NT_S390_LAST_BREAK	= 0x306;	/// 
enum NT_S390_SYSTEM_CALL	= 0x307;	/// 
enum NT_S390_TDB	= 0x308;	/// 
enum NT_S390_VXRS_LOW	= 0x309;	/// 
enum NT_S390_VXRS_HIGH	= 0x30a;	/// 
enum NT_S390_GS_CB	= 0x30b;	/// 
enum NT_S390_GS_BC	= 0x30c;	/// 
enum NT_S390_RI_CB	= 0x30d;	/// 
enum NT_ARM_VFP	= 0x400;	/// 
enum NT_ARM_TLS	= 0x401;	/// 
enum NT_ARM_HW_BREAK	= 0x402;	/// 
enum NT_ARM_HW_WATCH	= 0x403;	/// 
enum NT_ARM_SYSTEM_CALL	= 0x404;	/// 
enum NT_ARM_SVE	= 0x405;	/// 
enum NT_ARM_PAC_MASK	= 0x406;	/// 
enum NT_ARM_PACA_KEYS	= 0x407;	/// 
enum NT_ARM_PACG_KEYS	= 0x408;	/// 
enum NT_METAG_CBUF	= 0x500;	/// 
enum NT_METAG_RPIPE	= 0x501;	/// 
enum NT_METAG_TLS	= 0x502;	/// 
enum NT_ARC_V2	= 0x600;	/// 
enum NT_VMCOREDD	= 0x700;	/// 
enum NT_MIPS_DSP	= 0x800;	/// 
enum NT_MIPS_FP_MODE	= 0x801;	/// 
enum NT_MIPS_MSA	= 0x802;	/// 
enum NT_VERSION	= 1;	/// 

/**
 * The ptrace() system call provides a means by which one process (the
 * "tracer") may observe and control the execution of another process
 * (the "tracee"), and examine and change the tracee's memory and
 * registers.  It is primarily used to implement breakpoint debugging
 * and system call tracing.
 * 
 * Params:
 * 	request = See PTRACE_* enumeration values
 * 	pid = Process ID number
 * 	addr = Memory pointer
 * 	data = Data pointer
 * 
 * Returns: 0 on success; -1 on error. For PTRACE_PEEK requests, check errno
 * first
 */
c_long ptrace(int request, ...);