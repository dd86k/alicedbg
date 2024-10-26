/// ptrace(3) bindings for Linux.
///
/// x32 is not supported.
///
/// Source: Linux 6.5.7
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.include.linux.ptrace;

version (linux):

import adbg.include.c.config;

extern (C):

// include/uapi/linux/ptrace.h
enum PTRACE_MODE_READ	= 0x01;
enum PTRACE_MODE_ATTACH	= 0x02;
enum PTRACE_MODE_NOAUDIT	= 0x04;
enum PTRACE_MODE_FSCREDS	= 0x08;
enum PTRACE_MODE_REALCREDS	= 0x10;

/* shorthands for READ/ATTACH and FSCREDS/REALCREDS combinations */
enum PTRACE_MODE_READ_FSCREDS	= PTRACE_MODE_READ | PTRACE_MODE_FSCREDS;
enum PTRACE_MODE_READ_REALCREDS	= PTRACE_MODE_READ | PTRACE_MODE_REALCREDS;
enum PTRACE_MODE_ATTACH_FSCREDS	= PTRACE_MODE_ATTACH | PTRACE_MODE_FSCREDS;
enum PTRACE_MODE_ATTACH_REALCREDS	= PTRACE_MODE_ATTACH | PTRACE_MODE_REALCREDS;

enum PTRACE_TRACEME	= 0;
enum PTRACE_PEEKTEXT	= 1;
enum PTRACE_PEEKDATA	= 2;
enum PTRACE_PEEKUSR	= 3;
enum PTRACE_POKETEXT	= 4;
enum PTRACE_POKEDATA	= 5;
enum PTRACE_POKEUSR	= 6;
enum PTRACE_CONT	= 7;
enum PTRACE_KILL	= 8;
enum PTRACE_SINGLESTEP	= 9;
enum PTRACE_ATTACH	= 16;
enum PTRACE_DETACH	= 17;
enum PTRACE_SYSCALL	= 24;
enum PTRACE_SETOPTIONS	= 0x4200;
enum PTRACE_GETEVENTMSG	= 0x4201;
enum PTRACE_GETSIGINFO	= 0x4202;
enum PTRACE_SETSIGINFO	= 0x4203;
enum PTRACE_GETREGSET	= 0x4204;
enum PTRACE_SETREGSET	= 0x4205;
enum PTRACE_SEIZE	= 0x4206;
enum PTRACE_INTERRUPT	= 0x4207;
enum PTRACE_LISTEN	= 0x4208;
enum PTRACE_PEEKSIGINFO	= 0x4209;
enum PTRACE_GETSIGMASK	= 0x420a;
enum PTRACE_SETSIGMASK	= 0x420b;
enum PTRACE_SECCOMP_GET_FILTER	= 0x420c;
enum PTRACE_SECCOMP_GET_METADATA	= 0x420d;
enum PTRACE_GET_SYSCALL_INFO	= 0x420e;
enum PTRACE_SYSCALL_INFO_NONE	= 0;
enum PTRACE_SYSCALL_INFO_ENTRY	= 1;
enum PTRACE_SYSCALL_INFO_EXIT	= 2;
enum PTRACE_SYSCALL_INFO_SECCOMP	=3;
enum PTRACE_GET_RSEQ_CONFIGURATION	= 0x420f;
enum PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG	= 0x4210;
enum PTRACE_GET_SYSCALL_USER_DISPATCH_CONFIG	= 0x4211;
enum PTRACE_EVENTMSG_SYSCALL_ENTRY	= 1;
enum PTRACE_EVENTMSG_SYSCALL_EXIT	= 2;
enum PTRACE_PEEKSIGINFO_SHARED	= 1 << 0;
enum PTRACE_EVENT_FORK	= 1;
enum PTRACE_EVENT_VFORK	= 2;
enum PTRACE_EVENT_CLONE	= 3;
enum PTRACE_EVENT_EXEC	= 4;
enum PTRACE_EVENT_VFORK_DONE	= 5;
enum PTRACE_EVENT_EXIT	= 6;
enum PTRACE_EVENT_SECCOMP	= 7;
enum PTRACE_EVENT_STOP	= 128;
enum PTRACE_O_TRACESYSGOOD	= 1;
enum PTRACE_O_TRACEFORK	= 1 << PTRACE_EVENT_FORK;
enum PTRACE_O_TRACEVFORK	= 1 << PTRACE_EVENT_VFORK;
enum PTRACE_O_TRACECLONE	= 1 << PTRACE_EVENT_CLONE;
enum PTRACE_O_TRACEEXEC	= 1 << PTRACE_EVENT_EXEC;
enum PTRACE_O_TRACEVFORKDONE	= 1 << PTRACE_EVENT_VFORK_DONE;
enum PTRACE_O_TRACEEXIT	= 1 << PTRACE_EVENT_EXIT;
enum PTRACE_O_TRACESECCOMP	= 1 << PTRACE_EVENT_SECCOMP;
enum PTRACE_O_EXITKILL	= 1 << 20;
enum PTRACE_O_SUSPEND_SECCOMP	= 1 << 21;
enum PTRACE_O_MASK	= 0x000000ff | PTRACE_O_EXITKILL | PTRACE_O_SUSPEND_SECCOMP;

// arch/x86/include/uapi/asm/ptrace-abi.h
version (X86) version = X86_Any;
version (X86_64) {
	version = X86_Any;
	enum PTRACE_ARCH_PRCTL	= 30;
}
version (X86_Any) {
	enum PTRACE_GETREGS	= 12;
	enum PTRACE_SETREGS	= 13;
	enum PTRACE_GETFPREGS	= 14;
	enum PTRACE_SETFPREGS	= 15;
	enum PTRACE_GETFPXREGS	= 18;
	enum PTRACE_SETFPXREGS	= 19;

	enum PTRACE_OLDSETOPTIONS	= 21;

	// only useful for access 32bit programs / kernels
	enum PTRACE_GET_THREAD_AREA	= 25;
	enum PTRACE_SET_THREAD_AREA	= 26;

	enum PTRACE_SYSEMU	= 31;
	enum PTRACE_SYSEMU_SINGLESTEP	= 32;

	enum PTRACE_SINGLEBLOCK	= 33;	/* resume execution until next branch */
}

// arch/arm/include/asm/ptrace.h
// arch/arm64/include/asm/ptrace.h
version (ARM) version = ARM_Any;
version (AArch64) {
	version = ARM_Any;
	// These are 'magic' values for PTRACE_PEEKUSR that return info about
	// where a process is located in memory.
	enum COMPAT_PT_TEXT_ADDR	= 0x10000;
	enum COMPAT_PT_DATA_ADDR	= 0x10004;
	enum COMPAT_PT_TEXT_END_ADDR	= 0x10008;
}
version (ARM_Any) {
	enum PTRACE_GETREGS	= 12;	// + aarch32
	enum PTRACE_SETREGS	= 13;	// + aarch32
	enum PTRACE_GETFPREGS	= 14;
	enum PTRACE_SETFPREGS	= 15;
	enum PTRACE_GETWMMXREGS	= 18;
	enum PTRACE_SETWMMXREGS	= 19;
	enum PTRACE_OLDSETOPTIONS	= 21;
	enum PTRACE_GET_THREAD_AREA	= 22;	// + aarch32
	enum PTRACE_SET_SYSCALL	= 23;	// + aarch32
	enum PTRACE_GETCRUNCHREGS	= 25; /* obsolete */
	enum PTRACE_SETCRUNCHREGS	= 26; /* obsolete */
	enum PTRACE_GETVFPREGS	= 27;	// + aarch32
	enum PTRACE_SETVFPREGS	= 28;	// + aarch32
	enum PTRACE_GETHBPREGS	= 29;	// + aarch32
	enum PTRACE_SETHBPREGS	= 30;	// + aarch32
	enum PTRACE_GETFDPIC	= 31;

	enum PTRACE_GETFDPIC_EXEC	= 0;
	enum PTRACE_GETFDPIC_INTERP	= 1;
}

// arch/powerpc/include/uapi/ptrace.h
version (PPC) version = PPC_Any;
version (PPC64) version = PPC_Any;
version (PPC_Any) {
	enum PTRACE_GETVRREGS	= 0x12;
	enum PTRACE_SETVRREGS	= 0x13;
	enum PTRACE_GETEVRREGS	= 0x14;
	enum PTRACE_SETEVRREGS	= 0x15;
	enum PTRACE_GETVSRREGS	= 0x1b;
	enum PTRACE_SETVSRREGS	= 0x1c;
	enum PTRACE_SYSEMU	= 0x1d;
	enum PTRACE_SYSEMU_SINGLESTEP	= 0x1e;
	enum PTRACE_GET_DEBUGREG	= 0x19;
	enum PTRACE_SET_DEBUGREG	= 0x1a;
	
	enum PTRACE_GETREGS	= 0xc;
	enum PTRACE_SETREGS	= 0xd;
	enum PTRACE_GETFPREGS	= 0xe;
	enum PTRACE_SETFPREGS	= 0xf;
	enum PTRACE_GETREGS64	= 0x16;
	enum PTRACE_SETREGS64	= 0x17;

	enum PPC_PTRACE_PEEKTEXT_3264	= 0x95;
	enum PPC_PTRACE_PEEKDATA_3264	= 0x94;
	enum PPC_PTRACE_POKETEXT_3264	= 0x93;
	enum PPC_PTRACE_POKEDATA_3264	= 0x92;
	enum PPC_PTRACE_PEEKUSR_3264	= 0x91;
	enum PPC_PTRACE_POKEUSR_3264	= 0x90;

	enum PTRACE_SINGLEBLOCK	= 0x100;	/* resume execution until next branch */

	enum PPC_PTRACE_GETHWDBGINFO	= 0x89;
	enum PPC_PTRACE_SETHWDEBUG	= 0x88;
	enum PPC_PTRACE_DELHWDEBUG	= 0x87;

}

/// The ptrace() system call provides a means by which one process (the
/// "tracer") may observe and control the execution of another process
/// (the "tracee"), and examine and change the tracee's memory and
/// registers.  It is primarily used to implement breakpoint debugging
/// and system call tracing.
///
/// Although arguments to ptrace() are interpreted according to the
/// prototype given, glibc currently declares ptrace() as a variadic
/// function with only the request argument fixed.  It is recommended
/// to always supply four arguments, even if the requested operation
/// does not use them, setting unused/ignored arguments to 0L or
/// (void *) 0.
/// 
/// Params:
/// 	req = PTRACE request
/// 	pid = Process ID number (On Linux, that's a thread ID)
/// 	addr = Memory pointer
/// 	data = Data pointer
/// 
/// Returns: 0 on success; -1 on error. For PT_PEEK requests, check errno
/// first
c_long ptrace(int req, ...);