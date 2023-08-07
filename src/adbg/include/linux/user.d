/// Linux user thread context.
/// 
/// Required for PTRACE_GETREGS.
///
/// Despite glibc explaining in sysdeps/unix/sysv/linux/x86/sys/user.h@L21:
/// ---
/// // The whole purpose of this file is for GDB and GDB only.  Don't read
/// // too much into it.  Don't use it for anything other than GDB unless
/// // you know what you are doing.
/// ---
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.include.linux.user;

// NOTE: User and ptrace contexts
//       user and pt_regs structures may differ.
//       PTRACE_GETREGS typically requires pt_regs.
//       The definition can be found in arch/*/include/asm/ptrace.h

version (linux):

import adbg.include.c.config;

version (X86) {
	/// 
	struct user_fpregs {
		int cwd;	/// 
		int swd;	/// 
		int twd;	/// 
		int fip;	/// 
		int fcs;	/// 
		int foo;	/// 
		int fos;	/// 
		int[20] st_space;	/// 
	}
	/// 
	struct user_fpxregs {
		/// 
		ushort cwd;
		/// 
		ushort swd;
		/// 
		ushort twd;
		/// 
		ushort fop;
		/// 
		int fip;
		/// 
		int fcs;
		/// 
		int foo;
		/// 
		int fos;
		/// 
		int mxcsr;
		/// 
		int reserved;
		/// 8*16 bytes for each FP-reg = 128 bytes
		int [32]st_space;
		/// 8*16 bytes for each XMM-reg = 128 bytes
		int [32]xmm_space;
		/// 
		int [56]padding;
	}
	/// 
	struct user_regs_struct {
		uint ebx;	/// 
		uint ecx;	/// 
		uint edx;	/// 
		uint esi;	/// 
		uint edi;	/// 
		uint ebp;	/// 
		uint eax;	/// 
		uint xds;	/// 
		uint xes;	/// 
		uint xfs;	/// 
		uint xgs;	/// 
		uint orig_eax;	/// 
		uint eip;	/// 
		uint xcs;	/// 
		uint eflags;	/// 
		uint esp;	/// 
		uint xss;	/// 
	}
	/// 
	struct user {
		/// 
		user_regs_struct regs;
		/// 
		int u_fpvalid;
		/// 
		user_fpregs i387;
		/// Text segment size (pages).
		uint u_tsize;
		/// Data segment size (pages).
		uint u_dsize;
		/// Stack segment size (pages).
		uint u_ssize;
		/// Starting virtual address of text.
		uint start_code;
		/// Starting virtual address of stack area.
		uint start_stack;
		/// 
		int signal;
		/// 
		int reserved;
		/// 
		user_regs*	u_ar0;
		/// 
		user_fpregs*	u_fpstate;
		/// 
		uint magic;
		/// 
		char[32] u_comm;
		/// 
		int[8] u_debugreg;
	}
} else version (X86_64) {
	/// 
	struct user_fpregs {
		ushort cwd;	/// 
		ushort swd;	/// 
		ushort ftw;	/// 
		ushort fop;	/// 
		ulong rip;	/// 
		ulong rdp;	/// 
		uint mxcsr;	/// 
		uint mxcr_mask;	/// 
		/// 8*16 bytes for each FP-reg = 128 bytes
		uint[32] st_space;
		/// 16*16 bytes for each XMM-reg = 256 bytes
		uint[64] xmm_space;
		uint[32] padding;	/// 
	}
	/// 
	struct user_regs_struct {
		ulong r15;	/// 
		ulong r14;	/// 
		ulong r13;	/// 
		ulong r12;	/// 
		ulong rbp;	/// 
		ulong rbx;	/// 
		ulong r11;	/// 
		ulong r10;	/// 
		ulong r9;	/// 
		ulong r8;	/// 
		ulong rax;	/// 
		ulong rcx;	/// 
		ulong rdx;	/// 
		ulong rsi;	/// 
		ulong rdi;	/// 
		ulong orig_rax;	/// 
		ulong rip;	/// 
		ulong cs;	/// 
		ulong eflags;	/// 
		ulong rsp;	/// 
		ulong ss;	/// 
		ulong fs_base;	/// 
		ulong gs_base;	/// 
		ulong ds;	/// 
		ulong es;	/// 
		ulong fs;	/// 
		ulong gs;	/// 
	}
	/// 
	struct user {
		/// 
		user_regs_struct regs;
		/// 
		int u_fpvalid;
		/// 
		user_fpregs i387;
		/// Text segment size (pages).
		long u_tsize;
		/// Data segment size (pages).
		long u_dsize;
		/// Stack segment size (pages).
		long u_ssize;
		/// Starting virtual address of text.
		long start_code;
		/// Starting virtual address of stack area.
		long start_stack;
		/// 
		long signal;
		/// 
		int reserved;
		union {
			user_regs *u_ar0;	/// 
			ulong __u_ar0_word;	/// 
		}
		union {
			user_fpregs *u_fpstate;	/// 
			ulong __u_fpstate_word;	/// 
		}
		///
		ulong magic;
		///
		char  [32]u_comm;
		///
		ulong [8]u_debugreg;
		ulong error_code;	/// 
		ulong fault_address;	/// 
	}
} else version (ARM) {
	// sysdeps/unix/sysv/linux/arm/sys/user.h
	// sysdeps/unix/sysv/linux/arm/sys/ucontext.h
	
	enum NGREG = 18;
	
	
	/*#define ARM_cpsr	uregs[16]
	#define ARM_pc		uregs[15]
	#define ARM_lr		uregs[14]
	#define ARM_sp		uregs[13]
	#define ARM_ip		uregs[12]
	#define ARM_fp		uregs[11]
	#define ARM_r10		uregs[10]
	#define ARM_r9		uregs[9]
	#define ARM_r8		uregs[8]
	#define ARM_r7		uregs[7]
	#define ARM_r6		uregs[6]
	#define ARM_r5		uregs[5]
	#define ARM_r4		uregs[4]
	#define ARM_r3		uregs[3]
	#define ARM_r2		uregs[2]
	#define ARM_r1		uregs[1]
	#define ARM_r0		uregs[0]
	#define ARM_ORIG_r0	uregs[17]*/
	struct user_regs_struct {
		c_ulongint r0;
		c_ulongint r1;
		c_ulongint r2;
		c_ulongint r3;
		c_ulongint r4;
		c_ulongint r5;
		c_ulongint r6;
		c_ulongint r7;
		c_ulongint r8;
		c_ulongint r9;
		c_ulongint r10;
		c_ulongint fp;
		c_ulongint ip;
		c_ulongint sp;
		c_ulongint lr;
		c_ulongint pc;
		c_ulongint orig_r0;
	}
	struct user_regs_struct {
		c_ulongint[NGREG] uregs;	/// 
	}
	
	struct fpregset_t {
		struct fpregs_t { /*
			unsigned int sign1:1;
			unsigned int unused:15;
			unsigned int sign2:1;
			unsigned int exponent:14;
			unsigned int j:1;
			unsigned int mantissa1:31;
			unsigned int mantissa0:32;*/
			ushort sign1;
			ushort sign2j;
			uint mantissa1;
			uint mantissa0;
		}
		fpregs_t[8] fpregs;
		uint fpsr; // status
		uint fpcr; // control
		ubyte[8] ftype;
		uint init_flag;
	}
	alias fpregset_t user_fpregs;
	
	struct ucontext {
		c_ulong uc_flags;
		ucontext *link;
		__sigset_t uc_sigmask;
		align(8) c_ulong[128] uc_regspace;
	}
	
	struct user {
		user_regs_struct regs;	/// 
		int u_fpvalid;	/// 
		
		c_ulongint u_tsize;	/// 
		c_ulongint u_dsize;	/// 
		c_ulongint u_ssize;	/// 
		
		c_ulong start_code;	/// 
		c_ulong start_stack;	/// 
		
		c_longint signal;	/// 
		int reserved;	/// 
		user_regs *u_ar0;	/// 
		
		c_ulong magic;	/// 
		ubyte[32] u_comm;	/// 
		int[8] u_debugreg;	/// 
		user_fpregs u_fp;	/// 
		user_fpregs *u_fp0;	/// 
	}
} else version (AArch64) {
	// sysdeps/unix/sysv/linux/aarch64/sys/user.h
	// sysdeps/unix/sysv/linux/aarch64/sys/ucontext.h
	// arch/arm64/include/asm/ptrace.h
	
	public import core.sys.posix.ucontext : mcontext_t;
	public import core.sys.posix.signal : sigset_t;
	
	//TODO: Move uint128_t in some config file (c, d, or adbg.config)
	struct __uint128_t {
		ulong[2] parts;
	}
	
	struct user_fpsimd {
		__uint128_t[32] vregs;
		uint fpsr;
		uint fpcr;
	}
	
	// user_pt_regs
	struct user_regs_struct {
		ulong[31] regs;
		ulong sp;
		ulong pc;
		ulong pstate;
	}
	
	/// User structure
	struct user {
		user_regs_struct regs;	/// General registers
		int u_fpvalid;	/// True if math co-processor being used.

		c_ulongint u_tsize;	/// Text segment size (pages).
		c_ulongint u_dsize;	/// Data segment size (pages).
		c_ulongint u_ssize;	/// Stack segment size (pages).

		c_ulong start_code;	/// Starting virtual address of text.
		c_ulong start_stack;	/// Starting virtual address of stack.

		c_longint signal;	/// Signal that caused the core dump.
		int reserved;	/// No longer used
		user_regs *u_ar0;	/// help gdb to find the general registers.

		c_ulong magic;		/// uniquely identify a core file
		ubyte[32] u_comm;		/// User command that was responsible
		int[8] u_debugreg;	/// No longer used
		user_fpregs u_fp;	/// Floating point registers
		user_fpregs *u_fp0;	/// help gdb to find the FP registers.
	}
} else version (RISCV64) {
	/*
	 * User-mode register state for core dumps, ptrace, sigcontext
	 *
	 * This decouples struct pt_regs from the userspace ABI.
	 * struct user_regs_struct must form a prefix of struct pt_regs.
	 */
	struct user_regs_struct {
		c_ulong pc;
		c_ulong ra;
		c_ulong sp;
		c_ulong gp;
		c_ulong tp;
		c_ulong t0;
		c_ulong t1;
		c_ulong t2;
		c_ulong s0;
		c_ulong s1;
		c_ulong a0;
		c_ulong a1;
		c_ulong a2;
		c_ulong a3;
		c_ulong a4;
		c_ulong a5;
		c_ulong a6;
		c_ulong a7;
		c_ulong s2;
		c_ulong s3;
		c_ulong s4;
		c_ulong s5;
		c_ulong s6;
		c_ulong s7;
		c_ulong s8;
		c_ulong s9;
		c_ulong s10;
		c_ulong s11;
		c_ulong t3;
		c_ulong t4;
		c_ulong t5;
		c_ulong t6;
	}
}