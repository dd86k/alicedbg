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
/// Copyright: © 2019-2022 dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.include.linux.user;

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
	struct user_regs {
		int ebx;	/// 
		int ecx;	/// 
		int edx;	/// 
		int esi;	/// 
		int edi;	/// 
		int ebp;	/// 
		int eax;	/// 
		int xds;	/// 
		int xes;	/// 
		int xfs;	/// 
		int xgs;	/// 
		int orig_eax;	/// 
		int eip;	/// 
		int xcs;	/// 
		int eflags;	/// 
		int esp;	/// 
		int xss;	/// 
	}
	/// 
	struct user {
		/// 
		user_regs regs;
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
	struct user_regs {
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
		user_regs regs;
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
	
	// typedef greg_t gregset_t[NGREG]; // #define NGREG	18
	struct user_regs {
		int r0, r1, r2, r3, r4, r5, r6, r7, r8,
			r9, r10, r11, r12, r13, r14, r15;
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
	
	struct user_regs {
		c_ulongint[18] uregs;	/// 
	}
	
	struct user {
		user_regs regs;	/// 
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
	public import core.sys.posix.ucontext : mcontext_t;
	public import core.sys.posix.signal : sigset_t;
	
	//TODO: Move uint128_t in some config file (c, d, or adbg.config)
	struct __uint128_t {
		ulong[2] parts;
	}
	
	struct user_regs {
		ulong[31] regs;
		ulong sp;
		ulong pc;
		ulong pstate;
	}
	
	struct user_fpsimd {
		__uint128_t[32] vregs;
		uint fpsr;
		uint fpcr;
	}
	
	/+struct sigstack_t {
		void *ss_sp;
		int ss_flags;
		size_t ss_size;
	}
	
	// linux:include/uapi/linux/signal.h
	private enum _NSIG	= 64;
	private enum _NSIG_BPW	= c_long.sizeof * 8; // __BITS_PER_LONG, c
	private enum _NSIG_WORDS	= _NSIG / _NSIG_BPW;
	
	struct ucontext {
		c_ulong	uc_flags;
		ucontext*	uc_link;
		sigstack_t	uc_stack;
		sigset_t	uc_sigmask;
		mcontext_t	uc_mcontext;
	}+/
	struct user {
		user_regs regs;	/// General registers
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
		int[8] u_debugreg;
		user_fpregs u_fp;	/// Floating point registers
		user_fpregs *u_fp0;	/// help gdb to find the FP registers.
	}
}