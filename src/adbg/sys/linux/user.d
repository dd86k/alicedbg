/**
 * Necessary platform specific module adbg.for ptrace-related stuff from glibc.
 *
 * Despite glibc explaining in sysdeps/unix/sysv/linux/x86/sys/user.h@L21:
 * ```
 * The whole purpose of this file is for GDB and GDB only.  Don't read
 * too much into it.  Don't use it for anything other than GDB unless
 * you know what you are doing.
 * ```
 * We need this for PTRACE_GETREGS, for example.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2013 dd86k
 * License: BSD-3-Clause
 */
module adbg.sys.linux.user;

version (Posix):

version (X86) {
	/// 
	struct user_fpregs_struct {
		/// 
		int cwd;
		/// 
		int swd;
		/// 
		int twd;
		/// 
		int fip;
		/// 
		int fcs;
		/// 
		int foo;
		/// 
		int fos;
		/// 
		int [20]st_space;
	}
	/// 
	struct user_fpxregs_struct {
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
		/// 
		int ebx;
		/// 
		int ecx;
		/// 
		int edx;
		/// 
		int esi;
		/// 
		int edi;
		/// 
		int ebp;
		/// 
		int eax;
		/// 
		int xds;
		/// 
		int xes;
		/// 
		int xfs;
		/// 
		int xgs;
		/// 
		int orig_eax;
		/// 
		int eip;
		/// 
		int xcs;
		/// 
		int eflags;
		/// 
		int esp;
		/// 
		int xss;
	}
	/// 
	struct user {
		/// 
		user_regs_struct regs;
		/// 
		int u_fpvalid;
		/// 
		user_fpregs_struct i387;
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
		user_regs_struct*	u_ar0;
		/// 
		user_fpregs_struct*	u_fpstate;
		/// 
		uint magic;
		/// 
		char [32]u_comm;
		/// 
		int  [8]u_debugreg;
	}
} else
version (X86_64) {
	/// 
	struct user_fpregs_struct {
		/// 
		ushort cwd;
		/// 
		ushort swd;
		/// 
		ushort ftw;
		/// 
		ushort fop;
		/// 
		ulong rip;
		/// 
		ulong rdp;
		/// 
		uint mxcsr;
		/// 
		uint mxcr_mask;
		/// 8*16 bytes for each FP-reg = 128 bytes
		uint [32]st_space;
		/// 16*16 bytes for each XMM-reg = 256 bytes
		uint [64]xmm_space;
		/// 
		uint [32]padding;
	}
	/// 
	struct user_regs_struct {
		/// 
		ulong r15;
		/// 
		ulong r14;
		/// 
		ulong r13;
		/// 
		ulong r12;
		/// 
		ulong rbp;
		/// 
		ulong rbx;
		/// 
		ulong r11;
		/// 
		ulong r10;
		/// 
		ulong r9;
		/// 
		ulong r8;
		/// 
		ulong rax;
		/// 
		ulong rcx;
		/// 
		ulong rdx;
		/// 
		ulong rsi;
		/// 
		ulong rdi;
		/// 
		ulong orig_rax;
		/// 
		ulong rip;
		/// 
		ulong cs;
		/// 
		ulong eflags;
		/// 
		ulong rsp;
		/// 
		ulong ss;
		/// 
		ulong fs_base;
		/// 
		ulong gs_base;
		/// 
		ulong ds;
		/// 
		ulong es;
		/// 
		ulong fs;
		/// 
		ulong gs;
	}
	/// 
	struct user {
		/// 
		user_regs_struct regs;
		/// 
		int u_fpvalid;
		/// 
		user_fpregs_struct i387;
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
			/// 
			user_regs_struct *u_ar0;
			/// 
			ulong __u_ar0_word;
		}
		union {
			/// 
			user_fpregs_struct *u_fpstate;
			/// 
			ulong __u_fpstate_word;
		}
		///
		ulong magic;
		///
		char  [32]u_comm;
		///
		ulong [8]u_debugreg;
		ulong error_code;
		ulong fault_address;
	}
}