/// FreeBSD thread context.
/// 
/// Required for PTRACE_GETREGS.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.include.freebsd.reg;

version (FreeBSD):

// sys/x86/include/reg.h

struct reg_x86 { // __reg32
	uint	r_fs;
	uint	r_es;
	uint	r_ds;
	uint	r_edi;
	uint	r_esi;
	uint	r_ebp;
	uint	r_isp;
	uint	r_ebx;
	uint	r_edx;
	uint	r_ecx;
	uint	r_eax;
	uint	r_trapno;
	uint	r_err;
	uint	r_eip;
	uint	r_cs;
	uint	r_eflags;
	uint	r_esp;
	uint	r_ss;
	uint	r_gs;
}

struct reg_amd64 { // __reg64
	long	r_r15;
	long	r_r14;
	long	r_r13;
	long	r_r12;
	long	r_r11;
	long	r_r10;
	long	r_r9;
	long	r_r8;
	long	r_rdi;
	long	r_rsi;
	long	r_rbp;
	long	r_rbx;
	long	r_rdx;
	long	r_rcx;
	long	r_rax;
	uint	r_trapno;
	ushort	r_fs;
	ushort	r_gs;
	uint	r_err;
	ushort	r_es;
	ushort	r_ds;
	long	r_rip;
	long	r_cs;
	long	r_rflags;
	long	r_rsp;
	long	r_ss;
}

// sys/arm64/include/reg.h

struct reg_arm { // reg32
	uint[13] r;
	uint r_sp;
	uint r_lr;
	uint r_pc;
	uint r_cpsr;
}
struct fpreg_arm { // fpreg32
	int dummy;
}
struct dbreg32 {
	int dummy;
}

struct reg_aarch64 { // reg
	ulong[30] x;
	ulong lr;	/// Link Register
	ulong sp;	/// Stack Pointer
	ulong elr;	/// Exception Link Register
	ulong spsr;	/// Saved Program Status Registers
}
struct __uint128_t { ulong[2] u; }
struct fpreg_aarch64 { // fpreg
	__uint128_t[32]	fp_q;
	uint	fp_sr;
	uint	fp_cr;
}
struct dbreg {
	ubyte		db_debug_ver;
	ubyte		db_nbkpts;
	ubyte		db_nwtpts;
	ubyte[5]	db_pad;

	struct _db_breakregs {
		ulong dbr_addr;
		uint dbr_ctrl;
		uint dbr_pad;
	}
	_db_breakregs[16] db_breakregs;
	struct _db_watchregs {
		ulong dbw_addr;
		uint dbw_ctrl;
		uint dbw_pad;
	}
	_db_watchregs[16] db_watchregs;
}

version (X86)
	alias reg = reg_x86;
else version (X86_64)
	alias reg = reg_amd64;
else version (ARM)
	alias reg = reg_arm;
else version (AArch64)
	alias reg = reg_aarch64;