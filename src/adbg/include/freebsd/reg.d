/// FreeBSD thread context.
/// 
/// Required for PTRACE_GETREGS.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.include.freebsd.reg;

version (FreeBSD):

struct __uint128_t { ulong[2] u; }
union  __fp80_t { ubyte[10] u; }

version (X86) {
	// sys/x86/include/reg.h

	struct x86reg32 { // __reg32
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
	struct x86fpreg32 { // __fpreg32
		uint[7]	fpr_env;	// __uint32_t	fpr_env[7];
		__fp80_t[8]	fpr_acc;	// __uint8_t	fpr_acc[8][10];
		uint	fpr_ex_sw;	// __uint32_t	fpr_ex_sw;
		ubyte[64]	fpr_pad;	// __uint8_t	fpr_pad[64];
	}
	struct x86dbreg32 { // __dbreg32
		/* Index 0-3: debug address registers */
		/* Index 4-5: reserved */
		/* Index 6: debug status */
		/* Index 7: debug control */
		uint[8] dr;	/* debug registers */
	}

	alias reg = x86reg32;
	alias fpreg = x86fpreg32;
} else version (X86_64) {
	// sys/x86/include/reg.h

	struct x86reg64 { // __reg64
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
	struct x86fpreg64 { // __fpreg64
		ulong[4]	fpr_env;	// __uint64_t	fpr_env[4];
		__uint128_t[8]	fpr_acc;	// __uint8_t	fpr_acc[8][16];
		__uint128_t[16]	fpr_xacc;	// __uint8_t	fpr_xacc[16][16];
		ulong[12]	fpr_spare;	// __uint64_t	fpr_spare[12];
	}
	struct x86dbreg64 { // __dbreg64
		/* Index 0-3: debug address registers */
		/* Index 4-5: reserved */
		/* Index 6: debug status */
		/* Index 7: debug control */
		/* Index 8-15: reserved */
		ulong[16] dr;	/* debug registers */
	}

	// Available with PT_GETXMMREGS
	struct xmmreg {
		uint[8]	xmm_env;	// xmm_env[8];
		__uint128_t[8]	xmm_acc;	// xmm_acc[8][16];
		__uint128_t[8]	xmm_reg;	// xmm_reg[8][16];
		ubyte[224]	xmm_pad;	// xmm_pad[224];
	}

	alias reg = x86reg64;
	alias fpreg = x86fpreg64;
} else version (Arm) {
	// sys/arm/include/reg.h

	struct arm32reg { // reg32
		uint[13] r;
		uint r_sp;
		uint r_lr;
		uint r_pc;
		uint r_cpsr;
	}
	struct fp_extended_precision {
		uint fp_exponent;
		uint fp_mantissa_hi;
		uint fp_mantissa_lo;
	}
	alias fp_extended_precision fp_reg_t;
	struct arm32fpreg { // fpreg
		uint fpr_fpsr;
		fp_reg_t[8] fpr;
	}
	enum ARM_WR_MAX = 16; /* Maximum number of watchpoint registers */
	struct arm32dbreg {
		uint[ARM_WR_MAX] dbg_wcr; /* Watchpoint Control Registers */
		uint[ARM_WR_MAX] dbg_wvr; /* Watchpoint Value Registers */
	}
	
	alias reg = arm32reg;
	alias fpreg = arm32fpreg;
} else version (AArch64) {
	// sys/arm64/include/reg.h

	struct arm64reg { // reg
		ulong[30] x;
		ulong lr;	/// Link Register
		ulong sp;	/// Stack Pointer
		ulong elr;	/// Exception Link Register
		ulong spsr;	/// Saved Program Status Registers
	}
	struct arm64fpreg { // fpreg
		__uint128_t[32]	fp_q;
		uint	fp_sr;
		uint	fp_cr;
	}
	struct arm64dbreg { //dbreg
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
	
	alias reg = arm64reg;
	alias fpreg = arm64fpreg;
}