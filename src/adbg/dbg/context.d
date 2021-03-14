/**
 * License: BSD-3-Clause
 */
module adbg.dbg.context;

import adbg.dbg.debugger : g_debuggee;

version (Windows) {
	import adbg.sys.windows.wow64;
	import core.sys.windows.windows;
} else
version (Posix) {
	import adbg.sys.linux.user;
	import adbg.sys.posix.ptrace;
	import core.sys.posix.signal;
}

version (X86)
	version = X86_ANY;
else version (X86_64)
	version = X86_ANY;

extern (C):

version (X86) {
	enum EX_REG_COUNT = 10;	/// Number of registers for platform
} else version (X86_64) {
	enum EX_REG_COUNT = 18;	/// Number of registers for platform
} else
	static assert(0, "EX_REG_COUNT not defined");

/// Register size
enum RegisterType {
	u8, u16, u32, u64, f32, f64,
	flags_x86, flags_x86_64
}

/// Register structure, designs a single register for UI ends to understand
struct register_t {
	RegisterType type;	/// Register type (size)
	union {
		ubyte  u8;	/// Register data: ubyte (u8)
		ushort u16;	/// Register data: ushort (u16)
		uint   u32;	/// Register data: uint (u32)
		ulong  u64;	/// Register data: ulong (u64)
		float  f32;	/// Register data: float (f32)
		double f64;	/// Register data: double (f64)
	}
	const(char) *name;	/// Register name from adbg_ex_reg_init
}

/// Represents a thread context structure with the register values once a
/// process is paused.
struct thread_context_t {
	/// Register count in registers field, populated by
	/// adbg_ex_reg_init.
	uint count;
	/// Register population, this may depends by platform.
	register_t [EX_REG_COUNT]items;
	/// If context was initiated.
	bool initiated;
}

/// (Internal) Initiate register fields with their names and sizes.
/// Params: e = Exception structure
void adbg_ctx_init(thread_context_t *e) {
	version (X86) {
		adbg_ctx_init_x86(e);
	} else version (X86_64) {
		version (Win64) {
			if (g_debuggee.wow64)
				adbg_ctx_init_x86(e);
			else
				adbg_ctx_init_x86_64(e);
		} else
			adbg_ctx_init_x86_64(e);
	}
}

/// (Internal) Get the thread context from debuggee
/// Params: ctx = Thread context structure pointer
void adbg_ctx_get(thread_context_t *ctx) {
	version (Windows) {
		CONTEXT winctx = void;
		version (Win64) {
			WOW64_CONTEXT winctxwow64 = void;
			if (g_debuggee.wow64) {
				winctxwow64.ContextFlags = CONTEXT_ALL;
				Wow64GetThreadContext(g_debuggee.htid, &winctxwow64);
				adbg_ctx_os_wow64(ctx, &winctxwow64);
			} else {
				winctx.ContextFlags = CONTEXT_ALL;
				GetThreadContext(g_debuggee.htid, &winctx);
				adbg_ctx_os(ctx, &winctx);
			}
		} else {
			winctx.ContextFlags = CONTEXT_ALL;
			GetThreadContext(g_debuggee.htid, &winctx);
			adbg_ctx_os(ctx, &winctx);
		}
	} else
	version (Posix) {
		user_regs_struct u = void;
		if (ptrace(PTRACE_GETREGS, g_debuggee.pid, null, &u) < 0)
			ctx.count = 0;
		else
			adbg_ctx_os(ctx, &u);
	}
}

//TODO: adbg_ctx_set

/// Format a register depending on their type as a zero-padded number.
/// Params: reg = register_t structure
/// Returns: Formatted hexadecimal string
const(char) *adbg_ctx_reg_hex(register_t *reg) {
	import adbg.utils.str : adbg_util_strf;
	with (RegisterType)
	switch (reg.type) {
	case u8:
		return adbg_util_strf("%02x", reg.u8);
	case u16:
		return adbg_util_strf("%04x", reg.u16);
	case u32, f32, flags_x86:
		return adbg_util_strf("%08x", reg.u32);
	case u64, f64, flags_x86_64:
		return adbg_util_strf("%016llx", reg.u64);
	default:
		assert(0);
	}
}

/// Format a register's context with their formatted value.
/// Params: reg = register_t structure
/// Returns: Formatted string
const(char) *adbg_ctx_reg_val(register_t *reg) {
	import adbg.utils.str : adbg_util_strf, empty_string;
	import adbg.utils.bit : BIT;
	enum F_X86_CF = BIT!(0);
	enum F_X86_PF = BIT!(2);
	enum F_X86_AF = BIT!(4);
	enum F_X86_ZF = BIT!(6);
	enum F_X86_SF = BIT!(7);
	enum F_X86_TF = BIT!(8);
	enum F_X86_IF = BIT!(9);
	enum F_X86_DF = BIT!(10);
	enum F_X86_OF = BIT!(11);
	enum F_X86_IOPL = BIT!(12) | BIT!(13);
	enum F_X86_NT = BIT!(14);
	enum F_X86_RF = BIT!(16);
	enum F_X86_VM = BIT!(17);
	enum F_X86_AC = BIT!(18);
	enum F_X86_VIF = BIT!(19);
	enum F_X86_VIP = BIT!(20);
	enum F_X86_ID = BIT!(21);
	__gshared const(char) *FS_X86_CF	= " CF";
	__gshared const(char) *FS_X86_PF	= " PF";
	__gshared const(char) *FS_X86_AF	= " AF";
	__gshared const(char) *FS_X86_ZF	= " ZF";
	__gshared const(char) *FS_X86_SF	= " SF";
	__gshared const(char) *FS_X86_TF	= " TF";
	__gshared const(char) *FS_X86_IF	= " IF";
	__gshared const(char) *FS_X86_DF	= " DF";
	__gshared const(char) *FS_X86_OF	= " OF";
	__gshared const(char) *FS_X86_NT	= " NT";
	__gshared const(char) *FS_X86_RF	= " RF";
	__gshared const(char) *FS_X86_VM	= " VM";
	__gshared const(char) *FS_X86_AC	= " AC";
	__gshared const(char) *FS_X86_VIF	= " VIF";
	__gshared const(char) *FS_X86_VIP	= " VIP";
	__gshared const(char) *FS_X86_ID	= " ID";
	with (RegisterType)
	switch (reg.type) {
	case u8:	return adbg_util_strf("%u", reg.u8);
	case u16:	return adbg_util_strf("%u", reg.u16);
	case u32:	return adbg_util_strf("%u", reg.u32);
	case u64:	return adbg_util_strf("%llu", reg.u64);
	case f32:	return adbg_util_strf("%f", reg.f32);
	case f64:	return adbg_util_strf("%f", reg.f64);
	case flags_x86, flags_x86_64:
		uint f = reg.u32;
		return adbg_util_strf(
			"[%s%s%s%s%s%s%s%s%s IOPL=%d%s%s%s%s%s%s ]",
			f & F_X86_CF ? FS_X86_CF : empty_string,
			f & F_X86_PF ? FS_X86_PF : empty_string,
			f & F_X86_AF ? FS_X86_AF : empty_string,
			f & F_X86_ZF ? FS_X86_ZF : empty_string,
			f & F_X86_SF ? FS_X86_SF : empty_string,
			f & F_X86_TF ? FS_X86_TF : empty_string,
			f & F_X86_IF ? FS_X86_IF : empty_string,
			f & F_X86_DF ? FS_X86_DF : empty_string,
			f & F_X86_OF ? FS_X86_OF : empty_string,
			(f & F_X86_IOPL) >> 12,
			f & F_X86_NT ? FS_X86_NT : empty_string,
			f & F_X86_RF ? FS_X86_RF : empty_string,
			f & F_X86_VM ? FS_X86_VM : empty_string,
			f & F_X86_AC ? FS_X86_AC : empty_string,
			f & F_X86_VIF ? FS_X86_VIF : empty_string,
			f & F_X86_VIP ? FS_X86_VIP : empty_string,
			f & F_X86_ID ? FS_X86_ID : empty_string,
			);
	default:	assert(0);
	}
}

version (X86_ANY)
private void adbg_ctx_init_x86(thread_context_t *ctx) {
	ctx.count = EX_REG_COUNT;
	ctx.items[0].name = "eip";
	ctx.items[0].type = RegisterType.u32;
	ctx.items[1].name = "eflags";
	ctx.items[1].type = RegisterType.flags_x86;
	ctx.items[2].name = "eax";
	ctx.items[2].type = RegisterType.u32;
	ctx.items[3].name = "ebx";
	ctx.items[3].type = RegisterType.u32;
	ctx.items[4].name = "ecx";
	ctx.items[4].type = RegisterType.u32;
	ctx.items[5].name = "edx";
	ctx.items[5].type = RegisterType.u32;
	ctx.items[6].name = "esp";
	ctx.items[6].type = RegisterType.u32;
	ctx.items[7].name = "ebp";
	ctx.items[7].type = RegisterType.u32;
	ctx.items[8].name = "esi";
	ctx.items[8].type = RegisterType.u32;
	ctx.items[9].name = "edi";
	ctx.items[9].type = RegisterType.u32;
}

version (X86_64)
private void adbg_ctx_init_x86_64(thread_context_t *ctx) {
	ctx.count = EX_REG_COUNT;
	ctx.items[0].name  = "rip";
	ctx.items[0].type  = RegisterType.u64;
	ctx.items[1].name  = "rflags";
	ctx.items[1].type  = RegisterType.flags_x86_64;
	ctx.items[2].name  = "rax";
	ctx.items[2].type  = RegisterType.u64;
	ctx.items[3].name  = "rbx";
	ctx.items[3].type  = RegisterType.u64;
	ctx.items[4].name  = "rcx";
	ctx.items[4].type  = RegisterType.u64;
	ctx.items[5].name  = "rdx";
	ctx.items[5].type  = RegisterType.u64;
	ctx.items[6].name  = "rsp";
	ctx.items[6].type  = RegisterType.u64;
	ctx.items[7].name  = "rbp";
	ctx.items[7].type  = RegisterType.u64;
	ctx.items[8].name  = "rsi";
	ctx.items[8].type  = RegisterType.u64;
	ctx.items[9].name  = "rdi";
	ctx.items[9].type  = RegisterType.u64;
	ctx.items[10].name = "r8";
	ctx.items[10].type = RegisterType.u64;
	ctx.items[11].name = "r9";
	ctx.items[11].type = RegisterType.u64;
	ctx.items[12].name = "r10";
	ctx.items[12].type = RegisterType.u64;
	ctx.items[13].name = "r11";
	ctx.items[13].type = RegisterType.u64;
	ctx.items[14].name = "r12";
	ctx.items[14].type = RegisterType.u64;
	ctx.items[15].name = "r13";
	ctx.items[15].type = RegisterType.u64;
	ctx.items[16].name = "r14";
	ctx.items[16].type = RegisterType.u64;
	ctx.items[17].name = "r15";
	ctx.items[17].type = RegisterType.u64;
}

version (Windows) {
	//
	// ANCHOR Windows functions
	//

	// Populate exception_t.registers array from Windows' CONTEXT
	void adbg_ctx_os(thread_context_t *ctx, CONTEXT *winctx) {
		version (X86) {
			ctx.items[0].u32 = winctx.Eip;
			ctx.items[1].u32 = winctx.EFlags;
			ctx.items[2].u32 = winctx.Eax;
			ctx.items[3].u32 = winctx.Ebx;
			ctx.items[4].u32 = winctx.Ecx;
			ctx.items[5].u32 = winctx.Edx;
			ctx.items[6].u32 = winctx.Esp;
			ctx.items[7].u32 = winctx.Ebp;
			ctx.items[8].u32 = winctx.Esi;
			ctx.items[9].u32 = winctx.Edi;
		} else
		version (X86_64) {
			ctx.items[0].u64  = winctx.Rip;
			ctx.items[1].u64  = winctx.EFlags;
			ctx.items[2].u64  = winctx.Rax;
			ctx.items[3].u64  = winctx.Rbx;
			ctx.items[4].u64  = winctx.Rcx;
			ctx.items[5].u64  = winctx.Rdx;
			ctx.items[6].u64  = winctx.Rsp;
			ctx.items[7].u64  = winctx.Rbp;
			ctx.items[8].u64  = winctx.Rsi;
			ctx.items[9].u64  = winctx.Rdi;
			ctx.items[10].u64 = winctx.R8;
			ctx.items[11].u64 = winctx.R9;
			ctx.items[12].u64 = winctx.R10;
			ctx.items[13].u64 = winctx.R11;
			ctx.items[14].u64 = winctx.R12;
			ctx.items[15].u64 = winctx.R13;
			ctx.items[16].u64 = winctx.R14;
			ctx.items[17].u64 = winctx.R15;
		}
	}

	version (Win64)
	package void adbg_ctx_os_wow64(thread_context_t *ctx, WOW64_CONTEXT *winctx) {
		ctx.items[0].u32 = winctx.Eip;
		ctx.items[1].u32 = winctx.EFlags;
		ctx.items[2].u32 = winctx.Eax;
		ctx.items[3].u32 = winctx.Ebx;
		ctx.items[4].u32 = winctx.Ecx;
		ctx.items[5].u32 = winctx.Edx;
		ctx.items[6].u32 = winctx.Esp;
		ctx.items[7].u32 = winctx.Ebp;
		ctx.items[8].u32 = winctx.Esi;
		ctx.items[9].u32 = winctx.Edi;
	}
} else version (Posix) {
	//
	// ANCHOR Posix functions
	//

	/// Populate exception_t.registers array from user_regs_struct
	package void adbg_ctx_os(thread_context_t *ctx, user_regs_struct *u) {
		version (X86) {
			ctx.items[0].u32 = u.eip;
			ctx.items[1].u32 = u.eflags;
			ctx.items[2].u32 = u.eax;
			ctx.items[3].u32 = u.ebx;
			ctx.items[4].u32 = u.ecx;
			ctx.items[5].u32 = u.edx;
			ctx.items[6].u32 = u.esp;
			ctx.items[7].u32 = u.ebp;
			ctx.items[8].u32 = u.esi;
			ctx.items[9].u32 = u.edi;
		} else
		version (X86_64) {
			ctx.items[0].u64 = u.rip;
			ctx.items[1].u64 = u.eflags;
			ctx.items[2].u64 = u.rax;
			ctx.items[3].u64 = u.rbx;
			ctx.items[4].u64 = u.rcx;
			ctx.items[5].u64 = u.rdx;
			ctx.items[6].u64 = u.rsp;
			ctx.items[7].u64 = u.rbp;
			ctx.items[8].u64 = u.rsi;
			ctx.items[9].u64 = u.rdi;
			ctx.items[10].u64 = u.r8;
			ctx.items[11].u64 = u.r9;
			ctx.items[12].u64 = u.r10;
			ctx.items[13].u64 = u.r11;
			ctx.items[14].u64 = u.r12;
			ctx.items[15].u64 = u.r13;
			ctx.items[16].u64 = u.r14;
			ctx.items[17].u64 = u.r15;
		}
	}
} // version Posix