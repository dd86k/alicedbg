/**
 * License: BSD-3-Clause
 */
module adbg.dbg.context;

version (Windows) {
	import core.sys.windows.windows;
	import adbg.sys.windows.wow64;
	version (Win32)
		import adbg.dbg.debugger : g_pid, g_tid;
	else
		import adbg.dbg.debugger : g_pid, g_tid, processWOW64;
} else
version (Posix) {
	import adbg.sys.linux.user;
	import adbg.sys.posix.ptrace;
	import core.sys.posix.signal;
	import adbg.dbg.debugger : g_pid;
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
	u8, u16, u32, u64, f32, f64
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
		size_t st;	/// Register data: size_t
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
}

/// (Internal) Initiate register fields with their names and sizes.
/// Params: e = Exception structure
void adbg_ctx_init(thread_context_t *e) {
	version (X86) {
		adbg_ctx_init_x86(e);
	} else version (X86_64) {
		version (Win64) {
			if (processWOW64)
				adbg_ctx_init_x86(e);
			else
				adbg_ctx_init_x86_64(e);
		} else
			adbg_ctx_init_x86_64(e);
	}
}

void adbg_ctx_get(thread_context_t *ctx) {
	version (Windows) {
		CONTEXT winctx = void;
		version (Win64) {
			WOW64_CONTEXT winctxwow64 = void;
			if (processWOW64) {
				winctxwow64.ContextFlags = CONTEXT_ALL;
				Wow64GetThreadContext(g_tid, &winctxwow64);
				adbg_ctx_os_wow64(ctx, &winctxwow64);
			} else {
				winctx.ContextFlags = CONTEXT_ALL;
				GetThreadContext(g_tid, &winctx);
				adbg_ctx_os(ctx, &winctx);
			}
		} else {
			winctx.ContextFlags = CONTEXT_ALL;
			GetThreadContext(g_tid, &winctx);
			adbg_ctx_os(ctx, &winctx);
		}
	} else
	version (Posix) {
		user_regs_struct u = void;
		if (ptrace(PTRACE_GETREGS, g_pid, null, &u) < 0)
			ctx.count = 0;
		else
			adbg_ctx_os(ctx, &u);
	}
}

//TODO: adbg_ctx_set

/// Format a register depending on their type as a zero-padded number.
/// Params: reg = register_t structure
/// Returns: Formatted hexadecimal value
const(char) *adbg_ex_reg_fhex(register_t *reg) {
	import adbg.utils.str : adbg_util_strf;
	with (RegisterType)
	switch (reg.type) {
	case u8:	return adbg_util_strf("%02x", reg.u8);
	case u16:	return adbg_util_strf("%04x", reg.u16);
	case u32, f32:	return adbg_util_strf("%08x", reg.u32);
	case u64, f64:	return adbg_util_strf("%016llx", reg.u64);
	default: assert(0);
	}
}

/*
const(char) *exception_reg_fval(register_t *reg) {
	import utils.str : adbg_util_strf;
	
}*/

version (X86_ANY)
private void adbg_ctx_init_x86(thread_context_t *ctx) {
	ctx.count = EX_REG_COUNT;
	ctx.items[0].name = "EIP";
	ctx.items[0].type = RegisterType.u32;
	ctx.items[1].name = "EFLAGS";
	ctx.items[1].type = RegisterType.u32;
	ctx.items[2].name = "EAX";
	ctx.items[2].type = RegisterType.u32;
	ctx.items[3].name = "EBX";
	ctx.items[3].type = RegisterType.u32;
	ctx.items[4].name = "ECX";
	ctx.items[4].type = RegisterType.u32;
	ctx.items[5].name = "EDX";
	ctx.items[5].type = RegisterType.u32;
	ctx.items[6].name = "ESP";
	ctx.items[6].type = RegisterType.u32;
	ctx.items[7].name = "EBP";
	ctx.items[7].type = RegisterType.u32;
	ctx.items[8].name = "ESI";
	ctx.items[8].type = RegisterType.u32;
	ctx.items[9].name = "EDI";
	ctx.items[9].type = RegisterType.u32;
}

version (X86_64)
private void adbg_ctx_init_x86_64(thread_context_t *ctx) {
	ctx.count = EX_REG_COUNT;
	ctx.items[0].name  = "RIP";
	ctx.items[0].type  = RegisterType.u64;
	ctx.items[1].name  = "RFLAGS";
	ctx.items[1].type  = RegisterType.u64;
	ctx.items[2].name  = "RAX";
	ctx.items[2].type  = RegisterType.u64;
	ctx.items[3].name  = "RBX";
	ctx.items[3].type  = RegisterType.u64;
	ctx.items[4].name  = "RCX";
	ctx.items[4].type  = RegisterType.u64;
	ctx.items[5].name  = "RDX";
	ctx.items[5].type  = RegisterType.u64;
	ctx.items[6].name  = "RSP";
	ctx.items[6].type  = RegisterType.u64;
	ctx.items[7].name  = "RBP";
	ctx.items[7].type  = RegisterType.u64;
	ctx.items[8].name  = "RSI";
	ctx.items[8].type  = RegisterType.u64;
	ctx.items[9].name  = "RDI";
	ctx.items[9].type  = RegisterType.u64;
	ctx.items[10].name = "R8";
	ctx.items[10].type = RegisterType.u64;
	ctx.items[11].name = "R9";
	ctx.items[11].type = RegisterType.u64;
	ctx.items[12].name = "R10";
	ctx.items[12].type = RegisterType.u64;
	ctx.items[13].name = "R11";
	ctx.items[13].type = RegisterType.u64;
	ctx.items[14].name = "R12";
	ctx.items[14].type = RegisterType.u64;
	ctx.items[15].name = "R13";
	ctx.items[15].type = RegisterType.u64;
	ctx.items[16].name = "R14";
	ctx.items[16].type = RegisterType.u64;
	ctx.items[17].name = "R15";
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