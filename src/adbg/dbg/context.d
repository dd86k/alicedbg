/**
 * Thread context handling.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.dbg.context;

import adbg.dbg.debugger : g_debuggee;
private import core.stdc.stdio : snprintf;
private import core.stdc.stdarg;

version (Windows) {
	import adbg.sys.windows.wow64;
	import core.sys.windows.windows;
} else version (Posix) {
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
enum AdbgRegisterSize {
	u8, u16, u32, u64, f32, f64
}

/// Register structure, designs a single register for UI ends to understand
struct register_t {
	AdbgRegisterSize type;	/// Register type (size)
	union {
		ulong  u64;	/// Register data: ulong (u64)
		uint   u32;	/// Register data: uint (u32)
		ushort u16;	/// Register data: ushort (u16)
		ubyte  u8;	/// Register data: ubyte (u8)
		double f64;	/// Register data: double (f64)
		float  f32;	/// Register data: float (f32)
	}
	const(char) *name;	/// Register name from adbg_ex_reg_init
}

/// Represents a thread context structure with the register values once a
/// process is paused.
//TODO: Consider doing an immutable array
//      And still support WOW64
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
				if (Wow64GetThreadContext(g_debuggee.htid, &winctxwow64) == FALSE) {
					ctx.count = 0;
					return;
				}
				adbg_ctx_os_wow64(ctx, &winctxwow64);
			} else {
				winctx.ContextFlags = CONTEXT_ALL;
				if (GetThreadContext(g_debuggee.htid, &winctx)) {
					ctx.count = 0;
					return;
				}
				adbg_ctx_os(ctx, &winctx);
			}
		} else {
			winctx.ContextFlags = CONTEXT_ALL;
			if (GetThreadContext(g_debuggee.htid, &winctx)) {
				ctx.count = 0;
				return;
			}
			adbg_ctx_os(ctx, &winctx);
		}
	} else
	version (Posix) {
		//TODO: PTRACE_GETFPREGS
		user_regs_struct u = void;
		if (ptrace(PTRACE_GETREGS, g_debuggee.pid, null, &u) < 0) {
			ctx.count = 0;
			return;
		}
		adbg_ctx_os(ctx, &u);
	}
}

//TODO: adbg_ctx_set

/// Format a register depending on their type as a zero-padded number.
/// Params: reg = register_t structure
/// Returns: Formatted hexadecimal string
const(char) *adbg_ctx_reg_hex(register_t *reg) {
	enum SZ = 18;
	__gshared char[SZ] buffer;
	switch (reg.type) with (AdbgRegisterSize) {
	case u8:  snprintf(buffer.ptr, SZ, "%02x", reg.u8); break;
	case u16: snprintf(buffer.ptr, SZ, "%04x", reg.u16); break;
	case u32: snprintf(buffer.ptr, SZ, "%08x", reg.u32); break;
	case u64: snprintf(buffer.ptr, SZ, "%016llx", reg.u64); break;
	default:  assert(0);
	}
	return buffer.ptr;
}

/// Format a register's context with their formatted value.
/// Params: reg = register_t structure
/// Returns: Formatted string
const(char) *adbg_ctx_reg_val(register_t *reg) {
	enum SZ = 18;
	__gshared char[SZ] buffer;
	with (AdbgRegisterSize)
	switch (reg.type) {
	case u8:  snprintf(buffer.ptr, SZ, "%u", reg.u8); break;
	case u16: snprintf(buffer.ptr, SZ, "%u", reg.u16); break;
	case u32: snprintf(buffer.ptr, SZ, "%u", reg.u32); break;
	case u64: snprintf(buffer.ptr, SZ, "%llu", reg.u64); break;
	case f32: snprintf(buffer.ptr, SZ, "%f", reg.f32); break;
	case f64: snprintf(buffer.ptr, SZ, "%f", reg.f64); break;
	default:  assert(0);
	}
	return buffer.ptr;
}

version (X86_ANY)
private void adbg_ctx_init_x86(thread_context_t *ctx) {
	ctx.count = EX_REG_COUNT;
	ctx.items[0].name = "eip";
	ctx.items[0].type = AdbgRegisterSize.u32;
	ctx.items[1].name = "eflags";
	ctx.items[1].type = AdbgRegisterSize.u32;
	ctx.items[2].name = "eax";
	ctx.items[2].type = AdbgRegisterSize.u32;
	ctx.items[3].name = "ebx";
	ctx.items[3].type = AdbgRegisterSize.u32;
	ctx.items[4].name = "ecx";
	ctx.items[4].type = AdbgRegisterSize.u32;
	ctx.items[5].name = "edx";
	ctx.items[5].type = AdbgRegisterSize.u32;
	ctx.items[6].name = "esp";
	ctx.items[6].type = AdbgRegisterSize.u32;
	ctx.items[7].name = "ebp";
	ctx.items[7].type = AdbgRegisterSize.u32;
	ctx.items[8].name = "esi";
	ctx.items[8].type = AdbgRegisterSize.u32;
	ctx.items[9].name = "edi";
	ctx.items[9].type = AdbgRegisterSize.u32;
}

version (X86_64)
private void adbg_ctx_init_x86_64(thread_context_t *ctx) {
	ctx.count = EX_REG_COUNT;
	ctx.items[0].name  = "rip";
	ctx.items[0].type  = AdbgRegisterSize.u64;
	ctx.items[1].name  = "rflags";
	ctx.items[1].type  = AdbgRegisterSize.u64;
	ctx.items[2].name  = "rax";
	ctx.items[2].type  = AdbgRegisterSize.u64;
	ctx.items[3].name  = "rbx";
	ctx.items[3].type  = AdbgRegisterSize.u64;
	ctx.items[4].name  = "rcx";
	ctx.items[4].type  = AdbgRegisterSize.u64;
	ctx.items[5].name  = "rdx";
	ctx.items[5].type  = AdbgRegisterSize.u64;
	ctx.items[6].name  = "rsp";
	ctx.items[6].type  = AdbgRegisterSize.u64;
	ctx.items[7].name  = "rbp";
	ctx.items[7].type  = AdbgRegisterSize.u64;
	ctx.items[8].name  = "rsi";
	ctx.items[8].type  = AdbgRegisterSize.u64;
	ctx.items[9].name  = "rdi";
	ctx.items[9].type  = AdbgRegisterSize.u64;
	ctx.items[10].name = "r8";
	ctx.items[10].type = AdbgRegisterSize.u64;
	ctx.items[11].name = "r9";
	ctx.items[11].type = AdbgRegisterSize.u64;
	ctx.items[12].name = "r10";
	ctx.items[12].type = AdbgRegisterSize.u64;
	ctx.items[13].name = "r11";
	ctx.items[13].type = AdbgRegisterSize.u64;
	ctx.items[14].name = "r12";
	ctx.items[14].type = AdbgRegisterSize.u64;
	ctx.items[15].name = "r13";
	ctx.items[15].type = AdbgRegisterSize.u64;
	ctx.items[16].name = "r14";
	ctx.items[16].type = AdbgRegisterSize.u64;
	ctx.items[17].name = "r15";
	ctx.items[17].type = AdbgRegisterSize.u64;
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