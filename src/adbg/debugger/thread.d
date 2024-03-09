/// Thread context handling.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.debugger.thread;

import adbg.debugger.process : adbg_process_t;
import adbg.include.c.stdio : snprintf;
import adbg.include.c.stdlib;
import core.stdc.string : memset, strncmp;
import adbg.error;
import adbg.object.machines;

//TODO: Register registers statically
//      adbg_register_t { string name; int type; etc. }
//      adbg_register_t[18] registers = [ ... ]
//      - Remove usage of REG_COUNT
//TODO: Support FPU registers

version (Windows) {
	import adbg.include.windows.wow64;
	import core.sys.windows.windows;
} else version (Posix) {
	import adbg.include.linux.user;
	import adbg.include.posix.ptrace;
	import core.sys.posix.signal;
}

version (X86) {
	version = X86_ANY;
	private enum REG_COUNT = 10;	/// Number of registers for platform
} else version (X86_64) {
	version = X86_ANY;
	private enum REG_COUNT = 18;	/// Ditto
} else version (ARM) {
	private enum REG_COUNT = 0;	/// Ditto
} else version (AArch64) {
	private enum REG_COUNT = 0;	/// Ditto
} else
	private enum REG_COUNT = 0;	/// Ditto

extern (C):

//TODO: Rename to AdbgRegType
//TODO: Support f80 (x87)
/// Register size
enum AdbgRegisterSize : ubyte {
	u8, u16, u32, u64,
	f32, f64
}

//TODO: Rename to AdbgRegFormat
enum {
	FORMAT_DEC,
	FORMAT_HEX,
	FORMAT_HEXPADDED,
}

/// Register structure, designs a single register for UI ends to understand
struct adbg_register_t {
	const(char) *name;	/// Register name
	AdbgRegisterSize type;	/// Register type (size)
	union {
		ulong  u64;	/// Register data: ulong (u64)
		uint   u32;	/// Register data: uint (u32)
		ushort u16;	/// Register data: ushort (u16)
		ubyte  u8;	/// Register data: ubyte (u8)
		double f64;	/// Register data: double (f64)
		float  f32;	/// Register data: float (f32)
	}
}

/// Represents a thread context structure with the register values once a
/// process is paused.
struct adbg_registers_t {
	/// Register count in registers field.
	ushort count;
	/// Register population, this may depends by platform.
	adbg_register_t[REG_COUNT] items;
}

adbg_registers_t* adbg_registers_new(AdbgMachine mach) {
	adbg_registers_t* regs = cast(adbg_registers_t*)malloc(adbg_registers_t.sizeof);
	if (regs == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	if (adbg_registers_config(regs, mach)) {
		free(regs);
		return null;
	}
	return regs;
}

int adbg_registers_config(adbg_registers_t *ctx, AdbgMachine mach) {
	if (ctx == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	switch (mach) with (AdbgMachine) {
	case x86:
		adbg_context_start_x86(ctx);
		break;
	case amd64:
		adbg_context_start_x86_64(ctx);
		break;
	default:
		return adbg_oops(AdbgError.objectInvalidMachine);
	}
	
	return 0;
}

//TODO: Deprecate this in favor of adbg_register_list_init due to lack of flexibility
/// Initiate register fields with their names and sizes.
/// This is usually done by the debugger itself.
void adbg_registers_init(adbg_registers_t *ctx, adbg_process_t *tracee) {
	version (Trace) trace("tracee=%p ctx=%p", ctx, tracee);
	if (tracee == null || ctx == null)
		return;
	
	version (X86) {
		adbg_context_start_x86(ctx);
	} else version (X86_64) {
		version (Win64) { // Windows 64-bit
			if (tracee.wow64)
				adbg_context_start_x86(ctx);
			else
				adbg_context_start_x86_64(ctx);
		} else // Anything else 64-bit
			adbg_context_start_x86_64(ctx);
	} else
		ctx.count = 0;
}

//TODO: Thread type, to hold its context
int adbg_registers_fill(adbg_registers_t *ctx, adbg_process_t *tracee) {
	import adbg.debugger.process : AdbgCreation;
	
	version (Trace) trace("tracee=%p ctx=%p", ctx, tracee);
	
	if (tracee == null || ctx == null)
		return adbg_oops(AdbgError.nullArgument);
	
	ctx.count = 0;
	memset(ctx, 0, adbg_registers_t.sizeof);
	
	if (tracee.creation == AdbgCreation.unloaded)
		return adbg_oops(AdbgError.debuggerUnattached);
	
	version (Windows) {
		CONTEXT winctx = void;
		version (Win64) {
			WOW64_CONTEXT winctxwow64 = void;
			if (tracee.wow64) {
				winctxwow64.ContextFlags = CONTEXT_ALL;
				if (Wow64GetThreadContext(tracee.htid, &winctxwow64) == FALSE) {
					return adbg_oops(AdbgError.os);
				}
				adbg_context_fill_wow64(ctx, &winctxwow64);
			} else {
				winctx.ContextFlags = CONTEXT_ALL;
				if (GetThreadContext(tracee.htid, &winctx) == FALSE) {
					return adbg_oops(AdbgError.os);
				}
				adbg_context_fill_win(ctx, &winctx);
			}
		} else {
			winctx.ContextFlags = CONTEXT_ALL;
			if (GetThreadContext(tracee.htid, &winctx) == FALSE) {
				return adbg_oops(AdbgError.os);
			}
			adbg_context_fill_win(ctx, &winctx);
		}
	} else version (Posix) {
		//TODO: PT_GETFPREGS
		//      PT_GETWMMXREGS
		//      PT_GET_THREAD_AREA
		//      PT_GETCRUNCHREGS
		//      PT_GETVFPREGS
		//      PT_GETHBPREGS
		user_regs_struct u = void;
		if (ptrace(PT_GETREGS, tracee.pid, null, &u) < 0) {
			return adbg_oops(AdbgError.os);
		}
		adbg_context_fill_linux(ctx, &u);
	}
	return 0;
}

/// Format a register's value into a string buffer.
/// Errors: invalidOption for format.
/// Params:
/// 	buffer = Reference to text buffer.
/// 	len = Size of buffer.
/// 	reg = Register.
/// 	format = String format.
/// Returns: Number of characters written.
size_t adbg_register_format(char *buffer, size_t len, adbg_register_t *reg, int format) {
	if (reg == null || buffer == null || len == 0)
		return 0;
	
	const(char) *sformat = void;
	switch (format) {
	case FORMAT_DEC:
		switch (reg.type) with (AdbgRegisterSize) {
		case u8, u16, u32, u64:
			sformat = "%llu"; break;
		case f32, f64:
			sformat = "%f"; break;
		default:
			adbg_oops(AdbgError.assertion);
			return 0;
		}
		break;
	case FORMAT_HEX:
		sformat = "%llx";
		break;
	case FORMAT_HEXPADDED:
		switch (reg.type) with (AdbgRegisterSize) {
		case u8:       sformat = "%02x"; break;
		case u16:      sformat = "%04x"; break;
		case u32, f32: sformat = "%08x"; break;
		case u64, f64: sformat = "%016llx"; break;
		default:
			adbg_oops(AdbgError.assertion);
			return 0;
		}
		break;
	default:
		adbg_oops(AdbgError.invalidOption);
		return 0;
	}
	
	return snprintf(buffer, len, sformat, reg.u64);
}
unittest {
	adbg_register_t reg;
	reg.name = "TEST";
	reg.type = AdbgRegisterSize.u16;
	reg.u16  = 0x1234;
	
	char[16] buffer = void;
	assert(adbg_register_format(buffer.ptr, 16, &reg, FORMAT_HEXPADDED) == 4);
	assert(strncmp(buffer.ptr, "1234", 16) == 0);
}

private:

version (X86_ANY)
void adbg_context_start_x86(adbg_registers_t *ctx) {
	version (Trace) trace("ctx=%p", ctx);
	ctx.count = 10;
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
void adbg_context_start_x86_64(adbg_registers_t *ctx) {
	version (Trace) trace("ctx=%p", ctx);
	ctx.count = 18;
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
	// Populate exception_t.registers array from Windows' CONTEXT
	void adbg_context_fill_win(adbg_registers_t *ctx, CONTEXT *winctx) {
		version (Trace) trace("ctx=%p win=%p", ctx, winctx);
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
		} else version (X86_64) {
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

	version (Win64) {
		version (X86_64)
		void adbg_context_fill_wow64(adbg_registers_t *ctx, WOW64_CONTEXT *winctx) {
			version (Trace) trace("ctx=%p win=%p", ctx, winctx);
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
		
		//TODO: Windows WoW64 AArch64 filler
	}
} else version (linux) {
	/// Populate exception_t.registers array from user_regs_struct
	void adbg_context_fill_linux(adbg_registers_t *ctx, user_regs_struct *u) {
		version (Trace) trace("ctx=%p u=%p", ctx, u);
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
		} else version (X86_64) {
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
