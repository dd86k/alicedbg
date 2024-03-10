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
	import adbg.include.windows.wow64apiset;
	import adbg.include.windows.winnt;
	import core.sys.windows.winbase;
} else version (Posix) {
	import adbg.include.linux.user;
	import adbg.include.posix.ptrace;
	import core.sys.posix.signal;
}

/// Number of registers, used for buffer
private enum REG_COUNT = 18; // Currently, x86-64 has highest number

extern (C):

//TODO: Support f80 (x87)
/// Register size
enum AdbgRegType : ubyte {
	u8, u16, u32, u64,
	f32, f64
}

/// Register 
enum AdbgRegFormat {
	dec,
	hex,
	hexPadded,
}

/// Register name and type.
struct adbg_register_info_t {
	const(char) *name;	/// Register name
	AdbgRegType type;	/// Register type (size)
}

/// Register structure, designs a single register for UI ends to understand
struct adbg_register_t {
	/// Register name and type.
	adbg_register_info_t info;
	union { // Data
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
	
	static immutable adbg_register_info_t[] regs_x86 = [
		{ "eip",	AdbgRegType.u32 },
		{ "eflags",	AdbgRegType.u32 },
		{ "eax",	AdbgRegType.u32 },
		{ "ebx",	AdbgRegType.u32 },
		{ "ecx",	AdbgRegType.u32 },
		{ "edx",	AdbgRegType.u32 },
		{ "esp",	AdbgRegType.u32 },
		{ "ebp",	AdbgRegType.u32 },
		{ "esi",	AdbgRegType.u32 },
		{ "edi",	AdbgRegType.u32 },
	];
	static immutable adbg_register_info_t[] regs_x86_64 = [
		{ "rip",	AdbgRegType.u64 },
		{ "rflags",	AdbgRegType.u64 },
		{ "rax",	AdbgRegType.u64 },
		{ "rbx",	AdbgRegType.u64 },
		{ "rcx",	AdbgRegType.u64 },
		{ "rdx",	AdbgRegType.u64 },
		{ "rsp",	AdbgRegType.u64 },
		{ "rbp",	AdbgRegType.u64 },
		{ "rsi",	AdbgRegType.u64 },
		{ "rdi",	AdbgRegType.u64 },
		{ "r8",	AdbgRegType.u64 },
		{ "r9",	AdbgRegType.u64 },
		{ "r10",	AdbgRegType.u64 },
		{ "r11",	AdbgRegType.u64 },
		{ "r12",	AdbgRegType.u64 },
		{ "r13",	AdbgRegType.u64 },
		{ "r14",	AdbgRegType.u64 },
		{ "r15",	AdbgRegType.u64 },
	];
	
	immutable(adbg_register_info_t)[] regs = void;
	
	switch (mach) with (AdbgMachine) {
	case x86:
		regs = regs_x86;
		break;
	case amd64:
		regs = regs_x86_64;
		break;
	default:
		return adbg_oops(AdbgError.objectInvalidMachine);
	}
	
	for (size_t i; i < regs.length; ++i) {
		ctx.items[i].info = regs[i];
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
		adbg_registers_config(ctx, AdbgMachine.x86);
	} else version (X86_64) {
		version (Win64) { // Windows 64-bit
			if (tracee.wow64)
				adbg_registers_config(ctx, AdbgMachine.x86);
			else
				adbg_registers_config(ctx, AdbgMachine.amd64);
		} else // Anything else 64-bit
			adbg_registers_config(ctx, AdbgMachine.amd64);
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
	
	if (tracee.creation == AdbgCreation.unloaded)
		return adbg_oops(AdbgError.debuggerUnattached);
	
	memset(ctx, 0, adbg_registers_t.sizeof);
	
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
			if (GetThreadContext(tracee.htid, cast(LPCONTEXT)&winctx) == FALSE) {
				return adbg_oops(AdbgError.os);
			}
			adbg_context_fill_win(ctx, &winctx);
		}
	} else {
		winctx.ContextFlags = CONTEXT_ALL;
		if (GetThreadContext(tracee.htid, cast(LPCONTEXT)&winctx) == FALSE) {
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
} // version (Posix)
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
int adbg_register_format(char *buffer, size_t len, adbg_register_t *reg, AdbgRegFormat format) {
	if (reg == null || buffer == null || len == 0)
		return 0;
	
	// Get value
	ulong n = void;
	switch (reg.info.type) with (AdbgRegType) {
	case u8:  n = reg.u8; break;
	case u16: n = reg.u16; break;
	case u32: n = reg.u32; break;
	case u64: n = reg.u64; break;
	case f32: *cast(double*)n = reg.f32; break;
	case f64: *cast(double*)n = reg.f64; break;
	default:
		adbg_oops(AdbgError.invalidOption);
		return 0;
	}
	
	// Get format
	const(char) *sformat = void;
	switch (format) with (AdbgRegFormat) {
	case dec:
		switch (reg.info.type) with (AdbgRegType) {
		case u8, u16, u32, u64:
			sformat = "%llu"; break;
		case f32, f64:
			sformat = "%f"; break;
		default:
			adbg_oops(AdbgError.assertion);
			return 0;
		}
		break;
	case hex:
		sformat = "%llx";
		break;
	case hexPadded:
		switch (reg.info.type) with (AdbgRegType) {
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
	
	return snprintf(buffer, len, sformat, n);
}
unittest {
	adbg_register_t reg = void;
	reg.info.type = AdbgRegType.u16;
	reg.u16  = 0x1234;
	enum BUFSZ = 16;
	char[BUFSZ] buffer = void;
	int r = adbg_register_format(buffer.ptr, BUFSZ, &reg, AdbgRegFormat.hex);
	assert(r == 4);
	// 16 to check null terminator
	assert(strncmp(buffer.ptr, "1234", BUFSZ) == 0);
}

private:

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

} // version linux
