/// Core disassembler module.
///
/// The API was inspired by fopen and uses Capstone for its backend.
///
/// Tested with: Capstone 4.0.2.
/// 
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.v2.disassembler.core;

import adbg.include.capstone;
import adbg.include.c.stdarg;
import adbg.error;
import adbg.platform;
import adbg.v2.debugger.process : adbg_process_t;
import adbg.v2.object.machines : AdbgMachine;

version (X86) { // CS_OPT_SYNTAX_DEFAULT
	private enum {
		CS_DEFAULT_PLATFORM = CS_ARCH_X86,	/// Platform default platform
		CS_DEFAULT_MODE = CS_MODE_32,	/// Platform default platform
	}
} else version (X86_64) {
	private enum {
		CS_DEFAULT_PLATFORM = CS_ARCH_X86,	/// Ditto
		CS_DEFAULT_MODE = CS_MODE_64,	/// Ditto
	}
} else version (Thumb) {
	private enum {
		CS_DEFAULT_PLATFORM = CS_ARCH_ARM,	/// Ditto
		CS_DEFAULT_MODE = CS_MODE_THUMB,	/// Ditto
	}
} else version (ARM) {
	private enum {
		CS_DEFAULT_PLATFORM = CS_ARCH_ARM,	/// Ditto
		CS_DEFAULT_MODE = CS_MODE_V8, // or CS_MODE_ARM?,	/// Ditto
	}
} else version (AArch64) {
	private enum {
		CS_DEFAULT_PLATFORM = CS_ARCH_ARM64,	/// Ditto
		CS_DEFAULT_MODE = CS_MODE_ARM,	/// Ditto
	}
} else version (RISCV32) {
	private enum {
		CS_DEFAULT_PLATFORM = -3,	/// Ditto
		CS_DEFAULT_MODE = -3,	/// Ditto
	}
} else version (RISCV64) {
	private enum {
		CS_DEFAULT_PLATFORM = -1,	/// Ditto
		CS_DEFAULT_MODE = -3,	/// Ditto
	}
} else {
	static assert(0, "Set DEFAULT_PLATFORM and DEFAULT_SYNTAX");
}

private
enum ADBG_DASM_MAGIC = 0xcafebabe;

extern (C):

/// Disassembler structure.
/// 
/// Anything marked as used internally, should be left untouched.
struct adbg_disassembler_t {
	/// Used internally.
	int magic;
	
	/// Current address, typically points to next instruction.
	ulong address_current;
	/// Last address.
	ulong address_last;
	/// Base address for current disassembled instruction.
	ulong address_base;
	
	/// User input buffer pointer.
	/// Adjusted when called.
	void *buffer;
	/// User input buffer size.
	/// Adjusted when called.
	size_t buffer_size;
	
	/// CS handle.
	/// Used internally.
	csh cs_handle;
	/// CS instruction instance.
	/// Used internally.
	cs_insn *cs_inst;
}

/// Decoded instruction information.
struct adbg_opcode_t {
	ulong base;	/// Base address
	int size;	/// Instruction size in Bytes.
	const(char) *mnemonic;	/// Instruction mnemonic.
	const(char) *operands;	/// Instruction operands.
}

/// Assembler syntax.
enum AdbgDasmSyntax {
	/// Default option for platform.
	native,
	/// Intel syntax
	/// Year: 1978
	/// Destination: Left
	///
	/// Similar to the Macro/Microsoft Assembler (MASM) syntax.
	/// This is the reference syntax for the x86 instruction set.
	/// For more information, consult the Intel and AMD reference manuals.
	///
	/// Example:
	/// ---
	/// mov edx, dword ptr ss:[eax+ecx*2-0x20]
	/// ---
	intel,
	/// AT&T syntax
	/// Year: 1960s
	/// Destination: Right
	///
	/// For more information, consult the IAS/RSX-11 MACRO-11 Reference
	/// Manual and the GNU Assembler documentation.
	///
	/// Example:
	/// ---
	/// mov %ss:-0x20(%eax,%ecx,2), %edx
	/// ---
	att,
}

/// Disassembler options.
enum AdbgDasmOption {
	/// Change syntax.
	/// Type: int
	/// Default: AdbgDasmSyntax.native
	syntax = 2,
	//TODO: Only get size, etc.
	//mode = 3,
}

private __gshared bool loaded_cs;

// Platform to CS' ARCH and MODE types
private
int adbg_dasm_lib_a2cs(ref int cs_arch, ref int cs_mode, AdbgMachine platform) {
	switch (platform) with (AdbgMachine) {
	case native: // equals 0
		cs_arch = CS_DEFAULT_PLATFORM;
		cs_mode = CS_DEFAULT_MODE;
		break;
	case i8086:
		cs_arch = CS_ARCH_X86;
		cs_mode = CS_MODE_16;
		break;
	case x86:
		cs_arch = CS_ARCH_X86;
		cs_mode = CS_MODE_32;
		break;
	case amd64:
		cs_arch = CS_ARCH_X86;
		cs_mode = CS_MODE_64;
		break;
	default:
		return adbg_oops(AdbgError.unsupportedPlatform);
	}
	return 0;
}

// NOTE: Could have done adbg_process_machine but safer to do this.
int adbg_dasm_openproc(adbg_disassembler_t *dasm, adbg_process_t *tracee) {
	AdbgMachine mach;
	
	version (Win64) { // Windows + x86-64
		version (X86_64) {
			mach = tracee.wow64 ? AdbgMachine.x86 : AdbgMachine.amd64;
		}
	}
	
	return adbg_dasm_open(dasm, mach);
}

/* May offer this as an option later
adbg_disassembler_t* adbg_dasm_allocate() {
	
}
void adbg_dasm_free(adbg_disassembler_t* dasm) {
}*/

/// Open a disassembler instance.
/// Params:
///   dasm = Reference to disassembler instance.
///   machine = Machine architecture.
/// Returns: Error code.
int adbg_dasm_open(adbg_disassembler_t *dasm,
	AdbgMachine machine = AdbgMachine.native) {
	//TODO: static if (CAPSTONE_DYNAMIC)
	if (loaded_cs == false) {
		if (capstone_dyn_init()) {
			version (Trace) {
				import bindbc.loader.sharedlib : errors;
				foreach (e; errors) {
					trace("%s", e.message);
				}
			}
			return adbg_oops(AdbgError.libLoader);
		}
		loaded_cs = true;
		version (Trace) trace("capstone loaded");
	}
	
	int cs_arch = void, cs_mode = void;
	if (adbg_dasm_lib_a2cs(cs_arch, cs_mode, machine))
		return adbg_errno;
	
	if (cs_open(cs_arch, cs_mode, &dasm.cs_handle))
		return adbg_oops(AdbgError.libCapstone, &dasm.cs_handle);
	
	dasm.cs_inst = cs_malloc(dasm.cs_handle);
	if (dasm.cs_inst == null)
		return adbg_oops(AdbgError.libCapstone, &dasm.cs_handle);
	
	dasm.magic = ADBG_DASM_MAGIC;
	return 0;
}

/// Re-open a disassembler instance by closing it and opening it again.
/// Params:
///   dasm = Reference to disassembler instance.
///   machine = Machine architecture.
/// Returns: Error code.
int adbg_dasm_reopen(adbg_disassembler_t *dasm, AdbgMachine machine) {
	if (dasm == null)
		return adbg_oops(AdbgError.nullArgument);
	adbg_dasm_close(dasm);
	return adbg_dasm_open(dasm, machine);
}

/// Closes a disassembler instance.
/// Params: dasm = Reference to disassembler instance.
void adbg_dasm_close(adbg_disassembler_t *dasm) {
	import core.stdc.stdlib : free;
	if (dasm == null || dasm.magic != ADBG_DASM_MAGIC)
		return;
	if (dasm.cs_inst)
		cs_free(dasm.cs_inst, 1);
	cs_close(&dasm.cs_handle);
	dasm.magic = 0;
}

/// Configure an option to the disassembler.
/// 
/// Always end the list of options with 0.
///
/// Example:
/// ---
/// adbg_dasm_options(dasm,
///   AdbgDasmOption.syntax, AdbgDasmSyntax.intel,
///   0);
/// ---
/// Params:
///   dasm = Reference to disassembler instance.
///   ... = Options.
/// Returns: Error code.
int adbg_dasm_options(adbg_disassembler_t *dasm, ...) {
	if (dasm == null)
		return adbg_oops(AdbgError.nullArgument);
	
	if (dasm.magic != ADBG_DASM_MAGIC &&
		adbg_dasm_open(dasm))
		return adbg_errno;
	
	va_list args = void;
	va_start(args, dasm);
	
L_ARG:
	switch (va_arg!int(args)) {
	case 0: break;
	case AdbgDasmOption.syntax:
		int cs_syntax = void;
		switch (va_arg!int(args)) {
		case AdbgDasmSyntax.native:
			cs_syntax = CS_OPT_SYNTAX_DEFAULT;
			break;
		case AdbgDasmSyntax.intel:
			cs_syntax = CS_OPT_SYNTAX_INTEL;
			break;
		case AdbgDasmSyntax.att:
			cs_syntax = CS_OPT_SYNTAX_ATT;
			break;
		default:
			return adbg_oops(AdbgError.invalidOptionValue);
		}
		if (cs_option(dasm.cs_handle, CS_OPT_SYNTAX, cs_syntax))
			return adbg_oops(AdbgError.libCapstone, &dasm.cs_handle);
		goto L_ARG;
	default:
		return adbg_oops(AdbgError.invalidOption);
	}
	
	return 0;
}

//TODO: Consider user buffer to opcode struct for multi-buffer support?

/// Start a disassembler session from user data.
///
/// This is typically used before entering a loop.
/// Params:
///   dasm = Reference to disassembler instance.
///   data = Reference to user data.
///   size = Size of the user data.
/// Returns: Error code.
int adbg_dasm_start(adbg_disassembler_t *dasm, void *data, size_t size) {
	if (dasm == null || data == null)
		return adbg_oops(AdbgError.nullArgument);
	dasm.buffer = data;
	dasm.buffer_size = size;
	return 0;
}

/// Disassemble one instruction.
/// Params:
///   dasm = Reference to disassembler instance.
///   opcpde = Reference to an option instance.
/// Returns: Error code.
int adbg_dasm(adbg_disassembler_t *dasm, adbg_opcode_t *opcode) {
	if (dasm == null || opcode == null)
		return adbg_oops(AdbgError.nullArgument);
	if (dasm.magic != ADBG_DASM_MAGIC)
		return adbg_oops(AdbgError.uninitiated);
	
	dasm.address_last = dasm.address_current;
	
	if (cs_disasm_iter(dasm.cs_handle,
		cast(const(ubyte*)*)&dasm.buffer,
		&dasm.buffer_size,
		&dasm.address_base,
		dasm.cs_inst) == false) {
		if (cs_errno(dasm.cs_handle) != CS_ERR_OK)
			return adbg_oops(AdbgError.libCapstone, &dasm.cs_handle);
		
		return adbg_oops(AdbgError.outOfData);
	}
	
	//TODO: disasm modes
	opcode.base = dasm.address_base;
	opcode.size = dasm.cs_inst.size;
	opcode.mnemonic = cs_insn_name(dasm.cs_handle, dasm.cs_inst.id);
	opcode.operands = dasm.cs_inst.op_str.ptr;
	
	return 0;
}

int adbg_dasm_once(adbg_disassembler_t *dasm, adbg_opcode_t *opcode, void *data, size_t size) {
	int e = adbg_dasm_start(dasm, data, size);
	return e ? e : adbg_dasm(dasm, opcode);
}
