/// Core disassembler module.
///
/// The API was inspired by fopen and uses Capstone for its backend.
///
/// Tested with Capstone 4.0.2.
/// 
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.disassembler;

import adbg.include.capstone;
import adbg.include.c.stdarg;
import adbg.error;
import adbg.debugger.process : adbg_process_t;
import adbg.object.machines : AdbgMachine, adbg_object_machine_alias;
import adbg.debugger.exception : adbg_exception_t;
import adbg.debugger.memory : adbg_memory_read;
import core.stdc.string : memcpy;

//TODO: Capstone CS_MODE_BIG_ENDIAN
//      Depending on target endianness, Capstone may need this bit

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

/// Maximum instruction size.
enum MAX_INSTR_SIZE = 16;

private {
	enum ADBG_DASM_MAGIC = 0xcafebabe;
}

extern (C):

/// Disassembler structure.
/// 
/// All fields are used internally, do not touch.
struct adbg_disassembler_t {
	/// Used internally.
	int magic;
	
	//
	// User settings
	//
	
	/// User input buffer pointer.
	/// Adjusted when called.
	void *buffer;
	/// User input buffer size.
	/// Adjusted when called.
	size_t buffer_size;
	
	/// Base address for current disassembled instruction.
	ulong address_base;
	
	/// Attached process.
	adbg_process_t *process;
	
	//
	// Stats
	//
	
	/// Number of successfully decoded instructions.
	int decoded_count;
	
	//
	// Capstone
	//
	
	/// CS handle.
	/// Used internally.
	csh cs_handle;
	/// CS instruction instance.
	/// Used internally.
	cs_insn *cs_inst;
}

/// Decoded instruction information.
struct adbg_opcode_t {
	ulong address;	/// Base instruction address.
	int size;	/// Instruction size in Bytes.
	ubyte[MAX_INSTR_SIZE] machine;	/// Machine bytes.
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

// Platform to CS' ARCH and MODE types
private
int adbg_dasm_lib_a2cs(ref int cs_arch, ref int cs_mode, AdbgMachine platform) {
	switch (platform) with (AdbgMachine) {
	case native: // equals 0
		cs_arch = CS_DEFAULT_PLATFORM;
		cs_mode = CS_DEFAULT_MODE;
		break;
	//
	// x86
	//
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
	//
	// Arm
	//
	case thumb:
		cs_arch = CS_ARCH_ARM;
		cs_mode = CS_MODE_THUMB;
		break;
	case thumb32:
		cs_arch = CS_ARCH_ARM;
		cs_mode = CS_MODE_THUMB | CS_MODE_V8;
		break;
	case arm:
		cs_arch = CS_ARCH_ARM;
		cs_mode = CS_MODE_ARM | CS_MODE_V8;
		break;
	case aarch64:
		cs_arch = CS_ARCH_ARM64;
		cs_mode = CS_MODE_ARM;
		break;
	//
	// Others
	//
	default:
		return adbg_oops(AdbgError.unsupportedPlatform);
	}
	return 0;
}

/// Open a disassembler instance.
/// Params:
///   dasm = Reference to disassembler instance.
///   machine = Machine architecture.
/// Returns: Error code.
int adbg_dasm_open(adbg_disassembler_t *dasm,
	AdbgMachine machine = AdbgMachine.native) {
	//TODO: static if (CAPSTONE_DYNAMIC)
	if (libcapstone_dynload())
		return adbg_errno;
	
	version (Trace) trace("machine=%u (%s)", machine, adbg_object_machine_alias(machine));
	
	int cs_arch = void, cs_mode = void;
	if (adbg_dasm_lib_a2cs(cs_arch, cs_mode, machine))
		return adbg_errno;
	
	//TODO: If already opened, close
	if (cs_open(cs_arch, cs_mode, &dasm.cs_handle))
		return adbg_oops(AdbgError.libCapstone, &dasm.cs_handle);
	
	dasm.cs_inst = cs_malloc(dasm.cs_handle);
	if (dasm.cs_inst == null)
		return adbg_oops(AdbgError.libCapstone, &dasm.cs_handle);
	
	dasm.decoded_count =
	dasm.address_base =
	dasm.buffer_size = 0;
	dasm.buffer = null;
	
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
	//free(dasm); Uncomment when _open uses mallocs
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
L_OPTION:
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
		goto L_OPTION;
	default:
		return adbg_oops(AdbgError.invalidOption);
	}
	
	return 0;
}

/// Start a disassembler session from user data.
///
/// This is typically used before entering a loop.
/// Params:
///   dasm = Reference to disassembler instance.
///   data = Reference to user data.
///   size = Size of the user data.
///   base_address = Base address.
/// Returns: Error code.
int adbg_dasm_start(adbg_disassembler_t *dasm, void *data, size_t size, ulong base_address = 0) {
	if (dasm == null || data == null)
		return adbg_oops(AdbgError.nullArgument);
	dasm.address_base = base_address;
	dasm.buffer = data;
	dasm.buffer_size = size;
	dasm.process = null;
	return 0;
}

/// Disassemble one instruction.
/// Params:
///   dasm = Disassembler instance.
///   opcode = Opcode instance.
/// Returns: Error code.
int adbg_dasm(adbg_disassembler_t *dasm, adbg_opcode_t *opcode) {
	if (dasm == null || opcode == null)
		return adbg_oops(AdbgError.nullArgument);
	if (dasm.magic != ADBG_DASM_MAGIC)
		return adbg_oops(AdbgError.uninitiated);
	
	version (Trace) trace("buffer_size=%u", cast(uint)dasm.buffer_size);
	
	opcode.address = dasm.address_base; // Save before CS modifies it
	
	//TODO: Consider making a specific error code if decoded count is zero.
	//      Use case:
	//        If cs_disasm_iter returns false and cs_errno
	//        returns CS_ERR_OK, this could mean that an invalid
	//        machine type was specified when opening the instance.
	//TODO: Consider replacing mnemonic by "error"
	
	// NOTE: CS modifies buffer, buffer_size, and address_base.
	if (cs_disasm_iter(dasm.cs_handle,
		cast(const(ubyte*)*)&dasm.buffer,
		&dasm.buffer_size,
		&dasm.address_base,
		dasm.cs_inst) == false) {
		if (cs_errno(dasm.cs_handle) != CS_ERR_OK)
			return adbg_oops(AdbgError.libCapstone, &dasm.cs_handle);
		
		// NOTE: Can't reliably check buffer_size left.
		
		// Can't decode instruction but no errors happened?
		// If there were no other instructions decoded, must be illegal
		if (dasm.decoded_count == 0)
			return adbg_oops(AdbgError.illegalInstruction);
		
		return adbg_oops(AdbgError.outOfData);
	}
	
	++dasm.decoded_count;
	
	//TODO: disasm modes
	opcode.size = dasm.cs_inst.size;
	opcode.mnemonic = cs_insn_name(dasm.cs_handle, dasm.cs_inst.id);
	opcode.operands = dasm.cs_inst.op_str.ptr;
	memcpy(opcode.machine.ptr, dasm.buffer - opcode.size, opcode.size);
	return 0;
}

/// Setup buffer and disassemble one instruction.
/// Params:
///   dasm = Disassembler instance.
///   opcode = Opcode instance.
///   data = Pointer to user buffer.
///   size = Size of user buffer.
/// Returns: Error code.
int adbg_dasm_once(adbg_disassembler_t *dasm, adbg_opcode_t *opcode, void *data, size_t size,
	ulong base_address = 0) {
	int e = adbg_dasm_start(dasm, data, size, base_address);
	return e ? e : adbg_dasm(dasm, opcode);
}

//
// Process wrappers
//

int adbg_dasm_start_process(adbg_disassembler_t *dasm, adbg_process_t *process, ulong location) {
	if (dasm == null || process == null)
		return adbg_oops(AdbgError.nullArgument);
	dasm.address_base = location;
	dasm.process = process;
	return 0;
}

int adbg_dasm_process(adbg_disassembler_t *dasm, adbg_opcode_t *opcode) {
	if (dasm == null || opcode == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	if (adbg_memory_read(dasm.process, dasm.address_base, opcode.machine.ptr, MAX_INSTR_SIZE))
		return adbg_errno;
	
	dasm.buffer = opcode.machine.ptr;
	dasm.buffer_size = MAX_INSTR_SIZE;
	
	return adbg_dasm(dasm, opcode);
}

/// Wrapper that reads memory from process that disassembles one instruction.
/// Params:
/// 	dasm = Disassembler instance.
/// 	opcode = Opcode instance.
/// 	tracee = Debuggee process.
/// 	address = Process virtual memory location.
/// Returns: Error code.
int adbg_dasm_process_once(adbg_disassembler_t *dasm, adbg_opcode_t *opcode, adbg_process_t *tracee, ulong address) {
	if (dasm == null || tracee == null || opcode == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	if (adbg_memory_read(tracee, address, opcode.machine.ptr, MAX_INSTR_SIZE))
		return adbg_errno;
	if (adbg_dasm_once(dasm, opcode, opcode.machine.ptr, MAX_INSTR_SIZE))
		return adbg_errno;
	return 0;
}
