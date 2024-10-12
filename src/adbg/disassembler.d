/// Core disassembler module.
///
/// The API was inspired by fopen and uses Capstone for its backend.
///
/// Tested with Capstone 4.0.2.
/// 
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.disassembler;

import adbg.include.capstone;
import adbg.include.c.stdarg;
import adbg.error;
import adbg.process.base : adbg_process_t;
import adbg.process.memory : adbg_memory_read;
import adbg.machines : AdbgMachine, adbg_machine_current;
import core.stdc.string : memcpy;
import core.stdc.stdlib : malloc, free;

// TODO: Function to format machine code
// TODO: Redo Disassembler API
//       - Rename prefix to adbg_disasm_
//       - adbg_disasm_open
//       - adbg_disasm_close
//       - adbg_disasm_supported_machines
//       - adbg_disasm_set_options
//       - adbg_disasm_buffer_start
//       - adbg_disasm_buffer_stepin
//       - adbg_disasm (with buffer and its length)
//       - Move process wrappers to debugger module
//         - adbg_debugger_disassemble_at(memoryloc)

// NOTE: Longest architectural instruction contest
//       x86: 15 bytes
//       AArch32: 2 (T32) or 4 (A32) bytes
//       AArch64: 4 bytes
//       Power: 4 bytes
//       MIPS: 4 bytes
//       RISC-V: 24 bytes (reserved)
//       SPARC: 4 bytes
//       IA64: 16 bytes
//       Alpha: 4 bytes

// NOTE: Instruction buffer
//       Some decoders, like Capstone, is keen to go over architectural
//       limits in some cases. Like with x86, where its architectural limit
//       is 15 Bytes, CS might act weird and go over that, so we bump the
//       buffer when this happens.
/// Maximum instruction size in bytes.
enum MAX_INSTR_SIZE = 24;

private {
	enum ADBG_MAGIC = 0xcafebabe;
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
enum AdbgDisSyntax {
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
enum AdbgDisOpt {
	/// Change syntax.
	/// Type: int
	/// Default: AdbgDasmSyntax.native
	syntax = 2,
	//TODO: Only get size, etc.
	//mode = 3,
}

private
struct dismachine_t {
	AdbgMachine mach;
	int cs_arch;
	int cs_mode;
}
private // "works": MODE values worked with a sample
immutable dismachine_t[] machmap_capstone = [
	{ AdbgMachine.i8086,	CS_ARCH_X86,	CS_MODE_16 }, // works
	{ AdbgMachine.i386,	CS_ARCH_X86,	CS_MODE_32 }, // works
	{ AdbgMachine.amd64,	CS_ARCH_X86,	CS_MODE_64 }, // works
	{ AdbgMachine.thumb,	CS_ARCH_ARM,	CS_MODE_THUMB },
	{ AdbgMachine.thumb32,	CS_ARCH_ARM,	CS_MODE_THUMB | CS_MODE_V8 },
	{ AdbgMachine.arm,	CS_ARCH_ARM,	CS_MODE_ARM | CS_MODE_V8 }, // works
	{ AdbgMachine.aarch64,	CS_ARCH_ARM64,	0 }, // works
	{ AdbgMachine.ppc,	CS_ARCH_PPC,	CS_MODE_32 | CS_MODE_BIG_ENDIAN }, // works
	{ AdbgMachine.ppcle,	CS_ARCH_PPC,	CS_MODE_32 | CS_MODE_LITTLE_ENDIAN }, // works
	{ AdbgMachine.ppc64,	CS_ARCH_PPC,	CS_MODE_64 | CS_MODE_BIG_ENDIAN },
	{ AdbgMachine.ppc64le,	CS_ARCH_PPC,	CS_MODE_64 | CS_MODE_LITTLE_ENDIAN },
	{ AdbgMachine.mips,	CS_ARCH_MIPS,	CS_MODE_32 | CS_MODE_BIG_ENDIAN }, // works
	{ AdbgMachine.mipsle,	CS_ARCH_MIPS,	CS_MODE_32 | CS_MODE_LITTLE_ENDIAN },
	{ AdbgMachine.mipsii,	CS_ARCH_MIPS,	CS_MODE_32 | CS_MODE_MIPS2 | CS_MODE_BIG_ENDIAN },
	{ AdbgMachine.mipsiii,	CS_ARCH_MIPS,	CS_MODE_32 | CS_MODE_MIPS3 | CS_MODE_BIG_ENDIAN },
	{ AdbgMachine.mipsiv,	CS_ARCH_MIPS,	CS_MODE_32 | CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN },
	{ AdbgMachine.sparc,	CS_ARCH_SPARC,	0 },
	{ AdbgMachine.sparc9,	CS_ARCH_SPARC,	CS_MODE_V9 }, // works
	{ AdbgMachine.systemz,	CS_ARCH_SYSZ,	0 }, // works
];

// Platform to CS' ARCH and MODE types
private
int adbg_dis_lib_a2cs(ref int cs_arch, ref int cs_mode, AdbgMachine platform) {
	// If no architecture specified, get target default
	if (platform == AdbgMachine.unknown)
		platform = adbg_machine_current();
	
	// Get matching available architecture
	foreach (ref immutable(dismachine_t) dismach; machmap_capstone) {
		if (platform != dismach.mach)
			continue;
		cs_arch = dismach.cs_arch;
		cs_mode = dismach.cs_mode;
		return 0;
	}
	
	return adbg_oops(AdbgError.disasmUnsupportedMachine);
}

/// Open a disassembler instance.
/// Params: machine = Machine architecture.
/// Returns: Error code.
adbg_disassembler_t* adbg_dis_open(AdbgMachine machine = AdbgMachine.unknown) {
	//TODO: static if (CAPSTONE_DYNAMIC)
	if (libcapstone_dynload())
		return null;
	
	int cs_arch = void, cs_mode = void;
	if (adbg_dis_lib_a2cs(cs_arch, cs_mode, machine))
		return null;
	
	adbg_disassembler_t *dasm = cast(adbg_disassembler_t*)malloc(adbg_disassembler_t.sizeof);
	if (dasm == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	if (cs_open(cs_arch, cs_mode, &dasm.cs_handle)) {
		adbg_oops(AdbgError.libCapstone, &dasm.cs_handle);
		free(dasm);
		return null;
	}
	
	dasm.cs_inst = cs_malloc(dasm.cs_handle);
	if (dasm.cs_inst == null) {
		adbg_oops(AdbgError.libCapstone, &dasm.cs_handle);
		free(dasm);
		return null;
	}
	
	dasm.decoded_count = 0;
	dasm.address_base  = 0;
	dasm.buffer_size   = 0;
	dasm.buffer = null;
	dasm.magic = ADBG_MAGIC;
	return dasm;
}

/// Closes a disassembler instance.
/// Params: dasm = Reference to disassembler instance.
void adbg_dis_close(adbg_disassembler_t *dasm) {
	if (dasm == null || dasm.magic != ADBG_MAGIC)
		return;
	if (dasm.cs_inst)
		cs_free(dasm.cs_inst, 1);
	cs_close(&dasm.cs_handle);
	free(dasm);
}

// HACK: Index parameter since I cannot simply give list linearly
/// Returns a null-terminated list of machines that the disassembler supports.
/// Returns: Pointer to null-terminated list.
immutable(AdbgMachine)* adbg_dis_machines(size_t i) {
	if (i >= machmap_capstone.length)
		return null;
	return &machmap_capstone[i].mach;
}

/// Configure an option to the disassembler.
/// 
/// Always end the list of options with 0.
///
/// Example:
/// ---
/// adbg_dis_options(dasm,
///   AdbgDasmOption.syntax, AdbgDasmSyntax.intel,
///   0);
/// ---
/// Params:
///   dasm = Reference to disassembler instance.
///   ... = Options.
/// Returns: Error code.
int adbg_dis_options(adbg_disassembler_t *dasm, ...) {
	if (dasm == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (dasm.magic != ADBG_MAGIC)
		return adbg_oops(AdbgError.uninitiated);
	
	va_list args = void;
	va_start(args, dasm);
L_OPTION:
	switch (va_arg!int(args)) {
	case 0: break;
	case AdbgDisOpt.syntax:
		int cs_syntax = void;
		switch (va_arg!int(args)) {
		case AdbgDisSyntax.native:
			cs_syntax = CS_OPT_SYNTAX_DEFAULT;
			break;
		case AdbgDisSyntax.intel:
			cs_syntax = CS_OPT_SYNTAX_INTEL;
			break;
		case AdbgDisSyntax.att:
			cs_syntax = CS_OPT_SYNTAX_ATT;
			break;
		default:
			return adbg_oops(AdbgError.invalidValue);
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
int adbg_dis_start(adbg_disassembler_t *dasm, void *data, size_t size, ulong base_address = 0) {
	if (dasm == null || data == null)
		return adbg_oops(AdbgError.invalidArgument);
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
int adbg_dis_step(adbg_disassembler_t *dasm, adbg_opcode_t *opcode) {
	if (dasm == null || opcode == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (dasm.magic != ADBG_MAGIC)
		return adbg_oops(AdbgError.uninitiated);
	
	version (Trace) trace("buffer_size=%u", cast(uint)dasm.buffer_size);
	
	opcode.address = dasm.address_base; // Save before CS modifies it
	
	//TODO: Consider replacing mnemonic by "error" or "illegal"
	//      Needs to be something specific (e.g., .bytes 0x11 0x22)
	
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
			return adbg_oops(AdbgError.disasmIllegalInstruction);
		
		return adbg_oops(AdbgError.disasmEndOfData);
	}
	
	++dasm.decoded_count;
	
	//TODO: disasm modes
	opcode.size = dasm.cs_inst.size;
	opcode.mnemonic = cs_insn_name(dasm.cs_handle, dasm.cs_inst.id);
	opcode.operands = dasm.cs_inst.op_str[0] ? dasm.cs_inst.op_str.ptr : null;
	memcpy(opcode.machine.ptr, dasm.buffer - opcode.size, opcode.size);
	return 0;
}

/// Setup buffer and disassemble one instruction.
/// Params:
///   dasm = Disassembler instance.
///   opcode = Opcode instance.
///   data = Pointer to user buffer.
///   size = Size of user buffer.
///   base_address = Base address.
/// Returns: Error code.
int adbg_dis_once(adbg_disassembler_t *dasm, adbg_opcode_t *opcode, void *data, size_t size,
	ulong base_address = 0) {
	int e = adbg_dis_start(dasm, data, size, base_address);
	return e ? e : adbg_dis_step(dasm, opcode);
}

//
// Process wrappers
//

int adbg_dis_process_start(adbg_disassembler_t *dasm, adbg_process_t *process, ulong location) {
	if (dasm == null || process == null)
		return adbg_oops(AdbgError.invalidArgument);
	dasm.address_base = location;
	dasm.process = process;
	return 0;
}

int adbg_dis_process_step(adbg_disassembler_t *dasm, adbg_opcode_t *opcode) {
	if (dasm == null || opcode == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	if (adbg_memory_read(dasm.process, cast(size_t)dasm.address_base, opcode.machine.ptr, MAX_INSTR_SIZE))
		return adbg_errno;
	
	dasm.buffer = opcode.machine.ptr;
	dasm.buffer_size = MAX_INSTR_SIZE;
	
	return adbg_dis_step(dasm, opcode);
}

/// Wrapper that reads memory from process that disassembles one instruction.
/// Params:
/// 	dasm = Disassembler instance.
/// 	opcode = Opcode instance.
/// 	tracee = Debuggee process.
/// 	address = Process virtual memory location.
/// Returns: Error code.
int adbg_dis_process_once(adbg_disassembler_t *dasm, adbg_opcode_t *opcode, adbg_process_t *tracee, ulong address) {
	if (dasm == null || tracee == null || opcode == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	if (adbg_memory_read(tracee, cast(size_t)address, opcode.machine.ptr, MAX_INSTR_SIZE))
		return adbg_errno;
	if (adbg_dis_once(dasm, opcode, opcode.machine.ptr, MAX_INSTR_SIZE))
		return adbg_errno;
	return 0;
}
