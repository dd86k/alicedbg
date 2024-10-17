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
import adbg.platform;
import adbg.process.base : adbg_process_t;
import adbg.process.memory : adbg_memory_read;
import adbg.machines : AdbgMachine, adbg_machine_current;
import adbg.utils.math : min;
import core.stdc.string : memcpy;
import core.stdc.stdlib : malloc, calloc, free;

// TODO: Function to format machine code
// TODO: Opcode utilities
//       adbg_disassembler_opcode_illegal or _class

// NOTE: Instruction buffer
//       Some decoders, like Capstone, is keen to go over architectural
//       limits in some cases. Like with x86, where its architectural limit
//       is 15 Bytes, CS might act weird and go over that, so we bump the
//       buffer when this happens.
/// Maximum instruction size in bytes.
enum OPCODE_BUFSIZE = 24;

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
	
	/// User input buffer pointer.
	void *buffer;
	/// User input buffer size.
	size_t buffer_size;
	/// Base address for current disassembled instruction.
	ulong address_base;
	
	union {
		struct { // Capstone internals
			/// CS handle.
			/// Used internally.
			csh cs_handle;
			/// CS instruction instance.
			/// Used internally.
			cs_insn *cs_inst;
			/// Associated machine.
			immutable(libcsmachine_t) *machinfo;
		}
	}
}

/// Decoded instruction information.
struct adbg_opcode_t {
	ulong address;	/// Base instruction address.
	int size;	/// Instruction size in Bytes.
	ubyte[OPCODE_BUFSIZE] data;	/// Machine bytes.
	alias machine = data;
	const(char) *mnemonic;	/// Instruction mnemonic.
	const(char) *operands;	/// Instruction operands.
}

/// Assembler syntax.
enum AdbgDisassemblerSyntax {
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
enum AdbgDisassemblerOption {
	/// Change syntax.
	/// Type: int
	/// Default: AdbgDasmSyntax.native
	syntax = 2,
	//TODO: Only get size, etc.
	//mode = 3,
}

// NOTE: Architectural instruction limit
//       RISC-V: 24 bytes (reserved)
//       IA64: 16 bytes
//       Alpha: 4 bytes
private
struct libcsmachine_t {
	AdbgMachine mach;
	int maxopsize;
	int cs_arch;
	int cs_mode;
}
private // "works": MODE values worked with a sample
immutable libcsmachine_t[] machmap_capstone = [
	{ AdbgMachine.i8086,	15,	CS_ARCH_X86,	CS_MODE_16 }, // works
	{ AdbgMachine.i386,	15,	CS_ARCH_X86,	CS_MODE_32 }, // works
	{ AdbgMachine.amd64,	15,	CS_ARCH_X86,	CS_MODE_64 }, // works
	{ AdbgMachine.thumb,	2,	CS_ARCH_ARM,	CS_MODE_THUMB },
	{ AdbgMachine.thumb32,	4,	CS_ARCH_ARM,	CS_MODE_THUMB | CS_MODE_V8 },
	{ AdbgMachine.arm,	4,	CS_ARCH_ARM,	CS_MODE_ARM | CS_MODE_V8 }, // works
	{ AdbgMachine.aarch64,	4,	CS_ARCH_ARM64,	0 }, // works
	{ AdbgMachine.ppc,	4,	CS_ARCH_PPC,	CS_MODE_32 | CS_MODE_BIG_ENDIAN }, // works
	{ AdbgMachine.ppcle,	4,	CS_ARCH_PPC,	CS_MODE_32 | CS_MODE_LITTLE_ENDIAN }, // works
	{ AdbgMachine.ppc64,	4,	CS_ARCH_PPC,	CS_MODE_64 | CS_MODE_BIG_ENDIAN },
	{ AdbgMachine.ppc64le,	4,	CS_ARCH_PPC,	CS_MODE_64 | CS_MODE_LITTLE_ENDIAN },
	{ AdbgMachine.mips,	4,	CS_ARCH_MIPS,	CS_MODE_32 | CS_MODE_BIG_ENDIAN }, // works
	{ AdbgMachine.mipsle,	4,	CS_ARCH_MIPS,	CS_MODE_32 | CS_MODE_LITTLE_ENDIAN },
	{ AdbgMachine.mipsii,	4,	CS_ARCH_MIPS,	CS_MODE_32 | CS_MODE_MIPS2 | CS_MODE_BIG_ENDIAN },
	{ AdbgMachine.mipsiii,	4,	CS_ARCH_MIPS,	CS_MODE_32 | CS_MODE_MIPS3 | CS_MODE_BIG_ENDIAN },
	{ AdbgMachine.mipsiv,	4,	CS_ARCH_MIPS,	CS_MODE_32 | CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN },
	{ AdbgMachine.sparc,	4,	CS_ARCH_SPARC,	0 },
	{ AdbgMachine.sparc9,	4,	CS_ARCH_SPARC,	CS_MODE_V9 }, // works
	// BRANCH AND LINK with address is 8 bytes, opcodes vary by 2, 4, 6 bytes
	{ AdbgMachine.systemz,	8,	CS_ARCH_SYSZ,	0 }, // works
];

// Platform to CS' ARCH and MODE types
private
immutable(libcsmachine_t)* adbg_disassembler_liba2cs(AdbgMachine platform) {
	// Get matching available architecture
	for (size_t i; i < machmap_capstone.length; ++i) {
		immutable(libcsmachine_t)* info = &machmap_capstone[i];
		if (platform != info.mach)
			continue;
		return info;
	}
	return null;
}

/// Open a disassembler instance.
/// Params: machine = Machine architecture.
/// Returns: Error code.
adbg_disassembler_t* adbg_disassembler_open(AdbgMachine machine = AdbgMachine.unknown) {
	//TODO: static if (CAPSTONE_DYNAMIC)
	if (libcapstone_dynload())
		return null;
		
	// If no architecture specified, get target default
	if (machine == AdbgMachine.unknown)
		machine = adbg_machine_current();
	
	// Get matching machine info
	immutable(libcsmachine_t) *csinfo = adbg_disassembler_liba2cs(machine);
	if (csinfo == null) {
		adbg_oops(AdbgError.disasmUnsupportedMachine);
		return null;
	}
	
	// Allocate an instance of disassembler
	adbg_disassembler_t *dasm = cast(adbg_disassembler_t*)malloc(adbg_disassembler_t.sizeof);
	if (dasm == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	// Open CS
	if (cs_open(csinfo.cs_arch, csinfo.cs_mode, &dasm.cs_handle)) {
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
	
	dasm.machinfo = csinfo;
	dasm.address_base  = 0;
	dasm.buffer_size   = 0;
	dasm.buffer = null;
	dasm.magic = ADBG_MAGIC;
	return dasm;
}

/// Closes a disassembler instance.
/// Params: dasm = Reference to disassembler instance.
void adbg_disassembler_close(adbg_disassembler_t *dasm) {
	if (dasm == null || dasm.magic != ADBG_MAGIC)
		return;
	if (dasm.cs_inst)
		cs_free(dasm.cs_inst, 1);
	cs_close(&dasm.cs_handle);
	free(dasm);
}

/// Get the maximum instruction size permited architecturally from the currently
/// selected machine type within the disassembler instance.
/// Params: dasm = Disassembler instance.
/// Returns: The number maximum of bytes; Otherwise -1 on error.
int adbg_disassembler_max_opcode_size(adbg_disassembler_t *dasm) {
	if (dasm == null) {
		adbg_oops(AdbgError.invalidArgument);
		return -1;
	}
	assert(dasm.machinfo);
	return dasm.machinfo.maxopsize;
}

/// Return the amount of bytes left in the buffer to process.
/// Params: dasm = Disassembler instance.
/// Returns: Buffer length left; Otherwise 0 on error.
size_t adbg_disassembler_buffer_left(adbg_disassembler_t *dasm) {
	if (dasm == null) {
		adbg_oops(AdbgError.invalidArgument);
		return 0;
	}
	return dasm.buffer_size;
}

/// Returns a null-terminated list of machines that the disassembler supports.
/// Returns: Pointer to null-terminated list.
immutable(AdbgMachine)* adbg_disassembler_machines() {
	__gshared bool init;
	__gshared AdbgMachine[machmap_capstone.length + 1] list;
	// Since machine mapping array isn't linear, make a linear list here
	if (init == false) {
		foreach (i, ref immutable(libcsmachine_t) mach; machmap_capstone)
			list[i] = mach.mach;
		list[machmap_capstone.length] = AdbgMachine.unknown;
		init = true;
	}
	return cast(immutable(AdbgMachine)*)list.ptr;
}
extern (D) unittest {
	immutable(AdbgMachine)* machs = adbg_disassembler_machines();
	assert(machs[0] == AdbgMachine.i8086);
	assert(machs[1] == AdbgMachine.i386);
	assert(machs[machmap_capstone.length] == 0);
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
int adbg_disassembler_options(adbg_disassembler_t *dasm, ...) {
	if (dasm == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (dasm.magic != ADBG_MAGIC)
		return adbg_oops(AdbgError.uninitiated);
	
	va_list args = void;
	va_start(args, dasm);
Loption:
	switch (va_arg!int(args)) {
	case 0: break;
	case AdbgDisassemblerOption.syntax:
		int cs_syntax = void;
		switch (va_arg!int(args)) {
		case AdbgDisassemblerSyntax.native:
			cs_syntax = CS_OPT_SYNTAX_DEFAULT;
			break;
		case AdbgDisassemblerSyntax.intel:
			cs_syntax = CS_OPT_SYNTAX_INTEL;
			break;
		case AdbgDisassemblerSyntax.att:
			cs_syntax = CS_OPT_SYNTAX_ATT;
			break;
		default:
			return adbg_oops(AdbgError.invalidValue);
		}
		if (cs_option(dasm.cs_handle, CS_OPT_SYNTAX, cs_syntax))
			return adbg_oops(AdbgError.libCapstone, &dasm.cs_handle);
		goto Loption;
	default:
		return adbg_oops(AdbgError.invalidOption);
	}
	
	return 0;
}

/// Disassemble one instruction.
/// Params:
///   dasm = Disassembler instance.
///   opcode = Opcode instance.
///   buffer = Data buffer.
///   len = Length of data buffer.
///   base_address = Base address.
/// Returns: Error code.
int adbg_disassemble(adbg_disassembler_t *dasm, adbg_opcode_t *opcode,
	void *buffer, size_t len, ulong base_address = 0) {
	if (dasm == null || opcode == null || buffer == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (dasm.magic != ADBG_MAGIC)
		return adbg_oops(AdbgError.uninitiated);
	
	version (Trace) trace("buffer_size=%u", cast(uint)dasm.buffer_size);
	
	dasm.buffer = buffer;
	dasm.buffer_size = len;
	dasm.address_base = base_address;
	
	return adbg_disassembler_buffer_step(dasm, opcode);
}

/// Prepare the disassembler to iterate a data buffer.
/// Params:
/// 	dasm = Disassembler instance.
/// 	data = Data buffer pointer.
/// 	size = Length of data buffer.
/// 	base_address = Base address 
/// Returns: Error code.
int adbg_disassembler_buffer_start(adbg_disassembler_t *dasm,
	void *data, size_t size, ulong base_address = 0) {
	if (dasm == null || data == null || size == 0)
		return adbg_oops(AdbgError.invalidArgument);
	dasm.buffer = data;
	dasm.buffer_size = size;
	dasm.address_base = base_address;
	return 0;
}

/// With a previously given buffer, perform a step into the data buffer.
/// Params:
/// 	dasm = Disassembler instance.
/// 	opcode = Opcode instance.
/// Returns: Error code.
int adbg_disassembler_buffer_step(adbg_disassembler_t *dasm, adbg_opcode_t *opcode) {
	if (dasm == null || opcode == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (dasm.buffer == null || dasm.buffer_size == 0)
		return adbg_oops(AdbgError.uninitiated);
	
	opcode.address = dasm.address_base; // Save address before CS modifies it
	void *buffer = dasm.buffer;
	size_t len = dasm.buffer_size;
	
	// TODO: Consider replacing mnemonic by "error" or "illegal"
	//       Needs to be something specific (e.g., .bytes 0x11 0x22)
	
	// NOTE: CS modifies buffer pointer, buffer_size, and address_base.
	if (cs_disasm_iter(dasm.cs_handle,
		cast(const(ubyte*)*)&dasm.buffer,
		&dasm.buffer_size,
		&dasm.address_base,
		dasm.cs_inst) == false) {
		// Library error
		if (cs_errno(dasm.cs_handle) != CS_ERR_OK)
			return adbg_oops(AdbgError.libCapstone, &dasm.cs_handle);
		
		// Since disassembly simply didn't work out, and CS does not
		// give us an instruction size, we go by the maximum opcode size
		// and copy that many bytes into the opcode buffer.
		opcode.size = cast(int)min(OPCODE_BUFSIZE, dasm.machinfo.maxopsize);
		opcode.mnemonic = "illegal";
		opcode.operands = null;
		memcpy(opcode.machine.ptr, buffer, opcode.size);
		return adbg_oops(AdbgError.disasmIllegalInstruction);
	}
	
	// TODO: disasm modes
	opcode.size = dasm.cs_inst.size;
	opcode.mnemonic = cs_insn_name(dasm.cs_handle, dasm.cs_inst.id);
	opcode.operands = dasm.cs_inst.op_str[0] ? dasm.cs_inst.op_str.ptr : null;
	memcpy(opcode.machine.ptr, buffer, opcode.size);
	return 0;
}

//
// Opcode utilities
//

/// For platform that cannot have the opcode structure defined,
/// and while not necessarily required, this function allocates
/// one instance of an instruction opcode for use with the disassembler.
/// Returns: Opcode instance; Or null on allocation error.
adbg_opcode_t* adbg_disassembler_new_opcode() {
	adbg_opcode_t *opcode = cast(adbg_opcode_t*)calloc(1, adbg_opcode_t.sizeof);
	if (opcode == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	return opcode;
}

/// Closes the opcode instance.
/// Params: opcode = Opcode instance.
void adbg_disassembler_close_opcode(adbg_opcode_t *opcode) {
	if (opcode) free(opcode);
}
