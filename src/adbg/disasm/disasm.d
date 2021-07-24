/**
 * Disassembler module.
 *
 * This module is responsable for disassembling and formatting machine code.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.disasm.disasm;

import adbg.error;
private import adbg.utils.bit : swapfunc16, swapfunc32, swapfunc64, BIT;
private import adbg.utils.str;
private import adbg.platform : adbg_address_t;
private import adbg.disasm.arch.x86,
	adbg.disasm.arch.riscv;
private import adbg.disasm.syntax.intel,
	adbg.disasm.syntax.nasm,
	adbg.disasm.syntax.att;

//NOTE: The _start functions avoid repetiveness in runtime.
//NOTE: The formatting can be done at the same time to avoid unnessary actions.
//      Like, specifying the mode to data calculates jump offsets, but does not
//      add items in the syntaxer buffers.

//TODO: revamp "machine buffer" part
//TODO: Consider isa info structures in memory
//      Depending on ISA enum
//      Little/Big endian for fetch operations
//TODO: Invalid results could be rendered differntly
//      e.g., .byte 0xd6,0xd6 instead of (bad)
//      Take from machine buffer? (only if it were a plain buffer...)
//TODO: Consider making the machine buffer a plain buffer
//      e.g., do not already format the bytes?
//        pros: - caller has the.. instruction bytes?
//              - format later? (even if we are using our "fast" formatting functions?)
//        cons: - no grouping from decoder
//                - re-introduce group with instruction offset in buffer?
//TODO: option for hex offset prefix/suffix ($,h,0x)
//      Maybe per syntax? At least default setting?
//TODO: Figure out how to do offsets in memory accesses
//      Displacement size / signed / etc.

extern (C):

/// Character buffer size
///
/// Currently, 64 characters is enough to hold SIB memory references, AVX-512
/// instructions, or 15 bytes of machine code hexadecimal numbers. Used in
/// formatter module.
///
/// If that's not enough, update to 80 characters.
deprecated package enum ADBG_DISASM_BUFFER_SIZE = 64;

/// Buffer size for prefixes.
private enum ADBG_MAX_PREFIXES = 4;
/// Buffer size for operands.
private enum ADBG_MAX_OPERANDS = 4;

/// Don't tell anyone.
// Acts as a "bool" to see if things are setup.
version (X86)
	private enum ADBG_COOKIE = 0xccccc0fe;
else version (X86_64)
	private enum ADBG_COOKIE = 0xccccc0fe;	/// Ditto

/// Disassembler ABI
enum AdbgPlatform : ubyte {
	native,	/// (Default) Platform compiled target, see DEFAULT_PLATFORM
	x86_16,	/// (WIP) 8086, 80186, 80286
	x86_32,	/// (WIP) 80386/i386, not to be confused with x32
	x86_64,	/// (WIP) AMD64, EM64T/Intel64, x64
	arm_t32,	/// (TODO) ARM T32 (thumb)
	arm_a32,	/// (TODO) ARM A32 (arm)
	arm_a64,	/// (TODO) ARM A64 (aarch64)
	riscv32,	/// (WIP) RISC-V 32-bit
	riscv64,	/// (TODO) RISC-V 64-bit
}

/// Disassembler options
enum AdbgDisasmOpt {
	/// Set the operating mode.
	mode,
	/// Set new target platform.
	platform,
	/// Set the mnemonic syntax.
	syntax,
	///TODO: If set, go backward instead of forward in memory.
	backward,
	///TODO: Add commentary
	commentary,
	/// Input mode. See $(SEE AdbgDisasmInput).
	input,
	/// Instead of a space, insert a tab between between the instruction
	/// mnemonic and operands.
	mnemonicTab
}

/// Disassembler operating mode
enum AdbgDisasmMode : ubyte {
	size,	/// Only calculate operation code sizes
	data,	/// Opcode sizes with jump locations (e.g. JMP, CALL)
	file,	/// Machine code and instruction mnemonics formatting
	full	/// (TODO) Analysis
}

/// Assembler syntax
enum AdbgSyntax : ubyte {
	/// Platform compiled default for target.
	platform,
	/// Intel syntax
	/// Year: 1978
	/// Destination: Left
	///
	/// Similar to the Microsoft/Macro Assembler (MASM) syntax.
	/// This is the reference syntax for the x86 instruction set.
	/// For more information, consult the Intel and AMD reference manuals.
	///
	/// Example:
	/// ---
	/// mov edx, dword ptr ss:[eax+ecx*2-0x20]
	/// ---
	intel,
	/// AT&T syntax
	/// Year: 1975
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
	/// Netwide Assembler syntax (NASM)
	/// Year: 1996
	/// Destination: Left
	///
	/// This is a popular alternative syntax for the x86 instruction set.
	/// For more information, consult The Netwide Assembler manual.
	///
	/// Example:
	/// ---
	/// mov edx, dword ptr [ss:eax+ecx*2-0x20]
	/// ---
	nasm,
	///TODO: Borland Turbo Assembler Ideal syntax
	/// Year: 1989
	/// Destination: Left
	///
	/// Also known as the TASM enhanced mode.
	/// For more information, consult the Borland Turbo Assembler Reference Guide.
	///
	/// Example:
	/// ---
	/// mov ecx, [dword ss:eax+ecx*2-0x20]
	/// ---
//	ideal,
	/// TODO: Randall Hyde High Level Assembly Language syntax
	/// Year: 2008
	/// Destination: Right
	///
	/// Created by Randy Hyde, this syntax is based on the PL/360 mnemonics.
	/// For more information, consult the HLA Reference Manual.
	///
	/// Example:
	/// ---
	/// mov( [type dword ss:eax+ecx*2-0x20], ecx )
	/// ---
//	hyde,
	///TODO: ARM native syntax.
	/// Destination: Left
	///
	/// Example:
	/// ---
	/// ldr r0, [r1]
	/// ---
//	arm,
	///TODO: RISC-V native syntax.
	/// Destination: Left
	///
	/// Example:
	/// ---
	/// lw x13, 0(x13)
	/// ---
//	riscv,
}

/// Disassembler warnings
//TODO: Only define warnings that are useful
enum AdbgDisasmWarning {
	/// Far jump, call, or return.
	farAddr	= BIT!(0),
	/// Loads a segment register.
	segment	= BIT!(1),
	/// Privileged instruction.
	privileged	= BIT!(2),
	/// I/O instruction.
	io	= BIT!(3),
}

/// Disassembler input
// NOTE: Uh, and why/how I'll do File/MmFile implementations?
//       There is no point to these two... Unless proven otherwise.
enum AdbgDisasmInput {
	raw,	/// Buffer
	debugger,	/// Debuggee
	file,	///TODO: File
	mmfile,	///TODO: MmFile
}

version (X86) {
	/// Platform default platform
	private enum DEFAULT_PLATFORM = AdbgPlatform.x86;
	/// Platform default syntax
	private enum DEFAULT_SYNTAX = AdbgSyntax.intel;
} else version (X86_64) {
	/// Platform default platform
	private enum DEFAULT_PLATFORM = AdbgPlatform.x86_64;
	/// Platform default syntax
	private enum DEFAULT_SYNTAX = AdbgSyntax.intel;
} else version (Thumb) {
	/// Platform default platform
	private enum DEFAULT_PLATFORM = AdbgPlatform.arm_t32;
	/// Platform default syntax
	private enum DEFAULT_SYNTAX = AdbgSyntax.att;	//TODO: ARM syntax
} else version (ARM) {
	/// Platform default platform
	private enum DEFAULT_PLATFORM = AdbgPlatform.arm_a32;
	/// Platform default syntax
	private enum DEFAULT_SYNTAX = AdbgSyntax.att;	//TODO: ARM syntax
} else version (AArch64) {
	/// Platform default platform
	private enum DEFAULT_PLATFORM = AdbgPlatform.arm_a64;
	/// Platform default syntax
	private enum DEFAULT_SYNTAX = AdbgSyntax.att;	//TODO: ARM syntax
} else version (RISCV32) {
	/// Platform default platform
	private enum DEFAULT_PLATFORM = AdbgPlatform.rv32;
	/// Platform default syntax
	private enum DEFAULT_SYNTAX = AdbgSyntax.att;	//TODO: RISC-V syntax
} else version (RISCV64) {
	/// Platform default platform
	private enum DEFAULT_PLATFORM = AdbgPlatform.rv64;
	/// Platform default syntax
	private enum DEFAULT_SYNTAX = AdbgSyntax.att;	//TODO: RISC-V syntax
} else {
	static assert(0, "Set default disassembler variables");
}

/// The basis of an operation code
struct adbg_disasm_opcode_t {
	int size;	/// Opcode size
	const(char) *mnemonic;	/// 
	const(char) *segment;	/// 
	size_t operandCount;	/// 
	adbg_disasm_operand_t[ADBG_MAX_OPERANDS] operands;	/// 
	size_t prefixCount;	/// 
	const(char)*[ADBG_MAX_PREFIXES] prefixes;	/// 
	//TODO: call/jump target
}

/// Represents a formatted instruction
// TODO: ubyte[8] for machine byte groups?
struct adbg_disasm_instruction_t {
	const(char) *machine;	/// Instruction machine code
	const(char) *mnemonic;	/// Instruction mnemonic
	int warnings;	/// Warning flags
	int size;	/// Instruction size
}

/// Disassembler parameters structure. This structure is not meant to be
/// accessed directly.
struct adbg_disasm_t { align(1):
	//
	// Generic
	//
	
	adbg_address_t current;	/// Current address, used as a program counter.
	adbg_address_t base;	/// Base address, used for target calculations.
	adbg_address_t last;	/// Last address, saved from input.
	
	/// Decoder function
	int function(adbg_disasm_t*) decode;
	/// Syntax operand handler function
	bool function(adbg_disasm_t*, ref adbg_string_t, ref adbg_disasm_operand_t) handle;
	union {
		void *internal;	/// Pointer for internal decoders
		x86_internals_t *x86;	/// Ditto
		riscv_internals_t *rv;	/// Ditto
	}
	/// Opcode information
	adbg_disasm_opcode_t *opcode;
	/// Internal cookie. Yummy!
	uint cookie;
	
	//
	// Options
	//
	
	/// Disassembling Platform.
	///
	/// Instruction set architecture platform to disassemble from. See the
	/// AdbgDisasmPlatform enumeration for more details.
	AdbgPlatform platform;
	/// Operation mode.
	///
	/// Disassembler operating mode. See the AdbgDisasmMode enumeration for
	/// more details.
	AdbgDisasmMode mode;
	/// User data length that can be processed. If disassembling a debuggee,
	/// this field is not taken into account.
	size_t left;
	
	/// Input mode.
	AdbgDisasmInput input;
	
	/// Decoder formatting options.
	adbg_disasm_decoder_options_t decoderOpts;
	/// User formatting options.
	adbg_disasm_user_options_t userOpts;
	/// Current syntax option.
	AdbgSyntax syntax;
}

// alloc
adbg_disasm_t *adbg_disasm_new(AdbgPlatform m) {
	import core.stdc.stdlib : calloc;
	
	adbg_disasm_t *s = cast(adbg_disasm_t *)calloc(1, adbg_disasm_t.sizeof);
	if (s == null) {
		adbg_oops(AdbgError.allocationFailed);
		return null;
	}
	
	if (adbg_disasm_configure(s, m)) {
		free(s);
		return null;
	}
	
	return s;
}

// configure
int adbg_disasm_configure(adbg_disasm_t *p, AdbgPlatform m) {
	with (AdbgPlatform)
	switch (m) {
	case native: goto case DEFAULT_PLATFORM;
	case x86_16, x86_32, x86_64:
		p.decode = &adbg_disasm_x86;
		break;
	case riscv32:
		p.decode = &adbg_disasm_riscv;
		break;
	default:
		return adbg_oops(AdbgError.unsupportedPlatform);
	}
	
	static if (DEFAULT_SYNTAX == AdbgSyntax.intel) {
		p.handle = &adbg_disasm_operand_intel;
	} else {
		p.handle = &adbg_disasm_operand_att;
	}
	
	p.platform = m;
	p.cookie = ADBG_COOKIE;
	return 0;
}

// start: raw buffer
int adbg_disasm_start_buffer(adbg_disasm_t *p, AdbgDisasmMode mode, void *buffer, size_t size) {
	if (p == null)
		return adbg_oops(AdbgError.nullArgument);
	
	p.input = AdbgDisasmInput.raw;
	p.mode = mode;
	p.current.raw = p.base.raw = buffer;
	p.left = size;
	return 0;
}

// start: debuggee
//TODO: Consider adding base parameter
int adbg_disasm_start_debuggee(adbg_disasm_t *p, AdbgDisasmMode mode, size_t addr) {
	if (p == null)
		return adbg_oops(AdbgError.nullArgument);
	
	p.input = AdbgDisasmInput.debugger;
	p.mode = mode;
	p.current.sz = p.base.sz = addr;
	return 0;
}

// set option
int adbg_disasm_opt(adbg_disasm_t *p, AdbgDisasmOpt opt, int val) {
	if (p == null)
		return adbg_oops(AdbgError.nullArgument);
	
	with (AdbgDisasmOpt)
	switch (opt) {
	case mode:
		if (val >= AdbgDisasmMode.max)
			return adbg_oops(AdbgError.invalidOptionValue);
		p.mode = cast(AdbgDisasmMode)val;
		break;
	case platform:
		if (val >= AdbgPlatform.max)
			return adbg_oops(AdbgError.invalidOptionValue);
		p.platform = cast(AdbgPlatform)val;
		break;
	case input:
		if (val >= AdbgDisasmInput.max)
			return adbg_oops(AdbgError.invalidOptionValue);
		p.input = cast(AdbgDisasmInput)val;
		break;
	case syntax:
		p.syntax = cast(AdbgSyntax)val;
		with (AdbgSyntax)
		switch (p.syntax) {
		case intel: p.handle = &adbg_disasm_operand_intel; break;
		case nasm:  p.handle = &adbg_disasm_operand_nasm; break;
		case att:   p.handle = &adbg_disasm_operand_att; break;
		default:    return adbg_oops(AdbgError.invalidOptionValue);
		}
		break;
	case mnemonicTab:
		p.userOpts.mnemonicTab = val != 0;
		break;
	default:
		return adbg_oops(AdbgError.invalidOption);
	}
	
	return 0;
}

/// Populate machine mnemonic and machine code buffers.
///
/// Disassemble one instruction from a buffer pointer given in adbg_disasm_t.
/// Caller must ensure memory pointer points to readable regions and givens
/// bounds are respected. The error field is always set.
///
/// Params: p = Disassembler structure
/// Returns: Error code; Non-zero indicating an error
int adbg_disasm(adbg_disasm_t *p, adbg_disasm_opcode_t *op) {
	if (p == null || op == null)
		return adbg_oops(AdbgError.nullArgument);
	if (p.cookie != ADBG_COOKIE)
		return adbg_oops(AdbgError.uninitiated);
	
	p.opcode = op;
	
	// Reset opcode info
	if (p.mode >= AdbgDisasmMode.file) {
		with (op) {
			mnemonic = segment = null;
			prefixCount = operandCount = 0;
		}
	}
	
	p.last = p.current;	// Save address
	int e = p.decode(p);	// Decode
	op.size = cast(int)(p.current.sz - p.last.sz);	// opcode size
	
	return e;
}

void adbg_disasm_render(adbg_disasm_t *p, char *buffer, size_t size) {
	adbg_string_t s = adbg_string_t(buffer, size);
	adbg_disasm_opcode_t *op = p.opcode;
	
	// Prefixes, skipped if empty or decoder says not to include them
	if (p.decoderOpts.noPrefixes == false && op.prefixCount) {
		for (size_t i; i < op.prefixCount; ++i) {
			if (s.add(op.prefixes[i]))
				return;
			if (s.add(' '))
				return;
		}
	}
	
	// Mnemonic
	if (s.add(op.mnemonic))
		return;
	
	// Operands, skipped if empty
	if (op.operandCount == 0) return;
	
	if (s.add(p.userOpts.mnemonicTab ? '\t' : ' '))
		return;
	
	with (AdbgSyntax)
	switch (p.syntax) {
	case intel, nasm:
		--op.operandCount;
		for (size_t i; i <= op.operandCount; ++i) {
			if (p.handle(p, s, op.operands[i]))
				return;
			if (i < op.operandCount)
				if (s.add(','))
					return;
		}
		return;
	default:
		for (size_t i = op.operandCount - 1; i; --i) {
			if (p.handle(p, s, op.operands[i]))
				return;
			if (i > 1)
				if (s.add(','))
					return;
		}
		return;
	}
}

private import core.stdc.stdlib : free;
/// Frees a previously allocated disassembly structure.
public  alias adbg_disasm_delete = free;

//
// SECTION Decoder stuff
//

/// Memory width
package
enum AdbgDisasmWidth : ubyte {
	i8, i16, i32, i64, i128, i256, i512, i1024
}

/// Main operand types.
package
enum AdbgDisasmOperand : ubyte {
	immediate,	/// 
	register,	/// 
	memory,	/// 
}

/// Immediate operand
package
struct adbg_disasm_operand_imm_t {
	int value;
	ushort segment;
}

/// Register operand
package
struct adbg_disasm_operand_reg_t {
	const(char) *name;
}

/// Memory operand
package
struct adbg_disasm_operand_mem_t {
	const(char) *base;	/// Used for normal usage, otherwise SIB:BASE
	const(char) *index;	/// SIB:INDEX
	int disp;	/// Offset or SIB:OFFSET
	ubyte scale;	/// SIB:SCALE
	AdbgDisasmWidth width;	/// Memory operation width
	AdbgDisasmWidth size;	/// Offset size
	bool scaled;	/// SIB or any scaling mode
}

/// Operand structure
package
struct adbg_disasm_operand_t { align(1):
	AdbgDisasmOperand type;	/// Operand type
	union {
		adbg_disasm_operand_imm_t imm;	/// Immediate item
		adbg_disasm_operand_reg_t reg;	/// Register item
		adbg_disasm_operand_mem_t mem;	/// Memory operand item
	}
}

private
struct adbg_disasm_decoder_options_t { align(1):
	union {
		uint all;	/// Unset when initiated
		struct {
			/// Skip prefixes when rendering.
			///
			/// Under x86, some prefixes like LOCK can sometimes be
			/// printed, or not, depending on the instruction.
			/// If set, the prefixes are not included in the output.
			bool noPrefixes;
			/// (AT&T syntax) Msnemonic is basic for width modifier.
			bool primitive;
			/// (AT&T syntax) Instruction is a far (absolute) call/jump.
			bool absolute;
		}
	}
}

private
struct adbg_disasm_user_options_t { align(1):
	union {
		//TODO: Consider "addresses as decimal" option
		//TODO: Consider "immediates as decimal" option
		uint all;	/// Unset when initiated
		struct {
			/// If set, inserts a tab instead of a space between
			/// mnemonic and operands.
			bool mnemonicTab;
			/// Opcodes and operands are not seperated by spaces.
			bool machinePacked;
		}
	}
}

/// (Internal) Fetch data from data source.
/// Params:
/// 	p = Disassembler structure pointer
/// 	u = Data pointer
/// Returns: Non-zero on error
package
int adbg_disasm_fetch(T)(adbg_disasm_t *p, T *u) {
	int e = void;
	with (AdbgDisasmInput)
	switch (p.input) {
	case debugger:
		import adbg.dbg.debugger : adbg_mm_cread;
		e = adbg_mm_cread(p.current.sz, u, T.sizeof);
		break;
	case raw:
		if (p.left < T.sizeof)
			return adbg_oops(AdbgError.outOfData);
		*u = *cast(T*)p.current;
		p.left -= T.sizeof;
		e = 0;
		break;
	default: assert(0);
	}
	p.current.sz += T.sizeof;
	return e;
}

// calculate near offset
package
void adbg_disasm_calc_offset(T)(adbg_disasm_t *p, T u) {
	//TODO: adbg_disasm_offset
}

//
// ANCHOR Prefixes
//

// add prefix in prefix buffer
package
void adbg_disasm_add_prefix(adbg_disasm_t *p, const(char) *prefix) {
	if (p.opcode.prefixCount >= ADBG_MAX_PREFIXES)
		return;
	
	p.opcode.prefixes[p.opcode.prefixCount++] = prefix;
}

//
// ANCHOR Mnemonic instruction
//

// set instruction mnemonic
package
void adbg_disasm_add_mnemonic(adbg_disasm_t *p, const(char) *instruction) {
	p.opcode.mnemonic = instruction;
}

//
// ANCHOR Segment register
//

// set segment register
package
void adbg_disasm_add_segment(adbg_disasm_t *p, const(char) *segment) {
	p.opcode.segment = segment;
}

//
// ANCHOR Operand operations
//

// immediate operand type

private
adbg_disasm_operand_t* adbg_disasm_item_operand(adbg_disasm_t *p) {
	return cast(adbg_disasm_operand_t*)&p.opcode.operands[p.opcode.operandCount++];
}

package
void adbg_disasm_add_immediate(adbg_disasm_t *p, uint v) {
	if (p.opcode.operandCount >= ADBG_MAX_OPERANDS)
		return;
	
	adbg_disasm_operand_t *item = adbg_disasm_item_operand(p);
	item.type = AdbgDisasmOperand.immediate;
	item.imm.value = v;
}

// register operand type

package
void adbg_disasm_add_register(adbg_disasm_t *p, const(char) *register) {
	if (p.opcode.operandCount >= ADBG_MAX_OPERANDS)
		return;
	
	adbg_disasm_operand_t *item = adbg_disasm_item_operand(p);
	item.type = AdbgDisasmOperand.register;
	item.reg.name = register;
}

// memory operand type

package
void adbg_disasm_add_memory(adbg_disasm_t *p,
	const(char) *regbase,
	const(char) *regindex,
	int disp,
	//TODO: ushort segment
	AdbgDisasmWidth width,
	ubyte scale,
	bool scaled) {
	if (p.opcode.operandCount >= ADBG_MAX_OPERANDS)
		return;
	
	adbg_disasm_operand_t *item = adbg_disasm_item_operand(p);
	item.type = AdbgDisasmOperand.memory;
	item.mem.width	= width;
	item.mem.base	= regbase;
	item.mem.index	= regindex;
	item.mem.disp	= disp;
	item.mem.scale	= scale;
	item.mem.scaled	= scaled;
}
