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
	adbg.disasm.syntax.att,
	adbg.disasm.syntax.ideal,
	adbg.disasm.syntax.hyde;

//TODO: Invalid results could be rendered differently
//      e.g., .byte 0xd6,0xd6 instead of (bad)
//      Option 1. Add lasterror in adbg_disasm_t
//TODO: enum AdbgDisasmEndian : ubyte { native, little, big }
//      adbg_disasm_t: AdbgDisasmEndian endian;
//      Configured when _configure is called, used for fetching
//TODO: Flow-oriented analysis to mitigate anti-dissassembly techniques
//      Obviously with a setting (what should be the default?)
//      Save jmp/call targets
//TODO: Visibility system for prefixes
//      Tag system? e.g., groups (ubyte + bitflag)
//TODO: Move float80 (x87) register handling here
//      adbg_disasm_add_register: Add register width? index parameter?
//TODO: Consider doing subcodes (extended codes) to specify why instruction is illegal
//      e.g., empty buffer, invalid opcode, invalid modrm:reg, lock disallowed, etc.
//      Option 1. adbg_disasm_oops(adbg_disasm_t*,AdbgDisasmError);
//                Should set value in struct, and that gets returned.
//      Option 2. adbg_oops(AdbgError,AdbgExtendedError);
//      Option 3. Or simply extend the current codes
//TODO: HLA: Consider adding option for alternative SIB syntax
//      [ebx+2]       -> [ebx][2]
//      [ebx+ecx*4+8] -> [ebx][ecx][8]
//      label[ebp-2]  -> label[ebp][-2]
//TODO: Consider adding syntax options (3[RDI], .rodata[00h][RIP])

extern (C):

package immutable const(char) *UNKNOWN_TYPE = "word?";

private enum {
	ADBG_MAX_PREFIXES = 8,	/// Buffer size for prefixes.
	ADBG_MAX_OPERANDS = 4,	/// Buffer size for operands.
	ADBG_MAX_MACHINE  = 16,	/// Buffer size for machine groups.
	ADBG_COOKIE	= 0xcc00ffee,	/// Don't tell anyone.
	ADBG_X86_MAX	= 15,	/// Inclusive maximum instruction size for x86.
	ADBG_RV32_MAX	= 4,	/// Inclusive maximum instruction size for RV32I.
	ADBG_RV64_MAX	= 8,	/// Inclusive maximum instruction size for RV64I.
}

/// Disassembler platform
enum AdbgPlatform : ubyte {
	native,	/// Platform compiled target (Default)
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
	/// Set the mnemonic syntax.
	syntax,
	///TODO: If set, go backward instead of forward in memory.
	backward,
	///TODO: Add commentary
	commentary,
	/// Instead of a space, insert a tab between between the instruction
	/// mnemonic and operands.
	mnemonicTab,
	/// 
	hexFormat
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
	/// Native compiled target default. (Default)
	/// x86: Intel
	/// riscv: AT&T (for the moment being)
	platform,
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
	/// Borland Turbo Assembler Ideal syntax
	/// Year: 1989
	/// Destination: Left
	///
	/// Also known as the TASM enhanced mode.
	/// For more information, consult the Borland Turbo Assembler Reference Guide.
	///
	/// Example:
	/// ---
	/// mov edx, [dword ss:eax+ecx*2-0x20]
	/// ---
	ideal,
	/// High Level Assembly Language syntax
	/// Year: 1999
	/// Destination: Right
	///
	/// Created by Randall Hyde, this syntax is based on the PL/360 mnemonics.
	/// For more information, consult the HLA Reference Manual.
	///
	/// Example:
	/// ---
	/// sseg: mov ([type dword eax+ecx*2-0x20], edx)
	/// ---
	hyde,
	///TODO: ARM native syntax.
	/// Year: 1985
	/// Destination: Left
	///
	/// Example:
	/// ---
	/// ldr r0, [r1]
	/// ---
//	arm,
	///TODO: RISC-V native syntax.
	/// Year: 2010
	/// Destination: Left
	///
	/// Example:
	/// ---
	/// lw x13, 0(x13)
	/// ---
//	riscv,
}

/// Disassembler input
// NOTE: Uh, and why/how I'll do File/MmFile implementations?
//       There is no point to these two... Unless proven otherwise.
//       Raw: Dumper could go by chunks of 32 bytes, smartly
enum AdbgDisasmInput : ubyte {
	raw,	/// Buffer
	debugger,	/// Debuggee
//	file,	///TODO: File
//	mmfile,	///TODO: MmFile
}

/// Machine bytes tag
enum AdbgDisasmTag : ushort {
	unknown,	/// Unknown, either now or forever
	opcode,	/// Operation code
	prefix,	/// Instruction prefix
	operand,	/// Instruction operand
	immediate,	/// 
	disp,	/// Displacement/Offset
	modrm,	/// x86: ModR/M byte
	sib,	/// x86: SIB byte
}

enum AdbgDisasmNumberType : ubyte {
	decimal,	/// 
	hexadecimal,	/// 
}
enum AdbgDisasmHexStyle : ubyte {
	defaultPrefix,	/// 0x0010, default
	hSuffix,	/// 0010h
	hPrefix,	/// 0h0010
	numberSignPrefix,	/// #0010
	pourcentPrefix,	/// %0010
	dollarPrefix,	/// $0010
}

version (X86) {
	private enum {
		DEFAULT_PLATFORM = AdbgPlatform.x86_32,	/// Platform default platform
		DEFAULT_SYNTAX = AdbgSyntax.intel,	/// Platform default syntax
	}
} else version (X86_64) {
	private enum {
		DEFAULT_PLATFORM = AdbgPlatform.x86_64,	/// Ditto
		DEFAULT_SYNTAX = AdbgSyntax.intel,	/// Ditto
	}
} else version (Thumb) {
	private enum {
		DEFAULT_PLATFORM = AdbgPlatform.arm_t32,	/// Ditto
		DEFAULT_SYNTAX = AdbgSyntax.att,	/// Ditto
	}
} else version (ARM) {
	private enum {
		DEFAULT_PLATFORM = AdbgPlatform.arm_a32,	/// Ditto
		DEFAULT_SYNTAX = AdbgSyntax.att,	/// Ditto
	}
} else version (AArch64) {
	private enum {
		DEFAULT_PLATFORM = AdbgPlatform.arm_a64,	/// Ditto
		DEFAULT_SYNTAX = AdbgSyntax.att,	/// Ditto
	}
} else version (RISCV32) {
	private enum {
		DEFAULT_PLATFORM = AdbgPlatform.riscv32,	/// Ditto
		DEFAULT_SYNTAX = AdbgSyntax.att,	/// Ditto
	}
} else version (RISCV64) {
	private enum {
		DEFAULT_PLATFORM = AdbgPlatform.riscv64,	/// Ditto
		DEFAULT_SYNTAX = AdbgSyntax.att,	/// Ditto
	}
} else {
	static assert(0, "Set default disassembler variables");
}

struct adbg_disasm_number_t {
	union {
		ulong  u64; long  i64;
		uint   u32; int   i32;
		ushort u16; short i16;
		ubyte  u8;  byte  i8;
		double f64; float f32;
	}
	AdbgDisasmType type;
	/*AdbgDisasmNumberStyle ;
	union {
		bool signed;
		AdbgDisasmNumType? type;
	}*/
}

struct adbg_disasm_machine_t {
	union {
		ulong  u64; long  i64;
		uint   u32; int   i32;
		ushort u16; short i16;
		ubyte  u8;  byte  i8;
		double f64; float f32;
	}
	AdbgDisasmType type;
	AdbgDisasmTag tag;
}

/// The basis of an operation code
struct adbg_disasm_opcode_t {
	// size mode:
	int size;	/// Opcode size
	// data mode:
//	enum targetMode target;	/// none, near, far
//	ulong targetAddress;	/// CALL/JMP absolute target
//	union targetOffset;	/// CALL/JMP relative target
	// file mode:
	const(char) *segment;	/// Segment register string
	const(char) *mnemonic;	/// Instruction mnemonic
	size_t operandCount;	/// Number of operands
	adbg_disasm_operand_t[ADBG_MAX_OPERANDS] operands;	/// Operands
	size_t prefixCount;	/// Number of prefixes
	const(char)*[ADBG_MAX_PREFIXES] prefixes;	/// Prefixes
	size_t machineCount;	/// Number of disassembler fetches
	adbg_disasm_machine_t[ADBG_MAX_MACHINE] machine;	/// Machine bytes
}

/// Disassembler parameters structure. This structure is not meant to be
/// accessed directly.
struct adbg_disasm_t { align(1):
	adbg_address_t current;	/// Current address, used as a program counter.
	adbg_address_t base;	/// Base address, used for target calculations.
	adbg_address_t last;	/// Last address, saved from input.
	/// Decoder function
	int function(adbg_disasm_t*) fdecode;
	/// Syntax operand handler function
	//TODO: Move in _mnemonic one specific syntax float80 situation is fixed
	bool function(adbg_disasm_t*, ref adbg_string_t, ref adbg_disasm_operand_t) foperand;
	union {
		void *internal;	/// Pointer for internal decoders
		x86_internals_t *x86;	/// Ditto
		riscv_internals_t *rv;	/// Ditto
	}
	/// Internal cookie. Yummy!
	uint cookie;
	/// Instruction set architecture platform to disassemble from.
	AdbgPlatform platform;
	/// Current syntax option.
	AdbgSyntax syntax;
	/// Operating mode.
	AdbgDisasmMode mode;
	/// Input mode.
	AdbgDisasmInput input;
	/// Opcode information
	adbg_disasm_opcode_t *opcode;
	/// Memory operation width
	AdbgDisasmType memWidth;
	/// Buffer: When "start buffer" is used, this dictates how much data is left.
	/// If disassembling a debuggee, this field is not taken into account.
	size_t left;
	/// Maximum opcode length. (Architectural limit, inclusive)
	/// x86: >15 illegal
	/// riscv32: >4 illegal
	/// riscv64: >8 illegal
	int max;
	package union { // Decoder options
		uint decoderAll;
		struct {
			ubyte pfGroups;	///TODO: Prefixes to show/hide, upto 8 groups
			bool indistinguishable;	///TODO: ATT: Ambiguate instruction
			bool reverse;	///TODO: ATT: Reverse order
		}
	}
	package union { // User options
		uint userAll;
		struct {
			/// If set, inserts a tab instead of a space between
			/// mnemonic and operands.
			bool mnemonicTab;
			///TODO: Opcodes and operands are not seperated by spaces.
			bool machinePacked;
		}
	}
}

// alloc
adbg_disasm_t *adbg_disasm_new(AdbgPlatform m) {
	import core.stdc.stdlib : calloc;
	
	version (Trace) trace("platform=%u", m);
	
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
	version (Trace) trace("platform=%u", m);
	
	with (AdbgPlatform)
	switch (m) {
	case native:
		m = DEFAULT_PLATFORM;
		goto case DEFAULT_PLATFORM;
	case x86_16, x86_32, x86_64:
		p.max = ADBG_X86_MAX;
		p.fdecode = &adbg_disasm_x86;
		break;
	case riscv32:
		p.max = ADBG_RV32_MAX;
		p.fdecode = &adbg_disasm_riscv;
		break;
	/*case riscv64:
		p.max = ADBG_RV64_MAX;
		p.fdecode = &adbg_disasm_riscv;
		break;*/
	default:
		return adbg_oops(AdbgError.unsupportedPlatform);
	}
	
	static if (DEFAULT_SYNTAX == AdbgSyntax.intel) {
		p.syntax = AdbgSyntax.intel;
		p.foperand = &adbg_disasm_operand_intel;
	} else {
		p.syntax = AdbgSyntax.att;
		p.foperand = &adbg_disasm_operand_att;
	}
	
	p.platform = m;
	p.cookie = ADBG_COOKIE;
	return 0;
}

// set option
int adbg_disasm_opt(adbg_disasm_t *p, AdbgDisasmOpt opt, int val) {
	if (p == null)
		return adbg_oops(AdbgError.nullArgument);
	
	version (Trace) trace("opt=%u val=%d", opt, val);
	
	with (AdbgDisasmOpt)
	switch (opt) {
	case syntax:
		p.syntax = cast(AdbgSyntax)val;
		switch (p.syntax) with (AdbgSyntax) {
		case intel: p.foperand = &adbg_disasm_operand_intel; break;
		case nasm:  p.foperand = &adbg_disasm_operand_nasm; break;
		case att:   p.foperand = &adbg_disasm_operand_att; break;
		case ideal: p.foperand = &adbg_disasm_operand_ideal; break;
		case hyde:  p.foperand = &adbg_disasm_operand_hyde; break;
		default:    return adbg_oops(AdbgError.invalidOptionValue);
		}
		break;
	case mnemonicTab:
		p.mnemonicTab = val != 0;
		break;
	default:
		return adbg_oops(AdbgError.invalidOption);
	}
	
	return 0;
}

/// Start a disassembler region using a buffer.
/// Params:
/// 	p = Disassembler structure.
/// 	mode = Disassembly mode.
/// 	buffer = Buffer pointer.
/// 	size = Buffer size.
/// Returns: Error code
int adbg_disasm_start_buffer(adbg_disasm_t *p, AdbgDisasmMode mode, void *buffer, size_t size) {
	if (p == null)
		return adbg_oops(AdbgError.nullArgument);
	
	p.input = AdbgDisasmInput.raw;
	p.mode = mode;
	p.current.raw = p.base.raw = buffer;
	p.left = size;
	return 0;
}

//TODO: Consider adding base parameter
/// Start a disassembler region at the debuggee's location.
/// Params:
/// 	p = Disassembler structure.
/// 	mode = Disassembly mode.
/// 	addr = Debuggee address.
/// Returns: Error code
int adbg_disasm_start_debuggee(adbg_disasm_t *p, AdbgDisasmMode mode, size_t addr) {
	if (p == null)
		return adbg_oops(AdbgError.nullArgument);
	
	p.input = AdbgDisasmInput.debugger;
	p.mode = mode;
	p.current.sz = p.base.sz = addr;
	return 0;
}

int adbg_disasm_once_buffer(adbg_disasm_t *p, adbg_disasm_opcode_t *op, AdbgDisasmMode mode, void *buffer, size_t size) {
	int e = adbg_disasm_start_buffer(p, mode, buffer, size);
	if (e) return e;
	return adbg_disasm(p, op);
}

int adbg_disasm_once_debuggee(adbg_disasm_t *p, adbg_disasm_opcode_t *op, AdbgDisasmMode mode, size_t addr) {
	int e = adbg_disasm_start_debuggee(p, mode, addr);
	if (e) return e;
	return adbg_disasm(p, op);
}

/// Disassemble one instruction.
///
/// This calls the corresponding decoder configured before calling this
/// function. The decoder will, whenever possible, populate the opcode
/// structure.
///
/// Params:
/// 	p = Disassembler structure.
/// 	op = Opcode information structure.
/// Returns: Non-zero indicates an error has occured.
int adbg_disasm(adbg_disasm_t *p, adbg_disasm_opcode_t *op) {
	if (p == null || op == null)
		return adbg_oops(AdbgError.nullArgument);
	if (p.cookie != ADBG_COOKIE)
		return adbg_oops(AdbgError.uninitiated);
	
	with (op) { // reset opcode
		mnemonic = segment = null;
		size = machineCount = prefixCount = operandCount = 0;
	}
	with (p) { // reset disasm
		decoderAll = 0;
	}
	
	p.opcode = op;
	p.last = p.current;	// Save address
	return p.fdecode(p);	// Decode
}

/// Renders the mnemonic instruction into a buffer.
/// Params:
/// 	p = Disassembler
/// 	buffer = Character buffer
/// 	size = Buffer size
/// 	op = Opcode information
void adbg_disasm_mnemonic(adbg_disasm_t *p, char *buffer, size_t size, adbg_disasm_opcode_t *op) {
	if (p.opcode.mnemonic == null)
		return;
	
	__gshared const(char) *sep = ", ";
	adbg_string_t s = adbg_string_t(buffer, size);
	
	bool isHyde = p.syntax == AdbgSyntax.hyde;
	
	if (isHyde) {
		//TODO: p.decoderOpts.noSegment
		if (p.opcode.segment) {
			if (s.addc(p.opcode.segment[0]))
				return;
			if (s.adds("seg: "))
				return;
		}
	}
	
	// Prefixes, skipped if empty
	version (Trace) trace("prefixCount=%u", op.prefixCount);
	if (op.prefixCount) {
		for (size_t i; i < op.prefixCount; ++i) {
			if (s.adds(op.prefixes[i]))
				return;
			if (s.addc(isHyde ? '.' : ' '))
				return;
		}
	}
	
	// Mnemonic
	version (Trace) trace("mnemonic=%s", op.mnemonic);
	if (s.adds(op.mnemonic))
		return;
	
	// Operands, skipped if empty
	version (Trace) trace("operandCount=%u", op.operandCount);
	if (op.operandCount == 0) return;
	if (s.addc(p.mnemonicTab ? '\t' : ' '))
		return;
	
	//TODO: Consider setting the operand handler function here.
	//      + Instead of taking space in the structure.
	//      + Would also help to move it out of the configuration function.
	//      + Syntax-related configuration here instead (direction, etc.).
	//      - Every call would have the syntax option.
	
	switch (p.syntax) with (AdbgSyntax) {
	case hyde:
		if (s.addc('('))
			return;
		goto case att;
	case att:
		for (size_t i = op.operandCount; i-- > 0;) {
			version (Trace) trace("i=%u", cast(uint)i);
			if (p.foperand(p, s, op.operands[i]))
				return;
			if (i)
				if (s.adds(sep))
					return;
		}
		if (isHyde)
			if (s.addc(')'))
				return;
		return;
	default:
		size_t opCount = op.operandCount - 1;
		for (size_t i; i <= opCount; ++i) {
			version (Trace) trace("i=%u", cast(uint)i);
			if (p.foperand(p, s, op.operands[i]))
				return;
			if (i < opCount)
				if (s.adds(sep))
					return;
		}
		return;
	}
}

/// Renders the machine opcode into a buffer.
/// Params:
/// 	p = Disassembler
/// 	buffer = Character buffer
/// 	size = Buffer size
/// 	op = Opcode information
void adbg_disasm_machine(adbg_disasm_t *p, char *buffer, size_t size, adbg_disasm_opcode_t *op) {
	import adbg.utils.str : empty_string;
	
	if (op.machineCount == 0) {
		buffer = empty_string;
		return;
	}
	
	adbg_string_t s = adbg_string_t(buffer, size);
	adbg_disasm_machine_t *num = &op.machine[0];
	
	//TODO: Unpack option would mean e.g., 4*1byte on i32
	size_t edge = op.machineCount - 1;
	for (size_t i; i < op.machineCount; ++i, ++num) {
		switch (num.type) with (AdbgDisasmType) {
		case i8:       s.addx8(num.i8, true); break;
		case i16:      s.addx16(num.i16, true); break;
		case i32, f32: s.addx32(num.i32, true); break;
		case i64, f64: s.addx64(num.i64, true); break;
		default:  assert(0);
		}
		if (i < edge) s.addc(' ');
	}
}

private import core.stdc.stdlib : free;
/// Frees a previously allocated disassembly structure.
public  alias adbg_disasm_delete = free;

//
// SECTION Decoder stuff
//

/// Memory type
//package
enum AdbgDisasmType : ubyte {
	i8,  i16, i32, i64,  i128, i256, i512, i1024,
	f16, f32, f64, f128,
	none = 0,
}

/// Main operand types.
//package
enum AdbgDisasmOperand : ubyte {
	immediate,	/// 
	register,	/// 
	memory,	/// 
}

//TODO: Display option for integer/byte/float operations
//      Smart: integer=decimal, bitwise=hex, fpu=float
//      A setting for each group (that will be a lot of groups...)
/// Immediate operand
//package
struct adbg_disasm_operand_imm_t {
	adbg_disasm_number_t value;
	ushort segment;
}

/// Register operand
//package
struct adbg_disasm_operand_reg_t {
	const(char) *name;
}

/// Memory operand
//package
struct adbg_disasm_operand_mem_t {
	const(char) *base;	/// Base register, (scaled) SIB:BASE
	const(char) *index;	/// Additional register, (scaled) SIB:INDEX
	ubyte scale;	/// SIB:SCALE
	bool hasOffset;	/// 
	adbg_disasm_number_t offset;	/// Displacement
	bool scaled;	/// SIB or any scaling mode
	//TODO: Call/jmp type (bool: near/far)
}

/// Operand structure
//package
struct adbg_disasm_operand_t { align(1):
	AdbgDisasmOperand type;	/// Operand type
	union {
		adbg_disasm_operand_imm_t imm;	/// Immediate item
		adbg_disasm_operand_reg_t reg;	/// Register item
		adbg_disasm_operand_mem_t mem;	/// Memory operand item
	}
}

/// (Internal) Fetch data from data source.
/// Params:
/// 	p = Disassembler structure pointer
/// 	u = Data pointer
/// 	tag = Byte tag
/// Returns: Non-zero on error
//TODO: Tag data with opcode/prefix/etc. you get the point
package
int adbg_disasm_fetch(T)(adbg_disasm_t *p, T *u, AdbgDisasmTag tag = AdbgDisasmTag.unknown) {
	if (p.opcode.size + T.sizeof > p.max)
		return adbg_oops(AdbgError.opcodeLimit);
	//TODO: Auto bswap if architecture endian is different than target
	int e = void;
	switch (p.input) with (AdbgDisasmInput) {
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
	p.opcode.size += T.sizeof;
	
	if (p.mode >= AdbgDisasmMode.file && p.opcode.machineCount < ADBG_MAX_MACHINE) {
		adbg_disasm_machine_t *n = &p.opcode.machine[p.opcode.machineCount++];
		n.tag = tag;
		static if (is(T == ubyte)) {
			n.i8 = *u;
			n.type = AdbgDisasmType.i8;
		} else static if (is(T == ushort)) {
			n.i16 = *u;
			n.type = AdbgDisasmType.i16;
		} else static if (is(T == uint)) {
			n.i32 = *u;
			n.type = AdbgDisasmType.i32;
		} else static if (is(T == ulong)) {
			n.i64 = *u;
			n.type = AdbgDisasmType.i64;
		} else static assert(0, "fetch support type");
	}
	return e;
}

// fix last tag
package
void adbg_disasm_fetch_tag(adbg_disasm_t *p, AdbgDisasmTag tag) {
	p.opcode.machine[p.opcode.machineCount - 1].tag = tag;
}

// calculate near offset
package
void adbg_disasm_calc_offset(T)(adbg_disasm_t *p, T u) {
	//TODO: adbg_disasm_offset
}

package
bool adbg_disasm_render_number(adbg_disasm_t *p,
	ref adbg_string_t s, ref adbg_disasm_number_t n, bool offset) {
	__gshared const(char) *prefix = "0x";
	
	switch (n.type) with (AdbgDisasmType) {
	case i8:
		if (offset) {
			if (s.addc(n.i8 < 0 ? '-' : '+'))
				return true;
		}
		if (s.adds(prefix)) // temp
			return true;
		if (s.addx8(n.i8))
			return true;
		break;
	case i16:
		if (offset) {
			if (s.addc(n.i16 < 0 ? '-' : '+'))
				return true;
		}
		if (s.adds(prefix)) // temp
			return true;
		if (s.addx16(n.i16))
			return true;
		break;
	case i32:
		if (offset) {
			if (s.addc(n.i32 < 0 ? '-' : '+'))
				return true;
		}
		if (s.adds(prefix)) // temp
			return true;
		if (s.addx32(n.i32))
			return true;
		break;
	case i64:
		if (offset) {
			if (s.addc(n.i64 < 0 ? '-' : '+'))
				return true;
		}
		if (s.adds(prefix)) // temp
			return true;
		if (s.addx32(n.i32))
			return true;
		break;
	default: assert(0);
	}
	
	return false;
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
	version (Trace) trace("mnemonic=%s", instruction);
	
	p.opcode.mnemonic = instruction;
}

//
// ANCHOR Segment register
//

// set segment register
package
void adbg_disasm_add_segment(adbg_disasm_t *p, const(char) *segment) {
	version (Trace) trace("segment=%s", segment);
	
	p.opcode.segment = segment;
}

//
// ANCHOR Operand operations
//

// immediate operand type

private
adbg_disasm_operand_t* adbg_disasm_get_operand(adbg_disasm_t *p) {
	return cast(adbg_disasm_operand_t*)&p.opcode.operands[p.opcode.operandCount++];
}

package
void adbg_disasm_add_immediate(adbg_disasm_t *p, AdbgDisasmType w, void *v) {
	if (p.opcode.operandCount >= ADBG_MAX_OPERANDS)
		return;
	
	version (Trace) trace("type=%u", w);
	
	adbg_disasm_operand_t *item = adbg_disasm_get_operand(p);
	item.type = AdbgDisasmOperand.immediate;
	item.imm.value.type = w;
	
	switch (w) with (AdbgDisasmType) {
	case i8:  item.imm.value.u8  = *cast(ubyte*)v;  return;
	case i16: item.imm.value.u16 = *cast(ushort*)v; return;
	case i32: item.imm.value.u32 = *cast(uint*)v;   return;
	case i64: item.imm.value.u64 = *cast(ulong*)v;  return;
	default: assert(0);
	}
}

// register operand type

package
void adbg_disasm_add_register(adbg_disasm_t *p, const(char) *register) {
	if (p.opcode.operandCount >= ADBG_MAX_OPERANDS)
		return;
	
	version (Trace) trace("register=%s", register);
	
	adbg_disasm_operand_t *item = adbg_disasm_get_operand(p);
	item.type     = AdbgDisasmOperand.register;
	item.reg.name = register;
}

// memory operand type

package
void adbg_disasm_add_memory(adbg_disasm_t *p,
	AdbgDisasmType width,
	const(char) *regbase,
	const(char) *regindex,
	AdbgDisasmType dispWidth,
	void *disp,
	//TODO: ushort segment
	//TODO: bool far
	ubyte scale,
	bool scaled) {
	if (p.opcode.operandCount >= ADBG_MAX_OPERANDS)
		return;
	
	version (Trace) trace("base=%s", regbase);
	
	p.memWidth      = width;
	adbg_disasm_operand_t *item = adbg_disasm_get_operand(p);
	item.type       = AdbgDisasmOperand.memory;
	item.mem.base	= regbase;
	item.mem.index	= regindex;
	item.mem.scale	= scale;
	item.mem.scaled	= scaled;
	item.mem.hasOffset = disp != null;
	
	if (disp) {
		item.mem.offset.type	= dispWidth;
		switch (dispWidth) with (AdbgDisasmType) {
		case i8:  item.mem.offset.u8  = *cast(ubyte*)disp;  return;
		case i16: item.mem.offset.u16 = *cast(ushort*)disp; return;
		case i32: item.mem.offset.u32 = *cast(uint*)disp;   return;
		case i64: item.mem.offset.u64 = *cast(ulong*)disp;  return;
		default: assert(0);
		}
	}
}

package
void adbg_disasm_add_memory_raw(adbg_disasm_t *p, AdbgDisasmType width, adbg_disasm_operand_mem_t *m) {
	if (p.opcode.operandCount >= ADBG_MAX_OPERANDS)
		return;
	
	version (Trace) trace("m=%p", m);
	
	p.memWidth = width;
	adbg_disasm_operand_t *item = adbg_disasm_get_operand(p);
	item.type  = AdbgDisasmOperand.memory;
	item.mem   = *m;
}