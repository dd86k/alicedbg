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

//TODO: Invalid results could be rendered differently
//      e.g., .byte 0xd6,0xd6 instead of (bad)
//      1. Check last error code from specifc disasm structure
//TODO: adbg_disasm_t: bool swap; (set on configuration target endian != isa)
//TODO: Flow-oriented analysis to mitigate anti-dissassembly techniques
//      Obviously with a setting (what should be the default?)
//      Save jmp/call targets
//TODO: Better prefix handling
//      With a visibility system
//TODO: Move float80 register handling here
//      This will permit adding Syntax paramter to mnemonic renderer
//TODO: Consider doing subcodes (extended codes) to specify why instruction is illegal
//      adbg_disasm_oops(adbg_disasm_t*,AdbgError,AdbgDisasmError);
//      Or extend current system
//        adbg_oops(AdbgError,AdbgExtendedError);

extern (C):

/// Buffer size for prefixes.
private enum ADBG_MAX_PREFIXES = 8;
/// Buffer size for operands.
private enum ADBG_MAX_OPERANDS = 4;
/// Buffer size for machine groups.
// x86 max: 15 bytes
private enum ADBG_MAX_MACHINE  = 16;

/// Don't tell anyone.
private enum ADBG_COOKIE = 0xc0fec0fe;

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
	/// mov ([type dword ss:eax+ecx*2-0x20], ecx)
	/// ---
//	hyde,
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
enum AdbgDisasmInput : ubyte {
	raw,	/// Buffer
	debugger,	/// Debuggee
	file,	///TODO: File
	mmfile,	///TODO: MmFile
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
	/// Platform default platform
	private enum DEFAULT_PLATFORM = AdbgPlatform.x86_32;
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
		AdbgDisasmHexStyle hexStyle;
	}*/
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
//	bool hasTarget;	/// 
//	adbg_address_t target;	/// CALL/JMP target
	size_t machineCount;	/// 
	adbg_disasm_number_t[ADBG_MAX_MACHINE] machine;	/// 
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
	int function(adbg_disasm_t*) fdecode;
	/// Syntax operand handler function
	bool function(adbg_disasm_t*, ref adbg_string_t, ref adbg_disasm_operand_t) foperand;
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
	/// User data length that can be processed from the buffer size provided.
	/// If disassembling a debuggee, this field is not taken into account.
	size_t left;
	/// Maximum opcode length. (Architectural limit, inclusive)
	/// x86: >=16 bytes is illegal
	int max;
	/// Input mode.
	AdbgDisasmInput input;
	/// Decoder formatting options.
	adbg_disasm_decoder_options_t decoderOpts;
	/// User formatting options.
	adbg_disasm_user_options_t userOpts;
	/// Current syntax option.
	AdbgSyntax syntax;
	/// Memory operation width
	//TODO: Move this to opcode structure, rename as opWidth
	//      Affected by memory and immediates
	AdbgDisasmType memWidth;
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
		p.max = 15;
		p.fdecode = &adbg_disasm_x86;
		break;
	case riscv32:
		p.max = 4;
		p.fdecode = &adbg_disasm_riscv;
		break;
	/*case riscv64:
		p.max = 8;
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
	
	version (Trace) trace("opt=%u val=%d", opt, val);
	
	with (AdbgDisasmOpt)
	switch (opt) {
	case syntax:
		p.syntax = cast(AdbgSyntax)val;
		with (AdbgSyntax)
		switch (p.syntax) {
		case intel: p.foperand = &adbg_disasm_operand_intel; break;
		case nasm:  p.foperand = &adbg_disasm_operand_nasm; break;
		case att:   p.foperand = &adbg_disasm_operand_att; break;
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
	
	// Reset opcode info
	with (op) {
		mnemonic = segment = null;
		size = machineCount = prefixCount = operandCount = 0;
	}
	
	p.opcode = op;
	p.last = p.current;	// Save address
	return p.fdecode(p);	// Decode
}

void adbg_disasm_mnemonic(adbg_disasm_t *p, char *buffer, size_t size, adbg_disasm_opcode_t *op) {
	__gshared const(char) *comma = ", ";
	adbg_string_t s = adbg_string_t(buffer, size);
	
	// Prefixes, skipped if empty or decoder says not to include them
	version (Trace) trace("prefixCount=%u", op.prefixCount);
	if (p.decoderOpts.noPrefixes == false && op.prefixCount) {
		for (size_t i; i < op.prefixCount; ++i) {
			if (s.adds(op.prefixes[i]))
				return;
			if (s.addc(' '))
				return;
		}
	}
	
	// Mnemonic
	version (Trace) trace("mnemonic=%u", op.mnemonic);
	if (s.adds(op.mnemonic))
		return;
	
	// Operands
	// Skipping operands if empty
	version (Trace) trace("operandCount=%u", op.operandCount);
	if (op.operandCount == 0) return;
	if (s.addc(p.userOpts.mnemonicTab ? '\t' : ' '))
		return;
	
	//TODO: Consider setting the operand handler function here.
	//      + Instead of taking space in the structure.
	//      + Would also help to move it out of the configuration function.
	//      + Syntax-related configuration here instead (direction, etc.).
	//      - Every call would have the syntax option.
	
	switch (p.syntax) with (AdbgSyntax) {
	case att:
		for (size_t i = op.operandCount; i-- > 0;) {
			version (Trace) trace("i=%u", cast(uint)i);
			if (p.foperand(p, s, op.operands[i]))
				return;
			if (i)
				if (s.adds(comma))
					return;
		}
		return;
	default:
		size_t opCount = op.operandCount - 1;
		for (size_t i; i <= opCount; ++i) {
			version (Trace) trace("i=%u", cast(uint)i);
			if (p.foperand(p, s, op.operands[i]))
				return;
			if (i < opCount)
				if (s.adds(comma))
					return;
		}
		return;
	}
}

void adbg_disasm_machine(adbg_disasm_t *p, char *buffer, size_t size, adbg_disasm_opcode_t *op) {
	import adbg.utils.str : empty_string;
	
	if (op.machineCount == 0) {
		buffer = empty_string;
		return;
	}
	
	adbg_string_t s = adbg_string_t(buffer, size);
	adbg_disasm_number_t *num = &op.machine[0];
	
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
package
enum AdbgDisasmType : ubyte {
	i8,  i16, i32, i64,  i128, i256, i512, i1024,
	f16, f32, f64, f128,
}

/// Main operand types.
//package
enum AdbgDisasmOperand : ubyte {
	immediate,	/// 
	register,	/// 
	memory,	/// 
}

/// Immediate operand
package
struct adbg_disasm_operand_imm_t {
	adbg_disasm_number_t value;
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
	ubyte scale;	/// SIB:SCALE
	adbg_disasm_number_t offset;	/// Displacement
	bool scaled;	/// SIB or any scaling mode
	//TODO: Call/jmp type (bool: normal/near, far)
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

//TODO: Fetch append to machine option
//      While automatically appending to the machine buffer is great for
//      CISC settings, RISC environments tell another story.
//      For example, RISC-V initially fetches a 2-byte number, but it may be
//      extended to a 4-byte number with another 2-byte fetch. So since the
//      instruction is 4-byte, it would not be 2 
private
struct adbg_disasm_decoder_options_t { align(1):
	union {
		ulong all;	/// Unset when initiated
		struct {
			/// Skip prefixes when rendering.
			///
			/// Under x86, some prefixes like LOCK can sometimes be
			/// printed, or not, depending on the instruction.
			/// If set, the prefixes are not included in the output.
			// NOTE: Prefix could need of groups (bit flags) in case
			bool noPrefixes;
			/// (AT&T syntax) Msnemonic is basic for width modifier.
			bool primitive;
			/// (AT&T syntax) Instruction is a far (absolute) call/jump.
			bool absolute;
		}
	}
}

//TODO: Display option for integer/byte/float operations
//      Smart: integer=decimal, bitwise=hex, fpu=float
//      A setting for each group (that will be a lot of groups...)
private
struct adbg_disasm_user_options_t { align(1):
	union {
		ulong all;	/// Unset when initiated
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
/// 	add = If true, adds to the machine buffer
/// Returns: Non-zero on error
package
int adbg_disasm_fetch(T)(adbg_disasm_t *p, T *u, bool add = true) {
	if (p.opcode.size + T.sizeof > p.max)
		return adbg_oops(AdbgError.opcodeLimit);
	//TODO: Auto bswap if architecture endian is different than target
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
	p.opcode.size += T.sizeof;
	if (add && p.mode >= AdbgDisasmMode.file)
	if (p.opcode.machineCount < ADBG_MAX_MACHINE) {
		adbg_disasm_number_t *n = &p.opcode.machine[p.opcode.machineCount++];
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
	const(char) *regbase,
	const(char) *regindex,
	adbg_disasm_number_t *disp,
	//TODO: ushort segment
	AdbgDisasmType width,
	ubyte scale,
	bool scaled) {
	if (p.opcode.operandCount >= ADBG_MAX_OPERANDS)
		return;
	
	version (Trace) trace("base=%s", regbase);
	
	p.memWidth	= width;
	adbg_disasm_operand_t *item = adbg_disasm_get_operand(p);
	item.type       = AdbgDisasmOperand.memory;
	item.mem.base	= regbase;
	item.mem.index	= regindex;
	item.mem.offset	= *disp;
	item.mem.scale	= scale;
	item.mem.scaled	= scaled;
}
