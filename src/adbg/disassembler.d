/**
 * Disassembler module.
 *
 * This module is responsable for disassembling and formatting machine code.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2022 dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module adbg.disassembler;

import adbg.error;
private import adbg.utils.str;
private import adbg.platform : adbg_address_t;
private import adbg.disasm.decoders;
public import adbg.disasm.formatter;

//TODO: Invalid results could be rendered differently
//      e.g., .byte 0xd6,0xd6 instead of (bad)
//      Option 1. Add lasterror in adbg_disasm_t
//TODO: enum AdbgDisasmEndian : ubyte { native, little, big }
//      adbg_disasm_t: AdbgDisasmEndian endian;
//      Configured when _configure is called, used for fetching
//TODO: Flow-oriented analysis to mitigate anti-dissassembly techniques
//      Obviously with a setting (what should be the default?)
//      adbg_disasm_cfa(bool)
//        true : malloc table with X initial entries
//        false: free table
//      Save jmp/call targets in allocated table
//TODO: Visibility system for prefixes
//      Tag system? e.g., groups (ubyte + bitflag)
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
//TODO: Consider adding alternative syntax options
//      e.g., 3[RDI], .rodata[00h][RIP]
//TODO: Support for no pseudo-instructions
//      and setting bool userNoPseudoInstructions
//      If true, tells decoder to get the base instruction instead
//      In RISC-V, addi x0,x0,0 is basically nop, and nop is the 
//      pseudo-instruction

extern (C):

private enum {
	ADBG_MAX_PREFIXES = 8,	/// Buffer size for prefixes.
	ADBG_MAX_OPERANDS = 4,	/// Buffer size for operands.
	ADBG_MAX_MACHINE  = 16,	/// Buffer size for machine groups.
	ADBG_COOKIE	= 0xcc00ffee,	/// Don't tell anyone.
	ADBG_MAX_X86	= 15,	/// Inclusive maximum instruction size for x86.
	ADBG_MAX_RV32	= 4,	/// Inclusive maximum instruction size for RV32I.
	ADBG_MAX_RV64	= 8,	/// Inclusive maximum instruction size for RV64I.
}

/// Disassembler platform
enum AdbgPlatform : ubyte {
	native,	/// Platform compiled target (Default)
	x86_16,	/// (WIP) 8086, 80186, 80286
	x86_32,	/// (WIP) 80386/i386, not to be confused with x32
	x86_64,	/// (WIP) AMD64, EM64T/Intel64, x64
	arm_t32,	///TODO: ARM T32 (thumb)
	arm_a32,	///TODO: ARM A32 (arm)
	arm_a64,	///TODO: ARM A64 (aarch64)
	riscv32,	/// (WIP) RISC-V 32-bit
	riscv64,	///TODO: RISC-V 64-bit
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
//TODO: Consider making these feature bits instead of modes
enum AdbgDisasmMode : ubyte {
	size,	/// Only calculate operation code sizes
	data,	/// Opcode sizes with jump locations (e.g. JMP, CALL)
	file,	/// Machine code and instruction mnemonics formatting
	full	///TODO: Analysis
}

/// Assembler syntax
enum AdbgSyntax : ubyte {
	/// Native compiled target default. (Default)
	/// The default syntax for each platform is listed below.
	/// x86: intel
	/// riscv: riscv
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
	/// RISC-V native syntax.
	/// Year: 2010
	/// Destination: Left
	///
	/// Example:
	/// ---
	/// lw t0, 12(sp)
	/// ---
	riscv,
	///TODO: ARM native syntax.
	/// Year: 1985
	/// Destination: Left
	///
	/// Example:
	/// ---
	/// mov r0, [fp, #-8]
	/// ---
//	arm,
}

/// Disassembler input
//TODO: Stream (file) mode
//      Useful for (when 'dumping'):
//      - stdin
//      - character/block devices
enum AdbgDisasmSource : ubyte {
	buffer,	/// Buffer
	debugger,	/// Debuggee
//	stream,	/// Stream (FILE*)
}

/// Machine tags when fetching
enum AdbgDisasmTag : ushort {
	unknown,	/// Unknown, either now or forever
	opcode,	/// Operation code
	prefix,	/// Instruction prefix
	operand,	/// Instruction operand
	immediate,	/// Immediate operand
	// Why is this there when we have .immediate?
	disp,	/// Displacement/Offset immediate
	// Why is this there when we have .immediate?
	segment,	/// Immediate used in far calls
	modrm,	/// x86: ModR/M byte
	sib,	/// x86: SIB byte
	rex,	/// x86: REX byte
	vex,	/// x86: VEX bytes
	evex,	/// x86: EVEX bytes
}

/// Data types
//TODO: Rename to AdbgDataType? Move to its own module? Make definitions.d?
//TODO: f64 and f32?
enum AdbgDisasmType : ubyte {
	none,
	i8,  i16, i32, i64, i128, i256, i512, i1024,
	far, f80, res11, res12, res13, res14, res15,
	
	length = res15 + 1,
}

/// Main operand types.
enum AdbgDisasmOperand : ubyte {
	immediate,	/// 
	register,	/// 
	memory,	/// 
	
	length = memory + 1,
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
		DEFAULT_SYNTAX = AdbgSyntax.riscv,	/// Ditto
	}
} else version (RISCV64) {
	private enum {
		DEFAULT_PLATFORM = AdbgPlatform.riscv64,	/// Ditto
		DEFAULT_SYNTAX = AdbgSyntax.riscv,	/// Ditto
	}
} else {
	static assert(0, "Set DEFAULT_PLATFORM and DEFAULT_SYNTAX");
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
struct adbg_disasm_opcode_t { align(1):
	//TODO: Success bool or last error code in opcode structure
	//      Would help formatter to ouput .byte 0xaa,0xbb etc.
	// size mode:
	int size;	/// Opcode size
	// data mode:
	//TODO: Jump/call target in opcode structure
//	ulong targetAddress;	/// CALL/JMP calculated target (absolute)
	// file mode:
	const(char) *segment;	/// Last segment register string override
	const(char) *mnemonic;	/// Instruction mnemonic
	size_t operandCount;	/// Number of operands
	adbg_disasm_operand_t[ADBG_MAX_OPERANDS] operands;	/// Operands
	size_t prefixCount;	/// Number of prefixes
	adbg_disasm_prefix_t[ADBG_MAX_PREFIXES] prefixes;	/// Prefixes
	size_t machineCount;	/// Number of disassembler fetches
	adbg_disasm_machine_t[ADBG_MAX_MACHINE] machine;	/// Machine bytes
	// analysis mode:
	// struct:
	//   target information (label)
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
	//TODO: Move in format functions once format option is passed as a parameter
	bool function(adbg_disasm_t*, ref adbg_string_t, ref adbg_disasm_operand_t) foperand;
	/// Internal cookie. Yummy!
	uint cookie;
	/// Instruction set architecture platform to disassemble from.
	AdbgPlatform platform;
	/// Current syntax option.
	AdbgSyntax syntax;
	//TODO: Deprecate operating mode.
	//      Separate bool/bit values is much simpler to play with.
	//      Input: AdbgDisasmFeature.A | AdbgDisasmFeature.B | etc.
	//      bool modeOffsets;
	//      bool modeFile;
	/// Operating mode.
	AdbgDisasmMode mode;
	/// Source mode.
	AdbgDisasmSource source;
	/// Opcode information
	adbg_disasm_opcode_t *opcode;
	/// Buffer: This field dictates how much data is left.
	/// Debuggee: This field is not taken into account.
	size_t left;
	/// Architectural limit length for an opcode in bytes.
	/// Past this number, the decoder will automatically trip.
	/// x86: 15 bytes
	/// riscv32: 4 bytes
	/// riscv64: 8 bytes
	int limit;
	/// Memory operation width
	AdbgDisasmType memWidth;
	//TODO: Redo these as bit flags
	//      They are not accessed as often as I would think
	package union { // Decoder options
		uint decoderAll;
		struct {
			bool decoderNoReverse;	/// ATT: Do not reverse the order of operands. (e.g., FP or 2 immediates)
			bool decoderFar;	/// ATT: Far call or jumdisasm. Set when Type is far.
			ubyte decoderPfGroups;	///TODO: Prefixes to show/hide, upto 8 groups.
			bool decoderAmbiguate;	///TODO: ATT: Ambiguate instruction.
		}
	}
	package union { // User options
		uint userAll;
		struct {
			/// If set, inserts a tab instead of a space between
			/// mnemonic and operands.
			//TODO: Deprecate userMnemonicTab
			//      bool userMnemonicSepSet;
			//      char userMnemonicSep;
			bool userMnemonicTab;
			///TODO: Opcodes and operands are not seperated by spaces.
			bool userUnpackMachine;
		}
	}
}

package
template ADBG_TYPE(T) {
	static if (is(T == ubyte))
		enum ADBG_TYPE = AdbgDisasmType.i8;
	else static if (is(T == ushort))
		enum ADBG_TYPE = AdbgDisasmType.i16;
	else static if (is(T == uint))
		enum ADBG_TYPE = AdbgDisasmType.i32;
	else static if (is(T == ulong))
		enum ADBG_TYPE = AdbgDisasmType.i64;
	else static if (is(T == float)) // weird
		enum ADBG_TYPE = AdbgDisasmType.i32;
	else static if (is(T == double)) // ditto
		enum ADBG_TYPE = AdbgDisasmType.i64;
}

// alloc
adbg_disasm_t *adbg_disasm_alloc(AdbgPlatform m) {
	import core.stdc.stdlib : calloc;
	
	version (Trace) trace("platform=%u", m);
	
	adbg_disasm_t *s = cast(adbg_disasm_t*)calloc(1, adbg_disasm_t.sizeof);
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
int adbg_disasm_configure(adbg_disasm_t *disasm, AdbgPlatform m) {
	version (Trace) trace("platform=%u", m);
	
	with (AdbgPlatform)
	switch (m) {
	case native: // equals 0
		m = DEFAULT_PLATFORM;
		goto case DEFAULT_PLATFORM;
	case x86_16, x86_32, x86_64:
		disasm.limit = ADBG_MAX_X86;
		disasm.fdecode = &adbg_disasm_x86;
		disasm.syntax = AdbgSyntax.intel;
		disasm.foperand = &adbg_disasm_operand_intel;
		break;
	case riscv32:
		disasm.limit = ADBG_MAX_RV32;
		disasm.fdecode = &adbg_disasm_riscv;
		disasm.syntax = AdbgSyntax.riscv;
		disasm.foperand = &adbg_disasm_operand_riscv;
		break;
	/*case riscv64:
		disasm.limit = ADBG_MAX_RV64;
		disasm.fdecode = &adbg_disasm_riscv;
		disasm.syntax = AdbgSyntax.riscv;
		disasm.foperand = &adbg_disasm_operand_riscv;
		break;*/
	default:
		return adbg_oops(AdbgError.unsupportedPlatform);
	}
	
	// Defaults
	disasm.platform = m;
	disasm.cookie = ADBG_COOKIE;
	disasm.userAll = 0;
	return 0;
}

// set option
int adbg_disasm_opt(adbg_disasm_t *disasm, AdbgDisasmOpt opt, int val) {
	if (disasm == null)
		return adbg_oops(AdbgError.nullArgument);
	
	version (Trace) trace("opt=%u val=%d", opt, val);
	
	with (AdbgDisasmOpt)
	switch (opt) {
	case syntax:
		disasm.syntax = cast(AdbgSyntax)val; //TODO: To deprecate (??)
		switch (disasm.syntax) with (AdbgSyntax) {
		case intel:  disasm.foperand = &adbg_disasm_operand_intel; break;
		case nasm:   disasm.foperand = &adbg_disasm_operand_nasm; break;
		case att:    disasm.foperand = &adbg_disasm_operand_att; break;
		case ideal:  disasm.foperand = &adbg_disasm_operand_ideal; break;
		case hyde:   disasm.foperand = &adbg_disasm_operand_hyde; break;
		case riscv:  disasm.foperand = &adbg_disasm_operand_riscv; break;
		default:     return adbg_oops(AdbgError.invalidOptionValue);
		}
		break;
	case mnemonicTab:
		disasm.userMnemonicTab = val != 0;
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
int adbg_disasm_start_buffer(adbg_disasm_t *disasm, AdbgDisasmMode mode, void *buffer, size_t size) {
	if (disasm == null || buffer == null)
		return adbg_oops(AdbgError.nullArgument);
	
	disasm.source = AdbgDisasmSource.buffer;
	disasm.mode = mode;
	disasm.current.raw = disasm.base.raw = buffer;
	disasm.left = size;
	return 0;
}

//TODO: Consider adding base parameter
/// Start a disassembler region at the debuggee's location.
/// Params:
/// 	p = Disassembler structure.
/// 	mode = Disassembly mode.
/// 	addr = Debuggee address.
/// Returns: Error code
int adbg_disasm_start_debuggee(adbg_disasm_t *disasm, AdbgDisasmMode mode, size_t addr) {
	if (disasm == null)
		return adbg_oops(AdbgError.nullArgument);
	
	disasm.source = AdbgDisasmSource.debugger;
	disasm.mode = mode;
	disasm.current.sz = disasm.base.sz = addr;
	return 0;
}

int adbg_disasm_once_buffer(adbg_disasm_t *disasm, adbg_disasm_opcode_t *op, AdbgDisasmMode mode, void *buffer, size_t size) {
	int e = adbg_disasm_start_buffer(disasm, mode, buffer, size);
	if (e) return e;
	return adbg_disasm(disasm, op);
}

int adbg_disasm_once_debuggee(adbg_disasm_t *disasm, adbg_disasm_opcode_t *op, AdbgDisasmMode mode, size_t addr) {
	int e = adbg_disasm_start_debuggee(disasm, mode, addr);
	if (e) return e;
	return adbg_disasm(disasm, op);
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
int adbg_disasm(adbg_disasm_t *disasm, adbg_disasm_opcode_t *op) {
	if (disasm == null || op == null)
		return adbg_oops(AdbgError.nullArgument);
	if (disasm.cookie != ADBG_COOKIE)
		return adbg_oops(AdbgError.uninitiated);
	
	//TODO: longjmp
	//      Trust me, if I had working longjmp bindings on Windows, I
	//      would have absolutely make the decoders longjmp back here
	//      on error
	
	with (op) { // reset opcode
		mnemonic = segment = null;
		size = machineCount = prefixCount = operandCount = 0;
	}
	with (disasm) { // reset disasm
		decoderAll = 0;
	}
	
	extern (C)
	int function(adbg_disasm_t*) decode = disasm.fdecode;
	
	if (decode == null)
		return adbg_oops(AdbgError.uninitiated);
	
	disasm.opcode = op;
	disasm.last = disasm.current;	// Save address
	return decode(disasm);	// Decode
}

private import core.stdc.stdlib : free;
/// Frees a previously allocated disassembly structure.
public  alias adbg_disasm_free = free;

/// Represents an instruction prefix
struct adbg_disasm_prefix_t {
	const(char) *name;
	ubyte group;
}

/// Immediate operand type.
//package
//TODO: Display option for integer/byte/float operations
//      Smart: integer=decimal, bitwise=hex, fpu=float
//      A setting for each group (that will be a lot of groups...)
struct adbg_disasm_operand_imm_t { align(1):
	adbg_disasm_number_t value;	/// 
	ushort segment;	/// 
	bool absolute;	/// 
	//TODO: AdbgDisasmImmPurpose
	//      default -> decimal
	//      bitop -> hex
}

/// Register operand type.
//package
//TODO: Consider "stack register" type
//      How would this benefit?
struct adbg_disasm_operand_reg_t { align(1):
	const(char) *name;	/// Register name
	const(char) *mask1;	/// Mask register (e.g., {k2} when EVEX.aaa=010)
	const(char) *mask2;	/// Mask register (e.g., {z} when EVEX.z=1)
	int index;	/// If indexed, adds an index to register
	bool isStack;	/// x86: Applies to x87
}

/// Memory operand type.
//package
struct adbg_disasm_operand_mem_t { align(1):
	const(char) *segment;	/// Segment register
	const(char) *base;	/// Base register, (scaled) SIB:BASE
	const(char) *index;	/// Additional register, (scaled) SIB:INDEX
	ubyte scale;	/// SIB:SCALE
	bool hasOffset;	/// Has memory offset
	adbg_disasm_number_t offset;	/// Displacement
	bool scaled;	/// SIB or any scaling mode
	bool absolute;	/// Absolute address jump or call
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

/// Memory displacement
struct adbg_disasm_disp_t { align(1):
	AdbgDisasmType type;	/// Displacement type
	void *value;	/// Displacement value pointer
}

package
adbg_disasm_disp_t adbg_disasm_disp(void *data, AdbgDisasmType type) {
	adbg_disasm_disp_t v = void;
	v.value = data;
	v.type = type;
	return v;
}
package
adbg_disasm_disp_t adbg_disasm_dispt(T)(void *data) {
	adbg_disasm_disp_t v = void;
	v.type = ADBG_TYPE!(T);
	v.value = data;
	return v;
}

/// (Internal) Fetch data from data source.
/// Params:
/// 	data = Data pointer
/// 	disasm = Disassembler structure pointer
/// 	tag = Byte tag
/// Returns: Non-zero on error
package
int adbg_disasm_fetch(T)(void *data, adbg_disasm_t *disasm, AdbgDisasmTag tag = AdbgDisasmTag.unknown) {
	version (Trace) trace("size=%u left=%zu", disasm.opcode.size, disasm.left);

	if (disasm.opcode.size + T.sizeof > disasm.limit)
		return adbg_oops(AdbgError.opcodeLimit);
	
	//TODO: Auto bswap if architecture endian is different than target
	//      enum bool SWAP = TargetEndian != disasm.platform && T.sizeof > 1
	//TODO: Function pointer instead of switch?
	int e = void;
	switch (disasm.source) with (AdbgDisasmSource) {
	case buffer:
		if (disasm.left < T.sizeof)
			return adbg_oops(AdbgError.outOfData);
		*cast(T*)data = *cast(T*)disasm.current;
		disasm.left -= T.sizeof;
		e = 0;
		break;
	case debugger:
		import adbg.dbg.debugger : adbg_mm_cread;
		e = adbg_mm_cread(disasm.current.sz, data, T.sizeof);
		break;
	default: assert(0);
	}
	
	disasm.current.sz += T.sizeof;
	disasm.opcode.size += T.sizeof;
	
	if (disasm.mode >= AdbgDisasmMode.file &&
		disasm.opcode.machineCount < ADBG_MAX_MACHINE) {
		adbg_disasm_machine_t *n =
			&disasm.opcode.machine[disasm.opcode.machineCount++];
		n.tag = tag;
		static if (is(T == ubyte)) {
			n.i8 = *cast(T*)data;
			n.type = AdbgDisasmType.i8;
		} else static if (is(T == ushort)) {
			n.i16 = *cast(T*)data;
			n.type = AdbgDisasmType.i16;
		} else static if (is(T == uint)) {
			n.i32 = *cast(T*)data;
			n.type = AdbgDisasmType.i32;
		} else static if (is(T == ulong)) {
			n.i64 = *cast(T*)data;
			n.type = AdbgDisasmType.i64;
		/*} else static if (is(T == float)) {
			n.f32 = *cast(T*)data;
			n.type = AdbgDisasmType.f32;
		} else static if (is(T == double)) {
			n.f64 = *cast(T*)data;
			n.type = AdbgDisasmType.f64;*/
		} else static assert(0, "fetch support type");
	}
	return e;
}

// fix last tag
package
void adbg_disasm_fetch_lasttag(adbg_disasm_t *disasm, AdbgDisasmTag tag) {
	disasm.opcode.machine[disasm.opcode.machineCount - 1].tag = tag;
}

// calculate near offset
//TODO: Rename to adbg_disasm_offset
package
void adbg_disasm_calc_offset(T)(adbg_disasm_t *disasm, T u) {
}

//
// ANCHOR Prefixes
//

// add prefix in prefix buffer
package
void adbg_disasm_add_prefix(adbg_disasm_t *disasm, const(char) *prefix) {
	if (disasm.opcode.prefixCount >= ADBG_MAX_PREFIXES)
		return;
	
	adbg_disasm_prefix_t *pf = &disasm.opcode.prefixes[disasm.opcode.prefixCount++];
	pf.name = prefix;
}

//
// ANCHOR Mnemonic instruction
//

// set instruction mnemonic
package
void adbg_disasm_add_mnemonic(adbg_disasm_t *disasm, const(char) *instruction) {
	version (Trace) trace("mnemonic=%s", instruction);
	
	disasm.opcode.mnemonic = instruction;
}

//
// ANCHOR Operand operations
//

// select operand
private
adbg_disasm_operand_t* adbg_disasm_get_operand(adbg_disasm_t *disasm) {
	return cast(adbg_disasm_operand_t*)
		&disasm.opcode.operands[disasm.opcode.operandCount++];
}

// add segment override
package
void adbg_disasm_add_segment(adbg_disasm_t *disasm, const(char) *segment) {
	disasm.opcode.segment = segment;
}

// set memory
package
void adbg_disasm_set_memory(
	adbg_disasm_operand_mem_t *mem,
	const(char) *segment,
	const(char) *regbase,
	const(char) *regindex,
	AdbgDisasmType dispWidth,
	void *disp,
	ubyte scale,
	bool scaled,
	bool absolute) {
	mem.segment   = segment;
	mem.base      = regbase;
	mem.index     = regindex;
	mem.scale     = scale;
	mem.scaled    = scaled;
	mem.absolute  = absolute;
	mem.hasOffset = disp != null;
	if (disp) {
		mem.offset.type = dispWidth;
		switch (dispWidth) with (AdbgDisasmType) {
		case i8:  mem.offset.u8  = *cast(ubyte*)disp;  return;
		case i16: mem.offset.u16 = *cast(ushort*)disp; return;
		case i32: mem.offset.u32 = *cast(uint*)disp;   return;
		case i64: mem.offset.u64 = *cast(ulong*)disp;  return;
		default: assert(0);
		}
	}
}

// add immediate
package
void adbg_disasm_add_immediate(
	adbg_disasm_t *disasm,
	AdbgDisasmType width,
	void *v,
	ushort segment = 0,
	bool absolute = false) {
	if (disasm.opcode.operandCount >= ADBG_MAX_OPERANDS)
		return;
	
	version (Trace) {
		switch (width) with (AdbgDisasmType) {
		case i8:  trace("segment=%u v=%u", segment, *cast(ubyte*)v); break;
		case i16: trace("segment=%u v=%u", segment, *cast(ushort*)v); break;
		case i32: trace("segment=%u v=%u", segment, *cast(uint*)v); break;
		case i64: trace("segment=%u v=%llu", segment, *cast(ulong*)v); break;
		default: assert(0);
		}
	}
	
	adbg_disasm_operand_t *item = adbg_disasm_get_operand(disasm);
	item.type = AdbgDisasmOperand.immediate;
	item.imm.value.type = width;
	item.imm.segment    = segment;
	item.imm.absolute   = absolute;
	switch (width) with (AdbgDisasmType) {
	case i8:  item.imm.value.u8  = *cast(ubyte*)v;  return;
	case i16: item.imm.value.u16 = *cast(ushort*)v; return;
	case i32: item.imm.value.u32 = *cast(uint*)v;   return;
	case i64: item.imm.value.u64 = *cast(ulong*)v;  return;
	default: assert(0);
	}
}

// add register
package
void adbg_disasm_add_register(adbg_disasm_t *disasm, const(char) *register,
	const(char) *mask1 = null, const(char) *mask2 = null,
	int index = 0, bool indexed = false) {
	if (disasm.opcode.operandCount >= ADBG_MAX_OPERANDS)
		return;
	
	version (Trace) trace("name=%s index=%d indexed=%d", register, index, indexed);
	
	adbg_disasm_operand_t *item = adbg_disasm_get_operand(disasm);
	item.type        = AdbgDisasmOperand.register;
	item.reg.name    = register;
	item.reg.mask1   = mask1;
	item.reg.mask2   = mask2;
	item.reg.index   = index;
	item.reg.isStack = indexed;
}

// add memory operand item
package
void adbg_disasm_add_memory(
	adbg_disasm_t *disasm,
	AdbgDisasmType width,
	const(char) *segment,
	const(char) *regbase,
	const(char) *regindex,
	AdbgDisasmType dispWidth,
	void *disp,
	ubyte scale,
	bool scaled,
	bool absolute) {
	if (disasm.opcode.operandCount >= ADBG_MAX_OPERANDS)
		return;
	
	version (Trace) {
		trace("width=%u base=%s index=%s dwidth=%u disp=%p scale=%u scaled=%d",
			width, regbase, regindex, dispWidth, disp, scale, scaled);
		switch (dispWidth) with (AdbgDisasmType) {
		case i8:  trace("disp=%x", *cast(ubyte*)disp); break;
		case i16: trace("disp=%x", *cast(ushort*)disp); break;
		case i32: trace("disp=%x", *cast(uint*)disp); break;
		case i64: trace("disp=%llx", *cast(ulong*)disp); break;
		default:
		}
	}
	
	adbg_disasm_operand_t *item = adbg_disasm_get_operand(disasm);
	disasm.memWidth         = width;
	item.type          = AdbgDisasmOperand.memory;
	item.mem.segment   = segment;
	item.mem.base      = regbase;
	item.mem.index     = regindex;
	item.mem.scale     = scale;
	item.mem.scaled	   = scaled;
	item.mem.absolute  = absolute;
	item.mem.hasOffset = disp != null;
	if (disp) {
		item.mem.offset.type = dispWidth;
		switch (dispWidth) with (AdbgDisasmType) {
		case i8:  item.mem.offset.u8  = *cast(ubyte*)disp;  return;
		case i16: item.mem.offset.u16 = *cast(ushort*)disp; return;
		case i32: item.mem.offset.u32 = *cast(uint*)disp;   return;
		case i64: item.mem.offset.u64 = *cast(ulong*)disp;  return;
		default: assert(0, "add type");
		}
	}
}

package
void adbg_disasm_add_memory2(adbg_disasm_t *disasm, AdbgDisasmType width, adbg_disasm_operand_mem_t *m) {
	if (disasm.opcode.operandCount >= ADBG_MAX_OPERANDS)
		return;
	
	version (Trace) trace("m=%p", m);
	
	disasm.memWidth = width;
	adbg_disasm_operand_t *item = adbg_disasm_get_operand(disasm);
	item.type  = AdbgDisasmOperand.memory;
	item.mem   = *m;
}