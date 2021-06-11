/**
 * Disassembler syntax engine.
 *
 * TODO
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.disasm.syntaxer;

//TODO: Invalid results could be rendered differntly
//      e.g., .byte 0xd6,0xd6 instead of (bad)

private import adbg.error;
//TODO: Deprecate?
private import core.stdc.stdarg;
private import adbg.utils.str : sbuffer_t;

extern (C):

/// Buffer size for prefixes.
private enum ADBG_MAXCOUNT_PREFIXES = 8;
/// Buffer size for operands.
private enum ADBG_MAXCOUNT_OPERANDS = 4;
/// String buffer sizes in bytes
private enum ADBG_SYNTAX_BUFFER_LENGTH = 64;

/// Assembler syntax
enum AdbgSyntax : ubyte {
	/// Platform compiled default for target.
	platform,
	/// Intel syntax (1978), similar to Microsoft/Macro Assembler (MASM).
	/// Example:
	/// ---
	/// mov ecx, dword ptr ss:[ebp-14]
	/// ---
	intel,
	/// AT&T syntax (1975).
	/// See the GNU Assembler documentation or the
	/// IAS/RSX-11 MACRO-11 Reference Manual for more information.
	/// Example:
	/// ---
	/// mov ss:-14(%ebp), %ecx
	/// ---
	att,
	/// Netwide Assembler syntax (NASM, 1996).
	/// Example:
	/// ---
	/// mov ecx, dword ptr [ss:ebp-14]
	/// ---
	nasm,
	///TODO: Borland Ideal (enhanced mode of TASM) syntax.
	/// Example:
	/// ---
	/// mov ecx, [dword ss:ebp-14]
	/// ---
//	ideal,
	/// TODO: Randall Hyde High Level Assembly Language syntax.
	/// Example:
	/// ---
	/// mov( [type dword ss:ebp-14], ecx )
	/// ---
//	hyde,	///
	///TODO: ARM native syntax.
	/// Example:
	/// ---
	/// ldr r0, [r1]
	/// ---
//	arm,
	///TODO: RISC-V native syntax.
	/// Example:
	/// ---
	/// TODO
	/// ---
//	riscv,
} 

/// Memory width
package
enum AdbgSyntaxWidth : ubyte {
	i8, i16, i32, i64, i128, i256, i512, i1024
}

private
enum AdbgNumber {
	u8,
	u16,
	u32,
	u64,
	f32,
	f64,
}

private
struct adbg_syntax_number_t {
	union {
		ulong u64;	/// 64-bit unsigned value
		long i64;	/// 64-bit signed value
		uint u32;	/// 32-bit unsigned value
		int i32;	/// 32-bit signed value
		ushort u16;	/// 16-bit unsigned value
		short i16;	/// 16-bit signed value
		ubyte u8;	/// 8-bit unsigned value
		byte i8;	/// 8-bit signed value
		float f32;	/// 32-bit single-precision floating number
		double f64;	/// 64-bit double-precision floating number
	}
	AdbgSyntaxWidth width;
}
version (PrintInfo)
	pragma(msg, "adbg_syntax_number_t.sizeof\t", adbg_syntax_number_t.sizeof);

/// Operand types.
package
enum AdbgSyntaxItem : ubyte {
	/// A constant value.
	immediate,	// 0xff
	/// 
	immediateFar,	// 0x10:0x1000 / $0x10:0x1000
	/// A register string.
	register,	// eax
	/// A IEEE 754 80-bit register index and string.
	// base register string and index
	realRegister,	// intel=st,st(1) / nasm=st0,st1 / att=%st,%st(1)
	/// A constant memory location.
	memory,	// [0x10]
	/// A far constant memory location.
	memoryFar,	// [0x10:0x1000] / (0x10:0x1000)
	/// A memory location pointed by a register string.
	memoryRegister,	// [eax]
	/// A memory location pointed by a register pair. (notably x86-16)
	memoryRegisterPair,	// [sp+ax] / (%sp,%ax)
	/// A far memory location pointed by a constant segment and register string.
	memoryRegisterFar,	// [0x10:eax] / (0x10:eax)
	/// 
	memoryRegisterOffset,	// [eax+0xff]
	/// Memory scale with BASE and INDEX registers + multiplier.
	/// x86: ModRM MOD=00 + SIB
	memoryScaleBaseIndexScale,	// [eax+ecx*2] / (eax,ecx,2)
	/// Memory scale with INDEX register.
	/// x86: ModRM MOD=00 + SIB INDEX=100
	memoryScaleBase,	// [eax] / (,ecx,)
	/// Memory scale with INDEX register + multiplier + offset.
	/// x86: ModRM MOD=01
	memoryScaleIndexScaleOffset,	// es:[ecx*2+0x50] / %es:0x50(,ecx,2)
	/// Memory scale with offset only.
	/// x86: ModRM MOD=01 + SIB INDEX=100
	memoryScaleOffset,	// [0x50] / 0x50(,,)
	/// Memory scale with BASE and INDEX registers + multiplier.
	/// x86: ModRM MOD=10 + SIB
	memoryScaleBaseIndexScaleOffset,	// [eax+ecx*2+0x50] / 0x50(eax,ecx,2)
	/// Memory scale with BASE register + offset.
	/// x86: ModRM MOD=10 + SIB INDEX=100
	memoryScaleBaseOffset,	// [eax+0x50] / 0x50(eax,,)
}

/// 
private
struct adbg_syntax_item_op_t(AdbgSyntaxItem item) { align(1):
	static if (item == AdbgSyntaxItem.immediate) {
		uint value;
	} else static if (item == AdbgSyntaxItem.immediateFar) {
		ushort segment;
		uint value;
	} else static if (item == AdbgSyntaxItem.register) {
		const(char) *name;
	} else static if (item == AdbgSyntaxItem.realRegister) {
		const(char) *name;
		ushort index;
	} else static if (item == AdbgSyntaxItem.memory) {
		adbg_syntax_number_t offset;
		AdbgSyntaxWidth width;
	} else static if (item == AdbgSyntaxItem.memoryFar) {
		ushort segment;
		adbg_syntax_number_t offset;
		AdbgSyntaxWidth width;
	} else static if (item == AdbgSyntaxItem.memoryRegister) {
		const(char) *register;
		AdbgSyntaxWidth width;
	} else static if (item == AdbgSyntaxItem.memoryRegisterPair) {
		const(char) *registerBase;
		const(char) *registerOffset;
		AdbgSyntaxWidth width;
	} else static if (item == AdbgSyntaxItem.memoryRegisterFar) {
		const(char) *register;
		ushort segment;
		AdbgSyntaxWidth width;
	} else static if (item == AdbgSyntaxItem.memoryRegisterOffset) {
		const(char) *register;
		adbg_syntax_number_t offset;
		AdbgSyntaxWidth width;
	} else static if (item == AdbgSyntaxItem.memoryScaleBaseIndexScale) {
		const(char) *base;
		const(char) *index;
		ubyte scale;
		AdbgSyntaxWidth width;
	} else static if (item == AdbgSyntaxItem.memoryScaleBase) {
		const(char) *base;
		AdbgSyntaxWidth width;
	} else static if (item == AdbgSyntaxItem.memoryScaleIndexScaleOffset) {
		const(char) *index;
		adbg_syntax_number_t offset;
		ubyte scale;
		AdbgSyntaxWidth width;
	} else static if (item == AdbgSyntaxItem.memoryScaleOffset) {
		adbg_syntax_number_t offset;
		AdbgSyntaxWidth width;
	} else static if (item == AdbgSyntaxItem.memoryScaleBaseIndexScaleOffset) {
		const(char) *base;
		const(char) *index;
		adbg_syntax_number_t offset;
		ubyte scale;
		AdbgSyntaxWidth width;
	} else static if (item == AdbgSyntaxItem.memoryScaleBaseOffset) {
		const(char) *base;
		adbg_syntax_number_t offset;
		AdbgSyntaxWidth width;
	} else static assert(0, "Implement for specified AdbgSyntaxItem");
}

package
struct adbg_syntax_item_t { align(1):
	AdbgSyntaxItem type;	/// operand type
	union {
		adbg_syntax_item_op_t!(AdbgSyntaxItem.immediate) immediate;
		adbg_syntax_item_op_t!(AdbgSyntaxItem.immediateFar) immediateFar;
		adbg_syntax_item_op_t!(AdbgSyntaxItem.register) register;
		adbg_syntax_item_op_t!(AdbgSyntaxItem.realRegister) realRegister;
		adbg_syntax_item_op_t!(AdbgSyntaxItem.memory) memory;
		adbg_syntax_item_op_t!(AdbgSyntaxItem.memoryFar) memoryFar;
		adbg_syntax_item_op_t!(AdbgSyntaxItem.memoryRegister) memoryRegister;
		adbg_syntax_item_op_t!(AdbgSyntaxItem.memoryRegisterPair) memoryRegisterPair;
		adbg_syntax_item_op_t!(AdbgSyntaxItem.memoryRegisterFar) memoryRegisterFar;
		adbg_syntax_item_op_t!(AdbgSyntaxItem.memoryRegisterOffset) memoryRegisterOffset;
		adbg_syntax_item_op_t!(AdbgSyntaxItem.memoryScaleBaseIndexScale) memoryScaleBaseIndexScale;
		adbg_syntax_item_op_t!(AdbgSyntaxItem.memoryScaleBase) memoryScaleBase;
		adbg_syntax_item_op_t!(AdbgSyntaxItem.memoryScaleIndexScaleOffset) memoryScaleIndexScaleOffset;
		adbg_syntax_item_op_t!(AdbgSyntaxItem.memoryScaleOffset) memoryScaleOffset;
		adbg_syntax_item_op_t!(AdbgSyntaxItem.memoryScaleBaseIndexScaleOffset) memoryScaleBaseIndexScaleOffset;
		adbg_syntax_item_op_t!(AdbgSyntaxItem.memoryScaleBaseOffset) memoryScaleBaseOffset;
	}
}
private
struct adbg_syntaxter_decoder_options_t { align(1):
	union {
		uint all;	/// Unset when initiated
		struct {
			/// memory operation width
			/// Should be automatically set when a memory operand is pushed.
			AdbgSyntaxWidth memWidth;
			/// Under x86, some prefixes like LOCK can sometimes be
			/// printed, or not, depending on the instruction.
			/// If set, the prefixes are not included in the output.
			bool noPrefixes;
			/// (AT&T syntax) if mnemonic is basic for width modifier.
			bool primitive;
			/// (AT&T syntax) Instruction is a far (absolute) call/jump.
			bool absolute;
		}
	}
}

private
struct adbg_syntaxter_user_options_t { align(1):
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

/// Syntax engine structure
struct adbg_syntax_t { align(1):
	
	// Decoder items
	
	/// Current index for operands items. Also serves as item count.
	size_t indexOperands;
	/// Operand items.
	adbg_syntax_item_t[ADBG_MAXCOUNT_OPERANDS] operands;
	/// Current index for prefixes items. Also serves as item count.
	size_t indexPrefixes;
	/// Prefixe items.
	const(char)*[ADBG_MAXCOUNT_PREFIXES] prefixes;
	/// Instruction mnemonic set by the platform.
	const(char) *mnemonicInstruction;
	/// Segment for instruction. Affects memory operands.
	/// Pushed by supported platforms.
	const(char) *segmentRegister;
	
	// Buffers
	
	/// Syntax item handler.
	void function(ref adbg_syntax_t, ref adbg_syntax_item_t) handler;
	/// Machine buffer.
	sbuffer_t!(ADBG_SYNTAX_BUFFER_LENGTH) machineBuffer;
	/// Mnemonic buffer.
	sbuffer_t!(ADBG_SYNTAX_BUFFER_LENGTH) mnemonicBuffer;
	/// Disassembly comment.
	const(char) *comment;
	
	// Settings
	
	/// Decoder formatting options.
	adbg_syntaxter_decoder_options_t decoderOpts;
	/// User formatting options.
	adbg_syntaxter_user_options_t userOpts;
	/// Current syntax option.
	AdbgSyntax syntax;
}
version (PrintInfo)
	pragma(msg, "adbg_syntax_t.sizeof\t", adbg_syntax_t.sizeof);

// init structure
package
int adbg_syntax_init(ref adbg_syntax_t p, AdbgSyntax syntax) {
	import adbg.disasm.syntax.intel : adbg_syntax_intel_item;
	import adbg.disasm.syntax.nasm : adbg_syntax_nasm_item;
	import adbg.disasm.syntax.att : adbg_syntax_att_item;
	with (AdbgSyntax)
	switch (syntax) {
	case intel: p.handler = &adbg_syntax_intel_item; break;
	case nasm:  p.handler = &adbg_syntax_nasm_item; break;
	case att:   p.handler = &adbg_syntax_att_item; break;
	default:    return adbg_error(AdbgError.invalidOptionValue);
	}
	p.decoderOpts.all = 0;
	p.userOpts.all = 0;
	return 0;
}

// reset structure for prep work
package
void adbg_syntax_reset(ref adbg_syntax_t p) {
	p.machineBuffer.index = 0;
	p.mnemonicBuffer.index = 0;
	p.indexOperands = 0;
	p.indexPrefixes = 0;
	p.segmentRegister = null;
	p.mnemonicInstruction = null;
}

//
// ANCHOR Machine buffer
//

// adds to machine buffer
package
void adbg_syntax_add_machine(T)(ref adbg_syntax_t p, T v) {
	import adbg.utils.str :
		adbg_util_strx02, adbg_util_strx04,
		adbg_util_strx08, adbg_util_strx016;
	
	static if (is(T == ubyte) || is(T == byte)) {
		p.mnemonicBuffer.add(adbg_util_strx02(v, false));
	} else static if (is(T == ushort) || is(T == short)) {
		p.mnemonicBuffer.add(adbg_util_strx04(v, false));
	} else static if (is(T == uint) || is(T == int)) {
		p.mnemonicBuffer.add(adbg_util_strx08(v, false));
	} else static if (is(T == ulong) || is(T == long)) {
		p.mnemonicBuffer.add(adbg_util_strx016(v, false));
	} else static if (is(T == float)) {
		union u32_t {
			uint u32;
			float f32;
		}
		u32_t u = void;
		u.f32 = v;
		p.mnemonicBuffer.add(adbg_util_strx04(u.u32, false));
	} else static if (is(T == double)) {
		union u64_t {
			ulong u32;
			double f32;
		}
		u64_t u = void;
		u.f64 = v;
		p.mnemonicBuffer.add(adbg_util_strx08(u.u64, false));
	} else static assert(0, "adbg_syntax_add_machine: Type not supported");
	
	if (p.userOpts.machinePacked == false)
		p.mnemonicBuffer.add(' ');
}

//
// ANCHOR Prefixes
//

// add prefix in prefix buffer
package
void adbg_syntax_add_prefix(ref adbg_syntax_t p, const(char) *prefix) {
	if (p.indexPrefixes >= ADBG_MAXCOUNT_PREFIXES)
		return;
	
	p.prefixes[p.indexPrefixes++] = prefix;
}

//
// ANCHOR Mnemonic instruction
//

// set instruction mnemonic
package
void adbg_syntax_add_mnemonic(ref adbg_syntax_t p, const(char) *instruction) {
	p.mnemonicInstruction = instruction;
}


//
// ANCHOR Segment register
//

// set segment register
package
void adbg_syntax_add_segment(ref adbg_syntax_t p, const(char) *segment) {
	p.segmentRegister = segment;
}

//
// ANCHOR Operands
//

// immediate type
package
void adbg_syntax_add_immediate(ref adbg_syntax_t p, uint v) {
	if (p.indexOperands >= ADBG_MAXCOUNT_OPERANDS)
		return;
	
	adbg_syntax_item_t *item = &p.operands[p.indexOperands++];
	item.type = AdbgSyntaxItem.immediate;
	item.immediate.value = v;
}

// immediateFar type

// register type
package
void adbg_syntax_add_register(ref adbg_syntax_t p, const(char) *register) {
	if (p.indexOperands >= ADBG_MAXCOUNT_OPERANDS)
		return;
	
	adbg_syntax_item_t *item = &p.operands[p.indexOperands++];
	item.type = AdbgSyntaxItem.register;
	item.register.name = register;
}

// realRegister type


// add constant memory operation
package
void adbg_syntax_add_memory(T)(ref adbg_syntax_t p, AdbgSyntaxWidth opwidth, T offset) {
	if (p.indexOperands >= ADBG_MAXCOUNT_OPERANDS)
		return;
	
	adbg_syntax_item_t *item = &p.operands[p.indexOperands++];
	item.type = AdbgSyntaxItem.memory;
	/*item.memwidth = opwidth;
	
	static if (is(T == ubyte)) {
		item.ui8 = offset;
	} else static if (is(T == ushort)) {
		item.ui16 = offset;
	} else static if (is(T == uint)) {
		item.ui32 = offset;
	} else static if (is(T == ulong)) {
		item.ui64 = offset;
	} else static assert(0, __FUNCTION__);*/
}

// memoryFar type


// memoryRegister type


// memoryRegisterPair type


// memoryRegisterFar type


// memoryRegisterOffset type


// memoryScaleBaseIndexScale type


// memoryScaleBase type


// memoryScaleIndexScaleOffset type


// memoryScaleOffset type


// memoryScaleBaseIndexScaleOffset type


// memoryScaleBaseOffset

//
// ANCHOR Rendering
//

// render whole mneomnic line, called automatically from disasm
package
void adbg_syntax_render(ref adbg_syntax_t p) {
	// Prefixes
	if (p.decoderOpts.noPrefixes == false) {
		size_t c = p.indexPrefixes - 1;
		for (size_t i; i < p.indexPrefixes; ++i) {
			p.mnemonicBuffer.add(p.prefixes[i]);
			if (i < c)
				p.mnemonicBuffer.add(' ');
		}
	}
	
	// Mnemonic
	p.mnemonicBuffer.add(p.mnemonicInstruction);
	
	if (p.indexOperands == 0)
		return;
	
	// Operands
	p.mnemonicBuffer.add(p.userOpts.mnemonicTab ? '\t' : ' ');
	
	with (AdbgSyntax)
	switch (p.syntax) {
	case intel, nasm:
		size_t sepmin = p.indexOperands - 1;
		for (size_t i; i < p.indexOperands; ++i) {
			p.handler(p, p.operands[i]);
			if (i < sepmin)
				p.mnemonicBuffer.add(',');
		}
		return;
	default:
		for (size_t i = p.indexOperands - 1; i > 0; --i) {
			p.handler(p, p.operands[i]);
			if (i > 1)
				p.mnemonicBuffer.add(',');
		}
		return;
	}
}

// render immediate hexadecimal
package
void adbg_syntax_render_offset(ref adbg_syntax_t p, ref adbg_syntax_number_t num) {
	import adbg.etc.c.stdio : snprintf;
	
	size_t l = p.mnemonicBuffer.size - p.mnemonicBuffer.index - 1;
	char *bufptr = p.mnemonicBuffer.ptr;
	
	with (AdbgSyntaxWidth)
	switch (num.width) {
	case i8:
		p.mnemonicBuffer.add(num.u8 > byte.max ? '-' : '+');
		p.mnemonicBuffer.index += snprintf(bufptr, l, "0x%x", num.u8);
		return;
	case i16:
		p.mnemonicBuffer.add(num.u16 > short.max ? '-' : '+');
		p.mnemonicBuffer.index += snprintf(bufptr, l, "0x%x", num.u16);
		return;
	case i32:
		p.mnemonicBuffer.add(num.u32 > int.max ? '-' : '+');
		p.mnemonicBuffer.index += snprintf(bufptr, l, "0x%x", num.u32);
		return;
	case i64:
		p.mnemonicBuffer.add(num.u64 > long.max ? '-' : '+');
		p.mnemonicBuffer.index += snprintf(bufptr, l, "0x%llx", num.u64);
		return;
	default: assert(0, __FUNCTION__);
	}
}
