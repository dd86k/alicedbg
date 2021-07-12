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
private import adbg.disasm : AdbgSyntax;
//TODO: Deprecate?
private import core.stdc.stdarg;
private import adbg.utils.str : sbuffer_t;

extern (C):

/// Buffer size for prefixes.
private enum ADBG_MAX_PREFIXES = 4;
/// Buffer size for operands.
private enum ADBG_MAX_OPERANDS = 4;
/// String buffer sizes in bytes
private enum ADBG_SYNTAX_BUFFER_LENGTH = 64;

/// Memory width
package
enum AdbgSyntaxWidth : ubyte {
	i8, i16, i32, i64, i128, i256, i512, i1024
}

/// Operand type.
package
enum AdbgSyntaxType : ubyte {
	immediate,	/// 
	register,	/// 
	memory,	/// 
}

/// Memory immediate types
package
enum AdbgSyntaxImmType : ubyte {
	absolute,	/// 
	relative,	/// 
	signed = relative,	/// 
	far	/// 
}

/// Memory operand layouts
package
enum AdbgSyntaxMemType : ubyte {
	/// Access with register.
	// intel: [eax]
	// att: (eax)
	register,
	/// Register with displacement.
	// intel: [eax+0xff]
	// att: 0xff(%eax)
	registerOffset,
	/// A memory location pointed by a register pair. (notably x86-16)
	// intel: [sp+ax]
	// att: (%sp,%ax)
	registerRegisterOffset,
	/// A far memory location pointed by a constant segment and register string.
	// intel: [0x10:eax]
	// att: (0x10:%eax)
	far,
	/// Memory scale with BASE and INDEX registers + scale.
	/// x86: ModRM MOD=00 + SIB
	// intel: [eax+ecx*2]
	// att: (%eax,%ecx,2)
	scaleBaseIndexScale,
	/// Memory scale with INDEX register.
	/// x86: ModRM MOD=00 + SIB INDEX=100
	// intel: [ecx]
	// att: (,%ecx,)
	scaleIndex,
	/// Memory scale with INDEX register + scale + offset.
	/// x86: ModRM MOD=01
	// intel: es:[ecx*2+0x50]
	// att: %es:0x50(,%ecx,2)
	scaleIndexScaleOffset,
	/// Memory scale with offset only.
	/// x86: ModRM MOD=01 + SIB INDEX=100
	// intel: [0x50]
	// att: 0x50(,,)
	scaleOffset,
	/// Memory scale with BASE and INDEX registers + scale.
	/// x86: ModRM MOD=10 + SIB
	// intel: [eax+ecx*2+0x50]
	// att: 0x50(%eax,%ecx,2)
	scaleBaseIndexScaleOffset,
	/// Memory scale with BASE register + offset.
	/// x86: ModRM MOD=10 + SIB INDEX=100
	// intel: [eax+0x50]
	// att:  0x50(%eax,,)
	scaleBaseOffset,
}

package
struct adbg_syntax_op_imm_t {
	AdbgSyntaxImmType type;
	uint value;
	ushort segment;
}

/// Immediate operand
package
struct adbg_syntax_op_imm64_t {
	ulong value;
}

/// Register operand
package
struct adbg_syntax_op_reg_t {
	const(char) *name;
	byte index;
	bool isReal;	/// x87/80-bit type
}

/// Memory operand
package
struct adbg_syntax_op_mem_t {
	AdbgSyntaxMemType type;	/// 
	const(char) *base;	/// Used for normal usage, otherwise SIB:BASE
	const(char) *index;	/// SIB:INDEX
	uint disp;	/// Offset or SIB:OFFSET
	ubyte scale;	/// SIB:SCALE
	AdbgSyntaxWidth width;	/// Memory operation width
}

/// Operand structure
package
struct adbg_syntax_op_t { align(1):
	AdbgSyntaxType type;	/// Operand type
	union {
		adbg_syntax_op_imm_t imm;	/// Immediate item
		adbg_syntax_op_imm64_t imm64;	/// Long immediate item
		adbg_syntax_op_reg_t reg;	/// Register item
		adbg_syntax_op_mem_t mem;	/// Memory operand item
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
package
struct adbg_syntaxer_t { align(1):
	
	// Operands
	
	/// Current index for operands items. Also serves as item count.
	size_t opIndex;
	/// Operand items.
	adbg_syntax_op_t[ADBG_MAX_OPERANDS] op;
	
	// Prefixes
	
	/// Current index for prefixes items. Also serves as item count.
	size_t pfIndex;
	/// Prefixe items.
	const(char)*[ADBG_MAX_PREFIXES] pf;
	
	// Mnemonic
	
	/// Instruction mnemonic set by the platform.
	const(char) *mnemonicInstruction;
	
	// Segment, if supported
	
	/// Segment for instruction. Affects memory operands.
	/// Pushed by supported platforms.
	const(char) *segmentRegister;
	
	// Buffers
	
	/// Syntax item handler.
	void function(ref adbg_syntaxer_t, ref adbg_syntax_op_t) handler;
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
int adbg_syntax_init(ref adbg_syntaxer_t p, AdbgSyntax syntax) {
	import adbg.disasm.syntax.intel : adbg_syntax_op_intel;
	import adbg.disasm.syntax.nasm : adbg_syntax_op_nasm;
	import adbg.disasm.syntax.att : adbg_syntax_op_att;
	with (AdbgSyntax)
	switch (syntax) {
	case intel: p.handler = &adbg_syntax_op_intel; break;
	case nasm:  p.handler = &adbg_syntax_op_nasm; break;
	case att:   p.handler = &adbg_syntax_op_att; break;
	default:    return adbg_error(AdbgError.invalidOptionValue);
	}
	p.decoderOpts.all = 0;
	p.userOpts.all = 0;
	return 0;
}

// reset structure for prep work
package
void adbg_syntax_reset(ref adbg_syntaxer_t p) {
	p.machineBuffer.index = 0;
	p.mnemonicBuffer.index = 0;
	p.opIndex = 0;
	p.pfIndex = 0;
	p.segmentRegister = null;
	p.mnemonicInstruction = null;
}

//
// ANCHOR Machine buffer
//

// adds to machine buffer
package
void adbg_syntax_add_machine(T)(ref adbg_syntaxer_t p, T v) {
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
void adbg_syntax_add_prefix(ref adbg_syntaxer_t p, const(char) *prefix) {
	if (p.pfIndex >= ADBG_MAX_PREFIXES)
		return;
	
	p.pf[p.pfIndex++] = prefix;
}

//
// ANCHOR Mnemonic instruction
//

// set instruction mnemonic
package
void adbg_syntax_add_mnemonic(ref adbg_syntaxer_t p, const(char) *instruction) {
	p.mnemonicInstruction = instruction;
}


//
// ANCHOR Segment register
//

// set segment register
package
void adbg_syntax_add_segment(ref adbg_syntaxer_t p, const(char) *segment) {
	p.segmentRegister = segment;
}

//
// ANCHOR Operands
//

// immediate type
package
void adbg_syntax_add_immediate(ref adbg_syntaxer_t p, uint v) {
	if (p.opIndex >= ADBG_MAX_OPERANDS)
		return;
	
	adbg_syntax_op_t *item = &p.op[p.opIndex++];
	item.type = AdbgSyntaxType.immediate;
	item.imm.value = v;
}

// immediateFar type

// register type
package
void adbg_syntax_add_register(ref adbg_syntaxer_t p, const(char) *register) {
	if (p.opIndex >= ADBG_MAX_OPERANDS)
		return;
	
	adbg_syntax_op_t *item = &p.op[p.opIndex++];
	item.type = AdbgSyntaxType.register;
	item.reg.isReal = false;
	item.reg.name = register;
}

// realRegister type
package
void adbg_syntax_add_realRegister(ref adbg_syntaxer_t p, const(char) *register, int index) {
	
}

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
void adbg_syntax_render(ref adbg_syntaxer_t p) {
	// Prefixes
	if (p.decoderOpts.noPrefixes == false && p.pfIndex) {
		--p.pfIndex;
		for (size_t i; i <= p.pfIndex; ++i) {
			p.mnemonicBuffer.add(p.pf[i]);
			if (i < p.pfIndex)
				p.mnemonicBuffer.add(' ');
		}
	}
	
	
	// Mnemonic
	p.mnemonicBuffer.add(p.mnemonicInstruction);
	
	if (p.opIndex == 0)
		return;
	
	// Operands
	p.mnemonicBuffer.add(p.userOpts.mnemonicTab ? '\t' : ' ');
	with (AdbgSyntax)
	switch (p.syntax) {
	case intel, nasm:
		size_t sepmin = p.opIndex - 1;
		for (size_t i; i < p.opIndex; ++i) {
			p.handler(p, p.op[i]);
			if (i < sepmin)
				p.mnemonicBuffer.add(',');
		}
		return;
	default:
		for (size_t i = p.opIndex - 1; i > 0; --i) {
			p.handler(p, p.op[i]);
			if (i > 1)
				p.mnemonicBuffer.add(',');
		}
		return;
	}
}

// render immediate hexadecimal
/*package
void adbg_syntax_render_offset(ref adbg_syntaxer_t p, ref adbg_syntax_number_t num) {
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
}*/
