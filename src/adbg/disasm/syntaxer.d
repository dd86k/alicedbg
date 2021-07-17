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
//TODO: option for hex offset prefix/suffix ($,h,0x)

//TODO: Figure out how to offset

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
///
/// All examples may feature a base register (eax), an additional register
/// (ecx), a displacement or offset (0x50 or 80), or a segment register (es).
package
enum AdbgSyntaxMemType : ubyte {
	/// Access with register.
	/// intel:
	/// 	---
	/// 	es:[eax]
	/// 	---
	/// nasm:
	/// 	---
	/// 	[es:eax]
	/// 	---
	/// att:
	/// 	---
	/// 	%es:(%eax)
	/// 	---
	register,
	/// Register with displacement.
	/// intel:
	/// 	---
	/// 	es:[eax+0x50]
	/// 	---
	/// nasm:
	/// 	---
	/// 	[es:eax+0x50]
	/// 	---
	/// att:
	/// 	---
	/// 	%es:0x50(%eax)
	/// 	---
	registerOffset,
	/// A memory location pointed by a register pair. (notably x86-16)
	/// intel:
	/// 	---
	/// 	es:[sp+ax]
	/// 	---
	/// nasm:
	/// 	---
	/// 	[es:sp+ax]
	/// 	---
	/// att:
	/// 	---
	/// 	%es:(%sp+%ax)
	/// 	---
	registerRegister,
	/// A memory location pointed by a register pair. (notably x86-16)
	/// intel:
	/// 	---
	/// 	es:[sp+ax+0x50]
	/// 	---
	/// nasm:
	/// 	---
	/// 	[es:sp+ax+0x50]
	/// 	---
	/// att:
	/// 	---
	/// 	%es:0x50(%sp+%ax)
	/// 	---
	/// intel: [sp+ax+0x50]
	/// att: 0x50(%sp+%ax)
	registerRegisterOffset,
	/// A far memory location pointed by a constant segment and register string.
	/// intel:
	/// 	---
	/// 	es:[0x50:eax]
	/// 	---
	/// nasm:
	/// 	---
	/// 	[es:0x50:eax]
	/// 	---
	/// att:
	/// 	---
	/// 	%es:(0x10:%eax)
	/// 	---
	far,
	/// Memory scale with BASE and INDEX registers + scale.
	/// x86: ModRM MOD=00 + SIB
	/// intel:
	/// 	---
	/// 	es:[eax+ecx*2]
	/// 	---
	/// nasm:
	/// 	---
	/// 	[es:eax+ecx*2]
	/// 	---
	/// att:
	/// 	---
	/// 	%es:(%eax,%ecx,2)
	/// 	---
	scaleBaseIndexScale,
	/// Memory scale with INDEX register.
	/// x86: ModRM MOD=00 + SIB INDEX=100
	/// intel:
	/// 	---
	/// 	es:[ecx]
	/// 	---
	/// nasm:
	/// 	---
	/// 	[es:ecx]
	/// 	---
	/// att:
	/// 	---
	/// 	%es:(,%ecx,)
	/// 	---
	scaleIndex,
	/// Memory scale with INDEX register + scale + offset.
	/// x86: ModRM MOD=01
	/// intel:
	/// 	---
	/// 	es:[ecx*2+0x50]
	/// 	---
	/// nasm:
	/// 	---
	/// 	[es:ecx*2+0x50]
	/// 	---
	/// att:
	/// 	---
	/// 	%es:0x50(,%ecx,2)
	/// 	---
	scaleIndexScaleOffset,
	/// Memory scale with offset only.
	/// x86: ModRM MOD=01 + SIB INDEX=100
	/// intel:
	/// 	---
	/// 	es:[0x50]
	/// 	---
	/// nasm:
	/// 	---
	/// 	[es:0x50]
	/// 	---
	/// att:
	/// 	---
	/// 	%es:0x50(,,)
	/// 	---
	scaleOffset,
	/// Memory scale with BASE and INDEX registers + scale.
	/// x86: ModRM MOD=10 + SIB
	/// intel:
	/// 	---
	/// 	es:[eax+ecx*2+0x50]
	/// 	---
	/// nasm:
	/// 	---
	/// 	[es:eax+ecx*2+0x50]
	/// 	---
	/// att:
	/// 	---
	/// 	%es:0x50(%eax,%ecx,2)
	/// 	---
	scaleBaseIndexScaleOffset,
	/// Memory scale with BASE register + offset.
	/// x86: ModRM MOD=10 + SIB INDEX=100
	/// intel:
	/// 	---
	/// 	es:[eax+0x50]
	/// 	---
	/// nasm:
	/// 	---
	/// 	[es:eax+0x50]
	/// 	---
	/// att:
	/// 	---
	/// 	%es:0x50(%eax,,)
	/// 	---
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
}

/// Memory operand
package
struct adbg_syntax_op_mem_t {
	AdbgSyntaxMemType type;	/// 
	const(char) *base;	/// Used for normal usage, otherwise SIB:BASE
	const(char) *index;	/// SIB:INDEX
	int disp;	/// Offset or SIB:OFFSET
	ubyte scale;	/// SIB:SCALE
	AdbgSyntaxWidth width;	/// Memory operation width
	AdbgSyntaxWidth size;	/// Offset size
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
	default:    return adbg_oops(AdbgError.invalidOptionValue);
	}
	p.syntax = syntax;
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
		p.machineBuffer.add(adbg_util_strx02(v, false));
	} else static if (is(T == ushort) || is(T == short)) {
		p.machineBuffer.add(adbg_util_strx04(v, false));
	} else static if (is(T == uint) || is(T == int)) {
		p.machineBuffer.add(adbg_util_strx08(v, false));
	} else static if (is(T == ulong) || is(T == long)) {
		p.machineBuffer.add(adbg_util_strx016(v, false));
	} else static if (is(T == float)) {
		union u32_t {
			uint u32;
			float f32;
		}
		u32_t u = void;
		u.f32 = v;
		p.machineBuffer.add(adbg_util_strx04(u.u32, false));
	} else static if (is(T == double)) {
		union u64_t {
			ulong u32;
			double f32;
		}
		u64_t u = void;
		u.f64 = v;
		p.machineBuffer.add(adbg_util_strx08(u.u64, false));
	} else static assert(0, "adbg_syntax_add_machine: Type not supported");
	
	if (p.userOpts.machinePacked == false)
		p.machineBuffer.add(' ');
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
// ANCHOR Operand operations
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

// register type

package
void adbg_syntax_add_register(ref adbg_syntaxer_t p, const(char) *register) {
	if (p.opIndex >= ADBG_MAX_OPERANDS)
		return;
	
	adbg_syntax_op_t *item = &p.op[p.opIndex++];
	item.type = AdbgSyntaxType.register;
	item.reg.name = register;
}

// memory type
//TODO: Think if a smart structure constructor is better than this...
//      Make it variadic (compile-time?) or just C-like variadic?
//      Smartly configure the operand within ctor?

package
void adbg_syntax_add_memory_register(ref adbg_syntaxer_t p, AdbgSyntaxWidth width,
	const(char) *register) {
	if (p.opIndex >= ADBG_MAX_OPERANDS)
		return;
	
	adbg_syntax_op_t *item = &p.op[p.opIndex++];
	item.type = AdbgSyntaxType.memory;
	item.mem.type = AdbgSyntaxMemType.register;
	item.mem.width = width;
	item.mem.base = register;
}

package
void adbg_syntax_add_memory_register_offset(ref adbg_syntaxer_t p, AdbgSyntaxWidth width,
	const(char) *register, int offset) {
	if (p.opIndex >= ADBG_MAX_OPERANDS)
		return;
	
	adbg_syntax_op_t *item = &p.op[p.opIndex++];
	item.type = AdbgSyntaxType.memory;
	item.mem.type = AdbgSyntaxMemType.registerOffset;
	item.mem.width = width;
	item.mem.base = register;
	item.mem.disp = offset;
}

package
void adbg_syntax_add_memory_register_register(ref adbg_syntaxer_t p, AdbgSyntaxWidth width,
	const(char) *register1, const(char) *register2) {
	if (p.opIndex >= ADBG_MAX_OPERANDS)
		return;
	
	adbg_syntax_op_t *item = &p.op[p.opIndex++];
	item.type = AdbgSyntaxType.memory;
	item.mem.width = width;
	item.mem.type = AdbgSyntaxMemType.registerRegister;
	item.mem.base = register1;
	item.mem.index = register2;
}

package
void adbg_syntax_add_memory_register_register_offset(ref adbg_syntaxer_t p, AdbgSyntaxWidth width,
	const(char) *register1, const(char) *register2, int offset) {
	if (p.opIndex >= ADBG_MAX_OPERANDS)
		return;
	
	adbg_syntax_op_t *item = &p.op[p.opIndex++];
	item.type = AdbgSyntaxType.memory;
	item.mem.width = width;
	item.mem.type = AdbgSyntaxMemType.registerRegisterOffset;
	item.mem.base = register1;
	item.mem.index = register2;
	item.mem.disp = offset;
}

//
// ANCHOR Rendering
//

// render whole mnemonic line, called automatically from disasm
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
	
	if (p.opIndex == 0)	// No operands
		return;
	
	// Operands
	p.mnemonicBuffer.add(p.userOpts.mnemonicTab ? '\t' : ' ');
	
	with (AdbgSyntax)
	switch (p.syntax) {
	case intel, nasm:
		--p.opIndex;
		for (size_t i; i <= p.opIndex; ++i) {
			p.handler(p, p.op[i]);
			if (i < p.opIndex)
				p.mnemonicBuffer.add(',');
		}
		return;
	default:
		for (size_t i = p.opIndex - 1; i; --i) {
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
