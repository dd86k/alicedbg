/**
 * Disassembler syntax engine.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.disasm.syntaxer;

import adbg.error;
import adbg.utils.str : sbuffer_t;

package enum ADBG_SYNTAX_MAX_ITEMS = 8;
private enum ADBG_SYNTAX_BUFFER_LENGTH = 64;

/// Assembler syntax
enum AdbgSyntax : ubyte {
	platform,	/// Platform compiled default for target
	intel,	/// Intel syntax, similar to Microsoft/Macro Assembler (MASM)
	nasm,	/// Netwide Assembler syntax (NASM)
	att,	/// AT&T syntax
//	arm,	/// (TODO) ARM native syntax
//	riscv,	/// (TODO) RISC-V native syntax
//	ideal,	/// (TODO) Borland Ideal (enhanced mode of TASM)
//	hyde,	/// (TODO) Randall Hyde High Level Assembly Language
}
package
enum AdbgSyntaxWidth : ubyte {
	i8, i16, i32, i64, i128, i256, i512, i1024,
	i80, far1616, far1632, far1664
}
package
enum AdbgSyntaxItem : ubyte {
	/// Instruction mnemonic
	mnemonic,	// add
	/// Instruction prefix
	prefix,	// lock
	///
	immediate,	// 0xff
	/// Register
	register,	// eax
	/// 
	memory,	// [0x10]
	/// 
	memoryFar,	// [0x10:0x1000]
	/// 
	memoryRegister,	// [eax]
	/// 
	memoryFarRegister,	// [0x10:eax]
	/// 
	memoryRegisterOffset,	// [eax+0xff]
	/// (SIB) x86: SIB MOD=00
	memoryScaleBaseIndexScale,	// [eax+ecx*2] / (eax,ecx,2)
	/// (SIB) x86: SIB MOD=00 I=100
	memoryScaleBase,	// [eax] / (,ecx,)
	/// (SIB) x86: SIB MOD=01
	memoryScaleIndexScaleOffset,	// [ecx*2+0x50] / 0x50(,ecx,2)
	/// (SIB) x86: SIB MOD=01 I=100
	memoryScaleOffset,	// [0x50] / 0x50(,,)
	/// (SIB) x86: SIB MOD=10
	memoryScaleBaseIndexScaleOffset,	// [eax+ecx*2+0x50] / 0x50(eax,ecx,2)
	/// (SIB) x86: SIB MOD=10 I=100
	memoryScaleBaseOffset,	// [eax+0x50] / 0x50(eax,,)
}

private
struct adbg_syntax_item_MF_t { // Far
	ushort segment;
	union {
		ulong u64;
		uint u32;
		ushort u16;
	}
}
private
struct adbg_syntax_item_MFR_t { // FarRegister
	ushort segment;
	const(char) *register;
}
private
struct adbg_syntax_item_MRO_t { // RegisterOffset
	const(char) *register;
	union {
		ulong u64;
		uint u32;
		ushort u16;
	}
}
private
struct adbg_syntax_item_MSBIS_t { // ScaleBaseIndexScale
	const(char)* base, index;
	ubyte scale;
}
private
struct adbg_syntax_item_MSISO_t { // ScaleIndexScaleOffset
	const(char)* index;
	uint offset;
	ubyte scale;
}
private
struct adbg_syntax_item_MSBO_t { // ScaleBaseOffset
	const(char)* base;
	uint offset;
}

package
struct adbg_syntax_item_t {
	AdbgSyntaxItem type;	/// operand type
	AdbgSyntaxWidth width;	/// immediate or memory width
	union {
		// 1 item
		ulong iu64;	/// 64-bit unsigned value
		long is64;	/// 64-bit signed value
		uint iu32;	/// 32-bit unsigned value
		int is32;	/// 32-bit signed value
		ushort iu16;	/// 16-bit unsigned value
		short is16;	/// 16-bit signed value
		ubyte iu8;	/// 8-bit unsigned value
		byte is8;	/// 8-bit signed value
		const(char) *svalue;	/// register/prefix/mnemonic
		// 2+ items
		adbg_syntax_item_MF_t mf;	/// MemoryFar
		adbg_syntax_item_MFR_t mfr;	/// MemoryFarRegister
		adbg_syntax_item_MRO_t mro;	/// MemoryRegisterOffset
		// scale items
		adbg_syntax_item_MSBIS_t msbis;	/// ScaleBaseIndexScale
		adbg_syntax_item_MSISO_t msiso;	/// ScaleIndexScaleOffset
		adbg_syntax_item_MSBO_t msbo;	/// ScaleBaseOffset
	}
}
private
struct adbg_syntaxter_decoder_options_t { align(1):
	union {
		uint all;	/// Unset when initiated
		struct {
			/// memory operation width
			/// Automatically set when a memory operand is pushed.
			AdbgSyntaxWidth memWidth;
			/// Under x86, some prefixes like LOCK can sometimes be
			/// printed, or not, depending on the instruction.
			/// If set, the prefixes are not included in the output.
			bool noPrefixes;
			/// (AT&T syntax) if mnemonic is basic for width modifier
			/// If set, this mnemonic can be 
			bool primitive;
		}
	}
}
private
struct adbg_syntaxter_user_options_t { align(1):
	union {
		//TODO: Consider "addresses as decimal" option
		//TODO: Consider "immediates as decimal" option
		//TODO: Consider "pack machine opcodes" option
		//TODO: Consider "unpack immediate opcodes" option
		uint all;	/// Unset when initiated
		struct {
			/// If set, inserts a tab instead of a space between mnemonic and operands.
			bool mnemonicTab;
		}
	}
}
/// Syntax engine structure
struct adbg_syntax_t { align(1):
	/// Item index
	size_t index;
	/// Segment for instruction.
	/// Affects memory operands, if the syntax supports it.
	const(char) *segment;
	/// Decoder formatting options
	adbg_syntaxter_decoder_options_t decoderOpts;
	/// User formatting options
	adbg_syntaxter_user_options_t userOpts;
	/// Syntax handler
	int function(adbg_syntax_t*) handler;
	/// Item buffer
	adbg_syntax_item_t[ADBG_SYNTAX_MAX_ITEMS] buffer;
	/// 
	sbuffer_t!(ADBG_SYNTAX_BUFFER_LENGTH) machine;
	/// 
	sbuffer_t!(ADBG_SYNTAX_BUFFER_LENGTH) mnemonic;
	/// 
	AdbgSyntax syntax;
}

// init
int adbg_syntax_init(adbg_syntax_t *p, AdbgSyntax syntax) {
	import adbg.disasm.syntax.intel : adbg_syntax_intel_start;
	import adbg.disasm.syntax.nasm : adbg_syntax_nasm_start;
	import adbg.disasm.syntax.att : adbg_syntax_att_start;
	with (AdbgSyntax)
	switch (syntax) {
	case intel:
		p.handler = &adbg_syntax_intel_start;
		break;
	case nasm:
		p.handler = &adbg_syntax_nasm_start;
		break;
	case att:
		p.handler = &adbg_syntax_att_start;
		break;
	default:
		return adbg_error(AdbgError.invalidOptionValue);
	}
	p.decoderOpts.all = 0;
	p.userOpts.all = 0;
	p.segment = null;
	return 0;
}

// reset
void adbg_syntax_reset(adbg_syntax_t *p) {
	p.index = 0;
}

private
bool adbg_syntax_select(adbg_syntax_t *p, adbg_syntax_item_t **item) {
	if (p.index >= ADBG_SYNTAX_MAX_ITEMS)
		return true;
	
	size_t index = p.index;
	*item = &p.buffer[index];
	p.index = ++index;
	return false;
}

// adds to machine buffer
void adbg_syntax_add_machine(T)(adbg_syntax_t *p, T opcode) {
	import adbg.utils.str :
		adbg_util_strx02, adbg_util_strx04,
		adbg_util_strx08, adbg_util_strx016;
	union u_t {
		ulong u64;
		long i64;
		uint u32;
		int i32;
		ushort u16;
		short i16;
		ubyte u8;
		byte i8;
		float f32;
		double f64;
	}
//	u_t u = void;
	static if (is(T == ubyte) || is(T == byte))
	{
		p.mnemonic.add(adbg_util_strx02(opcode, false));
	}
	else static if (is(T == ushort) || is(T == short))
	{
		p.mnemonic.add(adbg_util_strx04(opcode, false));
	}
	else static if (is(T == uint) || is(T == int))
	{
		p.mnemonic.add(adbg_util_strx08(opcode, false));
	}
	else static if (is(T == ulong) || is(T == long))
	{
		p.mnemonic.add(adbg_util_strx016(opcode, false));
	}
	/*else static if (is(T == float))
	{
		p.mnemonic.add(adbg_util_strx04(opcode, false));
	}
	else static if (is(T == double))
	{
		p.mnemonic.add(adbg_util_strx04(opcode, false));
	}*/
	else static assert(0, "Type not supported");
}

// adds prefix
void adbg_syntax_add_prefix(adbg_syntax_t *p, const(char) *prefix) {
	adbg_syntax_item_t *item = void;
	if (adbg_syntax_select(p, &item))
		return;
	
	item.type = AdbgSyntaxItem.prefix;
	item.svalue = prefix;
}

// adds mnemonic instruction
void adbg_syntax_add_mnemonic(adbg_syntax_t *p, const(char) *mnemonic) {
	adbg_syntax_item_t *item = void;
	if (adbg_syntax_select(p, &item))
		return;
	
	item.type = AdbgSyntaxItem.mnemonic;
	item.svalue = mnemonic;
}

// adds register name
void adbg_syntax_add_register(adbg_syntax_t *p, const(char) *register) {
	adbg_syntax_item_t *item = void;
	if (adbg_syntax_select(p, &item))
		return;
	
	item.type = AdbgSyntaxItem.register;
	item.svalue = register;
}

// adds to machine buffer
void adbg_syntax_add_immediate(T)(adbg_syntax_t *p, T opcode) {
	import adbg.utils.str :
		adbg_util_strx02, adbg_util_strx04,
		adbg_util_strx08, adbg_util_strx016;
	p.mnemonic.add("0x");
	static if (is(T == ubyte) || is(T == byte))
	{
		p.mnemonic.add(adbg_util_strx02(opcode, false));
	}
	else static if (is(T == ushort) || is(T == short))
	{
		p.mnemonic.add(adbg_util_strx04(opcode, false));
	}
	else static if (is(T == uint) || is(T == int))
	{
		p.mnemonic.add(adbg_util_strx08(opcode, false));
	}
	else static if (is(T == ulong) || is(T == long))
	{
		p.mnemonic.add(adbg_util_strx016(opcode, false));
	}
	else static if (is(T == float))
	{
		union u32_t {
			uint u32;
			float f32;
		}
		u32_t u = void;
		u.f32 = opcode;
		p.mnemonic.add(adbg_util_strx04(u.u32, false));
	}
	else static if (is(T == double))
	{
		union u64_t {
			ulong u64;
			double f64;
		}
		u64_t u = void;
		u.f64 = opcode;
		p.mnemonic.add(adbg_util_strx04(u.u64, false));
	}
	else static assert(0, "Type not supported");
}


