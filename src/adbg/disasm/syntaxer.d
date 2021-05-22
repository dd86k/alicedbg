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

private import adbg.error;
private import adbg.utils.str : sbuffer_t;

/// Syntax buffer size in items
package enum ADBG_SYNTAX_MAX_ITEMS = 8;
/// String buffer sizes in bytes
private enum ADBG_SYNTAX_BUFFER_LENGTH = 64;

/// Assembler syntax
enum AdbgSyntax : ubyte {
	/// Platform compiled default for target.
	platform,
	/// Intel syntax, similar to Microsoft/Macro Assembler (MASM).
	/// Example:
	/// ---
	/// mov ecx, dword ptr ss:[ebp-14]
	/// ---
	intel,
	/// AT&T syntax.
	/// Example:
	/// ---
	/// mov ss:-14(%ebp), %ecx
	/// ---
	att,
	/// Netwide Assembler syntax (NASM).
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

/// 
package
enum AdbgSyntaxWidth : ubyte {
	i8, i16, i32, i64, i128, i256, i512, i1024
}

/// 
package
enum AdbgSyntaxItem : ubyte {
	/// An instruction mnemonic.
	mnemonic,	// add
	/// An instruction prefix.
	prefix,	// lock
	/// A constant value.
	immediate,	// 0xff
	/// 
	immediateNear,	// 0x10:0x1000 / $0x10:0x1000
	/// A register string.
	register,	// eax
	/// A IEEE 754 80-bit register index and string.
	// base register index
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
struct adbg_syntax_item_t { align(1):
	AdbgSyntaxItem type;	/// operand type
	AdbgSyntaxWidth width;	/// immediate or memory width
	union {
		ushort optall;
		struct {
			bool signed;
		}
	}
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
	//
	// Internal fields
	//
	/// Item index.
	size_t index;
	/// Item buffer.
	adbg_syntax_item_t[ADBG_SYNTAX_MAX_ITEMS] buffer;
	/// Segment for instruction.
	/// Affects memory operands, if the syntax supports it.
	const(char) *segment;
	/// Decoder formatting options.
	adbg_syntaxter_decoder_options_t decoderOpts;
	/// User formatting options.
	adbg_syntaxter_user_options_t userOpts;
	/// Syntax item handler.
	void function(adbg_syntax_t*, adbg_syntax_item_t*) handler;
	/// Machine buffer.
	sbuffer_t!(ADBG_SYNTAX_BUFFER_LENGTH) machine;
	/// Mnemonic buffer.
	sbuffer_t!(ADBG_SYNTAX_BUFFER_LENGTH) mnemonic;
	/// Disassembly comment.
	const(char) *comment;
	/// Current syntax option.
	AdbgSyntax syntax;
}

// init structure
int adbg_syntax_init(adbg_syntax_t *p, AdbgSyntax syntax) {
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
	p.segment = null;
	return 0;
}

// reset structure
void adbg_syntax_reset(adbg_syntax_t *p) {
	p.index = 0;
	p.machine.index = 0;
	p.mnemonic.index = 0;
}

//
// ANCHOR Internal utils
//

private
bool adbg_syntax_select(adbg_syntax_t *p, adbg_syntax_item_t **item) {
	if (p.index >= ADBG_SYNTAX_MAX_ITEMS)
		return true;
	
	*item = &p.buffer[p.index++];
	return false;
}

//
// ANCHOR Machine buffer
//

// adds to machine buffer
package
void adbg_syntax_add_machine(T)(adbg_syntax_t *p, T v) {
	import adbg.utils.str :
		adbg_util_strx02, adbg_util_strx04,
		adbg_util_strx08, adbg_util_strx016;
	
	static if (is(T == ubyte) || is(T == byte)) {
		p.mnemonic.add(adbg_util_strx02(v, false));
	} else static if (is(T == ushort) || is(T == short)) {
		p.mnemonic.add(adbg_util_strx04(v, false));
	} else static if (is(T == uint) || is(T == int)) {
		p.mnemonic.add(adbg_util_strx08(v, false));
	} else static if (is(T == ulong) || is(T == long)) {
		p.mnemonic.add(adbg_util_strx016(v, false));
	} else static if (is(T == float)) {
		union u32_t {
			uint u32;
			float f32;
		}
		u32_t u = void;
		u.f32 = v;
		p.mnemonic.add(adbg_util_strx04(u.u32, false));
	} else static if (is(T == double)) {
		union u64_t {
			ulong u32;
			double f32;
		}
		u64_t u = void;
		u.f64 = v;
		p.mnemonic.add(adbg_util_strx08(u.u64, false));
	} else static assert(0, "adbg_syntax_add_machine: Type not supported");
	
	if (p.userOpts.machinePacked == false)
		p.mnemonic.add(' ');
}

//
// ANCHOR Mnemonic buffer
//

// adds prefix
package
void adbg_syntax_add_prefix(adbg_syntax_t *p, const(char) *prefix) {
	adbg_syntax_item_t *item = void;
	if (adbg_syntax_select(p, &item))
		return;
	
	item.type = AdbgSyntaxItem.prefix;
	item.svalue = prefix;
}

// adds mnemonic instruction
package
void adbg_syntax_add_mnemonic(adbg_syntax_t *p, const(char) *mnemonic) {
	adbg_syntax_item_t *item = void;
	if (adbg_syntax_select(p, &item))
		return;
	
	item.type = AdbgSyntaxItem.mnemonic;
	item.svalue = mnemonic;
}

// adds register name
package
void adbg_syntax_add_register(adbg_syntax_t *p, const(char) *register) {
	adbg_syntax_item_t *item = void;
	if (adbg_syntax_select(p, &item))
		return;
	
	item.type = AdbgSyntaxItem.register;
	item.svalue = register;
}

// adds immediate
package
void adbg_syntax_add_immediate(T)(adbg_syntax_t *p, T v) {
	adbg_syntax_item_t *item = void;
	if (adbg_syntax_select(p, &item))
		return;
	
	//TODO: Template mixin
	static if (T.sizeof == ubyte.sizeof) {
		item.width = AdbgSyntaxWidth.i8;
		item.iu8 = v;
	} else static if (T.sizeof == ushort.sizeof) {
		item.width = AdbgSyntaxWidth.i16;
		item.iu16 = v;
	} else static if (T.sizeof == uint.sizeof) {
		item.width = AdbgSyntaxWidth.i32;
		item.iu32 = v;
	} else static if (T.sizeof == ulong.sizeof) {
		item.width = AdbgSyntaxWidth.i64;
		item.iu64 = v;
	} else static assert(0, __FUNCTION__~": Type not supported");
}

//
// ANCHOR Rendering
//

// render whole line
package
void adbg_syntax_render(adbg_syntax_t *p) {
	with (AdbgSyntax)
	switch (p.syntax) {
	case intel, nasm:
	
		return;
	default:
	
		return;
	}
}

// render immediate hexadecimal to mnemonic buffer
package
void adbg_syntax_render_immediate_hex(adbg_syntax_t *p, adbg_syntax_item_t *item) {
	import adbg.utils.str :
		adbg_util_strx02, adbg_util_strx04,
		adbg_util_strx08, adbg_util_strx016;
	
	p.mnemonic.add("0x");
	const(char) *v = void;
	with (AdbgSyntaxWidth)
	switch (item.width) {
	case i8:
		v = adbg_util_strx02(item.iu8, false);
		break;
	case i16:
		v = adbg_util_strx04(item.iu16, false);
		break;
	case i32:
		v = adbg_util_strx08(item.iu32, false);
		break;
	case i64:
		v = adbg_util_strx016(item.iu16, false);
		break;
	default: assert(0, __FUNCTION__);
	}
	p.mnemonic.add(v);
}
