/**
 * Disassembler formatting engine.
 *
 * The formatting engine is designed to format any given pieces of string from
 * the decoder in a given order by the style setting.
 *
 * This module adbg.provides the item and style formatting for the disassembler. The
 * decoder (disassembler) pushes items with their respective types (e.g.
 * register, immediate, etc.) and the formatter takes take of rendering
 * the final result. Values are referenced (i.e. strings), not copied. For
 * example, adbg_dasm_push_reg pushes a register string value.
 *
 * Each item in the stack are processed from first to last (left to right),
 * typically begining with the mnemonic instruction, then usually an immediate,
 * memory reference, or register, to finally be formatted using their respected
 * formatting function (e.g. a register string is passed through
 * adbg_dasm_fmt_reg).
 *
 * The operand ordering is INSTRUCTION TARGET, SOURCE (Intel), this is
 * important to know since this behavior is affected by the disassembler
 * syntax setting (e.g. At&t vs. Intel/Nasm/Masm). This behavior can be
 * bypassed with the FORMATTER_O_NO_DIRECTION formatter setting if the style
 * does not affect the operand ordering.
 *
 * Machine code and mnemonic items are processed differently. The machine code
 * items are immediately processed upon arrival onto the string buffer, so
 * machine code and mnemonic items can be pushed in any order, only the
 * mnemonic items use the formatter's stack.
 *
 * License: BSD 3-Clause
 */
module adbg.debugger.disasm.formatter;

import core.stdc.stdarg;
import adbg.debugger.disasm.core;
import adbg.utils.str;

//TODO: New type: Prefix -- Next thing to print would be a space, not comma

extern (C):

/// Formatter item stack size
enum FORMATTER_STACK_SIZE = 8;
/// Formatter stack limit (size - 1)
enum FORMATTER_STACK_LIMIT = FORMATTER_STACK_SIZE - 1;

//
// Formatter options for decoder
//

/// Items will be processed in order regardless of style
enum FORMATTER_O_NO_DIRECTION = 1;
/// (Not implemented) Second separator will be a space (" ") instead of a comma (", ").
/// Very useful for instruction prefixes such as LOCK (x86)
enum FORMATTER_O_PREFIX = 2;

//TODO: Make MemMem type (0000:0000)
//TODO: Hexadecimal format setting (with width?)
/// Item type, each item more or less has their own formatting function
enum FormatType {
	String,	/// Pure string
	Reg,	/// Register spec
	SegReg,	/// Register spec
	Imm,	/// Immediate spec
	Mem,	/// Memory spec
	MemReg,	/// Memory with Register
	MemSegReg,	/// Memory with Segment/Extra Register and Register
	MemRegImm,	/// Memory with Register and Immediate
	MemSegRegImm,	/// Memory with Extra Register, Register, and Immediate
	x86_SIB_MemSegBaseIndexScale,	/// x86: SIB MOD=00 format
	x86_SIB_MemSegBase,	/// x86: SIB MOD=00 I=100 format
	x86_SIB_MemSegIndexScaleImm,	/// x86: SIB MOD=00 B=101 format
	x86_SIB_MemSegImm,	/// x86: SIB MOD=00 I=100 B=101 format
	x86_SIB_MemSegBaseIndexScaleImm,	/// x86: SIB MOD=01/10 format
	x86_SIB_MemSegBaseImm,	/// x86: SIB MOD=01/10 I=100 format
}

/// Format item structure. Can hold up to 3 integer and 3 string values.
struct disasm_fmt_item_t {
	FormatType type;	/// Item type, see FormatType structure
	int ival1;	/// Integer value 1
	int ival2;	/// Integer value 2
	int ival3;	/// Integer value 3
	const(char) *sval1;	/// String value 1
	const(char) *sval2;	/// String value 2
	const(char) *sval3;	/// String value 3
}
/// Formatter structure embedded into the disassembler structure
struct disasm_fmt_t { align(1):
	disasm_fmt_item_t [FORMATTER_STACK_SIZE]items;	/// Stack
	size_t itemno;	/// Current item number
	/// Formatter settings for current stack/instruction (from decoder)
	ushort settings;
}

/// Default string for illegal instructions
private
__gshared const(char) *DISASM_FMT_ERR_STR	= "(bad)";
private
__gshared const(char) *DISASM_FMT_SPACE	= " ";
private
__gshared const(char) *DISASM_FMT_TAB	= "\t";
private
__gshared const(char) *DISASM_FMT_COMMA_SPACE	= ", ";

//
// Machine code functions
//

/// Push an 8-bit value into the machine code buffer.
/// Params:
/// 	p = Disassembler parameters
/// 	v = 8-bit value
void adbg_dasm_push_x8(disasm_params_t *p, ubyte v) {
	adbg_dasm_xadd(p, adbg_util_strx02(v));
	if ((p.options & DISASM_O_MC_NOSPACE) == 0)
		adbg_dasm_xadd(p, DISASM_FMT_SPACE);
}
/// Push an 16-bit value into the machine code buffer.
/// Params:
/// 	p = Disassembler parameters
/// 	v = 16-bit value
void adbg_dasm_push_x16(disasm_params_t *p, ushort v) {
	adbg_dasm_xadd(p, adbg_util_strx04(v));
	if ((p.options & DISASM_O_MC_NOSPACE) == 0)
		adbg_dasm_xadd(p, DISASM_FMT_SPACE);
}
/// Push an 32-bit value into the machine code buffer.
/// Params:
/// 	p = Disassembler parameters
/// 	v = 32-bit value
void adbg_dasm_push_x32(disasm_params_t *p, uint v) {
	adbg_dasm_xadd(p, adbg_util_strx08(v));
	if ((p.options & DISASM_O_MC_NOSPACE) == 0)
		adbg_dasm_xadd(p, DISASM_FMT_SPACE);
}
/// Push an 64-bit value into the machine code buffer.
/// Params:
/// 	p = Disassembler parameters
/// 	v = 64-bit value
void adbg_dasm_push_x64(disasm_params_t *p, ulong v) {
	adbg_dasm_xadd(p, adbg_util_strx016(v));
	if ((p.options & DISASM_O_MC_NOSPACE) == 0)
		adbg_dasm_xadd(p, DISASM_FMT_SPACE);
}

//
// Pushing functions
//

//TODO: Consider renaming the push names
//      e.g. memsegregimm to msri

/// Push a string value into the formatting stack. This is printed as-is.
/// Params:
/// 	p = Disassembler parameters
/// 	v = String value
void adbg_dasm_push_str(disasm_params_t *p, const(char) *v) {
	disasm_fmt_item_t *i = adbg_dasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.String;
	i.sval1 = v;
}
/// Format and format a string into the formatting stack. This is printed as-is.
/// Params:
/// 	p = Disassembler parameters
/// 	f = String format
///     ... = Arguments
void adbg_dasm_push_strf(disasm_params_t *p, const(char) *f, ...) {
	disasm_fmt_item_t *i = adbg_dasm_fmt_select(p);
	if (i == null) return;
	va_list va;
	va_start(va, f);
	i.type = FormatType.String;
	i.sval1 = adbg_util_strfva(f, va);
}
/// Push a register value into the formatting stack. This is printed depending
/// on the register formatter (adbg_dasm_fmt_reg).
/// Params:
/// 	p = Disassembler parameters
/// 	reg = Register value
void adbg_dasm_push_reg(disasm_params_t *p, const(char) *reg) {
	disasm_fmt_item_t *i = adbg_dasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.Reg;
	i.sval1 = reg;
}
/// Push a segment+register value into the formatting stack. This is printed
/// depending on the register formatter (adbg_dasm_fmt_segreg).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	reg = Register value
void adbg_dasm_push_segreg(disasm_params_t *p, const(char) *seg, const(char) *reg) {
	disasm_fmt_item_t *i = adbg_dasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.Reg;
	i.sval1 = seg;
	i.sval2 = reg;
}
/// Push an immediate value into the formatting stack. This is printed depending
/// on the immediate formatter (adbg_dasm_fmt_imm).
/// Params:
/// 	p = Disassembler parameters
/// 	v = Immediate value
void adbg_dasm_push_imm(disasm_params_t *p, int v) {
	disasm_fmt_item_t *i = adbg_dasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.Imm;
	i.ival1 = v;
}
/// Push a memory value into the formatting stack. This is printed depending
/// on the memory formatter (adbg_dasm_fmt_mem).
/// Params:
/// 	p = Disassembler parameters
/// 	v = Absolute memory value
void adbg_dasm_push_mem(disasm_params_t *p, int v) {
	disasm_fmt_item_t *i = adbg_dasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.Mem;
	i.ival1 = v;
}
/// Push a memory+register value into the formatting stack. This is printed
/// depending on the memory+register formatter (adbg_dasm_fmt_memreg).
/// Params:
/// 	p = Disassembler parameters
/// 	reg = Register value
void adbg_dasm_push_memreg(disasm_params_t *p, const(char) *reg) {
	disasm_fmt_item_t *i = adbg_dasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.MemReg;
	i.sval1 = reg;
}
/// Push a memory+segment+register value into the formatting stack. This is
/// printed depending on its formatter (adbg_dasm_fmt_memsegreg).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	reg = Register value
void adbg_dasm_push_memsegreg(disasm_params_t *p, const(char) *seg, const(char) *reg) {
	disasm_fmt_item_t *i = adbg_dasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.MemSegReg;
	i.sval1 = reg;
	i.sval2 = seg;
}
/// Push a memory+register+immediate value into the formatting stack. This is
/// printed depending on its formatter (adbg_dasm_fmt_memregimm).
/// Params:
/// 	p = Disassembler parameters
/// 	reg = Register value
/// 	v = Immediate value
void adbg_dasm_push_memregimm(disasm_params_t *p, const(char) *reg, int v) {
	disasm_fmt_item_t *i = adbg_dasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.MemRegImm;
	i.sval1 = reg;
	i.ival1 = v;
}
/// Push a memory+segment+register+immediate value into the formatting stack.
/// This is printed depending on its formatter (adbg_dasm_fmt_memsegregimm).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	reg = Register value
/// 	v = Immediate value
void adbg_dasm_push_memsegregimm(disasm_params_t *p, const(char) *seg, const(char) *reg, int v) {
	disasm_fmt_item_t *i = adbg_dasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.MemSegRegImm;
	i.sval1 = reg;
	i.sval2 = seg;
	i.ival1 = v;
}
/// (x86) Push a SIB value when MOD=00 into the formatting stack.
/// This is printed depending on its formatter (adbg_dasm_fmt_sib_memsegbaseindexscale).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	base = Base register value
/// 	index = Index register value
/// 	scale = Scale value
void adbg_dasm_push_x86_sib_mod00(disasm_params_t *p,
	const(char) *seg, const(char) *base, const(char) *index, int scale) {
	disasm_fmt_item_t *i = adbg_dasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.x86_SIB_MemSegBaseIndexScale;
	i.sval1 = base;
	i.sval2 = index;
	i.sval3 = seg;
	i.ival1 = scale;
}
/// (x86) Push a SIB value when MOD=00 INDEX=100 into the formatting stack.
/// This is printed depending on its formatter (adbg_dasm_fmt_sib_memsegbase).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	base = Base register value
void adbg_dasm_push_x86_sib_m00_i100(disasm_params_t *p,
	const(char) *seg, const(char) *base) {
	disasm_fmt_item_t *i = adbg_dasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.x86_SIB_MemSegBase;
	i.sval1 = base;
	i.sval2 = seg;
}
/// (x86) Push a SIB value when MOD=00 BASE=101 into the formatting stack.
/// This is printed depending on its formatter (adbg_dasm_fmt_sib_memsegindexscaleimm).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	index = Index register value
/// 	scale = Scale value
/// 	imm = Displacement value
void adbg_dasm_push_x86_sib_m00_b101(disasm_params_t *p,
	const(char) *seg, const(char) *index, int scale, int imm) {
	disasm_fmt_item_t *i = adbg_dasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.x86_SIB_MemSegIndexScaleImm;
	i.sval1 = index;
	i.sval2 = seg;
	i.ival1 = scale;
	i.ival2 = imm;
}
/// (x86) Push a SIB value when MOD=00 INDEX=100 BASE=101 into the formatting
/// stack. This is printed depending on its formatter (adbg_dasm_fmt_sib_memsegimm).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	imm = Displacement value
void adbg_dasm_push_x86_sib_m00_i100_b101(disasm_params_t *p,
	const(char) *seg, int imm) {
	disasm_fmt_item_t *i = adbg_dasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.x86_SIB_MemSegImm;
	i.sval1 = seg;
	i.ival1 = imm;
}
/// (x86) Push a SIB value when MOD=01 into the formatting stack.
/// This is printed depending on its formatter
/// (adbg_dasm_fmt_sib_memsegbaseindexscaleimm).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	base = Base register value
/// 	index = Index register value
/// 	scale = Scale value
/// 	imm = Displacement value
void adbg_dasm_push_x86_sib_m01(disasm_params_t *p,
	const(char) *seg, const(char) *base, const(char) *index, int scale, int imm) {
	disasm_fmt_item_t *i = adbg_dasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.x86_SIB_MemSegBaseIndexScaleImm;
	i.sval1 = base;
	i.sval2 = index;
	i.sval3 = seg;
	i.ival1 = scale;
	i.ival2 = imm;
}
/// (x86) Push a SIB value when MOD=01 INDEX=100 into the formatting stack.
/// This is printed depending on its formatter
/// (adbg_dasm_fmt_sib_memsegbaseindexscaleimm).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	base = Base register value
/// 	imm = Displacement value
void adbg_dasm_push_x86_sib_m01_i100(disasm_params_t *p,
	const(char) *seg, const(char) *base, int imm) {
	disasm_fmt_item_t *i = adbg_dasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.x86_SIB_MemSegBaseImm;
	i.sval1  = base;
	i.sval2 = seg;
	i.ival1  = imm;
}

//
// Core functions
//

/// Set error code with DisasmError enum and override mnemonic buffer to
/// DISASM_FMT_ERR_STR (copied string). Does not touch the machine code buffer.
/// Params:
/// 	p = Disassembler parameters
/// 	err = Disassembler error (DisasmError, defaults to Illegal)
void adbg_dasm_err(disasm_params_t *p, DisasmError err = DisasmError.Illegal) {
	p.error = err;
	p.mnbufi =
	adbg_util_stradd(cast(char*)p.mnbuf, DISASM_BUF_SIZE, 0, DISASM_FMT_ERR_STR);
}

/// Process items in the formatter stack and output them into the formatter
/// buffers. Caller is responsible of terminating string buffers. Called by
/// adbg_dasm_line.
/// Params:
/// 	p = Disassembler parameters
void adbg_dasm_render(disasm_params_t *p) {
	size_t nbitems = p.fmt.itemno; /// number of total items

	if (nbitems < 1) return;

	adbg_dasm_madd(p, adbg_dasm_fmt_item(p, &p.fmt.items[0]));

	if (nbitems < 2) return;

	bool inversedir = void;

	if (p.fmt.settings & FORMATTER_O_NO_DIRECTION) {
		inversedir = false;
	} else {
		with (DisasmSyntax)
		switch (p.style) {
		case Att: inversedir = true; break;
		default:  inversedir = false;
		}
	}

	adbg_dasm_madd(p, DISASM_FMT_TAB);

	if (inversedir) {
		if (nbitems > 2) {
			adbg_dasm_madd(p, adbg_dasm_fmt_item(p, &p.fmt.items[2]));
			adbg_dasm_madd(p, DISASM_FMT_COMMA_SPACE);
		}
		adbg_dasm_madd(p, adbg_dasm_fmt_item(p, &p.fmt.items[1]));
	} else {
		adbg_dasm_madd(p, adbg_dasm_fmt_item(p, &p.fmt.items[1]));
		if (nbitems > 2) {
			adbg_dasm_madd(p, DISASM_FMT_COMMA_SPACE);
			adbg_dasm_madd(p, adbg_dasm_fmt_item(p, &p.fmt.items[2]));
		}
	}

	for (size_t index = 3; index < nbitems; ++index) {
		adbg_dasm_madd(p, DISASM_FMT_COMMA_SPACE);
		adbg_dasm_madd(p, adbg_dasm_fmt_item(p, &p.fmt.items[index]));
	}
}
/// (Internal) Places null characters in buffers
/// Params: p = Disassembler parameters
void adbg_dasm_finalize(disasm_params_t *p) {
	with (p) {
		if (mcbuf[mcbufi - 1] == ' ') --mcbufi;
		mcbuf[mcbufi] = mnbuf[mnbufi] = 0;
	}
}

//
// Internal functions
//

package:

/// (Internal) Automatically select next item to be pushed into the stack. This
/// also increments the stack pointer. Called by pushing functions.
/// Params:
/// 	p = Disassembler parameters
/// Returns: Formatter item if there is still space; Otherwise null
disasm_fmt_item_t *adbg_dasm_fmt_select(disasm_params_t *p) {
	if (p.fmt.itemno >= FORMATTER_STACK_LIMIT) return null;
	return &p.fmt.items[p.fmt.itemno++];
}
/// (Internal) Add string into the formatter's mnemonic string buffer. Called
/// by adbg_dasm_render from adbg_dasm_line.
/// Params:
/// 	p = Disassembler parameters
/// 	s = String
void adbg_dasm_madd(disasm_params_t *p, const(char) *s) {
	with (p)
	mnbufi = adbg_util_stradd(cast(char*)mnbuf, DISASM_BUF_SIZE, mnbufi, s);
}
/// (Internal) Add string into the formatter's machine code string buffer.
/// Called by disasm_push_x* functions.
/// Params:
/// 	p = Disassembler parameters
/// 	s = String
void adbg_dasm_xadd(disasm_params_t *p, const(char) *s) {
	with (p)
	mcbufi = adbg_util_stradd(cast(char*)mcbuf, DISASM_BUF_SIZE, mcbufi, s);
}

//
// Formatting functions
//

/// (Internal) Format and return the formatted string of a formatter item. Called
/// by adbg_dasm_render.
/// Params:
/// 	p = Disassembler parameters
/// 	i = Formatter item
/// Returns: Formatted string
const(char) *adbg_dasm_fmt_item(disasm_params_t *p, disasm_fmt_item_t *i) {
	//TODO: Consider inlining most of these items
	with (FormatType)
	final switch (i.type) {
	case String:	return i.sval1;
	case Reg:	return adbg_dasm_fmt_reg(p, i.sval1);
	case SegReg:	return adbg_dasm_fmt_segreg(p, i.sval1, i.sval2);
	case Imm:	return adbg_dasm_fmt_imm(p, i.ival1);
	case Mem:	return adbg_dasm_fmt_mem(p, i.ival1);
	case MemReg:	return adbg_dasm_fmt_memreg(p, i.sval1);
	case MemSegReg:	return adbg_dasm_fmt_memsegreg(p, i.sval2, i.sval1);
	case MemRegImm:	return adbg_dasm_fmt_memregimm(p, i.sval1, i.ival1);
	case MemSegRegImm:
		return adbg_dasm_fmt_memsegregimm(p, i.sval2, i.sval1, i.ival1);
	case x86_SIB_MemSegBaseIndexScale:
		return adbg_dasm_fmt_sib_memsegbaseindexscale(p,
			i.sval3, i.sval1, i.sval2, i.ival1);
	case x86_SIB_MemSegBase:
		return adbg_dasm_fmt_sib_memsegbase(p, i.sval2, i.sval1);
	case x86_SIB_MemSegIndexScaleImm:
		return adbg_dasm_fmt_sib_memsegindexscaleimm(p,
			i.sval2, i.sval1, i.ival1, i.ival2);
	case x86_SIB_MemSegImm:
		return adbg_dasm_fmt_sib_memsegimm(p, i.sval1, i.ival1);
	case x86_SIB_MemSegBaseIndexScaleImm:
		return adbg_dasm_fmt_sib_memsegbaseindexscaleimm(p,
			i.sval3, i.sval1, i.sval2, i.ival1, i.ival2);
	case x86_SIB_MemSegBaseImm:
		return adbg_dasm_fmt_sib_memsegbaseimm(p, i.sval2, i.sval1, i.ival1);
	}
}
const(char) *adbg_dasm_fmt_reg(disasm_params_t *p,
	const(char) *v) {
	if (v[0] == 0) return v;
	with (DisasmSyntax)
	switch (p.style) {
	case Att: return adbg_util_strf("%%%s", v);
	default:  return v;
	}
}
const(char) *adbg_dasm_fmt_segreg(disasm_params_t *p,
	const(char) *seg, const(char) *reg) {
	seg = adbg_dasm_fmt_reg(p, seg);
	reg = adbg_dasm_fmt_reg(p, reg);
	return adbg_util_strf("%s%s", seg, reg);
}
const(char) *adbg_dasm_fmt_imm(disasm_params_t *f,
	int v) {
	with (DisasmSyntax)
	switch (f.style) {
	case Att: return adbg_util_strf("$%d", v);
	default:  return adbg_util_strf("%d", v);
	}
}
const(char) *adbg_dasm_fmt_mem(disasm_params_t *p,
	int v) {
	with (DisasmSyntax)
	switch (p.style) {
	case Att: return adbg_util_strf("(%d)", v);
	default:  return adbg_util_strf("[%d]", v);
	}
}
const(char) *adbg_dasm_fmt_memreg(disasm_params_t *p,
	const(char) *v) {
	with (DisasmSyntax)
	switch (p.style) {
	case Att: return adbg_util_strf("(%s)", v);
	default:  return adbg_util_strf("[%s]", v);
	}
}
const(char) *adbg_dasm_fmt_memsegreg(disasm_params_t *p,
	const(char) *seg, const(char) *reg) {
	seg = adbg_dasm_fmt_reg(p, seg);
	reg = adbg_dasm_fmt_reg(p, reg);
	with (DisasmSyntax)
	switch (p.style) {
	case Att:  return adbg_util_strf("%s(%s)", seg, reg);
	case Nasm: return adbg_util_strf("[%s%s]", seg, reg);
	default:   return adbg_util_strf("%s[%s]", seg, reg);
	}
}
const(char) *adbg_dasm_fmt_memregimm(disasm_params_t *p,
	const(char) *reg, int v) {
	reg = adbg_dasm_fmt_reg(p, reg);
	with (DisasmSyntax)
	switch (p.style) {
	case Att:  return adbg_util_strf("(%s%+d)", reg, v);
	default:   return adbg_util_strf("[%s%+d]", reg, v);
	}
}
const(char) *adbg_dasm_fmt_memsegregimm(disasm_params_t *p,
	const(char) *seg, const(char) *reg, int v) {
	seg = adbg_dasm_fmt_reg(p, seg);
	reg = adbg_dasm_fmt_reg(p, reg);
	with (DisasmSyntax)
	switch (p.style) {
	case Att:  return adbg_util_strf("%s(%s%+d)", seg, reg, v);
	case Nasm: return adbg_util_strf("[%s%s%+d]", seg, reg, v);
	default:   return adbg_util_strf("%s[%s%+d]", seg, reg, v);
	}
}
const(char) *adbg_dasm_fmt_sib_memsegbaseindexscale(disasm_params_t *p,
	const(char) *seg, const(char) *base, const(char) *index, int scale) {
	seg = adbg_dasm_fmt_reg(p, seg);
	base = adbg_dasm_fmt_reg(p, base);
	index = adbg_dasm_fmt_reg(p, index);
	with (DisasmSyntax)
	switch (p.style) {
	case Att:  return adbg_util_strf("%s(%s,%s,%d)", seg, base, index, scale);
	case Nasm: return adbg_util_strf("[%s%s+%s*%d]", seg, base, index, scale);
	default:   return adbg_util_strf("%s[%s+%s*%d]", seg, base, index, scale);
	}
}
const(char) *adbg_dasm_fmt_sib_memsegbase(disasm_params_t *p,
	const(char) *seg, const(char) *base) {
	seg = adbg_dasm_fmt_reg(p, seg);
	base = adbg_dasm_fmt_reg(p, base);
	with (DisasmSyntax)
	switch (p.style) {
	case Att:  return adbg_util_strf("%s(,%s,)", seg, base);
	case Nasm: return adbg_util_strf("[%s%s]", seg, base);
	default:   return adbg_util_strf("%s[%s]", seg, base);
	}
}
const(char) *adbg_dasm_fmt_sib_memsegindexscaleimm(disasm_params_t *p,
	const(char) *seg, const(char) *index, ulong scale, int imm) {
	seg = adbg_dasm_fmt_reg(p, seg);
	index = adbg_dasm_fmt_reg(p, index);
	with (DisasmSyntax)
	switch (p.style) {
	case Att:  return adbg_util_strf("%s%+d(,%s,%d)", seg, imm, index, scale);
	case Nasm: return adbg_util_strf("[%s%s*%d%+d]", seg, index, scale, imm);
	default:   return adbg_util_strf("%s[%s*%d%+d]", seg, index, scale, imm);
	}
}
const(char) *adbg_dasm_fmt_sib_memsegimm(disasm_params_t *p,
	const(char) *seg, int imm) {
	seg = adbg_dasm_fmt_reg(p, seg);
	with (DisasmSyntax)
	switch (p.style) {
	case Att:  return adbg_util_strf("%s%+d(,,)", seg, imm);
	case Nasm: return adbg_util_strf("[%s%+d]", seg, imm);
	default:   return adbg_util_strf("%s[%+d]", seg, imm);
	}
}
const(char) *adbg_dasm_fmt_sib_memsegbaseindexscaleimm(disasm_params_t *p,
	const(char) *seg, const(char) *base, const(char) *index, int scale, int imm) {
	seg = adbg_dasm_fmt_reg(p, seg);
	base = adbg_dasm_fmt_reg(p, base);
	index = adbg_dasm_fmt_reg(p, index);
	with (DisasmSyntax)
	switch (p.style) {
	case Att:  return adbg_util_strf("%s%+d(%s,%s,%d)", seg, imm, base, index, scale);
	case Nasm: return adbg_util_strf("[%s%s+%s*%d%+d]", seg, base, index, scale, imm);
	default:   return adbg_util_strf("%s[%s+%s*%d%+d]", seg, base, index, scale, imm);
	}
}
const(char) *adbg_dasm_fmt_sib_memsegbaseimm(disasm_params_t *p,
	const(char) *seg, const(char) *base, int imm) {
	seg = adbg_dasm_fmt_reg(p, seg);
	base = adbg_dasm_fmt_reg(p, base);
	with (DisasmSyntax)
	switch (p.style) {
	case Att:  return adbg_util_strf("%s%+d(%s,,)", seg, imm, base);
	case Nasm: return adbg_util_strf("[%s%s%+d]", seg, base, imm);
	default:   return adbg_util_strf("%s[%s%+d]", seg, base, imm);
	}
}
