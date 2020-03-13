/**
 * Disassembler formatting engine.
 *
 * The formatting engine is designed to format any given pieces of string from
 * the decoder in a given order by the style setting.
 *
 * This module provides the item and style formatting for the disassembler. The
 * decoder (disassembler) pushes items with their respective types (e.g.
 * register, immediate, etc.) and the formatter takes take of rendering
 * the final result. Values are referenced (i.e. strings), not copied. For
 * example, disasm_push_reg pushes a register string value.
 *
 * Each item in the stack are processed from first to last (left to right),
 * typically begining with the mnemonic instruction, then usually an immediate,
 * memory reference, or register, to finally be formatted using their respected
 * formatting function (e.g. a register string is passed through
 * disasm_fmt_reg).
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
module debugger.disasm.formatter;

import core.stdc.stdarg;
import debugger.disasm.core;
import utils.str;

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
struct disasm_fmt_t {
	disasm_fmt_item_t [FORMATTER_STACK_SIZE]items;	/// Stack
	size_t itemno;	/// Current item number
	int opwidth;	/// Last operation width
	int settings;	/// Formatter settings for current stack/instruction (from decoder)
}

/// Default string for illegal instructions
// immutable implies __gshared
private
immutable const(char) *DISASM_FMT_ERR_STR = "??";
private
immutable const(char) *DISASM_FMT_SPACE = " ";
private
immutable const(char) *DISASM_FMT_COMMA_SPACE = ", ";

//
// Machine code functions
//

/// Push an 8-bit value into the machine code buffer.
/// Params:
/// 	p = Disassembler parameters
/// 	v = 8-bit value
void disasm_push_x8(ref disasm_params_t p, ubyte v) {
	disasm_xadd(p, strx02(v));
	if ((p.options & DISASM_O_MC_NOSPACE) == 0)
		disasm_xadd(p, DISASM_FMT_SPACE);
}
/// Push an 16-bit value into the machine code buffer.
/// Params:
/// 	p = Disassembler parameters
/// 	v = 16-bit value
void disasm_push_x16(ref disasm_params_t p, ushort v) {
	disasm_xadd(p, strx04(v));
	if ((p.options & DISASM_O_MC_NOSPACE) == 0)
		disasm_xadd(p, DISASM_FMT_SPACE);
}
/// Push an 32-bit value into the machine code buffer.
/// Params:
/// 	p = Disassembler parameters
/// 	v = 32-bit value
void disasm_push_x32(ref disasm_params_t p, uint v) {
	disasm_xadd(p, strx08(v));
	if ((p.options & DISASM_O_MC_NOSPACE) == 0)
		disasm_xadd(p, DISASM_FMT_SPACE);
}
/// Push an 64-bit value into the machine code buffer.
/// Params:
/// 	p = Disassembler parameters
/// 	v = 64-bit value
void disasm_push_x64(ref disasm_params_t p, ulong v) {
	disasm_xadd(p, strx016(v));
	if ((p.options & DISASM_O_MC_NOSPACE) == 0)
		disasm_xadd(p, DISASM_FMT_SPACE);
}

//
// Pushing functions
//

/// Push a string value into the formatting stack. This is printed as-is.
/// Params:
/// 	p = Disassembler parameters
/// 	v = String value
void disasm_push_str(ref disasm_params_t p, const(char) *v) {
	disasm_fmt_item_t *i = disasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.String;
	i.sval1 = v;
}
/// Format and format a string into the formatting stack. This is printed as-is.
/// Params:
/// 	p = Disassembler parameters
/// 	f = String format
///     ... = Arguments
void disasm_push_strf(ref disasm_params_t p, const(char) *f, ...) {
	disasm_fmt_item_t *i = disasm_fmt_select(p);
	if (i == null) return;
	va_list va;
	va_start(va, f);
	i.type = FormatType.String;
	i.sval1 = strfva(f, va);
}
/// Push a register value into the formatting stack. This is printed depending
/// on the register formatter (disasm_fmt_reg).
/// Params:
/// 	p = Disassembler parameters
/// 	reg = Register value
void disasm_push_reg(ref disasm_params_t p, const(char) *reg) {
	disasm_fmt_item_t *i = disasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.Reg;
	i.sval1 = reg;
}
/// Push a segment+register value into the formatting stack. This is printed
/// depending on the register formatter (disasm_fmt_segreg).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	reg = Register value
void disasm_push_segreg(ref disasm_params_t p, const(char) *seg, const(char) *reg) {
	disasm_fmt_item_t *i = disasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.Reg;
	i.sval1 = seg;
	i.sval2 = reg;
}
/// Push an immediate value into the formatting stack. This is printed depending
/// on the immediate formatter (disasm_fmt_imm).
/// Params:
/// 	p = Disassembler parameters
/// 	v = Immediate value
void disasm_push_imm(ref disasm_params_t p, int v) {
	disasm_fmt_item_t *i = disasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.Imm;
	i.ival1 = v;
}
/// Push a memory value into the formatting stack. This is printed depending
/// on the memory formatter (disasm_fmt_mem).
/// Params:
/// 	p = Disassembler parameters
/// 	v = Absolute memory value
void disasm_push_mem(ref disasm_params_t p, int v) {
	disasm_fmt_item_t *i = disasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.Mem;
	i.ival1 = v;
}
/// Push a memory+register value into the formatting stack. This is printed
/// depending on the memory+register formatter (disasm_fmt_memreg).
/// Params:
/// 	p = Disassembler parameters
/// 	reg = Register value
void disasm_push_memreg(ref disasm_params_t p, const(char) *reg) {
	disasm_fmt_item_t *i = disasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.MemReg;
	i.sval1 = reg;
}
/// Push a memory+segment+register value into the formatting stack. This is
/// printed depending on its formatter (disasm_fmt_memsegreg).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	reg = Register value
void disasm_push_memsegreg(ref disasm_params_t p, const(char) *seg, const(char) *reg) {
	disasm_fmt_item_t *i = disasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.MemSegReg;
	i.sval1 = reg;
	i.sval2 = seg;
}
/// Push a memory+register+immediate value into the formatting stack. This is
/// printed depending on its formatter (disasm_fmt_memregimm).
/// Params:
/// 	p = Disassembler parameters
/// 	reg = Register value
/// 	v = Immediate value
void disasm_push_memregimm(ref disasm_params_t p, const(char) *reg, int v) {
	disasm_fmt_item_t *i = disasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.MemRegImm;
	i.sval1 = reg;
	i.ival1 = v;
}
/// Push a memory+segment+register+immediate value into the formatting stack.
/// This is printed depending on its formatter (disasm_fmt_memsegregimm).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	reg = Register value
/// 	v = Immediate value
void disasm_push_memsegregimm(ref disasm_params_t p, const(char) *seg, const(char) *reg, int v) {
	disasm_fmt_item_t *i = disasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.MemSegRegImm;
	i.sval1 = reg;
	i.sval2 = seg;
	i.ival1 = v;
}
/// (x86) Push a SIB value when MOD=00 into the formatting stack.
/// This is printed depending on its formatter (disasm_fmt_sib_memsegbaseindexscale).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	base = Base register value
/// 	index = Index register value
/// 	scale = Scale value
void disasm_push_x86_sib_mod00(ref disasm_params_t p,
	const(char) *seg, const(char) *base, const(char) *index, int scale) {
	disasm_fmt_item_t *i = disasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.x86_SIB_MemSegBaseIndexScale;
	i.sval1 = base;
	i.sval2 = index;
	i.sval3 = seg;
	i.ival1 = scale;
}
/// (x86) Push a SIB value when MOD=00 INDEX=100 into the formatting stack.
/// This is printed depending on its formatter (disasm_fmt_sib_memsegbase).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	base = Base register value
void disasm_push_x86_sib_mod00_index100(ref disasm_params_t p,
	const(char) *seg, const(char) *base) {
	disasm_fmt_item_t *i = disasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.x86_SIB_MemSegBase;
	i.sval1 = base;
	i.sval2 = seg;
}
/// (x86) Push a SIB value when MOD=00 BASE=101 into the formatting stack.
/// This is printed depending on its formatter (disasm_fmt_sib_memsegindexscaleimm).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	index = Index register value
/// 	scale = Scale value
/// 	imm = Displacement value
void disasm_push_x86_sib_mod00_base101(ref disasm_params_t p,
	const(char) *seg, const(char) *index, int scale, int imm) {
	disasm_fmt_item_t *i = disasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.x86_SIB_MemSegIndexScaleImm;
	i.sval1 = index;
	i.sval2 = seg;
	i.ival1 = scale;
	i.ival2 = imm;
}
/// (x86) Push a SIB value when MOD=00 INDEX=100 BASE=101 into the formatting
/// stack. This is printed depending on its formatter (disasm_fmt_sib_memsegimm).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	imm = Displacement value
void disasm_push_x86_sib_mod00_index100_base101(ref disasm_params_t p,
	const(char) *seg, int imm) {
	disasm_fmt_item_t *i = disasm_fmt_select(p);
	if (i == null) return;
	i.type = FormatType.x86_SIB_MemSegImm;
	i.sval1 = seg;
	i.ival1 = imm;
}
/// (x86) Push a SIB value when MOD=01 into the formatting stack.
/// This is printed depending on its formatter
/// (disasm_fmt_sib_memsegbaseindexscaleimm).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	base = Base register value
/// 	index = Index register value
/// 	scale = Scale value
/// 	imm = Displacement value
void disasm_push_x86_sib_mod01(ref disasm_params_t p,
	const(char) *seg, const(char) *base, const(char) *index, int scale, int imm) {
	disasm_fmt_item_t *i = disasm_fmt_select(p);
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
/// (disasm_fmt_sib_memsegbaseindexscaleimm).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	base = Base register value
/// 	imm = Displacement value
void disasm_push_x86_sib_mod01_index100(ref disasm_params_t p,
	const(char) *seg, const(char) *base, int imm) {
	disasm_fmt_item_t *i = disasm_fmt_select(p);
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
void disasm_err(ref disasm_params_t p, DisasmError err = DisasmError.Illegal) {
	p.error = err;
	p.mnbufi =
	stradd(cast(char*)p.mnbuf, DISASM_BUF_SIZE, 0, DISASM_FMT_ERR_STR);
}

/// Process items in the formatter stack and output them into the formatter
/// buffers. Caller is responsible of terminating string buffers. Called by
/// disasm_line.
/// Params:
/// 	p = Disassembler parameters
void disasm_render(ref disasm_params_t p) {
	size_t nbitems = p.fmt.itemno; /// number of total items

	if (nbitems < 1) return;

	disasm_madd(p, disasm_fmt_item(p, p.fmt.items[0]));

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

	disasm_madd(p, DISASM_FMT_SPACE);
	if (inversedir) {
		if (nbitems > 2) {
			disasm_madd(p, disasm_fmt_item(p, p.fmt.items[2]));
			disasm_madd(p, DISASM_FMT_COMMA_SPACE);
		}
		disasm_madd(p, disasm_fmt_item(p, p.fmt.items[1]));
	} else {
		disasm_madd(p, disasm_fmt_item(p, p.fmt.items[1]));
		if (nbitems > 2) {
			disasm_madd(p, DISASM_FMT_COMMA_SPACE);
			disasm_madd(p, disasm_fmt_item(p, p.fmt.items[2]));
		}
	}

	for (size_t index = 3; index < nbitems; ++index) {
		disasm_madd(p, DISASM_FMT_COMMA_SPACE);
		disasm_madd(p, disasm_fmt_item(p, p.fmt.items[index]));
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
disasm_fmt_item_t *disasm_fmt_select(ref disasm_params_t p) {
	if (p.fmt.itemno >= FORMATTER_STACK_LIMIT) return null;
	return &p.fmt.items[p.fmt.itemno++];
}
/// (Internal) Add string into the formatter's mnemonic string buffer. Called
/// by disasm_render from disasm_line.
/// Params:
/// 	p = Disassembler parameters
/// 	s = String
void disasm_madd(ref disasm_params_t p, const(char) *s) {
	with (p)
	mnbufi = stradd(cast(char*)mnbuf, DISASM_BUF_SIZE, mnbufi, s);
}
/// (Internal) Add string into the formatter's machine code string buffer.
/// Called by disasm_push_x* functions.
/// Params:
/// 	p = Disassembler parameters
/// 	s = String
void disasm_xadd(ref disasm_params_t p, const(char) *s) {
	with (p)
	mcbufi = stradd(cast(char*)mcbuf, DISASM_BUF_SIZE, mcbufi, s);
}

//
// Formatting functions
//

/// (Internal) Format and return the formatted string of a formatter item. Called
/// by disasm_render.
/// Params:
/// 	p = Disassembler parameters
/// 	i = Formatter item
/// Returns: Formatted string
const(char) *disasm_fmt_item(ref disasm_params_t p, ref disasm_fmt_item_t i) {
	with (FormatType)
	final switch (i.type) {
	case String:	return i.sval1;
	case Reg:	return disasm_fmt_reg(p, i.sval1);
	case SegReg:	return disasm_fmt_segreg(p, i.sval1, i.sval2);
	case Imm:	return disasm_fmt_imm(p, i.ival1);
	case Mem:	return disasm_fmt_mem(p, i.ival1);
	case MemReg:	return disasm_fmt_memreg(p, i.sval1);
	case MemSegReg:	return disasm_fmt_memsegreg(p, i.sval2, i.sval1);
	case MemRegImm:	return disasm_fmt_memregimm(p, i.sval1, i.ival1);
	case MemSegRegImm:
		return disasm_fmt_memsegregimm(p, i.sval2, i.sval1, i.ival1);
	case x86_SIB_MemSegBaseIndexScale:
		return disasm_fmt_sib_memsegbaseindexscale(p,
			i.sval3, i.sval1, i.sval2, i.ival1);
	case x86_SIB_MemSegBase:
		return disasm_fmt_sib_memsegbase(p, i.sval2, i.sval1);
	case x86_SIB_MemSegIndexScaleImm:
		return disasm_fmt_sib_memsegindexscaleimm(p,
			i.sval2, i.sval1, i.ival1, i.ival2);
	case x86_SIB_MemSegImm:
		return disasm_fmt_sib_memsegimm(p, i.sval1, i.ival1);
	case x86_SIB_MemSegBaseIndexScaleImm:
		return disasm_fmt_sib_memsegbaseindexscaleimm(p,
			i.sval3, i.sval1, i.sval2, i.ival1, i.ival2);
	case x86_SIB_MemSegBaseImm:
		return disasm_fmt_sib_memsegbaseimm(p, i.sval2, i.sval1, i.ival1);
	}
}
const(char) *disasm_fmt_reg(ref disasm_params_t p,
	const(char) *v) {
	if (v[0] == 0) return v;
	with (DisasmSyntax)
	switch (p.style) {
	case Att: return strf("%%%s", v);
	default:  return v;
	}
}
const(char) *disasm_fmt_segreg(ref disasm_params_t p,
	const(char) *seg, const(char) *reg) {
	seg = disasm_fmt_reg(p, seg);
	reg = disasm_fmt_reg(p, reg);
	return strf("%s%s", seg, reg);
}
const(char) *disasm_fmt_imm(ref disasm_params_t f,
	int v) {
	with (DisasmSyntax)
	switch (f.style) {
	case Att: return strf("$%d", v);
	default:  return strf("%d", v);
	}
}
const(char) *disasm_fmt_mem(ref disasm_params_t p,
	int v) {
	with (DisasmSyntax)
	switch (p.style) {
	case Att: return strf("(%d)", v);
	default:  return strf("[%d]", v);
	}
}
const(char) *disasm_fmt_memreg(ref disasm_params_t p,
	const(char) *v) {
	with (DisasmSyntax)
	switch (p.style) {
	case Att: return strf("(%s)", v);
	default:  return strf("[%s]", v);
	}
}
const(char) *disasm_fmt_memsegreg(ref disasm_params_t p,
	const(char) *seg, const(char) *reg) {
	seg = disasm_fmt_reg(p, seg);
	reg = disasm_fmt_reg(p, reg);
	with (DisasmSyntax)
	switch (p.style) {
	case Att:  return strf("%s(%s)", seg, reg);
	case Nasm: return strf("[%s%s]", seg, reg);
	default:   return strf("%s[%s]", seg, reg);
	}
}
const(char) *disasm_fmt_memregimm(ref disasm_params_t p,
	const(char) *reg, int v) {
	reg = disasm_fmt_reg(p, reg);
	with (DisasmSyntax)
	switch (p.style) {
	case Att:  return strf("(%s%+d)", reg, v);
	default:   return strf("[%s%+d]", reg, v);
	}
}
const(char) *disasm_fmt_memsegregimm(ref disasm_params_t p,
	const(char) *seg, const(char) *reg, int v) {
	seg = disasm_fmt_reg(p, seg);
	reg = disasm_fmt_reg(p, reg);
	with (DisasmSyntax)
	switch (p.style) {
	case Att:  return strf("%s(%s%+d)", seg, reg, v);
	case Nasm: return strf("[%s%s%+d]", seg, reg, v);
	default:   return strf("%s[%s%+d]", seg, reg, v);
	}
}
const(char) *disasm_fmt_sib_memsegbaseindexscale(ref disasm_params_t p,
	const(char) *seg, const(char) *base, const(char) *index, int scale) {
	seg = disasm_fmt_reg(p, seg);
	base = disasm_fmt_reg(p, base);
	index = disasm_fmt_reg(p, index);
	with (DisasmSyntax)
	switch (p.style) {
	case Att:  return strf("%s(%s,%s,%d)", seg, base, index, scale);
	case Nasm: return strf("[%s%s+%s*%d]", seg, base, index, scale);
	default:   return strf("%s[%s+%s*%d]", seg, base, index, scale);
	}
}
const(char) *disasm_fmt_sib_memsegbase(ref disasm_params_t p,
	const(char) *seg, const(char) *base) {
	seg = disasm_fmt_reg(p, seg);
	base = disasm_fmt_reg(p, base);
	with (DisasmSyntax)
	switch (p.style) {
	case Att:  return strf("%s(,%s,)", seg, base);
	case Nasm: return strf("[%s%s]", seg, base);
	default:   return strf("%s[%s]", seg, base);
	}
}
const(char) *disasm_fmt_sib_memsegindexscaleimm(ref disasm_params_t p,
	const(char) *seg, const(char) *index, ulong scale, int imm) {
	seg = disasm_fmt_reg(p, seg);
	index = disasm_fmt_reg(p, index);
	with (DisasmSyntax)
	switch (p.style) {
	case Att:  return strf("%s%+d(,%s,%d)", seg, imm, index, scale);
	case Nasm: return strf("[%s%s*%d%+d]", seg, index, scale, imm);
	default:   return strf("%s[%s*%d%+d]", seg, index, scale, imm);
	}
}
const(char) *disasm_fmt_sib_memsegimm(ref disasm_params_t p,
	const(char) *seg, int imm) {
	seg = disasm_fmt_reg(p, seg);
	with (DisasmSyntax)
	switch (p.style) {
	case Att:  return strf("%s%+d(,,)", seg, imm);
	case Nasm: return strf("[%s%+d]", seg, imm);
	default:   return strf("%s[%+d]", seg, imm);
	}
}
const(char) *disasm_fmt_sib_memsegbaseindexscaleimm(ref disasm_params_t p,
	const(char) *seg, const(char) *base, const(char) *index, int scale, int imm) {
	seg = disasm_fmt_reg(p, seg);
	base = disasm_fmt_reg(p, base);
	index = disasm_fmt_reg(p, index);
	with (DisasmSyntax)
	switch (p.style) {
	case Att:  return strf("%s%+d(%s,%s,%d)", seg, imm, base, index, scale);
	case Nasm: return strf("[%s%s+%s*%d%+d]", seg, base, index, scale, imm);
	default:   return strf("%s[%s+%s*%d%+d]", seg, base, index, scale, imm);
	}
}
const(char) *disasm_fmt_sib_memsegbaseimm(ref disasm_params_t p,
	const(char) *seg, const(char) *base, int imm) {
	seg = disasm_fmt_reg(p, seg);
	base = disasm_fmt_reg(p, base);
	with (DisasmSyntax)
	switch (p.style) {
	case Att:  return strf("%s%+d(%s,,)", seg, imm, base);
	case Nasm: return strf("[%s%s%+d]", seg, base, imm);
	default:   return strf("%s[%s%+d]", seg, base, imm);
	}
}
