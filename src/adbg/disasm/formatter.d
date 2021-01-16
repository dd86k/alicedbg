/**
 * Disassembler formatting engine.
 *
 * The formatting engine is designed to format any given pieces of string from
 * the decoder in a given order by the style setting.
 *
 * This module provides the item and style formatting functions for the
 * disassembler. The decoder pushes items with their respective types (e.g.
 * register, immediate, etc.) and the formatter takes take of rendering
 * the final result. Values are referenced (i.e. strings), not copied. For
 * example, adbg_disasm_push_reg pushes a register string value.
 *
 * Each item in the stack are processed from first to last (left to right),
 * typically begining with the mnemonic instruction, then usually an immediate,
 * memory reference, or register, to finally be formatted using their respected
 * formatting function (e.g. a register string is passed through
 * adbg_disasm_fmt_reg).
 *
 * The operand ordering is INSTRUCTION TARGET, SOURCE (Intel), this is
 * important to know since this behavior is affected by the disassembler
 * syntax setting (e.g. At&t vs. Intel/Nasm/Masm).
 *
 * Machine code and mnemonic items are processed differently. The machine code
 * items are immediately processed upon arrival onto the string buffer, so
 * machine code and mnemonic items can be pushed in any order, only the
 * mnemonic items use the formatter's stack.
 *
 * License: BSD-3-Clause
 */
module adbg.disasm.formatter;

import core.stdc.stdarg;
import core.stdc.stdio : snprintf;
import adbg.error;
import adbg.disasm.disasm;
import adbg.utils.str, adbg.platform;

extern (C):

//
// Formatter options for decoder
//

/// Number of items the formatter can hold
private enum FORMATTER_STACK_SIZE = 8;
/// Formatter stack limit (size - 1)
private enum FORMATTER_STACK_LIMIT = FORMATTER_STACK_SIZE - 1;
/// Formatter register buffers size
private enum FORMATTER_REGBUF_SIZE = 16;

//TODO: New type -- Prefix
//      Prefixes are simple strings to process before the normal instruction
//      Currently not supported because other ISAs (than x86) don't seem to have such thing
/// Item type, each item more or less has their own formatting function
enum FormatType {
	String,	/// String that will remain unformatted, typically the instruction
	Reg,	/// Register spec
	SegReg,	/// Segment:Register spec
	Addr,	/// Address spec (e.g. jumps)
	Imm,	/// Immediate spec
	Imm64,	/// Immediate 64-bit spec
	ImmFar,	/// Immediate far spec (notably for x86), x:x format
	ImmSeg,	/// Segment:Immediate spec (notably for x86), s:x format
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
/// Memory operation pointer width for memory types
enum MemWidth {
	i8,	/// 8-bit
	i16,	/// 16-bit
	i32,	/// 32-bit
	i64,	/// 64-bit
	i128,	/// 128-bit
	i256,	/// 256-bit
	i512,	/// 512-bit
	i1024,	/// 1024-bit
	far,	/// (x86) fword m16:32 or m16:16
	f80,	/// (x86) tword 80-bit
}

/// Format item structure. Can hold up to 3 integer and 3 string values.
package
struct disasm_fmt_item_t {
	FormatType type;	/// Item type, see FormatType structure
	union {
		ulong lval1;
		version (LittleEndian)
			struct { int ival1, ival2; }
		else
			struct { int ival2, ival1; }
	}
	int ival3;	/// Typically holds memory pointer width
	const(char) *sval1;
	const(char) *sval2;
	const(char) *sval3;
}
/// Formatter structure embedded into the disassembler structure
package
struct disasm_fmt_t { align(1):
	size_t itemno;	/// Current item number
	disasm_fmt_item_t [FORMATTER_STACK_SIZE]items;	/// Stack
}

/// Default string for illegal instructions
private immutable
const(char) *DISASM_FMT_ERR	= "(bad)";	/// Error function string
private immutable
const(char) *DISASM_FMT_SPACE	= " ";	/// Between instruction and operands
private immutable
const(char) *DISASM_FMT_TAB	= "\t";	/// Between instruction and operands
private immutable
const(char) *DISASM_FMT_COMMA_SPACE	= ", ";	/// Typically in-between operands

private immutable
const(char) *[]MEM_WIDTHS_INTEL = [
	"byte", "word", "dword", "qword", "xmmword", "ymmword", "zmmword", "word?",
	"fword", "tword", "word?", "word?", "word?", "word?", "word?", "word?"
];
private immutable
const(char) *[]MEM_WIDTHS_NASM = [
	"byte", "word", "dword", "qword", "oword", "yword", "zword", "word?",
	"fword", "tword", "word?", "word?", "word?", "word?", "word?", "word?"
];

//
// ANCHOR Machine code functions
//

/// Push an 8-bit value into the machine code buffer.
/// Params:
/// 	p = Disassembler parameters
/// 	v = 8-bit value
void adbg_disasm_push_x8(adbg_disasm_t *p, ubyte v) {
	adbg_disasm_xadd(p, adbg_util_strx02(v));
	if ((p.options & DISASM_O_MC_NOSPACE) == 0)
		adbg_disasm_xadd(p, DISASM_FMT_SPACE);
}
/// Push an 16-bit value into the machine code buffer.
/// Params:
/// 	p = Disassembler parameters
/// 	v = 16-bit value
void adbg_disasm_push_x16(adbg_disasm_t *p, ushort v) {
	adbg_disasm_xadd(p, adbg_util_strx04(v));
	if ((p.options & DISASM_O_MC_NOSPACE) == 0)
		adbg_disasm_xadd(p, DISASM_FMT_SPACE);
}
/// Push an 32-bit value into the machine code buffer.
/// Params:
/// 	p = Disassembler parameters
/// 	v = 32-bit value
void adbg_disasm_push_x32(adbg_disasm_t *p, uint v) {
	adbg_disasm_xadd(p, adbg_util_strx08(v));
	if ((p.options & DISASM_O_MC_NOSPACE) == 0)
		adbg_disasm_xadd(p, DISASM_FMT_SPACE);
}
/// Push an 64-bit value into the machine code buffer.
/// Params:
/// 	p = Disassembler parameters
/// 	v = 64-bit value
void adbg_disasm_push_x64(adbg_disasm_t *p, ulong v) {
	adbg_disasm_xadd(p, adbg_util_strx016(v));
	if ((p.options & DISASM_O_MC_NOSPACE) == 0)
		adbg_disasm_xadd(p, DISASM_FMT_SPACE);
}

//
// ANCHOR Pushing functions
//

//TODO: Consider renaming the push names
//      e.g. memsegregimm to msri

/// Push a string value into the formatting stack. This is printed as-is.
/// Params:
/// 	p = Disassembler parameters
/// 	v = String value
void adbg_disasm_push_str(adbg_disasm_t *p, const(char) *v) {
	if (p.fmt.itemno >= FORMATTER_STACK_LIMIT)
		return;
	disasm_fmt_item_t *i = adbg_disasm_fmt_select(p);
	i.type = FormatType.String;
	i.sval1 = v;
}
/// Format and format a string into the formatting stack. This is printed as-is.
/// Params:
/// 	p = Disassembler parameters
/// 	f = String format
///     ... = Arguments
void adbg_disasm_push_strf(adbg_disasm_t *p, const(char) *f, ...) {
	if (p.fmt.itemno >= FORMATTER_STACK_LIMIT)
		return;
	disasm_fmt_item_t *i = adbg_disasm_fmt_select(p);
	i.type = FormatType.String;
	va_list va;
	va_start(va, f);
	i.sval1 = adbg_util_strfva(f, va);
}
/// Push a register value into the formatting stack. This is printed depending
/// on the register formatter (adbg_disasm_fmt_reg).
/// Params:
/// 	p = Disassembler parameters
/// 	reg = Register value
void adbg_disasm_push_reg(adbg_disasm_t *p, const(char) *reg) {
	if (p.fmt.itemno >= FORMATTER_STACK_LIMIT)
		return;
	disasm_fmt_item_t *i = adbg_disasm_fmt_select(p);
	i.type = FormatType.Reg;
	i.sval1 = reg;
}
/// Push a segment+register value into the formatting stack. This is printed
/// depending on the register formatter (adbg_disasm_fmt_segreg).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	reg = Register value
void adbg_disasm_push_segreg(adbg_disasm_t *p, const(char) *seg, const(char) *reg) {
	if (p.fmt.itemno >= FORMATTER_STACK_LIMIT)
		return;
	disasm_fmt_item_t *i = adbg_disasm_fmt_select(p);
	i.type = FormatType.SegReg;
	i.sval1 = seg;
	i.sval2 = reg;
}
/// Push an address value into the formatting stack. This is printed depending
/// on the immediate formatter (adbg_disasm_fmt_addr).
/// Params:
/// 	p = Disassembler parameters
/// 	addr = Address value
void adbg_disasm_push_addr(adbg_disasm_t *p, ulong addr) {
	if (p.fmt.itemno >= FORMATTER_STACK_LIMIT)
		return;
	disasm_fmt_item_t *i = adbg_disasm_fmt_select(p);
	i.type = FormatType.Addr;
	i.lval1 = addr;
}
/// Push an immediate value into the formatting stack. This is printed depending
/// on the immediate formatter (adbg_disasm_fmt_imm).
/// Params:
/// 	p = Disassembler parameters
/// 	imm = Immediate value
void adbg_disasm_push_imm(adbg_disasm_t *p, int imm) {
	if (p.fmt.itemno >= FORMATTER_STACK_LIMIT)
		return;
	disasm_fmt_item_t *i = adbg_disasm_fmt_select(p);
	i.type = FormatType.Imm;
	i.ival1 = imm;
}
/// Push an 64-bit immediate value into the formatting stack. This is printed depending
/// on the immediate formatter (adbg_disasm_fmt_imm64).
/// Params:
/// 	p = Disassembler parameters
/// 	imm = Immediate value
void adbg_disasm_push_imm64(adbg_disasm_t *p, long imm) {
	if (p.fmt.itemno >= FORMATTER_STACK_LIMIT)
		return;
	disasm_fmt_item_t *i = adbg_disasm_fmt_select(p);
	i.type = FormatType.Imm;
	i.lval1 = imm;
}
/// Push an immediate value into the formatting stack. This is printed depending
/// on the immediate formatter (adbg_disasm_fmt_immfar).
/// Params:
/// 	p = Disassembler parameters
/// 	imm = Immediate value
/// 	seg = segment value
void adbg_disasm_push_immfar(adbg_disasm_t *p, int imm, int seg) {
	if (p.fmt.itemno >= FORMATTER_STACK_LIMIT)
		return;
	disasm_fmt_item_t *i = adbg_disasm_fmt_select(p);
	i.type = FormatType.ImmFar;
	i.ival1 = imm;
	i.ival2 = seg;
}
/// Push an seg:imm value into the formatting stack. This is printed depending
/// on the immediate formatter (adbg_disasm_fmt_immseg).
/// Params:
/// 	p = Disassembler parameters
/// 	imm = Immediate value
/// 	seg = Segment string
void adbg_disasm_push_immseg(adbg_disasm_t *p, int imm, const(char) *seg) {
	if (p.fmt.itemno >= FORMATTER_STACK_LIMIT)
		return;
	disasm_fmt_item_t *i = adbg_disasm_fmt_select(p);
	i.type = FormatType.ImmSeg;
	i.ival1 = imm;
	i.sval1 = seg;
}
/// Push a memory value into the formatting stack. This is printed depending
/// on the memory formatter (adbg_disasm_fmt_mem).
/// Params:
/// 	p = Disassembler parameters
/// 	v = Absolute memory value
/// 	w = Operation width
void adbg_disasm_push_mem(adbg_disasm_t *p, int v, int w) {
	if (p.fmt.itemno >= FORMATTER_STACK_LIMIT)
		return;
	disasm_fmt_item_t *i = adbg_disasm_fmt_select(p);
	i.type = FormatType.Mem;
	i.ival1 = v;
	i.ival3 = w;
}
/// Push a memory+register value into the formatting stack. This is printed
/// depending on the memory+register formatter (adbg_disasm_fmt_memreg).
/// Params:
/// 	p = Disassembler parameters
/// 	reg = Register value
/// 	w = Operation width
void adbg_disasm_push_memreg(adbg_disasm_t *p, const(char) *reg, int w) {
	if (p.fmt.itemno >= FORMATTER_STACK_LIMIT)
		return;
	disasm_fmt_item_t *i = adbg_disasm_fmt_select(p);
	i.type = FormatType.MemReg;
	i.sval1 = reg;
	i.ival3 = w;
}
/// Push a memory+segment+register value into the formatting stack. This is
/// printed depending on its formatter (adbg_disasm_fmt_memsegreg).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	reg = Register value
/// 	w = Operation width
void adbg_disasm_push_memsegreg(adbg_disasm_t *p, const(char) *seg, const(char) *reg, int w) {
	if (p.fmt.itemno >= FORMATTER_STACK_LIMIT)
		return;
	disasm_fmt_item_t *i = adbg_disasm_fmt_select(p);
	i.type = FormatType.MemSegReg;
	i.sval1 = reg;
	i.sval2 = seg;
	i.ival3 = w;
}
/// Push a memory+register+immediate value into the formatting stack. This is
/// printed depending on its formatter (adbg_disasm_fmt_memregimm).
/// Params:
/// 	p = Disassembler parameters
/// 	reg = Register value
/// 	imm = Immediate value
/// 	w = Operation width
void adbg_disasm_push_memregimm(adbg_disasm_t *p, const(char) *reg, int imm, int w) {
	if (p.fmt.itemno >= FORMATTER_STACK_LIMIT)
		return;
	disasm_fmt_item_t *i = adbg_disasm_fmt_select(p);
	i.type = FormatType.MemRegImm;
	i.sval1 = reg;
	i.ival1 = imm;
	i.ival3 = w;
}
/// Push a memory+segment+register+immediate value into the formatting stack.
/// This is printed depending on its formatter (adbg_disasm_fmt_memsegregimm).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	reg = Register value
/// 	imm = Immediate value
/// 	w = Operation width
void adbg_disasm_push_memsegregimm(adbg_disasm_t *p, const(char) *seg, const(char) *reg, int imm, int w) {
	if (p.fmt.itemno >= FORMATTER_STACK_LIMIT)
		return;
	disasm_fmt_item_t *i = adbg_disasm_fmt_select(p);
	i.type = FormatType.MemSegRegImm;
	i.sval1 = reg;
	i.sval2 = seg;
	i.ival1 = imm;
	i.ival3 = w;
}
/// (x86) Push a SIB value when MOD=00 into the formatting stack.
/// This is printed depending on its formatter (adbg_disasm_fmt_sib_memsegbaseindexscale).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	base = Base register value
/// 	index = Index register value
/// 	scale = Scale value
/// 	w = Operation width
void adbg_disasm_push_x86_sib_mod00(adbg_disasm_t *p,
	const(char) *seg, const(char) *base, const(char) *index, int scale, int w) {
	if (p.fmt.itemno >= FORMATTER_STACK_LIMIT)
		return;
	disasm_fmt_item_t *i = adbg_disasm_fmt_select(p);
	i.type = FormatType.x86_SIB_MemSegBaseIndexScale;
	i.sval1 = base;
	i.sval2 = index;
	i.sval3 = seg;
	i.ival1 = scale;
	i.ival3 = w;
}
/// (x86) Push a SIB value when MOD=00 INDEX=100 into the formatting stack.
/// This is printed depending on its formatter (adbg_disasm_fmt_sib_memsegbase).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	base = Base register value
/// 	w = Operation width
void adbg_disasm_push_x86_sib_m00_i100(adbg_disasm_t *p,
	const(char) *seg, const(char) *base, int w) {
	if (p.fmt.itemno >= FORMATTER_STACK_LIMIT)
		return;
	disasm_fmt_item_t *i = adbg_disasm_fmt_select(p);
	i.type = FormatType.x86_SIB_MemSegBase;
	i.sval1 = base;
	i.sval2 = seg;
	i.ival3 = w;
}
/// (x86) Push a SIB value when MOD=00 BASE=101 into the formatting stack.
/// This is printed depending on its formatter (adbg_disasm_fmt_sib_memsegindexscaleimm).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	index = Index register value
/// 	scale = Scale value
/// 	imm = Displacement value
/// 	w = Operation width
void adbg_disasm_push_x86_sib_m00_b101(adbg_disasm_t *p,
	const(char) *seg, const(char) *index, int scale, int imm, int w) {
	if (p.fmt.itemno >= FORMATTER_STACK_LIMIT)
		return;
	disasm_fmt_item_t *i = adbg_disasm_fmt_select(p);
	i.type = FormatType.x86_SIB_MemSegIndexScaleImm;
	i.sval1 = index;
	i.sval2 = seg;
	i.ival1 = scale;
	i.ival2 = imm;
	i.ival3 = w;
}
/// (x86) Push a SIB value when MOD=00 INDEX=100 BASE=101 into the formatting
/// stack. This is printed depending on its formatter (adbg_disasm_fmt_sib_memsegimm).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	imm = Displacement value
/// 	w = Operation width
void adbg_disasm_push_x86_sib_m00_i100_b101(adbg_disasm_t *p,
	const(char) *seg, int imm, int w) {
	if (p.fmt.itemno >= FORMATTER_STACK_LIMIT)
		return;
	disasm_fmt_item_t *i = adbg_disasm_fmt_select(p);
	i.type = FormatType.x86_SIB_MemSegImm;
	i.sval1 = seg;
	i.ival1 = imm;
	i.ival3 = w;
}
/// (x86) Push a SIB value when MOD=01 into the formatting stack.
/// This is printed depending on its formatter
/// (adbg_disasm_fmt_sib_memsegbaseindexscaleimm).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	base = Base register value
/// 	index = Index register value
/// 	scale = Scale value
/// 	imm = Displacement value
/// 	w = Operation width
void adbg_disasm_push_x86_sib_m01(adbg_disasm_t *p,
	const(char) *seg, const(char) *base, const(char) *index, int scale, int imm, int w) {
	if (p.fmt.itemno >= FORMATTER_STACK_LIMIT)
		return;
	disasm_fmt_item_t *i = adbg_disasm_fmt_select(p);
	i.type = FormatType.x86_SIB_MemSegBaseIndexScaleImm;
	i.sval1 = base;
	i.sval2 = index;
	i.sval3 = seg;
	i.ival1 = scale;
	i.ival2 = imm;
	i.ival3 = w;
}
/// (x86) Push a SIB value when MOD=01 INDEX=100 into the formatting stack.
/// This is printed depending on its formatter
/// (adbg_disasm_fmt_sib_memsegbaseindexscaleimm).
/// Params:
/// 	p = Disassembler parameters
/// 	seg = Segment register value
/// 	base = Base register value
/// 	imm = Displacement value
/// 	w = Operation width
void adbg_disasm_push_x86_sib_m01_i100(adbg_disasm_t *p,
	const(char) *seg, const(char) *base, int imm, int w) {
	if (p.fmt.itemno >= FORMATTER_STACK_LIMIT)
		return;
	disasm_fmt_item_t *i = adbg_disasm_fmt_select(p);
	i.type = FormatType.x86_SIB_MemSegBaseImm;
	i.sval1 = base;
	i.sval2 = seg;
	i.ival1 = imm;
	i.ival3 = w;
}

/// Adjust a signed i8 number from an int, useful with push functions.
/// Params: Unsigned n = 8-bit number
/// Returns: 32-bit adjusted number
int adbg_disasm_adj_i8(ubyte n) {
	if (n > byte.max) // > 127
		return n - 256;
	return n;
}

/// Adjust an unsigned i16 number to an int, useful with push functions.
/// Params: n = Unsigned 16-bit number
/// Returns: 32-bit adjusted number
int adbg_disasm_adj_i16(ushort n) {
	if (n > short.max) // > 32,767
		return n - 65536;
	return n;
}

//
// Core functions
//

/// (Internal) Process items in the formatter stack and output them into the
/// formatter buffers. Caller is responsible of terminating string buffers.
/// Called by adbg_disasm_line.
/// Params: p = Disassembler parameters
void adbg_disasm_render(adbg_disasm_t *p) {
	size_t nitems = p.fmt.itemno; /// number of total items

	if (nitems < 1) return;

	//TODO: "Prefix" types would be procssed here before the main instruction
	//      If need be, peek the first value

	adbg_disasm_fadd(p, &p.fmt.items[0]);

	if (nitems < 2) return;

	adbg_disasm_madd(p, p.options & DISASM_O_SPACE ? DISASM_FMT_SPACE : DISASM_FMT_TAB);

	with (AdbgDisasmSyntax)
	switch (p.syntax) {
	case Att: adbg_disasm_render_att(p, nitems); return;
	default: adbg_disasm_render_intel(p, nitems); return;
	}
}

//
// Internal functions
//

private:

void adbg_disasm_render_intel(adbg_disasm_t *p, size_t nitems) {
	adbg_disasm_fadd(p, &p.fmt.items[1]);

	for (size_t index = 2; index < nitems; ++index) {
		adbg_disasm_madd(p, DISASM_FMT_COMMA_SPACE);
		adbg_disasm_fadd(p, &p.fmt.items[index]);
	}
}
void adbg_disasm_render_att(adbg_disasm_t *p, size_t nitems) {
	size_t index = nitems - 1;
	adbg_disasm_fadd(p, &p.fmt.items[index]);

	for (--index; index > 0; --index) {
		adbg_disasm_madd(p, DISASM_FMT_COMMA_SPACE);
		adbg_disasm_fadd(p, &p.fmt.items[index]);
	}
}

/// (Internal) Automatically select next item to be pushed into the stack. This
/// also increments the stack pointer. Called by pushing functions.
/// Params:
/// 	p = Disassembler parameters
/// Returns: Formatter item
disasm_fmt_item_t *adbg_disasm_fmt_select(adbg_disasm_t *p) {
	return &p.fmt.items[p.fmt.itemno++];
}
/// (Internal) Add string into the formatter's mnemonic string buffer. Called
/// by adbg_disasm_render from adbg_disasm_line.
/// Params:
/// 	p = Disassembler parameters
/// 	s = String
void adbg_disasm_madd(adbg_disasm_t *p, const(char) *s) {
	with (p)
	mnbufi = adbg_util_stradd(cast(char*)mnbuf, DISASM_CBUF_SIZE, mnbufi, s);
}
/// (Internal) Add string into the formatter's machine code string buffer.
/// Called by disasm_push_x* functions.
/// Params:
/// 	p = Disassembler parameters
/// 	s = String
void adbg_disasm_xadd(adbg_disasm_t *p, const(char) *s) {
	with (p)
	mcbufi = adbg_util_stradd(cast(char*)mcbuf, DISASM_CBUF_SIZE, mcbufi, s);
}

/// (Internal) Format and add item to mnemonic buffer. No-op if
/// buffersize - bufferindex <= 0.
/// Params:
/// 	p = Disassembler parameters
/// 	i = Disassembler formatter item
void adbg_disasm_fadd(adbg_disasm_t *p, disasm_fmt_item_t *i) {
	//NOTE: Final switch
	//      + Ensures all enumeration values are used
	//      + Barely makes a different by using functions

	ptrdiff_t left = DISASM_CBUF_SIZE - p.mnbufi;
	if (left <= 0) return;

	char *bp = cast(char*)&p.mnbuf + p.mnbufi;
	const(char) *f = void;
	char[FORMATTER_REGBUF_SIZE] b1 = void, b2 = void, b3 = void;

	with (FormatType)
	final switch (i.type) {
	case String:	adbg_disasm_madd(p, i.sval1); return;
	case Reg:
		if (i.sval1[0] == 0) return;
		adbg_disasm_madd(p, adbg_disasm_fmtreg(p, i.sval1, &b1));
		return;
	case SegReg:
		i.sval1 = adbg_disasm_fmtreg(p, i.sval1, &b1);
		i.sval2 = adbg_disasm_fmtreg(p, i.sval2, &b2);
		p.mnbufi += snprintf(bp, left, "%s%s", i.sval1, i.sval2);
		return;
	case Addr:
		if (i.ival2)
			p.mnbufi += snprintf(bp, left, "<0x%016llx>", i.lval1);
		else
			p.mnbufi += snprintf(bp, left, "<0x%08x>", i.ival1);
		return;
	case Imm:
		with (AdbgDisasmSyntax)
		switch (p.syntax) {
		case Att: f = "$%d"; break;
		default:  f = "%d"; break;
		}
		p.mnbufi += snprintf(bp, left, f, i.ival1);
		return;
	case Imm64:
		with (AdbgDisasmSyntax)
		switch (p.syntax) {
		case Att: f = "$%lld"; break;
		default:  f = "%lld"; break;
		}
		p.mnbufi += snprintf(bp, left, f, i.lval1);
		return;
	case ImmFar:
		with (AdbgDisasmSyntax)
		switch (p.syntax) {
		case Att: f = "$0x%x, $0x%x"; break;
		default:  f = "0x%x:0x%x"; break;
		}
		p.mnbufi += snprintf(bp, left, f, i.ival2, i.ival1);
		return;
	case ImmSeg:
		with (AdbgDisasmSyntax)
		switch (p.syntax) {
		case Att: f = "%%%s0x%x"; break;
		default:  f = "%s0x%x"; break;
		}
		p.mnbufi += snprintf(bp, left, f, i.sval1, i.ival1);
		return;
	case Mem:
		with (AdbgDisasmSyntax)
		switch (p.syntax) {
		case Att: f = "(%d)"; break;
		default:  f = "[%d]"; break;
		}
		p.mnbufi += snprintf(bp, left, f, i.ival1);
		return;
	case MemReg:
		with (AdbgDisasmSyntax)
		switch (p.syntax) {
		case Att:
			//TODO: '*' for any call/jmps under at&t
			//      AT&T syntax emplois '*' for call/jmps with any type (dword/fword)
			//      Also for far jumps and calls, the instruction prepends 'l'
			const(char) *fmt = i.ival3 == MemWidth.far ? "*(%s)" : "(%s)";
			p.mnbufi += snprintf(bp, left, fmt, i.sval1);
			return;
		default:
			p.mnbufi += snprintf(bp, left, "%s ptr [%s]",
				MEM_WIDTHS_INTEL[i.ival3], i.sval1);
			return;
		}
	case MemSegReg:
		i.sval1 = adbg_disasm_fmtreg(p, i.sval1, &b1); // reg
		i.sval2 = adbg_disasm_fmtreg(p, i.sval2, &b2); // seg
		with (AdbgDisasmSyntax)
		switch (p.syntax) {
		case Att:
			const(char) *fmt = i.ival3 == MemWidth.far ? "*%s(%s)" : "%s(%s)";
			p.mnbufi += snprintf(bp, left, fmt, i.sval2, i.sval1);
			return;
		case Nasm:
			p.mnbufi += snprintf(bp, left, "%s ptr [%s%s]",
				MEM_WIDTHS_NASM[i.ival3], i.sval2, i.sval1);
			return;
		default:
			p.mnbufi += snprintf(bp, left, "%s ptr %s[%s]",
				MEM_WIDTHS_INTEL[i.ival3], i.sval2, i.sval1);
			return;
		}
	case MemRegImm:
		i.sval1 = adbg_disasm_fmtreg(p, i.sval1, &b1);
		with (AdbgDisasmSyntax)
		switch (p.syntax) {
		case Att:
			const(char) *fmt = i.ival3 == MemWidth.far ? "*%d(%s)" : "%d(%s)";
			p.mnbufi += snprintf(bp, left, fmt, i.ival1, i.sval1);
			return;
		case Nasm:
			p.mnbufi += snprintf(bp, left, "%s ptr [%s%+d]",
				MEM_WIDTHS_NASM[i.ival3], i.sval1, i.ival1);
			return;
		default:
			p.mnbufi += snprintf(bp, left, "%s ptr [%s%+d]",
				MEM_WIDTHS_INTEL[i.ival3], i.sval1, i.ival1);
			return;
		}
	case MemSegRegImm:
		i.sval2 = adbg_disasm_fmtreg(p, i.sval2, &b2);
		i.sval1 = adbg_disasm_fmtreg(p, i.sval1, &b1);
		with (AdbgDisasmSyntax)
		switch (p.syntax) {
		case Att:
			const(char) *fmt = i.ival3 == MemWidth.far ? "*%s+%d(%s)" : "%s%+d(%s)";
			p.mnbufi += snprintf(bp, left, fmt, i.sval2, i.ival1, i.sval1);
			return;
		case Nasm:
			p.mnbufi += snprintf(bp, left, "%s ptr [%s%s%+d]",
				MEM_WIDTHS_NASM[i.ival3], i.sval2, i.sval1, i.ival1);
			return;
		default:
			p.mnbufi += snprintf(bp, left, "%s ptr %s[%s%+d]",
				MEM_WIDTHS_INTEL[i.ival3], i.sval2, i.sval1, i.ival1);
			return;
		}
	case x86_SIB_MemSegBaseIndexScale:
		i.sval1 = adbg_disasm_fmtreg(p, i.sval1, &b1);
		i.sval2 = adbg_disasm_fmtreg(p, i.sval2, &b2);
		i.sval3 = adbg_disasm_fmtreg(p, i.sval3, &b3);
		with (AdbgDisasmSyntax)
		switch (p.syntax) {
		case Att:
			p.mnbufi += snprintf(bp, left, "%s(%s,%s,%d)", i.sval3, i.sval1, i.sval2, i.ival1);
			return;
		case Nasm:
			p.mnbufi += snprintf(bp, left, "%s ptr [%s%s+%s*%d]",
				MEM_WIDTHS_NASM[i.ival3], i.sval3, i.sval1, i.sval2, i.ival1);
			return;
		default:
			p.mnbufi += snprintf(bp, left, "%s ptr %s[%s+%s*%d]",
				MEM_WIDTHS_INTEL[i.ival3], i.sval3, i.sval1, i.sval2, i.ival1);
			return;
		}
	case x86_SIB_MemSegBase:
		i.sval2 = adbg_disasm_fmtreg(p, i.sval2, &b2);
		i.sval1 = adbg_disasm_fmtreg(p, i.sval1, &b1);
		with (AdbgDisasmSyntax)
		switch (p.syntax) {
		case Att:
			p.mnbufi += snprintf(bp, left, "%s(,%s,)", i.sval2, i.sval1);
			return;
		case Nasm:
			p.mnbufi += snprintf(bp, left, "%s ptr [%s%s]",
				MEM_WIDTHS_NASM[i.ival3], i.sval2, i.sval1);
			return;
		default:
			p.mnbufi += snprintf(bp, left, "%s ptr %s[%s]",
				MEM_WIDTHS_INTEL[i.ival3], i.sval2, i.sval1);
			return;
		}
	case x86_SIB_MemSegIndexScaleImm:
		i.sval2 = adbg_disasm_fmtreg(p, i.sval2, &b2);
		i.sval1 = adbg_disasm_fmtreg(p, i.sval1, &b1);
		with (AdbgDisasmSyntax)
		switch (p.syntax) {
		case Att:
			p.mnbufi += snprintf(bp, left, "%s%+d(,%s,%d)",
				i.sval2, i.ival2, i.sval1, i.ival1);
			return;
		case Nasm:
			p.mnbufi += snprintf(bp, left, "%s ptr [%s%s*%d%+d]",
				MEM_WIDTHS_NASM[i.ival3], i.sval2, i.sval1, i.ival1, i.ival2);
			return;
		default:
			p.mnbufi += snprintf(bp, left, "%s ptr %s[%s*%d%+d]",
				MEM_WIDTHS_INTEL[i.ival3], i.sval2, i.sval1, i.ival1, i.ival2);
			return;
		}
	case x86_SIB_MemSegImm:
		i.sval1 = adbg_disasm_fmtreg(p, i.sval1, &b1);
		with (AdbgDisasmSyntax)
		switch (p.syntax) {
		case Att:
			p.mnbufi += snprintf(bp, left, "%s%+d(,,)", i.sval1, i.ival1);
			return;
		case Nasm:
			p.mnbufi += snprintf(bp, left, "%s ptr [%s%+d]",
				MEM_WIDTHS_NASM[i.ival3], i.sval1, i.ival1);
			return;
		default:
			p.mnbufi += snprintf(bp, left, "%s ptr %s[%+d]",
				MEM_WIDTHS_INTEL[i.ival3], i.sval1, i.ival1);
			return;
		}
	case x86_SIB_MemSegBaseIndexScaleImm:
		i.sval3 = adbg_disasm_fmtreg(p, i.sval3, &b3);
		i.sval1 = adbg_disasm_fmtreg(p, i.sval1, &b1);
		i.sval2 = adbg_disasm_fmtreg(p, i.sval2, &b2);
		with (AdbgDisasmSyntax)
		switch (p.syntax) {
		case Att:
			p.mnbufi += snprintf(bp, left, "%s%+d(%s,%s,%d)",
				i.sval3, i.ival2, i.sval1, i.sval2, i.ival1);
			return;
		case Nasm:
			p.mnbufi += snprintf(bp, left, "%s ptr [%s%s+%s*%d%+d]",
				MEM_WIDTHS_NASM[i.ival3], i.sval3, i.sval1, i.sval2, i.ival1, i.ival2);
			return;
		default:
			p.mnbufi += snprintf(bp, left, "%s ptr %s[%s+%s*%d%+d]",
				MEM_WIDTHS_INTEL[i.ival3], i.sval3, i.sval1, i.sval2, i.ival1, i.ival2);
			return;
		}
	case x86_SIB_MemSegBaseImm:
		i.sval2 = adbg_disasm_fmtreg(p, i.sval2, &b2);
		i.sval1 = adbg_disasm_fmtreg(p, i.sval1, &b1);
		with (AdbgDisasmSyntax)
		switch (p.syntax) {
		case Att:
			p.mnbufi += snprintf(bp, left, "%s%+d(%s,,)", i.sval2, i.ival1, i.sval1);
			return;
		case Nasm:
			p.mnbufi += snprintf(bp, left, "%s ptr [%s%s%+d]",
				MEM_WIDTHS_NASM[i.ival3], i.sval2, i.sval1, i.ival1);
			return;
		default:
			p.mnbufi += snprintf(bp, left, "%s ptr %s[%s%+d]",
				MEM_WIDTHS_INTEL[i.ival3], i.sval2, i.sval1, i.ival1);
			return;
		}
	}
}
const(char) *adbg_disasm_fmtreg(adbg_disasm_t *p, const(char) *s, char[FORMATTER_REGBUF_SIZE] *buffer) {
	import core.stdc.stdio : snprintf;
	if (s[0] == 0) return "";
	with (AdbgDisasmSyntax)
	switch (p.syntax) {
	case Att:
		snprintf(cast(char*)buffer, 16, "%%%s", s);
		return cast(char*)buffer;
	default: return s;
	}
}
