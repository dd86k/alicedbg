/**
 * Disassembler styling engine
 */
deprecated
module debugger.disasm.style;

import debugger.disasm.core;
import utils.str;
import core.stdc.stdarg;

extern (C):

//
// Enumerations
//

version (X86)
	/// Optimal style depending on ISA
	enum DISASM_STYLE_OPTIMAL = DisasmSyntax.Intel;
else version (X86_64)
	/// Optimal style depending on ISA
	enum DISASM_STYLE_OPTIMAL = DisasmSyntax.Intel;
else version (ARM)
	/// Optimal style depending on ISA
	enum DISASM_STYLE_OPTIMAL = DisasmSyntax.Att;
else version (Aarch64)
	/// Optimal style depending on ISA
	enum DISASM_STYLE_OPTIMAL = DisasmSyntax.Att;

package:

//immutable const(char) *UNKNOWN_OP = "??";

void style_ill(ref disasm_params_t p) {
	if (p.mode & DISASM_I_MACHINECODE)
		mnadd(p, UNKNOWN_OP);
	p.error = DisasmError.Illegal;
}

void style_mc_x8(ref disasm_params_t p, ubyte v) {
	style_mc_f(p, "%02X ", v);
}
void style_mc_x16(ref disasm_params_t p, ushort v) {
	style_mc_f(p, "%04X ", v);
}
void style_mc_x32(ref disasm_params_t p, uint v) {
	style_mc_f(p, "%08X ", v);
}
void style_mc_x64(ref disasm_params_t p, ulong v) {
	style_mc_f(p, "%016llX ", v);
}

void style_mn_2(ref disasm_params_t p, const(char) *a, const(char) *b) {
	immutable const(char) *f = " %s, %s";
	const(char) *c = void;

	with (DisasmSyntax)
	switch (p.style) {
	case Att: c = strf(f, b, a); break;
	default: c = strf(f, a, b); break;
	}

	style_mn(p, c);
}

const(char) *style_mn_reg(ref disasm_params_t p, const(char) *reg) {
	if (p.style == DisasmSyntax.Att)
		return strf("%%%s", reg);
	else
		return reg;
}

const(char) *style_mn_seg(ref disasm_params_t p, const(char) *seg) {
	if (seg[0] == 0) return seg;
	return style_mn_reg(p, seg);
}

const(char) *style_mn_imm(ref disasm_params_t p, int imm) {
	if (p.style  == DisasmSyntax.Att)
		return strf("$%d", imm);
	else
		return strf("%d", imm);
}

const(char) *style_mn_mem(ref disasm_params_t p, uint mem) {
	return style_mn_segmem(p, "", mem);
}

const(char) *style_mn_segmem(ref disasm_params_t p, const(char) *seg, uint mem) {
	if (p.style  == DisasmSyntax.Att)
		return strf("(%u)", mem);
	else
		return strf("[%u]", mem);
}

const(char) *style_mn_memstr(ref disasm_params_t p, const(char) *mem) {
	return style_mn_segmemstr(p, "", mem);
}

const(char) *style_mn_segmemstr(ref disasm_params_t p, const(char) *seg, const(char) *mem) {
	if (p.style  == DisasmSyntax.Att)
		return strf("(%s%s)", seg, mem);
	else
		return strf("[%s%s]", seg, mem);
}

//
// (X86) ModR/M
//

void style_mn_rm_00(ref disasm_params_t p,
	const(char) *seg, const(char) *reg) {
	seg = style_mn_seg(p, seg);
	reg = style_mn_reg(p, reg);
	with (DisasmSyntax)
	final switch (p.style) {
	case Intel:
		style_mn_f(p, " %s[%s]", seg, reg);
		break;
	case Nasm:
		style_mn_f(p, " [%s%s]", seg, reg);
		break;
	case Att:
		style_mn_f(p, " %s(%s)", seg, reg);
		break;
	}
}
void style_mn_rm_01(ref disasm_params_t p,
	const(char) *seg, const(char) *reg, int imm) {
	seg = style_mn_seg(p, seg);
	reg = style_mn_reg(p, reg);
	with (DisasmSyntax)
	final switch (p.style) {
	case Intel:
		style_mn_f(p, " %s[%s%+d]", seg, reg, imm);
		break;
	case Nasm:
		style_mn_f(p, " [%s%s%+d]", seg, reg, imm);
		break;
	case Att:
		style_mn_f(p, " %s%+d(%s)", seg, imm, reg);
		break;
	}
}

//
// (X86) SIB
//
// Intel: section:[base + index*scale + disp]
// ATT: section:disp(base, index, scale)
//

void style_mn_sib_00(ref disasm_params_t p,
	const(char) *seg, const(char) *base, const(char) *index, int scale) {
	seg = style_mn_seg(p, seg);
	base = style_mn_reg(p, base);
	index = style_mn_reg(p, index);
	with (DisasmSyntax)
	final switch (p.style) {
	case Intel:
		style_mn_f(p, " %s[%s+%s*%d]", seg, base, index, scale);
		break;
	case Nasm:
		style_mn_f(p, " [%s%s+%s*%d]", seg, base, index, scale);
		break;
	case Att:
		style_mn_f(p, " %s(%s,%s,%d)", seg, base, index, scale);
		break;
	}
}
void style_mn_sib_00_100(ref disasm_params_t p,
	const(char) *seg, const(char) *index) {
	seg = style_mn_seg(p, seg);
	index = style_mn_reg(p, index);
	with (DisasmSyntax)
	final switch (p.style) {
	case Intel:
		style_mn_f(p, " %s[%s]", seg, index);
		break;
	case Nasm:
		style_mn_f(p, " [%s%s]", seg, index);
		break;
	case Att:
		style_mn_f(p, " %s(,%s,)", seg, index);
		break;
	}
}
void style_mn_sib_00_101(ref disasm_params_t p,
	const(char) *seg, const(char) *index, int scale, int imm) {
	seg = style_mn_seg(p, seg);
	index = style_mn_reg(p, index);
	with (DisasmSyntax)
	final switch (p.style) {
	case Intel:
		style_mn_f(p, " %s[%s*%d%+d]", seg, index, scale, imm);
		break;
	case Nasm:
		style_mn_f(p, " [%s%s*%d%+d]", seg, index, scale, imm);
		break;
	case Att:
		style_mn_f(p, " %s%+d(,%s,%d)", seg, imm, index, scale);
		break;
	}
}
void style_mn_sib_00_101_100(ref disasm_params_t p,
	const(char) *seg, int imm) {
	seg = style_mn_seg(p, seg);
	with (DisasmSyntax)
	final switch (p.style) {
	case Intel:
		style_mn_f(p, " %s[%+d]", seg, imm);
		break;
	case Nasm:
		style_mn_f(p, " [%s%+d]", seg, imm);
		break;
	case Att:
		style_mn_f(p, " %s%+d(,,)", seg, imm);
		break;
	}
}
void style_mn_sib_01(ref disasm_params_t p,
	const(char) *seg, const(char) *base, const(char) *index, int scale, int imm) {
	seg = style_mn_seg(p, seg);
	base = style_mn_reg(p, base);
	index = style_mn_reg(p, index);
	with (DisasmSyntax)
	final switch (p.style) {
	case Intel:
		style_mn_f(p, " %s[%s+%s*%d%+d]", seg, base, index, scale, imm);
		break;
	case Nasm:
		style_mn_f(p, " [%s%s+%s*%d%+d]", seg, base, index, scale, imm);
		break;
	case Att:
		style_mn_f(p, " %s%+d(%s,%s,%d)", seg, imm, base, index, scale);
		break;
	}
}
void style_mn_sib_01_100(ref disasm_params_t p,
	const(char) *seg, const(char) *base, int imm) {
	seg = style_mn_seg(p, seg);
	base = style_mn_reg(p, base);
	with (DisasmSyntax)
	final switch (p.style) {
	case Intel:
		style_mn_f(p, " %s[%s%+d]", seg, base, imm);
		break;
	case Nasm:
		style_mn_f(p, " [%s%s%+d]", seg, base, imm);
		break;
	case Att:
		style_mn_f(p, " %s%+d(%s,,)", seg, imm, base);
		break;
	}
}

//
// Core functions
//

void style_mc(ref disasm_params_t p, const(char) *str) {
	with (p)
	mcbufi = stradd(cast(char*)mcbuf, DISASM_BUF_SIZE, mcbufi, str);
}

void style_mc_f(ref disasm_params_t p, const(char) *f, ...) {
	va_list va;
	va_start(va, f);
	with (p)
	mcbufi = straddva(cast(char*)mcbuf, DISASM_BUF_SIZE, mcbufi, f, va);
}

void style_mn(ref disasm_params_t p, const(char) *str) {
	with (p)
	mnbufi = stradd(cast(char*)mnbuf, DISASM_BUF_SIZE, mnbufi, str);
}

void style_mn_f(ref disasm_params_t p, const(char) *f, ...) {
	va_list va;
	va_start(va, f);
	with (p)
	mnbufi = straddva(cast(char*)mnbuf, DISASM_BUF_SIZE, mnbufi, f, va);
}