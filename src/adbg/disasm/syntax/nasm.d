/**
 * Implements the Netwide Assembler syntax.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.disasm.syntax.nasm;

import adbg.disasm, adbg.utils.str;

extern (C):

private immutable const(char)*[] NASM_WIDTH = [
	"byte", "word", "dword", "qword", "oword", "yword", "zword", UNKNOWN_TYPE,
	"word", "dword", "qword", "oword", "fword", "tword", UNKNOWN_TYPE, UNKNOWN_TYPE,
];

// render nasm
bool adbg_disasm_operand_nasm(adbg_disasm_t *p, ref adbg_string_t s, ref adbg_disasm_operand_t op) {
	switch (op.type) with (AdbgDisasmOperand) {
	case immediate:
		if (p.far) {
			if (s.adds("0x"))
				return true;
			if (s.addx16(op.imm.segment))
				return true;
			if (s.addc(':'))
				return true;
		}
		return adbg_disasm_render_number(p, s, op.imm.value, false);
	case register:
		if (s.adds(op.reg.name))
			return true;
		return op.reg.index ? s.addf("(%u)", op.reg.index) : false;
	case memory:
		if (s.adds(NASM_WIDTH[p.memWidth]))
			return true;
		if (s.adds(" ptr ["))
			return true;
		
		//TODO: p.decoderOpts.noSegment
		if (op.mem.segment) {
			if (s.adds(op.mem.segment))
				return true;
			if (s.addc(':'))
				return true;
		}
		
		if (op.mem.base)
			if (s.adds(op.mem.base))
				return true;
		if (op.mem.index) {
			if (op.mem.base)
				if (s.addc('+'))
					return true;
			if (s.adds(op.mem.index))
				return true;
		}
		if (op.mem.scale) {
			if (s.addf("*%u", op.mem.scale))
				return true;
		}
		if (op.mem.hasOffset) {
			bool addPlus = op.mem.base != null || op.mem.index != null;
			if (adbg_disasm_render_number(p, s, op.mem.offset, addPlus))
				return true;
		}
		
		return s.addc(']');
	default: assert(0);
	}
}