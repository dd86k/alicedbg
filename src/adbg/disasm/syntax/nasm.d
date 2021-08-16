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
	"byte",  "word",  "dword", "qword",
	"oword", "yword", "zword", UNKNOWN_TYPE,
	UNKNOWN_TYPE, UNKNOWN_TYPE, UNKNOWN_TYPE, UNKNOWN_TYPE,
	UNKNOWN_TYPE, UNKNOWN_TYPE, UNKNOWN_TYPE, UNKNOWN_TYPE,
];

// render nasm
bool adbg_disasm_operand_nasm(adbg_disasm_t *p, ref adbg_string_t s, ref adbg_disasm_operand_t op) {
	switch (op.type) with (AdbgDisasmOperand) {
	case immediate: return adbg_disasm_render_number(p, s, op.imm.value, false);
	case register:  return s.adds(op.reg.name);
	case memory:
		if (s.adds(NASM_WIDTH[p.memWidth]))
			return true;
		if (s.adds(" ptr ["))
			return true;
		
		//TODO: p.decoderOpts.noSegment
		if (p.opcode.segment) {
			if (s.adds(p.opcode.segment))
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