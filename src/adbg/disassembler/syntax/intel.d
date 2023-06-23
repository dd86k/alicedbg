/**
 * Implements the Intel syntax.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2022 dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module adbg.disassembler.syntax.intel;

import adbg.disassembler : adbg_disasm_t, adbg_disasm_operand_t, AdbgDisasmOperand;
import adbg.disassembler.formatter;
import adbg.utils.string;

extern (C):

private immutable const(char)*[16] INTEL_WIDTH = [
	null,
	"byte", "word",  "dword", "qword", "xmmword", "ymmword", "zmmword", TYPE_UNKNOWN,
	"fword", "tbyte", TYPE_UNKNOWN, TYPE_UNKNOWN, TYPE_UNKNOWN, TYPE_UNKNOWN, TYPE_UNKNOWN,
];

// render intel
bool adbg_disasm_operand_intel(adbg_disasm_t *p, ref adbg_string_t s, ref adbg_disasm_operand_t op) {
	switch (op.type) with (AdbgDisasmOperand) {
	case immediate:
		if (op.imm.absolute) {
			if (s.adds("0x"))
				return true;
			if (s.addx16(op.imm.segment))
				return true;
			if (s.addc(':'))
				return true;
		}
		return adbg_disasm_render_number(s, op.imm.value, false, false);
	case register:
		if (s.adds(op.reg.name))
			return true;
		if (op.reg.isStack)
			if (s.addf("(%u)", op.reg.index))
				return true;
		if (op.reg.mask1) {
			if (s.addf(" {%s}", op.reg.mask1))
				return true;
			if (op.reg.mask2)
				if (s.addf("{%s}", op.reg.mask2))
					return true;
		}
		return false;
	case memory:
		if (p.memWidth) {
			if (s.adds(INTEL_WIDTH[p.memWidth]))
				return true;
			if (s.adds(" ptr "))
				return true;
		}
		
		if (op.mem.segment) {
			if (s.adds(op.mem.segment))
				return true;
			if (s.addc(':'))
				return true;
		}
		
		if (s.addc('['))
			return true;
		
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
			if (adbg_disasm_render_number(s, op.mem.offset, addPlus, false))
				return true;
		}
		
		return s.addc(']');
	default: assert(0);
	}
}