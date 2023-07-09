/**
 * Implements Randall Hyde's High Level Assembly syntax.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module adbg.v1.disassembler.syntax.hyde;

import adbg.v1.disassembler : adbg_disasm_t, adbg_disasm_operand_t, AdbgDisasmOperand;
import adbg.v1.disassembler.formatter;
import adbg.utils.string;

extern (C):

private immutable const(char)*[16] HYDE_WIDTH = [
	null,
	"byte",  "word",  "dword", "qword", "xmmword", "ymmword", "zmmword", TYPE_UNKNOWN,
	"fword", "tbyte", TYPE_UNKNOWN, TYPE_UNKNOWN, TYPE_UNKNOWN, TYPE_UNKNOWN, TYPE_UNKNOWN,
];

// render hla
bool adbg_disasm_operand_hyde(adbg_disasm_t *p, ref adbg_string_t s, ref adbg_disasm_operand_t op) {
	switch (op.type) with (AdbgDisasmOperand) {
	case immediate: //TODO: Handle absolute
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
			if (s.adds("[type "))
				return true;
			if (s.adds(HYDE_WIDTH[p.memWidth]))
				return true;
			if (s.addc(' '))
				return true;
		} else if (s.addc('['))
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