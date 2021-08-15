/**
 * Implements Randall Hyde's High Level Assembly syntax.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.disasm.syntax.hyde;

import adbg.disasm, adbg.utils.str;

extern (C):

private immutable const(char)*[] HYDE_WIDTH = [
	"byte",    "word",    "dword",   "qword",
	"xmmword", "ymmword", "zmmword", UNKNOWN_TYPE,
	UNKNOWN_TYPE, UNKNOWN_TYPE, UNKNOWN_TYPE, UNKNOWN_TYPE,
	UNKNOWN_TYPE, UNKNOWN_TYPE, UNKNOWN_TYPE, UNKNOWN_TYPE,
];

// render hla
bool adbg_disasm_operand_hyde(adbg_disasm_t *p, ref adbg_string_t s, ref adbg_disasm_operand_t op) {
	switch (op.type) with (AdbgDisasmOperand) {
	//TODO: Handle far
	case immediate: return adbg_disasm_render_number(p, s, op.imm.value, false);
	case register:  return s.adds(op.reg.name);
	case memory:
		if (s.adds("[type "))
			return true;
		if (s.adds(HYDE_WIDTH[p.memWidth]))
			return true;
		if (s.addc(' '))
			return true;
		
		if (op.mem.scaled) { // SIB
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
				if (s.addc('*'))
					return true;
				if (s.addf("%u", op.mem.scale))
					return true;
			}
			if (op.mem.hasOffset) {
				if (adbg_disasm_render_number(p, s, op.mem.offset, true))
					return true;
			}
		} else if (op.mem.base) { // register-based
			if (s.adds(op.mem.base))
				return true;
			if (op.mem.index) {
				if (s.addc('+'))
					return true;
				if (s.adds(op.mem.index))
					return true;
			}
			if (op.mem.hasOffset) {
				if (adbg_disasm_render_number(p, s, op.mem.offset, true))
					return true;
			}
		} else { // Absolute (+far) or relative address
			//TODO: address
		}
		
		return s.addc(']');
	default: assert(0);
	}
}