/**
 * Implemets the AT&T syntax.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.disasm.syntax.att;

import adbg.disasm : adbg_disasm_t, adbg_disasm_operand_t, AdbgDisasmOperand,
	adbg_disasm_render_number;
import adbg.utils.str;

extern (C):

// render at&t
bool adbg_disasm_operand_att(adbg_disasm_t *p, ref adbg_string_t s, ref adbg_disasm_operand_t op) {
	switch (op.type) with (AdbgDisasmOperand) {
	case immediate: return adbg_disasm_render_number(p, s, op.imm.value, false);
	case register:
		if (s.addc('%'))
			return true;
		return s.adds(op.reg.name);
	case memory:
		//TODO: p.decoderOpts.noSegment
		if (p.opcode.segment) {
			if (s.addc('%'))
				return true;
			if (s.adds(p.opcode.segment))
				return true;
			if (s.addc(':'))
				return true;
		}
		
		if (op.mem.offset.i32)
			if (adbg_disasm_render_number(p, s, op.mem.offset, true))
				return true;
		
		if (s.addc('('))
			return true;
		
		if (op.mem.scaled) { // SIB
			if (op.mem.base)
				if (s.adds(op.mem.base))
					return true;
			if (s.addc(','))
				return true;
			if (op.mem.index)
				if (s.adds(op.mem.index))
					return true;
			if (s.addc(','))
				return true;
			if (op.mem.scale)
				if (s.addf("%u", op.mem.scale))
					return true;
		} else if (op.mem.base) { // register-based
			if (s.adds(op.mem.base))
				return true;
			if (op.mem.index) {
				if (s.addc(','))
					return true;
				if (s.adds(op.mem.index))
					return true;
			}
		} else { // Absolute (+far) or relative address
			//TODO: address
		}
		
		return s.addc(')');
	default: assert(0);
	}
}

