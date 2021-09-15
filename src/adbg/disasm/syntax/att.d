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
	case immediate:
		if (op.imm.absolute) {
			if (s.adds("$0x"))
				return true;
			if (s.addx16(op.imm.segment))
				return true;
			if (s.adds(", "))
				return true;
		}
		if (s.addc('$'))
			return true;
		return adbg_disasm_render_number(p, s, op.imm.value, false);
	case register:
		if (s.addc('%'))
			return true;
		if (s.adds(op.reg.name))
			return true;
		return op.reg.isStack ? s.addf("(%u)", op.reg.index) : false;
	case memory:
		if (op.mem.segment) {
			if (s.addc('%'))
				return true;
			if (s.adds(op.mem.segment))
				return true;
			if (s.addc(':'))
				return true;
		}
		
		if (op.mem.hasOffset)
			if (adbg_disasm_render_number(p, s, op.mem.offset, true))
				return true;
		
		if (op.mem.absolute)
			if (s.addc('*'))
				return true;
		
		if (s.addc('('))
			return true;
		
		if (op.mem.scaled) { // SIB
			if (op.mem.base) {
				if (s.addc('%'))
					return true;
				if (s.adds(op.mem.base))
					return true;
			}
			if (s.addc(','))
				return true;
			if (op.mem.index) {
				if (s.addc('%'))
					return true;
				if (s.adds(op.mem.index))
					return true;
			}
			if (s.addc(','))
				return true;
			if (op.mem.scale)
				if (s.addf("%u", op.mem.scale))
					return true;
		} else if (op.mem.base) { // register-based
			if (s.addc('%'))
				return true;
			if (s.adds(op.mem.base))
				return true;
			if (op.mem.index) {
				if (s.adds(",%"))
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
