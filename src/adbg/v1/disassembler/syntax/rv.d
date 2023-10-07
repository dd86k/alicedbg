/**
 * Implements the RISC-V native syntax.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module adbg.v1.disassembler.syntax.rv;

import adbg.v1.disassembler : adbg_disasm_t, adbg_disasm_operand_t, AdbgDisasmOperand;
import adbg.v1.disassembler.formatter;
import adbg.utils.strings;

extern (C):

// render at&t
bool adbg_disasm_operand_riscv(adbg_disasm_t *p, ref adbg_string_t s, ref adbg_disasm_operand_t op) {
	switch (op.type) with (AdbgDisasmOperand) {
	case immediate:
		if (op.imm.absolute) {
			if (s.adds("0x"))
				return true;
			if (s.addx16(op.imm.segment))
				return true;
			if (s.adds(":"))
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
		if (op.mem.segment) {
			if (s.adds(op.mem.segment))
				return true;
			if (s.addc(':'))
				return true;
		}
		
		if (op.mem.hasOffset)
			if (adbg_disasm_render_number(s, op.mem.offset, false, false))
				return true;
		
		if (s.addc('('))
			return true;
		
		if (op.mem.scaled) { // SIB
			if (op.mem.base) {
				if (s.adds(op.mem.base))
					return true;
			}
			if (s.addc('+'))
				return true;
			if (op.mem.index)
				if (s.adds(op.mem.index))
					return true;
			if (op.mem.scale)
				if (s.addf("*%u", op.mem.scale))
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
		}
		
		return s.addc(')');
	default: assert(0);
	}
}

