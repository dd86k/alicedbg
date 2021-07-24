/**
 * Implements the Intel syntax.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.disasm.syntax.intel;

import adbg.disasm : adbg_disasm_t, adbg_disasm_operand_t, AdbgDisasmOperand;
import adbg.utils.str;

extern (C):

private immutable const(char)*[] INTEL_WIDTH = [
	"byte",    "word",    "dword",   "qword",
	"xmmword", "ymmword", "zmmword", "word?"
];

// render intel
bool adbg_disasm_operand_intel(adbg_disasm_t *p, ref adbg_string_t s, ref adbg_disasm_operand_t op) {
	switch (op.type) with (AdbgDisasmOperand) {
	case immediate: return s.addf("0x%x", op.imm.value);
	case register:  return s.add(op.reg.name);
	case memory:
		if (s.add(INTEL_WIDTH[op.mem.width]))
			return true;
		if (s.add(" ptr "))
			return true;
		
		//TODO: p.decoderOpts.noSegment
		if (p.opcode.segment) {
			if (s.add(p.opcode.segment))
				return true;
			if (s.add(':'))
				return true;
		}
		
		if (s.add('['))
			return true;
		
		if (op.mem.base) { // register-based
			if (s.add(op.mem.base))
				return true;
			if (op.mem.index) {
				if (s.add('+'))
					return true;
				if (s.add(op.mem.index))
					return true;
			}
			if (op.mem.scale) {
				if (s.add('*'))
					return true;
				if (s.addf("%u", op.mem.scale))
					return true;
			}
			if (op.mem.disp) {
				//TODO: Displacement
			}
		} else { // Absolute (+far) or relative address
			//TODO: address
		}
		
		return s.add(']');
	default: assert(0);
	}
}