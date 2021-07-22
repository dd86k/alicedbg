/**
 * Implements the Intel syntax.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.disasm.syntax.intel;

import adbg.disasm : adbg_disasm_t;
import adbg.disasm.syntaxer;

extern (C):

private immutable const(char)*[] INTEL_WIDTH = [
	"byte",    "word",    "dword",   "qword",
	"xmmword", "ymmword", "zmmword", "word?"
];

// render intel
void adbg_syntax_op_intel(ref adbg_syntaxer_t p, ref adbg_syntax_op_t op) {
	switch (op.type) with (AdbgSyntaxOperand) {
	case immediate:
		p.mnemonicBuffer.add("0x%x", op.imm.value);
		break;
	case register:
		p.mnemonicBuffer.add(op.reg.name);
		break;
	case memory:
		p.mnemonicBuffer.add(INTEL_WIDTH[op.mem.width]);
		p.mnemonicBuffer.add(" ptr ");
		
		//TODO: p.decoderOpts.noSegment
		if (p.segmentRegister) {
			p.mnemonicBuffer.add(p.segmentRegister);
			p.mnemonicBuffer.add(':');
		}
		
		p.mnemonicBuffer.add('[');
		
		if (op.mem.base) { // register-based
			p.mnemonicBuffer.add(op.mem.base);
			if (op.mem.index) {
				p.mnemonicBuffer.add('+');
				p.mnemonicBuffer.add(op.mem.index);
			}
			if (op.mem.scale) {
				p.mnemonicBuffer.add('*');
				p.mnemonicBuffer.add("%u", op.mem.scale);
			}
			if (op.mem.disp) {
				
			}
		} else { // Absolute (+far) or relative address
		}
		
		p.mnemonicBuffer.add(']');
		break;
	default: assert(0);
	}
}