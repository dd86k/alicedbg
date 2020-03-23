/**
 * x86-16 disassembler (based on x86-32 decoder)
 *
 * License: BSD 3-Clause
 */
module debugger.disasm.arch.x86_16;

import debugger.disasm.core : disasm_params_t;
import debugger.disasm.arch.x86 : disasm_x86, x86_internals_t;

extern (C):

/**
 * x86-16 disassembler.
 * Params: p = Disassembler parameters
 */
void disasm_x86_16(disasm_params_t *p) {
	x86_internals_t i;
	i.pf_operand = 0x66;
	i.pf_address = 0x67;
	p.x86 = &i;
	disasm_x86(p, false);
}