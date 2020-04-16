/**
 * x86-16 disassembler (based on x86-32 decoder)
 *
 * License: BSD 3-Clause
 */
module adbg.debugger.disasm.arch.x86_16;

import adbg.debugger.disasm.core : disasm_params_t;
import adbg.debugger.disasm.arch.x86 : adbg_dasm_x86, x86_internals_t;

extern (C):

/**
 * x86-16 disassembler.
 * Params: p = Disassembler parameters
 */
void adbg_dasm_x86_16(disasm_params_t *p) {
	x86_internals_t i;
	i.pf_operand = 0x66;
	i.pf_address = 0x67;
	p.x86 = &i;
	adbg_dasm_x86(p, false);
}