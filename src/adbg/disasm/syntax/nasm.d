/**
 * Implements the Netwide Assembler syntax.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.disasm.syntax.nasm;

import adbg.disasm : adbg_disasm_t, adbg_disasm_operand_t;
import adbg.utils.str;

extern (C):

private immutable const(char)*[] NASM_WIDTH = [
	"byte", "word", "dword", "qword",
	"oword", "yword", "zword", "word?"
];

// render nasm
bool adbg_disasm_operand_nasm(adbg_disasm_t *p, ref adbg_string_t s, ref adbg_disasm_operand_t op) {
	
	
	
	return false;
}

