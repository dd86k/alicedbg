/**
 * Implements the Netwide Assembler syntax.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.disasm.syntax.nasm;

import adbg.disasm : adbg_disasm_t;
import adbg.disasm.syntaxer;

private immutable const(char)*[] WIDTHS = [
	"byte", "word", "dword", "qword",
	"oword", "yword", "zword", "word?"
];

// render nasm
void adbg_syntax_nasm_item(adbg_syntax_t *p, adbg_syntax_item_t *i) {
	
	
}

