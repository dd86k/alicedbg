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

int adbg_syntax_intel_start(adbg_syntax_t *p) {
	for (size_t i; i < p.index; ++i) {
		// or ref
		adbg_syntax_item_t *item = &p.buffer[i];
		
		
	}
	
	return 0;
}