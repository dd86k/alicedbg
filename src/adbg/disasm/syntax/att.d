/**
 * Implemets the AT&T syntax.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.disasm.syntax.att;

import adbg.disasm : adbg_disasm_t, adbg_disasm_operand_t;
import adbg.utils.str;

extern (C):

// render at&t
bool adbg_disasm_operand_att(adbg_disasm_t *p, ref adbg_string_t s, ref adbg_disasm_operand_t op) {
	
	return false;
}

