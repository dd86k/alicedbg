/**
 * Common stuff shared between UIs, such as global variables.
 *
 * Sharing this module adbg.has a few advantages such as: reduce binary size, avoid
 * linking issues, etc.
 *
 * License: BSD 3-clause
 */
module adbg.ui.common;

import adbg.disasm;
import core.stdc.string : memcpy;

public:

/// Disassembler parameters
__gshared disasm_params_t g_disparams;

void adbg_ui_common_params(disasm_params_t *params) {
	memcpy(&g_disparams, params, disasm_params_t.sizeof);
}