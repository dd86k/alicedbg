/**
 * Common stuff shared between UIs, such as global variables.
 *
 * Sharing this module adbg.has a few advantages such as: reduce binary size, avoid
 * linking issues, etc.
 *
 * License: BSD 3-clause
 */
module debugger.common;

import adbg.debugger.exception;
import adbg.disasm;
import core.stdc.string : memcpy;

public:
extern (C):
__gshared:

/// Last exception
exception_t g_lastexception;

/// Disassembler parameters
adbg_disasm_t g_disparams;

void adbg_ui_common_params(adbg_disasm_t *params) {
	memcpy(&g_disparams, params, adbg_disasm_t.sizeof);
}