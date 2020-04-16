/**
 * Common stuff shared between UIs, such as global variables.
 *
 * Sharing this module adbg.has a few advantages such as: reduce binary size, avoid
 * linking issues, etc.
 *
 * License: BSD 3-Clause
 */
module adbg.ui.common;

import adbg.debugger.disasm;

public:

/// Disassembler parameters
__gshared disasm_params_t g_disparams;
