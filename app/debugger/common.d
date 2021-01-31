/**
 * Common stuff shared between UIs, such as global variables.
 *
 * Sharing this module adbg.has a few advantages such as: reduce binary size, avoid
 * linking issues, etc.
 *
 * License: BSD-3-Clause
 */
module app.debugger.common;

import adbg.debugger.exception;
import adbg.disasm;
import core.stdc.string : memcpy;

public:
extern (C):
__gshared:

/// Last exception
exception_t common_exception;

/// Disassembler parameters
adbg_disasm_t common_disasm_params;
