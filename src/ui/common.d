/**
 * Common stuff shared between UIs, such as global variables.
 *
 * Sharing this module has a few advantages such as: reduce binary size, avoid
 * linking issues, etc.
 *
 * License: BSD 3-Clause
 */
module ui.common;

import debugger.disasm;

public:

/// Disassembler parameters
__gshared disasm_params_t disparams;
