/**
 * Arm Aarch64 decoder.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: See LICENSE
 * License: BSD-3-Clause
 */
module adbg.disasm.arch.aarch64;

import adbg.disasm.disasm;
import adbg.disasm.formatter;
import adbg.utils.bit;

extern (C):

struct aarch64_internals_t { align(1):
	union {
		uint op;
		version (LittleEndian)
			struct { align(1): ushort op1, op2; }
		else
			struct { align(1): ushort op2, op1; }
	}
}

/// Disassemble Aarch64
/// Params: p = Disassembler parameters
void adbg_disasm_aarch64(adbg_disasm_t *p) {
}