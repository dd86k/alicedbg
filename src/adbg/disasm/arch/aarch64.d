/**
 * Arm Aarch64 decoder.
 *
 * License: BSD 3-clause
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

//TODO: Functions to process opcodes by types (C.I, I, C.J, J, etc.)
//      1. rv32_ci(string, int) e.g. rv32_ci("c.jal", op);
//      2. rv32_ci(string, string, int) e.g. rv32_ci("c.jal", "x1", 0x20);

/// Disassemble Aarch64
/// Params: p = Disassembler parameters
void adbg_dasm_aarch64(disasm_params_t *p) {
}