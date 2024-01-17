/// Process breakpoint management and evaluation.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.v2.debugger.breakpoint;

import adbg.v2.debugger.process;
import adbg.error;

extern (C):

// NOTE: When a breakpoint is hit by the debugger, the address should
//       be checked against the process' breakpoint list.

version (X86) {
	private alias ubyte opcode_t;
	private enum opcode_t BREAKPOINT = 0xCC; // INT3
} else version (X86_64) {
	private alias ubyte opcode_t;
	private enum opcode_t BREAKPOINT = 0xCC; // INT3
} else version (ARM_Thumb) {
	private alias ushort opcode_t;
	version (LittleEndian)
		private enum opcode_t BREAKPOINT = 0xDDBE; // BKPT #221 (0xdd)
	else
		private enum opcode_t BREAKPOINT = 0xBEDD; // BKPT #221 (0xdd)
} else version (ARM) {
	private alias uint opcode_t;
	version (LittleEndian)
		private enum opcode_t BREAKPOINT = 0x7D0D20E1; // BKPT #221 (0xdd)
	else
		private enum opcode_t BREAKPOINT = 0xE1200D7D; // BKPT #221 (0xdd)
} else version (AArch64) {
	private alias uint opcode_t;
	// NOTE: Checked under ODA, endianness seems to be moot
	version (LittleEndian)
		private enum opcode_t BREAKPOINT = 0xA01B20D4; // BKPT #221 (0xdd)
	else
		private enum opcode_t BREAKPOINT = 0xA01B20D4; // BKPT #221 (0xdd)
} else
	static assert(0, "Missing BREAKPOINT value for target platform");

struct adbg_breakpoints_t {
	adbg_breakpoint_t *list;
	size_t count;
}
struct adbg_breakpoint_t {
	size_t address;
	opcode_t opcode;
}

int adbg_breakpoint_set(adbg_process_t *tracee, size_t addr) {
	return adbg_oops(AdbgError.unimplemented);
}
int adbg_breakpoint_get(adbg_process_t *tracee, size_t addr) {
	return adbg_oops(AdbgError.unimplemented);
}
int adbg_breakpoint_list(adbg_process_t *tracee, adbg_breakpoints_t *list) {
	return adbg_oops(AdbgError.unimplemented);
}
int adbg_breakpoint_unset(adbg_process_t *tracee, size_t address) {
	return adbg_oops(AdbgError.unimplemented);
}
int adbg_breakpoint_unset_all(adbg_process_t *tracee) {
	return adbg_oops(AdbgError.unimplemented);
}
