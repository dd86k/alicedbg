/// Error handling, printing, and contracting
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module common.error;

import core.stdc.stdlib : exit;
import core.stdc.string : strerror;
import core.stdc.errno : errno;
import adbg.error;
import adbg.disassembler;
import adbg.debugger.exception;
import adbg.machines : AdbgMachine;
import core.stdc.stdio;
import core.stdc.stdlib : malloc;

void print_adbg_error(
	const(char)* mod = cast(char*)__MODULE__,
	int line = __LINE__) {
	printf("%s", mod);
	debug printf("@%u", line);
	printf(": %s\n", mod, line, adbg_error_msg());
	debug print_adbg_trace();
}

private
void print_adbg_trace() {
	const(adbg_error_t)* e = adbg_error_current();
	printf("  %s@%u\n", e.mod, e.line);
}

void panic(int code, const(char)* message,
	const(char)* mod = cast(char*)__MODULE__,
	int line = __LINE__) {
	printf("%s@%u: %s\n", mod, line, message);
	exit(0);
}
void panic_crt() {
	panic(errno, strerror(errno));
}
void panic_adbg() {
	panic(adbg_errno(), adbg_error_msg());
}