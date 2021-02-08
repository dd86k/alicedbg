/**
 * Loop on exceptions and continue whenever possible. No user input for this UI.
 *
 * License: BSD-3-Clause
 */
module app.debugger.ui.loop;

import core.stdc.string : memcpy;
import adbg.etc.c.stdio;
import adbg.debugger, adbg.sys.err : SYS_ERR_FMT;
import adbg.disasm;
import app.term;
import app.common;

extern (C):

/// Starts loop UI
int loop() {
	if (adbg_state != AdbgState.loaded) {
		puts("loop: No program loaded");
		return 1;
	}
	if (term_init) return 1;
	return adbg_run(&loop_handler);
}

private:

int loop_handler(exception_t *e) {
	__gshared uint en;
	printf(
	"\n-------------------------------------\n"~
	"* EXCEPTION #%u: %s ("~SYS_ERR_FMT~")\n"~
	"* PID=%u TID=%u\n",
	en++, adbg_exception_string(e.type), e.oscode,
	e.pid, e.tid,
	);

	// * Print disassembly, if available
	if (e.faultaddr) {
		common_settings.disasm.a = e.faultaddr;
		if (adbg_disasm(&common_settings.disasm, AdbgDisasmMode.file) == 0) {
			printf("> %p: %s| %s\n",
				e.faultaddr,
				common_settings.disasm.mcbuf.ptr,
				common_settings.disasm.mnbuf.ptr);
		}
	}

	// * Print registers, print in pairs
	for (size_t i; i < e.registers.count; ++i) {
		register_t *reg = &e.registers.items[i];
		printf("%8s=%s", reg.name, adbg_ex_reg_fhex(reg));
		if (i & 1)
			putchar('\n');
	}

	// * Process input
L_PROMPT:
	printf("\nAction [S=Step,C=Continue,Q=Quit] ");
	InputInfo input = void;
L_INPUT:
	term_read(&input);
	if (input.type != InputType.Key)
		goto L_INPUT;
	with (AdbgAction)
	switch (input.key.keyCode) {
	case Key.S: puts("Stepping...");	return step;
	case Key.C: puts("Continuing...");	return proceed;
	case Key.Q: puts("Quitting...");	return exit;
	default: goto L_PROMPT;
	}
}