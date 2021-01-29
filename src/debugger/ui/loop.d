/**
 * Loop on exceptions and continue whenever possible. No user input for this UI.
 *
 * License: BSD-3-Clause
 */
module debugger.ui.loop;

import adbg.etc.c;
import adbg.debugger, adbg.sys.err : SYS_ERR_FMT;
import adbg.disasm;
import term;
import core.stdc.stdio : printf, puts;
import core.stdc.string : memcpy;
import debugger.common;

extern (C):

/// Starts loop UI
int loop() {
	if (term_init)
		return 1;
	common_disasm_params.options = AdbgDisasmOption.spaceSep;
	adbg_event_exception(&adbg_ui_loop_handler);
	return adbg_run;
}

private:

int adbg_ui_loop_handler(exception_t *e) {
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
		common_disasm_params.a = e.faultaddr;
		if (adbg_disasm(&common_disasm_params, AdbgDisasmMode.file) == 0) {
			printf("> %p: %s| %s\n",
				e.faultaddr, common_disasm_params.mcbuf.ptr, common_disasm_params.mnbuf.ptr);
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