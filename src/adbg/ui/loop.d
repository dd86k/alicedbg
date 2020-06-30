/**
 * Loop on exceptions and continue whenever possible. No user input for this UI.
 *
 * License: BSD 3-Clause
 */
module adbg.ui.loop;

import adbg.etc.ddc;
import core.stdc.stdio : printf, puts;
import core.stdc.string : memcpy;
import adbg.debugger, adbg.os.err : ERR_FMT;
import adbg.disasm;
import adbg.os.term;
import adbg.ui.common;

extern (C):

/// Starts plain UI
int adbg_ui_loop_enter(disasm_params_t *p) {
	if (adbg_term_init)
		return 1;
	p.options = DISASM_O_SPACE;
	memcpy(&g_disparams, p, disasm_params_t.sizeof);
	adbg_userfunc(&adbg_ui_loop_handler);
	return adbg_run;
}

private:

int adbg_ui_loop_handler(exception_t *e) {
	__gshared uint en;
	printf(
	"\n-------------------------------------\n"~
	"* EXCEPTION #%u: %s ("~ERR_FMT~")\n"~
	"* PID=%u TID=%u\n",
	en++, adbg_ex_typestr(e.type), e.oscode,
	e.pid, e.tid,
	);

	// * Print disassembly, if available
	if (e.addr) {
		g_disparams.a = e.addr;
		if (adbg_dasm_line(&g_disparams, DisasmMode.File) == 0) {
			printf("> %p: %s| %s\n",
				e.addr, &g_disparams.mcbuf, &g_disparams.mnbuf);
		}
	}

	// * Print registers, print in pairs
	for (size_t i; i < e.regcount; ++i) {
		printf("%8s=%s",
			e.registers[i].name,
			adbg_ex_reg_fhex(&e.registers[i]));
		if (i & 1)
			putchar('\n');
	}

	// * Process input
L_PROMPT:
	printf("\nAction [S=Step,C=Continue,Q=Quit] ");
	InputInfo input = void;
L_INPUT:
	adbg_term_read(&input);
	if (input.type != InputType.Key)
		goto L_INPUT;
	with (DebuggerAction)
	switch (input.key.keyCode) {
	case Key.S: puts("Stepping...");	return step;
	case Key.C: puts("Continuing...");	return proceed;
	case Key.Q: puts("Quitting...");	return exit;
	default: goto L_PROMPT;
	}
}