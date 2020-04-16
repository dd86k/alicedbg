/**
 * Loop on exceptions and continue whenever possible. No user input for this UI.
 *
 * License: BSD 3-Clause
 */
module adbg.ui.loop;

import adbg.etc.ddc;
import core.stdc.stdio : printf, puts;
import core.stdc.string : memcpy;
import adbg.debugger, adbg.os.err : F_ERR;
import adbg.os.term : adbg_term_init, adbg_term_read, InputInfo, Key, InputType;
import adbg.ui.common;

extern (C):

/// Starts plain UI
int adbg_ui_loop_enter(disasm_params_t *p) {
	if (adbg_term_init)
		return 1;
	memcpy(&g_disparams, p, disasm_params_t.sizeof);
	adbg_sethandler(&adbg_ui_loop_handler);
	return adbg_enterloop;
}

private:

int adbg_ui_loop_handler(exception_t *e) {
	__gshared uint en;
	printf(
	"\n-------------------------------------\n"~
	"* EXCEPTION #%u: %s ("~F_ERR~")\n"~
	"* PID=%u TID=%u\n"~
	"> %zX",
	en++, adbg_ex_typestr(e.type), e.oscode,
	e.pid, e.tid,
	e.addrv
	);

	// * Disassembly
	g_disparams.addr = e.addr;
	DisasmError derr = cast(DisasmError)adbg_dasm_line(&g_disparams, DisasmMode.File);
	with (DisasmError)
	switch (derr) {
	case None:
		printf(" / %s / %s", &g_disparams.mcbuf, &g_disparams.mnbuf);
		break;
	case Illegal:
		printf(" / %s", &g_disparams.mcbuf);
		break;
	default:
	}
	putchar('\n');

	// * Register
	// Print per block of two registers
	for (size_t i; i < e.regcount; ++i) {
		printf("  %6s=%s",
			e.registers[i].name,
			adbg_ex_reg_fhex(&e.registers[i]));
		if (i & 1)
			putchar('\n');
	}

	// * Input
L_PROMPT:
	printf("\nAction [S=Step,C=Continue,Q=Quit] ");
	InputInfo ii = void;
L_INPUT:
	adbg_term_read(&ii);
	if (ii.type != InputType.Key)
		goto L_INPUT;
	switch (ii.key.keyCode) {
	case Key.S: puts("Stepping..."); return DebuggerAction.step;
	case Key.C: puts("Continuing..."); return DebuggerAction.proceed;
	case Key.Q: puts("Quitting..."); return DebuggerAction.exit;
	default: goto L_PROMPT;
	}
}