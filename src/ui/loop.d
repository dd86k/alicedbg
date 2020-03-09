/**
 * Loop on exceptions and continue whenever possible. No user input for this UI.
 */
module ui.loop;

import etc.ddc;
import core.stdc.stdio : printf, puts;
import core.stdc.string : memcpy;
import debugger, os.err : F_ERR;
import os.term : term_init, term_read, InputInfo, Key, InputType;
import ui.common;

extern (C):

/// Starts plain UI
int loop_enter(ref disasm_params_t p) {
	if (term_init)
		return 1;
	disparams = p;
	dbg_sethandle(&loop_handler);
	return dbg_loop;
}

private:

int loop_handler(exception_t *e) {
	__gshared uint en;
	printf(
	"\n-------------------------------------\n"~
	"* EXCEPTION #%u: %s ("~F_ERR~")\n"~
	"* PID=%u TID=%u\n"~
	"> %zX",
	en++, exception_type_str(e.type), e.oscode,
	e.pid, e.tid,
	e.addrv
	);
	disparams.addr = e.addr;
	if (disasm_line(disparams, DisasmMode.File) == DisasmError.None) {
		printf(" / %s / %s", &disparams.mcbuf, &disparams.mnbuf);
	}
	putchar('\n');
	// Print per block of two registers
	for (size_t i; i < e.regcount; ++i) {
		printf("  %6s=%s",
			e.registers[i].name,
			exception_reg_fhex(e.registers[i]));
		if (i & 1)
			putchar('\n');
	}
L_PROMPT:
	printf("\nAction [S=Step,C=Continue,Q=Quit] ");
	InputInfo ii = void;
L_INPUT:
	term_read(ii);
	if (ii.type != InputType.Key)
		goto L_INPUT;
	switch (ii.key.keyCode) {
	case Key.S: puts("Stepping..."); return DebuggerAction.step;
	case Key.C: puts("Continuing..."); return DebuggerAction.proceed;
	case Key.Q: puts("Quitting..."); return DebuggerAction.exit;
	default: goto L_PROMPT;
	}
}