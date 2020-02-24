/**
 * Loop on exceptions and continue whenever possible. No user input for this UI.
 */
module ui.loop;

import core.stdc.stdio;
import debugger, os.err : F_ERR;

extern (C):

private int putchar(int); // the D definition crashes?

/// Starts plain UI
int loop_enter() {
	dbg_sethandle(&loop_handler);
	return dbg_loop;
}

private:

int loop_handler(exception_t *e) {
	__gshared uint en;
	disasm_params_t p;
	p.addr = e.addr;
	disasm_line(p, DisasmMode.File);
	printf(
	"\n-------------------------------------\n"~
	"* EXCEPTION #%u: %s ("~F_ERR~")\n"~
	"* PID=%u TID=%u\n"~
	"> %zX / %s / %s\n",
	en++, exception_type_str(e.type), e.oscode,
	e.pid, e.tid,
	e.addrv, &p.mcbuf, &p.mnbuf
	);
	// Print per block of two registers
	for (size_t i; i < e.regcount; ++i) {
		printf("  %6s=%s",
			e.registers[i].name,
			exception_reg_fhex(e.registers[i]));
		if (i & 1)
			putchar('\n');
	}
	return DebuggerAction.proceed;
}