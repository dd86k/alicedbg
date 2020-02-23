/**
 * Loop on exceptions and continue whenever possible. No user input for this UI.
 */
module ui.loop;

//import misc.ddc;
import core.stdc.stdio;
import debugger.exception, debugger.core, debugger.disasm;

extern (C):

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
	"* EXCEPTION #%u\n"~
	"PID=%u  TID=%u\n"~
	"%s (%X) at %zX\n"~
	"Code: %s (%s)\n"~
	"\n"
	,
	en++,
	e.pid, e.tid,
	e.type.typestr, e.oscode, e.addrv,
	&p.mcbuf, &p.mnbuf
	);
	return DebuggerAction.proceed;
}