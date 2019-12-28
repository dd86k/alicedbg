/**
 * Loop on exceptions and continue whenever possible. No user input for this UI.
 */
module ui.loop;

//import misc.ddc;
import core.stdc.stdio;
import debugger.exception, debugger.core;

extern (C):

/// Starts plain UI
int ui_loop() {
	dbg_sethandle(&except);
	return dbg_loop;
}

private:

int except(exception_t *e) {
	printf(
	"\n"~
	"*************\n"~
	"* EXCEPTION *\n"~
	"*************\n"~
	"PID=%u  TID=%u\n"~
	"%s (%X) at %zX\n"~
	"%s=%016X\n"
	,
	e.pid, e.tid,
	e.type.typestr, e.oscode, e.addrv,
	e.registers[0].name, e.registers[0].u64
	);
	return DebuggerAction.proceed;
}