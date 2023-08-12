/**
 * Loop on exceptions and continue whenever possible.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module ui.loop;

import core.stdc.string : memcpy;
import adbg.include.c.stdio;
import adbg.v1.debugger;
import adbg.v1.disassembler;
import adbg.error;
import common;

//TODO: Consider moving this thing to "examples/"
//      Sub-package :example

extern (C):

/// Starts loop UI
int app_loop() {
	if (adbg_state != AdbgStatus.ready) {
		puts("loop: No program loaded");
		return 1;
	}
	if (adbg_disasm_init(&dism))
		return printerror();
	if (globals.syntax && adbg_disasm_syntax(&dism, globals.syntax))
		return printerror();
	
	return adbg_run(&loop_handler);
}

private:

__gshared adbg_disasm_t dism;

int loop_handler(exception_t *e) {
	__gshared uint ex_num; /// Exception number
	printf(
	"\n----------------------------------------\n"~
	"* EXCEPTION #%u: %s ("~ADBG_OS_ERROR_FORMAT~")\n"~
	"* PID=%u TID=%u\n",
	ex_num++, adbg_exception_string(e.type), e.oscode,
	e.pid, e.tid,
	);
	
	// Print disassembly if available
	if (e.fault) {
		adbg_disasm_opcode_t op = void;
		if (adbg_disasm_once_debuggee(&dism,
			&op,
			AdbgDisasmMode.file,
			e.fault.sz)) {
			printf("> %p: (error:%s)\n", e.fault.raw, adbg_error_msg);
		} else with (globals) {
			adbg_disasm_format(&dism,
				bufferMnemonic.ptr,
				bufferMnemonic.sizeof, &op);
			adbg_disasm_machine(&dism,
				bufferMachine.ptr,
				bufferMachine.sizeof, &op);
			printf("> %p: (%s) %s\n",
				e.fault.raw, bufferMachine.ptr, bufferMnemonic.ptr);
		}
	}
	
	// Process input
L_PROMPT:
	printf("\nAction [S=Step,C=Continue,Q=Quit] ");
	switch (getchar()) with (AdbgAction) {
	case 's', 'S': puts("Stepping...");	return step;
	case 'c', 'C': puts("Continuing...");	return proceed;
	case 'q', 'Q': puts("Quitting...");	return exit;
	default: goto L_PROMPT;
	}
}