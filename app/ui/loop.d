/**
 * Loop on exceptions and continue whenever possible.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2022 dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module ui.loop;

import core.stdc.string : memcpy;
import adbg.include.c.stdio;
import adbg.v1.debugger;
import adbg.v1.disassembler;
import adbg.error;
import common, term;

//TODO: Consider moving this thing to "examples/"
//      Sub-package :example
//TODO: Remove term dependency
//      Use getchar() or similar

extern (C):

/// Starts loop UI
int app_loop() {
	if (adbg_state != AdbgStatus.ready) {
		puts("loop: No program loaded");
		return 1;
	}
	if (term_init) return 1;
	return adbg_run(&loop_handler);
}

private:

int loop_handler(exception_t *e) {
	__gshared uint ex_num; /// Exception number
	printf(
	"\n----------------------------------------\n"~
	"* EXCEPTION #%u: %s ("~ADBG_OS_ERROR_FORMAT~")\n"~
	"* PID=%u TID=%u\n",
	ex_num++, adbg_exception_string(e.type), e.oscode,
	e.pid, e.tid,
	);
	
	// * Print disassembly, if available
	if (e.fault) {
		adbg_disasm_opcode_t op = void;
		if (adbg_disasm_once_debuggee(&globals.dism,
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
	
	// * Process input
	//TODO: get rid of term dependency and use getchar() or something
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