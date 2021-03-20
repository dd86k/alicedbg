/**
 * Loop on exceptions and continue whenever possible. No user input for this UI.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: See LICENSE
 * License: BSD-3-Clause
 */
module ui.loop;

import core.stdc.string : memcpy;
import adbg.etc.c.stdio;
import adbg.dbg, adbg.sys.err : SYS_ERR_FMT;
import adbg.disasm;
import term;
import common;

//TODO: loop option or new ui for just logging in faults

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
		char[16] b = void;
		if (adbg_mm_cread(e.faultaddrv, cast(void*)b.ptr, 16)) {
			puts("> Unable to read process memory.");
			goto L_PROMPT;
		}
		common_disasm.a = b.ptr;
		if (adbg_disasm(&common_disasm, AdbgDisasmMode.file) == 0) {
			printf("> %p: %s| %s\n",
				e.faultaddr,
				common_disasm.mcbuf.ptr,
				common_disasm.mnbuf.ptr);
		}
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