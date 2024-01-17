/// Loop on exceptions and continue whenever possible.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module examples.simple_v1;

import adbg.include.c.stdio;
import adbg.legacy.debugger, adbg.legacy.disassembler, adbg.error;

extern (C):

int main(int argc, const(char) **argv) {
	if (argc < 2) {
		puts("Missing file");
		return 1;
	}
	if (adbg_load(argv[1])) {
		printf("error: %s\n", adbg_error_msg);
		return adbg_errno;
	}
	if (adbg_disasm_init(&dism)) {
		printf("error: %s\n", adbg_error_msg);
		return adbg_errno;
	}
	
	return adbg_run(&loop_handler);
}

private: // Shuts up dscanner

__gshared adbg_disasm_t dism;

int choice(const(char) *msg) {
	import core.stdc.ctype : isprint;
	printf("\n%s: ", msg);
INPUT:
	int c = getchar;
	if (isprint(c)) return c;
	goto INPUT;
}

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
		char[40] bmne = void;
		char[40] bmac = void;
		if (adbg_disasm_once_debuggee(&dism,
			&op, AdbgDisasmMode.file, e.fault.sz)) {
			printf("> %p: (error:%s)\n", e.fault.raw, adbg_error_msg);
		} else {
			adbg_disasm_format(&dism, bmne.ptr, bmne.sizeof, &op);
			adbg_disasm_machine(&dism, bmac.ptr, bmac.sizeof, &op);
			printf("> %p: (%s) %s\n", e.fault.raw, bmac.ptr, bmne.ptr);
		}
	}
	
	// Process input
L_PROMPT:
	switch (choice("Action [s=Step,c=Continue,q=Quit]")) with (AdbgAction) {
	case 's': puts("Stepping...");	return step;
	case 'c': puts("Continuing...");	return proceed;
	case 'q': puts("Quitting...");	return exit;
	default: goto L_PROMPT;
	}
}