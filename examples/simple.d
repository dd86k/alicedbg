/// Loop on exceptions and continue whenever possible.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module examples.simple;

import core.stdc.stdio;
import core.stdc.stdlib;
import core.stdc.ctype : isprint;
import adbg;

extern (C):
__gshared:
private: // Shuts up dscanner

adbg_disassembler_t *dis;

void die(int code = 0, const(char) *reason = null) {
	printf("error: %s\n", reason ? reason : adbg_error_message);
	if (code == 0) code = adbg_errno;
	exit(code);
}

int choice(const(char) *msg) {
	printf("\n%s: ", msg);
LINPUT:	int c = getchar;
	if (isprint(c)) return c;
	goto LINPUT;
}

void loop_handler(adbg_process_t *proc, int event, void *evdata) {
	if (event != AdbgEvent.exception)
		return;
	
	adbg_exception_t *ex = cast(adbg_exception_t*)evdata;
	printf(
	"\n----------------------------------------\n"~
	"* EXCEPTION ("~ADBG_OS_ERROR_FORMAT~"): %s\n"~
	"* PID=%u TID=%u\n"~
	"* FAULT=%8llx",
	ex.oscode, adbg_exception_name(ex),
	ex.pid, ex.tid,
	ex.fault_address
	);
	
	// Print disassembly if available
	if (dis && ex.faultz) {
		adbg_opcode_t op = void;
		if (adbg_dis_process_once(dis, &op, proc, ex.fault_address)) {
			printf("  (error:%s)\n", adbg_error_message);
			return;
		}
		if (op.operands)
			printf("  (%s %s)\n", op.mnemonic, op.operands);
		else
			printf("  (%s)\n", op.mnemonic);
	}
}

int main(int argc, const(char) **argv) {
	if (argc < 2)
		die(1, "Missing path to executable");
	
	adbg_process_t *process = adbg_debugger_spawn(argv[1], 0);
	if (process == null)
		die;
	
	dis = adbg_dis_open(adbg_process_get_machine(process));
	if (dis == null)
		printf("warning: Disassembler unavailable (%s)\n", adbg_error_message());
	
LOOP:	// Process input
	switch (choice("Action [?=Help]")) {
	case '?':
		puts(
		"s - Instruction step.\n"~
		"c - Continue.\n"~
		"q - Quit."
		);
		goto LOOP;
	case 's':
		puts("Stepping...");
		adbg_debugger_stepi(process);
		break;
	case 'c':
		puts("Continuing...");
		adbg_debugger_continue(process);
		break;
	case 'q':
		puts("Quitting...");
		return 0;
	default:
		goto LOOP;
	}
	
	adbg_debugger_wait(process, &loop_handler);
	goto LOOP;
}