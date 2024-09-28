/// Minimal example that loops until the first fault is fault.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module examples.simple;

import core.stdc.stdio;
import core.stdc.stdlib : exit;
import adbg;

extern (C): __gshared: private:

enum {
	SIMPLE_STOP = 0,
	SIMPLE_CONTINUE = 1,
}

int putchar(int);

adbg_disassembler_t *dis;

void oops(int code = 0, const(char) *reason = null) {
	printf("* error=\"%s\"\n", reason ? reason : adbg_error_message());
	if (code == 0) code = adbg_errno;
	exit(code);
}

void loop_handler(adbg_process_t *proc, int event, void *edata, void *udata) {
	switch (event) {
	case AdbgEvent.exception:
		adbg_exception_t *ex = cast(adbg_exception_t*)edata;
		
		// Assume singleprocess, so don't print its PID
		printf(`* tid=%d exception="%s" oscode=`~ERR_OSFMT,
			proc.tid, adbg_exception_name(ex), ex.oscode);
		
		// Print fault address if available
		if (ex.faultz)
			printf(" address=%#llx", ex.fault_address);
		
		// If disassembler is available, disassemble one instruction
		if (ex.faultz && dis) {
			adbg_opcode_t op = void;
			if (adbg_dis_process_once(dis, &op, proc, ex.fault_address))
				printf(` nodisasm="%s"`, adbg_error_message);
			else if (op.operands)
				printf(` disasm="%s %s"`, op.mnemonic, op.operands);
			else
				printf(` disasm="%s"`, op.mnemonic);
		}
		
		switch (ex.type) with (AdbgException) {
		case Breakpoint, Step:
			adbg_debugger_continue(proc);
			putchar('\n');
			return;
		default: // Quit at first fault
			*(cast(int*)udata) = SIMPLE_STOP;
		}
		
		// If available, print register data
		adbg_thread_t *thread = adbg_thread_list_by_id(proc, proc.tid);
		if (thread && adbg_thread_context_update(proc, thread) == 0) {
			int id;
			adbg_register_t *reg = void;
			while ((reg = adbg_register_by_id(thread, id++)) != null) {
				char[20] hex = void;
				adbg_register_format(hex.ptr, 20, reg, AdbgRegisterFormat.hexPadded);
				printf(` %s=0x%s`, adbg_register_name(reg), hex.ptr);
			}
		}
		
		putchar('\n');
		return;
	case AdbgEvent.processExit:
		int *oscode = cast(int*)edata;
		printf("* exited with code %d\n", *oscode);
		*(cast(int*)udata) = SIMPLE_STOP;
		return;
	default:
	}
}

int main(int argc, const(char) **argv) {
	if (argc < 2)
		oops(1, "Missing path to executable");
	
	// if additional arguments, they are for process to debug
	const(char) **pargv = argc > 2 ? argv + 2 : null;
	
	adbg_process_t *process =
		adbg_debugger_spawn(argv[1],
			AdbgSpawnOpt.argv, pargv,
			0);
	if (process == null)
		oops;
	
	dis = adbg_dis_open(adbg_process_machine(process));
	if (dis == null)
		printf("* warning=\"Disassembler unavailable: %s\"\n", adbg_error_message());
	
	int state = SIMPLE_CONTINUE;
	if (adbg_debugger_continue(process))
		oops;
Lcontinue:
	if (adbg_debugger_wait(process, &loop_handler, &state))
		oops;
	if (state) goto Lcontinue;
	return 0;
}