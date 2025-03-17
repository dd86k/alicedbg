/// Minimal example that loops until the first fault is fault.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module examples.simple;

import core.stdc.stdio;
import core.stdc.stdlib : exit, EXIT_FAILURE, EXIT_SUCCESS;
import adbg;

extern (C): __gshared: private:

enum {
	SIMPLE_STOP = 0,
	SIMPLE_CONTINUE = 1,
}

int putchar(int);

adbg_disassembler_t *disassembler;
int status = SIMPLE_CONTINUE;

void oops(int code = 0, const(char) *reason = null) {
	printf("* error=\"%s\" code=\"%d\"\n",
		reason ? reason : adbg_error_message(),
		code ? code : adbg_error_code()
	);
	exit(EXIT_FAILURE);
}

void event_exception(adbg_process_t *proc, void *udata, adbg_exception_t *exception) {
	long tid = adbg_exception_tid(exception);
	printf(`* pid=%d tid=%lld event=\"exception\" name="%s" oscode=`~ERR_OSFMT,
		adbg_process_id(proc), tid,
		adbg_exception_name(exception), adbg_exception_orig_code(exception));
	
	// Print fault address if available
	ulong faultaddr = adbg_exception_fault_address(exception);
	if (faultaddr)
		printf(" address=%#llx", faultaddr);
	
	// If disassembler is available, disassemble one instruction
	if (faultaddr && disassembler) {
		enum BSZ = 32;
		ubyte[BSZ] buffer = void;
		adbg_opcode_t opcode = void;
		if (adbg_memory_read(proc, cast(size_t)faultaddr, buffer.ptr, BSZ) || 
			adbg_disassemble(disassembler, &opcode, buffer.ptr, BSZ, faultaddr))
			goto Lnodisasm;
		
		goto Ldisasm;
	Lnodisasm:
		printf(` nodisasm="%s"`, adbg_error_message());
		goto Ldone;
	Ldisasm:
		printf(` disasm="%s`, opcode.mnemonic);
		if (opcode.operands) printf(` %s"`, opcode.operands);
		putchar('"');
	Ldone:
	}
	
	// If available, print register data for thread
	void *thrlist = adbg_thread_list_new(proc);
	if (thrlist) {
		adbg_thread_t *thread = adbg_thread_list_by_id(thrlist, tid);
		if (thread && adbg_thread_context_update(proc, thread) == 0) {
			int rid;
			adbg_register_t *reg = void;
			while ((reg = adbg_register_by_id(thread, rid++)) != null) {
				char[20] hex = void;
				adbg_register_format(hex.ptr, 20, reg, AdbgRegisterFormat.hex);
				printf(` %s=0x%s`, adbg_register_name(reg), hex.ptr);
			}
		}
		adbg_thread_list_close(thrlist);
	}
	
	putchar('\n');
	
	switch (adbg_exception_type(exception)) with (AdbgException) {
	case Breakpoint, Step:
		adbg_debugger_continue(proc, tid);
		break;
	default: // Quit at first fault
		*(cast(int*)udata) = SIMPLE_STOP;
	}
}
void event_process_continue(adbg_process_t *proc, void *udata, long tid) {
	printf("* pid=%d event=\"continued\"\n", adbg_process_id(proc));
}
void event_process_exit(adbg_process_t *proc, void *udata, int code) {
	printf("* pid=%d event=\"exited\" code=%d\n", adbg_process_id(proc), code);
	*(cast(int*)udata) = SIMPLE_STOP;
}

int main(int argc, const(char) **argv) {
	if (argc < 2)
		oops(1, "Missing path to executable");
	
	// Additional arguments for debuggee
	const(char) **pargv = argc > 2 ? argv + 2 : null;
	
	// Launch process
	adbg_process_t *process =
		adbg_debugger_spawn(argv[1],
			AdbgSpawnOpt.argv, pargv,
			0);
	if (process == null)
		oops;
	adbg_debugger_on_exception(process, &event_exception);
	adbg_debugger_on_process_continue(process, &event_process_continue);
	adbg_debugger_on_process_exit(process, &event_process_exit);
	adbg_debugger_udata(process, &status);
	
	// New disassembler instance, if able
	disassembler = adbg_disassembler_open(adbg_process_machine(process));
	if (disassembler == null)
		printf("* warning=\"Disassembler unavailable: %s\"\n", adbg_error_message());
	
	// Start and listen to events
	while (status) {
		if (adbg_debugger_wait(process))
			oops;
	}
	puts("* quitting");
	return 0;
}