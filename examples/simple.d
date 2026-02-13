/// Minimal example that loops until the first fault is fault.
///
/// Uses the Multi API. Use `dub build :simple` (from parent dir) to build.
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

void oops(int code = 0, const(char) *reason = null) {
	printf("* error=\"%s\" code=\"%d\"\n",
		reason ? reason : adbg_error_message(),
		code ? code : adbg_error_code()
	);
	exit(EXIT_FAILURE);
}

void event_exception(adbg_process_t *process, adbg_exception_t *exception, int *status) {
	adbg_process_thread_t *thread = adbg_exception_thread(exception);
	long tid = thread ? adbg_process_thread_id(thread) : 0;
	
	printf(`* pid=%d tid=%lld event=\"exception\" name="%s" oscode=`~ERR_OSFMT,
		adbg_process_id(process), tid,
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
		if (adbg_memory_read(process, cast(size_t)faultaddr, buffer.ptr, BSZ) || 
			adbg_disassemble(disassembler, &opcode, buffer.ptr, BSZ, faultaddr))
			goto Lnodisasm;
		
		goto Ldisasm;
	Lnodisasm:
		printf(` nodisasm="%s"`, adbg_error_message());
		goto Ldone;
	Ldisasm:
		printf(` disasm="%s`, opcode.mnemonic);
		if (opcode.operands) printf(` %s`, opcode.operands);
		putchar('"');
	Ldone:
	}
	
	// Print thread's context
	adbg_thread_context_t *ctx = adbg_process_thread_context(thread);
	if (ctx) {
		adbg_register_t *reg = void;
		for (int id; (reg = adbg_register_by_id(ctx, id)) != null; id++) {
			char[20] hex = void;
			adbg_register_format(hex.ptr, 20, reg, AdbgRegisterFormat.hex);
			printf(` %s=0x%s`, adbg_register_name(reg), hex.ptr);
		}
	}
	
	putchar('\n');
	
	switch (adbg_exception_type(exception)) with (AdbgException) {
	case Breakpoint, Step:
		adbg_debugger_continue(process, tid);
		break;
	default: // Quit at first fault
		*status = SIMPLE_STOP;
	}
}

int main(int argc, const(char) **argv) {
	if (argc < 2)
		oops(1, "Missing path to executable");
	
	// Additional arguments for debuggee
	const(char) **pargv = argc > 2 ? argv + 2 : null;
	
	// Launch process
	adbg_process_t *process = adbg_debugger_spawn(argv[1], AdbgSpawnOpt.argv, pargv, 0);
	if (process == null)
		oops;
	
	// New disassembler instance, if able
	disassembler = adbg_disassembler_open(adbg_process_machine(process));
	if (disassembler == null)
		printf("* warning=\"Disassembler unavailable: %s\"\n", adbg_error_message());
	
	// Start and listen to events
	adbg_event_t event = void;
	int status = SIMPLE_CONTINUE;
	A: while (status) {
		adbg_process_t *proc = adbg_debugger_wait(process, &event);
		if (proc == null)
			oops;
		
		switch (event.type) {
		case AdbgEvent.exception:
			event_exception(proc, &event.exception, &status);
			break;
		case AdbgEvent.processCreated:
			printf("* event=\"created\" pid=%d\n", adbg_process_id(proc));
			break;
		case AdbgEvent.processContinue:
			printf("* event=\"continued\" pid=%d\n", adbg_process_id(proc));
			break;
		case AdbgEvent.processExit:
			printf("* event=\"exited\" pid=%d code=%d\n", adbg_process_id(proc), event.exitcode);
			break A;
		default:
		}
	}
	puts("* quitting");
	return 0;
}