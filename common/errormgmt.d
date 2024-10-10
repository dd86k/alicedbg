/// Error handling, printing, and contracting
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module common.errormgmt;

import adbg.self;
import adbg.machines : adbg_machine_current;
import adbg.disassembler;
import adbg.process.base;
import adbg.process.exception;
import adbg.error;
import core.stdc.string : strerror;
import core.stdc.errno : errno;
import core.stdc.stdio;
import core.stdc.stdlib : malloc, exit;

extern (C):

void print_error(const(char) *message, int code,
	const(char)* prefix = null, const(char)* mod = cast(char*)__MODULE__, int line = __LINE__) {
	debug printf("[%s@%d] ", mod, line);
	fputs("error: ", stderr);
	if (prefix) {
		fputs(prefix, stderr);
		fputs(": ", stderr);
	}
	fprintf(stderr, "(%d) %s\n", code, message);
}
void print_error_adbg(
	const(char)* mod = __FILE__.ptr, int line = __LINE__) {
	debug printf("[%s@%d] ", mod, line);
	const(adbg_error_t)* e = adbg_error_current();
	print_error(adbg_error_message(), e.code, null, e.func, e.line);
}

void panic(int code, const(char)* message,
	const(char)* prefix = null, const(char)* mod = __MODULE__.ptr, int line = __LINE__) {
	print_error(message, code, prefix, mod, line);
	exit(code);
}
void panic_crt(const(char)* prefix = null, const(char)* mod = __MODULE__.ptr, int line = __LINE__) {
	panic(errno, strerror(errno), prefix, mod, line);
}
void panic_adbg(const(char)* prefix = null, const(char)* mod = __MODULE__.ptr) {
	const(adbg_error_t)* e = adbg_error_current();
	panic(adbg_errno(), adbg_error_message(), prefix, e.func, e.line);
}

void reset_error() {
	adbg_error_reset();
}
int errorcode() {
	return adbg_errno();
}

void crashed(adbg_process_t *proc, adbg_exception_t *ex) {
	puts(
`
   _ _ _   _ _ _       _ _       _ _ _   _     _   _
 _|_|_|_| |_|_|_|_   _|_|_|_   _|_|_|_| |_|   |_| |_|
|_|       |_|_ _|_| |_|_ _|_| |_|_ _    |_|_ _|_| |_|
|_|       |_|_|_|_  |_|_|_|_|   |_|_|_  |_|_|_|_| |_|
|_|_ _ _  |_|   |_| |_|   |_|  _ _ _|_| |_|   |_|  _
  |_|_|_| |_|   |_| |_|   |_| |_|_|_|   |_|   |_| |_|
`
	);
	
	printf(
	"Code       : "~ERR_OSFMT~"\n"~
	"Exception  : %s\n"~
	"PID        : %d\n",
	ex.oscode, adbg_exception_name(ex), adbg_process_pid(proc));
	
	// Fault address & disasm if available
	if (ex.faultz) {
		printf("Address    : %#zx\n", ex.faultz);
		
		adbg_opcode_t op = void;
		adbg_disassembler_t *dis = adbg_dis_open(adbg_machine_current());
		printf("Instruction:");
		if (dis && adbg_dis_process_once(dis, &op, proc, ex.fault_address) == 0) {
			// Print machine bytes
			for (size_t bi; bi < op.size; ++bi)
				printf(" %02x", op.machine[bi]);
			printf(" (%s", op.mnemonic);
			if (op.operands)
				printf(" %s", op.operands);
			puts(")");
		} else {
			printf(" Disassembly unavailable (%s)\n", adbg_error_message());
		}
	}
	
	// TODO: Get thread context
	
	//TODO: Option to attach debugger to this process
	exit(ex.oscode);
}
