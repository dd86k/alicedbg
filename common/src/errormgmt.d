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
import adbg.process.memory;
import adbg.error;
import core.stdc.string : strerror;
import core.stdc.errno : errno;
import core.stdc.stdio;
import core.stdc.stdlib : exit;
import common.terminal;

extern (C):

void print_error(const(char) *message, int code,
	const(char)* prefix = null, const(char)* mod = cast(char*)__MODULE__, int line = __LINE__) {
	debug console_writef(CONSOLE_STDERR, "[%s@%d] ", mod, line);
	console_write2(CONSOLE_STDERR, "error: ");
	if (prefix)
		console_writef(CONSOLE_STDERR, "%s: ", prefix);
	console_writef(CONSOLE_STDERR, "(%d) %s\n", code, message);
}
void print_error_adbg(
	const(char)* mod = __FILE__.ptr, int line = __LINE__) {
	print_error(adbg_error_message(), adbg_error_code(), null, adbg_error_function(), adbg_error_line());
}

void panic(int code, const(char)* message,
	const(char)* prefix = null, const(char)* mod = __MODULE__.ptr, int line = __LINE__) {
	print_error(message, code, prefix, mod, line);
	// NOTE: If a code returned is used as a special signal (like on Windows),
	//       it could mean something bad, so only return 1 (EXIT_FAILURE) or 2.
	exit(2);
}
void panic_crt(const(char)* prefix = null, const(char)* mod = __MODULE__.ptr, int line = __LINE__) {
	panic(errno, strerror(errno), prefix, mod, line);
}
void panic_adbg(const(char)* prefix = null, const(char)* mod = __MODULE__.ptr) {
	panic(adbg_error_code(), adbg_error_message(), prefix, adbg_error_function(), adbg_error_line());
}

void reset_error() {
	adbg_error_reset();
}
int errorcode() {
	return adbg_error_code();
}

void crashed(adbg_process_t *proc, adbg_exception_t *ex) {
	console_write2(CONSOLE_STDERR,
`
   _ _ _   _ _ _       _ _       _ _ _   _     _   _
 _|_|_|_| |_|_|_|_   _|_|_|_   _|_|_|_| |_|   |_| |_|
|_|       |_|_ _|_| |_|_ _|_| |_|_ _    |_|_ _|_| |_|
|_|       |_|_|_|_  |_|_|_|_|   |_|_|_  |_|_|_|_| |_|
|_|_ _ _  |_|   |_| |_|   |_|  _ _ _|_| |_|   |_|  _
  |_|_|_| |_|   |_| |_|   |_| |_|_|_|   |_|   |_| |_|
`);
	
	// NOTE: Any future call could make the app crash harder,
	//       so, print one line at at time
	console_writef(CONSOLE_STDERR, "PID        : %d\n", adbg_process_id(proc));
	console_writef(CONSOLE_STDERR, "Code       : "~ERR_OSFMT~"\n", ex.oscode);
	console_writef(CONSOLE_STDERR, "Exception  : %s\n", adbg_exception_name(ex));
	
	// TODO: Get thread context
	
	// Fault address & disasm if available
	if (ex.fault_address) {
		console_writef(CONSOLE_STDERR, "Address    : %#llx\n", ex.fault_address);
		
		ubyte[OPCODE_BUFSIZE] buffer = void;
		adbg_opcode_t op = void;
		adbg_disassembler_t *dis = adbg_disassembler_open(adbg_machine_current());
		if (dis == null)
			goto Lunavail;
		if (adbg_memory_read(proc, cast(size_t)ex.fault_address, buffer.ptr, OPCODE_BUFSIZE))
			goto Lunavail;
		if (adbg_disassemble(dis, &op, buffer.ptr, OPCODE_BUFSIZE))
			goto Lunavail;
		
		console_write2(CONSOLE_STDERR, "Instruction:");
		for (size_t bi; bi < op.size; ++bi)
			console_writef(CONSOLE_STDERR, " %02x", op.data[bi]);
		console_writef(CONSOLE_STDERR, " (%s", op.mnemonic);
		if (op.operands) console_writef(CONSOLE_STDERR, " %s", op.operands);
		console_write2(CONSOLE_STDERR, ")");
		
		goto Lcont;
		
	Lunavail:
		console_writef(CONSOLE_STDERR, " Disassembly unavailable (%s)\n", adbg_error_message());
	Lcont:
	}
	
	// TODO: Option to attach debugger to this process
	exit(ex.oscode);
}
