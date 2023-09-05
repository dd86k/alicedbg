/// Command interpreter.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module ui.cmd;

import adbg.include.c.stdio;
import adbg.include.c.stdlib;
import core.stdc.string;
import adbg.error;
import adbg.utils.string;
import adbg.v2.debugger;
import adbg.v2.disassembler;
import common, term;

//TODO: cmd_file -- read (commands) from file
//TODO: cmd_strace [on|off]
//TODO: Command re-structure
//      show r|registers
//      show b|breakpoints
//      show s|stack
//      show state
//      add breakpoint
//TODO: Move commands to its own module? rename ui as shell?
//      "tcp" ui might re-use commands
//TODO: int cmd_error(const(char)*);
//      or just cmd_log() with "debugger: " prepended
//TODO: Improve help system by avoiding help functions

extern (C):

/// Enter the command-line loop
/// Returns: Error code
int app_cmd() {
	tracee = alloc!adbg_process_t();
	disasm = alloc!adbg_disassembler_t();
	
	//TODO: check for pid option too
	// If file specified, load it
	if (globals.file) {
		if (adbg_spawn(tracee, globals.file, 0))
			return oops;
		puts("Process created.");
	
		if (adbg_dasm_openproc(disasm, tracee)) {
			disasm_available = false;
			printf("warning: Disassembler not available (%s)\n",
				adbg_error_msg());
		} else disasm_available = true;
	}
	
	term_init;
	
	user_continue = true;
	
	return prompt();
}

private:

int prompt() {
	char* line = void;
	int argc = void;
	int error;
	while (user_continue) {
		cmd_prompt(); // print prompt
		line = term_readline(&argc); // read line
		
		//TODO: remove once term gets key events
		if (line == null) {
			printf("^D");
			return 0;
		}
		
		error = cmd_execl(line, argc); // execute line
		if (error == AppError.alicedbg)
			oops;
	}
	return error;
}

/// Execute a line of command
/// Returns: Error code
int cmd_exec(char *command) {
	return cmd_execl(command, strlen(command));
}
/// Execute a line of command
/// Returns: Error code
int cmd_execl(char *command, size_t len) {
	int argc = void;
	char** argv = adbg_util_expand(command, &argc);
	return cmd_execv(argc, cast(const(char)**)argv);
}

//
// Private globals
//

__gshared adbg_process_t *tracee;
__gshared adbg_disassembler_t *disasm;
__gshared bool disasm_available;
__gshared bool user_continue;	/// if user wants to continue
__gshared AdbgAction user_action;

//
// prompt
//

void cmd_prompt() {
	printf("(adbg) ");
}

void cmd_help_chapter(const(char) *name) {
	puts(name);
}
void cmd_help_paragraph(const(char) *p) {
L_PRINT:
	int o = printf("\t%.72s\n", p);
	if (o < 72)
		return;
	p += 72;
	goto L_PRINT;
}

//
// Command handling
//

struct command_t {
	const(char) *str;	/// command string
	const(char) *synop;	/// command synopsis
	const(char) *desc;	/// help description
	int function(int, const(char)**) func;	/// command implementation
	void function() help;	/// help implementation
}
immutable command_t[] commands = [
	{
		"load", "<file> [<arg>...]",
		"Load executable file into the debugger",
		&cmd_c_load, &cmd_h_load
	},
//	{ "core",   null, "Load core debugging object into debugger", &cmd_c_load },
//	{ "attach", null, "Attach the debugger to pid", &cmd_c_pid },
//	{ "b",      "<action>", "Breakpoint management", & },
//	{ "d",      "<addr>", "Disassemble address", & },
	{
		"go", null,
		"Continue or start debugging.",
		&cmd_c_go
	},
	//TODO: restart
	{
		"stepi", null,
		"Perform an instruction step.",
		&cmd_c_stepi
	},
	//TODO: status
	{
		"reg", null,
		"Register management.",
		&cmd_c_reg
	},
	{
		"help", "<command>",
		"Show this help screen.",
		&cmd_c_help
	},
	{
		"maps", null,
		"Show memory maps.",
		&cmd_c_maps
	},
	{
		"scan", null,
		"Scan memory for value.",
		&cmd_c_scan
	},
	{
		"quit", null,
		"Quit debugger.",
		&cmd_c_quit
	},
	{
		"q", null,
		"Alias to quit.",
		&cmd_c_quit
	},
];

int cmd_execv(int argc, const(char) **argv) {
	if (argc <= 0 || argv == null)
		return 0;
	
	foreach (comm; commands)
		if (strcmp(argv[0], comm.str) == 0)
			return comm.func(argc, argv);
	
	printf("unknown command: '%s'\n", argv[0]);
	return AppError.invalidCommand;
}

//
// load command
//

int cmd_c_load(int argc, const(char) **argv) {
	if (argc < 2) {
		puts("missing file argument");
		return AppError.invalidParameter;
	}
	
	if (adbg_spawn(tracee, argv[1], argc > 2 ? argv + 2: null, 0)) {
		oops();
		return AppError.loadFailed;
	}
	
	return 0;
}
void cmd_h_load() {
	cmd_help_chapter("DESCRIPTION");
	cmd_help_paragraph(
	`Load an executable file into the debugger. Any arguments after the `~
	`file are arguments passed into the debugger.`
	);
}

//
// reg command
//

int cmd_c_reg(int argc, const(char) **argv) {
	adbg_thread_context_t *context = adbg_context_easy(tracee);
	
	if (context == null)
		return AppError.alicedbg;
	if (context.count == 0) {
		puts("No registers available");
		return AppError.unavailable;
	}
	
	adbg_register_t *regs = context.items.ptr;
	const(char) *rselect = argc >= 2 ? argv[1] : null;
	bool found;
	for (size_t i; i < context.count; ++i) {
		adbg_register_t *reg = &context.items[i];
		bool show = rselect == null || strcmp(rselect, regs[i].name) == 0;
		if (show == false) continue;
		char[20] normal = void, hexdec = void;
		adbg_context_format(normal.ptr, 20, reg, FORMAT_NORMAL);
		adbg_context_format(hexdec.ptr, 20, reg, FORMAT_HEXPADDED);
		printf("%-8s  0x%8s  %s\n", regs[i].name, hexdec.ptr, normal.ptr);
		found = true;
	}
	if (rselect && found == false) {
		puts("Register not found");
		return AppError.invalidParameter;
	}
	return 0;
}

//
// help command
//

int cmd_c_help(int argc, const(char) **argv) {
	// Help on command
	if (argc >= 2) {
		const(char) *arg = argv[1];
		
		foreach (comm; commands) {
			if (strcmp(arg, comm.str))
				continue;
			if (comm.help == null) {
				puts("Command has no help article available");
				return AppError.unavailable;
			}
			printf("COMMAND\n\t%s - %s\n\nSYNOPSIS\n\t%s %s\n\n",
				comm.str, comm.desc,
				comm.str, comm.synop);
			comm.help();
			return 0;
		}
		
		printf("No help article found for '%s'\n", arg);
		return AppError.invalidCommand;
	}
	
	static immutable const(char) *cmd_fmt   = " %-10s                      %s\n";
	static immutable const(char) *cmd_fmta  = " %-10s %-20s %s\n";
	
	// Command list
	foreach (comm; commands) {
		if (comm.synop)
			printf(cmd_fmta, comm.str, comm.synop, comm.desc);
		else
			printf(cmd_fmt, comm.str, comm.desc);
	}
	
	return 0;
}

//
// go command
//

int cmd_c_go(int argc, const(char) **argv) {
	if (adbg_continue(tracee))
		return AppError.alicedbg;
	if (adbg_wait(tracee, &cmd_exception_handler))
		return AppError.alicedbg;
	// Temporary: Cheap hack for process exit
	if (adbg_status(tracee) == AdbgStatus.unloaded)
		printf("*\tProcess %d exited\n", tracee.pid);
	return 0;
}

//
// stepi command
//

int cmd_c_stepi(int argc, const(char) **argv) {
	if (adbg_stepi(tracee))
		return AppError.alicedbg;
	if (adbg_wait(tracee, &cmd_exception_handler))
		return AppError.alicedbg;
	return 0;
}

//
// maps command
//

//TODO: optional arg: filter module by name (contains string)
int cmd_c_maps(int argc, const(char) **argv) {
	adbg_memory_map_t *mmaps = void;
	size_t mcount = void;
	
	if (adbg_memory_maps(tracee, &mmaps, &mcount, 0)) {
		return AppError.alicedbg;
	}
	for (size_t i; i < mcount; ++i) {
		adbg_memory_map_t *map = &mmaps[i];
		with (map) printf("%8p %10lld %s\n", base, size, name.ptr);
	}
	if (mcount) free(mmaps);
	
	return 0;
}

//
// scan command
//

// v1: can only handle one scan at a time
// v2: multiple scans
// Examples:
// - scan int -2 (new or continue scan)
//   print "123 hits"
//   or "123 hits, job 2 created"
// - scan reset (reset scan)
// - v2: scan list (list scans)
int cmd_c_scan(int argc, const(char) **argv) {
	// Sub command
	if (argc > 1) {
	}
	
	// Otherwise, new list
	
	return 0;
}

//
// quit command
//

int cmd_c_quit(int argc, const(char) **argv) {
	//TODO: Quit confirmation if debuggee is alive
	//      could do with optional "forced yes" type of optional
	exit(0);
	return 0;
}

//
// exception handler
//

void cmd_exception_handler(adbg_exception_t *ex) {
	printf("*	Process %d thread %d stopped\n"~
		"	Reason: %s ("~ADBG_OS_ERROR_FORMAT~")\n",
		ex.pid, ex.tid,
		adbg_exception_name(ex), ex.oscode);
	
	if (ex.faultz) {
		// NOTE: size_t stuff on Windows works with %Ix,
		//       so for now, print full.
		printf("	Fault address: %llx\n", ex.fault_address);
		printf("	Faulting instruction: ");
		cmd_disasm(ex.faultz);
	}
}

void cmd_disasm(size_t address, int count = 1) {
	if (disasm_available == false)
		return;
	
	for (int i; i < count; ++i) {
		ubyte[16] data = void;
		if (adbg_memory_read(tracee, address, data.ptr, 16)) {
			oops;
			return;
		}
		adbg_opcode_t op = void;
		if (adbg_dasm_once(disasm, &op, data.ptr, 16))
			printf("(error:%s)\n", adbg_error_msg);
		else
			printf("%s %s\n", op.mnemonic, op.operands);
	}
}
