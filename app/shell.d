/// Command shell and interface to debugger.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module shell;

import adbg.error, adbg.debugger, adbg.disassembler, adbg.object;
import adbg.include.c.stdio : printf, puts, putchar;
import adbg.include.c.stdlib : atoi, malloc, free, exit;
import core.stdc.string : strcmp, strncmp;
import common, utils;
import term;

//TODO: Print process exit code

extern (C):

/// Application error
enum ShellError {
	none	= 0,
	invalidParameter	= -1,
	invalidCommand	= -2, // or action or sub-command
	unavailable	= -3,
	loadFailed	= -4,
	pauseRequired	= -5,
	alreadyLoaded	= -6,
	missingOption	= -7,
	unformat	= -8,
	invalidCount	= -9,
	
	scanMissingType	= -20,
	scanMissingValue	= -21,
	scanInputOutOfRange	= -22,
	scanNoScan	= -23,
	scanInvalidSubCommand	= -24,
	
	crt	= -1000,
	alicedbg	= -1001,
}

const(char) *errorstring(ShellError code) {
	switch (code) with (ShellError) {
	case alicedbg:
		return adbg_error_msg;
	case invalidParameter:
		return "Invalid command parameter.";
	case invalidCommand:
		return "Invalid command.";
	case unavailable:
		return "Debugger unavailable.";
	case loadFailed:
		return "Failed to load file.";
	case pauseRequired:
		return "Debugger needs to be paused for this action.";
	case alreadyLoaded:
		return "File already loaded.";
	case missingOption:
		return "Missing option for command.";
	case unformat:
		return "Input is not a number.";
	case invalidCount:
		return "Count must be 1 or higher.";
	
	case scanMissingType:
		return "Missing type parameter.";
	case scanMissingValue:
		return "Missing value parameter.";
	case scanInputOutOfRange:
		return "Value out of range.";
	case scanNoScan:
		return "No prior scan were initiated.";
	case scanInvalidSubCommand:
		return "Invalid type or subcommand.";
	
	case none:
		return "No error occured.";
	default:
		return "Unknown error.";
	}
}

/*void registerError(void function(ref command2_help_t help)) {
	
}
void registerHelp(void function(ref command2_help_t help)) {
	
}*/

int shell_loop() {
	// Load process if CLI specified it
	if (globals.file) {
		if (adbg_debugger_spawn(&process, globals.file,
			AdbgSpawnOpt.argv, globals.args, 0))
			return oops;
		
		puts("Process created.");
	
		if (adbg_dasm_open(&dasm, adbg_process_get_machine(&process))) {
			dasm_available = false;
			printf("warning: Disassembler not available (%s)\n",
				adbg_error_msg());
		} else dasm_available = true;
		
		if (globals.syntax && dasm_available)
			adbg_dasm_options(&dasm, AdbgDasmOption.syntax, globals.syntax, 0);
	} else if (globals.pid) {
		if (adbg_debugger_attach(&process, globals.pid, 0))
			return oops;
		
		puts("Debugger attached to process");
	
		if (adbg_dasm_open(&dasm, adbg_process_get_machine(&process))) {
			dasm_available = false;
			printf("warning: Disassembler not available (%s)\n",
				adbg_error_msg());
		} else dasm_available = true;
		
		if (globals.syntax && dasm_available)
			adbg_dasm_options(&dasm, AdbgDasmOption.syntax, globals.syntax, 0);
	}
	
	term_init;

LINPUT:
	printf("(adbg) "); // print prompt
	char* line = term_readline(null); // read line
	
	//TODO: remove once term gets key events
	if (line == null) {
		printf("^D");
		return 0;
	}
	
	int error = shell_exec(line); // execute line
	if (error)
		printf("error: %s\n", errorstring(cast(ShellError)error));
	goto LINPUT;
}

int shell_exec(const(char) *command) {
	import adbg.utils.strings : adbg_util_expand;
	if (command == null) return 0;
	int argc = void;
	char** argv = adbg_util_expand(command, &argc);
	return shell_execv(argc, cast(const(char)**)argv);
}

int shell_execv(int argc, const(char) **argv) {
	if (argc <= 0 || argv == null)
		return 0;
	
	const(char) *ucommand = argv[0];
	immutable(command2_t) *command = shell_findcommand(ucommand);
	if (command == null) {
		serror("unknown command: '%s'", ucommand);
		return ShellError.invalidCommand;
	}
	
	return command.entry(argc, argv);
}

private:
__gshared:

//TODO: Make debugger return process pointer
adbg_process_t process;
//TODO: Make disassembler return instance pointer
adbg_disassembler_t dasm;

//TODO: Rely on disassembler pointer instead
bool dasm_available;

void function(const(char)* sev, const(char)* msg) userlog;

//TODO: Shell logging
void serror(const(char) *fmt, ...) {
	if (userlog == null) return;
	
}
void slog(const(char) *msg) {
	if (userlog == null) return;
	
}

immutable string RCFILE = ".adbgrc";

immutable string MODULE_SHELL = "Shell";
immutable string MODULE_DEBUGGER = "Debugger";
immutable string MODULE_DISASSEMBLER = "Disassembler";
immutable string MODULE_OBJECTSERVER = "Object Server";

immutable string CATEGORY_SHELL = "Command-line";
immutable string CATEGORY_PROCESS = "Process management";
immutable string CATEGORY_CONTEXT = "Thread context management";
immutable string CATEGORY_MEMORY = "Memory management";
immutable string CATEGORY_EXCEPTION = "Exception management";

immutable string SECTION_NAME = "NAME";
immutable string SECTION_SYNOPSIS = "SYNOPSIS";
immutable string SECTION_DESCRIPTION = "DESCRIPTION";
immutable string SECTION_NOTES = "NOTES";
immutable string SECTION_EXAMPLES = "EXAMPLES";

struct command2_help_section_t {
	string name;
	string[] bodies;
}
struct command2_help_t {
	// Debugger, Disassembler, Object Server
	string module_;
	// Process management, Memory, etc.
	string category;
	// Short description.
	string description;
	// 
	command2_help_section_t[] sections;
}
struct command2_t {
	string[] names;
	string description;
	string[] synopsis;
	string doc_module;
	string doc_category;
	command2_help_section_t[] doc_sections;
	int function(int, const(char)**) entry;
}
// NOTE: Called "commands_list" to avoid conflict with future "command_list" function
//TODO: Commands
// - !: Run host shell commands
// - b|breakpoint: Breakpoint management
// - t|thread: Thread management (e.g., selection, callstack)
// - sym: Symbol management
immutable command2_t[] shell_commands = [
	//
	// Debugger
	//
	{
		[ "status" ],
		"Get process status.",
		[],
		MODULE_DEBUGGER, CATEGORY_PROCESS,
		[
			{
				SECTION_DESCRIPTION,
				[ "Print the status of the debuggee process." ]
			}
		],
		&command_status,
	},
	{
		[ "spawn" ],
		"Spawn a new process into debugger.",
		[
			"FILE [ARGS...]"
		],
		MODULE_DEBUGGER, CATEGORY_PROCESS,
		[
			{
				SECTION_DESCRIPTION,
				[ "Spawns a new process from path with the debugger attached." ]
			}
		],
		&command_spawn,
	},
	{
		[ "attach" ],
		"Attach debugger to live process.",
		[
			"PID"
		],
		MODULE_DEBUGGER, CATEGORY_PROCESS,
		[
			{
				SECTION_DESCRIPTION,
				[ "Attaches debugger to an existing process by its Process ID." ]
			}
		],
		&command_attach,
	},
	{
		[ "detach" ],
		"Detach debugger from process.",
		[],
		MODULE_DEBUGGER, CATEGORY_PROCESS,
		[
			{
				SECTION_DESCRIPTION,
				[ "If the debugger was attached to a live process, detach "~
				"the debugger." ]
			}
		],
		&command_detach,
	},
	{
		[ "restart" ],
		"Restart the debugging process.",
		[],
		MODULE_DEBUGGER, CATEGORY_PROCESS,
		[
			{
				SECTION_DESCRIPTION,
				[ "The debugger will be re-attached or the process will be "~
				"killed and respawned." ]
			}
		],
		&command_restart,
	},
	{
		[ "go" ],
		"Continue debugging process.",
		[],
		MODULE_DEBUGGER, CATEGORY_PROCESS,
		[
			{
				SECTION_DESCRIPTION,
				[ "The debugger will be re-attached or the process will be "~
				"killed and respawned." ]
			}
		],
		&command_go,
	},
	{
		[ "kill" ],
		"Terminate process.",
		[],
		MODULE_DEBUGGER, CATEGORY_PROCESS,
		[
			{
				SECTION_DESCRIPTION,
				[ "The debugger will be re-attached or the process will be "~
				"killed and respawned." ]
			}
		],
		&command_kill,
	},
	{
		[ "stepi" ],
		"Perform an instruction step.",
		[],
		MODULE_DEBUGGER, CATEGORY_PROCESS,
		[
			{
				SECTION_DESCRIPTION,
				[ "From a paused state, executes exactly one instruction." ]
			}
		],
		&command_stepi,
	},
	//
	// Context
	//
	{
		[ "regs" ],
		"Lists register values.",
		[
			"[NAME]"
		],
		MODULE_DEBUGGER, CATEGORY_CONTEXT,
		[
			{
				SECTION_DESCRIPTION,
				[ "Get list of registers and values from process." ]
			}
		],
		&command_regs,
	},
	//
	// Memory
	//
	{
		[ "m", "memory" ],
		"Dump process memory from address.",
		[
			"ADDRESS [LENGTH=64]"
		],
		MODULE_DEBUGGER, CATEGORY_MEMORY,
		[
			{
				SECTION_DESCRIPTION,
				[ "Print memory data from address as hexadecimal." ]
			}
		],
		&command_memory,
	},
	{
		[ "maps" ],
		"List memory mapped items.",
		[],
		MODULE_DEBUGGER, CATEGORY_MEMORY,
		[
			{
				SECTION_DESCRIPTION,
				[ "Lists loaded modules and their memory regions." ]
			}
		],
		&command_maps,
	},
	{
		[ "d", "disassemble" ],
		"Disassemble instructions at address.",
		[
			"ADDRESS [COUNT=1]"
		],
		MODULE_DEBUGGER, CATEGORY_MEMORY,
		[
			{
				SECTION_DESCRIPTION,
				[ "Invoke the disassembler at the address. The debugger "~
				"will read process memory, if able, and will repeat "~
				"the operation COUNT times. By default, it will only "~
				"disassemble one instruction." ]
			}
		],
		&command_disassemble,
	},
	{
		[ "scan" ],
		"Scan for value in memory.",
		[
			"TYPE VALUE",
			"show",
			"reset",
		],
		MODULE_DEBUGGER, CATEGORY_MEMORY,
		[
			{
				SECTION_DESCRIPTION,
				[ "Scan memory maps for specified value. "~
				"No writing capability is available at the moment. "~
				"To list last scan results, use 'show' subcommand.",
				"To clear results, use 'reset' subcommand." ]
			}
		],
		&command_scan,
	},
	//
	// Shell
	//
	{
		[ "help" ],
		"Show help or a command's help article.",
		[
			"[ITEM]"
		],
		MODULE_SHELL, CATEGORY_SHELL,
		[
			
		],
		&command_help,
	},
	{
		[ "q", "quit" ],
		"Quit shell session.",
		[],
		MODULE_SHELL, CATEGORY_SHELL,
		[
			{
				SECTION_DESCRIPTION,
				[ "Close the shell session along with the debugger and "~
				"application if it was spawned using the debugger." ]
			}
		],
		&command_quit,
	},
];

immutable(command2_t)* shell_findcommand(const(char) *ucommand) {
	// NOTE: Can't use foreach for local var escape
	for (size_t i; i < shell_commands.length; ++i) {
		immutable(command2_t) *cmd = &shell_commands[i];
		
		for (size_t c; c < cmd.names.length; ++c) {
			if (strcmp(ucommand, cmd.names[c].ptr) == 0)
				return cmd;
		}
	}
	
	return null;
}

//TODO: shell_spawn
//TODO: shell_attach

void shell_event_disassemble(size_t address, int count = 1, bool showAddress = true) {
	if (dasm_available == false)
		return;
	
	for (int i; i < count; ++i) {
		enum RDSZ = 16;
		ubyte[RDSZ] data = void;
		if (adbg_memory_read(&process, address, data.ptr, RDSZ)) {
			oops;
			return;
		}
		adbg_opcode_t op = void;
		if (adbg_dasm_once(&dasm, &op, data.ptr, RDSZ)) {
			printf("%8llx (error:%s)\n", cast(ulong)address, adbg_error_msg);
			return;
		}
		
		// Print address
		if (showAddress)
			printf("%8llx ", op.address);
		
		// Print machine bytes
		for (size_t bi; bi < op.size; ++bi) {
			printf("%02x ", op.machine[bi]);
		}
		
		// Print mnemonic & operands
		printf("%s", op.mnemonic);
		if (op.operands)
			printf(" %s", op.operands);
		
		putchar('\n');
		
		address += op.size;
	}
}

void shell_event_exception(adbg_exception_t *ex) {
	printf("*	Process %d thread %d stopped\n"~
		"	Reason: %s ("~ADBG_OS_ERROR_FORMAT~")\n",
		ex.pid, ex.tid,
		adbg_exception_name(ex), ex.oscode);
	
	if (ex.faultz) {
		printf("	Fault address: %llx\n", ex.fault_address);
		printf("	Faulting instruction: ");
		shell_event_disassemble(ex.faultz, 1, false);
	}
}

void shell_event_help(immutable(command2_t) *command) {
	// Print header
	int p = 34;
	for (size_t i; i < command.names.length; ++i) {
		if (i) {
			printf(", ");
			--p;
		}
		p -= printf("%s", command.names[i].ptr);
	}
	with (command) printf("%*s  %*s\n\nNAME\n ", p, doc_module.ptr, 34, doc_category.ptr);
	for (size_t i; i < command.names.length; ++i) {
		if (i) putchar(',');
		printf(" %s", command.names[i].ptr);
	}
	printf(" - %s\n", command.description.ptr);
	
	if (command.synopsis.length) {
		printf("\n%s\n", SECTION_SYNOPSIS.ptr);
		foreach (s; command.synopsis) {
			printf("  %s %s\n", command.names[$-1].ptr, s.ptr);
		}
	}
	
	enum COL = 72;
	foreach (section; command.doc_sections) {
		printf("\n%s\n", section.name.ptr);
		
		//TODO: Better cut-offs
		//      [0] spacing? remove
		//      [$-1] non-spacing? put dash
		for (size_t i; i < section.bodies.length; ++i) {
			const(char) *b = section.bodies[i].ptr;
			if (i) putchar('\n');
		LPRINT:
			int o = printf("  %.*s\n", COL, b);
			if (o < COL)
				continue;
			b += COL;
			goto LPRINT;
		}
	}
	
	putchar('\n');
}

int command_status(int argc, const(char) **argv) {
	AdbgProcStatus state = adbg_process_status(&process);
	const(char) *m = void;
	switch (state) with (AdbgProcStatus) {
	case unloaded:	m = "unloaded"; break;
	case standby:	m = "standby"; break;
	case running:	m = "running"; break;
	case paused:	m = "paused"; break;
	default:	m = "(unknown)";
	}
	puts(m);
	return 0;
}

//TODO: List per category
//      Comparing could be per pointer or enum
int command_help(int argc, const(char) **argv) {
	if (argc > 1) { // Requesting help article for command
		const(char) *ucommand = argv[1];
		immutable(command2_t) *command = shell_findcommand(ucommand);
		if (command == null) {
			serror("Command not found: '%s'", ucommand);
			return ShellError.invalidCommand;
		}
		
		shell_event_help(command);
		return 0;
	}
	
	enum PADDING = 20;
	static immutable const(char) *liner = "..........................................";
	foreach (cmd; shell_commands) {
		int p;
		for (size_t i; i < cmd.names.length; ++i) {
			if (i) {
				putchar(',');
				++p;
			}
			p += printf(" %s", cmd.names[i].ptr);
		}
		
		printf(" %.*s %s\n", PADDING - p, liner, cmd.description.ptr);
	}
	
	return 0;
}

int command_spawn(int argc, const(char) **argv) {
	if (argc < 2) {
		serror("Missing file argument.");
		return ShellError.invalidParameter;
	}
	
	globals.file = argv[1];
	globals.args = argc > 2 ? argv + 2: null;
	
	if (adbg_debugger_spawn(&process, globals.file,
		AdbgSpawnOpt.argv, globals.args,
		0)) {
		serror("Could not spawn process.");
		return ShellError.alicedbg;
	}
	if (adbg_dasm_open(&dasm, adbg_process_get_machine(&process))) {
		dasm_available = false;
		printf("warning: Disassembler not available (%s)\n",
			adbg_error_msg());
	} else dasm_available = true;
	
	return 0;
}

//TODO: int shell_postload(
//      Load disassembler, etc.

int command_attach(int argc, const(char) **argv) {
	if (argc < 2) {
		serror("Missing pid argument");
		return ShellError.invalidParameter;
	}
	
	int pid = atoi(argv[1]);
	if (adbg_debugger_attach(&process, pid, 0)) {
		serror("Could not attach to process.");
		return ShellError.alicedbg;
	}
	if (adbg_dasm_open(&dasm, adbg_process_get_machine(&process))) {
		dasm_available = false;
		printf("warning: Disassembler not available (%s)\n",
			adbg_error_msg());
	} else dasm_available = true;
	
	return 0;
}

int command_detach(int argc, const(char) **argv) {
	if (adbg_debugger_detach(&process)) {
		serror("Could not detach process.");
		return ShellError.alicedbg;
	}
	if (dasm_available)
		adbg_dasm_close(&dasm);
	
	return 0;
}

int command_restart(int argc, const(char) **argv) {
	switch (process.creation) with (AdbgCreation) {
	case attached:
		int pid = adbg_process_get_pid(&process);
		if (adbg_debugger_detach(&process)) {
			serror("Could not detach process.");
			return ShellError.alicedbg;
		}
		if (adbg_debugger_attach(&process, pid)) {
			serror("Could not attach process.");
			return ShellError.alicedbg;
		}
		if (dasm_available)
			adbg_dasm_close(&dasm);
		if (adbg_dasm_open(&dasm, adbg_process_get_machine(&process))) {
			dasm_available = false;
			printf("warning: Disassembler not available (%s)\n",
				adbg_error_msg());
		} else dasm_available = true;
		puts("Debugger re-attached");
		break;
	case spawned:
		if (adbg_debugger_terminate(&process)) {
			serror("Could not terminate process.");
			return ShellError.alicedbg;
		}
		if (adbg_debugger_spawn(&process, globals.file,
			AdbgSpawnOpt.argv, globals.args,
			0)) {
			serror("Could not spawn process.");
			return ShellError.alicedbg;
		}
		if (dasm_available)
			adbg_dasm_close(&dasm);
		if (adbg_dasm_open(&dasm, adbg_process_get_machine(&process))) {
			dasm_available = false;
			printf("warning: Disassembler not available (%s)\n",
				adbg_error_msg());
		} else dasm_available = true;
		puts("Process respawned");
		break;
	default:
		serror("No process attached or spawned.");
		return 0;
	}
	
	return 0;
}

int command_go(int argc, const(char) **argv) {
	if (adbg_debugger_continue(&process))
		return ShellError.alicedbg;
	if (adbg_debugger_wait(&process, &shell_event_exception))
		return ShellError.alicedbg;
	// Temporary: Cheap hack for process exit
	if (adbg_process_status(&process) == AdbgProcStatus.unloaded)
		printf("*\tProcess %d exited\n", process.pid);
	return 0;
}

int command_kill(int argc, const(char) **argv) {
	if (adbg_debugger_terminate(&process))
		return ShellError.alicedbg;
	return 0;
}

int command_stepi(int argc, const(char) **argv) {
	if (adbg_debugger_stepi(&process))
		return ShellError.alicedbg;
	if (adbg_debugger_wait(&process, &shell_event_exception))
		return ShellError.alicedbg;
	return 0;
}

int command_regs(int argc, const(char) **argv) {
	adbg_registers_t regs = void;
	adbg_registers(&regs, &process);
	
	if (regs.count == 0) {
		serror("No registers available");
		return ShellError.unavailable;
	}
	
	adbg_register_t *reg = regs.items.ptr;
	const(char) *rselect = argc >= 2 ? argv[1] : null;
	bool found;
	for (size_t i; i < regs.count; ++i, ++reg) {
		bool show = rselect == null || strcmp(rselect, reg.name) == 0;
		if (show == false) continue;
		char[20] normal = void, hexdec = void;
		adbg_register_format(normal.ptr, 20, reg, FORMAT_DEC);
		adbg_register_format(hexdec.ptr, 20, reg, FORMAT_HEXPADDED);
		printf("%-8s  0x%8s  %s\n", reg.name, hexdec.ptr, normal.ptr);
		found = true;
	}
	if (rselect && found == false) {
		serror("Register not found");
		return ShellError.invalidParameter;
	}
	return 0;
}

int command_memory(int argc, const(char) **argv) {
	if (argc < 2) {
		return ShellError.missingOption;
	}
	
	long uaddress = void;
	if (unformat64(&uaddress, argv[1]))
		return ShellError.unformat;
	
	int ulength = 64;
	if (argc >= 3) {
		if (unformat(&ulength, argv[2]))
			return ShellError.unformat;
		if (ulength <= 0)
			return 0;
	}
	
	ubyte *data = cast(ubyte*)malloc(ulength);
	if (data == null)
		return ShellError.crt;
	
	if (adbg_memory_read(&process, cast(size_t)uaddress, data, ulength))
		return ShellError.alicedbg;
	
	// Print column header
	enum COLS = 16; /// Columns in bytes
	size_t count = ulength / COLS;
	printf("                  ");
	for (size_t c; c < COLS; ++c) {
		printf("%2x ", cast(uint)c);
	}
	putchar('\n');
	
	// Print rows
	for (size_t c; c < count; ++c, uaddress += COLS) {
		printf("%16llx  ", uaddress);
		for (size_t i; i < COLS && c * i < ulength; ++i) {
			printf("%02x ", data[(c * COLS) + i]);
		}
		putchar('\n');
	}
	
	return 0;
}

//TODO: optional arg: filter module by name (contains string)
//TODO: max count to show or option to filter modules out
int command_maps(int argc, const(char) **argv) {
	adbg_memory_map_t *mmaps = void;
	size_t mcount = void;
	
	if (adbg_memory_maps(&process, &mmaps, &mcount, 0))
		return ShellError.alicedbg;
	
	puts("Region           Size       T Perm File");
	for (size_t i; i < mcount; ++i) {
		adbg_memory_map_t *map = &mmaps[i];
		
		char[4] perms = void;
		perms[0] = map.access & AdbgMemPerm.read  ? 'r' : '-';
		perms[1] = map.access & AdbgMemPerm.write ? 'w' : '-';
		perms[2] = map.access & AdbgMemPerm.exec  ? 'x' : '-';
		perms[3] = map.access & AdbgMemPerm.private_ ? 'p' : 's';
		
		char t = void;
		switch (map.type) {
		case AdbgPageUse.resident: 	t = 'R'; break;
		case AdbgPageUse.fileview: 	t = 'F'; break;
		case AdbgPageUse.module_:	t = 'M'; break;
		default:	t = '?';
		}
		
		with (map) printf("%16zx %10lld %c %.4s %s\n",
			cast(size_t)base, size, t, perms.ptr, name.ptr);
	}
	
	free(mmaps);
	return 0;
}

//TODO: start,+length start,end syntax
int command_disassemble(int argc, const(char) **argv) {
	if (dasm_available == false)
		return ShellError.unavailable;
	if (argc < 2) {
		return ShellError.missingOption;
	}
	
	long uaddress = void;
	if (unformat64(&uaddress, argv[1]))
		return ShellError.unformat;
	
	int ucount = 1;
	if (argc >= 3) {
		if (unformat(&ucount, argv[2]))
			return ShellError.unformat;
		if (ucount <= 0)
			return 0;
	}
	if (ucount < 1) {
		return ShellError.invalidCount;
	}
	
	shell_event_disassemble(cast(size_t)uaddress, ucount);
	return 0;
}

__gshared size_t last_scan_size;
__gshared ulong last_scan_data;
__gshared adbg_scan_t *last_scan;

void shell_event_list_scan_results() {
	// super lazy hack
	long mask = void;
	switch (last_scan_size) {
	case 8: mask = 0; break;
	case 7: mask = 0xff_ffff_ffff_ffff; break;
	case 6: mask = 0xffff_ffff_ffff; break;
	case 5: mask = 0xff_ffff_ffff; break;
	case 4: mask = 0xffff_ffff; break;
	case 3: mask = 0xff_ffff; break;
	case 2: mask = 0xffff; break;
	case 1: mask = 0xff; break;
	default:
		puts("fatal: mask fail");
		return;
	}
	//    0000. ffffffffffffffff  18446744073709551615
	puts("No.   Address           Previous              Current");
	adbg_scan_result_t *result = last_scan.results;
	uint count = cast(uint)last_scan.result_count + 1; // temp cast until better z printf
	for (uint i = 1; i < count; ++i, ++result) {
		printf("%4u. %-16llx  %*llu  ", i, result.address, -20, result.value_u64 & mask);
		ulong udata = void;
		if (adbg_memory_read(&process, cast(size_t)result.address, &udata, cast(uint)last_scan_size))
			puts("???");
		else
			printf("%llu\n", udata & mask);
	}
}

int command_scan(int argc, const(char) **argv) {
	if (argc < 2)
		return ShellError.scanMissingType;
	
	const(char) *usub = argv[1];
	
	if (strcmp(usub, "show") == 0) {
		if (last_scan == null)
			return ShellError.scanNoScan;
		
		shell_event_list_scan_results;
		return 0;
	} else if (strcmp(usub, "reset") == 0) {
		if (last_scan == null)
			return 0;
		
		adbg_memory_scan_close(last_scan);
		last_scan = null;
		return 0;
	}
	
	if (argc < 3)
		return ShellError.scanMissingValue;
	
	const(char) *uin = argv[2];
	
	union u {
		long data64;
		int data;
	}
	u user = void;
	if (strcmp(usub, "byte") == 0) {
		last_scan_size = ubyte.sizeof;
		if (unformat(&user.data, uin))
			return ShellError.unformat;
		if (user.data > ubyte.max)
			return ShellError.scanInputOutOfRange;
	} else if (strcmp(usub, "short") == 0) {
		last_scan_size = short.sizeof;
		if (unformat(&user.data, uin))
			return ShellError.unformat;
		if (user.data > short.max)
			return ShellError.scanInputOutOfRange;
	} else if (strcmp(usub, "int") == 0) {
		last_scan_size = int.sizeof;
		if (unformat(&user.data, uin))
			return ShellError.unformat;
	} else if (strcmp(usub, "long") == 0) {
		last_scan_size = long.sizeof;
		if (unformat64(&user.data64, uin))
			return ShellError.unformat;
	} else
		return ShellError.scanInvalidSubCommand;
	
	if (last_scan)
		adbg_memory_scan_close(last_scan);
	
	last_scan_data = user.data64;
	
	if ((last_scan = adbg_memory_scan(&process, &user, last_scan_size,
		AdbgScanOpt.capacity, 100,
		0)) == null)
		return ShellError.alicedbg;
	
	printf("Scan completed with %u results.\n", cast(uint)last_scan.result_count);
	return 0;
}

int command_rescan(int argc, const(char) **argv) {
	if (argc < 2)
		return ShellError.scanMissingType;
	if (argc < 3)
		return ShellError.scanMissingValue;
	
	const(char) *usub = argv[1];
	const(char) *uin = argv[2];
	
	union u {
		long data64;
		int data;
	}
	u user = void;
	if (strcmp(usub, "byte") == 0) {
		last_scan_size = ubyte.sizeof;
		if (unformat(&user.data, uin))
			return ShellError.unformat;
		if (user.data > ubyte.max)
			return ShellError.scanInputOutOfRange;
	} else if (strcmp(usub, "short") == 0) {
		last_scan_size = short.sizeof;
		if (unformat(&user.data, uin))
			return ShellError.unformat;
		if (user.data > short.max)
			return ShellError.scanInputOutOfRange;
	} else if (strcmp(usub, "int") == 0) {
		last_scan_size = int.sizeof;
		if (unformat(&user.data, uin))
			return ShellError.unformat;
	} else if (strcmp(usub, "long") == 0) {
		last_scan_size = long.sizeof;
		if (unformat64(&user.data64, uin))
			return ShellError.unformat;
	} else
		return ShellError.scanInvalidSubCommand;
	
	if (adbg_memory_rescan(last_scan, &user, last_scan_size))
		return ShellError.alicedbg;
	
	last_scan_data = user.data64;
	
	printf("Scan completed with %u results.\n", cast(uint)last_scan.result_count);
	return 0;
}

int command_quit(int argc, const(char) **argv) {
	//TODO: Quit confirmation if debuggee is alive
	//      could do with optional "forced yes" type of optional
	exit(0);
	return 0;
}