/// Command shell and interface to debugger.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module shell;

// TODO: Pre-load/Exit event handlers (e.g., closing disassembler) functions

import adbg;
import adbg.error;
import adbg.include.c.stdio;
import adbg.include.c.stdlib;
import adbg.include.c.stdarg;
import adbg.os.path;
import adbg.utils.strings : adbg_util_expand;
import core.stdc.string;
import common.errormgmt;
import common.cli : opt_syntax;
import common.utils;
import term;

extern (C):

enum { // Shell options
	SHELL_NOCOLORS = 1, /// Disable colors for logger
}

/// 
__gshared int opt_pid;
/// 
__gshared const(char) **opt_file_argv;

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
	missingArgument	= -8,
	unformat	= -9,
	invalidCount	= -10,
	unattached	= -11,
	
	scanMissingType	= -20,
	scanMissingValue	= -21,
	scanInputOutOfRange	= -22,
	scanNoScan	= -23,
	scanInvalidSubCommand	= -24,
	
	crt	= -1000,
	alicedbg	= -1001,
}

const(char) *shell_error_string(int code) {
	switch (code) with (ShellError) {
	case alicedbg:
		return adbg_error_message();
	case invalidParameter:
		return "Invalid command parameter.";
	case invalidCommand:
		return "Invalid command.";
	case unavailable:
		return "Feature unavailable.";
	case loadFailed:
		return "Failed to load file.";
	case pauseRequired:
		return "Debugger needs to be paused for this action.";
	case alreadyLoaded:
		return "File already loaded.";
	case missingOption:
		return "Missing option for command.";
	case missingArgument:
		return "Missing argument.";
	case unformat:
		return "Input is not a number.";
	case invalidCount:
		return "Count must be 1 or higher.";
	case unattached:
		return "Need to be attached to a process for this feature.";
	
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

private __gshared int shellflags;
private __gshared int logflags;
void logerror(const(char) *fmt, ...) {
	va_list args = void;
	va_start(args, fmt);
	logwrite("error", TextColor.red, fmt, args);
}
void logwarn(const(char) *fmt, ...) {
	va_list args = void;
	va_start(args, fmt);
	logwrite("warning", TextColor.yellow, fmt, args);
}
void loginfo(const(char) *fmt, ...) {
	va_list args = void;
	va_start(args, fmt);
	
	logwrite(null, 0, fmt, args);
}
private
void logwrite(const(char) *pre, int color, const(char) *fmt, va_list args) {
	if (pre) {
		if ((shellflags & SHELL_NOCOLORS) == 0)
			concoltext(cast(TextColor)color, stderr);
		fputs(pre, stderr);
		if ((shellflags & SHELL_NOCOLORS) == 0)
			concolrst(stderr);
		fputs(": ", stderr);
	}
	
	vfprintf(stderr, fmt, args);
	putchar('\n');
}

int shell_start(int argc, const(char)** argv) {
	// TODO: Use commands directly?
	// Start or attach to process if specified
	if (argc > 0 && argv && shell_spawn(*argv, argc > 1 ? argv + 1 : null)) {
		logerror("Could not spawn process: %s", adbg_error_message());
		return 1;
	} else if (opt_pid && shell_attach(opt_pid)) {
		logerror("Could not attach to process: %s", adbg_error_message());
		return 1;
	}
	
Lcommand:
	fputs("(adbg) ", stdout);
	fflush(stdout);
	
	// .ptr is temporary because a slice with a length of 0
	// also make its pointer null.
	char* line = conrdln().ptr;
	
	// Invalid line or CTRL+D
	if (line == null || line[0] == 4)
		return 0;
	
	// External shell command
	if (line[0] == '!') {
		if (line[1]) // has something
			loginfo("Command exited with code %d\n", system(line + 1));
		goto Lcommand;
	}
	
	int e = shell_exec(line);
	if (e)
		logerror(shell_error_string(e));
	goto Lcommand;
}

int shell_exec(const(char) *command) {
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
	if (command == null)
		return ShellError.invalidCommand;
	
	assert(command.entry, "Command missing entry function");
	return command.entry(argc, argv);
}

private:
__gshared:

// NOTE: Process management
//       Right now the shell is only capable of dealing with one process
adbg_process_t *process;
adbg_disassembler_t *dis;

const(char)* last_spawn_exec;
const(char)** last_spawn_argv;

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
		[ "FILE [ARGS...]" ],
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
		[ "PID" ],
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
				[ "From a paused state, executes exactly one or more instruction." ]
			}
		],
		&command_stepi,
	},
	//
	// Memory
	//
	{
		[ "m", "memory" ],
		"Dump process memory from address.",
		[ "ADDRESS [LENGTH=64]" ],
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
		[ "[ADDRESS=PC/EIP/RIP [COUNT=1]]" ],
		MODULE_DEBUGGER, CATEGORY_MEMORY,
		[
			{
				SECTION_DESCRIPTION,
				[ "Invoke the disassembler at the given address.",
				"The debugger will read process memory, if able,"~
				" and will repeat the operation COUNT times."~
				" By default, it will only disassemble one instruction at"~
				" the register value that PC, EIP, or RIP points to." ]
			}
		],
		&command_disassemble,
	},
	{
		[ "scan" ],
		"Scan for value in memory.",
		[ "TYPE VALUE", "show", "reset", ],
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
	// Process management
	//
	{
		[ "plist" ],
		"List running programs.",
		[],
		MODULE_DEBUGGER, CATEGORY_PROCESS,
		[
			{ SECTION_DESCRIPTION,
			[ "List active processes." ]
			}
		],
		&command_plist,
	},
	//
	// Thread management
	//
	{
		[ "t", "thread" ],
		"Manage process threads.",
		[ "list", "TID registers" ],
		MODULE_DEBUGGER, CATEGORY_PROCESS,
		[
			{ SECTION_DESCRIPTION,
			[ "" ]
			}
		],
		&command_thread,
	},
	//
	// Shell
	//
	{
		[ "pwd" ],
		"Print the current working directory.",
		[],
		MODULE_SHELL, CATEGORY_SHELL,
		[
		],
		&command_pwd,
	},
	{
		[ "cd" ],
		"Change current directory.",
		[ "PATH" ],
		MODULE_SHELL, CATEGORY_SHELL,
		[
		],
		&command_cd,
	},
	{
		[ "help" ],
		"Show help or a command's help article.",
		[ "[ITEM]" ],
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
	debug static immutable(command2_t) ucommand_crash = {
		[ "crash" ],
		null,
		[],
		null, null,
		[],
		&command_crash
	};
	debug if (strcmp(ucommand, ucommand_crash.names[0].ptr) == 0)
		return &ucommand_crash;
	
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

int shell_spawn(const(char) *exec, const(char) **argv) {
	// Save for restart
	last_spawn_exec = exec;
	last_spawn_argv = argv;
	
	// Spawn process
	process = adbg_debugger_spawn(exec,
		AdbgSpawnOpt.argv, argv,
		0);
	if (process == null)
		return ShellError.alicedbg;
	
	printf("Process '%s' created", exec);
	if (argv && *argv) {
		printf(" with arguments:");
		for (int i; argv[i]; ++i)
			printf(" '%s'", argv[i]);
	}
	putchar('\n');
	
	// Open disassembler for process machine type
	dis = adbg_dis_open(adbg_process_machine(process));
	if (dis == null)
		logwarn("Disassembler not available (%s)", adbg_error_message());
	
	return 0;
}

int shell_attach(int pid) {
	// Save for restart
	opt_pid = pid;
	
	// Attach to process
	process = adbg_debugger_attach(pid, 0);
	if (process == null)
		return ShellError.alicedbg;
	
	loginfo("Debugger attached.");
	
	// Open disassembler for process machine type
	dis = adbg_dis_open(adbg_process_machine(process));
	if (dis) {
		if (opt_syntax)
			adbg_dis_options(dis, AdbgDisOpt.syntax, opt_syntax, 0);
	} else {
		logwarn("Disassembler not available (%s)\n",
			adbg_error_message());
	}
	
	return 0;
}

void shell_event_disassemble(size_t address, int count = 1, bool showAddress = true) {
	if (dis == null)
		return;
	
	enum MBUFSZ = 64; /// Machine string buffer size
	
	ubyte[MAX_INSTR_SIZE] data = void; /// Main input buffer
	char[MBUFSZ] machbuf = void; /// Formatted machine codes buffer
	for (int i; i < count; ++i) {
		if (adbg_memory_read(process, address, data.ptr, MAX_INSTR_SIZE)) {
			print_error_adbg();
			return;
		}
		adbg_opcode_t op = void;
		if (adbg_dis_once(dis, &op, data.ptr, MAX_INSTR_SIZE)) {
			printf("%8llx (error:%s)\n", cast(ulong)address, adbg_error_message());
			return;
		}
		
		// Print address
		if (showAddress)
			printf("%zx ", address);
		
		// Print machine bytes into a dedicated buffer
		size_t bo;
		for (size_t bi; bi < op.size && bo < MBUFSZ; ++bi)
			bo += snprintf(machbuf.ptr + bo, MBUFSZ - bo, " %02x", op.machine[bi]);
		
		// Print opcodes and mnemonic
		printf("%*s  %s", -(10 * 3), machbuf.ptr, op.mnemonic);
		
		// Print operands, if any
		if (op.operands)
			printf("\t%s", op.operands);
		
		// Terminate line
		putchar('\n');
		
		address += op.size;
	}
}

void shell_event_debugger(adbg_process_t *proc, int event, void *edata, void *udata) {
	process = proc;
	
	switch (event) with (AdbgEvent) {
	case exception:
		adbg_exception_t *ex = cast(adbg_exception_t*)edata;
		
		// HACK: Currently have no way to determine remote associated thread
		version (Windows)
		printf("*	Process %d (thread %d) stopped\n"~
			"	Reason  : %s ("~ADBG_OS_ERROR_FORMAT~")\n",
			proc.pid, proc.tid,
			adbg_exception_name(ex), ex.oscode);
		else
		printf("*	Process %d stopped\n"~
			"	Reason  : %s ("~ADBG_OS_ERROR_FORMAT~")\n",
			proc.pid,
			adbg_exception_name(ex), ex.oscode);
		
		// No fault address available
		if (ex.faultz == 0)
			return;
		
		printf("	Address : 0x%llx\n", ex.fault_address);
		
		// No disassembler available
		if (dis == null)
			return;
		
		printf("	Machine :");
		
		// Ready memory
		ubyte[MAX_INSTR_SIZE] data = void;
		if (adbg_memory_read(process, ex.faultz, data.ptr, MAX_INSTR_SIZE)) {
			printf(" read error (%s)\n", adbg_error_message());
			return; // Nothing else to do
		}
		
		adbg_opcode_t op = void;
		if (adbg_dis_once(dis, &op, data.ptr, MAX_INSTR_SIZE)) {
			printf(" disassembly error (%s)\n", adbg_error_message());
			return;
		}
		
		// Print machine bytes
		for (size_t bi; bi < op.size; ++bi) {
			printf(" %02x", op.machine[bi]);
		}
		putchar('\n');
		
		// Print mnemonic
		printf("	Mnemonic: %s", op.mnemonic);
		if (op.operands)
			printf(" %s", op.operands);
		putchar('\n');
		return;
	case processExit:
		int *exitcode = cast(int*)(edata);
		printf("* Process exited with code %d\n", *exitcode);
		return;
	default:
	}
}

void shell_event_help(immutable(command2_t) *command) {
	// Print header
	int p = 34; // horizontal alignment padding
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

debug
int command_crash(int, const(char) **) {
	void function() fnull;
	fnull();
	return 0;
}

int command_status(int argc, const(char) **argv) {
	puts(adbg_process_status_string(process));
	return 0;
}

//TODO: List per category
//      Comparing could be per pointer or enum
int command_help(int argc, const(char) **argv) {
	if (argc > 1) { // Requesting help article for command
		const(char) *ucommand = argv[1];
		immutable(command2_t) *command = shell_findcommand(ucommand);
		if (command == null)
			return ShellError.invalidParameter;
		
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
		
		printf("  %.*s %s\n", PADDING - p, liner, cmd.description.ptr);
	}
	
	return 0;
}

int command_spawn(int argc, const(char) **argv) {
	if (argc < 2)
		return ShellError.missingArgument;
	
	return shell_spawn(argv[1], argv + 2);
}

int command_attach(int argc, const(char) **argv) {
	if (argc < 2)
		return ShellError.invalidParameter;
	
	return shell_attach(atoi(argv[1]));
}

int command_detach(int argc, const(char) **argv) {
	if (adbg_debugger_detach(process))
		return ShellError.alicedbg;
	
	adbg_dis_close(dis);
	return 0;
}

int command_restart(int argc, const(char) **argv) {
	// TODO: Use commands directly?
	switch (process.creation) with (AdbgCreation) {
	case spawned:
		// Terminate first, ignore on error (e.g., already gone)
		adbg_debugger_terminate(process);
		
		// Spawn, shell still messages status
		return shell_spawn(last_spawn_exec, last_spawn_argv);
	case attached:
		// Detach first, ignore on error (e.g., already detached)
		adbg_debugger_detach(process);
		
		// Attach, shell still messages status
		return shell_attach(opt_pid);
	default:
		return ShellError.unattached;
	}
}

int command_go(int argc, const(char) **argv) {
	if (adbg_debugger_continue(process))
		return ShellError.alicedbg;
	if (adbg_debugger_wait(process, &shell_event_debugger, null))
		return ShellError.alicedbg;
	return 0;
}

int command_kill(int argc, const(char) **argv) {
	if (adbg_debugger_terminate(process))
		return ShellError.alicedbg;
	loginfo("Process killed");
	adbg_dis_close(dis);
	return 0;
}

// NOTE: Can't simply execute stepi multiple times in a row
int command_stepi(int argc, const(char) **argv) {
	if (adbg_debugger_stepi(process))
		return ShellError.alicedbg;
	if (adbg_debugger_wait(process, &shell_event_debugger, null))
		return ShellError.alicedbg;
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
	
	if (adbg_memory_read(process, cast(size_t)uaddress, data, ulength))
		return ShellError.alicedbg;
	
	enum COLS = 16; /// Columns in bytes
	enum PADD = 12; /// Address padding
	
	// Print column header
	for (int c; c < PADD; ++c)
		putchar(' ');
	putchar(' ');
	putchar(' ');
	for (int c; c < COLS; ++c)
		printf("%2x ", cast(uint)c);
	putchar('\n');
	
	// Print data rows
	size_t count = ulength / COLS;
	for (size_t c; c < count; ++c, uaddress += COLS) {
		// Print address
		printf("%.*llx  ", PADD, uaddress);
		
		// Print data column
		for (size_t i; i < COLS && c * i < ulength; ++i)
			printf("%02x ", data[(c * COLS) + i]);
		
		// Print ascii column
		putchar(' ');
		for (size_t i; i < COLS && c * i < ulength; ++i)
			putchar(asciichar(data[(c * COLS) + i], '.'));
		
		putchar('\n');
	}
	
	return 0;
}

//TODO: optional arg: filter module by name (contains string)
//TODO: max count to show or option to filter modules out
int command_maps(int argc, const(char) **argv) {
	adbg_memory_map_t *mmaps = void;
	size_t mcount = void;
	
	if (adbg_memory_maps(process, &mmaps, &mcount, 0))
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
		
		with (map) printf("%16zx %10zd %c %.4s %s\n",
			cast(size_t)base, size, t, perms.ptr, name.ptr);
	}
	
	free(mmaps);
	return 0;
}

//TODO: "start,+length" and "start,end" syntax
int command_disassemble(int argc, const(char) **argv) {
	if (process == null)
		return ShellError.unattached;
	if (dis == null)
		return ShellError.unavailable;
	
	// TODO: Add default address to PC/RIP
	//       Once Posix side gets thread id matching
	// Need address
	if (argc < 2)
		return ShellError.missingArgument;
	
	long uaddress = void;
	if (unformat64(&uaddress, argv[1]))
		return ShellError.unformat;
	
	// Number of instruction, default to 10
	int ucount = 10;
	if (argc >= 3) {
		if (unformat(&ucount, argv[2]))
			return ShellError.unformat;
		if (ucount <= 0)
			return 0;
	}
	if (ucount < 1)
		return ShellError.invalidCount;
	
	shell_event_disassemble(cast(size_t)uaddress, ucount);
	return 0;
}

size_t last_scan_size;
ulong last_scan_data;
adbg_scan_t *last_scan;

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
		if (adbg_memory_read(process, cast(size_t)result.address, &udata, cast(uint)last_scan_size))
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
	
	if ((last_scan = adbg_memory_scan(process, &user, last_scan_size,
		AdbgScanOpt.capacity, 100,
		0)) == null)
		return ShellError.alicedbg;
	
	loginfo("Scan completed with %u results.\n", cast(uint)last_scan.result_count);
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
	
	loginfo("Scan completed with %u results.\n", cast(uint)last_scan.result_count);
	return 0;
}

int command_plist(int argc, const(char) **argv) {
	void* proclist = adbg_process_list_new();
	if (proclist == null)
		return ShellError.alicedbg;
	
	puts("PID         Name");
	enum BUFFERSIZE = 2048;
	char[BUFFERSIZE] buffer = void;
	adbg_process_t *proc = void;
	for (size_t i; (proc = adbg_process_list_get(proclist, i)) != null; ++i) {
		printf("%10d  ", adbg_process_pid(proc));
		if (adbg_process_path(proc, buffer.ptr, BUFFERSIZE)) {
			version (Trace) trace("error: %s", adbg_error_message());
			else            putchar('\n');
			continue;
		}
		puts(buffer.ptr);
	}
	adbg_process_list_close(proclist);
	return 0;
}

int command_thread(int argc, const(char) **argv) {
	if (process == null)
		return ShellError.pauseRequired;
	if (argc < 2)
		return ShellError.missingArgument;
	
	adbg_thread_t *thread = void;
	
	const(char) *action = argv[1];
	// thread list - get a list of threads
	if (strcmp(action, "list") == 0) {
		if (adbg_thread_list_update(process))
			return ShellError.alicedbg;
		
		puts("Threads:");
		size_t i;
		while ((thread = adbg_thread_list_by_index(process, i++)) != null) {
			printf("%*d\n", -10, adbg_thread_id(thread));
		}
		return 0;
	}
	
	// Else: thread TID subcommand
	if (argc < 3) // thread id
		return ShellError.missingArgument;
	
	// Select thread
	thread = adbg_thread_list_by_id(process, atoi(argv[1]));
	if (thread == null)
		return ShellError.alicedbg;
	
	action = argv[2];
	if (strcmp(action, "registers") == 0) {
		// Update its context
		adbg_thread_context_update(process, thread);
		
		int id;
		adbg_register_t *register = void;
		while ((register = adbg_register_by_id(thread, id++)) != null) {
			char[20] dec = void, hex = void;
			adbg_register_format(dec.ptr, 20, register, AdbgRegisterFormat.dec);
			adbg_register_format(hex.ptr, 20, register, AdbgRegisterFormat.hexPadded);
			printf("%*s  0x%*s  %s\n",
				-8, adbg_register_name(register),
				8, hex.ptr,
				dec.ptr);
		}
	} else
		return ShellError.invalidParameter;
	
	return 0;
}

int command_cd(int argc, const(char) **argv) {
	if (argc < 2)
		return ShellError.missingArgument;
	if (adbg_os_chdir(argv[1]))
		return ShellError.alicedbg;
	return 0;
}

int command_pwd(int argc, const(char) **argv) {
	char[4096] b = void;
	const(char) *path = adbg_os_pwd(b.ptr, 4096);
	if (path == null)
		return ShellError.alicedbg;
	puts(path);
	return 0;
}

int command_quit(int argc, const(char) **argv) {
	//TODO: Quit confirmation if debuggee is alive
	//      could do with optional "forced yes" type of optional
	exit(0);
	return 0;
}