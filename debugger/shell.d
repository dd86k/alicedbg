/// Command shell and interface to debugger.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module shell;

import adbg.error, adbg.debugger, adbg.disassembler, adbg.object, adbg.machines;
import adbg.include.c.stdio;
import adbg.include.c.stdlib;
import adbg.include.c.stdarg;
import core.stdc.string;
import common.error;
import common.cli : opt_syntax;
import common.utils;
import debugger;
import term;

// Enable new process name, although it is currently broken on Windows
//version = UseNewProcessName

//TODO: Make disassembler setting to space out machine opcodes

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

int shell_start(int argc, const(char)** argv) {
	int ecode = void;
	
	if (loginit(null))
		return 1337;
	
	// Start process if specified
	if (argc > 0 && argv) {
		// Assume argv is null-terminated as it is on msvcrt and glibc
		ecode = shell_proc_spawn(*argv, argv + 1);
		if (ecode) {
			printf("Error: %s\n", adbg_error_message());
			return ecode;
		}
	} else if (opt_pid) { // Or attach to process if specified
		ecode = shell_proc_attach(opt_pid);
		if (ecode) {
			printf("Error: %s\n", adbg_error_message());
			return ecode;
		}
	}
	
	coninit();

Lcommand:
	printf("(adbg) ");
	fflush(stdout);
	
	// .ptr is temporary because a slice with a length of 0
	// also make its pointer null.
	char* line = conrdln().ptr;
	
	if (line == null || line[0] == 4) { // 4 == ^D
		return 0;
	}
	
	ecode = shell_exec(line);
	if (ecode)
		logerror(shell_error_string(ecode));
	goto Lcommand;
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
		return ShellError.invalidCommand;
	}
	return command.entry(argc, argv);
}

private:
__gshared:

adbg_process_t *process;
adbg_disassembler_t *dis;
adbg_registers_t *registers;

const(char)* last_spawn_exec;
const(char)** last_spawn_argv;

// NOTE: BetterC stderr bindings on Windows are broken
//       And don't allow re-opening the streams, so screw it
//       Fixed since DMD 1.103.1 and LDC 1.32.1?

FILE *logfd;
int loginit(const(char) *path) {
	version (Windows) {
		// 1. HANDLE stdHandle = GetStdHandle(STD_ERROR_HANDLE);
		// 2. int fileDescriptor = _open_osfhandle((intptr_t)stdHandle, _O_TEXT);
		// 3. FILE* file = _fdopen(fileDescriptor, "w");
		// 4. int dup2Result = _dup2(_fileno(file), _fileno(stderr));
		// 5. setvbuf(stderr, NULL, _IONBF, 0);
		if (path == null) path = "CONOUT$";
	} else {
		if (path == null) path = "/dev/stderr";
	}
	
	logfd = fopen(path, "wb");
	if (logfd) {
		setvbuf(logfd, null, _IONBF, 0);
	}
	return logfd == null;
}
void logerror(const(char) *fmt, ...) {
	va_list args = void;
	va_start(args, fmt);
	logwrite("error", fmt, args);
}
void logwarn(const(char) *fmt, ...) {
	va_list args = void;
	va_start(args, fmt);
	logwrite("warning", fmt, args);
}
void loginfo(const(char) *fmt, ...) {
	va_list args = void;
	va_start(args, fmt);
	logwrite(null, fmt, args);
}
void logwrite(const(char) *level, const(char) *fmt, va_list args) {
	if (level) {
		fputs(level, logfd);
		fputs(": ", logfd);
	}
	vfprintf(logfd, fmt, args);
	putchar('\n');
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
	// Context
	//
	{
		[ "regs" ],
		"Lists register values.",
		[ "[NAME]" ],
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
	// Shell
	//
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
debug { // Crash command
	static immutable(command2_t) ucommand_crash = {
		[ "crash" ],
		null,
		[],
		null, null,
		[],
		&command_crash
	};
	
	if (strcmp(ucommand, ucommand_crash.names[0].ptr) == 0)
		return &ucommand_crash;
} // debug
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

int shell_proc_spawn(const(char) *exec, const(char) **argv) {
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
	dis = adbg_dis_open(adbg_process_get_machine(process));
	if (dis == null)
		logwarn("Disassembler not available (%s)", adbg_error_message());
	
	return 0;
}

int shell_proc_attach(int pid) {
	// Save for restart
	opt_pid = pid;
	
	// Attach to process
	process = adbg_debugger_attach(pid, 0);
	if (process == null) {
		return ShellError.alicedbg;
	}
	
	puts("Debugger attached.");
	
	// Open disassembler for process machine type
	dis = adbg_dis_open(adbg_process_get_machine(process));
	if (dis) {
		if (opt_syntax)
			adbg_dis_options(dis, AdbgDisOpt.syntax, opt_syntax, 0);
	} else {
		printf("warning: Disassembler not available (%s)\n",
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
			print_adbg_error();
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
			printf(" %s", op.operands);
		
		// Terminate line
		putchar('\n');
		
		address += op.size;
	}
}

void shell_event_exception(adbg_process_t *proc, int event, void* evdata) {
	if (event != AdbgEvent.exception)
		return;
	
	adbg_exception_t *ex = cast(adbg_exception_t*)evdata;
	
	printf("*	Process %d (thread %d) stopped\n"~
		"	Reason  : %s ("~ADBG_OS_ERROR_FORMAT~")\n",
		ex.pid, ex.tid,
		adbg_exception_name(ex), ex.oscode);
	
	if (ex.faultz) {
		printf("	Address : 0x%llx\n", ex.fault_address);
		
		if (dis) {
			printf("	Machine :");
			
			// Print machine bytes
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
		}
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
		if (command == null) {
			return ShellError.invalidParameter;
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
		
		printf("  %.*s %s\n", PADDING - p, liner, cmd.description.ptr);
	}
	
	return 0;
}

int command_spawn(int argc, const(char) **argv) {
	if (argc < 2)
		return ShellError.missingArgument;
	
	// Assume argv is null-terminated
	return shell_proc_spawn(argv[1], argv + 2);
}

int command_attach(int argc, const(char) **argv) {
	if (argc < 2)
		return ShellError.invalidParameter;
	
	return shell_proc_attach(atoi(argv[1]));
}

int command_detach(int argc, const(char) **argv) {
	if (adbg_debugger_detach(process)) {
		return ShellError.alicedbg;
	}
	adbg_dis_close(dis);
	free(registers);
	
	return 0;
}

int command_restart(int argc, const(char) **argv) {
	int e;
	
	switch (process.creation) with (AdbgCreation) {
	case spawned:
		// Terminate first, ignore on error (e.g., already gone)
		adbg_debugger_terminate(process);
		
		// Spawn, shell still messages status
		e = shell_proc_spawn(last_spawn_exec, last_spawn_argv);
		break;
	case attached:
		// Detach first, ignore on error (e.g., already detached)
		adbg_debugger_detach(process);
		
		// Attach, shell still messages status
		e = shell_proc_attach(opt_pid);
		break;
	default:
		return ShellError.unattached;
	}
	
	return e;
}

int command_go(int argc, const(char) **argv) {
	if (adbg_debugger_continue(process))
		return ShellError.alicedbg;
	if (adbg_debugger_wait(process, &shell_event_exception))
		return ShellError.alicedbg;
	// Temporary: Cheap hack for process exit
	if (adbg_process_status(process) == AdbgProcStatus.unloaded)
		printf("*\tProcess %d exited\n", process.pid);
	return 0;
}

int command_kill(int argc, const(char) **argv) {
	if (adbg_debugger_terminate(process))
		return ShellError.alicedbg;
	puts("Process killed");
	adbg_dis_close(dis);
	free(registers);
	return 0;
}

// NOTE: Can't simply execute stepi multiple times in a row
int command_stepi(int argc, const(char) **argv) {
	if (adbg_debugger_stepi(process))
		return ShellError.alicedbg;
	if (adbg_debugger_wait(process, &shell_event_exception))
		return ShellError.alicedbg;
	return 0;
}

int command_regs(int argc, const(char) **argv) {
	if (process == null)
		return ShellError.pauseRequired;
	
	if (registers == null) {
		registers = adbg_registers_new(adbg_process_get_machine(process));
		if (registers == null)
			return ShellError.alicedbg;
	}
	
	adbg_registers_fill(registers, process);
	
	if (registers.count == 0) {
		logerror("No registers available");
		return ShellError.unavailable;
	}
	
	adbg_register_t *reg = registers.items.ptr;
	const(char) *rselect = argc >= 2 ? argv[1] : null;
	bool found;
	for (size_t i; i < registers.count; ++i, ++reg) {
		bool show = rselect == null || strcmp(rselect, reg.info.name) == 0;
		if (show == false) continue;
		char[20] normal = void, hexdec = void;
		adbg_register_format(normal.ptr, 20, reg, AdbgRegFormat.dec);
		adbg_register_format(hexdec.ptr, 20, reg, AdbgRegFormat.hexPadded);
		printf("%-8s  0x%8s  %s\n", reg.info.name, hexdec.ptr, normal.ptr);
		found = true;
	}
	if (rselect && found == false) {
		logerror("Register not found");
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
	
	long uaddress = void;
	if (argc > 1) { // Address given
		if (unformat64(&uaddress, argv[1]))
			return ShellError.unformat;
	} else { // Address not given, get PC/eIP value
		//TODO: dedicated function to get PC/IP/EIP/RIP value
		// HACK: register list should be allocated on-demand in global space
		AdbgMachine mach = adbg_process_get_machine(process);
		adbg_registers_t regs = void;
		//if (adbg_registers_config(&regs, ))
		//	return ShellError.alicedbg;
		if (adbg_registers_fill(&regs, process))
			return ShellError.alicedbg;
		// Assume EIP/RIP is in regs[0]
		switch (mach) with (AdbgMachine) {
		case x86:   uaddress = regs.items[0].u32; break;
		case amd64: uaddress = regs.items[0].u64; break;
		default:    return ShellError.unavailable;
		}
	}
	
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

int command_plist(int argc, const(char) **argv) {
	// Disabled until adbg_process_get_name works on Windows
version (UseNewProcessName) {
	size_t count = void;
	int *plist = adbg_process_list(&count, 0);
	if (plist == null)
		return ShellError.alicedbg;
	
	enum BUFFERSIZE = 2048;
	char[BUFFERSIZE] buffer = void;
	
	version (Trace)
		trace("count=%zd", count);
	
	puts("PID         Name");
	foreach (int pid; plist[0..count]) {
		printf("%10d  ", pid);
		if (adbg_process_get_name(pid, buffer.ptr, BUFFERSIZE, true)) {
			puts(buffer.ptr);
			continue;
		}
		if (adbg_process_get_name(pid, buffer.ptr, BUFFERSIZE, false)) {
			puts(buffer.ptr);
			continue;
		}
		version (Trace)
			trace("error: %s", adbg_error_message());
		putchar('\n');
	}
	
	free(plist);
} else {
	adbg_process_list_t list = void;
	if (adbg_process_enumerate(&list, 0)) {
		return ShellError.alicedbg;
	}
	
	puts("PID         Name");
	foreach (adbg_process_t proc; list.processes[0..list.count]) {
		printf("%10d  %s\n", proc.pid, proc.name.ptr);
	}
}
	
	return 0;
}

int command_quit(int argc, const(char) **argv) {
	//TODO: Quit confirmation if debuggee is alive
	//      could do with optional "forced yes" type of optional
	exit(0);
	return 0;
}