/// Command shell and interface to debugger.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module shell;

import adbg.include.c.stdio : printf, puts, putchar;
import adbg.include.c.stdlib : atoi, malloc, free, exit;
import core.stdc.string : strcmp, strncmp;
import common, utils;
import term, adbg;

//TODO: Consider client.d with common actions

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
		if (adbg_spawn(&process, globals.file, 0))
			return oops;
		puts("Process created.");
	
		if (adbg_dasm_openproc(&dasm, &process)) {
			dasm_available = false;
			printf("warning: Disassembler not available (%s)\n",
				adbg_error_msg());
		} else dasm_available = true;
	}
	
	term_init;

LOOP:
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
	goto LOOP;
}

int shell_exec(const(char) *command) {
	import adbg.utils.string : adbg_util_expand;
	if (command == null) return 0;
	int argc = void;
	char** argv = adbg_util_expand(command, &argc);
	return shell_execv(argc, cast(const(char)**)argv);
}

int shell_execv(int argc, const(char) **argv) {
	if (argc <= 0 || argv == null)
		return 0;
	
	const(char) *ucommand = argv[0];
	immutable(command_t) *command = shell_findcommand(ucommand);
	if (command == null) {
		serror("unknown command: '%s'", ucommand);
		return ShellError.invalidCommand;
	}
	
	return command.entry(argc, argv);
}

private:

__gshared adbg_process_t process;
__gshared adbg_disassembler_t dasm;

__gshared bool dasm_available;
__gshared const(char) *last_spawn;
__gshared const(char) **last_spawn_argv;

__gshared void function(const(char)* sev, const(char)* msg) userlog;

void serror(const(char) *fmt, ...) {
	if (userlog == null) return;
	
}
void slog(const(char) *msg) {
	if (userlog == null) return;
	
}

immutable string RCFILE = ".alicedbgrc";

immutable string MOD_SHELL = "Shell";
immutable string MOD_DEBUGGER = "Debugger";
immutable string MOD_DISASSEMBLER = "Disassembler";
immutable string MOD_OBJECTSERVER = "Object Server";

immutable string CAT_SHELL = "Command-line";
immutable string CAT_PROCESS = "Process management";
immutable string CAT_CONTEXT = "Thread context management";
immutable string CAT_MEMORY = "Memory management";
immutable string CAT_EXCEPTION = "Exception management";

immutable string SECTION_NAME = "NAME";
immutable string SECTION_SYNOPSIS = "SYNOPSIS";
immutable string SECTION_DESCRIPTION = "DESCRIPTION";
immutable string SECTION_NOTES = "NOTES";
immutable string SECTION_EXAMPLES = "EXAMPLES";

struct command2_help_section_t {
	string name;
	string text;
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
struct command_t {
	align(2) char alias_;
	string name;
	string[] synopsis;
	command2_help_t help;
	int function(int, const(char)**) entry;
}
// NOTE: Called "commands_list" to avoid conflict with future "command_list" function
//TODO: Commands
// - !: Run [actual] shell commands
// - b|breakpoint: Breakpoint management
// - s|stack: Breakpoint management
// - api: Enable addon or api system
immutable command_t[] commands_list = [
	//
	// Debugger
	//
	{
		0, "status", [],
		{
			MOD_DEBUGGER, CAT_PROCESS,
			"Get debugger status.",
		},
		&command_status,
	},
	{
		0, "spawn", [
			"FILE [ARGS...]"
		],
		{
			MOD_DEBUGGER, CAT_PROCESS,
			"Spawn a new process into debugger.",
		},
		&command_spawn,
	},
	{
		0, "attach", [
			"PID"
		],
		{
			MOD_DEBUGGER, CAT_PROCESS,
			"Attach debugger to live process.",
		},
		&command_attach,
	},
	{
		0, "detach", [],
		{
			MOD_DEBUGGER, CAT_PROCESS,
			"Detach debugger from process.",
		},
		&command_detach,
	},
	{
		0, "restart", [],
		{
			MOD_DEBUGGER, CAT_PROCESS,
			"Spawn a new process into debugger.",
		},
		&command_restart,
	},
	{
		0, "go", [],
		{
			MOD_DEBUGGER, CAT_PROCESS,
			"Continue debugging process."
		},
		&command_go,
	},
	{
		0, "kill", [],
		{
			MOD_DEBUGGER, CAT_PROCESS,
			"Terminate process.",
		},
		&command_kill,
	},
	{
		0, "stepi", [],
		{
			MOD_DEBUGGER, CAT_PROCESS,
			"Perform an instruction step.",
		},
		&command_stepi,
	},
	//
	// Context
	//
	{
		0, "regs", [
			"[NAME]"
		],
		{
			MOD_DEBUGGER, CAT_CONTEXT,
			"Get list of registers and values from process.",
		},
		&command_regs,
	},
	//
	// Memory
	//
	{
		'm', "memory", [
			"ADDRESS [LENGTH=64]"
		],
		{
			MOD_DEBUGGER, CAT_MEMORY,
			"Dump process memory from address.",
		},
		&command_memory,
	},
	{
		0, "maps", [],
		{
			MOD_DEBUGGER, CAT_MEMORY,
			"Show memory mappings for process."
		},
		&command_maps,
	},
	{
		'd', "disassemble", [
			"ADDRESS [COUNT=1]"
		],
		{
			MOD_DEBUGGER, CAT_MEMORY,
			"Disassemble instructions at address.", [
				{
					SECTION_DESCRIPTION,
					"Invoke the disassembler at the address. The debugger "~
					"will read process memory, if able, and will repeat "~
					"the operation COUNT times. By default, it will only "~
					"disassemble one instruction."
				}
			]
		},
		&command_disassemble,
	},
	/*{
		0, "scan", [
			"TYPE VALUE"
		],
		{
			MOD_DEBUGGER, CAT_MEMORY,
			"Scan for value in memory."
		},
		&command_scan,
	},*/
	//
	// Shell
	//
	{
		0, "help", [],
		{
			MOD_SHELL, CAT_SHELL,
			"Show help article.", [
				{
					SECTION_DESCRIPTION,
					""
				}
			]
		},
		&command_help,
	},
	{
		'q', "quit", [],
		{
			MOD_SHELL, CAT_SHELL,
			"Quit debugger."
		},
		&command_quit,
	},
];

immutable(command_t)* shell_findcommand(const(char) *ucommand) {
	bool aonly = ucommand[1] == 0; /// Alias-only
	
	// NOTE: Can't use foreach for local var escape
	for (size_t i; i < commands_list.length; ++i) {
		immutable(command_t) *cmd = &commands_list[i];
		
		if ((aonly && ucommand[0] == cmd.alias_) ||
			strncmp(ucommand, cmd.name.ptr, cmd.name.length) == 0)
			return cmd;
	}
	
	return null;
}

void shell_disasm(size_t address, int count = 1) {
	enum BUFSIZE = 16;
	
	if (dasm_available == false)
		return;
	
	for (int i; i < count; ++i) {
		ubyte[BUFSIZE] data = void;
		if (adbg_memory_read(&process, address, data.ptr, BUFSIZE)) {
			oops;
			return;
		}
		adbg_opcode_t op = void;
		if (adbg_dasm_once(&dasm, &op, data.ptr, BUFSIZE))
			printf("(error:%s)\n", adbg_error_msg);
		else
			printf("%s %s\n", op.mnemonic, op.operands);
		address += op.size;
	}
}

void shell_exception(adbg_exception_t *ex) {
	printf("*	Process %d thread %d stopped\n"~
		"	Reason: %s ("~ADBG_OS_ERROR_FORMAT~")\n",
		ex.pid, ex.tid,
		adbg_exception_name(ex), ex.oscode);
	
	if (ex.faultz) {
		// NOTE: size_t stuff on Windows works with %Ix,
		//       so for now, print full.
		printf("	Fault address: %llx\n", ex.fault_address);
		printf("	Faulting instruction: ");
		shell_disasm(ex.faultz);
	}
}

void shell_help(immutable(command_t) *command) {
	with (command.help)
		printf("%s - %s: %s\n", module_.ptr, category.ptr, command.name.ptr);
	
	printf("\n%s\n", SECTION_NAME.ptr);
	printf("  %s - %s\n", command.name.ptr, command.help.description.ptr);
	
	if (command.synopsis.length) {
		printf("\n%s\n", SECTION_SYNOPSIS.ptr);
		foreach (s; command.synopsis) {
			printf("  %s %s\n", command.name.ptr, s.ptr);
		}
	}
	
	enum COL = 72;
	foreach (section; command.help.sections) {
		printf("\n%s\n", section.name.ptr);
		const(char) *p = section.text.ptr;
	L_PRINT:
		int o = printf("  %.*s\n", COL, p);
		if (o < COL)
			continue;
		p += COL;
		goto L_PRINT;
	}
}

int command_status(int argc, const(char) **argv) {
	AdbgStatus state = adbg_status(&process);
	const(char) *m = void;
	switch (state) with (AdbgStatus) {
	case unloaded:	m = "unloaded"; break;
	case standby:	m = "standby"; break;
	case running:	m = "running"; break;
	case paused:	m = "paused"; break;
	default:	m = "(unknown)";
	}
	puts(m);
	return 0;
}

int command_help(int argc, const(char) **argv) {
	if (argc > 1) { // Requesting help article for command
		const(char) *ucommand = argv[1];
		immutable(command_t) *command = shell_findcommand(ucommand);
		if (command == null) {
			serror("Command not found: '%s'", ucommand);
			return ShellError.invalidCommand;
		}
		
		shell_help(command);
		return 0;
	}
	
	foreach (cmd; commands_list) {
		if (cmd.alias_)
			printf("%c, %s", cmd.alias_, cmd.name.ptr);
		else
			printf("   %s", cmd.name.ptr);
		
		if (cmd.synopsis.length)
			printf("%s", cmd.synopsis[0].ptr);
		
		putchar('\n');
	}
	
	return 0;
}

int command_spawn(int argc, const(char) **argv) {
	if (argc < 2) {
		serror("Missing file argument.");
		return ShellError.invalidParameter;
	}
	
	last_spawn = argv[1];
	last_spawn_argv = argc > 2 ? argv + 2: null;
	
	if (adbg_spawn(&process, last_spawn,
		AdbgSpawnOpt.argv, last_spawn_argv,
		0)) {
		serror("Could not spawn process.");
		return ShellError.alicedbg;
	}
	if (adbg_dasm_openproc(&dasm, &process)) {
		dasm_available = false;
		printf("warning: Disassembler not available (%s)\n",
			adbg_error_msg());
	} else dasm_available = true;
	
	return 0;
}

int command_attach(int argc, const(char) **argv) {
	if (argc < 2) {
		serror("Missing pid argument");
		return ShellError.invalidParameter;
	}
	
	int pid = atoi(argv[1]);
	if (adbg_attach(&process, pid, 0)) {
		serror("Could not attach to process.");
		return ShellError.alicedbg;
	}
	if (adbg_dasm_openproc(&dasm, &process)) {
		dasm_available = false;
		printf("warning: Disassembler not available (%s)\n",
			adbg_error_msg());
	} else dasm_available = true;
	
	return 0;
}

int command_detach(int argc, const(char) **argv) {
	if (adbg_detach(&process)) {
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
		int pid = adbg_process_pid(&process);
		if (adbg_detach(&process)) {
			serror("Could not detach process.");
			return ShellError.alicedbg;
		}
		if (adbg_attach(&process, pid)) {
			serror("Could not attach process.");
			return ShellError.alicedbg;
		}
		if (dasm_available)
			adbg_dasm_close(&dasm);
		if (adbg_dasm_openproc(&dasm, &process)) {
			dasm_available = false;
			printf("warning: Disassembler not available (%s)\n",
				adbg_error_msg());
		} else dasm_available = true;
		break;
	case spawned:
		if (adbg_terminate(&process)) {
			serror("Could not terminate process.");
			return ShellError.alicedbg;
		}
		if (adbg_spawn(&process, last_spawn,
			AdbgSpawnOpt.argv, last_spawn_argv,
			0)) {
			serror("Could not spawn process.");
			return ShellError.alicedbg;
		}
		if (dasm_available)
			adbg_dasm_close(&dasm);
		if (adbg_dasm_openproc(&dasm, &process)) {
			dasm_available = false;
			printf("warning: Disassembler not available (%s)\n",
				adbg_error_msg());
		} else dasm_available = true;
		break;
	default:
		serror("No process attached or spawned.");
		return 0;
	}
	
	return 0;
}

int command_go(int argc, const(char) **argv) {
	if (adbg_continue(&process))
		return ShellError.alicedbg;
	if (adbg_wait(&process, &shell_exception))
		return ShellError.alicedbg;
	// Temporary: Cheap hack for process exit
	if (adbg_status(&process) == AdbgStatus.unloaded)
		printf("*\tProcess %d exited\n", process.pid);
	return 0;
}

int command_kill(int argc, const(char) **argv) {
	if (adbg_terminate(&process))
		return ShellError.alicedbg;
	return 0;
}

int command_stepi(int argc, const(char) **argv) {
	if (adbg_stepi(&process))
		return ShellError.alicedbg;
	if (adbg_wait(&process, &shell_exception))
		return ShellError.alicedbg;
	return 0;
}

int command_regs(int argc, const(char) **argv) {
	adbg_thread_context_t *context = adbg_context_easy(&process);
	
	if (context == null)
		return ShellError.alicedbg;
	if (context.count == 0) {
		serror("No registers available");
		return ShellError.unavailable;
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
	
	if (adbg_memory_maps(&process, &mmaps, &mcount, 0)) {
		return ShellError.alicedbg;
	}
	for (size_t i; i < mcount; ++i) {
		adbg_memory_map_t *map = &mmaps[i];
		with (map) printf("%8p %10lld %s\n", base, size, name.ptr);
	}
	if (mcount) free(mmaps);
	
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
	
	shell_disasm(cast(size_t)uaddress, ucount);
	return 0;
}

int command_quit(int argc, const(char) **argv) {
	//TODO: Quit confirmation if debuggee is alive
	//      could do with optional "forced yes" type of optional
	exit(0);
	return 0;
}