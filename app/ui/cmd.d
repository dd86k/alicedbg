/**
 * Command interpreter.
 *
 * License: BSD-3-Clause
 */
module ui.cmd;

import adbg.etc.c.stdio;
import adbg.dbg.debugger;
import adbg.dbg.exception;
import adbg.sys.err;
import adbg.utils.str;
import core.stdc.string;
import term;
import core.stdc.stdlib;
import common;

extern (C):
__gshared:

private bool continue_; /// if user wants to continue
private bool paused;	/// if debuggee is paused

/// Enter the command-line loop
/// Returns: Error code
int cmd() {
	term_init;
	return cmd_loop;
}

//TODO: adbg_ui_cmd_file -- read (commands) from file

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

private:

int cmd_loop() {
	char* line = void;
	int llen = void;
	int err;
	continue_ = true;
	
	while (continue_) {
		cmd_prompt(err); // print prompt
		line = term_readline(&llen); // read line
		
		//TODO: remove once term gets key events
		if (line == null) return 0;
		
		err = cmd_execl(line, llen); // execute line
		if (err > 1)
			printf("%s\n", adbg_sys_error(err));
	}
	
	return err;
}

void cmd_prompt(int err) { // [code*adbg]
	enum fmt = "[%d%cadbg] ";
	printf(fmt, err, paused ? '*' : ' ');
}

int cmd_execv(int argc, const(char) **argv) {
	if (argc <= 0 || argv == null)
		return 0;
	
	foreach (comm; commands)
		if (strcmp(argv[0], comm.opt) == 0)
			return comm.func(argc, argv);
	
	printf("unknown command: %s\n", argv[0]);
	
	return 1;
}

int cmd_action(const(char) *a) {
	foreach (action; actions) {
		if (strcmp(a, action.opt) == 0)
			return action.val;
	}
	
	return -1;
}

struct command_t {
	const(char) *opt;	/// command string
	const(char) *argf;	/// Argument formatting when displaying help
	const(char) *desc;	/// help description
	int function(int, const(char)**) func; /// function impl.
}
immutable command_t[] commands = [
	{ "load",   "FILE [ARG...]", "Load executable file into the debugger", &cmd_c_load },
//	{ "core",   null, "Load core debugging object into debugger", &cmd_c_load },
//	{ "attach", null, "Attach the debugger to pid", &cmd_c_pid },
//	{ "b",      null, "Manage breakpoints", & },
//	{ "d",      null, "Disassemble address", & },
	{ "run",    null, "Run debugger", &cmd_c_run },
	{ "status", null, "Show current state", &cmd_c_status },
	{ "r",      null, "Show debuggee registers", &cmd_c_r },
	{ "help",   null, "Show this help screen", &cmd_c_help },
	{ "quit",   null, "Quit", &cmd_c_quit },
	{ "q",      null, "Alias to quit", &cmd_c_quit },
];

struct action_t {
	immutable(char) *opt;	/// long option
	immutable(char) *desc;	/// help description
	AdbgAction val;	/// action value
}
immutable action_t[] actions = [
	{ "continue", "Resume debuggee", AdbgAction.proceed },
	{ "c",        "Alias to continue", AdbgAction.proceed },
	{ "close",    "Close debuggee process", AdbgAction.exit },
	{ "step",     "Step: Instruction", AdbgAction.step },
];

immutable const(char) *cmd_fmt  = " %-30s %s\n";

int cmd_c_load(int argc, const(char) **argv) {
	if (argc < 2) {
		puts("missing file argument");
		return 1;
	}
	
	//TODO: cmd argv handling
	
	int e = adbg_load(argv[1]);
	if (e) printerror;
	return e;
}

int cmd_c_status(int argc, const(char) **argv) {
	AdbgState s = adbg_state;
	const(char) *st = void;
	switch (s) {
	case AdbgState.idle:	st = "idle"; break;
	case AdbgState.loaded:	st = "loaded"; break;
	case AdbgState.running:	st = "running"; break;
	case AdbgState.paused:	st = "paused"; break;
	default:	st = "unknown";
	}
	printf(
	"state: (%d) %s\n"~
	"exception: ("~SYS_ERR_FMT~") %s\n",
	s, st,
	common_exception.oscode, adbg_exception_string(common_exception.type)
	);
	return 0;
}

int cmd_c_r(int argc, const(char) **argv) {
	int m = common_exception.registers.count;
	register_t *r = common_exception.registers.items.ptr;
	for (size_t i; i < m; ++i, ++r)
		printf("%-8s  0x%8s  %s\n",
			r.name,
			adbg_ctx_reg_hex(r),
			adbg_ctx_reg_val(r));
	return 0;
}

int cmd_c_help(int argc, const(char) **argv) {
	puts("Debugger commands:");
	foreach (comm; commands) {
		printf(cmd_fmt, comm.opt, comm.desc);
		
	}
	
	puts("\nWhen debuggee is paused:");
	foreach (action; actions)
		printf(cmd_fmt, action.opt, action.desc);
	
	return 0;
}

int cmd_c_run(int argc, const(char) **argv) {
	return adbg_run(&cmd_handler);
}

int cmd_c_quit(int argc, const(char) **argv) {
	continue_ = false;
	//TODO: Quit confirmation if debuggee is alive
	exit(0);
	return 0;
}

int cmd_handler(exception_t *ex) {
	memcpy(&common_exception, ex, exception_t.sizeof);
	
	printf(
	"*	Thread %d stopped for: %s ("~SYS_ERR_FMT~")\n"~
	"	Instruction address: %zx\n",
	ex.tid, adbg_exception_string(ex.type), ex.oscode,
	ex.nextaddrv
	);
	
	if (ex.faultaddr)
		printf("	Fault address: %zx\n", ex.faultaddrv);
	
	int err = ex.oscode;
	int length = void;
	int argc = void;
	paused = true;
	
L_INPUT:
	cmd_prompt(err);
	char* line = term_readline(&length);
	if (line == null) {
		continue_ = false;
		return AdbgAction.exit;
	}
	char** argv = adbg_util_expand(line, &argc);
	
	int a = cmd_action(argv[0]);
	if (a != -1) {
		paused = false;
		return a;
	}
	
	err = cmd_execl(line, length);
	goto L_INPUT;
}
