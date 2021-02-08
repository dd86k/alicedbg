/**
 * Command interpreter.
 *
 * License: BSD-3-Clause
 */
module app.debugger.ui.cmd;

import adbg.etc.c.stdio;
import core.stdc.stdlib;
import core.stdc.string;
import adbg.debugger.debugger;
import adbg.debugger.exception;
import adbg.sys.err;
import adbg.utils.str;
import app.term;
import app.common;

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
	enum fmt = "["~SYS_ERR_FMT~"%cadbg] ";
	printf(fmt, err, paused ? '*' : ' ');
}

int cmd_execv(int argc, const(char) **argv) {
	if (argc <= 0 || argv == null)
		return 0;
	
	const(char) *c = argv[0]; // command
	
	if (c[1] == 0) { // short
		char a = c[0];    // alias
		foreach (comm; commands) {
			if (comm.alt)
			if (a == comm.alt) {
				return comm.func(argc, argv);
			}
		}
	} else { // long
		foreach (comm; commands) {
			if (strcmp(c, comm.opt) == 0) {
				return comm.func(argc, argv);
			}
		}
	}
	
	printf("unknown command: %s\n", c);
	
	return 1;
}

int cmd_action(const(char) *a) {
	size_t l = strlen(a);
	
	if (l < 2) {
		char c = a[0];
		foreach (action; actions) {
			if (action.alt == 0) continue;
			if (c == action.alt)
				return action.val;
		}
	} else {
		foreach (action; actions) {
			if (strcmp(a, action.opt) == 0)
				return action.val;
		}
	}

L_END:
	return -1;
}

struct command_t {
	align(4) char alt;	/// short option
	immutable(char) *opt;	/// long option
	immutable(char) *desc;	/// help description
	int function(int, const(char)**) func;
}

immutable command_t[] commands = [
	{ 'l', "load",   "Load executable file into the debugger", &cmd_c_load },
//	{ 'c', "core",   "Load core debugging object into debugger", &cmd_c_load },
//	{ 'p', "pid",    "Attach the debugger to pid", &cmd_c_pid },
	{ 'r', "run",    "Run debugger", &cmd_c_run },
	{ 's', "status", "Print current state", &cmd_c_status },
	{ 'h', "help",   "Shows this help screen", &cmd_c_help },
	{ 'q', "quit",   "Quit", &cmd_c_quit },
];
struct action_t {
	align(4) char alt;	/// short option
	immutable(char) *opt;	/// long option
	immutable(char) *desc;	/// help description
	AdbgAction val;	/// action value
}
immutable action_t[] actions = [
	{ 'c', "continue", "Continue debuggee", AdbgAction.proceed },
	{ 0,   "close",    "Close debuggee process", AdbgAction.exit },
	{ 's', "step",     "Step: Instruction", AdbgAction.step },
];

int cmd_c_load(int argc, const(char) **argv) {
	if (argc < 2) {
		puts("missing file argument");
		return 1;
	}
	
	//TODO: cmd argv handling
	
	int e = adbg_load(argv[1]);
	if (e)
		adbg_sys_perror!"cmd"(e);
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

int cmd_c_help(int argc, const(char) **argv) {
	puts("Debugger commands:");
	foreach (comm; commands) {
		if (comm.alt)
			printf(" %c, %-12s %s\n", comm.alt, comm.opt, comm.desc);
		else
			printf(" %-15s %s\n", comm.opt, comm.desc);
	}
	puts("Commands when debuggee is paused:");
	foreach (action; actions) {
		if (action.alt)
			printf(" %c, %-12s %s\n", action.alt, action.opt, action.desc);
		else
			printf(" %-15s %s\n", action.opt, action.desc);
	}
	
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
	
	printf("*	Thread %d stopped for: %s\n",
		ex.tid, adbg_exception_string(ex.type));
	
	if (ex.faultaddr)
		printf("\t"~SYS_ERR_FMT~" at %p\n", ex.oscode, ex.faultaddr);
	
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
