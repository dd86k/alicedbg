/**
 * Command interpreter.
 *
 * License: BSD-3-Clause
 */
module debugger.ui.cmd;

import core.stdc.stdio;
import core.stdc.stdlib;
import core.stdc.string;
import adbg.debugger.debugger;
import adbg.debugger.exception;
import term;
import adbg.sys.err;
import adbg.utils.str;
import debugger.common;

extern (C):
__gshared:

private bool continue_; /// if user wants to continue

/// Enter the command-line loop
/// Returns: Error code
int cmd() {
	adbg_event_exception(&cmd_handler);
	term_init;
	return cmd_loop();
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
	char*[8] argv = void;
	int argc = adbg_util_argv_expand(command, len, cast(char**)argv);
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

void cmd_prompt(int err) {
	import adbg.sys.err : ERR_FMT;
	enum fmt = "["~ERR_FMT~" adbg] ";
	printf(fmt, err);
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

struct command_t {
	align(4) char alt;	/// short option
	immutable(char) *opt;	/// long option
	immutable(char) *desc;	/// help description
	int function(int, const(char)**) func;
}

immutable command_t[] commands = [
	{ 'f', "file", "Load file", &cmd_c_file },
//	{ 'p', "pid",  "Attach to pid", &cmd_c_pid },
//	{ 'p', "pause",  "Run debugger", & },
//	{ 'c', "continue",  "Debugger: Continue", & },
//	{ 'S', "step",  "Debugger: Instruction step", & },
	{ 'r', "run",  "Run debugger", &cmd_c_run },
	{ 'h', "help", "Shows this help screen", &cmd_c_help },
	{ 'q', "quit", "Quit", &cmd_c_quit },
];

int cmd_c_file(int argc, const(char) **argv) {
	if (argc < 2) {
		puts("missing file");
		return 1;
	}
	
	return adbg_load(argv[1], null, null, null, 0);
}

int cmd_c_help(int argc, const(char) **argv) {
	foreach (comm; commands) {
		if (comm.alt)
			printf("%c, %-12s %s\n", comm.alt, comm.opt, comm.desc);
		else
			printf("%-15s %s\n", comm.opt, comm.desc);
	}
	
	return 0;
}

int cmd_c_run(int argc, const(char) **argv) {
	puts("running...");
	return adbg_run;
}

int cmd_c_quit(int argc, const(char) **argv) {
	continue_ = false;
	//TODO: Quit confirmation if debuggee is alive
	return 0;
}

int cmd_handler(exception_t *ex) {
	memcpy(&g_lastexception, ex, exception_t.sizeof);
	printf("exception: %s\n", adbg_ex_typestr(ex.type));
	
	//TODO: 
	cmd_loop();
	
	return AdbgAction.exit;
}
