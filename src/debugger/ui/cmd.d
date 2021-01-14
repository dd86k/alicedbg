/**
 * Command interpreter.
 *
 * License: BSD 3-clause
 */
module debugger.ui.cmd;

import core.stdc.stdio;
import core.stdc.stdlib;
import core.stdc.string;
import adbg.debugger.debugger;
import adbg.debugger.exception : exception_t;
import adbg.sys.term;
import adbg.utils.str;
import debugger.common;

extern (C):
__gshared:

/// Enter the command-line loop
/// Returns: Error code
int adbg_ui_cmd() {
	adbg_event_exception(&adbg_ui_cmd_handler);
	adbg_term_init;
	char *buffer = cast(char*)malloc(1024);
	if (buffer == null)
		return 2;
	return adbg_ui_cmd_loop(buffer);
}

int adbg_ui_cmd_exec(char *command) {
	return adbg_ui_cmd_execl(command, strlen(command));
}
int adbg_ui_cmd_execl(char *command, size_t len) {
	char*[8] argv = void;
	int argc = adbg_util_argv_expand(command, len, cast(char**)argv);
	return adbg_ui_cmd_execv(argc, cast(const(char)**)argv);
}

private:

int adbg_ui_cmd_loop(char *buffer) {
	int err;
L_LINE:
	adbg_ui_cmd_prompt(err);
	size_t l = adbg_term_readline(buffer, 1024);
	err = adbg_ui_cmd_execl(buffer, l);
	if (err == -1) return 0;
	goto L_LINE;
}

// NOTE: Negative error codes have special meaning

enum CmdReturn {
	OK,
	UnknownCommand = -1,
	MissingArgument = -2,
	ActionContinue = AdbgAction.proceed,
	ActionExit = AdbgAction.exit,
	ActionStepInstruction = AdbgAction.step,
}

void adbg_ui_cmd_prompt(int err) {
	import adbg.sys.err : ERR_FMT;
	enum fmt = "["~ERR_FMT~" adbg] ";
	printf(fmt, err);
}

int adbg_ui_cmd_execv(int argc, const(char) **argv) {
	if (argc <= 0 || argv == null)
		return -1;
	const(char)  *c = argv[0]; // command
	char          a = c[0];    // alias
	foreach (ref command_t comm; commands) {
		if (comm.alt)
		if (a == comm.alt) {
			return comm.func(argc, argv);
		}
		
		if (strcmp(c, comm.opt) == 0) {
			return comm.func(argc, argv);
		}
	}
	return CmdReturn.UnknownCommand;
}

struct command_t {
	align(4) char alt;	/// short option
	immutable(char) *opt;	/// long option
	immutable(char) *desc;	/// help description
	int function(int, const(char)**) func;
}

command_t[] commands = [
	{ 'T', "test", "test command", &adbg_ui_cmd_c_test },
	{ 'f', "file", "Load file", &adbg_ui_cmd_c_file },
//	{ 'p', "pid",  "Attach to pid", &adbg_ui_cmd_c_pid },
//	{ 'p', "pause",  "Run debugger", &adbg_ui_cmd_c_run },
	{ 'c', "continue",  "Debugger: Continue", &adbg_ui_cmd_c_run },
	{ 'S', "step",  "Debugger: Instruction step", &adbg_ui_cmd_c_run },
	{ 'r', "run",  "Run debugger", &adbg_ui_cmd_c_run },
	{ 'h', "help", "Shows this help screen", &adbg_ui_cmd_c_help },
	{ 'q', "quit", "Quit", &adbg_ui_cmd_c_quit },
];

int adbg_ui_cmd_c_test(int argc, const(char) **argv) {
	for (int i; i < argc; ++i) {
		printf("argv[%d]: %s\n", i, argv[i]);
	}
	return 0;
}

int adbg_ui_cmd_c_file(int argc, const(char) **argv) {
	if (argc < 2) {
		puts("missing file");
		return CmdReturn.MissingArgument;
	}
	
	return CmdReturn.OK;
}

int adbg_ui_cmd_c_help(int argc, const(char) **argv) {
	foreach (ref command_t comm; commands) {
		if (comm.alt)
			printf("%c, %-12s %s\n", comm.alt, comm.opt, comm.desc);
		else
			printf("%-15s %s\n", comm.opt, comm.desc);
	}
	return CmdReturn.OK;
}

int adbg_ui_cmd_c_run(int argc, const(char) **argv) {
	return CmdReturn.OK;
}

int adbg_ui_cmd_c_quit(int argc, const(char) **argv) {
	//TODO: Quit confirmation if debuggee is alive
	exit(0);
	return CmdReturn.OK;
}

int adbg_ui_cmd_handler(exception_t *ex) {
	memcpy(&g_lastexception, ex, exception_t.sizeof);
	
	return 0;
}
