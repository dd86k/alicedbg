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
import adbg.debugger.exception : exception_t;
import adbg.sys.term;
import adbg.utils.str;
import debugger.common;

//TODO: adbg_ui_cmd_file -- read commands from file

extern (C):
__gshared:

private enum CLI_BUFFER_SIZE = 1024;
private int debuggerError;

/// Enter the command-line loop
/// Returns: Error code
int adbg_ui_cmd() {
	adbg_event_exception(&adbg_ui_cmd_handler);
	adbg_term_init;
	char *buffer = cast(char*)malloc(CLI_BUFFER_SIZE);
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
L_LINE:
	adbg_ui_cmd_prompt();
	size_t l = adbg_term_readline(buffer, CLI_BUFFER_SIZE);
	int c = adbg_ui_cmd_execl(buffer, l);
	if (c == CmdReturn.exit) return 0;
	goto L_LINE;
}

// NOTE: Negative error codes have special meaning

enum CmdReturn {
	ok,
	unknownCommand,
	missingArgument,
	exit,
	debuggerContinue = AdbgAction.proceed,
	debuggerExit = AdbgAction.exit,
	debuggerStepInstruction = AdbgAction.step,
}

void adbg_ui_cmd_prompt() {
	import adbg.sys.err : ERR_FMT;
	enum fmt = "["~ERR_FMT~" adbg] ";
	printf(fmt, debuggerError);
}

int adbg_ui_cmd_execv(int argc, const(char) **argv) {
	if (argc <= 0 || argv == null)
		return CmdReturn.ok;
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
	return CmdReturn.unknownCommand;
}

struct command_t {
	align(4) char alt;	/// short option
	immutable(char) *opt;	/// long option
	immutable(char) *desc;	/// help description
	int function(int, const(char)**) func;
}

command_t[] commands = [
	{ 'f', "file", "Load file", &adbg_ui_cmd_c_file },
//	{ 'p', "pid",  "Attach to pid", &adbg_ui_cmd_c_pid },
//	{ 'p', "pause",  "Run debugger", &adbg_ui_cmd_c_run },
	{ 'c', "continue",  "Debugger: Continue", &adbg_ui_cmd_c_run },
	{ 'S', "step",  "Debugger: Instruction step", &adbg_ui_cmd_c_run },
	{ 'r', "run",  "Run debugger", &adbg_ui_cmd_c_run },
	{ 'h', "help", "Shows this help screen", &adbg_ui_cmd_c_help },
	{ 'q', "quit", "Quit", &adbg_ui_cmd_c_quit },
];

int adbg_ui_cmd_c_file(int argc, const(char) **argv) {
	if (argc < 2) {
		puts("missing file");
		return CmdReturn.missingArgument;
	}
	
	return (debuggerError = adbg_load(argv[1], null, null, null, 0));
}

int adbg_ui_cmd_c_help(int argc, const(char) **argv) {
	foreach (ref command_t comm; commands) {
		if (comm.alt)
			printf("%c, %-12s %s\n", comm.alt, comm.opt, comm.desc);
		else
			printf("%-15s %s\n", comm.opt, comm.desc);
	}
	
	return CmdReturn.ok;
}

int adbg_ui_cmd_c_run(int argc, const(char) **argv) {
	return CmdReturn.ok;
}

int adbg_ui_cmd_c_quit(int argc, const(char) **argv) {
	//TODO: Quit confirmation if debuggee is alive
	return CmdReturn.exit;
}

int adbg_ui_cmd_handler(exception_t *ex) {
	memcpy(&g_lastexception, ex, exception_t.sizeof);
	
	return 0;
}
