/**
 * Command interpreter.
 *
 * License: BSD 3-clause
 */
module adbg.ui.cmd;

import core.stdc.stdio;
import core.stdc.stdlib;
import core.stdc.string;
import adbg.os.term;
import adbg.utils.str;

// NOTE: Commands is strongly recommended to return an error code higher than 1.

extern (C):
__gshared:

/// Enter the command-line loop
/// Returns: Error code
int adbg_ui_cmd() {
	adbg_term_init;
	char *buffer = cast(char*)malloc(1024);
	int err;
L_LINE:
	adbg_ui_cmd_prompt(err);
	size_t l = adbg_term_readline(buffer, 1024);
	err = adbg_ui_cmd_execl(buffer, l);
	if (err == -1) return 0;
	goto L_LINE;
}

int adbg_ui_cmd_exec(char *command) {
	return adbg_ui_cmd_execl(command, strlen(command));
}
int adbg_ui_cmd_execl(char *command, size_t len) {
	char **argv = void;
	int argc = adbg_util_argv_expand(command, len, argv);
	return adbg_ui_cmd_execv(argc, cast(const(char)**)argv);
}

private:

void adbg_ui_cmd_prompt(int err) {
	import adbg.os.err : ERR_FMT;
	enum fmt = "["~ERR_FMT~", adbg] ";
	printf(fmt, err);
}

int adbg_ui_cmd_execv(int argc, const(char) **argv) {
	if (argc <= 0 || argv == null)
		return 1;
	const(char)  *c = argv[0]; // command
	char          a = c[0];    // alias
	foreach (ref command_t comm; commands) {
		if (comm.alt)
		if (a == comm.alt) {
			return comm.func(argc, argv);
		}
		if (comm.opt)
		if (strcmp(c, comm.opt) == 0) {
			return comm.func(argc, argv);
		}
	}
	return 1;
}

struct command_t {
	align(4) char alt;	/// short option
	immutable(char) *opt;	/// long option
	immutable(char) *desc;	/// help description
	int function(int, const(char)**) func;
}

command_t[] commands = [
	{ 'h', "help", "Shows this help screen", &adbg_ui_cmd_c_help }
];

int adbg_ui_cmd_c_help(int argc, const(char) **argv) {
	foreach (ref command_t comm; commands) {
		if (comm.alt)
			printf("%c, %12s %s\n", comm.alt, comm.opt, comm.desc);
		else
			printf("%15s %s\n", comm.opt, comm.desc);
	}
	return 0;
}

