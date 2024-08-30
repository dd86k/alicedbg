/// Command line interface.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module main;

import adbg.include.c.stdlib : exit;
import adbg.self;
import adbg.error;
import core.stdc.stdlib : strtol, EXIT_SUCCESS, EXIT_FAILURE;
import core.stdc.stdio;
import shell;
import common.errormgmt;
import common.cli;
import common.utils : unformat64;

private:

immutable option_t[] options = [
	// secrets
	option_t(0,   "meow",	null, &cli_meow),
	// common options
	option_arch,
	option_syntax,
	// debugger options
//	option_t('E', "env",    "Debugger: Supply environment variables to executable", &cli_env),
	option_t('p', "attach", "Debugger: Attach to Process ID", &cli_pid),
	// pages
	option_t('h', "help",	"Show this help screen and exit", &cli_help),
	option_version,
	option_build_info,
	option_ver,
	option_license,
];
enum NUMBER_OF_SECRETS = 1;

//
// ANCHOR -E, --env
//

/*int cli_env(const(char) *val) {
	import adbg.utils.strings : adbg_util_env;
	
	globals.env = cast(const(char)**)adbg_util_env(val);
	
	if (globals.env == null) {
		printf("main: Parsing environment failed");
		return EXIT_FAILURE;
	}
	
	return EXIT_SUCCESS;
}*/

//
// ANCHOR --attach
//

int cli_pid(const(char) *val) {
	opt_pid = cast(ushort)strtol(val, null, 10);
	return EXIT_SUCCESS;
}

//
// ANCHOR --help
//

int cli_help() {
	puts(
	"alicedbg: Aiming to be a simple debugger.\n"~
	"\n"~
	"USAGE\n"~
	"  Spawn new process to debug:\n"~
	"    alicedbg FILE [OPTIONS...]\n"~
	"  Attach debugger to existing process:\n"~
	"    alicedbg --attach=PID [OPTIONS...]\n"~
	"  Show information page and exit:\n"~
	"    alicedbg {-h|--help|--version|--ver|--license}\n"~
	"\n"~
	"OPTIONS"
	);
	getoptprinter(options[NUMBER_OF_SECRETS..$]);
	puts("\nFor a list of values, for example a list of platforms, type '-a help'");
	exit(0);
	return 0;
}

// --meow: Secret
int cli_meow() {
	puts(
`
+-------------------+
| I hate x86, meow. |
+--. .--------------+
    \|  A_A
       (-.-)
       /   \    _
      /     \__/
      \_||__/
`
	);
	exit(0);
	return 0;
}

extern (C)
int main(int argc, const(char)** argv) {
	// Set crash handle, and ignore on error
	// Could do a warning, but it might be a little confusing
	adbg_self_set_crashhandler(&crashed);
	
	int cnt = getoptions(argc, argv, options);
	if (cnt < 0) {
		puts(getopterror());
		return EXIT_FAILURE;
	}
	
	return shell_start(cnt, getoptleftovers());
}
