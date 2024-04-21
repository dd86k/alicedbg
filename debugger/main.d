/// Command line interface.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module main;

import adbg.platform;
import adbg.include.c.stdlib : exit;
import adbg.debugger.exception : adbg_exception_t, adbg_exception_name;
import adbg.self;
import adbg.machines : adbg_machine_default;
import adbg.disassembler;
import adbg.error;
import adbg.debugger.process;
import core.stdc.stdlib : strtol, EXIT_SUCCESS, EXIT_FAILURE;
import core.stdc.stdio;
import debugger, shell;
import common.cli;
import common.utils : unformat64;

private:

immutable option_t[] options = [
	// secrets
	option_t(0,   "meow",	"Meow and exit", &cli_meow),
	// common options
	option_arch,
	option_syntax,
	// debugger options
	option_t(0,   "args",   "Debugger: Supply arguments to executable", &cli_args),
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
// ANCHOR --args/--
//

int cli_args_stop(int argi, int argc, const(char) **argv) { // --
	import adbg.utils.strings : adbg_util_move;
	
	//TODO: Allocate pointer buffer instead using calloc
	
	enum MAX = 16;
	__gshared const(char) *[MAX] args;
	
	opt_file_argv = cast(const(char)**)args;
	
	int left = argc - argi; /// to move
	void **s = cast(void**)(argv+argi);
	
	int m = adbg_util_move(
		cast(void**)&opt_file_argv, MAX,
		cast(void**)&s, left);
	
	debug assert(m == left, "cli_argsdd: 'adbg_util_move' Failed due to small buffer");
	
	return EXIT_SUCCESS;
}
int cli_args(const(char) *val) { // --args
	import adbg.utils.strings : adbg_util_expand;
	
	int argc = void;
	char **argv = adbg_util_expand(val, &argc);
	
	if (argc == 0)
		return EXIT_FAILURE;
	
	opt_file_argv = cast(const(char)**)argv;
	return EXIT_SUCCESS;
}

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
	"    alicedbg --attach PID [OPTIONS...]\n"~
	"  Show information page and exit:\n"~
	"    alicedbg {-h|--help|--version|--ver|--license}\n"~
	"\n"~
	"OPTIONS"
	);
	getoptprinter(options, NUMBER_OF_SECRETS);
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
void crash_handler(adbg_exception_t *ex) {
	scope(exit) exit(ex.oscode);
	
	adbg_process_t *self = adbg_self_process();
	
	puts(
r"
   _ _ _   _ _ _       _ _       _ _ _   _     _   _
 _|_|_|_| |_|_|_|_   _|_|_|_   _|_|_|_| |_|   |_| |_|
|_|       |_|_ _|_| |_|_ _|_| |_|_ _    |_|_ _|_| |_|
|_|       |_|_|_|_  |_|_|_|_|   |_|_|_  |_|_|_|_| |_|
|_|_ _ _  |_|   |_| |_|   |_|  _ _ _|_| |_|   |_|  _
  |_|_|_| |_|   |_| |_|   |_| |_|_|_|   |_|   |_| |_|
"
	);
	
	printf(
	"Exception  : %s\n"~
	"PID        : %d\n",
	adbg_exception_name(ex), cast(int)self.pid); // casting is temp
	
	// Fault address & disasm if available
	if (ex.faultz) {
		printf("Address    : %#zx\n", ex.faultz);
		
		adbg_opcode_t op = void;
		adbg_disassembler_t *dis = adbg_dis_open(adbg_machine_default());
		printf("Instruction:");
		if (dis && adbg_dis_process_once(dis, &op, self, ex.fault_address) == 0) {
			// Print address
			// Print machine bytes
			for (size_t bi; bi < op.size; ++bi)
				printf(" %02x", op.machine[bi]);
			// 
			printf(" (%s", op.mnemonic);
			if (op.operands)
				printf(" %s", op.operands);
			// 
			puts(")");
		} else {
			printf(" Disassembly unavailable (%s)\n", adbg_error_msg());
		}
	}
}

extern (C)
int main(int argc, const(char)** argv) {
	// Set crash handle, and ignore on error
	// Could do a warning, but it might be a little confusing
	adbg_self_set_crashhandler(&crash_handler);
	
	if (getopt(argc, argv, options) < 0) {
		puts(getopterrstring());
		return EXIT_FAILURE;
	}
	
	if (getoptremcnt() < 1) {
		puts("error: No file specified");
		return EXIT_FAILURE;
	}
	
	const(char)** args = getoptrem();
	
	return shell_loop(*args);
}
