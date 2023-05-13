/**
 * Command line interface.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2022 dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module main;

import adbg.platform;
import adbg.dbg : adbg_attach, adbg_load;
import adbg.disassembler;
import adbg.utils.str : adbg_util_hex_array;
import adbg.etc.c.stdlib : exit;
import core.stdc.stdlib : malloc, strtol, EXIT_SUCCESS, EXIT_FAILURE;
import core.stdc.string : strcmp;
import core.stdc.stdio;
import common, ui, dumper, analyzer;

private:
extern (C):

enum COPYRIGHT = "Copyright (c) 2019-2022 dd86k <dd@dax.moe>";

__gshared immutable(char) *page_license =
`BSD 3-Clause License

`~COPYRIGHT~`
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.`;

debug enum FULL_VERSION = ADBG_VERSION~"+"~__BUILDTYPE__;
else  enum FULL_VERSION = ADBG_VERSION;

__gshared immutable(char) *page_version =
"alicedbg "~FULL_VERSION~" (built: "~__TIMESTAMP__~")\n"~
COPYRIGHT~"\n"~
"License: BSD 3-Clause <https://opensource.org/licenses/BSD-3-Clause>\n"~
"Homepage: <https://git.dd86k.space/dd86k/alicedbg>\n"~
"Compiler: "~__VENDOR__~" "~DSTRVER!__VERSION__~"\n"~
"Target: "~TARGET_OBJFMT~" object, "~TARGET_FLTABI~" float\n"~
"Platform: "~TARGET_PLATFORM~"-"~TARGET_OS~"-"~TARGET_ENV~"\n"~
"CRT: "~TARGET_CRT~"\n"~
"CppRT: "~TARGET_CPPRT~"\n"~
"DFlags:"~D_FEATURES;

//NOTE: The CLI module is meh, waiting on some betterC getopt

// if asking for help, so '?' and "help" are accepted
bool wantsHelp(const(char) *query) {
	switch (query[0]) {
	case '?': return true;
	default: return strcmp(query, "help") == 0;
	}
}

struct option_t {
	align(4) char alt;
	immutable(char) *val;
	immutable(char) *desc;
	align(4) bool arg;	/// if it takes an argument
	union {
		extern(C) int function() f;
		extern(C) int function(const(char)*) fa;
	}
}
//TODO: --loop-log for turning the loop UI into an non-interactive session
//TODO: --seh/--no-seh: Enable/disable internal SEH
//TODO: -B/--disasm-base: base address (useful for COM files / org 0x100)
//TODO: -e/--dump-skip: skip N bytes (or do +N)
immutable option_t[] options = [
	// general
	{ 'a', "arch",	"Select architecture for disassembler (default=platform)", true, fa: &cli_march },
	{ 's', "syntax",	"Select disassembler syntax (default=platform)", true, fa: &cli_syntax },
	// debugger
	{ 'f', "file",	"Debugger: Load executable (default parameter)", true, fa: &cli_file },
	{ 0,   "args",	"Debugger: Supply arguments to executable, '--' works too", true, fa: &cli_args },
	{ 'E', "env",	"Debugger: Supply environment variables to executable", true, fa: &cli_env },
	{ 'p', "pid",	"Debugger: Attach to process", true, fa: &cli_pid },
	{ 'U', "ui",	"Debugger: Select debugger user interface (default=cmd)", true, fa: &cli_ui },
	// dumper
	{ 'D', "dump",	"Dumper: Dump an object file", false, &cli_dump },
	{ 'A', "analyze",	"Dumper: Show detailed information about hex string opcode", false, &cli_analyze },
	{ 'R', "raw",	"Dumper: Specify object is raw", false, &cli_raw },
	{ 'S', "show",	"Dumper: Select which part of the object to display (default=h)", true, fa: &cli_show },
//	{ 'l', "length",	"Dumper: ", true, &cli_length },
	// pages
	{ 'h', "help",	"Show this help screen and exit", false, &cli_help },
	{ 0,   "version",	"Show the version screen and exit", false, &cli_version },
	{ 0,   "ver",	"Show the version string and exit", false, &cli_ver },
	{ 0,   "license",	"Show the license page and exit", false, &cli_license },
	// secrets
	{ 0,   "meow",	"Meow and exit", false, &cli_meow },
];
enum NUMBER_OF_SECRETS = 1;

//
// ANCHOR --march
//

int cli_march(const(char) *val) {
	if (wantsHelp(val)) {
		puts("Available machine architectures:");
		foreach (setting_platform_t p; platforms) {
			with (p)
			printf("%8s, %-10s  %s\n", opt, alt, desc);
		}
		exit(0);
	}
	foreach (setting_platform_t p; platforms) {
		if (strcmp(val, p.opt) == 0 || strcmp(val, p.alt) == 0) {
			globals.cli.platform = p.val;
			return EXIT_SUCCESS;
		}
	}
	return EXIT_FAILURE;
}

//
// ANCHOR --syntax
//

int cli_syntax(const(char) *val) {
	if (wantsHelp(val)) {
		puts("Available disassembler syntaxes:");
		foreach (setting_syntax_t syntax; syntaxes) {
			with (syntax)
			printf("%-10s  %s\n", opt, desc);
		}
		exit(0);
	}
	foreach (setting_syntax_t syntax; syntaxes) {
		if (strcmp(val, syntax.opt) == 0) {
			globals.cli.syntax = syntax.val;
			return EXIT_SUCCESS;
		}
	}
	return EXIT_FAILURE;
}

//
// ANCHOR --file
//

int cli_file(const(char) *val) {
	globals.cli.file = val;
	return EXIT_SUCCESS;
}

//
// ANCHOR --args/--
//

int cli_args_stop(int argi, int argc, const(char) **argv) { // --
	import adbg.utils.str : adbg_util_move;
	
	enum MAX = 16;
	__gshared const(char) *[MAX] args;
	
	globals.cli.args = cast(const(char)**)args;
	
	int left = argc - argi; /// to move
	void **s = cast(void**)(argv+argi);
	
	int m = adbg_util_move(
		cast(void**)&globals.cli.args, MAX,
		cast(void**)&s, left);
	
	debug assert(m == left, "cli_argsdd: 'adbg_util_move' Failed due to small buffer");
	
	return EXIT_SUCCESS;
}
int cli_args(const(char) *val) { // --args
	import adbg.utils.str : adbg_util_expand;
	
	int argc = void;
	char **argv = adbg_util_expand(val, &argc);
	
	if (argc == 0)
		return EXIT_FAILURE;
	
	globals.cli.args = cast(const(char)**)argv;
	return EXIT_SUCCESS;
}

//
// ANCHOR -E, --env
//

int cli_env(const(char) *val) {
	import adbg.utils.str : adbg_util_env;
	
	globals.cli.env = cast(const(char)**)adbg_util_env(val);
	
	if (globals.cli.env == null) {
		printf("main: Parsing environment failed");
		return EXIT_FAILURE;
	}
	
	return EXIT_SUCCESS;
}

//
// ANCHOR --pid
//

int cli_pid(const(char) *val) {
	globals.cli.pid = cast(ushort)strtol(val, null, 10);
	return EXIT_SUCCESS;
}

//
// ANCHOR --ui
//

struct setting_ui_t {
	SettingUI val;
	immutable(char)* opt, desc;
}
immutable setting_ui_t[] uis = [
	{ SettingUI.loop,   "loop",   "Simple loop interface (default)" },
	{ SettingUI.cmd,    "cmd",    "(wip) Command-line interface" },
//	{ SettingUI.tui,    "tui",    "(wip) Interractive text user interface" },
//	{ SettingUI.server, "server", "(wip) TCP/IP server" },
];
int cli_ui(const(char)* val) {
	if (wantsHelp(val)) {
		puts("Available UIs:");
		foreach (setting_ui_t ui; uis) {
			printf("%-10s%s\n", ui.opt, ui.desc);
		}
		exit(0);
	}
	foreach (setting_ui_t ui; uis) {
		if (strcmp(val, ui.opt) == 0) {
			globals.cli.ui = ui.val;
			return 0;
		}
	}
	return EXIT_FAILURE;
}

//
// ANCHOR --dump
//

int cli_dump() {
	globals.cli.mode = SettingMode.dump;
	return EXIT_SUCCESS;
}

//
// ANCHOR -A/--analyze
//

int cli_analyze() {
	globals.cli.mode = SettingMode.analyze;
	return EXIT_SUCCESS;
}

//
// ANCHOR --raw
//

int cli_raw() {
	globals.cli.flags |= DumpOpt.raw;
	return EXIT_SUCCESS;
}

//
// ANCHOR --show
//

struct setting_show_t {
	align(4) char opt;	/// option character
	immutable(char) *desc;
	int val;	/// dumper flag
}
immutable setting_show_t[] showflags = [
	{ 'h', "Show header metadata (default)", DumpOpt.header },
	{ 's', "Show sections metadata", DumpOpt.sections },
	{ 'i', "Show imports", DumpOpt.imports },
//	{ 'e', "Show exports", DUMPER_SHOW_EXPORTS },
	{ 'c', "Show load configuration", DumpOpt.loadcfg },
	{ 'r', "Show load configuration", DumpOpt.relocs },
	{ 'p', "Show debug information", DumpOpt.debug_ },
	{ 'd', "Disassemble code (executable sections)", DumpOpt.disasm_code },
	{ 'D', "Disassemble all sections", DumpOpt.disasm_all },
	{ 'S', "Show disassembler statistics instead", DumpOpt.disasm_stats },
	{ 'A', "Show everything", DumpOpt.everything },
];
int cli_show(const(char) *val) {
	if (wantsHelp(val)) {
		puts("Available dumper display options:");
		foreach (setting_show_t show; showflags) {
			printf("%c\t%s\n", show.opt, show.desc);
		}
		exit(0);
	}
L_CHAR:
	char c = *(val++);
	if (c == 0)
		return EXIT_SUCCESS;
	foreach (setting_show_t show; showflags) {
		if (c == show.opt) {
			globals.cli.flags |= show.val;
			goto L_CHAR;
		}
	}
	return EXIT_FAILURE;
}

//
// ANCHOR --help
//

int cli_help() {
	puts(
	"alicedbg - Aiming to be a simple debugger\n"~
	"\n"~
	"USAGE\n"~
	" alicedbg {--pid ID|[--file] FILE|--dump FILE|--analyze HEX} [OPTIONS...]\n"~
	" alicedbg {-h|--help|--version|--license}\n"~
	"\n"~
	"OPTIONS"
	);
	foreach (option_t opt; options[0..$-NUMBER_OF_SECRETS]) {
		if (opt.alt)
			printf(" -%c, --%-11s  %s\n", opt.alt, opt.val, opt.desc);
		else
			printf(" --%-15s  %s\n", opt.val, opt.desc);
	}
	puts("\nFor a list of values, for example a list of platforms, type '-m help'");
	exit(0);
	return 0;
}

//
// ANCHOR --version
//

// Turns a __VERSION__ number into a string constant
template DSTRVER(uint ver) {
	enum DSTRVER =
		cast(char)((ver / 1000) + '0') ~ "." ~
		cast(char)(((ver % 1000) / 100) + '0') ~
		cast(char)(((ver % 100) / 10) + '0') ~
		cast(char)((ver % 10) + '0');
}

int cli_version() {
	import adbg.config : CONFIG_DISASM, AdbgConfigDisasm;
	puts(page_version);
	static if (CONFIG_DISASM == AdbgConfigDisasm.capstone) {
		import adbg.include.capstone : capstone_dyn_init, cs_version;
		if (capstone_dyn_init() == false) {
			int major = void, minor = void;
			cs_version(&major, &minor);
			printf("Capstone: %d.%d\n", major, minor);
		} else {
			puts("Capstone: error");
		}
	}
	exit(0);
	return 0;
}
int cli_ver() {
	puts(ADBG_VERSION);
	exit(0);
	return 0;
}
int cli_license() {
	puts(page_license);
	exit(0);
	return 0;
}

//
// --meow
//

int cli_meow() {
	puts(
`
+------------------+
| I hate x86, meow |
+--+---------------+
   |    A_A
   +-  (-.-)
       /   \    _
      /     \__/
      \_||__/
`
	);
	exit(0);
	return 0;
}

//
// Main
//

//TODO: Support --option=value syntax
//TODO: Support stdin (-) for -A, -D

int main(int argc, const(char)** argv) {
	const(char) *arg = void;
	const(char) *val = void;
	
	//TODO: util in app/ for separating args
	CLI: for (int argi = 1; argi < argc; ++argi) {
		arg = argv[argi];
		
		if (arg[1] == '-') { // Long options
			const(char) *argLong = arg + 2;
			
			// test for "--" (extra args)
			if (argLong[0] == 0) {
				if (cli_args_stop(++argi, argc, argv))
					return EXIT_FAILURE;
				break CLI;
			}
			
			L_LONG: foreach (option_t opt; options) {
				if (strcmp(argLong, opt.val))
					continue L_LONG;
				
				// no argument
				if (opt.arg == false) {
					if (opt.f())
						return EXIT_FAILURE;
					continue CLI;
				}
				
				// with argument
				if (++argi >= argc) {
					printf("main: missing argument for --%s\n", opt.val);
					return EXIT_FAILURE;
				}
				val = argv[argi];
				if (opt.fa(val)) {
					printf("main: '%s' is an invalid value for --%s", val, argLong);
					return EXIT_FAILURE;
				}
				continue CLI;
			}
		} else if (arg[0] == '-') { // Short options
			// test for "-" (stdin)
			char argShort = arg[1];
			if (argShort == 0) { // "-"
				puts("main: standard input not supported");
				return EXIT_FAILURE;
			}
			
			L_SHORT: foreach (option_t opt; options) {
				if (argShort != opt.alt)
					continue L_SHORT;
				
				// no argument
				if (opt.arg == false) {
					if (opt.f())
						return EXIT_FAILURE;
					continue CLI;
				}
				
				// with argument
				if (++argi >= argc) {
					printf("main: missing argument for -%c\n", argShort);
					return EXIT_FAILURE;
				}
				val = argv[argi];
				if (opt.fa(val)) {
					printf("main: '%s' is an invalid value for -%c", val, argShort);
					return EXIT_FAILURE;
				}
				continue CLI;
			}
		} else if (globals.cli.file == null) { // Default option value
			globals.cli.file = arg;
			continue CLI;
		}
		
		printf("main: unknown option '%s'\n", arg);
		return EXIT_FAILURE;
	}
	
	if (adbg_disasm_init())
		return printerror(__FUNCTION__);
	
	with (globals) {
		adbg_disasm_configure(&app.disasm, cli.platform);
		adbg_disasm_opt(&app.disasm, AdbgDisasmOpt.syntax, cli.syntax);
	}
	
	switch (globals.cli.mode) {
	case SettingMode.analyze:
		if (globals.cli.file == null) {
			puts("main: base16 input required");
			return EXIT_FAILURE;
		}
		
		//TODO: Should be allocated?
		with (globals) adbg_util_hex_array(
			cast(ubyte*)app.inputHex, 32, cli.file, app.inputHexSize);
		
		return analyze();
	case SettingMode.dump: return app_dump();
	case SettingMode.debugger:
		// Pre-load target if specified.
		// Necessary for loop UI, but optional for others
		with (globals.cli)
		if (file) {
			if (adbg_load(file, args)) {
				printerror;
				return EXIT_FAILURE;
			}
			
			printf("File '%s' loaded\n", globals.cli.file);
		}
		
		switch (globals.cli.ui) {
		case SettingUI.loop:	return app_loop();
		case SettingUI.cmd:	return app_cmd();
		case SettingUI.tcpserver:
			puts("main: tcp-server not yet supported");
			return EXIT_FAILURE;
		default: assert(0);
		}
	default: assert(0, "Implement SettingMode");
	}
}
