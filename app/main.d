/**
 * Command line interface.
 *
 * License: BSD-3-Clause
 */
module main;

import core.stdc.stdlib : malloc, strtol, exit, EXIT_SUCCESS, EXIT_FAILURE;
import core.stdc.string : strcmp, strncpy, strtok;
import core.stdc.stdio;
import adbg.platform;
import adbg.dbg : adbg_attach, adbg_load;
import adbg.disasm : adbg_disasm_t, AdbgDisasmPlatform, AdbgDisasmSyntax;
import adbg.sys.err : adbg_sys_perror;
import common, dumper, ui;

private:
extern (C):
__gshared:

//TODO: --loop-log for turning the loop UI into an non-interactive session
//TODO: --debug/--no-debug: Disable/enable internal SEH from main

//
// CLI utils
//

// if asking for help, so '?' and "help" are accepted
bool cli_wanthelp(const(char) *query) {
	switch (query[0]) {
	case '?': return true;
	default: return strcmp(query, "help") == 0;
	}
}

//TODO: Consider adding 'bool processed' field
//      Avoids repeating options, may speed-up parsing
//      * Could be an issue for repeatable options (unless another field added..)
//TODO: Consider adding 'bool bundled' field
//      Would allow alt options to be bundled: -DR
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
immutable option_t[] options = [
	// general
	{ 'm', "march",  "Select architecture for disassembler (default=platform)", true, fa: &cli_march },
	{ 's', "syntax", "Select disassembler syntax (default=platform)", true, fa: &cli_syntax },
	// debugger
	{ 'f', "file", "Debugger: Load executable (default parameter)", true, fa: &cli_file },
	{ 0,   "args", "Debugger: Supply arguments to executable, '--' works too", true, fa: &cli_args },
	{ 'E', "env",  "Debugger: Supply environment variables to executable", true, fa: &cli_env },
	{ 'p', "pid",  "Debugger: Attach to process", true, fa: &cli_pid },
	{ 'U', "ui",   "Debugger: Select debugger user interface (default=cmd)", true, fa: &cli_ui },
	// dumper
	{ 'D', "dump", "Dumper: Dump an object file", false, &cli_dump },
	{ 'R', "raw",  "Dumper: Specify object is raw", false, &cli_raw },
	{ 'S', "show", "Dumper: Select which part of the object to display (default=h)", true, fa: &cli_show },
	// pages
	{ 'h', "help",    "Show this help screen and exit", false, &cli_help },
	{ 0,   "version", "Show the version screen and exit", false, &cli_version },
	{ 0,   "ver",     "Show the version string and exit", false, &cli_ver },
	{ 0,   "license", "Show the license page and exit", false, &cli_license },
	// secrets
	{ 0,   "meow",    "Meow and exit", false, &cli_meow },
];
enum NUMBER_OF_SECRETS = 1;

//
// ANCHOR --march
//

int cli_march(const(char) *val) {
	if (cli_wanthelp(val)) {
		puts("Available machine architectures:");
		foreach (setting_platform_t p; platforms) {
			with (p)
			printf("%8s, %-10s  %s\n", opt, alt, desc);
		}
		exit(0);
	}
	foreach (setting_platform_t p; platforms) {
		if (strcmp(val, p.opt) == 0 || strcmp(val, p.alt) == 0) {
			common_settings.disasm.platform = p.val;
			return EXIT_SUCCESS;
		}
	}
	return EXIT_FAILURE;
}

//
// ANCHOR --syntax
//

int cli_syntax(const(char) *val) {
	if (cli_wanthelp(val)) {
		puts("Available disassembler syntaxes:");
		foreach (setting_syntax_t syntax; syntaxes) {
			with (syntax)
			printf("%-10s  %s\n", opt, desc);
		}
		exit(0);
	}
	foreach (setting_syntax_t syntax; syntaxes) {
		if (strcmp(val, syntax.opt) == 0) {
			common_settings.disasm.syntax = syntax.val;
			return EXIT_SUCCESS;
		}
	}
	return EXIT_FAILURE;
}

//
// ANCHOR --file
//

int cli_file(const(char) *val) {
	common_settings.file = val;
	return EXIT_SUCCESS;
}

//
// ANCHOR --args/--
//

int cli_argsdd(int argi, int argc, const(char) **argv) { // --
	import adbg.utils.str : adbg_util_move;
	
	enum MAX = 16;
	__gshared const(char) *[MAX] args;
	
	common_settings.args = cast(const(char)**)args;
	
	int left = argc - argi; /// to move
	void **s = cast(void**)(argv+argi);
	
	int m = adbg_util_move(
		cast(void**)&common_settings.args, MAX,
		cast(void**)&s, left);
	
	assert(m == left, "cli_argsdd: 'adbg_util_move' Failed due to small buffer");
	
	return EXIT_SUCCESS;
}
int cli_args(const(char) *val) { // --args
	import adbg.utils.str : adbg_util_expand;
	
	int argc = void;
	char **argv = adbg_util_expand(val, &argc);
	
	if (argc == 0)
		return EXIT_FAILURE;
	
	common_settings.args = cast(const(char)**)argv;
	return EXIT_SUCCESS;
}

//
// ANCHOR -E, --env
//

int cli_env(const(char) *val) {
	import adbg.utils.str : adbg_util_env;
	
	common_settings.env = cast(const(char)**)adbg_util_env(val);
	
	if (common_settings.env == null) {
		printf("main: Parsing environment failed");
		return EXIT_FAILURE;
	}
	
	return EXIT_SUCCESS;
}

//
// ANCHOR --pid
//

int cli_pid(const(char) *val) {
	common_settings.pid = cast(ushort)strtol(val, null, 10);
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
//	{ SettingUI.server, "server", "(n/a) TCP/IP server" },
];
int cli_ui(const(char)* val) {
	if (cli_wanthelp(val)) {
		puts("Available UIs:");
		foreach (setting_ui_t ui; uis) {
			printf("%-10s%s\n", ui.opt, ui.desc);
		}
		exit(0);
	}
	foreach (setting_ui_t ui; uis) {
		if (strcmp(val, ui.opt) == 0) {
			common_settings.ui = ui.val;
			return 0;
		}
	}
	return EXIT_FAILURE;
}

//
// ANCHOR --dump
//

int cli_dump() {
	common_settings.mode = SettingMode.dump;
	return EXIT_SUCCESS;
}

//
// ANCHOR --raw
//

int cli_raw() {
	common_settings.flags |= DumpOpt.raw;
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
	if (cli_wanthelp(val)) {
		puts("Available dumper display options:");
		foreach (setting_show_t show; showflags) {
			printf("%c\t%s\n", show.opt, show.desc);
		}
		exit(0);
	}
	A: while (*val) {
		char c = *val;
		++val;
		foreach (setting_show_t show; showflags) {
			if (c == show.opt) {
				common_settings.flags |= show.val;
				continue A;
			}
		}
		printf("main: unknown display flag '%c'\n", c);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

//
// ANCHOR --help
//

int cli_help() {
	puts(
	"alicedbg - Aiming to be a simple debugger\n"~
	"\n"~
	"USAGE\n"~
	" alicedbg {--pid ID|[--file] FILE|--dump FILE} [OPTIONS...]\n"~
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

debug private enum type = "-debug";
else  private enum type = "";

immutable(char) *fmt_version =
"alicedbg "~ADBG_VERSION~type~" (built: "~__TIMESTAMP__~")\n"~
"Compiler: "~__VENDOR__~" %u.%03u\n"~
"Target: "~TARGET_OBJFMT~" object, "~TARGET_FLTABI~" float\n"~
"Platform: "~TARGET_PLATFORM~"-"~TARGET_OS~"-"~TARGET_ENV~"\n"~
"CRT: "~TARGET_CRT~"\n"~
"CppRT: "~TARGET_CPPRT~"\n";
//TODO: Features:
int cli_version() {
	import d = std.compiler;
	printf(fmt_version, d.version_major, d.version_minor);
	exit(0);
	return 0;
}
int cli_ver() {
	puts(ADBG_VERSION);
	exit(0);
	return 0;
}

//
// ANCHOR --license
//

int cli_license() {
	puts(
	`BSD 3-Clause License

Copyright (c) 2019-2021, dd86k <dd@dax.moe>
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
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.`
	);
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

int main(int argc, const(char)** argv) {
	CLI: for (int argi = 1; argi < argc; ++argi) {
		const(char) *argLong = argv[argi];
		
		if (argLong[0] == 0) continue CLI;
		
		char argShort = void;
		bool isopt  = argLong[0] == '-';
		
		if (isopt == false) {
			if (common_settings.file == null) {
				common_settings.file = argLong;
				continue CLI;
			}
			
			printf("main: unknown option '%s'\n", argLong);
			return EXIT_FAILURE;
		}
		
		bool islong = argLong[1] == '-';
		const(char) *argval = void;
		
		if (islong) {
			// test for "--" (debuggee args)
			if (argLong[2] == 0) {
				if (cli_argsdd(++argi, argc, argv))
					return EXIT_FAILURE;
				break;
			}
			
			argLong = argLong + 2;
			LONGARG: foreach (option_t opt; options) {
				if (strcmp(argLong, opt.val)) continue LONGARG;
				
				// no argument
				if (opt.arg == false) {
					if (opt.f())
						return EXIT_FAILURE;
					continue CLI;
				}
				
				// with argument
				if (argi + 1 >= argc) {
					printf("main: missing argument for --%s\n", opt.val);
					return EXIT_FAILURE;
				}
				argval = argv[++argi];
				if (opt.fa(argval))
					return EXIT_FAILURE;
				
				continue CLI;
			}
			printf("main: unknown option '--%s'\n", argLong);
		} else { // short opt
			// test for "-" (stdin)
			argShort = argLong[1];
			if (argShort == 0) { // "-"
				puts("main: standard input not supported");
				return EXIT_FAILURE;
			}
			
			SHORTARG: foreach (option_t opt; options) {
				if (argShort != opt.alt)
					continue SHORTARG;
				
				// no argument
				if (opt.arg == false) {
					if (opt.f())
						return EXIT_FAILURE;
					continue CLI;
				}
				
				// with argument
				if (argi + 1 >= argc) {
					printf("main: missing argument for -%c\n", opt.alt);
					return EXIT_FAILURE;
				}
				argval = argv[++argi];
				if (opt.fa(argval))
					return EXIT_FAILURE;
				continue CLI;
			}
			printf("main: unknown option '-%c'\n", argShort);
		}
		
		return EXIT_FAILURE;
	}
	
	with (common_settings)
	switch (mode) {
	case SettingMode.dump:
		return dump(file, &disasm, flags);
	case SettingMode.trace:
		puts("main: tracer not supported at this moment");
		return EXIT_FAILURE;
	case SettingMode.debugger:
		// Pre-load target if specified.
		// Necessary for loop UI, but optional for others
		if (file) {
			if (adbg_load(file, args)) {
				printerror;
				return EXIT_FAILURE;
			}
			
			printf("File '%s' loaded\n", file);
		}
		
		switch (ui) {
		case SettingUI.loop:	return loop();
		case SettingUI.cmd:	return cmd();
		case SettingUI.tui:	return tui();
		case SettingUI.tcpserver:
			puts("main: tcp-server not yet supported");
			return EXIT_FAILURE;
		default: assert(0);
		}
	default: assert(0, "Implement SettingMode");
	}
}
