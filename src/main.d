/**
 * Command line interface.
 *
 * This module provides a non-pragmatic approach of configurating the debugger,
 * dumper, or profiler settings via a command-line interface.
 *
 * License: BSD 3-clause
 */
module main;

import core.stdc.stdlib : malloc, strtol, exit, EXIT_SUCCESS, EXIT_FAILURE;
import core.stdc.string : strcmp, strncpy, strtok;
import core.stdc.stdio;
import adbg.platform;
import adbg.debugger : adbg_attach, adbg_load;
import adbg.disasm : adbg_disasm_t, AdbgDisasmPlatform, AdbgDisasmSyntax;
import adbg.sys.err : adbg_sys_perror;
import d = std.compiler;
import debugger, dumper;

private:
extern (C):
__gshared:

//
// CLI utils
//

bool askhelp(const(char) *query) {
	switch (query[0]) {
	case '?': return true;
	default: return strcmp(query, "help") == 0;
	}
}

//immutable(char)* ARG    = "<arg>";
//immutable(char)* NOARG  = "     ";

//TODO: Consider adding 'bool avoidopt' field
//      Acts as "--", to stop processing options
struct settings_t {
	SettingUI ui;	/// Debugger user interface
	adbg_disasm_t disasm;	/// Disassembler settings
	bool dump;	/// Dump instead of debugging
	const(char) *file;	/// Debuggee: file
//	const(char) *dir;	/// Debuggee: directory
	const(char) **argv;	/// Debuggee: argument vector
	const(char) **env;	/// Debuggee: environement
	uint pid;	/// Debuggee: PID
	uint flags;	/// 
}

//TODO: Consider adding 'bool processed' field
//      Avoids repeating options, may speed-up parsing
//      * Could be an issue for repeatable options (unless another field added..)
struct option_t {
	align(4) char alt;
	immutable(char) *val;
	immutable(char) *desc;
	align(4) bool arg;	/// if it takes an argument
	union {
		extern(C) int function(settings_t*) f;
		extern(C) int function(settings_t*, const(char)*) farg;
	}
}
immutable option_t[] options = [
	// general
	{ 'm', "march",  "Select architecture for disassembler", true, farg: &climarch },
	{ 's', "syntax", "Select disassembler syntax", true, farg: &clisyntax },
	//TODO: --debug/--no-debug: Disable/enable internal SEH from main
	// debugger
	{ 'f', "file", "Debugger: Load file (default parameter)", true, farg: &clifile },
	{ 0,   "args", "Debugger: Supply arguments to file", true, farg: &cliargs },
	{ 0,   "env",  "Debugger: Supply environment to file", true, farg: &clienv },
	{ 'p', "pid",  "Debugger: Attach to process", true, farg: &clipid },
	{ 0,   "ui",   "Debugger: Select user interface (default=loop)", true, farg: &cliui },
	// dumper
	{ 'D', "dump", "Dumper: Select the object dump mode", false, &clidump },
	{ 'R', "raw",  "Dumper: File is not an object, but raw", false, &cliraw },
	{ 'S', "show", "Dumper: Select which portions to output (default=h)", true, farg: &clishow },
	// pages
	{ 'h', "help",    "Show this help screen and exit", false, &clihelp },
	{ 0,   "version", "Show the version screen and exit", false, &cliversion },
	{ 0,   "ver",     "Only show the version string and exit", false, &cliver },
	{ 0,   "license", "Show the license page and exit", false, &clilicense },
	{ 0,   "meow",    "Meow and exit", false, &climeow },
];

//
// ANCHOR --march
//

struct setting_platform_t {
	AdbgDisasmPlatform val;
	immutable(char)* opt, alt, desc;
}
immutable setting_platform_t[] platforms = [
	{ AdbgDisasmPlatform.x86_16, "x86_16", "8086",    "x86 16-bit (real-mode)" },
	{ AdbgDisasmPlatform.x86,    "x86",    "i386",    "x86 32-bit (extended mode)" },
	{ AdbgDisasmPlatform.x86_64, "x86_64", "amd64",   "x86 64-bit (long mode)" },
	{ AdbgDisasmPlatform.rv32,   "rv32",   "riscv32", "RISC-V 32-bit"},
];
int climarch(settings_t *settings, const(char) *val) {
	if (askhelp(val)) {
		puts("Available machine architectures:");
		foreach (setting_platform_t p; platforms) {
			with (p)
			printf("%8s, %-12s%s\n", opt, alt, desc);
		}
		exit(0);
	}
	foreach (setting_platform_t p; platforms) {
		if (strcmp(val, p.opt) == 0 || strcmp(val, p.alt) == 0) {
			settings.disasm.platform = p.val;
			return EXIT_SUCCESS;
		}
	}
	return EXIT_FAILURE;
}

//
// ANCHOR --syntax
//

struct setting_syntax_t {
	AdbgDisasmSyntax val;
	immutable(char)* opt, desc;
}
immutable setting_syntax_t[] syntaxes = [
	{ AdbgDisasmSyntax.Att, "att",   "AT&T syntax" },
	{ AdbgDisasmSyntax.Att, "intel", "Intel syntax" },
	{ AdbgDisasmSyntax.Att, "nasm",  "Netwide Assembler syntax" },
];
int clisyntax(settings_t *settings, const(char) *val) {
	if (askhelp(val)) {
		puts("Available disassembler syntaxes:");
		foreach (setting_syntax_t syntax; syntaxes) {
			with (syntax)
			printf("%-8s %s\n", opt, desc);
		}
		exit(0);
	}
	foreach (setting_syntax_t syntax; syntaxes) {
		if (strcmp(val, syntax.opt) == 0) {
			settings.disasm.syntax = syntax.val;
			return EXIT_SUCCESS;
		}
	}
	return EXIT_FAILURE;
}

//
// ANCHOR --file
//

int clifile(settings_t *settings, const(char) *val) {
	settings.file = val;
	return EXIT_SUCCESS;
}

//
// ANCHOR --args
//

int cliargs(settings_t *settings, const(char) *val) {
	puts("todo");
	return EXIT_FAILURE;
	//TODO: cliargs
	//      Seperate per space, "--example=33"
	/*settings.argv = cast(const(char)**)malloc(ADBG_CLI_ARGV_ARRAY_LENGTH);
	if (settings.argv == null) {
		puts("cli: could not allocate (args)");
		return EXIT_FAILURE;
	}
	size_t i;
	for (; argi < argc && i < ADBG_CLI_ARGV_ARRAY_COUNT - 1; ++i, ++argi)
		settings.argv[i] = argv[argi];
	settings.argv[i] = null;
	return EXIT_SUCCESS;*/
}

//
// ANCHOR --env
//

int clienv(settings_t *settings, const(char) *val) {
	puts("todo");
	return EXIT_FAILURE;
	/*opt.envp = cast(const(char)**)malloc(ADBG_CLI_ARGV_ARRAY_LENGTH);
	if (opt.envp == null) {
		puts("cli: could not allocate (envp)");
		return EXIT_FAILURE;
	}
	opt.envp[0] = strtok(cast(char*)argv[argi], ",");
	size_t ti;
	while (++ti < ADBG_CLI_ARGV_ARRAY_LENGTH - 1) {
		char* t = strtok(null, ",");
		opt.envp[ti] = t;
		if (t == null) break;
	}*/
}

//
// ANCHOR --pid
//

int clipid(settings_t *settings, const(char) *val) {
	settings.pid = cast(ushort)strtol(val, null, 10);
	return EXIT_SUCCESS;
}

//
// ANCHOR --ui
//

enum SettingUI { loop, cmd, tui, server }
struct setting_ui_t {
	SettingUI val;
	immutable(char)* opt, desc;
}
immutable setting_ui_t[] uis = [
	{ SettingUI.loop,   "loop",   "Simple loop interface with single-character choices (default)" },
	{ SettingUI.cmd,    "cmd",    "Command-line for more advanced sessions" },
	{ SettingUI.loop,   "tui",    "Text User Interface" },
//	{ SettingUI.server, "server", "Work In Progress" },
];
int cliui(settings_t* settings, const(char)* val) {
	if (askhelp(val)) {
		puts("Available UIs:");
		foreach (setting_ui_t ui; uis) {
			printf("%-10s%s\n", ui.opt, ui.desc);
		}
		exit(0);
	}
	foreach (setting_ui_t ui; uis) {
		if (strcmp(val, ui.opt) == 0) {
			settings.ui = ui.val;
			return 0;
		}
	}
	return EXIT_FAILURE;
}

//
// ANCHOR --dump
//

int clidump(settings_t *settings) {
	settings.dump = true;
	return EXIT_SUCCESS;
}

//
// ANCHOR --raw
//

int cliraw(settings_t *settings) {
	settings.flags |= DUMPER_FILE_RAW;
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
	{ 'h', "Show header metadata (default)", DUMPER_SHOW_HEADER },
	{ 's', "Show sections metadata", DUMPER_SHOW_SECTIONS },
	{ 'i', "Show imports", DUMPER_SHOW_IMPORTS },
	{ 'c', "Show load configuration", DUMPER_SHOW_LOADCFG },
//	{ 'e', "Show exports", DUMPER_SHOW_EXPORTS },
	{ 'p', "Show debug information", DUMPER_SHOW_DEBUG },
	{ 'd', "Disassemble code (e.g., .text)", DUMPER_DISASM_CODE },
	{ 'D', "Disassemble all sections", DUMPER_DISASM_ALL },
	{ 'S', "Show disassembler statistics", DUMPER_SHOW_HEADER },
	{ 'A', "Show everything (hsicpd)", DUMPER_SHOW_EVERYTHING },
];
int clishow(settings_t *settings, const(char) *val) {
	if (askhelp(val)) {
		puts("Available dumper-show options:");
		foreach (setting_show_t show; showflags) {
			printf("%c\t%s\n", show.opt, show.desc);
		}
		exit(0);
	}
	l_val: while (*val) {
		char c = *val;
		++val;
		foreach (setting_show_t show; showflags) {
			if (c == show.opt) {
				settings.flags |= show.val;
				continue l_val;
			}
		}
		printf("main: show flag '%c' unknown", c);
	}
	return EXIT_SUCCESS;
}

//
// ANCHOR --help
//

int clihelp(settings_t*) {
	puts(
		"Aiming to be a simple debugger, dumper, and profiler\n"~
		"Usage:\n"~
		"  alicedbg {--pid ID|--file FILE|--dump FILE} [OPTIONS...]\n"~
		"  alicedbg {-h|--help|--version|--license}\n"~
		"\n"~
		"OPTIONS"
	);
	foreach (option_t opt; options[0..$-1]) {
		if (opt.alt)
			printf("-%c, --%-11s%s\n", opt.alt, opt.val, opt.desc);
		else
			printf("--%-15s%s\n", opt.val, opt.desc);
	}
	exit(0);
	return 0;
}

//
// ANCHOR --version
//

immutable(char) *fmt_version =
"alicedbg "~ADBG_VERSION~" (built: "~__TIMESTAMP__~")\n"~
"License: BSD-3-Clause <https://spdx.org/licenses/BSD-3-Clause.html>\n"~
"Homes:\n"~
" - <https://git.dd86k.space/dd86k/alicedbg>\n"~
" - <https://github.com/dd86k/alicedbg>\n"~
"Compiler: "~__VENDOR__~" %u.%03u, "~TARGET_OBJFMT~" obj, "~TARGET_FLTABI~" float\n"~
"CRT: "~TARGET_CRT~" (C++RT: "~TARGET_CPPRT~") on "~TARGET_PLATFORM~"/"~TARGET_OS~"\n"~
"Environment: "~TARGET_ENV~"\n"~
"InlineAsm: "~IN_ASM_STR~"\n";
int cliversion(settings_t*) {
	printf(fmt_version, d.version_major, d.version_minor);
	exit(0);
	return 0;
}
int cliver(settings_t*) {
	puts(ADBG_VERSION);
	exit(0);
	return 0;
}

//
// ANCHOR --license
//

int clilicense(settings_t*) {
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

int climeow(settings_t*) {
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

int main(int argc, const(char)** argv) {
	if (argc <= 1)
		clihelp(null);
		
	// .init automatically take the defaults
	settings_t settings;	/// cli settings
	int lasterr;	/// last cli error
	
	A: for (int argi = 1; argi < argc; ++argi) {
		const(char) *argLong = argv[argi];
		
		if (argLong[0] == 0) continue;
		
		char argShort = void;
		bool isopt  = argLong[0] == '-';
		
		if (isopt) {
			bool islong = argLong[1] == '-';
			const(char) *argval = void;
			if (islong) {
				if (argLong[2] == 0) { // "--"
					//TODO: force isopt to false
					puts("main: -- not supported");
					return EXIT_FAILURE;
				}
				argLong = argLong + 2;
				foreach (option_t opt; options) {
					if (strcmp(argLong, opt.val)) continue;
					if (opt.arg == false) {
						lasterr = opt.f(&settings);
						continue A;
					}
					if (argi + 1 >= argc) {
						printf("missing argument for --%s\n", opt.val);
						return EXIT_FAILURE;
					}
					argval = argv[++argi];
					lasterr = opt.farg(&settings, argval);
					if (lasterr) {
						printf("main: '%s' failed with --%s\n", argval, opt.val);
						return lasterr;
					}
					continue A;
				}
			} else { // short opt
				argShort = argLong[1];
				if (argShort == 0) { // "-"
					puts("main: standard input not supported");
					return EXIT_FAILURE;
				}
				foreach (option_t opt; options) {
					if (argShort != opt.alt) continue;
					if (opt.arg == false) {
						lasterr = opt.f(&settings);
						continue A;
					}
					if (argi + 1 >= argc) {
						printf("missing argument for -%c\n", opt.alt);
						return EXIT_FAILURE;
					}
					argval = argv[++argi];
					lasterr = opt.farg(&settings, argval);
					if (lasterr) {
						printf("main: '%s' failed with -%c\n", argval, opt.alt);
						return lasterr;
					}
					continue A;
				}
			}
			if (islong) {
				printf("main: unknown option '--%s'\n", argLong);
				return EXIT_FAILURE;
			} else {
				printf("main: unknown option '-%c'\n", argShort);
				return EXIT_FAILURE;
			}
		} // not an option
		
		if (settings.file == null) {
			settings.file = argLong;
			continue;
		}
		
		printf("main: unknown option '%s'\n", argLong);
		return EXIT_FAILURE;
	}
	
	// app: dumper
	if (settings.dump)
		return adbg_dump(settings.file, &settings.disasm, settings.flags);
	
	// app: debugger
	lasterr = settings.pid ?
		adbg_attach(settings.pid, 0) :
		adbg_load(settings.file, null, settings.argv, null, 0);
	
	if (lasterr) {
		adbg_sys_perror!"dbg"(lasterr);
		return lasterr;
	}
	
	adbg_ui_common_params(&settings.disasm);
	with (SettingUI)
	final switch (settings.ui) {
	case loop: lasterr = adbg_ui_loop(); break;
	case cmd:  lasterr = adbg_ui_cmd(); break;
	case tui:  lasterr = adbg_ui_tui(); break;
	case server:
		puts("main: server ui not yet supported");
		return EXIT_FAILURE;
	}
	return lasterr;
}
