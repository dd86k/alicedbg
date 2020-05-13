/**
 * Command line interface.
 *
 * This module provides a non-pragmatic approach of configurating the debugger,
 * dumper, or profiler settings via a command-line interface.
 *
 * License: BSD 3-Clause
 */
module main;

import core.stdc.stdlib : strtol, EXIT_SUCCESS, EXIT_FAILURE;
import core.stdc.string : strcmp;
import core.stdc.stdio;
import adbg.consts;
import adbg.ui.loop : adbg_ui_loop_enter;
import adbg.ui.tui : adbg_ui_tui_enter;
import adbg.debugger, adbg.dumper;
import adbg.os.err;

extern (C):
private:

enum CLIOperatingMode {
	debug_,
	dump,
	profile
}

/// "sub-help" screen for cshow
enum CLIPage {
	main,
	ui,
	show,
	syntaxes,
	marchs,
	license,
}

// for debugger
enum DebuggerUI {
	tui,
	loop,
//	interpreter,
//	tcp_json,
}

enum DebuggerMode {
	undecided,
	file,
	pid
}

/// CLI options
struct cliopt_t {
	CLIOperatingMode mode;
	DebuggerUI ui;
	DebuggerMode debugtype;
	ushort pid;
	const(char) *file;
	const(char) *file_args;
	const(char) *file_env;
	int flags;	/// Flags for dumper
}

/// Version page
int cliver() {
	import d = std.compiler;
	printf(
	"alicedbg-"~__PLATFORM__~" "~PROJECT_VERSION~"-"~__BUILDTYPE__~"  ("~__TIMESTAMP__~")\n"~
	"License: BSD-3-Clause <https://spdx.org/licenses/BSD-3-Clause.html>\n"~
	"Home: <https://git.dd86k.space/dd86k/alicedbg>\n"~
	"Mirror: <https://github.com/dd86k/alicedbg>\n"~
	"Compiler: "~__VENDOR__~" %u.%03u, "~__TARGET_OBJ_FORMAT__~" obj, "~__TARGET_FLOAT_ABI__~" float\n"~
	"CRT: "~__CRT__~" (cpprt: "~__TARGET_CPP_RT__~") on "~__OS__~"\n"~
	"CPU: "~__TARGET_CPU__~"\n"~
	"Features: dbg disasm\n"~
	"Disasm: x86_16 x86\n",
	d.version_major, d.version_minor
	);
	return 0;
}

/// "sub-help" pages, such as -ui ? and the rest
/// Main advantage is that it's all in one place
int clipage(CLIPage h) {
	const(char) *r = void;
	with (CLIPage)
	final switch (h) {
	case main:
		r =
		"Aiming to be a simple debugger, dumper, and profiler\n"~
		"Usage:\n"~
		"  alicedbg {-pid|-exec|-dump} {FILE|ID} [OPTIONS...]\n"~
		"  alicedbg {--help|--version|--license}\n"~
		"\n"~
		"OPTIONS\n"~
		"  -mode    Manually select an operating mode (see -mode ?)\n"~
		"  -march   Select ISA for disassembler (see -march ?)\n"~
		"  -syntax  Select disassembler style (see -syntax ?)\n"~
		"  -exec    debugger: Load executable file\n"~
		"  -pid     debugger: Attach to process id\n"~
		"  -ui      debugger: Choose user interface (default=tui, see -ui ?)\n"~
		"  -dump    dumper: Selects dump mode\n"~
		"  -raw     dumper: Disassemble raw file\n"~
		"  -show    dumper: Select what to show (default=h, see -show ?)\n";
		break;
	case ui:
		r =
		"Available UIs (default=tui)\n"~
		"tui ....... (WIP) Text UI with full debugging experience.\n"~
		"loop ...... Print exceptions, minimum user interaction."
//		"cmd ....... (Experimental) (REPL) Command-based, like a shell.\n"
//		"tcp-json .. (Experimental) JSON API server via TCP.\n"
		;
		break;
	case show:
		r =
		"Available SHOW fields for dumper (default=h)\n"~
		"A .. Show all fields\n"~
		"h .. Show headers\n"~
		"s .. Show sections\n"~
		"i .. Show imports\n"~
		"d .. Show disassembly (code sections only)"
//		"D .. Show disassembly (all sections)"
		;
		break;
	case syntaxes:
		r =
		"Available disassembler styles\n"~
		"intel .... Intel syntax\n"~
		"nasm ..... Netwide Assembler syntax\n"~
		"att ...... AT&T syntax"
		;
		break;
	case marchs:
		r =
		"Available architectures\n"~
		"x86_16 ........ Intel x86 16-bit mode (8086)\n"~
		"x86 ........... Intel and AMD x86 (i386+)"
//		"x86_64 ........ EM64T/Intel64 and AMD64\n"
//		"thumb ......... ARM Thumb 32-bit\n"~
//		"arm ........... ARM 32-bit\n"~
//		"aarch64 ....... ARM 64-bit\n"~
//		"rv32 .......... RISC-V 32-bit\n"~
//		"rv64 .......... RISC-V 64-bit\n"~
//		"rv128 ......... RISC-V 128-bit\n"~
		;
		break;
	case license:
		r =
`BSD 3-Clause License

Copyright (c) 2019-2020, dd86k <dd@dax.moe>
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
		break;
	}
	puts(r);
	return 0;
}

int main(int argc, const(char) **argv) {
	if (argc <= 1)
		return clipage(CLIPage.main);

	cliopt_t opt;	/// Defaults to .init
	disasm_params_t disopt;	/// .init

	// CLI
	for (size_t argi = 1; argi < argc; ++argi) {
		const(char) *arg = argv[argi] + 1;

		if (*argv[argi] != '-') { // default arguments
			if (opt.file == null) {
				opt.debugtype = DebuggerMode.file;
				opt.file = argv[argi];
			} else if (opt.file_args == null) {
				opt.file_args = argv[argi];
			} else if (opt.file_env == null) {
				opt.file_env = argv[argi];
			} else {
				puts("cli: Out of default parameters");
				return EXIT_FAILURE;
			}
			continue;
		}

		// choose operating mode
		if (strcmp(arg, "mode") == 0) {
			if (argi + 1 >= argc) {
				puts("cli: path argument missing");
				return EXIT_FAILURE;
			}
			const(char) *mode = argv[++argi];
			if (strcmp(mode, "dump") == 0)
				opt.mode = CLIOperatingMode.dump;
			else if (strcmp(mode, "profile") == 0)
				opt.mode = CLIOperatingMode.profile;
			else if (strcmp(mode, "debug") == 0)
				opt.mode = CLIOperatingMode.debug_;
			else {
				printf("unknown mode: %s\n", mode);
				return EXIT_FAILURE;
			}
			continue;
		}

		// shorthand of "-mode dump"
		if (strcmp(arg, "dump") == 0) {
			opt.mode = CLIOperatingMode.dump;
			continue;
		}

		// debugger: select file
		if (strcmp(arg, "exec") == 0) {
			if (argi + 1 >= argc) {
				puts("cli: file argument missing");
				return EXIT_FAILURE;
			}
			opt.debugtype = DebuggerMode.file;
			opt.file = argv[++argi];
			continue;
		}
		/*
		if (strcmp(arg, "execarg") == 0) {
			
		}
		// Starting directory for file
		if (strcmp(arg, "execdir") == 0) {
			
		}*/

		// debugger: select pid
		if (strcmp(arg, "pid") == 0) {
			if (argi + 1 >= argc) {
				puts("cli: pid argument missing");
				return EXIT_FAILURE;
			}
			opt.debugtype = DebuggerMode.pid;
			const(char) *id = argv[++argi];
			opt.pid = cast(ushort)strtol(id, null, 10);
			continue;
		}

		// debugger: ui
		if (strcmp(arg, "ui") == 0) {
			if (argi + 1 >= argc) {
				puts("cli: ui argument missing");
				return EXIT_FAILURE;
			}
			const(char) *ui = argv[++argi];
			if (strcmp(ui, "tui") == 0)
				opt.ui = DebuggerUI.tui;
			else if (strcmp(ui, "loop") == 0)
				opt.ui = DebuggerUI.loop;
			else if (strcmp(ui, "?") == 0)
				return clipage(CLIPage.ui);
			else {
				printf("cli: ui \"%s\" not found, query \"-ui ?\" for a list\n",
					ui);
				return EXIT_FAILURE;
			}
			continue;
		}

		// debugger: machine architecture, affects disassembly
		if (strcmp(arg, "march") == 0) {
			if (argi + 1 >= argc) {
				puts("cli: architecture argument missing");
				return EXIT_FAILURE;
			}
			const(char) *march = argv[++argi];
			if (strcmp(march, "x86") == 0)
				disopt.isa = DisasmISA.x86;
			else if (strcmp(march, "x86_16") == 0)
				disopt.isa = DisasmISA.x86_16;
/*			else if (strcmp(march, "x86_64") == 0)
				disopt.isa = DisasmISA.x86_64;
			else if (strcmp(march, "thumb") == 0)
				disopt.isa = DisasmISA.arm_t32;
			else if (strcmp(march, "arm") == 0)
				disopt.isa = DisasmISA.arm_a32;
			else if (strcmp(march, "aarch64") == 0)
				disopt.isa = DisasmISA.arm_a64;
			else if (strcmp(march, "rv32") == 0)
				disopt.isa = DisasmISA.rv32;
			else if (strcmp(march, "rv64") == 0)
				disopt.isa = DisasmISA.rv64;*/
			else if (strcmp(march, "guess") == 0) {
				puts("guess feature not implemented");
				return EXIT_FAILURE;
			} else if (strcmp(march, "?") == 0)
				return clipage(CLIPage.marchs);
			else {
				printf("Unknown machine architecture: '%s'\n", march);
				return EXIT_FAILURE;
			}
			continue;
		}

		// disassembler: select syntax
		if (strcmp(arg, "syntax") == 0) {
			if (argi + 1 >= argc) {
				puts("cli: syntax argument missing");
				return EXIT_FAILURE;
			}
			const(char) *syntax = argv[++argi];
			if (strcmp(syntax, "intel") == 0)
				disopt.syntax = DisasmSyntax.Intel;
			else if (strcmp(syntax, "nasm") == 0)
				disopt.syntax = DisasmSyntax.Nasm;
			else if (strcmp(syntax, "att") == 0)
				disopt.syntax = DisasmSyntax.Att;
			else if (strcmp(syntax, "?") == 0)
				return clipage(CLIPage.syntaxes);
			else {
				printf("Unknown disassembler syntax: '%s'\n", syntax);
				return EXIT_FAILURE;
			}
			continue;
		}

		// Choose demangle settings for symbols
		/*if (strcmp(arg, "demangle") == 0) {
			
		}*/

		// Choose debugging backend, currently unsupported and only
		// embedded option is available
		/*if (strcmp(arg, "backend") == 0) {
			
		}*/

		// dumper: file is raw
		if (strcmp(arg, "raw") == 0) {
			opt.flags |= DUMPER_FILE_RAW;
			continue;
		}

		// dumper: show fields
		if (strcmp(arg, "show") == 0) {
			if (argi + 1 >= argc) {
				puts("cli: show argument missing");
				return EXIT_FAILURE;
			}
			const(char)* cf = argv[++argi];
			while (*cf) {
				char c = *cf;
				switch (c) {
				case 'A': opt.flags |= DUMPER_SHOW_EVERYTHING; break;
				case 'h': opt.flags |= DUMPER_SHOW_HEADER; break;
				case 's': opt.flags |= DUMPER_SHOW_SECTIONS; break;
				case 'i': opt.flags |= DUMPER_SHOW_IMPORTS; break;
				case 'c': opt.flags |= DUMPER_SHOW_LOADCFG; break;
//				case 'e': opt.flags |= DUMPER_SHOW_EXPORTS; break;
//				case '': opt.flags |= DUMPER_SHOW_; break;
				case 'd': opt.flags |= DUMPER_DISASM_CODE; break;
				case 'D': opt.flags |= DUMPER_DISASM_ALL; break;
				case 'S': opt.flags |= DUMPER_DISASM_STATS; break;
				case '?': return clipage(CLIPage.show);
				default:
					printf("cli: unknown show flag: %c\n", c);
					return EXIT_FAILURE;
				}
				++cf;
			}
			continue;
		}

		if (strcmp(arg, "version") == 0 || strcmp(arg, "-version") == 0)
			return cliver;
		if (strcmp(arg, "h") == 0 || strcmp(arg, "-help") == 0)
			return clipage(CLIPage.main);
		if (strcmp(arg, "-license") == 0)
			return clipage(CLIPage.license);

		printf("cli: unknown option: %s\n", arg);
		return EXIT_FAILURE;
	}

	int e = void;
	with (CLIOperatingMode)
	final switch (opt.mode) {
	case debug_:
		with (DebuggerMode)
		switch (opt.debugtype) {
		case file: e = adbg_load(opt.file); break;
		case pid: e = adbg_attach(opt.pid); break;
		default:
			puts("cli: No file nor pid were specified.");
			return EXIT_FAILURE;
		}

		if (e) {
			adbg_err_osprint("dbg", e);
			return e;
		}

		with (DebuggerUI)
		final switch (opt.ui) {
		case loop: e = adbg_ui_loop_enter(&disopt); break;
		case tui: e = adbg_ui_tui_enter(&disopt); break;
		}
		break;
	case dump:
		e = adbg_dmpr_dump(opt.file, &disopt, opt.flags);
		break;
	case profile:
		puts("Profiling feature not yet implemented");
		return EXIT_FAILURE;
	}

	return e;
}
