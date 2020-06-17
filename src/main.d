/**
 * Command line interface.
 *
 * This module provides a non-pragmatic approach of configurating the debugger,
 * dumper, or profiler settings via a command-line interface.
 *
 * License: BSD 3-Clause
 */
module main;

import core.stdc.stdlib : malloc, strtol, EXIT_SUCCESS, EXIT_FAILURE;
import core.stdc.string : strcmp, strncpy, strtok;
import core.stdc.stdio;
import adbg.consts;
import adbg.ui.loop : adbg_ui_loop_enter;
import adbg.ui.tui : adbg_ui_tui_enter;
import adbg.debugger, adbg.dumper;
import adbg.os.err, adbg.os.seh;

extern (C):
private:

enum CLIOpMode {
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
	surprise
}

// for debugger
enum DebuggerUI {
	loop,
//	cmd,
	tui,
//	tcp_json,
}

enum DebuggerMode {
	undecided,
	file,
	pid
}

/// CLI options
struct mainopt_t {
	CLIOpMode mode;
	DebuggerUI ui;
	DebuggerMode debugtype;
	union {	// File or PID
		ushort pid;
		const(char) *file;
	}
	const(char) *dir;
	const(char) **argv;
	const(char) **envp;
	int flags;	/// Flags
}

/// CLI option structure, good for looping over
struct mainopt {
	const(char)* name;
	union {
		int i32;
		DisasmISA isa;
		DisasmSyntax syntax;
	}
}

/// Version page
int cliver() {
	import d = std.compiler;
	printf(
	"alicedbg-"~__PLATFORM__~" "~APP_VERSION~"-"~__BUILDTYPE__~"  ("~__TIMESTAMP__~")\n"~
	"License: BSD-3-Clause <https://spdx.org/licenses/BSD-3-Clause.html>\n"~
	"Homes:\n"~
	" - <https://git.dd86k.space/dd86k/alicedbg>\n"~
	" - <https://github.com/dd86k/alicedbg>\n"~
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
		r = "Aiming to be a simple debugger, dumper, and profiler\n"~
		"Usage:\n"~
		"  alicedbg {--pid ID|--file FILE|--dump FILE} [OPTIONS...]\n"~
		"  alicedbg {-h|--help|--version|--license}\n"~
		"\n"~
		"OPTIONS\n"~
		"  -m, --march ..... Select ISA for disassembler (see -march ?)\n"~
		"  -s, --syntax .... Select disassembler style (see -syntax ?)\n"~
		"  -f, --file ...... debugger: Load executable file\n"~
		"  -p, --pid ....... debugger: Attach to process id\n"~
		"  -u, --ui ........ debugger: Select user interface (default=loop, see -ui ?)\n"~
		"  -D, --dump ...... dumper: Selects dump mode\n"~
		"  --raw ........... dumper: Disassemble as a raw file\n"~
		"  -S, --show ...... dumper: Select parts to show (default=h, see -show ?)\n";
		break;
	case ui:
		r = "Available debug UIs (default=loop)\n"~
		"loop ...... Print exceptions, minimum user interaction.\n"
//		"cmd ....... (Experimental) (REPL) Command-based, like a shell.\n"
//		"tui ....... (WIP) Text UI with full debugging experience.\n"
//		"tcp-json .. (Experimental) JSON API server via TCP.\n"
		;
		break;
	case show:
		r = "Available parts for dumper (default=h)\n"~
		"A .. Show all fields listed below\n"~
		"h .. Show headers\n"~
		"s .. Show sections\n"~
		"i .. Show imports\n"~
		"d .. Show disassembly (code sections only)"
//		"D .. Show disassembly (all sections)"
		;
		break;
	case syntaxes:
		r = "Available disassembler syntaxes\n"~
		"intel .... Intel syntax\n"~
		"nasm ..... Netwide Assembler syntax\n"~
		"att ...... AT&T syntax"
		;
		break;
	case marchs:
		r = "Available architectures\n"~
		"x86_16, 8086........ Intel 8086 (16-bit)\n"~
		"x86, i386 .......... Intel i386+ (32-bit)"
//		"x86_64, amd64 ...... EM64T/Intel64 and AMD64 (64-bit)\n"
//		"t32, thumb ......... ARM Thumb (16/32-bit)\n"~
//		"a32, arm ........... ARM (32-bit)\n"~
//		"a64, aarch64 ....... ARM (64-bit)\n"~
//		"rv32, riscv32 ...... RISC-V 32-bit\n"~
//		"rv64, riscv64 ...... RISC-V 64-bit\n"~
//		"rv128, riscv128 .... RISC-V 128-bit\n"~
		;
		break;
	case license:
		r = `BSD 3-Clause License

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
	case surprise:
		r = `
+------------------+
| Meow, I hate x86 |
+--+---------------+
   |    A_A
   +-  (-.-)
       /   \    _
      /     \__/
      \_||__/
`;
		break;
	}
	puts(r);
	return EXIT_SUCCESS;
}

int main(int argc, const(char) **argv) {
	if (argc <= 1)
		return clipage(CLIPage.main);

	mainopt_t opt;	/// Defaults to .init
	disasm_params_t disopt;	/// .init

	cli: for (size_t argi = 1; argi < argc; ++argi) {
		const(char) *arg = argv[argi] + 1;

		//
		// Debugger switches
		//

		// (debugger) --/--args: disable CLI parsing for argv
		if (strcmp(arg, "-") == 0 || strcmp(arg, "-args") == 0) {
			if (argi + 1 >= argc) {
				puts("cli: args missing");
				return EXIT_FAILURE;
			}
			opt.argv = cast(const(char)**)malloc(CLI_ARGV_ARRAY_LENGTH);
			if (opt.argv == null) {
				puts("cli: could not allocate (args)");
				return EXIT_FAILURE;
			}
			++argi;
			size_t i;
			while (argi < argc && i < CLI_ARGV_ARRAY_SIZE - 1)
				opt.argv[i++] = argv[argi++];
			opt.argv[i] = null;
			break;
		}

		// (debugger) -E/--env: environment string
		if (strcmp(arg, "E") == 0 || strcmp(arg, "-env") == 0) {
			if (argi + 1 >= argc) {
				puts("cli: env argument missing");
				return EXIT_FAILURE;
			}
			opt.envp = cast(const(char)**)malloc(CLI_ARGV_ARRAY_LENGTH);
			if (opt.envp == null) {
				puts("cli: could not allocate (envp)");
				return EXIT_FAILURE;
			}
			++argi;
			opt.envp[0] = strtok(cast(char*)argv[argi], ",");
			size_t ti;
			while (++ti < CLI_ARGV_ARRAY_LENGTH - 1) {
				char* t = strtok(null, ",");
				opt.envp[ti] = t;
				if (t == null) break;
			}
			continue;
		}

		// (debugger) -f/--file: path for debuggee
		if (strcmp(arg, "f") == 0 || strcmp(arg, "-file") == 0) {
			if (argi + 1 >= argc) {
				puts("cli: file argument missing");
				return EXIT_FAILURE;
			}
			opt.debugtype = DebuggerMode.file;
			opt.file = argv[++argi];
			continue;
		}

		// (debugger) -p/--pid: select pid
		if (strcmp(arg, "p") == 0 || strcmp(arg, "-pid") == 0) {
			if (argi + 1 >= argc) {
				puts("cli: pid argument missing");
				return EXIT_FAILURE;
			}
			opt.debugtype = DebuggerMode.pid;
			const(char) *id = argv[++argi];
			opt.pid = cast(ushort)strtol(id, null, 10);
			continue;
		}

		// (debugger) -u/--ui: select UI
		if (strcmp(arg, "u") == 0 || strcmp(arg, "-ui") == 0) {
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
				printf("Unknown UI: '%s', query \"-ui ?\" for list\n", ui);
				return EXIT_FAILURE;
			}
			continue;
		}

		// (debugger) -m/--march: machine architecture, affects disassembly
		if (strcmp(arg, "m") == 0 || strcmp(arg, "-march") == 0) {
			if (argi + 1 >= argc) {
				puts("cli: architecture argument missing");
				return EXIT_FAILURE;
			}
			__gshared mainopt[] isaopts = [
				{ "i386", DisasmISA.x86 },
				{ "x86", DisasmISA.x86 },
				{ "8086", DisasmISA.x86_16 },
				{ "x86_16", DisasmISA.x86_16 },
				{ "amd64", DisasmISA.x86_64 },
				{ "x86_64", DisasmISA.x86_64 },
//				{ "thumb", DisasmISA.arm_t32 },
//				{ "t32", DisasmISA.arm_t32 },
//				{ "arm", DisasmISA.arm_a32 },
//				{ "a32", DisasmISA.arm_a32 },
//				{ "aarch64", DisasmISA.arm_a64 },
//				{ "arm64", DisasmISA.arm_a64 },
				{ "rv32", DisasmISA.rv32 },
//				{ "riscv32", DisasmISA.rv32 },
//				{ "risc:rv32", DisasmISA.rv32 },
//				{ "rv64", DisasmISA.rv64 },
//				{ "riscv64", DisasmISA.rv64 },
//				{ "risc:rv64", DisasmISA.rv64 },
//				{ "guess", DisasmISA.Guess },
//				{ "default", DisasmISA.Default },
				{ "?", 255 },
			];
			const(char) *march = argv[++argi];
			foreach (ref mainopt o; isaopts) {
				if (strcmp(march, o.name) == 0) {
					if (o.i32 == 255)
						return clipage(CLIPage.marchs);
					disopt.isa = o.isa;
					continue cli;
				}
			}
			printf("Unknown march: '%s', query '-march ?' for list\n", march);
			return EXIT_FAILURE;
		}

		// (debugger) -d/--demangle: demangle symbols
		/*if (strcmp(arg, "d") == 0 || strcmp(arg, "-demangle") == 0) {
			
		}*/

		//
		// Dumper switches
		//

		// (dumper) -D/--dump: Switches the operation to "dump"
		if (strcmp(arg, "D") == 0 || strcmp(arg, "-dump") == 0) {
			opt.mode = CLIOpMode.dump;
			continue;
		}

		// (dumper) -R/--raw: file is raw
		if (strcmp(arg, "R") == 0 || strcmp(arg, "-raw") == 0) {
			opt.flags |= DUMPER_FILE_RAW;
			continue;
		}

		// (dumper) -S/--show: show fields
		if (strcmp(arg, "S") == 0 || strcmp(arg, "-show") == 0) {
			if (argi + 1 >= argc) {
				puts("cli: show argument missing");
				return EXIT_FAILURE;
			}
			const(char)* cf = argv[++argi];
			while (*cf) {
				char c = *cf;
				switch (c) {
				case 'h': opt.flags |= DUMPER_SHOW_HEADER; break;
				case 's': opt.flags |= DUMPER_SHOW_SECTIONS; break;
				case 'i': opt.flags |= DUMPER_SHOW_IMPORTS; break;
				case 'c': opt.flags |= DUMPER_SHOW_LOADCFG; break;
//				case 'e': opt.flags |= DUMPER_SHOW_EXPORTS; break;
//				case '': opt.flags |= DUMPER_SHOW_; break;
				case 'd': opt.flags |= DUMPER_DISASM_CODE; break;
				case 'D': opt.flags |= DUMPER_DISASM_ALL; break;
				case 'S': opt.flags |= DUMPER_DISASM_STATS; break;
				case 'A': opt.flags |= DUMPER_SHOW_EVERYTHING; break;
				case '?': return clipage(CLIPage.show);
				default:
					printf("cli: unknown show flag: %c\n", c);
					return EXIT_FAILURE;
				}
				++cf;
			}
			continue;
		}

		//
		// Disassembler switches
		//

		// (disassembler) -s/--syntax: select syntax
		if (strcmp(arg, "s") == 0 || strcmp(arg, "-syntax") == 0) {
			if (argi + 1 >= argc) {
				puts("cli: syntax argument missing");
				return EXIT_FAILURE;
			}
			__gshared mainopt[] syntaxopts = [
				{ "intel", DisasmSyntax.Intel },
				{ "nasm", DisasmSyntax.Nasm },
				{ "att", DisasmSyntax.Att },
				{ "?", 255 },
			];
			const(char) *syntax = argv[++argi];
			foreach (ref mainopt o; syntaxopts) {
				if (strcmp(syntax, o.name) == 0) {
					if (o.i32 == 255)
						return clipage(CLIPage.syntaxes);
					disopt.syntax = o.syntax;
					continue cli;
				}
			}
			printf("Unknown syntax: '%s', query '-syntax ?' for list\n", syntax);
			return EXIT_FAILURE;
		}

		if (*argv[argi] != '-') { // default arguments
			if (opt.file == null) {
				opt.debugtype = DebuggerMode.file;
				opt.file = argv[argi];
			} 
			continue;
		}

		if (strcmp(arg, "-version") == 0)
			return cliver;
		if (strcmp(arg, "h") == 0 || strcmp(arg, "-help") == 0)
			return clipage(CLIPage.main);
		if (strcmp(arg, "-license") == 0)
			return clipage(CLIPage.license);
		if (strcmp(arg, "-meow") == 0)
			return clipage(CLIPage.surprise);

		printf("unknown option: %s\n", arg);
		return EXIT_FAILURE;
	}

	int e = void;
	with (CLIOpMode)
	final switch (opt.mode) {
	case debug_:
		with (DebuggerMode)
		switch (opt.debugtype) {
		case file: e = adbg_load(opt.file, null, opt.argv, null, 0); break;
		case pid: e = adbg_attach(opt.pid, 0); break;
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
