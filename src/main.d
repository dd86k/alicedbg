import core.stdc.stdlib : strtol, EXIT_SUCCESS, EXIT_FAILURE;
import core.stdc.string : strcmp;
import core.stdc.stdio;
import consts;
import ui.loop : ui_loop;
import ui.tui : ui_tui;
import debugger.core;

extern (C):
private:

enum CLIUI {
	tui,
	loop,
	interpreter,
	json,
}

enum CLIDebug {
	undecided,
	file,
	pid
}

/// "sub-help" screen for cshow
enum CLIHelp {
	ui,
}

/// CLI options
struct cliopt_t {
	CLIUI ui;
	CLIDebug debugtype;
	union {
		ushort pid;
		const(char) *file;
	}
}

/// Help page
int chelp() {
	printf(
	"alicedbg debugger\n"~
	"Usage:\n"~
	"  alicedbg {-pid ID|-file EXEC} [OPTIONS...]\n"~
	"  alicedbg {--help|--version|--license}\n"~
	"\n"~
	"OPTIONS\n"~
	"	-file      debugger: Load executable file\n"~
	"	-pid       debugger: Attach to process id\n"~
	"	-ui        Choose UI (see -ui ? for a list of UIs)\n"
	);
	return 0;
}

/// Version page
int cversion() {
	import ver = std.compiler;
	printf(
	"alicedbg-"~__ABI__~" "~PROJECT_VERSION~"-"~__TYPE__~"  ("~__TIMESTAMP__~")\n"~
	"License: BSD 3-Clause <https://opensource.org/licenses/BSD-3-Clause>\n"~
	"Home: https://git.dd86k.space/alicedbg\n"~
	"Compiler: "~__VENDOR__~" %u.%03u, "~
		__traits(getTargetInfo, "objectFormat")~" obj format, "~
		__traits(getTargetInfo, "floatAbi")~" float abi\n"~
	"CRT: "~__CRT__~" ("~__traits(getTargetInfo,"cppRuntimeLibrary")~") on "~__OS__~"\n",
	ver.version_major, ver.version_minor
	);
	version (LDC)
		puts("CPU: "~__traits(targetCPU));
	return 0;
}

/// License page
int clicense() {
	puts(
`BSD 3-Clause License

Copyright (c) 2019, dd86k
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
	return 0;
}

/// "sub-help" pages, such as -ui ? and the rest
int cshow(CLIHelp h) {
	final switch (h) {
	case CLIHelp.ui:
		puts(
		"Available UIs (default=tui)\n"~
		"tui ....... Text UI with full debugging experience.\n"~
		"loop ...... Continues on exceptions, no user input.\n"
//		"tcp-json .. (Planned) JSON API server via TCP.\n"
		);
	break;
	}
	return 0;
}

int main(int argc, const(char) **argv) {
	if (argc <= 1)
		return chelp;

	cliopt_t opt;	/// Defaults to .init

	// CLI
	for (size_t argi = 1; argi < argc; ++argi) {
		if (argv[argi][0] != '-') continue;

		const(char) *arg = argv[argi] + 1;
		if (strcmp(arg, "-help") == 0)
			return chelp;
		if (strcmp(arg, "-version") == 0 ||
			strcmp(arg, "version") == 0)
			return cversion;
		if (strcmp(arg, "-license") == 0)
			return clicense;
		if (strcmp(arg, "exec") == 0) {
			if (argi + 1 >= argc) {
				puts("cli: file argument missing");
				return EXIT_FAILURE;
			}
			opt.debugtype = CLIDebug.file;
			opt.file = argv[++argi];
			continue;
		}
		/*
		if (strcmp(arg, "execarg") == 0) {
			
		}
		// Starting directory for file
		if (strcmp(arg, "execdir") == 0) {
			
		}*/
		if (strcmp(arg, "pid") == 0) {
			if (argi + 1 >= argc) {
				puts("cli: pid argument missing");
				return EXIT_FAILURE;
			}
			opt.debugtype = CLIDebug.pid;
			const(char) *id = argv[++argi];
			opt.pid = cast(ushort)strtol(id, &id, 10);
			continue;
		}
		if (strcmp(arg, "ui") == 0) {
			if (argi + 1 >= argc) {
				puts("cli: ui argument missing");
				return EXIT_FAILURE;
			}
			const(char) *ui = argv[++argi];
			if (strcmp(ui, "tui") == 0)
				opt.ui = CLIUI.tui;
			else if (strcmp(ui, "loop") == 0)
				opt.ui = CLIUI.loop;
			else if (strcmp(ui, "?") == 0)
				return cshow(CLIHelp.ui);
			else {
				printf("cli: ui \"%s\" not found, query \"-ui ?\" for a list\n",
					ui);
				return EXIT_FAILURE;
			}
			continue;
		}
		// Set machine architecture, affects disassembly
		/*if (strcmp(arg, "march") == 0) {
			
		}*/
		// Disassemble file
		// 
		if (strcmp(arg, "disasmdump") == 0) {
			import debugger.disasm : disasm_line, disasm_params_t,
				DISASM_I_MACHINECODE, DISASM_I_MNEMONICS;
			import core.stdc.config : c_long;
			import core.stdc.stdlib : malloc;

			if (argi + 1 >= argc) {
				puts("cli: path argument missing");
				return EXIT_FAILURE;
			}

			FILE *f = fopen(argv[++argi], "rb");

			if (f == null) {
				puts("cli: could not open file");
				return EXIT_FAILURE;
			}

			if (fseek(f, 0, SEEK_END)) {
				puts("cli: could not seek file");
				return EXIT_FAILURE;
			}
			c_long fl = ftell(f);
			fseek(f, 0, SEEK_SET); // rewind is broken

			ubyte *m = cast(ubyte*)malloc(fl);
			if (fread(m, fl, 1, f) == 0) {
				puts("cli: could not read file");
				return EXIT_FAILURE;
			}

			disasm_params_t p;
			p.include = DISASM_I_MACHINECODE | DISASM_I_MNEMONICS;
			p.addru8 = m;
			for (c_long fi; fi < fl; fi += p.addrv - p.thisaddr) {
				if (disasm_line(p)) continue;
				printf("%08X %-20s %-20s\n",
					cast(uint)fi, &p.mcbuf, &p.mnbuf);
			}

			return EXIT_SUCCESS;
		}
		// Choose demangle settings for symbols
		/*if (strcmp(arg, "demangle") == 0) {
			
		}*/
		// Choose debugging backend, currently unsupported and only
		// embedded option is available
		/*if (strcmp(arg, "backend") == 0) {
			
		}*/
	}

	int e = void;
	switch (opt.debugtype) {
	case CLIDebug.file:
		e = dbg_file(opt.file);
		if (e) {
			printf("dbg: Could not load executable (%X)\n", e);
			return e;
		}
		break;
	case CLIDebug.pid:
		e = dbg_attach(opt.pid);
		if (e) {
			printf("dbg: Could not attach to pid (%X)\n", e);
			return e;
		}
		break;
	default:
		puts("cli: No file nor pid were specified.");
		return EXIT_FAILURE;
	}

	with (CLIUI)
	switch (opt.ui) {
	case loop: return ui_loop;
	case tui: return ui_tui;
	default:
		puts("cli: No ui specified, or ui not found");
		return EXIT_FAILURE;
	}
}
