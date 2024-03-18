/// Command line interface.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module main;

import adbg.platform;
import adbg.include.c.stdlib : exit;
import adbg.include.d.config : GDC_VERSION, GDC_EXCEPTION_MODE, LLVM_VERSION;
import adbg.debugger.exception : adbg_exception_t, adbg_exception_name;
import adbg.self;
import adbg.object.machines : adbg_machine_default;
import adbg.disassembler;
import adbg.error;
import adbg.debugger.process;
import core.stdc.stdlib : strtol, EXIT_SUCCESS, EXIT_FAILURE;
import core.stdc.string : strcmp;
import core.stdc.stdio;
import common, dumper, shell;
import utils : unformat64;

private:
extern (C):

enum COPYRIGHT = "Copyright (c) 2019-2024 dd86k <dd@dax.moe>";

__gshared immutable(char) *page_license =
COPYRIGHT~`
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

enum __D_VERSION__ = DSTRVER!__VERSION__;

//NOTE: The CLI module is meh, waiting on some betterC getopt

// if asking for help, so '?' and "help" are accepted
bool wantsHelp(const(char) *query) {
	if (query[0] == '?') return true;
	
	return strcmp(query, "help") == 0;
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
//TODO: --dump-blob-offset/--dump-blob-seek/--dump-blob-start: Starting offset for raw blob
//TODO: --dump-length/--dump-end: Length or end
//TODO: --dump-imports-all: Dependency walker
//TODO: --dump-section=name: Hex or raw dump section
//TODO: --dump-stats: File statistics?
//                    pdb: stream count, positions, etc.
immutable option_t[] options = [
	// general
	{ 'a', "arch",   "Select architecture for disassembler (default=platform)", true, fa: &cli_march },
	{ 's', "syntax", "Select disassembler syntax (default=platform)", true, fa: &cli_syntax },
	// debugger
	{ 0,   "file",   "Debugger: Spawn FILE for debugging", true, fa: &cli_file },
	{ 0,   "args",   "Debugger: Supply arguments to executable", true, fa: &cli_args },
	{ 'E', "env",    "Debugger: Supply environment variables to executable", true, fa: &cli_env },
	{ 'p', "attach", "Debugger: Attach to Process ID", true, fa: &cli_pid },
	// dumper
	{ 'D', "dump",              "Aliased to --dump-headers", false, &cli_dump_headers },
	{ 0,   "dump-headers",      "Dump object's headers", false, &cli_dump_headers },
	{ 0,   "dump-sections",     "Dump object's sections", false, &cli_dump_sections },
	{ 0,   "dump-imports",      "Dump object's import information", false, &cli_dump_imports },
	{ 0,   "dump-exports",      "Dump object's export information", false, &cli_dump_exports },
	{ 0,   "dump-loadcfg",      "Dump object's load configuration", false, &cli_dump_loadcfg },
//	{ 0,   "dump-source",       "Dump object's source with disassembly", false, &cli_dump_source },
	{ 0,   "dump-relocs",       "Dump object's relocations", false, &cli_dump_reloc },
	{ 0,   "dump-debug",        "Dump object's debug information", false, &cli_dump_debug },
	{ 0,   "dump-everything",        "Dump everything except disassemblyn", false, &cli_dump_everything },
	{ 0,   "dump-disassembly",       "Dump object's disassembly", false, &cli_dump_disasm },
	{ 0,   "dump-disassembly-all",   "Dump object's disassembly for all sections", false, &cli_dump_disasm_all },
	{ 0,   "dump-disassembly-stats", "Dump object's disassembly statistics for executable sections", false, &cli_dump_disasm_stats },
	{ 0,   "dump-as-blob",      "Dump as raw binary blob", false, &cli_dump_blob },
	{ 0,   "dump-origin",       "Mark base address for disassembly", true, fa: &cli_dump_disasm_org },
	// pages
	{ 'h', "help",	"Show this help screen and exit", false, &cli_help },
	{ 0,   "version",	"Show the version screen and exit", false, &cli_version },
	{ 0,   "build-info",	"Show the build and debug information and exit", false, &cli_debug_version },
	{ 0,   "ver",	"Show only the version string and exit", false, &cli_ver },
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
			globals.machine = p.val;
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
			globals.syntax = syntax.val;
			return EXIT_SUCCESS;
		}
	}
	return EXIT_FAILURE;
}

//
// ANCHOR --file
//

int cli_file(const(char) *val) {
	globals.file = val;
	return EXIT_SUCCESS;
}

//
// ANCHOR --args/--
//

int cli_args_stop(int argi, int argc, const(char) **argv) { // --
	import adbg.utils.strings : adbg_util_move;
	
	enum MAX = 16;
	__gshared const(char) *[MAX] args;
	
	globals.args = cast(const(char)**)args;
	
	int left = argc - argi; /// to move
	void **s = cast(void**)(argv+argi);
	
	int m = adbg_util_move(
		cast(void**)&globals.args, MAX,
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
	
	globals.args = cast(const(char)**)argv;
	return EXIT_SUCCESS;
}

//
// ANCHOR -E, --env
//

int cli_env(const(char) *val) {
	import adbg.utils.strings : adbg_util_env;
	
	globals.env = cast(const(char)**)adbg_util_env(val);
	
	if (globals.env == null) {
		printf("main: Parsing environment failed");
		return EXIT_FAILURE;
	}
	
	return EXIT_SUCCESS;
}

//
// ANCHOR --attach
//

int cli_pid(const(char) *val) {
	globals.pid = cast(ushort)strtol(val, null, 10);
	return EXIT_SUCCESS;
}

//
// ANCHOR -A/--analyze
//

int cli_analyze() {
	globals.mode = SettingMode.analyze;
	return EXIT_SUCCESS;
}

//
// ANCHOR --dump-*
//

// Dump selectors

int cli_dump_headers() {
	globals.mode = SettingMode.dump;
	globals.dump_selections |= DumpSelect.headers;
	return 0;
}
int cli_dump_sections() {
	globals.mode = SettingMode.dump;
	globals.dump_selections |= DumpSelect.sections;
	return 0;
}
int cli_dump_imports() {
	globals.mode = SettingMode.dump;
	globals.dump_selections |= DumpSelect.imports;
	return 0;
}
int cli_dump_exports() {
	globals.mode = SettingMode.dump;
	globals.dump_selections |= DumpSelect.exports;
	return 0;
}
int cli_dump_loadcfg() {
	globals.mode = SettingMode.dump;
	globals.dump_selections |= DumpSelect.loadcfg;
	return 0;
}
int cli_dump_reloc() {
	globals.mode = SettingMode.dump;
	globals.dump_selections |= DumpSelect.relocs;
	return 0;
}
int cli_dump_debug() {
	globals.mode = SettingMode.dump;
	globals.dump_selections |= DumpSelect.debug_;
	return 0;
}
int cli_dump_disasm() {
	globals.mode = SettingMode.dump;
	globals.dump_selections |= DumpSelect.disasm;
	return 0;
}
int cli_dump_disasm_all() {
	globals.mode = SettingMode.dump;
	globals.dump_selections |= DumpSelect.disasm_all;
	return 0;
}
int cli_dump_disasm_stats() {
	globals.mode = SettingMode.dump;
	globals.dump_selections |= DumpSelect.disasm_stats;
	return 0;
}

int cli_dump_everything() {
	globals.mode = SettingMode.dump;
	globals.dump_selections |= DumpSelect.all_but_disasm;
	return 0;
}

// Dump options

int cli_dump_blob() {
	globals.mode = SettingMode.dump;
	globals.dump_options |= DumpOptions.raw;
	return 0;
}
int cli_dump_disasm_org(const(char) *val) {
	return unformat64(&globals.dump_base_address, val);
}

//
// ANCHOR --help
//

int cli_help() {
	puts(
	"alicedbg\n"~
	"Aiming to be a simple debugger.\n"~
	"\n"~
	"USAGE\n"~
	"  Spawn new process to debug:\n"~
	"    alicedbg FILE [OPTIONS...]\n"~
	"  Attach debugger to existing process:\n"~
	"    alicedbg --attach PID [OPTIONS...]\n"~
	"  Dump executable image headers:\n"~
	"    alicedbg --dump FILE [OPTIONS...]\n"~
	"  Show information page and exit:\n"~
	"    alicedbg {-h|--help|--version|--ver|--license}\n"~
	"\n"~
	"OPTIONS"
	);
	foreach (option_t opt; options[0..$-NUMBER_OF_SECRETS]) {
		if (opt.alt)
			printf(" -%c, --%-17s %s\n", opt.alt, opt.val, opt.desc);
		else
			printf("     --%-17s %s\n", opt.val, opt.desc);
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

int cli_debug_version() {
	__gshared immutable(char) *page =
	"Compiler    "~__VENDOR__~" "~__D_VERSION__~"\n"~
	"Target      "~TARGET_TRIPLE~"\n"~
	"Object      "~TARGET_OBJFMT~"\n"~
	"FPU         "~TARGET_FLTABI~"\n"~
	"CppRT       "~TARGET_CPPRT~"\n"~
	"Config     "~D_FEATURES;
	puts(page);
	
	static if (GDC_VERSION) {
		printf("GCC         %d\n", GDC_VERSION);
		printf("GDC-EH      %s\n", GDC_EXCEPTION_MODE);
	}
	
	version (CRuntime_Glibc) {
		import adbg.include.c.config : gnu_get_libc_version;
		printf("Glibc       %s\n", gnu_get_libc_version());
	}
	
	static if (LLVM_VERSION)
		printf("LLVM        %d\n", LLVM_VERSION);
	
	import adbg.include.capstone : libcapstone_dynload, cs_version;
	printf("Capstone    ");
	if (libcapstone_dynload()) {
		puts("error");
	} else {
		int major = void, minor = void;
		cs_version(&major, &minor);
		printf("%d.%d\n", major, minor);
	}
	
	exit(0);
	return 0;
}

int cli_version() {
	__gshared immutable(char) *page_version =
	"alicedbg    "~FULL_VERSION~"\n"~
	"            Built "~__TIMESTAMP__~"\n"~
	"            "~COPYRIGHT~"\n"~
	"License     BSD-3-Clause-Clear\n"~
	"            <https://opensource.org/licenses/BSD-3-Clause-Clear>\n"~
	"Homepage    https://git.dd86k.space/dd86k/alicedbg";
	
	puts(page_version);
	
	exit(0);
	return 0;
}
int cli_ver() {
	puts(FULL_VERSION);
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
+-------------------+
| I hate x86, meow. |
+---  --------------+
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

//
// Main
//

//TODO: Support --option=value syntax

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
		if (dis && adbg_dis_process_once(dis, &op, self, ex.fault_address) == 0) {
			// Print address
			printf("Instruction:");
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
			printf(" Unavailable (%s)\n", adbg_error_msg());
		}
	}
}

int main(int argc, const(char)** argv) {
	// Set crash handle, and ignore on error
	// Could do a warning, but it might be a little confusing
	adbg_self_set_crashhandler(&crash_handler);
	
	const(char) *arg = void;
	const(char) *val = void;
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
					printf("main: '%s' is an invalid value for --%s\n", val, argLong);
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
					printf("main: '%s' is an invalid value for -%c\n", val, argShort);
					return EXIT_FAILURE;
				}
				continue CLI;
			}
		} else if (globals.file == null) { // Default option value
			globals.file = arg;
			continue CLI;
		}
		
		printf("main: unknown option '%s'\n", arg);
		return EXIT_FAILURE;
	}
	
	switch (globals.mode) {
	case SettingMode.dump: return app_dump();
	case SettingMode.debugger:
		return shell_loop;
	default: assert(0, "Implement SettingMode");
	}
}
