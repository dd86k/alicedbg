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
import adbg.machines : adbg_machine_default;
import adbg.disassembler;
import adbg.error;
import adbg.debugger.process;
import core.stdc.stdlib : strtol, EXIT_SUCCESS, EXIT_FAILURE;
import core.stdc.string : strcmp;
import core.stdc.stdio;
import dumper;
import common.cli;
import common.utils : unformat64;

private:

//TODO: --dump-blob-offset/--dump-blob-seek/--dump-blob-start: Starting offset for raw blob
//TODO: --dump-length/--dump-end: Length or end
//TODO: --dump-imports-all: Dependency walker
//TODO: --dump-section=name: Hex or raw dump section
//TODO: --dump-stats: File statistics?
//                    pdb: stream count, positions, etc.
//TODO: --demangle
//TODO: --type-only: Returns short-name only for identification purposes
immutable option_t[] options = [
	// common options
	option_arch,
	option_syntax,
	// selections
	option_t('H', "headers",      "Dump object's headers", &cliopt_headers),
	option_t(0,   "section",      "Dump object's section by name", &cliopt_section),
	option_t('S', "sections",     "Dump object's sections", &cliopt_sections),
	option_t('I', "imports",      "Dump object's import information", &cliopt_imports),
	option_t('E', "exports",      "Dump object's export information", &cliopt_exports),
//	option_t(0,   "loadcfg",      "Dump object's load configuration", &cliopt_loadcfg),
//	option_t(0,   "source",       "Dump object's source with disassembly", &cliopt_source),
	option_t(0,   "relocs",       "Dump object's relocations", &cliopt_relocs),
	option_t(0,   "debug",        "Dump object's debug information", &cliopt_debug),
	option_t(0,   "everything",   "Dump everything except disassembly", &cliopt_everything),
	// settings
	option_t(0,   "as-blob",           "Setting: Input is headless binary blob", &cliopt_as_blob),
	option_t(0,   "disassemble",       "Setting: Disassemble executable sections", &cliopt_disasm),
	option_t(0,   "disassemble-all",   "Setting: Disassemble all sections", &cliopt_disasm_all),
	option_t(0,   "disassemble-stats", "Setting: Provide disassembly statistics", &cliopt_disasm_stats),
	option_t(0,   "origin",            "Setting: Mark base address for disassembly", &cliopt_origin),
	option_t(0,   "extract",           "Setting: Output selected portion to stdout", &cliopt_extract),
	option_t(0,   "extract-to",        "Setting: Output selected portion to file", &cliopt_extract_to),
	option_t(0,   "hexdump",           "Setting: Output selected portion to stdout as hexdump", &cliopt_hexdump),
	// pages
	option_t('h', "help", "Show this help screen and exit", &cli_help),
	option_version,
	option_build_info,
	option_ver,
	option_license,
];

//
// Selections
//

int cliopt_headers() {
	opt_selected |= Select.headers;
	return 0;
}
int cliopt_section(const(char) *val) {
	opt_selected |= Select.sections;
	opt_section_name = val;
	return 0;
}
int cliopt_sections() {
	opt_selected |= Select.sections;
	return 0;
}
int cliopt_imports() {
	opt_selected |= Select.imports;
	return 0;
}
int cliopt_exports() {
	opt_selected |= Select.exports;
	return 0;
}
int cliopt_loadcfg() {
	opt_selected |= Select.loadcfg;
	return 0;
}
int cliopt_relocs() {
	opt_selected |= Select.relocs;
	return 0;
}
int cliopt_debug() {
	opt_selected |= Select.debug_;
	return 0;
}

int cliopt_everything() {
	opt_selected |= Select.all;
	return 0;
}

//
// Settings
//

int cliopt_as_blob() {
	opt_settings |= Setting.blob;
	return 0;
}
int cliopt_disasm() {
	opt_settings |= Setting.disasm;
	return 0;
}
int cliopt_disasm_all() {
	opt_settings |= Setting.disasmAll;
	return 0;
}
int cliopt_disasm_stats() {
	opt_settings |= Setting.disasmStats;
	return 0;
}
int cliopt_origin(const(char) *val) {
	return unformat64(&opt_baseaddress, val);
}

int cliopt_extract() {
	opt_settings |= Setting.extract;
	return 0;
}
int cliopt_extract_to(const(char)* fname) {
	opt_settings |= Setting.extract;
	opt_extractfile = fname;
	return 0;
}
int cliopt_hexdump() {
	opt_settings |= Setting.hexdump;
	return 0;
}

//
// ANCHOR --help
//

int cli_help() {
	puts(
	"alicedump: Binary object dumper.\n"~
	"\n"~
	"USAGE\n"~
	"  Summarize object file:\n"~
	"    alicedbg [OPTIONS...] FILE\n"~
	"  Dump headers:\n"~
	"    alicedbg {-H|--headers} [OPTIONS...] FILE\n"~
	"  Show information page and exit:\n"~
	"    alicedbg {-h|--help|--version|--ver|--license}\n"~
	"\n"~
	"OPTIONS"
	);
	getoptprinter(options);
	exit(0);
	return 0;
}

extern (C)
void crash_handler(adbg_exception_t *ex) {
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
	
	exit(ex.oscode);
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
	
	return dump(*getoptrem()); // First argument as file
}
