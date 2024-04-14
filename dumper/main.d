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
	// general
	option_arch,
	option_syntax,
	// dumper
	option_t('H', "headers",      "Dump object's headers", &cli_dump_headers),
	option_t(0,   "section",      "Dump object's section by name", &cli_dump_section),
	option_t('S', "sections",     "Dump object's sections", &cli_dump_sections),
	option_t('I', "imports",      "Dump object's import information", &cli_dump_imports),
	option_t('E', "exports",      "Dump object's export information", &cli_dump_exports),
//	option_t(0,   "loadcfg",      "Dump object's load configuration", &cli_dump_loadcfg),
//	option_t(0,   "source",       "Dump object's source with disassembly", &cli_dump_source),
	option_t(0,   "relocs",       "Dump object's relocations", &cli_dump_reloc),
	option_t(0,   "debug",        "Dump object's debug information", &cli_dump_debug),
	option_t(0,   "everything",        "Dump everything except disassembly", &cli_dump_everything),
	option_t(0,   "disassembly",       "Dump object's disassembly", &cli_dump_disasm),
	option_t(0,   "disassembly-all",   "Dump object's disassembly for all sections", &cli_dump_disasm_all),
	option_t(0,   "disassembly-stats", "Dump object's disassembly statistics for executable sections", &cli_dump_disasm_stats),
	option_t(0,   "as-blob",      "Dump as raw binary blob", &cli_dump_blob),
	option_t(0,   "origin",       "Mark base address for disassembly", &cli_dump_disasm_org),
	// pages
	option_t('h', "help", "Show this help screen and exit", &cli_help),
	option_version,
	option_build_info,
	option_ver,
	option_license,
];

int cli_dump_headers() {
	opt_selected |= Select.headers;
	return 0;
}
int cli_dump_section(const(char) *val) {
	opt_selected |= Select.sections;
	opt_section = val;
	return 0;
}
int cli_dump_sections() {
	opt_selected |= Select.sections;
	return 0;
}
int cli_dump_imports() {
	opt_selected |= Select.imports;
	return 0;
}
int cli_dump_exports() {
	opt_selected |= Select.exports;
	return 0;
}
int cli_dump_loadcfg() {
	opt_selected |= Select.loadcfg;
	return 0;
}
int cli_dump_reloc() {
	opt_selected |= Select.relocs;
	return 0;
}
int cli_dump_debug() {
	opt_selected |= Select.debug_;
	return 0;
}
int cli_dump_disasm() {
	opt_settings |= Setting.disasm;
	return 0;
}
int cli_dump_disasm_all() {
	opt_settings |= Setting.disasmAll;
	return 0;
}
int cli_dump_disasm_stats() {
	opt_settings |= Setting.disasmStats;
	return 0;
}

int cli_dump_everything() {
	opt_selected |= Select.all;
	return 0;
}

// Dump options

int cli_dump_blob() {
	opt_settings |= Setting.blob;
	return 0;
}
int cli_dump_disasm_org(const(char) *val) {
	return unformat64(&opt_baseaddress, val);
}

//
// ANCHOR --help
//

int cli_help() {
	puts(
	"alicedump: Binary object dumper.\n"~
	"\n"~
	"USAGE\n"~
	"  Dump and summarize:\n"~
	"    alicedbg [OPTIONS...] FILE\n"~
	"  Dump headers:\n"~
	"    alicedbg --headers [OPTIONS...] FILE\n"~
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
	
	return app_dump(*args);
}
