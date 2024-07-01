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
import adbg.debugger.process : adbg_process_t;
import core.stdc.stdlib : EXIT_FAILURE;
import core.stdc.stdio;
import dumper;
import common.errormgmt;
import common.cli;
import common.utils : unformat64;

private:

//TODO: --dump-blob-offset/--dump-blob-seek/--dump-blob-start: Starting offset for raw blob
//TODO: --dump-length/--dump-end: Length or end
//TODO: --dump-stats: File statistics?
//                    pdb: stream count, positions, etc.
//TODO: --type-only: Returns short-name only for identification purposes
//TODO: --name: Extract by section, import, export name (will replace --section?)
//TODO: --all (to complement --headers)
immutable option_t[] options = [
	// secrets
	option_t(0,   "woof", null, &cliopt_woof),
	// common options
	option_arch,
	option_syntax,
	// selections
	option_t('H', "headers",      "Dump headers", &cliopt_headers),
	option_t('S', "sections",     "Dump sections", &cliopt_sections),
	option_t(0,   "section",      "Dump section by name", &cliopt_section),
	option_t(0,   "segments",     "Dump segments", &cliopt_segments),
	option_t('I', "imports",      "Dump import information", &cliopt_imports),
	option_t('E', "exports",      "Dump export information", &cliopt_exports),
//	option_t(0,   "loadcfg",      "Dump load configuration", &cliopt_loadcfg),
//	option_t(0,   "source",       "Dump source with disassembly", &cliopt_source),
	option_t(0,   "relocs",       "Dump relocations", &cliopt_relocs),
	option_t(0,   "debug",        "Dump debug information", &cliopt_debug),
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
	option_t('h', "help", "Show this help screen and exit", &cliopt_help),
	option_version,
	option_build_info,
	option_ver,
	option_license,
];
enum NUMBER_OF_SECRETS = 1;

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
int cliopt_segments() {
	opt_selected |= Select.segments;
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

int cliopt_help() {
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
	getoptprinter(options[NUMBER_OF_SECRETS..$]);
	exit(0);
	return 0;
}

int cliopt_woof() {
	puts(
r"
+---------------------+         ,
| Are you SystemReady |   .__,-/|
| compliant yet? Woof |    \_ ` \
+---------------------+      `====
                              {   \
                               \ / \
                               ///  `\ /
                              //_\   /`
"
	);
	exit(0);
	return 0;
}

extern (C)
int main(int argc, const(char)** argv) {
	// Set crash handle, and ignore on error
	// Could do a warning, but it might be a little confusing
	adbg_self_set_crashhandler(&crashed);
	
	int e = getoptions(argc, argv, options);
	if (e < 0) {
		puts(getopterror());
		return EXIT_FAILURE;
	}
	if (e == 0) {
		puts("error: No file specified");
		return EXIT_FAILURE;
	}
	
	return dump_file(*getoptleftovers()); // First argument as file
}
