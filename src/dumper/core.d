/**
 * Image/object dumper, imitates objdump
 *
 * License: BSD 3-Clause
 */
module dumper.core;

import core.stdc.stdio;
import core.stdc.config : c_long;
import core.stdc.stdlib : EXIT_SUCCESS, EXIT_FAILURE, malloc, realloc;
import debugger.disasm, debugger.file.loader, dumper.objs;

extern (C):

enum { // Dumper flags (-show)
	/// File is raw, do not attempt to detect its format
	DUMPER_FILE_RAW	= 1,
	/// Include headers (image headers, optional headers, directories) in
	/// output.
	DUMPER_SHOW_HEADERS	= 0x0100,
	/// Include sections in output.
	DUMPER_SHOW_SECTIONS	= 0x0200,
	/// Include imports in output. This includes dynamic libraries such as
	/// DLL files (for Windows, under `.rdata`) and SO files.
	DUMPER_SHOW_IMPORTS	= 0x0400,
	/// 
	//DUMPER_SHOW_EXPORTS	= 0x0400,
	/// Include symbols in output.
	DUMPER_SHOW_SYMBOLS	= 0x1000,
	/// Include section disassembly in output.
	DUMPER_SHOW_DISASSEMBLY	= 0x8000,
	/// Include everything in output
	DUMPER_SHOW_EVERYTHING	= 0xFF00,
	//TODO: flag to export resources/certs
	//DUMPER_EXPORT_RESOURCES	= 0x01_0000,
}

/// Disassemble given file to stdout. Currently only supports flat binary
/// files.
/// Params:
/// 	file = File path
/// 	disopt = Disassembler settings
/// 	flags = Dumper options
/// Returns: Error code if non-zero
int dump_file(const(char) *file, disasm_params_t *dp, int flags) {
	if (file == null) {
		puts("dump: file is null");
		return EXIT_FAILURE;
	}
	FILE *f = fopen(file, "rb");
	if (f == null) {
		puts("dump: could not open file");
		return EXIT_FAILURE;
	}

	if (flags & DUMPER_FILE_RAW) {
		if (fseek(f, 0, SEEK_END)) {
			puts("dump: could not seek file");
			return EXIT_FAILURE;
		}
		c_long fl = ftell(f);
		fseek(f, 0, SEEK_SET); // rewind is broken

		void *m = cast(void*)malloc(fl);
		if (fread(m, fl, 1, f) == 0) {
			puts("cli: could not read file");
			return EXIT_FAILURE;
		}

		dp.addr = m;
		for (c_long fi; fi < fl; fi += dp.addrv - dp.lastaddr) {
			disasm_line(dp, DisasmMode.File);
			printf("%08X %-30s %-30s\n",
				cast(uint)fi,
				&dp.mcbuf, &dp.mnbuf);
		}
		return EXIT_SUCCESS;
	}

	file_info_t finfo = void;
	if (file_load(f, &finfo, 0)) {
		puts("loader: could not load file");
		return EXIT_FAILURE;
	}

	if (dp.isa == DisasmISA.Default)
		dp.isa = finfo.isa;

	with (FileType)
	switch (finfo.type) {
	case PE: return dumper_print_pe32(&finfo, dp, flags);
	default:
		puts("loader: format not supported");
		return EXIT_FAILURE;
	}
}
