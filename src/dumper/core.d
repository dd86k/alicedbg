/**
 * Image/object dumper, imitates objdump
 *
 * License: BSD 3-Clause
 */
module dumper.core;

import core.stdc.stdio;
import core.stdc.config : c_long;
import core.stdc.stdlib : EXIT_SUCCESS, EXIT_FAILURE, malloc, realloc;
import debugger.disasm, debugger.obj.loader, dumper.objs;

extern (C):

enum { // Dumper flags (-show)
	//
	// Loader flags (settings)
	//

	///TODO: Load file entirely in memory
	DUMPER_LOADER_FILE_MEM	= LOADER_FILE_MEM,

	//
	// Dumper flags (settings)
	//

	/// ("-raw") File is raw, do not attempt to detect its format,
	/// disassembly only
	DUMPER_FILE_RAW	= 0x0100,
	///TODO: Do not format instructions. Instead, show disassembler statistics.
	/// Statistics include number of instructions, average instruction length,
	/// minimum instruction length, maximum instruction length, and its total
	/// size.
	DUMPER_FILE_DISASM_STATS	= 0x0200,
	///TODO: ('r') Show information raw (hexadecimal dumps) only. Affects
	/// resource exports as well.
	DUMPER_SHOW_RAW	= 0x8000,

	//
	// Show flags
	//

	/// ('h') Include headers (image headers, optional headers,
	/// directories) in output.
	DUMPER_SHOW_HEADERS	= 0x0001_0000,
	/// ('s') Include sections in output.
	DUMPER_SHOW_SECTIONS	= 0x0002_0000,
	/// ('i') Include imports in output. This includes dynamic libraries
	/// such as DLL files (for Window: Import Directory) and SO files.
	DUMPER_SHOW_IMPORTS	= 0x0004_0000,
	///TODO: ('e') Include exports in output.
	DUMPER_SHOW_EXPORTS	= 0x0008_0000,
	/// ('m') Include symbols in output.
	DUMPER_SHOW_SYMBOLS	= 0x0010_0000,
	/// ('l') Include load configuration.
	DUMPER_SHOW_LOADCFG	= 0x0020_0000,
	// ('') 
//	DUMPER_SHOW_	= 0x0040_0000,
	// ('') 
//	DUMPER_SHOW_	= 0x0080_0000,
	/// ('d') Include section disassembly in output.
	DUMPER_SHOW_DISASSEMBLY	= 0x0100_0000,
	/// ('A') Include everything in output.
	DUMPER_SHOW_EVERYTHING	= 0x0FFF_0000,

	//
	// Export flags
	//

	// These are more options that are unaffected by "show everything"
	///TODO: ('o') Export resources into current directory. This includes
	/// icons and images.
	DUMPER_EXPORT_RESOURCES	= 0x1000_0000,
	///TODO: ('c') Export certificates into current directory.
	DUMPER_EXPORT_CERTS	= 0x2000_0000,
}

/// This struct exists avoid casting all the time
struct uptr_t {
	union {
		size_t val;
		void   *vptr;
		ubyte  *u8ptr;
		ushort *u16ptr;
		uint   *u32ptr;
		ulong  *u64ptr;
	}
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

	// When nothing is set, the default is to show headers
	if ((flags & DUMPER_SHOW_EVERYTHING) == 0) {
		flags = DUMPER_SHOW_HEADERS;
	}

	obj_info_t finfo = void;
	if (obj_load(f, &finfo, 0)) {
		puts("loader: could not load file");
		return EXIT_FAILURE;
	}

	if (dp.isa == DisasmISA.Default)
		dp.isa = finfo.isa;

	with (ObjType)
	switch (finfo.type) {
	case PE: return dumper_print_pe32(&finfo, dp, flags);
	default:
		puts("loader: format not supported");
		return EXIT_FAILURE;
	}
}
