/**
 * Image/object dumper, imitates objdump
 *
 * License: BSD-3-Clause
 */
module dumper;

import core.stdc.stdio;
import core.stdc.stdlib : EXIT_SUCCESS, EXIT_FAILURE, malloc;
import adbg.error;
import adbg.disasm, adbg.obj.server;
import adbg.obj.server;
import common, objects;

extern (C):

/// Bitfield. Selects which information to display.
enum DumpOpt {
	/// Dump header
	header	= 1,
	/// Dump directories (PE32)
	dirs	= 1 << 1,
	/// Exports
	exports	= 1 << 2,
	/// Imports
	imports	= 1 << 3,
	/// Images, certificates, etc.
	resources	= 1 << 4,
	/// Structured Exception Handler
	seh	= 1 << 5,
	/// Symbol table(s)
	symbols	= 1 << 6,
	/// Debugging table
	debug_	= 1 << 7,
	/// Thread Local Storage
	tls	= 1 << 8,
	/// Load configuration
	loadcfg	= 1 << 9,
	/// Sections
	sections	= 1 << 10,
	/// Relocations
	relocs	= 1 << 11,
	
	/// Disassemble executable sections
	disasm	= 1 << 22,
	/// Disassembly statistics
	stats	= 1 << 23,
	/// Disassemble all sections
	disasm_all	= 1 << 24,
	
	/// File is raw, do not auto-detect
	raw	= 1 << 31,
	
	/// Display absolutely everything
	everything	= header | dirs |resources | seh |
		symbols | debug_ | tls | loadcfg |
		exports | imports | sections,
}

/// Output a dump title.
/// Params: title = Title
void dump_title(const(char) *title) {
	printf("%s format\n", title);
}

/// Output a dump chapter.
/// Params: c = Chapter name
void dump_chapter(const(char) *title) {
	printf("\n# %s\n\n", title);
}

/// Dump given file to stdout.
/// Params:
/// 	file = File path
/// 	dp = Disassembler settings
/// 	flags = Dumper options
/// Returns: Error code if non-zero
int dump(const(char) *file, adbg_disasm_t *dp, int flags) {
	FILE *f = fopen(file, "rb"); // Handles null file pointers
	if (f == null) {
		perror(__FUNCTION__);
		return EXIT_FAILURE;
	}

	if (flags & DumpOpt.raw) {
		if (fseek(f, 0, SEEK_END)) {
			perror(__FUNCTION__);
			puts("dump: could not seek file");
			return EXIT_FAILURE;
		}
		uint fl = cast(uint)ftell(f);
		fseek(f, 0, SEEK_SET); // rewind binding is broken

		void *m = malloc(fl + 16);
		if (m == null)
			return EXIT_FAILURE;
		if (fread(m, fl, 1, f) == 0) {
			perror(__FUNCTION__);
			return EXIT_FAILURE;
		}

		return dump_disasm(dp, m, fl, flags);
	}

	// When nothing is set, the default is to show headers
	if ((flags & 0xFF_FFFF) == 0)
		flags |= DumpOpt.header;

	adbg_object_t obj = void;
	if (adbg_obj_open_file(&obj, f)) {
		printerror;
		return 1;
	}

	if (dp.platform == AdbgDisasmPlatform.native)
		dp.platform = obj.platform;

	with (AdbgObjFormat)
	switch (obj.format) {
	case MZ: return dump_mz(&obj, dp, flags);
	case PE: return dump_pe(&obj, dp, flags);
	default:
		puts("dumper: format not supported");
		return EXIT_FAILURE;
	}
}

//TODO: Consider "dump_value" functions
//      dump_value(field, value)
//      dump_value_extra_x32(field, value, number)
//      dump_value_extra_string(field, value, string)

// NOTE: Normally, a FILE* parameter could be passed, but the Windows bindings
//       often do not correspond to their CRT equivalent, so this is hard-wired
//       to stdout, since this is only for the dumping functionality.
/// Disassemble data to stdout
/// Params:
/// 	dp = Disassembler parameters
/// 	data = Data pointer
/// 	size = Data size
/// 	flags = Configuration flags
/// Returns: Status code
int dump_disasm(adbg_disasm_t *dp, void* data, uint size, int flags) {
	dp.a = data;
	if (flags & DumpOpt.stats) {
		uint iavg;	/// instruction average size
		uint imax;	/// longest instruction size
		uint icnt;	/// instruction count
		uint ills;	/// Number of illegal instructions
		for (uint i, isize = void; i < size; i += isize) {
			AdbgError e = cast(AdbgError)adbg_disasm(dp, AdbgDisasmMode.size);
			isize = cast(uint)(dp.av - dp.la);
			with (AdbgError)
			switch (e) {
			case none:
				iavg += isize;
				++icnt;
				if (isize > imax)
					imax = isize;
				break;
			case illegalInstruction:
				iavg += isize;
				++icnt;
				++ills;
				break;
			default:
				printf("disasm: %s\n", adbg_error_msg);
				return e;
			}
		}
		printf(
		"Instruction statistics\n"~
		"avg. size: %.3f\n"~
		"max. size: %u\n"~
		"illegal  : %u\n"~
		"total    : %u\n",
		cast(float)iavg / icnt, imax, ills, icnt
		);
	} else {
		for (uint i; i < size; i += dp.av - dp.la) {
			AdbgError e = cast(AdbgError)adbg_disasm(dp, AdbgDisasmMode.file);
			with (AdbgError)
			switch (e) {
			case none:
				printf("%08X %-30s %s\n",
					i, dp.mcbuf.ptr, dp.mnbuf.ptr);
				continue;
			case illegalInstruction:
				printf("%08X %-30s (error)\n",
					i, dp.mcbuf.ptr);
				continue;
			default:
				printf("disasm: %s\n", adbg_error_msg);
				return e;
			}
		}
	}
	return 0;
}
