/**
 * Image/object dumper, imitates objdump
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: See LICENSE
 * License: BSD-3-Clause
 */
module dumper;

import core.stdc.stdio;
import core.stdc.stdlib : EXIT_SUCCESS, EXIT_FAILURE, malloc;
import adbg.error;
import adbg.disasm, adbg.obj.server;
import adbg.obj.server;
import adbg.utils.bit : BIT;
import common, objects;

extern (C):

/// Bitfield. Selects which information to display.
enum DumpOpt {
	/// 'h' - Dump header
	header	= BIT!(0),
	/// 'd' - Dump directories (PE32)
	dirs	= BIT!(1),
	/// 'e' - Exports
	exports	= BIT!(2),
	/// 'i' - Imports
	imports	= BIT!(3),
	/// 'c' - Images, certificates, etc.
	resources	= BIT!(4),
	/// 't' - Structured Exception Handler
	seh	= BIT!(5),
	/// 't' - Symbol table(s)
	symbols	= BIT!(6),
	/// 'T' - Dynamic symbol table
	dynsymbols	= BIT!(7),
	/// 'g' - Debugging material
	debug_	= BIT!(8),
	/// 'o' - Thread Local Storage
	tls	= BIT!(9),
	/// 'l' - Load configuration
	loadcfg	= BIT!(10),
	/// 's' - Sections
	sections	= BIT!(11),
	/// 'r' - Relocations
	relocs	= BIT!(12),
	/// 'R' - Dynamic relocations
	dynrelocs	= BIT!(13),
	
	/// Disassemble executable sections
	disasm_code	= BIT!(22),
	/// Disassembly statistics
	disasm_stats	= BIT!(23),
	/// Disassemble all sections
	disasm_all	= BIT!(24),
	
	/// File is raw, do not auto-detect
	raw	= BIT!(31),
	
	/// Display all metadata except disassembly
	everything = header | dirs | resources | seh |
		symbols | debug_ | tls | loadcfg |
		exports | imports | sections,
	
	/// Wants to disassemble at least something
	disasm = disasm_code | disasm_stats | disasm_all,
}

/// dump structure
struct dump_t {
	adbg_object_t *obj; /// object
	adbg_disasm_t *dopts; /// disasm options
	int flags; /// display settings
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
/// 	dopts = Disassembler settings
/// 	flags = Dumper options
/// Returns: Error code if non-zero
int dump(const(char) *file, adbg_disasm_t *dopts, int flags) {
	FILE *f = fopen(file, "rb"); // Handles null file pointers
	if (f == null) {
		perror(__FUNCTION__.ptr);
		return EXIT_FAILURE;
	}
	
	if (flags & DumpOpt.raw) {
		if (fseek(f, 0, SEEK_END)) {
			perror(__FUNCTION__.ptr);
			puts("dump: could not seek file");
			return EXIT_FAILURE;
		}
		uint fl = cast(uint)ftell(f);
		fseek(f, 0, SEEK_SET); // rewind binding is broken
		
		void *m = malloc(fl + 16);
		if (m == null)
			return EXIT_FAILURE;
		if (fread(m, fl, 1, f) == 0) {
			perror(__FUNCTION__.ptr);
			return EXIT_FAILURE;
		}
		
		return dump_disasm(dopts, m, fl, flags);
	}
	
	adbg_object_t obj = void;
	
	// Load object into memory
	if (adbg_obj_open_file(&obj, f)) {
		printerror;
		return 1;
	}
	
	// When nothing is set, the default is to show headers
	if ((flags & 0xFF_FFFF) == 0)
		flags |= DumpOpt.header;
	
	if (dopts.platform == AdbgDisasmPlatform.native)
		dopts.platform = obj.platform;
	
	dump_t dump = void;
	dump.obj = &obj;
	dump.dopts = dopts;
	dump.flags = flags;
	
	with (AdbgObjFormat)
	switch (dump.obj.format) {
	case MZ: return dump_mz(&dump);
	case PE: return dump_pe(&dump);
	case ELF: return dump_elf(&dump);
	default:
		puts("dumper: format not supported");
		return EXIT_FAILURE;
	}
}

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
	if (flags & DumpOpt.disasm_stats) {
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
		"average instruction size: %.3f\n"~
		"maximum instruction size: %u\n"~
		"illegal instructions    : %u\n"~
		"total instructions      : %u\n",
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
