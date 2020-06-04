/**
 * Image/object dumper, imitates objdump
 *
 * License: BSD 3-Clause
 */
module adbg.dumper.dumper;

import core.stdc.stdio;
import core.stdc.config : c_long;
import core.stdc.stdlib : EXIT_SUCCESS, EXIT_FAILURE, malloc, realloc;
import adbg.debugger.disasm, adbg.dumper.objs;
public import adbg.debugger.obj.loader;

extern (C):

enum {
	//
	// Dumper flags
	//
	DUMPER_SHOW_HEADER	= 0x0001,
	DUMPER_SHOW_EXPORTS	= 0x0002,
	DUMPER_SHOW_IMPORTS	= 0x0004,
	DUMPER_SHOW_RESOURCES	= 0x0008,
	DUMPER_SHOW_SEH	= 0x0010,
	DUMPER_SHOW_CERTS	= 0x0020,
	DUMPER_SHOW_RELOCS	= 0x0040,
	DUMPER_SHOW_DEBUG	= 0x0080,
	DUMPER_SHOW_ARCH	= 0x0100,
	DUMPER_SHOW_GLOBALPTR	= 0x0200,
	DUMPER_SHOW_TLS	= 0x0400,	/// Thead Local Storage
	DUMPER_SHOW_LOADCFG	= 0x0800,
	DUMPER_SHOW_VM	= 0x1000,	/// VM-related stuff, like CLR
	DUMPER_SHOW_SECTIONS	= 0x2000,
	DUMPER_SHOW_EVERYTHING	= 0x0F_FFFF,

	/// ('d') Include section disassembly in output.
	DUMPER_DISASM_CODE	= 0x01_0000,
	/// ('D') Include section disassembly in output.
	DUMPER_DISASM_ALL	= 0x02_0000,
	///TODO: Do not format instructions. Instead, show disassembler statistics.
	/// Statistics include number of instructions, average instruction length,
	/// minimum instruction length, maximum instruction length, and its total
	/// size.
	DUMPER_DISASM_STATS	= 0x04_0000,

	/// ("-raw") File is raw, do not attempt to detect its format,
	/// disassembly only
	DUMPER_FILE_RAW	= 0x10_0000,

	//
	// Export/Extract flags
	//

	// These are more options that are unaffected by "show everything"
	///TODO: ('R') Export resources into current directory. This includes
	/// icons and images.
	DUMPER_EXPORT_RESOURCES	= 0x0100_0000,
	///TODO: ('C') Export certificates into current directory.
	DUMPER_EXPORT_CERTS	= 0x0200_0000,
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

/// Dump given file to stdout.
/// Params:
/// 	file = File path
/// 	dp = Disassembler settings
/// 	flags = Dumper options
/// Returns: Error code if non-zero
int adbg_dmpr_dump(const(char) *file, disasm_params_t *dp, int flags) {
	FILE *f = fopen(file, "rb"); // Handles null file pointers
	if (f == null) {
		perror("dump");
		return EXIT_FAILURE;
	}

	if (flags & DUMPER_FILE_RAW) {
		if (fseek(f, 0, SEEK_END)) {
			puts("dump: could not seek file");
			return EXIT_FAILURE;
		}
		uint fl = cast(uint)ftell(f);
		fseek(f, 0, SEEK_SET); // rewind binding is broken

		void *m = malloc(fl + 16);
		if (m == null)
			return EXIT_FAILURE;
		if (fread(m, fl, 1, f) == 0) {
			puts("cli: could not read file");
			return EXIT_FAILURE;
		}

		return adbg_dmpr_disasm(dp, m, fl, flags);
	}

	// When nothing is set, the default is to show headers
	if ((flags & DUMPER_SHOW_EVERYTHING) == 0)
		flags |= DUMPER_SHOW_HEADER;

	obj_info_t info = void;
	ObjError e = cast(ObjError)adbg_obj_load(f, &info, 0);
	if (e) {
		printf("loader: %s\n", adbg_obj_errmsg(e));
		return e;
	}

	if (dp.isa == DisasmISA.platform)
		dp.isa = info.isa;

	with (ObjType)
	switch (info.type) {
	case PE: return adbg_dmpr_print_pe(&info, dp, flags);
	default:
		puts("dumper: format not supported");
		return EXIT_FAILURE;
	}
}

// NOTE: A FILE* could be passed, but Windows bindings often do not correspond
//       to their CRT equivalent, so this is hard-wired to stdout, since this
//       is only for the dumping functionality.
int adbg_dmpr_disasm(disasm_params_t *dp, void* data, uint size, int flags) {
	dp.a = data;
	if (flags & DUMPER_DISASM_STATS) {
		uint iavg;	/// instruction average size
		uint imax;	/// longest instruction size
		uint icnt;	/// instruction count
		uint ills;	/// Number of illegal instructions
		for (uint i, isize = void; i < size; i += isize) {
			DisasmError e = cast(DisasmError)adbg_dasm_line(dp, DisasmMode.Size);
			isize = cast(uint)(dp.av - dp.la);
			with (DisasmError)
			final switch (e) {
			case None:
				iavg += isize;
				++icnt;
				if (isize > imax)
					imax = isize;
				break;
			case Illegal: 
				iavg += isize;
				++icnt;
				++ills;
				break;
			case NullAddress, NotSupported:
				printf("disasm: %s\n", adbg_dasm_errmsg(e));
				return e;
			}
		}
		printf(
		"Instruction statistics\n"~
		"avg. size: %f\n"~
		"max. size: %u\n"~
		"illegal  : %u\n"~
		"total    : %u\n",
		cast(float)iavg / icnt, imax, ills, icnt
		);
	} else {
		for (uint i; i < size; i += dp.av - dp.la) {
			DisasmError e = cast(DisasmError)adbg_dasm_line(dp, DisasmMode.File);
			with (DisasmError)
			switch (e) {
			case None, Illegal:
				printf("%08X %-30s %-30s\n",
					i, &dp.mcbuf, &dp.mnbuf);
				continue;
			default:
				printf("disasm: %s\n", adbg_dasm_errmsg(e));
				return e;
			}
		}
	}
	return 0;
}
