/**
 * Image/object dumper, imitates objdump
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
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

private enum MODULE = __MODULE__.ptr;

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
	//TODO: Do bools instead
	int flags; /// display settings
}

/// Output a dump title.
/// Params: title = Title
void dump_title(const(char) *title) {
	printf("%s format\n", title);
}

/// Output a dump chapter.
/// Params: title = Chapter name
void dump_h1(const(char) *title) {
	printf("\n# %s\n\n", title);
}

/// Dump given file to stdout.
/// Returns: Error code if non-zero
int dump() {
	FILE *f = fopen(globals.cli.file, "rb"); // Handles null file pointers
	if (f == null) {
		perror(MODULE);
		return EXIT_FAILURE;
	}
	
	if (globals.cli.flags & DumpOpt.raw) {
		if (fseek(f, 0, SEEK_END)) {
			perror(MODULE);
			puts("dump: could not seek file");
			return EXIT_FAILURE;
		}
		uint fl = cast(uint)ftell(f);
		fseek(f, 0, SEEK_SET); // rewind binding is broken
		
		void *data = malloc(fl);
		if (data == null) {
			perror(MODULE);
			return EXIT_FAILURE;
		}
		if (fread(data, fl, 1, f) == 0) {
			perror(MODULE);
			return EXIT_FAILURE;
		}
		
		with (globals)
		return dump_disasm(&app.disasm, data, fl, cli.flags);
	}
	
	adbg_object_t obj = void;
	
	// Load object into memory
	if (adbg_obj_open_file(&obj, f)) {
		printerror;
		return 1;
	}
	
	// When nothing is set, the default is to show headers
	if ((globals.cli.flags & 0xFF_FFFF) == 0)
		globals.cli.flags |= DumpOpt.header;
	
	if (adbg_disasm_configure(&globals.app.disasm, obj.platform))
		return printerror();
	
	dump_t dump = void;
	dump.obj = &obj;
	dump.dopts = &globals.app.disasm;
	dump.flags = globals.cli.flags;
	
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

/// Disassemble data to stdout
/// Params:
/// 	dp = Disassembler parameters
/// 	data = Data pointer
/// 	size = Data size
/// 	flags = Configuration flags
/// Returns: Status code
int dump_disasm(adbg_disasm_t *dp, void* data, uint size, int flags) {
	adbg_disasm_opcode_t op = void;
	
	if (flags & DumpOpt.disasm_stats) {
		uint iavg;	/// instruction average size
		uint imin;	/// smallest instruction size
		uint imax;	/// longest instruction size
		uint icnt;	/// instruction count
		uint ills;	/// Number of illegal instructions
		adbg_disasm_start_buffer(dp, AdbgDisasmMode.size, data, size);
L_DISASM_1:
		with (AdbgError)
		switch (adbg_disasm(dp, &op)) {
		case none:
			iavg += op.size;
			++icnt;
			if (op.size > imax)
				imax = op.size;
			if (op.size < imin)
				imin = op.size;
			goto L_DISASM_1;
		case illegalInstruction:
			iavg += op.size;
			++icnt;
			++ills;
			goto L_DISASM_1;
		case outOfData: break;
		default: return printerror();
		}
		printf(
		"Opcode statistics\n"~
		"average size : %.3f\n"~
		"smallest size: %u\n"~
		"biggest size : %u\n"~
		"illegal      : %u\n"~
		"total        : %u\n",
		cast(float)iavg / icnt, imin, imax, ills, icnt
		);
		return 0;
	}
	
	adbg_disasm_opt(dp, AdbgDisasmOpt.mnemonicTab, true);
	uint i;
	char[40] mnemonic = void, machine = void;
	const(char)* mnptr = void, maptr = void;
	adbg_disasm_start_buffer(dp, AdbgDisasmMode.file, data, size);
L_DISASM_2:
	with (AdbgError)
	switch (adbg_disasm(dp, &op)) {
	case none:
		adbg_disasm_machine(dp, machine.ptr, 40, &op);
		adbg_disasm_format(dp, mnemonic.ptr, 40, &op);
		maptr = machine.ptr;
		mnptr = mnemonic.ptr;
		break;
	//TODO: Illegal should be moved with none and disasm takes care of buffer
	case illegalInstruction:
		adbg_disasm_machine(dp, machine.ptr, 40, &op);
		maptr = machine.ptr;
		mnptr = "(bad)";
		break;
	case outOfData: return 0;
	default: return printerror();
	}
	printf("%8x  %-25s  %s\n", i, maptr, mnptr);
	i += op.size;
	goto L_DISASM_2;
}
