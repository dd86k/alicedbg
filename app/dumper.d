/**
 * Image/object dumper, imitates objdump
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2022 dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module dumper;

import core.stdc.stdio;
import core.stdc.stdlib : EXIT_SUCCESS, EXIT_FAILURE, malloc;
import adbg.error;
import adbg.v1.disassembler;
import adbg.v1.server;
import adbg.utils.bit : BIT;
import adbg.utils.file;
import common, dump;

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
int app_dump() {
	if (globals.flags & DumpOpt.raw) {
		size_t size;
		ubyte *buffer = adbg_util_readall(&size, globals.file);
		
		if (buffer == null) {
			perror(MODULE);
			return EXIT_FAILURE;
		}
		
		//TODO: dump_disasm should take directly from globals
		with (globals)
		return dump_disasm(&dism, buffer, size, flags);
	}
	
	FILE *f = fopen(globals.file, "rb"); // Handles null file pointers
	if (f == null) {
		perror(MODULE);
		return EXIT_FAILURE;
	}
	
	adbg_object_t obj = void;
	
	// Load object into memory
	if (adbg_obj_open_file(&obj, f)) {
		printerror;
		return 1;
	}
	
	// When nothing is set, the default is to show headers
	//TODO: Set header in .init then
	if ((globals.flags & 0xFF_FFFF) == 0)
		globals.flags |= DumpOpt.header;
	
	dump_t dump = void;
	dump.obj = &obj;
	dump.dopts = &globals.dism;	//TODO: Why not make subfunctions take from global directly?
	dump.flags = globals.flags;
	
	switch (dump.obj.format) with (AdbgObjFormat) {
	case MZ:	return dump_mz(&dump);
	case PE:	return dump_pe(&dump);
	case ELF:	return dump_elf(&dump);
	case MachO:	return dump_macho(&dump);
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
int dump_disasm(adbg_disasm_t *dasm, void* data, size_t size, int flags) {
	adbg_disasm_opcode_t op = void;
	
	//TODO: Dedicated function
	if (flags & DumpOpt.disasm_stats) {
		uint iavg;	/// instruction average size
		uint imin;	/// smallest instruction size
		uint imax;	/// longest instruction size
		uint icnt;	/// instruction count
		uint ills;	/// Number of illegal instructions
		adbg_disasm_start_buffer(dasm, AdbgDisasmMode.size, data, size);
L_DISASM_1:
		with (AdbgError)
		switch (adbg_disasm(dasm, &op)) {
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
	
	uint i;
	
	import adbg.config : USE_CAPSTONE;
	
	static if (USE_CAPSTONE) {
		char[120] str_machine = "test";
		char[120] str_mnemonic = void;
		
		version(Trace) trace("size=%u", size);
		
		adbg_disasm_start_buffer(dasm, AdbgDisasmMode.file, data, size);
	
	L_DISASM_2:
		switch (adbg_disasm(dasm, &op)) with (AdbgError) {
		case none: break;
		case outOfData: return 0;
		default: return printerror();
		}
		adbg_disasm_machine(dasm, str_machine.ptr, 120, &op);
		adbg_disasm_format(dasm, str_mnemonic.ptr, 120, &op);
		printf("%8x  %-22s  %s\n", i, str_machine.ptr, str_mnemonic.ptr);
		i += op.size;
		goto L_DISASM_2;
	} else {
		char[40] machine = void, prefix = void, mnemonic = void, operands = void;
		const(char)* maptr = void, prptr = void, mnptr = void, opptr = void;
		adbg_disasm_start_buffer(dasm, AdbgDisasmMode.file, data, size);
	
	L_DISASM_2:
		switch (adbg_disasm(dasm, &op)) with (AdbgError) {
		case none:
			adbg_disasm_machine(dasm, machine.ptr, 40, &op);
			adbg_disasm_format_prefixes(dasm, prefix.ptr, 40, &op);
			adbg_disasm_format_mnemonic(dasm, mnemonic.ptr, 40, &op);
			adbg_disasm_format_operands(dasm, operands.ptr, 40, &op);
			maptr = machine.ptr;
			prptr = prefix.ptr;
			mnptr = mnemonic.ptr;
			opptr = operands.ptr;
			break;
		//TODO: Illegal should be moved with none and disasm takes care of buffer
		case illegalInstruction:
			adbg_disasm_machine(dasm, machine.ptr, 40, &op);
			maptr = machine.ptr;
			prptr = "";
			mnptr = "(bad)";
			opptr = "";
			break;
		case outOfData: return 0;
		default: return printerror();
		}
		printf("%8x  %-22s  %s%-12s%s\n", i, maptr, prptr, mnptr, opptr);
		i += op.size;
		goto L_DISASM_2;
	}
}
