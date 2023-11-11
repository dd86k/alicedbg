/**
 * Image/object dumper, imitates objdump
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module dumper;

import adbg.include.c.stdio;
import adbg.include.c.stdlib : EXIT_SUCCESS, EXIT_FAILURE, malloc, free;
import adbg.include.c.stdarg;
import adbg.v2, adbg.v2.object.machines;
import adbg.utils.bit : BIT;
import common, utils, dump;

extern (C):

//TODO: Consider a "Summary" ala objdump -f
//      Could be default over "all headers"
/// Bitfield. Selects which information to display.
enum DumpOpt {
	/// 'h' - Dump header
	header	= BIT!0,
	/// 'd' - Dump directories (PE32)
	dirs	= BIT!1,
	/// 'e' - Exports
	exports	= BIT!2,
	/// 'i' - Imports
	imports	= BIT!3,
	/// 'c' - Images, certificates, etc.
	resources	= BIT!4,
	/// 't' - Structured Exception Handler
	seh	= BIT!5,
	/// 't' - Symbol table(s)
	symbols	= BIT!6,
	/// 'T' - Dynamic symbol table
	dynsymbols	= BIT!7,
	/// 'g' - Debugging material
	debug_	= BIT!8,
	/// 'o' - Thread Local Storage
	tls	= BIT!9,
	/// 'l' - Load configuration
	loadcfg	= BIT!10,
	/// 's' - Sections
	sections	= BIT!11,
	/// 'r' - Relocations
	relocs	= BIT!12,
	/// 'R' - Dynamic relocations
	dynrelocs	= BIT!13,
	
	/// Disassemble executable sections
	disasm	= BIT!22,
	/// Disassembly statistics
	disasm_stats	= BIT!23,
	/// Disassemble all sections
	disasm_all	= BIT!24,
	
	/// File is raw, do not auto-detect
	raw	= BIT!31,
	
	/// Display all metadata except disassembly
	everything = header | dirs | resources | seh |
		symbols | debug_ | tls | loadcfg |
		exports | imports | sections,
	
	/// Any form of dissasembler is requested
	disasm_any = disasm | disasm_stats | disasm_all,
}

/// Dump given file to stdout.
/// Returns: Error code if non-zero
int app_dump() {
	if (globals.flags & DumpOpt.raw) {
		size_t size = void;
		ubyte *buffer = readall(globals.file, &size);
		
		if (buffer == null) {
			panic(AdbgError.crt);
		}
		
		if (size == 0)
			return 0;
		
		return dprint_disassemble(AdbgMachine.native,
			null, 0, buffer, size, globals.flags);
	}
	
	adbg_object_t *o = cast(adbg_object_t*)malloc(adbg_object_t.sizeof);
	if (o == null)
		panic(AdbgError.crt);
	
	//TODO: If only headers, use partial option
	// Load object into memory
	if (adbg_object_open(o, globals.file, 0)) {
		return oops;
	}
	
	// When nothing is set, the default is to show headers
	//TODO: Set header in .init then
	if ((globals.flags & 0xFF_FFFF) == 0)
		globals.flags |= DumpOpt.header;
	
	// NOTE: adbg_object_name safely returns "Unknown" in case of unknown.
	printf("%s object format\n", adbg_object_name(o));
	
	switch (o.format) with (AdbgObject) {
	case mz:	return dump_mz(o, globals.flags);
	case pe:	return dump_pe(o, globals.flags);
	case elf:	return dump_elf(o, globals.flags);
	case macho:	return dump_macho(o, globals.flags);
	default:
	}
	
	puts("\ndumper: format not supported or unknown.");
	return EXIT_FAILURE;
}

//TODO: Redo entirely of dumper functions
//      dprint_group_start(name)/dprint_group_end
//      or dprint(group_name, // header, program_header, etc.
//           spec, name, value, ...)
//      or consider struct DumperPrinter or similar
//TODO: object aware dumps
//      generic: dump_import(lib, name), etc.

private enum FORMAT_FIELD = "  %-30s:  ";

//TODO: Make this vararg and the default
//      Then removed print_columns
void dprint_header(const(char) *header) {
	printf("\n# %s\n", header);
}
void dprint_columns(const(char) *header, const(char) *s1, const(char) *s2) {
	printf("\n# %-30s   %-10s  %s\n", header, s1, s2);
}
void dprint_warn(const(char) *message) {
	printf("warning: %s\n", message);
}
void dprint_error(const(char) *message) {
	import core.stdc.stdlib : exit;
	printf("error: %s\n", message);
	exit(1);
}

void dprint_section(uint count, const(char) *section, uint max) {
	printf("\n%u. %.*s:\n", count, max, section);
}

void dprint_string(const(char) *name, const(char) *val) {
	printf(FORMAT_FIELD~"%s", name, val);
}
void dprint_stringl(const(char) *name, const(char) *val, uint len) {
	printf(FORMAT_FIELD~"%.*s", name, len, val);
}
void dprint_x8(const(char) *name, ubyte val,
	const(char) *meaning = null, const(char) *alias_ = null) {
	printf(FORMAT_FIELD~"0x%02x", name, val);
	if (meaning) printf("\t(%s)", meaning);
	putchar('\n');
}
void dprint_u8(const(char) *name, ubyte val,
	const(char) *meaning = null, const(char) *alias_ = null) {
	printf(FORMAT_FIELD~"%u", name, val);
	if (meaning) printf("\t(%s)", meaning);
	putchar('\n');
}
void dprint_x16(const(char) *name, ushort val,
	const(char) *meaning = null, const(char) *alias_ = null) {
	printf(FORMAT_FIELD~"0x%04x", name, val);
	if (meaning) printf("\t(%s)", meaning);
	putchar('\n');
}
void dprint_u16(const(char) *name, ushort val,
	const(char) *meaning = null, const(char) *alias_ = null) {
	printf(FORMAT_FIELD~"%u", name, val);
	if (meaning) printf("\t(%s)", meaning);
	putchar('\n');
}
// temp for pe32 import
void dprint_x16__i(uint rva, ushort hint, const(char) *s) {
	printf("  %-31x  %-10x  %.256s\n", rva, hint, s);
}

void dprint_x32(const(char) *name, uint val,
	const(char) *meaning = null, const(char) *alias_ = null) {
	printf(FORMAT_FIELD~"0x%08x", name, val);
	if (meaning) printf("\t(%s)", meaning);
	putchar('\n');
}
// temp for pe32 stuff
void dprint_x32s(const(char) *name, uint val,
	const(char) *meaning = null, uint max = 0) {
	printf(FORMAT_FIELD~"0x%08x", name, val);
	if (meaning) printf("\t(%.*s)", max, meaning);
	putchar('\n');
}
void dprint_u32(const(char) *name, uint val,
	const(char) *meaning = null, const(char) *alias_ = null) {
	printf(FORMAT_FIELD~"%u", name, val);
	if (meaning) printf("\t(%s)", meaning);
	putchar('\n');
}
void dprint_x64(const(char) *name, ulong val,
	const(char) *meaning = null, const(char) *alias_ = null) {
	printf(FORMAT_FIELD~"0x%016llx", name, val);
	if (meaning) printf("\t(%s)", meaning);
	putchar('\n');
}
void dprint_u64(const(char) *name, ulong val,
	const(char) *meaning = null, const(char) *alias_ = null) {
	printf(FORMAT_FIELD~"%llu", name, val);
	if (meaning) printf("\t(%s)", meaning);
	putchar('\n');
}

// temp for pe32 dir entry
void dprint_entry32(const(char) *section, uint u1, uint u2) {
	printf(FORMAT_FIELD~"0x%08x  %u\n", section, u1, u2);
}

// name + rvalue (stops when name is null)
void dprint_flags16(const(char) *section, ushort flags, ...) {
	printf(FORMAT_FIELD~"0x%04x\t(", section, flags);
	
	va_list args = void;
	va_start(args, flags);
	ushort count;
L_START:
	const(char) *name = va_arg!(const(char)*)(args);
	if (name == null) {
		puts(")");
		return;
	}
	
	if ((flags & va_arg!int(args)) == 0) goto L_START; // condition
	if (count++) putchar(',');
	printf("%s", name);
	goto L_START;
}
// name + rvalue (stops when name is null)
void dprint_flags32(const(char) *section, uint flags, ...) {
	printf(FORMAT_FIELD~"0x%08x\t(", section, flags);
	
	va_list args = void;
	va_start(args, flags);
	ushort count;
L_START:
	const(char) *name = va_arg!(const(char)*)(args);
	if (name == null) {
		puts(")");
		return;
	}
	
	if ((flags & va_arg!int(args)) == 0) goto L_START; // condition
	if (count++) putchar(',');
	printf("%s", name);
	goto L_START;
}
// name + rvalue (stops when name is null)
//TODO: Could make it a template?
void dprint_flags64(const(char) *section, ulong flags, ...) {
	printf(FORMAT_FIELD~"0x%016llx\t(", section, flags);
	
	va_list args = void;
	va_start(args, flags);
	ushort count;
L_START:
	const(char) *name = va_arg!(const(char)*)(args);
	if (name == null) {
		puts(")");
		return;
	}
	
	if ((flags & va_arg!long(args)) == 0) goto L_START; // condition
	if (count++) putchar(',');
	printf("%s", name);
	goto L_START;
}

// hexdump
void dprint_raw(const(char) *name, uint namemax,
	ulong filebase, void *data, size_t size) {
	//TODO: print "raw:<size>" or something and dump it
	//TODO: need to think of a "raw dump" setting
}

// name is typically section name or filename if raw
int dprint_disassemble_object(adbg_object_t *o,
	const(char) *name, uint namemax,
	void* data, ulong size,
	uint flags) {
	
	if (data + size >= o.buffer + o.file_size) {
		dprint_error("Buffer outside file");
	}
	
	return dprint_disassemble(
		adbg_object_machine(o), name, namemax, data, size, flags);
}
int dprint_disassemble(AdbgMachine machine,
	const(char) *name, uint namemax,
	void* data, ulong size,
	uint flags) {
	
	if (name && namemax) printf("<%.*s>:\n", namemax, name);
	if (data == null || size == 0) return 0;
	//TODO: Check data+size against object type (file_size)
	
	adbg_disassembler_t *dasm = cast(adbg_disassembler_t*)malloc(adbg_disassembler_t.sizeof);
	if (dasm == null)
		panic(AdbgError.crt);
	scope(exit) free(dasm);
	
	if (adbg_dasm_open(dasm, machine))
		panic();
	
	if (globals.syntax)
		adbg_dasm_options(dasm, AdbgDasmOption.syntax, globals.syntax, 0);
	
	adbg_opcode_t op = void;
	adbg_dasm_start(dasm, data, cast(size_t)size);
	
	// stats mode
	if (flags & DumpOpt.disasm_stats) {
		uint stat_avg;	/// instruction average size
		uint stat_min = uint.max;	/// smallest instruction size
		uint stat_max;	/// longest instruction size
		uint stat_total;	/// total instruction count
		uint stat_illegal;	/// Number of illegal instructions
L_STAT:
		switch (adbg_dasm(dasm, &op)) with (AdbgError) {
		case success:
			stat_avg += op.size;
			++stat_total;
			if (op.size > stat_max) stat_max = op.size;
			if (op.size < stat_min) stat_min = op.size;
			goto L_STAT;
		case illegalInstruction:
			stat_avg += op.size;
			++stat_total;
			++stat_illegal;
			goto L_STAT;
		case outOfData: break;
		default: panic();
		}
		printf(
		"Opcode statistics\n"~
		"average size : %.3f Bytes\n"~
		"shortest     : %u Bytes\n"~
		"largest      : %u Bytes\n"~
		"illegal      : %u instructions\n"~
		"valid        : %u instructions\n"~
		"total        : %u instructions\n",
		cast(float)stat_avg / stat_total,
		stat_min,
		stat_max,
		stat_illegal,
		stat_total - stat_illegal,
		stat_total
		);
		return 0;
	}
	
	// normal disasm mode
	//TODO: Could do better with a while (!= EOF) and is_opcode_illegal()
L_DISASM:
	switch (adbg_dasm(dasm, &op)) with (AdbgError) {
	case success:
		//TODO: print base as 08x if small enough
		printf("%016llx  %s\t%s\n", op.base, op.mnemonic, op.operands);
		goto L_DISASM;
	case illegalInstruction:
		printf("%016llx  illegal (%d bytes)\n", op.base, op.size);
		goto L_DISASM;
	case outOfData:
		return 0;
	default:
		panic();
		return 0;
	}
}
