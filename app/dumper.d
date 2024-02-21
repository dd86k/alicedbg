/// Image/object dumper, imitates objdump
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module dumper;

import adbg.error, adbg.disassembler, adbg.object;
import adbg.include.c.stdio;
import adbg.include.c.stdlib : EXIT_SUCCESS, EXIT_FAILURE, malloc, free;
import adbg.include.c.stdarg;
import adbg.object.machines;
import adbg.utils.bit : BIT;
import core.stdc.string;
import core.stdc.ctype : isprint;
import common, utils, dump;

extern (C):

/// Bitfield. Selects which information to display.
enum DumpSelect {
	/// 'h' - Dump headers
	headers	= BIT!0,
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
	
	// Bits 31-24: Disassembly
	
	/// Disassemble executable sections
	disasm	= BIT!24,
	/// Disassembly statistics
	disasm_stats	= BIT!25,
	/// Disassemble all sections
	disasm_all	= BIT!26,
	
	/// 
	all_but_disasm = 0xff_ffff,
	/// Any form of dissasembler is requested
	disasm_any = disasm | disasm_stats | disasm_all,
}
enum DumpOptions {
	/// File is raw, do not auto-detect
	raw	= BIT!0,
}

struct Dumper {
	extern (C):
	
	int selections;
	int options;
	
	this(int selects, int opts) {
		// Default selections
		if (selects == 0)
			selects = DumpSelect.headers;
		
		selections = selects;
		options = opts;
	}
	
	pragma(inline, true):
	
	//
	// Selections
	//
	
	bool selected_headers() { return (selections & DumpSelect.headers) != 0; }
	bool selected_sections() { return (selections & DumpSelect.sections) != 0; }
	bool selected_relocations() { return (selections & DumpSelect.relocs) != 0; }
	bool selected_exports() { return (selections & DumpSelect.exports) != 0; }
	bool selected_imports() { return (selections & DumpSelect.imports) != 0; }
	bool selected_debug() { return (selections & DumpSelect.debug_) != 0; }
	
	bool selected_disasm() { return (selections & DumpSelect.disasm) != 0; }
	bool selected_disasm_stats() { return (selections & DumpSelect.disasm_stats) != 0; }
	bool selected_disasm_all() { return (selections & DumpSelect.disasm_all) != 0; }
	bool selected_disasm_any() { return (selections & DumpSelect.disasm_any) != 0; }
	
	//
	// Options
	//
	
	bool option_blob() { return (options & DumpOptions.raw) != 0; }
}

/// Dump given file to stdout.
/// Returns: Error code if non-zero
int app_dump() {
	Dumper dump = Dumper(globals.dump_selections, globals.dump_options);
	
	if (dump.option_blob()) {
		// NOTE: Program exits and memory is free'd
		size_t size = void;
		ubyte *buffer = readall(globals.file, &size);
		if (buffer == null)
			quitext(ErrSource.crt);
		
		if (size == 0) {
			puts("Warning: File is empty");
			return 0;
		}
	
		print_string("filename", basename(globals.file));
		print_u64("filesize", size);
		print_string("format", "Blob");
		print_string("short_name", "blob");
		
		return dump_disassemble(dump, globals.machine, buffer, size, globals.dump_base_address);
	}
	
	adbg_object_t *o = adbg_object_open_file(globals.file, 0);
	if (o == null)
		return show_error();
	
	print_string("filename", basename(globals.file));
	print_u64("filesize", o.file_size);
	print_string("format", adbg_object_name(o));
	print_string("short_name", adbg_object_short_name(o));
	
	final switch (o.format) with (AdbgObject) {
	case mz:	return dump_mz(dump, o);
	case ne:	return dump_ne(dump, o);
	case pe:	return dump_pe(dump, o);
	case lx:	return dump_lx(dump, o);
	case elf:	return dump_elf(dump, o);
	case macho:	return dump_macho(dump, o);
	case pdb20:	return dump_pdb20(dump, o);
	case pdb70:	return dump_pdb70(dump, o);
	case archive:	return dump_archive(dump, o);
	case mdmp:	return dump_minidump(dump, o);
	case dmp:	return dump_dmp(dump, o);
	case unknown:	assert(0, "Unknown object type"); // Raw/unknown
	}
}

private immutable {
	/// Padding spacing to use in characters
	// PE32 has fields like MinorOperatingSystemVersion (27 chars)
	int __field_padding = -28;
	/// 
	int __columns = 16;
}

void print_header(const(char)* name) {
	printf("\n# %s\n", name);
}

// Field name only
void print_name(const(char)* name) {
	printf("%*s: ", __field_padding, name);
}

void print_section(uint i, const(char) *name = null, int len = 0) {
	putchar('\n');
	print_u32("index", i);
	if (name && len) print_stringl("name", name, len);
}
void print_disasm_line(adbg_opcode_t *op, const(char)* msg = null) {
	// Print address
	printf("%12llx ", op.address);
	
	// If opcode is empty, somehow, print message if available
	if (op.size == 0) {
		puts(msg ? msg : "empty");
		return;
	}
	
	// Format and print machine bytes
	enum MBFSZ = (16 * 3) + 2; // Enough for 16 bytes and spaces
	char[MBFSZ] machine = void;
	int left = MBFSZ; // Buffer left
	int tl; // Total length
	for (size_t bi; bi < op.size; ++bi) {
		int l = snprintf(machine.ptr + tl, left, " %02x", op.machine[bi]);
		if (l <= 0) break; // Ran out of buffer space
		tl += l;
		left -= l;
	}
	machine[tl] = 0;
	printf(" %*s ", -24, machine.ptr);
	
	// Print message or mnemonics
	if (msg) {
		puts(msg);
		return;
	}
	printf("%*s %s\n", -10, op.mnemonic, op.operands);
}

void print_u8(const(char)* name, ubyte val, const(char) *meaning = null) {
	print_u32(name, val, meaning);
}
void print_u16(const(char)* name, ushort val, const(char) *meaning = null) {
	print_u32(name, val, meaning);
}
void print_u32(const(char)* name, uint val, const(char) *meaning = null) {
	printf("%*s: %u", __field_padding, name, val);
	if (meaning) printf("\t(%s)", meaning);
	putchar('\n');
}
void print_u32l(const(char)* name, uint val, const(char) *meaning = null, int length = 0) {
	printf("%*s: %u", __field_padding, name, val);
	if (meaning && length) printf("\t(\"%.*s\")", length, meaning);
	putchar('\n');
}
void print_u64(const(char)* name, ulong val, const(char) *meaning = null) {
	printf("%*s: %llu", __field_padding, name, val);
	if (meaning) printf("\t(%s)", meaning);
	putchar('\n');
}

void print_x8(const(char)* name, ubyte val, const(char) *meaning = null) {
	printf("%*s: 0x%02x", __field_padding, name, val);
	if (meaning) printf("\t(%s)", meaning);
	putchar('\n');
}
void print_x16(const(char)* name, ushort val, const(char) *meaning = null) {
	printf("%*s: 0x%04x", __field_padding, name, val);
	if (meaning) printf("\t(%s)", meaning);
	putchar('\n');
}
void print_x16l(const(char)* name, ushort val, const(char) *meaning = null, int length = 0) {
	printf("%*s: 0x%04x", __field_padding, name, val);
	if (meaning) printf("\t(\"%.*s\")", length, meaning);
	putchar('\n');
}
void print_x32(const(char)* name, uint val, const(char) *meaning = null) {
	printf("%*s: 0x%08x", __field_padding, name, val);
	if (meaning) printf("\t(%s)", meaning);
	putchar('\n');
}
void print_x32l(const(char)* name, uint val, const(char) *meaning = null, int length = 0) {
	printf("%*s: 0x%08x", __field_padding, name, val);
	if (meaning) printf("\t(\"%.*s\")", length, meaning);
	putchar('\n');
}
void print_x64(const(char)* name, ulong val, const(char) *meaning = null) {
	printf("%*s: 0x%016llx", __field_padding, name, val);
	if (meaning) printf(`\t(%s)`, meaning);
	putchar('\n');
}

void print_f32(const(char)* name, float val, int pad = 2) {
	print_f64(name, val, pad);
}
void print_f64(const(char)* name, double val, int pad = 2) {
	printf("%*s: %.*f\n", __field_padding, name, pad, val);
}

void print_string(const(char)* name, const(char)* val) {
	printf("%*s: %s\n", __field_padding, name, val);
}
void print_stringl(const(char)* name, const(char)* val, int len) {
	printf("%*s: %.*s\n", __field_padding, name, len, val);
}
//TODO: print_stringf

void print_flags16(const(char) *section, ushort flags, ...) {
	printf("%*s: 0x%04x\t(", __field_padding, section, flags);
	
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
void print_flags32(const(char) *section, uint flags, ...) {
	printf("%*s: 0x%08x\t(", __field_padding, section, flags);
	
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
void print_flags64(const(char) *section, ulong flags, ...) {
	printf("%*s: 0x%016llx\t(", __field_padding, section, flags);
	
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

void print_raw(const(char)* name, void *data, size_t dsize, adbg_object_t *o) {
	// Is size fitting within file?
	if (adbg_object_outboundpl(o, data, dsize)) {
		print_string("warning", "Data goes beyond file bounds.");
		return;
	}
	
	print_header(name);
	
	size_t offset = data - o.buffer;
	
	// Print header
	static immutable string _soff = "Offset    ";
	printf(_soff.ptr);
	for (int ib; ib < __columns; ++ib)
		printf("%02x ", ib);
	putchar('\n');
	
	// Print data
	ubyte *d = cast(ubyte*)data;
	size_t afo; // Absolute file offset
	for (size_t id; id < dsize; id += __columns, offset += __columns) {
		printf("%8zx  ", offset);
		
		// Adjust column for row
		size_t col = __columns;//id + __columns >= dsize ? dsize - __columns : __columns;
		size_t off = afo;
		
		// Print data bytes
		for (size_t ib; ib < col; ++ib, ++off)
			printf("%02x ", d[off]);
		
		// Adjust spacing between the two
		if (col < __columns) {
			
		} else
			putchar(' ');
		
		// Print printable characters
		off = afo;
		for (size_t ib; ib < col; ++ib, ++off)
			putchar(isprint(d[off]) ? d[off] : '.');
		
		// New row
		afo += col;
		putchar('\n');
	}
}

void print_directory_entry(const(char)* name, uint rva, uint size) {
	printf("%*s: 0x%08x  %u\n", __field_padding, name, rva, size);
}

void print_reloc16(uint index, ushort seg, ushort off) {
	printf("%4u. 0x%04x:0x%04x\n", index, seg, off);
}

// name is typically section name or filename if raw
int dump_disassemble_object(ref Dumper dump, adbg_object_t *o,
	const(char) *name, int namemax,
	void* data, ulong size, ulong base_address) {
	
	print_header("Disassembly");
	
	if (name && namemax)
		print_stringl("section", name, namemax);
	
	if (data + size >= o.buffer + o.file_size) {
		print_string("error", "data + size >= dump.o.buffer + dump.o.file_size");
		return EXIT_FAILURE;
	}
	
	if (data == null || size == 0) {
		print_string("error", "data is NULL or size is 0");
		return 0;
	}
	
	return dump_disassemble(dump, adbg_object_machine(o), data, size, base_address);
}

int dump_disassemble(ref Dumper dump, AdbgMachine machine,
	void* data, ulong size, ulong base_address) {
	adbg_disassembler_t *dasm = cast(adbg_disassembler_t*)malloc(adbg_disassembler_t.sizeof);
	if (dasm == null)
		quitext(ErrSource.crt);
	scope(exit) free(dasm);
	
	if (adbg_dasm_open(dasm, machine))
		quitext(ErrSource.adbg);
	scope(exit) adbg_dasm_close(dasm);
	
	if (globals.syntax)
		adbg_dasm_options(dasm, AdbgDasmOption.syntax, globals.syntax, 0);
	
	adbg_opcode_t op = void;
	adbg_dasm_start(dasm, data, cast(size_t)size, base_address);
	
	// stats mode
	if (dump.selected_disasm_stats()) {
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
		default:
			quitext(ErrSource.adbg);
		}
		
		print_f32("average", cast(float)stat_avg / stat_total, 2);
		print_u32("shortest", stat_min);
		print_u32("largest", stat_max);
		print_u32("illegal", stat_illegal);
		print_u32("valid", stat_total - stat_illegal);
		print_u32("total", stat_total);
		return 0;
	}
	
	// normal disasm mode
L_DISASM:
	switch (adbg_dasm(dasm, &op)) with (AdbgError) {
	case success:
		print_disasm_line(&op);
		goto L_DISASM;
	case illegalInstruction:
		print_disasm_line(&op, "illegal");
		goto L_DISASM;
	case outOfData:
		return 0;
	default:
		print_string("error", adbg_error_msg());
		return 1;
	}
}
