/// Image/object dumper, imitates objdump
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module dumper;

import adbg.error, adbg.disassembler, adbg.object;
import adbg.include.c.stdio;
import adbg.include.c.stdlib : EXIT_SUCCESS, EXIT_FAILURE, malloc, free;
import adbg.include.c.stdarg;
import adbg.machines;
import adbg.utils.bit : BIT;
import core.stdc.string;
import core.stdc.ctype : isprint;
import core.stdc.errno;
import format;
import common.error;
import common.cli : opt_machine, opt_syntax;
import common.utils;

extern (C):
__gshared:

enum Select {
	headers	= BIT!0,
	/// Sections
	sections	= BIT!1,
	/// Relocations
	relocs	= BIT!2,
	/// Exported/dynamic symbols
	exports	= BIT!3,
	/// Import symbols
	imports	= BIT!4,
	/// Resources
	rsrc	= BIT!5,
	/// Debug info
	debug_	= BIT!6,
	
	// Source
//	source	= 
	
	/// PE32 directories
	dirs	= BIT!24,
	/// PE32 load configuration
	loadcfg	= BIT!25,
	
	/// 
	all = 0xffff_ffff,
}
enum Setting {
	/// Input file or data is blob
	blob	= BIT!0,
	/// Dump binary information as hex dump
	hexdump	= BIT!1,
	/// Extract binary information into stdout
	extract	= BIT!2,
	/// Disassemble selections (executable sections)
	disasm	= BIT!24,
	/// Disassemble selections (all sections)
	disasmAll	= BIT!25,
	/// Output disassembly statistics (sections)
	disasmStats	= BIT!26,
	
	/// Any disassembly is requested
	disasmAny = disasm | disasmAll | disasmStats,
}

const(char)* opt_file;
int opt_selected;
int opt_settings;
const(char)* opt_section;
long opt_baseaddress;

int selected_headers()	{ return opt_selected & Select.headers; }
int selected_sections()	{ return opt_selected & Select.sections; }
int selected_relocs()	{ return opt_selected & Select.relocs; }
int selected_exports()	{ return opt_selected & Select.exports; }
int selected_imports()	{ return opt_selected & Select.imports; }
int selected_rsrc()	{ return opt_selected & Select.rsrc; }
int selected_debug()	{ return opt_selected & Select.debug_; }
int selected_dirs()	{ return opt_selected & Select.dirs; }
int selected_loadcfg()	{ return opt_selected & Select.loadcfg; }

int setting_blob()	{ return opt_settings & Setting.blob; }
int setting_hexdump()	{ return opt_settings & Setting.hexdump; }
int setting_extract()	{ return opt_settings & Setting.extract; }

int setting_disasm()	{ return opt_settings & Setting.disasm; }
int setting_disasm_all()	{ return opt_settings & Setting.disasmAll; }
int setting_disasm_stats()	{ return opt_settings & Setting.disasmStats; }
int setting_disasm_any()	{ return opt_settings & Setting.disasmAny; }

/// Dump given file to stdout.
/// Returns: Error code if non-zero
int app_dump() {
	if (setting_blob()) {
		// NOTE: Program exits and memory is free'd
		size_t size = void;
		ubyte *buffer = readall(opt_file, &size);
		if (buffer == null)
			panic_crt();
		
		if (size == 0)
			panic(0, "File is empty");
	
		print_string("filename", opt_file);
		print_u64("filesize", size);
		print_string("format", "Blob");
		print_string("short_name", "blob");
		
		return dump_disassemble(opt_machine, buffer, size, opt_baseaddress);
	}
	
	adbg_object_t *o = adbg_object_open_file(opt_file, 0);
	if (o == null)
		panic_adbg();
	
	// If anything was selected to dump specifically
	if (opt_selected) {
		print_string("filename", opt_file);
		print_u64("filesize", o.file_size);
		print_string("format", adbg_object_name(o));
		print_string("short_name", adbg_object_short_name(o));
		final switch (o.format) with (AdbgObject) {
		case mz:	return dump_mz(o);
		case ne:	return dump_ne(o);
		case pe:	return dump_pe(o);
		case lx:	return dump_lx(o);
		case elf:	return dump_elf(o);
		case macho:	return dump_macho(o);
		case pdb20:	return dump_pdb20(o);
		case pdb70:	return dump_pdb70(o);
		case archive:	return dump_archive(o);
		case mdmp:	return dump_minidump(o);
		case dmp:	return dump_dmp(o);
		case coff:	return dump_coff(o);
		case mscoff:	return dump_mscoff(o);
		case unknown:	assert(0, "Unknown object type"); // Raw/unknown
		}
	}
	
	// Otherwise, make a basic summary
	printf("%s: %s\n", opt_file, adbg_object_name(o));
	return 0;
}

private immutable {
	/// Padding spacing to use in characters
	// PE32 has fields like MinorOperatingSystemVersion (27 chars)
	int __field_padding = -28;
	/// Number of columns to produce in hexdumps.
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

//TODO: if opt_extract_to defined, save to it
// dump binary data to stdout, unformatted
void print_rawdump(void* data, size_t size) {
	while (size > 0) {
		
	}
}

// pretty hex dump to stdout
void print_hexdump(const(char)* name, void *data, size_t dsize, ulong baseaddress = 0) {
	print_header(name);
	
	// Print header
	static immutable string _soff = "Offset    ";
	printf(_soff.ptr);
	for (int ib; ib < __columns; ++ib)
		printf("%02x ", ib);
	putchar('\n');
	
	// Print data
	ubyte *d = cast(ubyte*)data;
	size_t afo; // Absolute file offset
	for (size_t id; id < dsize; id += __columns, baseaddress += __columns) {
		printf("%8llx  ", baseaddress);
		
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
int dump_disassemble_object(adbg_object_t *o,
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
	
	return dump_disassemble(adbg_object_machine(o), data, size, base_address);
}

int dump_disassemble(AdbgMachine machine, void* data, ulong size, ulong base_address) {
	adbg_disassembler_t *dis = adbg_dis_open(machine);
	if (dis == null)
		panic_adbg();
	scope(exit) adbg_dis_close(dis);
	
	if (opt_syntax)
		adbg_dis_options(dis, AdbgDisOpt.syntax, opt_syntax, 0);
	
	adbg_opcode_t op = void;
	adbg_dis_start(dis, data, cast(size_t)size, base_address);
	
	// stats mode
	//TODO: attach shortest and longuest instructions found
	if (setting_disasm_stats()) {
		uint stat_avg;	/// instruction average size
		uint stat_min = uint.max;	/// smallest instruction size
		uint stat_max;	/// longest instruction size
		uint stat_total;	/// total instruction count
		uint stat_illegal;	/// Number of illegal instructions
L_STAT:
		switch (adbg_dis_step(dis, &op)) with (AdbgError) {
		case success:
			stat_avg += op.size;
			++stat_total;
			if (op.size > stat_max) stat_max = op.size;
			if (op.size < stat_min) stat_min = op.size;
			goto L_STAT;
		case disasmIllegalInstruction:
			stat_avg += op.size;
			++stat_total;
			++stat_illegal;
			goto L_STAT;
		case disasmEndOfData: break;
		default:
			panic_adbg();
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
	switch (adbg_dis_step(dis, &op)) with (AdbgError) {
	case success:
		print_disasm_line(&op);
		goto L_DISASM;
	case disasmIllegalInstruction:
		print_disasm_line(&op, "illegal");
		goto L_DISASM;
	case disasmEndOfData:
		return 0;
	default:
		print_string("error", adbg_error_msg());
		return 1;
	}
}
