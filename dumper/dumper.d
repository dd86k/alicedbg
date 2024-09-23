/// Image/object dumper, imitates objdump
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module dumper;

import adbg.error, adbg.disassembler, adbg.objectserver;
import adbg.include.c.stdio;
import adbg.include.c.stdlib : EXIT_SUCCESS, EXIT_FAILURE, malloc, free;
import adbg.include.c.stdarg;
import adbg.machines;
import adbg.utils.bit : BIT;
import adbg.utils.math : min;
import core.stdc.string;
import core.stdc.ctype : isprint;
import core.stdc.errno;
import format;
import common.errormgmt;
import common.cli : opt_machine, opt_syntax;
import common.utils;

// TODO: Like print_flagsX, something for bit masks: print_mask
//       signature: print_mask(name, flags, values...);
//       usage: print_mask("something", "something", FLAGS, MASK, FLAG1, FLAG2, etc.)
// TODO: print_wstringl (wide-string)
// TODO: (disassembly) attach shortest and longuest instructions found to buffers

extern (C):
__gshared:

enum Select {
	/// Headers, program headers
	headers	= BIT!0,
	/// Sections
	sections	= BIT!1,
	/// Segments
	segments	= BIT!2,
	
	/// Relocations
	relocs	= BIT!4,
	
	/// Exported/dynamic symbols
	exports	= BIT!8,
	/// Import symbols
	imports	= BIT!9,
	/// Resources
	rsrc	= BIT!10,
	/// Debug info
	debug_	= BIT!11,
	
	// Source
//	source	= 
	
	/// PE32 directories
	dirs	= BIT!24,
	/// PE32 load configuration
	loadcfg	= BIT!25,
	
	/// This is a hack to let dumper avoid making a summary
	any = BIT!31,
	
	/// Select everything to dump
	all = 0xffff_ffff,
}
enum Setting {
	/// Input file or data is blob
	blob	= BIT!0,
	/// 
	shortName	= BIT!1,
	
	/// 
	noPrefix = BIT!8,
	
	// bits 17-16: Extraction type
	
	/// Extract binary information into stdout
	extract	= BIT!16,
	/// Dump binary information as hex dump
	hexdump	= BIT!17,
	/// Any sort of extraction is requested
	extractAny = extract | hexdump,
	
	/// Disassemble selections (executable sections)
	disasm	= BIT!24,
	/// Disassemble selections (all sections)
	disasmAll	= BIT!25,
	/// Output disassembly statistics (sections)
	disasmStats	= BIT!26,
	/// Any disassembly is requested
	disasmAny = disasm | disasmAll | disasmStats,
}

int opt_selected;
int opt_settings;
const(char)* opt_section_name;
long opt_baseaddress;
const(char)* opt_extractfile;

const(char)* opt_pdb_stream;

int SELECTED(Select selection) { return opt_selected & selection; }
int SETTING(Setting setting)   { return opt_settings & setting; }

/// Dump given file to stdout.
/// Params: path = Path to object file.
/// Returns: Error code if non-zero
int dump_file(const(char)* path) {
	if (SETTING(Setting.blob)) {
		// NOTE: Program exits and memory is free'ds by OS
		size_t size = void;
		ubyte *buffer = readall(path, &size);
		if (buffer == null)
			panic_crt();
		
		if (size == 0)
			panic(0, "File is empty");
	
		print_string("filename", path);
		print_u64("filesize", size);
		print_string("format", "Blob");
		print_string("short_name", "blob");
		
		return dump_disassemble(opt_machine, buffer, size, opt_baseaddress);
	}
	
	// hotfix when section name specifed, force select all sections
	if (opt_section_name)
		opt_settings |= Setting.disasmAll;
	
	adbg_object_t *o = adbg_object_open_file(path, 0);
	if (o == null)
		panic_adbg("Failed to open object");
	
	// MODE: Advanced
	// If anything was selected to dump specifically, we'll proceed
	// to dump object-specific information.
	if (opt_selected || SETTING(Setting.disasmAny)) {
		// If not in any "extract" mode, print file info
		if (SETTING(Setting.extractAny) == 0) {
			print_string("filename", path);
			print_u64("filesize", adbg_object_filesize(o));
			print_string("type", adbg_object_type_name(o));
			print_string("shortname", adbg_object_type_shortname(o));
		}
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
		case omf:	return dump_omf(o);
		case coff:	return dump_coff(o);
		case mscoff:	return dump_mscoff(o);
		case unknown:	assert(0, "Unknown object type"); // Raw/unknown
		}
	}
	
	// TODO: MODE: Section dump
//	if (SETTING(Setting.extractAny | Setting.disasmAny))
	
	// MODE: Summary
	
	if (SETTING(Setting.noPrefix) == 0)
		printf("%s: ", path);
	
	if (SETTING(Setting.shortName)) {
		puts(SAFEVAL(adbg_object_type_shortname(o)));
		return 0;
	}
	
	// Otherwise, make a basic summary
	printf("%s, %s",
		adbg_object_type_name(o), adbg_object_kind_string(o));
	
	// Print machine type used for object
	AdbgMachine mach = adbg_object_machine(o);
	if (mach)
		printf(", %s", adbg_object_machine_string(o));
	
	putchar('\n');
	return 0;
}

const(char)* SAFEVAL(const(char)* value) {
	return value ? value : "Unknown";
}

private immutable {
	/// Padding spacing to use in characters
	// PE32 has fields like MinorOperatingSystemVersion (27 chars)
	int __field_padding = -28;
	/// Number of columns to produce in hexdumps, in bytes.
	int __columns = 16;
}

void print_header(const(char)* name) {
	printf("\n# %s\n", name);
}

// Field name only
void print_name(const(char)* name) {
	printf("%*s: ", __field_padding, name);
}

void print_columns(const(char)* field, ...) {
	print_name(field);
	
	va_list args = void;
	va_start(args, field);
	const(char) *name = void;
	size_t i;
	while ((name = va_arg!(char*)(args)) != null) {
		if (i++) putchar('\t');
		printf(name);
	}
	putchar('\n');
}

void print_section(uint i, const(char) *name = null, int len = 0) {
	putchar('\n');
	len ? print_u32l("index", i, name, len) : print_u32("index", i, name);
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
	printf("%*s ", -24, machine.ptr);
	
	// Print the more important message
	if (msg) {
		puts(msg);
		return;
	}
	
	printf(op.mnemonic);
	if (op.operands) printf("\t%s", op.operands);
	putchar('\n');
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

void print_char(const(char)* name, char c) {
	char[8] b = void;
	int l = realstring(b.ptr, 8, &c, 1, '\'', '\'');
	b[l] = 0;
	print_x8(name, c, b.ptr);
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
void print_stringf(const(char)* name, const(char)* fmt, ...) {
	printf("%*s: ", __field_padding, name);
	va_list list = void;
	va_start(list, fmt);
	vprintf(fmt, list);
	putchar('\n');
}

void print_warningf(const(char)* fmt, ...) {
	printf("\nwarning: ");
	va_list list = void;
	va_start(list, fmt);
	vprintf(fmt, list);
	putchar('\n');
}

void printf_x16(const(char) *fmt, ushort val, ...) {
	// Format field
	va_list list = void;
	va_start(list, val);
	char[128] b = void;
	vsnprintf(b.ptr, 128, fmt, list);
	
	// Print field and value
	printf("%*s: 0x%04x\n", __field_padding, b.ptr, val);
}

// exists due to int promotion
private
void print_flagsv(int flags, va_list list) {
	ushort count;
Lfetch:
	const(char) *name = va_arg!(const(char)*)(list);
	if (name == null) {
		puts(")");
		return;
	}
	
	if ((flags & va_arg!int(list)) == 0) goto Lfetch; // condition
	if (count++) putchar(',');
	printf("%s", name);
	goto Lfetch;
}

void print_flags8(const(char) *section, ubyte flags, ...) {
	printf("%*s: 0x%02x\t(", __field_padding, section, flags);
	
	va_list args = void;
	va_start(args, flags);
	print_flagsv(flags, args);
}
void print_flags16(const(char) *section, ushort flags, ...) {
	printf("%*s: 0x%04x\t(", __field_padding, section, flags);
	
	va_list args = void;
	va_start(args, flags);
	print_flagsv(flags, args);
}
void print_flags32(const(char) *section, uint flags, ...) {
	printf("%*s: 0x%08x\t(", __field_padding, section, flags);
	
	va_list args = void;
	va_start(args, flags);
	print_flagsv(flags, args);
}
void print_flags64(const(char) *section, ulong flags, ...) {
	printf("%*s: 0x%016llx\t(", __field_padding, section, flags);
	
	va_list args = void;
	va_start(args, flags);
	ushort count;
Lfetch:
	const(char) *name = va_arg!(const(char)*)(args);
	if (name == null) {
		puts(")");
		return;
	}
	
	if ((flags & va_arg!long(args)) == 0) goto Lfetch; // condition
	if (count++) putchar(',');
	printf("%s", name);
	goto Lfetch;
}

void print_directory_entry(const(char)* name, uint rva, uint size) {
	printf("%*s: 0x%08x  %u\n", __field_padding, name, rva, size);
}

void print_reloc16(uint index, ushort seg, ushort off) {
	printf("%4u. 0x%04x:0x%04x\n", index, seg, off);
}

void print_data(const(char)* name, void *data, size_t size, ulong baseaddress = 0) {
	if (SETTING(Setting.hexdump))
		hexdump(name, data, size, baseaddress);

	if (SETTING(Setting.extract))
		rawdump(opt_extractfile, data, size, baseaddress);
}

// dump binary data to stdout, unformatted
// if rawdump to file specified, write to file, otherwise stdout
void rawdump(const(char)* fname, void* data, size_t tsize, ulong baseaddress = 0) {
	FILE* fd = fname ? fopen(fname, "wb") : stdout;
	if (fd == null) {
		perror("fopen");
		return;
	}
	scope(exit) fclose(fd);
	
	size_t r = fwrite(data, tsize, 1, fd);
	if (r == 0) {
		perror("fwrite");
		return;
	}
}

// pretty hex dump to stdout
void hexdump(const(char)* name, void *data, size_t dsize, ulong baseaddress = 0) {
	print_header(name);
	
	// Print header
	static immutable string _soff = "Offset    ";
	printf(_soff.ptr);
	for (int ib; ib < __columns; ++ib)
		printf("%2x ", ib);
	putchar('\n');
	
	// Print data
	ubyte *ptr = cast(ubyte*)data;
	size_t offset; // Absolute file offset
	for (size_t id; id < dsize; id += __columns, baseaddress += __columns) {
		printf("%8llx  ", baseaddress);
		
		// Adjust column for row
		bool eof = offset + __columns >= dsize;
		int col = eof ? cast(int)(__columns - (dsize - offset)) : __columns;
		
		// Print data bytes
		for (size_t ib, oi = offset; ib < col; ++ib, ++oi)
			printf("%02x ", ptr[oi]);
		
		// Adjust spacing between the two sections
		int spcrem = ((__columns - col) * 3) + 1;
		for (int s; s < spcrem; ++s)
			putchar(' ');
		
		// Print printable characters
		for (size_t ib, oi = offset; ib < col; ++ib, ++oi)
			putchar(isprint(ptr[oi]) ? ptr[oi] : '.');
		
		// New row
		offset += col;
		putchar('\n');
	}
}
// name is typically section name or filename if raw
int dump_disassemble_object(adbg_object_t *o,
	const(char) *name, int namemax,
	void* data, ulong size, ulong base_address) {
	assert(data, "Data pointer null");
	
	if (name && namemax)
		print_stringl("section", name, namemax);
	
	if (size == 0)
		return 0;
	
	return dump_disassemble(adbg_object_machine(o), data, size, base_address);
}

int dump_disassemble(AdbgMachine machine, void* data, ulong size, ulong base_address) {
	// Overrides
	adbg_disassembler_t *dis = adbg_dis_open(opt_machine ? opt_machine : machine);
	if (dis == null)
		panic_adbg();
	scope(exit) adbg_dis_close(dis);
	
	if (opt_syntax)
		adbg_dis_options(dis, AdbgDisOpt.syntax, opt_syntax, 0);
	
	adbg_opcode_t op = void;
	adbg_dis_start(dis, data, cast(size_t)size, base_address);
	
	// stats mode
	if (SETTING(Setting.disasmStats)) {
		uint stat_avg;	/// instruction average size
		uint stat_min = uint.max;	/// smallest instruction size
		uint stat_max;	/// longest instruction size
		uint stat_total;	/// total instruction count
		uint stat_illegal;	/// Number of illegal instructions
Lstat:
		switch (adbg_dis_step(dis, &op)) with (AdbgError) {
		case success:
			stat_avg += op.size;
			++stat_total;
			if (op.size > stat_max) stat_max = op.size;
			if (op.size < stat_min) stat_min = op.size;
			goto Lstat;
		case disasmIllegalInstruction:
			stat_avg += op.size;
			++stat_total;
			++stat_illegal;
			goto Lstat;
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
Ldisasm:
	switch (adbg_dis_step(dis, &op)) with (AdbgError) {
	case success:
		print_disasm_line(&op);
		goto Ldisasm;
	case disasmIllegalInstruction:
		print_disasm_line(&op, "illegal");
		goto Ldisasm;
	case disasmEndOfData:
		return 0;
	default:
		panic_adbg();
		return 0;
	}
}
