module dump.macho;

import core.stdc.stdio;
import adbg.v1.disassembler : adbg_disasm_t, adbg_disasm, AdbgDisasmMode;
import adbg.v1.server.macho;
import adbg.v1.server : adbg_object_t;
import dumper;

int dump_macho(dump_t *dump) {
	dump_title("Apple Mach-O executable");
	
	if (dump.flags & DumpOpt.header)
		dump_macho_hdr(dump.obj);
	
	return 0;
}

private:

void dump_macho_hdr(adbg_object_t *obj) {
	if (obj.macho.fat) {
		dump_h1("FAT Header");
		with (obj.macho.fathdr) printf(
		"magic        %08x\t(%s)\n"~
		"nfat_arch    %u\n",
		magic, adbg_obj_macho_magic(magic),
		nfat_arch
		);
		dump_h1("FAT Arch Header");
		with (obj.macho.fatarch) printf(
		"cputype      %u\t(%s)\n"~
		"subtype      %u\t(%s)\n"~
		"offset       %u\n"~
		"size         %u\n"~
		"alignment    %u\n",
		cputype, adbg_obj_macho_cputype(cputype),
		subtype, adbg_obj_macho_subtype(cputype, subtype),
		offset,
		size,
		alignment
		);
	} else {
		dump_h1("Header");
		with (obj.macho.hdr) printf(
		"magic        %08x\t(%s)\n"~
		"cputype      %u\t(%s)\n"~
		"subtype      %u\t(%s)\n"~
		"filetype     %u\t(%s)\n"~
		"ncmds        %u\n"~
		"sizeofcmds   %u\n"~
		"flags        %08x\t(",
		magic, adbg_obj_macho_magic(magic),
		cputype, adbg_obj_macho_cputype(cputype),
		subtype, adbg_obj_macho_subtype(cputype, subtype),
		filetype, adbg_obj_macho_filetype(filetype),
		ncmds,
		sizeofcmds,
		flags
		);
		with (obj.macho.hdr) {
			if (flags & MACHO_FLAG_NOUNDEFS) printf("NOUNDEFS,");
			if (flags & MACHO_FLAG_INCRLINK) printf("INCRLINK,");
			if (flags & MACHO_FLAG_DYLDLINK) printf("DYLDLINK,");
			if (flags & MACHO_FLAG_BINDATLOAD) printf("BINDATLOAD,");
			if (flags & MACHO_FLAG_PREBOUND) printf("PREBOUND,");
			if (flags & MACHO_FLAG_SPLIT_SEGS) printf("SPLIT_SEGS,");
			if (flags & MACHO_FLAG_LAZY_INIT) printf("LAZY_INIT,");
			if (flags & MACHO_FLAG_TWOLEVEL) printf("TWOLEVEL,");
			if (flags & MACHO_FLAG_FORCE_FLAT) printf("FORCE_FLAT,");
			if (flags & MACHO_FLAG_NOMULTIDEFS) printf("NOMULTIDEFS,");
			if (flags & MACHO_FLAG_NOFIXPREBINDING) printf("NOFIXPREBINDING,");
			if (flags & MACHO_FLAG_PREBINDABLE) printf("PREBINDABLE,");
			if (flags & MACHO_FLAG_ALLMODSBOUND) printf("ALLMODSBOUND,");
			if (flags & MACHO_FLAG_SUBSECTIONS_VIA_SYMBOLS) printf("SUBSECTIONS_VIA_SYMBOLS,");
			if (flags & MACHO_FLAG_CANONICAL) printf("CANONICAL,");
			if (flags & MACHO_FLAG_WEAK_DEFINES) printf("WEAK_DEFINES,");
			if (flags & MACHO_FLAG_BINDS_TO_WEAK) printf("BINDS_TO_WEAK,");
			if (flags & MACHO_FLAG_ALLOW_STACK_EXECUTION) printf("ALLOW_STACK_EXECUTION,");
			if (flags & MACHO_FLAG_ROOT_SAFE) printf("ROOT_SAFE,");
			if (flags & MACHO_FLAG_SETUID_SAFE) printf("SETUID_SAFE,");
			if (flags & MACHO_FLAG_NO_REEXPORTED_DYLIBS) printf("NO_REEXPORTED_DYLIBS,");
			if (flags & MACHO_FLAG_PIE) printf("PIE,");
			if (flags & MACHO_FLAG_DEAD_STRIPPABLE_DYLIB) printf("DEAD_STRIPPABLE_DYLIB,");
			if (flags & MACHO_FLAG_HAS_TLV_DESCRIPTORS) printf("HAS_TLV_DESCRIPTORS,");
			if (flags & MACHO_FLAG_NO_HEAP_EXECUTION) printf("NO_HEAP_EXECUTION,");
			if (flags & MACHO_FLAG_APP_EXTENSION_SAFE) printf("APP_EXTENSION_SAFE,");
		}
		puts(")");
	}
}