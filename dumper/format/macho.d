/// Mach-O object dumper.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module format.macho;

import adbg.disassembler;
import adbg.objectserver;
import adbg.objects.macho;
import dumper;
import common.errormgmt;

int dump_macho(adbg_object_t *o) {
	if (SELECTED(Select.headers))
		adbg_object_macho_is_fat(o) ?
			dump_macho_header_fat(o) : dump_macho_header_regular(o);
	if (SELECTED(Select.segments))
		dump_macho_segments(o);
	if (SELECTED(Select.sections))
		dump_macho_sections(o);
	
	return 0;
}

private:

void dump_macho_header_fat(adbg_object_t *o) {
	print_header("FAT Header");
	
	macho_fat_header_t *header = adbg_object_macho_fat_header(o);
	
	print_x32("magic", header.magic, adbg_object_macho_magic_string(header.magic));
	print_u32("nfat_arch", header.nfat_arch);
	
	print_header("FAT Arch Headers");
	
	size_t i;
	macho_fat_arch_entry_t *arch = void;
	while ((arch = adbg_object_macho_fat_arch(o, i++)) != null) with (arch) {
		print_section(cast(uint)i);
		print_x32("cputype", cputype, adbg_object_macho_cputype_string(cputype));
		print_x32("subtype", subtype, adbg_object_macho_subtype_string(cputype, subtype));
		print_x32("offset", offset);
		print_x32("size", size);
		print_x32("alignment", alignment);
	}
}

void dump_macho_header_regular(adbg_object_t *o) {
	print_header("Header");
	
	macho_header_t *header = adbg_object_macho_header(o);
	
	with (header) {
	print_x32("magic", magic, adbg_object_macho_magic_string(magic));
	print_x32("cputype", cputype, adbg_object_macho_cputype_string(cputype));
	print_x32("subtype", subtype, adbg_object_macho_subtype_string(cputype, subtype));
	print_x32("filetype", filetype, adbg_object_macho_filetype_string(filetype));
	print_u32("ncmds", ncmds);
	print_u32("sizeofcmds", sizeofcmds);
	print_flags32("flags", flags,
		"NOUNDEFS".ptr,	MACHO_FLAG_NOUNDEFS,
		"INCRLINK".ptr,	MACHO_FLAG_INCRLINK,
		"DYLDLINK".ptr,	MACHO_FLAG_DYLDLINK,
		"BINDATLOAD".ptr,	MACHO_FLAG_BINDATLOAD,
		"PREBOUND".ptr,	MACHO_FLAG_PREBOUND,
		"SPLIT_SEGS".ptr,	MACHO_FLAG_SPLIT_SEGS,
		"LAZY_INIT".ptr,	MACHO_FLAG_LAZY_INIT,
		"TWOLEVEL".ptr,	MACHO_FLAG_TWOLEVEL,
		"FORCE_FLAT".ptr,	MACHO_FLAG_FORCE_FLAT,
		"NOMULTIDEFS".ptr,	MACHO_FLAG_NOMULTIDEFS,
		"NOFIXPREBINDING".ptr,	MACHO_FLAG_NOFIXPREBINDING,
		"PREBINDABLE".ptr,	MACHO_FLAG_PREBINDABLE,
		"ALLMODSBOUND".ptr,	MACHO_FLAG_ALLMODSBOUND,
		"SUBSECTIONS_VIA_SYMBOLS".ptr,	MACHO_FLAG_SUBSECTIONS_VIA_SYMBOLS,
		"CANONICAL".ptr,	MACHO_FLAG_CANONICAL,
		"WEAK_DEFINES".ptr,	MACHO_FLAG_WEAK_DEFINES,
		"BINDS_TO_WEAK".ptr,	MACHO_FLAG_BINDS_TO_WEAK,
		"ALLOW_STACK_EXECUTION".ptr,	MACHO_FLAG_ALLOW_STACK_EXECUTION,
		"ROOT_SAFE".ptr,	MACHO_FLAG_ROOT_SAFE,
		"SETUID_SAFE".ptr,	MACHO_FLAG_SETUID_SAFE,
		"NO_REEXPORTED_DYLIBS".ptr,	MACHO_FLAG_NO_REEXPORTED_DYLIBS,
		"PIE".ptr,	MACHO_FLAG_PIE,
		"DEAD_STRIPPABLE_DYLIB".ptr,	MACHO_FLAG_DEAD_STRIPPABLE_DYLIB,
		"HAS_TLV_DESCRIPTORS".ptr,	MACHO_FLAG_HAS_TLV_DESCRIPTORS,
		"NO_HEAP_EXECUTION".ptr,	MACHO_FLAG_NO_HEAP_EXECUTION,
		"APP_EXTENSION_SAFE".ptr,	MACHO_FLAG_APP_EXTENSION_SAFE,
		null);
	}
}

void dump_macho_segments(adbg_object_t *o) {
	// NOTE: These are load commands but using segments for all of them
	//       just makes naming shorter and simpler
	print_header("Segments");
	
	size_t i;
	macho_load_command_t *command = void;
	for (; (command = adbg_object_macho_load_command(o, i)) != null; ++i) {
		print_section(cast(uint)i);
		print_x32("cmd", command.cmd, SAFEVAL(adbg_object_macho_command_string(command.cmd)));
		print_x32("cmdsize", command.cmdsize);
		
		switch (command.cmd) {
		case MACHO_LC_SEGMENT:
			macho_segment_command_t *seg = cast(macho_segment_command_t*)command;
			print_stringl("segname", seg.segname.ptr, cast(uint)seg.segname.sizeof);
			print_x32("vmaddr", seg.vmaddr);
			print_x32("vmsize", seg.vmsize);
			print_x32("fileoff", seg.fileoff);
			print_x32("filesize", seg.filesize);
			print_u32("maxprot", seg.maxprot);
			print_u32("initprot", seg.initprot);
			print_u32("nsects", seg.nsects);
			print_x32("flags", seg.flags);
			continue;
		case MACHO_LC_SEGMENT_64:
			macho_segment_command_64_t *seg = cast(macho_segment_command_64_t*)command;
			print_stringl("segname", seg.segname.ptr, cast(uint)seg.segname.sizeof);
			print_x64("vmaddr", seg.vmaddr);
			print_x64("vmsize", seg.vmsize);
			print_x64("fileoff", seg.fileoff);
			print_x64("filesize", seg.filesize);
			print_u32("maxprot", seg.maxprot);
			print_u32("initprot", seg.initprot);
			print_u32("nsects", seg.nsects);
			print_x32("flags", seg.flags);
			continue;
		default: continue;
		}
	}
	if (i == 0)
		panic_adbg();
}

void dump_macho_sections(adbg_object_t *o) {
	print_header("Sections");
	
	void function(void*) dumpsection =
		adbg_object_macho_is_64bit(o) ?
		cast(void function(void*))&dump_macho_section64 :
		cast(void function(void*))&dump_macho_section32;
	size_t i;
	uint t;
	macho_load_command_t *command = void;
	for (; (command = adbg_object_macho_load_command(o, i)) != null; ++i) {
		size_t si;
		void *section = void;
		for (; (section = adbg_object_macho_segment_section(o, command, si)) != null; ++si) {
			print_section(t++);
			dumpsection(section);
		}
	}
}
void dump_macho_section32(macho_section_t *section) {
	print_stringl("sectname", section.sectname.ptr, section.sectname.sizeof);
	print_stringl("segname", section.segname.ptr, section.segname.sizeof);
	print_x32("addr", section.addr);
	print_x32("size", section.size);
	print_x32("offset", section.offset);
	print_x32("align", section.align_);
	print_x32("reloff", section.reloff);
	print_x32("nrelocs", section.nrelocs);
	print_x32("flags", section.flags);
	print_x32("reserved1", section.reserved1);
	print_x32("reserved2", section.reserved2);
}
void dump_macho_section64(macho_section64_t *section) {
	print_stringl("sectname", section.sectname.ptr, section.sectname.sizeof);
	print_stringl("segname", section.segname.ptr, section.segname.sizeof);
	print_x64("addr", section.addr);
	print_x64("size", section.size);
	print_x32("offset", section.offset);
	print_x32("align", section.align_);
	print_x32("reloff", section.reloff);
	print_x32("nrelocs", section.nrelocs);
	print_x32("flags", section.flags);
	print_x32("reserved1", section.reserved1);
	print_x32("reserved2", section.reserved2);
	print_x32("reserved3", section.reserved3);
	
}