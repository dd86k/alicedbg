/// Mach-O object dumper.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module dump.macho;

import adbg.v2.disassembler.core;
import adbg.v2.object.server;
import adbg.v2.object.format.macho;
import dumper;

int dump_macho(adbg_object_t *o, uint flags) {
	if (flags & DumpOpt.header)
		dump_macho_hdr(o);
	
	return 0;
}

private:

void dump_macho_hdr(adbg_object_t *o) {
	if (o.i.macho.fat) {
		dprint_header("FAT Header");
		
		with (o.i.macho.fat_header) {
		dprint_x32("magic", magic, adbg_object_macho_magic_string(magic));
		dprint_u32("nfat_arch", nfat_arch);
		}
		
		dprint_header("FAT Arch Header");
		
		//TODO: multiple nfat_arch
		with (o.i.macho.fat_arch) {
		dprint_x32("cputype", cputype, adbg_object_macho_cputype_string(cputype));
		dprint_x32("subtype", subtype, adbg_object_macho_subtype_string(cputype, subtype));
		dprint_x32("offset", offset);
		dprint_x32("size", size);
		dprint_x32("alignment", alignment);
		}
	} else {
		dprint_header("Header");
		
		with (o.i.macho.header) {
		dprint_x32("magic", magic, adbg_object_macho_magic_string(magic));
		dprint_x32("cputype", cputype, adbg_object_macho_cputype_string(cputype));
		dprint_x32("subtype", subtype, adbg_object_macho_subtype_string(cputype, subtype));
		dprint_x32("filetype", subtype, adbg_object_macho_filetype_string(filetype));
		dprint_u32("ncmds", ncmds);
		dprint_u32("sizeofcmds", sizeofcmds);
		dprint_x32("subtype", subtype, adbg_object_macho_subtype_string(cputype, subtype));
		dprint_flags32("flags", flags,
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
}