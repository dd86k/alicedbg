module adbg.legacy.server.macho;

import adbg.error : adbg_oops, AdbgError;
import adbg.legacy.server : adbg_object_t, AdbgObjFormat;
import adbg.utils.bit;

enum MACHO_MAGIC    = 0xFEEDFACEu;    /// Mach-O BE magic
enum MACHO_MAGIC_64 = 0xFEEDFACFu;    /// Mach-O BE x64 magic
enum MACHO_CIGAM    = 0xCEFAEDFEu;    /// Mach-O LE magic
enum MACHO_CIGAM_64 = 0xCFFAEDFEu;    /// Mach-O LE x64 magic
enum MACHO_FAT_MAGIC   = 0xCAFEBABEu; /// Mach-O FAT BE magic
enum MACHO_FAT_CIGAM   = 0xBEBAFECAu; /// Mach-O FAT LE magic

struct macho_header {
	// 64-bit version just adds a reserved field at the end.
	uint magic;      /// Mach magic number identifier
	uint cputype;    /// Cpu specifier
	uint subtype;    /// Machine specifier
	uint filetype;   /// Type of file
	uint ncmds;      /// Number of load commands
	uint sizeofcmds; /// The size of all the load commands
	uint flags;      /// Flags
}

struct macho_fatmach_header {
	uint magic;     /// Magic
	uint nfat_arch; /// FAT arch version?
}

struct macho_fat_arch {
	uint cputype;    /// 
	uint subtype;    /// 
	uint offset;     /// Offset to first segment?
	uint size;       /// Segments size?
	uint alignment;  /// Page alignment?
}

alias cpu_type_t = int;
enum {
	MACHO_CPUTYPE_VAX = 1,
	MACHO_CPUTYPE_ROMP = 2,
	MACHO_CPUTYPE_NS32032 = 4,
	MACHO_CPUTYPE_NS32332 = 5,
	MACHO_CPUTYPE_MC680x0 = 6,
	MACHO_CPUTYPE_I386 = 7,
	MACHO_CPUTYPE_MIPS = 8,
	MACHO_CPUTYPE_NS32532 = 9,
	MACHO_CPUTYPE_X86_64 = 0x1000007,
	MACHO_CPUTYPE_HPPA = 11,
	MACHO_CPUTYPE_ARM = 12,
	MACHO_CPUTYPE_MC88000 = 13,
	MACHO_CPUTYPE_SPARC = 14,
	MACHO_CPUTYPE_I860 = 15, // MSB
	MACHO_CPUTYPE_I860_LITTLE = 16, // LSB
	MACHO_CPUTYPE_RS6000 = 17,
	MACHO_CPUTYPE_MC98000 = 18,
	MACHO_CPUTYPE_POWERPC = 19,
	MACHO_CPUTYPE_ABI64 = 0x1000000,
	MACHO_CPUTYPE_POWERPC64 = 1000013,
	MACHO_CPUTYPE_VEO = 255
}

// =============================
// cpu_subtype_t - CPU Subtypes, int
// =============================

// VAX subtypes
enum { // SUBTYPE_VAX
	MACHO_SUBTYPE_VAX_ALL = 0,
	MACHO_SUBTYPE_VAX780 = 1,
	MACHO_SUBTYPE_VAX785 = 2,
	MACHO_SUBTYPE_VAX750 = 3,
	MACHO_SUBTYPE_VAX730 = 4,
	MACHO_SUBTYPE_UVAXI = 5,
	MACHO_SUBTYPE_UVAXII = 6,
	MACHO_SUBTYPE_VAX8200 = 7,
	MACHO_SUBTYPE_VAX8500 = 8,
	MACHO_SUBTYPE_VAX8600 = 9,
	MACHO_SUBTYPE_VAX8650 = 10,
	MACHO_SUBTYPE_VAX8800 = 11,
	MACHO_SUBTYPE_UVAXIII = 12
}

// ROMP subtypes
enum { // SUBTYPE_ROMP
	MACHO_SUBTYPE_RT_ALL = 0,
	MACHO_SUBTYPE_RT_PC = 1,
	MACHO_SUBTYPE_RT_APC = 2,
	MACHO_SUBTYPE_RT_135 = 3
}

// 32032/32332/32532 subtypes
enum { // SUBTYPE_32032
	MACHO_SUBTYPE_MMAX_ALL = 0,
	MACHO_SUBTYPE_MMAX_DPC = 1, /* 032 CPU */
	MACHO_SUBTYPE_SQT = 2,
	MACHO_SUBTYPE_MMAX_APC_FPU = 3, /* 32081 FPU */
	MACHO_SUBTYPE_MMAX_APC_FPA = 4, /* Weitek FPA */
	MACHO_SUBTYPE_MMAX_XPC = 5, /* 532 CPU */
}

/*uint32_t SUBTYPE_INTEL(short f, short m) {
	return f + (m << 4);
}*/

// x86 subtypes
enum { // SUBTYPE_I386
	MACHO_SUBTYPE_I386_ALL = 3,
	MACHO_SUBTYPE_X86_64_ALL = MACHO_SUBTYPE_I386_ALL,
	MACHO_SUBTYPE_i386 = 3,
	MACHO_SUBTYPE_i486 = 4,
	MACHO_SUBTYPE_i486SX = 132, // "4 + 128"
	MACHO_SUBTYPE_i586 = 5, // same as PENT, SUBTYPE_INTEL(5, 0)
	MACHO_SUBTYPE_PENPRO = 22, // SUBTYPE_INTEL(6, 1)
	MACHO_SUBTYPE_PENTII_M3 = 54, // SUBTYPE_INTEL(6, 3)
	MACHO_SUBTYPE_PENTII_M5 = 86, // SUBTYPE_INTEL(6, 5)
	MACHO_SUBTYPE_PENTIUM_4 = 10, // SUBTYPE_INTEL(10, 0)
}

// MIPS subty
enum { // SUBTYPE_MIPS
	MACHO_SUBTYPE_MIPS_ALL = 0,
	MACHO_SUBTYPE_R2300 = 1,
	MACHO_SUBTYPE_R2600 = 2,
	MACHO_SUBTYPE_R2800 = 3,
	MACHO_SUBTYPE_R2800a = 4
}

// 680x0 subtypes (m68k)
enum { // SUBTYPE_680x0
	MACHO_SUBTYPE_MC680x0_ALL = 1,
	MACHO_SUBTYPE_MC68030 = 1,
	MACHO_SUBTYPE_MC68040 = 2,
	MACHO_SUBTYPE_MC68030_ONLY = 3,
}

// HPPA subtypes
enum { // SUBTYPE_HPPA
	MACHO_SUBTYPE_HPPA7100 = 0,
	MACHO_SUBTYPE_HPPA7100LC = 1,
	MACHO_SUBTYPE_HPPA_ALL = 0,
}

// Acorn subtypes
enum { // SUBTYPE_ARM
	MACHO_SUBTYPE_ACORN_ALL = 0,
	MACHO_SUBTYPE_A500_ARCH = 1,
	MACHO_SUBTYPE_A500 = 2,
	MACHO_SUBTYPE_A440 = 3,
	MACHO_SUBTYPE_M4 = 4,
	MACHO_SUBTYPE_V4T = 5,
	MACHO_SUBTYPE_V6 = 6,
	MACHO_SUBTYPE_V5TEJ = 7,
	MACHO_SUBTYPE_XSCALE = 8,
	MACHO_SUBTYPE_V7 = 9,
}

// MC88000 subtypes
enum { // SUBTYPE_MC88000
	MACHO_SUBTYPE_MC88000_ALL = 0,
	MACHO_SUBTYPE_MMAX_JPC = 1,
	MACHO_SUBTYPE_MC88100 = 1,
	MACHO_SUBTYPE_MC88110 = 2,
}

// MC98000 (PowerPC) subtypes
enum { // SUBTYPE_MC98000
	MACHO_SUBTYPE_MC98000_ALL = 0,
	MACHO_SUBTYPE_MC98601 = 1,
}

// I860 subtypes
enum { // SUBTYPE_I860
	MACHO_SUBTYPE_I860_ALL = 0,
	MACHO_SUBTYPE_I860 = 1,
}

// I860_LITTLE subtypes
enum { // SUBTYPE_I860_LITTLE
	MACHO_SUBTYPE_I860_LITTLE_ALL = 0,
	MACHO_SUBTYPE_I860_LITTLE = 1
}

// RS6000 subtypes
enum { // SUBTYPE_RS6000
	MACHO_SUBTYPE_RS6000_ALL = 0,
	MACHO_SUBTYPE_RS6000 = 1,
}

// Sun4 subtypes (port done at CMU (?))
enum { // SUBTYPE_Sun4
	MACHO_SUBTYPE_SUN4_ALL = 0,
	MACHO_SUBTYPE_SUN4_260 = 1,
	MACHO_SUBTYPE_SUN4_110 = 2,
}

// SPARC subtypes
/*enum { // SUBTYPE_SPARC
	ALL = 0
};*/

// PowerPC subtypes
enum { // SUBTYPE_PowerPC
	MACHO_SUBTYPE_POWERPC_ALL = 0,
	MACHO_SUBTYPE_POWERPC_601 = 1,
	MACHO_SUBTYPE_POWERPC_602 = 2,
	MACHO_SUBTYPE_POWERPC_603 = 3,
	MACHO_SUBTYPE_POWERPC_603e = 4,
	MACHO_SUBTYPE_POWERPC_603ev = 5,
	MACHO_SUBTYPE_POWERPC_604 = 6,
	MACHO_SUBTYPE_POWERPC_604e = 7,
	MACHO_SUBTYPE_POWERPC_620 = 8,
	MACHO_SUBTYPE_POWERPC_750 = 9,
	MACHO_SUBTYPE_POWERPC_7400 = 10,
	MACHO_SUBTYPE_POWERPC_7450 = 11,
	MACHO_SUBTYPE_POWERPC_970 = 100,
}

// VEO subtypes
enum { // SUBTYPE_VEO
	MACHO_SUBTYPE_VEO_1 = 1,
	MACHO_SUBTYPE_VEO_2 = 2,
	MACHO_SUBTYPE_VEO_3 = 3,
	MACHO_SUBTYPE_VEO_4 = 4,
	//VEO_ALL = VEO_2,
}

// ========================
/// File types
// ========================
alias macho_filetype_t = int;
enum {
	MACHO_FILETYPE_UNKNOWN     = 0,
	MACHO_FILETYPE_OBJECT      = 0x1,
	MACHO_FILETYPE_EXECUTE     = 0x2,
	MACHO_FILETYPE_FVMLIB      = 0x3,
	MACHO_FILETYPE_CORE        = 0x4,
	MACHO_FILETYPE_PRELOAD     = 0x5,
	MACHO_FILETYPE_DYLIB       = 0x6,
	MACHO_FILETYPE_DYLINKER    = 0x7,
	MACHO_FILETYPE_BUNDLE      = 0x8,
	MACHO_FILETYPE_DYLIB_STUB  = 0x9,
	MACHO_FILETYPE_DSYM        = 0xA,
	MACHO_FILETYPE_KEXT_BUNDLE = 0xB,
}

alias macho_flag_t = int;
enum { //flag_t
	MACHO_FLAG_NOUNDEFS                = 0x00000001,
	MACHO_FLAG_INCRLINK                = 0x00000002,
	MACHO_FLAG_DYLDLINK                = 0x00000004,
	MACHO_FLAG_BINDATLOAD              = 0x00000008,
	MACHO_FLAG_PREBOUND                = 0x00000010,
	MACHO_FLAG_SPLIT_SEGS              = 0x00000020,
	MACHO_FLAG_LAZY_INIT               = 0x00000040,
	MACHO_FLAG_TWOLEVEL                = 0x00000080,
	MACHO_FLAG_FORCE_FLAT              = 0x00000100,
	MACHO_FLAG_NOMULTIDEFS             = 0x00000200,
	MACHO_FLAG_NOFIXPREBINDING         = 0x00000400,
	MACHO_FLAG_PREBINDABLE             = 0x00000800,
	MACHO_FLAG_ALLMODSBOUND            = 0x00001000,
	MACHO_FLAG_SUBSECTIONS_VIA_SYMBOLS = 0x00002000,
	MACHO_FLAG_CANONICAL               = 0x00004000,
	MACHO_FLAG_WEAK_DEFINES            = 0x00008000,
	MACHO_FLAG_BINDS_TO_WEAK           = 0x00010000,
	MACHO_FLAG_ALLOW_STACK_EXECUTION   = 0x00020000,
	MACHO_FLAG_ROOT_SAFE               = 0x00040000,
	MACHO_FLAG_SETUID_SAFE             = 0x00080000,
	MACHO_FLAG_NO_REEXPORTED_DYLIBS    = 0x00100000,
	MACHO_FLAG_PIE                     = 0x00200000,
	MACHO_FLAG_DEAD_STRIPPABLE_DYLIB   = 0x00400000,
	MACHO_FLAG_HAS_TLV_DESCRIPTORS     = 0x00800000,
	MACHO_FLAG_NO_HEAP_EXECUTION       = 0x01000000,
	MACHO_FLAG_APP_EXTENSION_SAFE      = 0x02000000
}

int adbg_obj_macho_load(adbg_object_t *obj, int sig) {
	obj.format = AdbgObjFormat.MachO;
	
	switch (sig) {
	case MACHO_MAGIC:	// 32-bit LE
		
		break;
	case MACHO_MAGIC_64:	// 64-bit LE
		
		break;
	case MACHO_CIGAM:	// 32-bit BE
		
		obj.macho.reversed = true;
		break;
	case MACHO_CIGAM_64:	// 64-bit BE
		
		obj.macho.reversed = true;
		break;
	case MACHO_FAT_MAGIC:	// Fat LE
		
		obj.macho.fat = true;
		break;
	case MACHO_FAT_CIGAM:	// Fat BE
		
		obj.macho.fat = true;
		obj.macho.reversed = true;
		break;
	default:
		return adbg_oops(AdbgError.assertion);
	}
	
	if (obj.macho.fat) {
		obj.macho.fathdr = cast(macho_fatmach_header*)(obj.buf);
		obj.macho.fatarch = cast(macho_fat_arch*)(obj.buf);
	} else {
		obj.macho.hdr = cast(macho_header*)(obj.buf);
	}
	
	if (obj.macho.reversed) {
		//obj.macho.hdr.magic = adbg_util_bswap32(obj.macho.hdr.magic);
		
		if (obj.macho.fat) {
			obj.macho.fathdr.nfat_arch = adbg_util_bswap32(obj.macho.fathdr.nfat_arch);
			obj.macho.fatarch.cputype = adbg_util_bswap32(obj.macho.fatarch.cputype);
			obj.macho.fatarch.subtype = adbg_util_bswap32(obj.macho.fatarch.subtype);
			obj.macho.fatarch.offset = adbg_util_bswap32(obj.macho.fatarch.offset);
			obj.macho.fatarch.size = adbg_util_bswap32(obj.macho.fatarch.size);
			obj.macho.fatarch.alignment = adbg_util_bswap32(obj.macho.fatarch.alignment);
		} else {
			obj.macho.hdr.cputype = adbg_util_bswap32(obj.macho.hdr.cputype);
			obj.macho.hdr.subtype = adbg_util_bswap32(obj.macho.hdr.subtype);
			obj.macho.hdr.filetype = adbg_util_bswap32(obj.macho.hdr.filetype);
			obj.macho.hdr.ncmds = adbg_util_bswap32(obj.macho.hdr.ncmds);
			obj.macho.hdr.sizeofcmds = adbg_util_bswap32(obj.macho.hdr.sizeofcmds);
			obj.macho.hdr.flags = adbg_util_bswap32(obj.macho.hdr.flags);
		}
	}
	
	
	
	return 0;
}

const(char) *adbg_obj_macho_magic(uint sig) {
	switch (sig) {
	case MACHO_MAGIC:	return "MACHO_MAGIC";
	case MACHO_MAGIC_64:	return "MACHO_MAGIC_64";
	case MACHO_CIGAM: 	return "MACHO_CIGAM";
	case MACHO_CIGAM_64:	return "MACHO_CIGAM_64";
	case MACHO_FAT_MAGIC:	return "MACHO_FAT_MAGIC";
	case MACHO_FAT_CIGAM:	return "MACHO_FAT_CIGAM";
	default: return null;
	}
}

const(char) *adbg_obj_macho_filetype(uint type) {
	switch (type) {
	case MACHO_FILETYPE_OBJECT:      return "Object";
	case MACHO_FILETYPE_EXECUTE:     return "Executable";
	case MACHO_FILETYPE_FVMLIB:      return "Fixed VM Library";
	case MACHO_FILETYPE_CORE:        return "Core";
	case MACHO_FILETYPE_PRELOAD:     return "Preload";
	case MACHO_FILETYPE_DYLIB:       return "Dynamic library";
	case MACHO_FILETYPE_DYLINKER:    return "Dynamic linker";
	case MACHO_FILETYPE_BUNDLE:      return "Bundle";
	case MACHO_FILETYPE_DYLIB_STUB:  return "Dynamic library stub";
	case MACHO_FILETYPE_DSYM:        return "Companion file (debug)";
	case MACHO_FILETYPE_KEXT_BUNDLE: return "Kext bundle";
	// Fat files have no "filetypes", thus why handled earlier
	default:             return "?";
	}
}

const(char) *adbg_obj_macho_cputype(uint type) {
	switch (type) {
	case MACHO_CPUTYPE_VAX:	return "VAX";
	case MACHO_CPUTYPE_ROMP:	return "ROMP";
	case MACHO_CPUTYPE_NS32032: return "NS32032";
	case MACHO_CPUTYPE_NS32332: return "NS32332";
	case MACHO_CPUTYPE_NS32532: return "NS32532";
	case MACHO_CPUTYPE_I386:	return "x86";
	case MACHO_CPUTYPE_X86_64:	return "x86-64";
	case MACHO_CPUTYPE_MIPS:	return "MIPS";
	case MACHO_CPUTYPE_MC680x0:	return "MC68000";
	case MACHO_CPUTYPE_HPPA:	return "HPPA";
	case MACHO_CPUTYPE_ARM:	return "ARM";
	case MACHO_CPUTYPE_MC88000:	return "MC88000";
	case MACHO_CPUTYPE_MC98000:	return "MC98000";
	case MACHO_CPUTYPE_I860, MACHO_CPUTYPE_I860_LITTLE:	return "i860";
	case MACHO_CPUTYPE_RS6000: return "RS6000";
	case MACHO_CPUTYPE_POWERPC64:	return "PowerPC64";
	case MACHO_CPUTYPE_POWERPC:	return "PowerPC";
	case MACHO_CPUTYPE_VEO:	return "VEO";
	default:	return "?";
	}
}

const(char) *adbg_obj_macho_subtype(uint type, uint subtype) {
	switch (type) {
	case MACHO_CPUTYPE_VAX:
		switch (subtype) {
		case MACHO_SUBTYPE_VAX780:  return "VAX780";
		case MACHO_SUBTYPE_VAX785:  return "VAX785";
		case MACHO_SUBTYPE_VAX750:  return "VAX750";
		case MACHO_SUBTYPE_VAX730:  return "VAX730";
		case MACHO_SUBTYPE_UVAXI:   return "UVAXI";
		case MACHO_SUBTYPE_UVAXII:  return "UVAXII";
		case MACHO_SUBTYPE_VAX8200: return "VAX8200";
		case MACHO_SUBTYPE_VAX8500: return "VAX8500";
		case MACHO_SUBTYPE_VAX8600: return "VAX8600";
		case MACHO_SUBTYPE_VAX8650: return "VAX8650";
		case MACHO_SUBTYPE_VAX8800: return "VAX8800";
		case MACHO_SUBTYPE_UVAXIII: return "UVAXIII";
		default:                    return "VAX";
		}
	case MACHO_CPUTYPE_ROMP:
		switch (subtype) {
		case MACHO_SUBTYPE_RT_PC:  return "RT_PC";
		case MACHO_SUBTYPE_RT_APC: return "RT_APC";
		case MACHO_SUBTYPE_RT_135: return "RT_135";
		default:                   return "ROMP";
		}
	case MACHO_CPUTYPE_NS32032: return "NS32032";
	case MACHO_CPUTYPE_NS32332: return "NS32332";
	case MACHO_CPUTYPE_NS32532: return "NS32532";
		/*switch (cpu_subtype) { aaaand don't feel like it
MMAX_DPC
SQT
MMAX_APC_FPU
MMAX_APC_FPA
MMAX_XPC
		}*/
	case MACHO_CPUTYPE_I386:
		switch (subtype) {
		case MACHO_SUBTYPE_i386:      return "i386";
		case MACHO_SUBTYPE_i486:      return "i486";
		case MACHO_SUBTYPE_i486SX:    return "i486SX";
		case MACHO_SUBTYPE_i586:      return "i586";
		case MACHO_SUBTYPE_PENPRO:    return "Pentium Pro";
		case MACHO_SUBTYPE_PENTII_M3: return "Pentium III (M3)";
		case MACHO_SUBTYPE_PENTII_M5: return "Pentium III (M5)";
		case MACHO_SUBTYPE_PENTIUM_4: return "Pentium 4";
		default:                      return "x86";
		}
	case MACHO_CPUTYPE_X86_64:        return "x86-64";
	case MACHO_CPUTYPE_MIPS:
		switch (subtype) {
		case MACHO_SUBTYPE_R2300:  return "R2300";
		case MACHO_SUBTYPE_R2600:  return "R2600";
		case MACHO_SUBTYPE_R2800:  return "R2800";
		case MACHO_SUBTYPE_R2800a: return "R2800a";
		default:                   return "MIPS";
		}
	case MACHO_CPUTYPE_MC680x0:
		switch (subtype) {
		case MACHO_SUBTYPE_MC68030:      return "MC68030";
		case MACHO_SUBTYPE_MC68040:      return "MC68040";
		case MACHO_SUBTYPE_MC68030_ONLY: return "MC68030-only";
		default:                         return "MC68000";
		}
	case MACHO_CPUTYPE_HPPA:
		switch (subtype) {
		case MACHO_SUBTYPE_HPPA7100LC: return "HPPA7100LC";
		default:                       return "HPPA7100";
		}
	case MACHO_CPUTYPE_ARM:
		switch (subtype) {
		case MACHO_SUBTYPE_A500_ARCH: return "ARM A500";
		case MACHO_SUBTYPE_A500:      return "ARM A500";
		case MACHO_SUBTYPE_A440:      return "ARM A440";
		case MACHO_SUBTYPE_M4:        return "ARM M4";
		case MACHO_SUBTYPE_V4T:       return "ARM V4T";
		case MACHO_SUBTYPE_V6:        return "ARM V6";
		case MACHO_SUBTYPE_V5TEJ:     return "ARM V5TEJ";
		case MACHO_SUBTYPE_XSCALE:    return "ARM XSCALE";
		case MACHO_SUBTYPE_V7:        return "ARM V7";
		default:                      return "ARM";
		}
	case MACHO_CPUTYPE_MC88000:
		switch (subtype) {
		case MACHO_SUBTYPE_MC88100: return "MC88100";
		case MACHO_SUBTYPE_MC88110: return "MC88110";
		default:                    return "MC88000";
		}
	case MACHO_CPUTYPE_MC98000: return subtype ? "MC98601" : "MC98000";
	case MACHO_CPUTYPE_I860: return "i860 (MSB)";
	case MACHO_CPUTYPE_I860_LITTLE: return "i860 (LSB)";
	case MACHO_CPUTYPE_RS6000: return "RS6000";
	case MACHO_CPUTYPE_POWERPC64:
		switch (subtype) {
		case MACHO_SUBTYPE_POWERPC_601:   return "PowerPC64 601";
		case MACHO_SUBTYPE_POWERPC_602:   return "PowerPC64 602";
		case MACHO_SUBTYPE_POWERPC_603:   return "PowerPC64 603";
		case MACHO_SUBTYPE_POWERPC_603e:  return "PowerPC64 603e";
		case MACHO_SUBTYPE_POWERPC_603ev: return "PowerPC64 603ev";
		case MACHO_SUBTYPE_POWERPC_604:   return "PowerPC64 604";
		case MACHO_SUBTYPE_POWERPC_604e:  return "PowerPC64 604e";
		case MACHO_SUBTYPE_POWERPC_620:   return "PowerPC64 620";
		case MACHO_SUBTYPE_POWERPC_750:   return "PowerPC64 750";
		case MACHO_SUBTYPE_POWERPC_7400:  return "PowerPC64 7400";
		case MACHO_SUBTYPE_POWERPC_7450:  return "PowerPC64 7450";
		case MACHO_SUBTYPE_POWERPC_970:   return "PowerPC64 970";
		default:                          return "PowerPC64";
		}
	case MACHO_CPUTYPE_POWERPC:
		switch (subtype) {
		case MACHO_SUBTYPE_POWERPC_601:   return "PowerPC 601";
		case MACHO_SUBTYPE_POWERPC_602:   return "PowerPC 602";
		case MACHO_SUBTYPE_POWERPC_603:   return "PowerPC 603";
		case MACHO_SUBTYPE_POWERPC_603e:  return "PowerPC 603e";
		case MACHO_SUBTYPE_POWERPC_603ev: return "PowerPC 603ev";
		case MACHO_SUBTYPE_POWERPC_604:   return "PowerPC 604";
		case MACHO_SUBTYPE_POWERPC_604e:  return "PowerPC 604e";
		case MACHO_SUBTYPE_POWERPC_620:   return "PowerPC 620";
		case MACHO_SUBTYPE_POWERPC_750:   return "PowerPC 750";
		case MACHO_SUBTYPE_POWERPC_7400:  return "PowerPC 7400";
		case MACHO_SUBTYPE_POWERPC_7450:  return "PowerPC 7450";
		case MACHO_SUBTYPE_POWERPC_970:   return "PowerPC 970";
		default:                          return "PowerPC";
		}
	case MACHO_CPUTYPE_VEO: return "VEO";
	default:	return "?";
	}
}