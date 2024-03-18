/// Mach-O format.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.object.format.macho;

import adbg.error;
import adbg.object.server : adbg_object_t, AdbgObject;
import adbg.object.machines : AdbgMachine;
import adbg.utils.bit;
import core.stdc.stdlib : calloc;

// Sources:
// - https://github.com/opensource-apple/cctools/blob/master/include/mach/machine.h
// - https://github.com/opensource-apple/cctools/blob/master/include/mach-o/loader.h

/// Smallest Mach-O size.
// https://codegolf.stackexchange.com/a/154685
private enum MINIMUM_SIZE = 0x1000; // Due to paging
private enum LIMIT_FAT_ARCH = 200;
private enum LIMIT_COMMANDS = 2000;

enum MACHO_MAGIC	= 0xFEEDFACEu; /// Mach-O BE magic
enum MACHO_MAGIC64	= 0xFEEDFACFu; /// Mach-O BE x64 magic
enum MACHO_CIGAM	= 0xCEFAEDFEu; /// Mach-O LE magic
enum MACHO_CIGAM64	= 0xCFFAEDFEu; /// Mach-O LE x64 magic
enum MACHO_FATMAGIC	= 0xCAFEBABEu; /// Mach-O FAT BE magic
enum MACHO_FATCIGAM	= 0xBEBAFECAu; /// Mach-O FAT LE magic

// 64-bit version just adds a 32-bit reserved field at the end.
struct macho_header {
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
	uint nfat_arch; /// Number of architectures (structs) in binary
}

struct macho_fat_arch {
	uint cputype;    /// 
	uint subtype;    /// 
	uint offset;     /// File offset to first segment or command?
	uint size;       /// Segments size?
	uint alignment;  /// Page alignment?
}

struct macho_load_command {
	uint cmd;	/// type of load command
	uint cmdsize;	/// total size of command in bytes
}

alias int vm_prot_t;

struct macho_segment_command { /* for 32-bit architectures */
	uint	cmd;	/// LC_SEGMENT
	uint	cmdsize;	/// includes sizeof section structs
	char[16]	segname;	/// segment name
	uint	vmaddr;	/// memory address of this segment
	uint	vmsize;	/// memory size of this segment
	uint	fileoff;	/// file offset of this segment
	uint	filesize;	/// amount to map from the file
	vm_prot_t	maxprot;	/// maximum VM protection
	vm_prot_t	initprot;	/// initial VM protection
	uint	nsects;	/// number of sections in segment
	uint	flags;	/// flags
}

struct macho_segment_command_64 { /* for 64-bit architectures */
	uint	cmd;	/// LC_SEGMENT_64
	uint	cmdsize;	/// includes sizeof section_64 structs
	char[16]	segname;	/// segment name
	ulong	vmaddr;	/// memory address of this segment
	ulong	vmsize;	/// memory size of this segment
	ulong	fileoff;	/// file offset of this segment
	ulong	filesize;	/// amount to map from the file
	vm_prot_t	maxprot;	/// maximum VM protection
	vm_prot_t	initprot;	/// initial VM protection
	uint	nsects;	/// number of sections in segment
	uint	flags;	/// flags
}

alias cpu_type_t = int;
enum {
	MACHO_CPUTYPE_ANY = -1,
	/// Used as a bitmask to mark cputype as 64-bit
	MACHO_CPUTYPE_ABI64 = 0x1000000,
	MACHO_CPUTYPE_VAX = 1,
	MACHO_CPUTYPE_ROMP = 2,
	MACHO_CPUTYPE_NS32032 = 4,
	MACHO_CPUTYPE_NS32332 = 5,
	MACHO_CPUTYPE_MC680x0 = 6,
	MACHO_CPUTYPE_I386 = 7,
	MACHO_CPUTYPE_X86_64 = MACHO_CPUTYPE_I386 | MACHO_CPUTYPE_ABI64,
	MACHO_CPUTYPE_MIPS = 8,
	MACHO_CPUTYPE_NS32532 = 9,
	MACHO_CPUTYPE_HPPA = 11,
	MACHO_CPUTYPE_ARM = 12,
	MACHO_CPUTYPE_ARM64 = MACHO_CPUTYPE_ARM | MACHO_CPUTYPE_ABI64,
	MACHO_CPUTYPE_MC88000 = 13,
	MACHO_CPUTYPE_SPARC = 14,
	MACHO_CPUTYPE_I860 = 15, // big-endian
	MACHO_CPUTYPE_I860_LITTLE = 16, // little-endian
	MACHO_CPUTYPE_RS6000 = 17,
	MACHO_CPUTYPE_MC98000 = 18,
	MACHO_CPUTYPE_POWERPC = 18,
	MACHO_CPUTYPE_POWERPC64 = MACHO_CPUTYPE_POWERPC | MACHO_CPUTYPE_ABI64,
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

private
template SUBTYPE_INTEL(short f, short m) {
	enum SUBTYPE_INTEL = f + (m << 4);
}

// x86 subtypes
enum { // SUBTYPE_I386
	MACHO_SUBTYPE_I386_ALL = 3,
	MACHO_SUBTYPE_X86_64_ALL = MACHO_SUBTYPE_I386_ALL,
	MACHO_SUBTYPE_i386 = 3,
	MACHO_SUBTYPE_i486 = 4,
	MACHO_SUBTYPE_i486SX = 4 + 128, // "4 + 128"
	MACHO_SUBTYPE_i586 = 5,
	MACHO_SUBTYPE_PENT = SUBTYPE_INTEL!(5, 0),
	MACHO_SUBTYPE_PENPRO = SUBTYPE_INTEL!(6, 1),
	MACHO_SUBTYPE_PENTII_M3 = SUBTYPE_INTEL!(6, 3),
	MACHO_SUBTYPE_PENTII_M5 = SUBTYPE_INTEL!(6, 5),
	MACHO_SUBTYPE_PENTIUM_4 = SUBTYPE_INTEL!(10, 0),
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
	MACHO_SUBTYPE_V8 = 13,
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

// Flags
alias macho_flag_t = int;
enum {
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

// Commands
enum {
	MACHO_LC_REQ_DYLD	= 0x80000000,	/// Requires dynamic linker
	MACHO_LC_SEGMENT	= 0x1,	/// Segment of this file to be mapped
	MACHO_LC_SYMTAB	= 0x2,	/// Link-edit stab symbol table info
	MACHO_LC_SYMSEG	= 0x3,	/// Link-edit gdb symbol table info (obsolete)
	MACHO_LC_THREAD	= 0x4,	/// Thread
	MACHO_LC_UNIXTHREAD	= 0x5,	/// Unix thread (includes a stack)
	MACHO_LC_LOADFVMLIB	= 0x6,	/// Load a specified fixed VM shared library
	MACHO_LC_IDFVMLIB	= 0x7,	/// Fixed VM shared library identification
	MACHO_LC_IDENT	= 0x8,	/// Object identification info (obsolete)
	MACHO_LC_FVMFILE	= 0x9,	/// Fixed VM file inclusion (internal use)
	MACHO_LC_PREPAGE	= 0xa,	/// Prepage command (internal use)
	MACHO_LC_DYSYMTAB	= 0xb,	/// Dynamic link-edit symbol table info
	MACHO_LC_LOAD_DYLIB	= 0xc,	/// Load a dynamically linked shared library
	MACHO_LC_ID_DYLIB	= 0xd,	/// Dynamically linked shared lib ident
	MACHO_LC_LOAD_DYLINKER	= 0xe,	/// Load a dynamic linker
	MACHO_LC_ID_DYLINKER	= 0xf,	/// Dynamic linker identification
	MACHO_LC_PREBOUND_DYLIB	= 0x10,	/// Modules prebound for a dynamically linked shared library
	MACHO_LC_ROUTINES	= 0x11,	/// Image routines
	MACHO_LC_SUB_FRAMEWORK	= 0x12,	/// Sub framework
	MACHO_LC_SUB_UMBRELLA	= 0x13,	/// Sub umbrella
	MACHO_LC_SUB_CLIENT	= 0x14,	/// Sub client
	MACHO_LC_SUB_LIBRARY	= 0x15,	/// Sub library
	MACHO_LC_TWOLEVEL_HINTS	= 0x16,	/// Two-level namespace lookup hints
	MACHO_LC_PREBIND_CKSUM	= 0x17,	/// Prebind checksum
	MACHO_LC_SEGMENT_64	= 0x19,	/// 64-bit segment of this file to be mapped
	MACHO_LC_ROUTINES_64	= 0x1a,	/// 64-bit image routines
	MACHO_LC_UUID	= 0x1b,	/// The uuid
	MACHO_LC_RPATH	= 0x1c | MACHO_LC_REQ_DYLD,	/// Runpath additions
	MACHO_LC_CODE_SIGNATURE	= 0x1d,	/// Local of code signature
	MACHO_LC_SEGMENT_SPLIT_INFO	= 0x1e,	/// Local of info to split segments
	MACHO_LC_REEXPORT_DYLIB	= 0x1f | MACHO_LC_REQ_DYLD,	/// Load and re-export dylib
	MACHO_LC_LAZY_LOAD_DYLIB	= 0x20,	/// Delay load of dylib until first use
	MACHO_LC_ENCRYPTION_INFO	= 0x21,	/// Encrypted segment information
	MACHO_LC_DYLD_INFO	= 0x22,	/// Compressed dyld information
	MACHO_LC_DYLD_INFO_ONLY	= 0x22 | MACHO_LC_REQ_DYLD,	/// Compressed dyld information only
	MACHO_LC_LOAD_UPWARD_DYLIB	= 0x23 | MACHO_LC_REQ_DYLD, /// Load upward dylib
	MACHO_LC_VERSION_MIN_MACOSX	= 0x24,	/// Build for MacOSX min OS version
	MACHO_LC_VERSION_MIN_IPHONEOS	= 0x25,	/// Build for iPhoneOS min OS version
	MACHO_LC_FUNCTION_STARTS	= 0x26,	/// Compressed table of function start addresses
	MACHO_LC_DYLD_ENVIRONMENT	= 0x27,	/// String for dyld to treat like environment variable
	MACHO_LC_MAIN	= 0x28 | MACHO_LC_REQ_DYLD,	/// Replacement for LC_UNIXTHREAD
	MACHO_LC_DATA_IN_CODE	= 0x29,	/// Table of non-instructions in __text
	MACHO_LC_SOURCE_VERSION	= 0x2a,	/// Source version used to build binary
	MACHO_LC_DYLIB_CODE_SIGN_DRS	= 0x2b,	/// Code signing DRs copied from linked dylibs
	MACHO_LC_ENCRYPTION_INFO_64	= 0x2c,	/// 64-bit encrypted segment information
	MACHO_LC_LINKER_OPTION	= 0x2D,	/// linker options in MH_OBJECT files
	MACHO_LC_LINKER_OPTIMIZATION_HINT	= 0x2e,	/// Optimization hints in MH_OBJECT files
	MACHO_LC_VERSION_MIN_WATCHOS	= 0x30,	/// Build for Watch min OS version
}

int adbg_object_macho_load(adbg_object_t *o) {
	if (o.file_size < MINIMUM_SIZE)
		return adbg_oops(AdbgError.objectTooSmall);
	
	o.format = AdbgObject.macho;
	
	o.i.macho.header = cast(macho_header*)o.buffer;
	
	// NOTE: Internals are set to zero.
	//       Unless I change that, and this snippet leads to a crash.
	with (o.i) switch (macho.header.magic) {
	case MACHO_MAGIC:	// 32-bit LE
		break;
	case MACHO_MAGIC64:	// 64-bit LE
		macho.is64 = true;
		break;
	case MACHO_CIGAM:	// 32-bit BE
		o.p.reversed = true;
		break;
	case MACHO_CIGAM64:	// 64-bit BE
		o.p.reversed = true;
		macho.is64 = true;
		break;
	case MACHO_FATMAGIC:	// Fat LE
		macho.fat = true;
		break;
	case MACHO_FATCIGAM:	// Fat BE
		macho.fat = true;
		o.p.reversed = true;
		break;
	default:
		return adbg_oops(AdbgError.assertion);
	}
	
	version (Trace) trace("64=%d reversed=%d fat=%d", o.i.macho.is64, o.p.reversed, o.i.macho.fat);
	
	with (o.i)
	if (o.p.reversed) {
		if (macho.fat) {
			macho.fat_header.nfat_arch = adbg_bswap32(macho.fat_header.nfat_arch);
			macho.fat_arch.cputype = adbg_bswap32(macho.fat_arch.cputype);
			macho.fat_arch.subtype = adbg_bswap32(macho.fat_arch.subtype);
			macho.fat_arch.offset = adbg_bswap32(macho.fat_arch.offset);
			macho.fat_arch.size = adbg_bswap32(macho.fat_arch.size);
			macho.fat_arch.alignment = adbg_bswap32(macho.fat_arch.alignment);
		} else {
			macho.header.cputype = adbg_bswap32(macho.header.cputype);
			macho.header.subtype = adbg_bswap32(macho.header.subtype);
			macho.header.filetype = adbg_bswap32(macho.header.filetype);
			macho.header.ncmds = adbg_bswap32(macho.header.ncmds);
			macho.header.sizeofcmds = adbg_bswap32(macho.header.sizeofcmds);
			macho.header.flags = adbg_bswap32(macho.header.flags);
		}
	}
	
	with (o.i)
	if (macho.fat) {
		macho.fat_arch = cast(macho_fat_arch*)(o.buffer + macho_fatmach_header.sizeof);
		macho.reversed_fat_arch = cast(bool*)calloc(macho.fat_header.nfat_arch, bool.sizeof);
		if (macho.reversed_fat_arch == null)
			return adbg_oops(AdbgError.crt);
	} else if (macho.header.ncmds) {
		macho.reversed_commands = cast(bool*)calloc(macho.header.ncmds, bool.sizeof);
		if (macho.reversed_commands == null)
			return adbg_oops(AdbgError.crt);
		size_t cl = macho.is64 ? macho_header.sizeof + uint.sizeof : macho_header.sizeof;
		version (Trace) trace("cl=%zx 64=%d", cl, macho.is64);
		macho.commands = cast(macho_load_command*)(o.buffer + cl);
	}
	
	return 0;
}

//TODO: Consider adbg_object_macho_isfat

macho_header* adbg_object_macho_header(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	// NOTE: pre-swapped
	return o.i.macho.header;
}

macho_fatmach_header* adbg_object_macho_header_fat(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	// NOTE: pre-swapped
	return o.i.macho.fat_header;
}

macho_fat_arch* adbg_object_macho_fat_arch(adbg_object_t *o, size_t index) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.i.macho.fat_header == null) {
		adbg_oops(AdbgError.uninitiated);
		return null; // not loaded
	}
	if (o.i.macho.fat == false) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (index >= LIMIT_FAT_ARCH) {
		adbg_oops(AdbgError.objectMalformed);
		return null;
	}
	if (index >= o.i.macho.fat_header.nfat_arch) {
		adbg_oops(AdbgError.objectMalformed);
		return null;
	}
	
	macho_fat_arch* fat_arch = &o.i.macho.fat_arch[index];
	if (o.p.reversed && o.i.macho.reversed_fat_arch[index] == false) {
		fat_arch.cputype	= adbg_bswap32(fat_arch.cputype);
		fat_arch.subtype	= adbg_bswap32(fat_arch.subtype);
		fat_arch.offset	= adbg_bswap32(fat_arch.offset);
		fat_arch.size	= adbg_bswap32(fat_arch.size);
		fat_arch.alignment	= adbg_bswap32(fat_arch.alignment);
		o.i.macho.reversed_fat_arch[index] = true;
	}
	return fat_arch;
}

// Load commands have a type and size.
// Size includes type (4 bytes), size (4 bytes), and anything that follows it
// until next command.
macho_load_command* adbg_object_macho_load_command(adbg_object_t *o, size_t index) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.i.macho.header == null) {
		adbg_oops(AdbgError.uninitiated);
		return null; // not loaded
	}
	if (o.i.macho.fat) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (index >= LIMIT_COMMANDS) {
		adbg_oops(AdbgError.objectMalformed);
		return null;
	}
	if (index >= o.i.macho.header.ncmds) {
		adbg_oops(AdbgError.objectMalformed);
		return null;
	}
	
	//TODO: Consider "caching" positions (calloc array) for faster lookup
	macho_load_command* command = void;
	size_t next;
	for (size_t i; i <= index; ++i) {
		command = cast(macho_load_command*)(cast(void*)o.i.macho.commands + next);
		if (o.p.reversed && o.i.macho.reversed_commands[i] == false) {
			version (Trace) trace("Reversing %u", cast(uint)i);
			command.cmd = adbg_bswap32(command.cmd);
			command.cmdsize = adbg_bswap32(command.cmdsize);
			o.i.macho.reversed_commands[i] = true;
		}
		version (Trace) trace("command cmd=%x size=0x%x", command.cmd, command.cmdsize);
		next += command.cmdsize;
		if (next >= o.file_size)
			return null;
	}
	return command;
}

const(char) *adbg_object_macho_magic_string(uint signature) {
	switch (signature) {
	case MACHO_MAGIC:	return "MACHO_MAGIC";
	case MACHO_MAGIC64:	return "MACHO_MAGIC_64";
	case MACHO_CIGAM: 	return "MACHO_CIGAM";
	case MACHO_CIGAM64:	return "MACHO_CIGAM_64";
	case MACHO_FATMAGIC:	return "MACHO_FAT_MAGIC";
	case MACHO_FATCIGAM:	return "MACHO_FAT_CIGAM";
	default:	return "?";
	}
}

const(char) *adbg_object_macho_filetype_string(uint type) {
	// NOTE: FAT files have no filetypes
	switch (type) {
	case MACHO_FILETYPE_OBJECT:	return "Object";
	case MACHO_FILETYPE_EXECUTE:	return "Executable";
	case MACHO_FILETYPE_FVMLIB:	return "Fixed VM Library";
	case MACHO_FILETYPE_CORE:	return "Core";
	case MACHO_FILETYPE_PRELOAD:	return "Preload";
	case MACHO_FILETYPE_DYLIB:	return "Dynamic library";
	case MACHO_FILETYPE_DYLINKER:	return "Dynamic linker";
	case MACHO_FILETYPE_BUNDLE:	return "Bundle";
	case MACHO_FILETYPE_DYLIB_STUB:	return "Dynamic library stub";
	case MACHO_FILETYPE_DSYM:	return "Companion file (debug)";
	case MACHO_FILETYPE_KEXT_BUNDLE:	return "Kext bundle";
	default:	return "?";
	}
}

AdbgMachine adbg_object_macho_machine(uint type) {
	switch (type) {
	case MACHO_CPUTYPE_VAX:	return AdbgMachine.vax;
	case MACHO_CPUTYPE_ROMP:	return AdbgMachine.romp;
	case MACHO_CPUTYPE_NS32032:
	case MACHO_CPUTYPE_NS32332:
	case MACHO_CPUTYPE_NS32532:	return AdbgMachine.ns32k;
	case MACHO_CPUTYPE_I386:	return AdbgMachine.x86;
	case MACHO_CPUTYPE_X86_64:	return AdbgMachine.amd64;
	case MACHO_CPUTYPE_MIPS:	return AdbgMachine.mips;
	case MACHO_CPUTYPE_HPPA:	return AdbgMachine.parisc;
	case MACHO_CPUTYPE_MC680x0:	return AdbgMachine.m68k;
	case MACHO_CPUTYPE_MC88000:	return AdbgMachine.m88k;
	case MACHO_CPUTYPE_ARM:	return AdbgMachine.arm;
	case MACHO_CPUTYPE_ARM64:	return AdbgMachine.aarch64;
	case MACHO_CPUTYPE_SPARC:	return AdbgMachine.sparc;
	case MACHO_CPUTYPE_I860_LITTLE:
	case MACHO_CPUTYPE_I860:	return AdbgMachine.i860;
	case MACHO_CPUTYPE_RS6000:	return AdbgMachine.rs6000;
	case MACHO_CPUTYPE_POWERPC64:	return AdbgMachine.ppc64;
	case MACHO_CPUTYPE_POWERPC:	return AdbgMachine.ppc;
	case MACHO_CPUTYPE_VEO:	return AdbgMachine.veo;
	default:	return AdbgMachine.unknown;
	}
}

const(char) *adbg_object_macho_cputype_string(uint type) {
	switch (type) {
	case MACHO_CPUTYPE_VAX:	return "VAX";
	case MACHO_CPUTYPE_ROMP:	return "ROMP";
	case MACHO_CPUTYPE_NS32032:	return "NS32032";
	case MACHO_CPUTYPE_NS32332:	return "NS32332";
	case MACHO_CPUTYPE_NS32532:	return "NS32532";
	case MACHO_CPUTYPE_I386:	return "x86";
	case MACHO_CPUTYPE_X86_64:	return "x86-64";
	case MACHO_CPUTYPE_MIPS:	return "MIPS";
	case MACHO_CPUTYPE_MC680x0:	return "MC68000";
	case MACHO_CPUTYPE_HPPA:	return "HPPA";
	case MACHO_CPUTYPE_ARM:	return "ARM";
	case MACHO_CPUTYPE_ARM64:	return "ARM64";
	case MACHO_CPUTYPE_MC88000:	return "MC88000";
	case MACHO_CPUTYPE_I860, MACHO_CPUTYPE_I860_LITTLE:	return "i860";
	case MACHO_CPUTYPE_RS6000:	return "RS6000";
	case MACHO_CPUTYPE_POWERPC64:	return "PowerPC64";
	case MACHO_CPUTYPE_POWERPC:	return "PowerPC";
	case MACHO_CPUTYPE_VEO:	return "VEO";
	default:	return "?";
	}
}

const(char) *adbg_object_macho_subtype_string(uint type, uint subtype) {
	switch (type) {
	case MACHO_CPUTYPE_VAX:
		switch (subtype) {
		case MACHO_SUBTYPE_VAX780:	return "VAX780";
		case MACHO_SUBTYPE_VAX785:	return "VAX785";
		case MACHO_SUBTYPE_VAX750:	return "VAX750";
		case MACHO_SUBTYPE_VAX730:	return "VAX730";
		case MACHO_SUBTYPE_UVAXI:	return "UVAXI";
		case MACHO_SUBTYPE_UVAXII:	return "UVAXII";
		case MACHO_SUBTYPE_VAX8200:	return "VAX8200";
		case MACHO_SUBTYPE_VAX8500:	return "VAX8500";
		case MACHO_SUBTYPE_VAX8600:	return "VAX8600";
		case MACHO_SUBTYPE_VAX8650:	return "VAX8650";
		case MACHO_SUBTYPE_VAX8800:	return "VAX8800";
		case MACHO_SUBTYPE_UVAXIII:	return "UVAXIII";
		default:	return "VAX";
		}
	case MACHO_CPUTYPE_ROMP:
		switch (subtype) {
		case MACHO_SUBTYPE_RT_PC:	return "ROMP RT_PC";
		case MACHO_SUBTYPE_RT_APC:	return "ROMP RT_APC";
		case MACHO_SUBTYPE_RT_135:	return "ROMP RT_135";
		default:	return "ROMP";
		}
	case MACHO_CPUTYPE_NS32032:	return "NS32032";
	case MACHO_CPUTYPE_NS32332:	return "NS32332";
	case MACHO_CPUTYPE_NS32532:	return "NS32532";
	case MACHO_CPUTYPE_I386:
		switch (subtype) {
		case MACHO_SUBTYPE_i386:	return "i386";
		case MACHO_SUBTYPE_i486:	return "i486";
		case MACHO_SUBTYPE_i486SX:	return "i486SX";
		case MACHO_SUBTYPE_PENT:	return "Pentium";
		case MACHO_SUBTYPE_PENPRO:	return "Pentium Pro";
		case MACHO_SUBTYPE_PENTII_M3:	return "Pentium III (M3)";
		case MACHO_SUBTYPE_PENTII_M5:	return "Pentium III (M5)";
		case MACHO_SUBTYPE_PENTIUM_4:	return "Pentium 4";
		default:	return "x86";
		}
	case MACHO_CPUTYPE_X86_64:	return "x86-64";
	case MACHO_CPUTYPE_MIPS:
		switch (subtype) {
		case MACHO_SUBTYPE_R2300:	return "MIPS R2300";
		case MACHO_SUBTYPE_R2600:	return "MIPS R2600";
		case MACHO_SUBTYPE_R2800:	return "MIPS R2800";
		case MACHO_SUBTYPE_R2800a:	return "MIPS R2800a";
		default:	return "MIPS";
		}
	case MACHO_CPUTYPE_MC680x0:
		switch (subtype) {
		case MACHO_SUBTYPE_MC68030:	return "MC68030";
		case MACHO_SUBTYPE_MC68040:	return "MC68040";
		case MACHO_SUBTYPE_MC68030_ONLY:	return "MC68030-only";
		default:	return "MC68000";
		}
	case MACHO_CPUTYPE_HPPA:
		switch (subtype) {
		case MACHO_SUBTYPE_HPPA7100LC:	return "HPPA7100LC";
		default:	return "HPPA7100";
		}
	case MACHO_CPUTYPE_ARM:
		switch (subtype) {
		case MACHO_SUBTYPE_A500_ARCH:	return "ARM A500";
		case MACHO_SUBTYPE_A500:	return "ARM A500";
		case MACHO_SUBTYPE_A440:	return "ARM A440";
		case MACHO_SUBTYPE_M4:	return "ARM M4";
		case MACHO_SUBTYPE_V4T:	return "ARM V4T";
		case MACHO_SUBTYPE_V6:	return "ARM V6";
		case MACHO_SUBTYPE_V5TEJ:	return "ARM V5TEJ";
		case MACHO_SUBTYPE_XSCALE:	return "ARM XSCALE";
		case MACHO_SUBTYPE_V7:	return "ARM V7";
		case MACHO_SUBTYPE_V8:	return "ARM V8";
		default:	return "ARM";
		}
	case MACHO_CPUTYPE_ARM64:	return "ARM64 V8";
	case MACHO_CPUTYPE_MC88000:
		switch (subtype) {
		case MACHO_SUBTYPE_MC88100:	return "MC88100";
		case MACHO_SUBTYPE_MC88110:	return "MC88110";
		default:	return "MC88000";
		}
	case MACHO_CPUTYPE_I860:	return "i860";
	case MACHO_CPUTYPE_I860_LITTLE:	return "i860 (little-endian)";
	case MACHO_CPUTYPE_RS6000:	return "IBM RS6000";
	case MACHO_CPUTYPE_POWERPC64:
		switch (subtype) {
		case MACHO_SUBTYPE_POWERPC_601:	return "PowerPC64 601";
		case MACHO_SUBTYPE_POWERPC_602:	return "PowerPC64 602";
		case MACHO_SUBTYPE_POWERPC_603:	return "PowerPC64 603";
		case MACHO_SUBTYPE_POWERPC_603e:	return "PowerPC64 603e";
		case MACHO_SUBTYPE_POWERPC_603ev:	return "PowerPC64 603ev";
		case MACHO_SUBTYPE_POWERPC_604:	return "PowerPC64 604";
		case MACHO_SUBTYPE_POWERPC_604e:	return "PowerPC64 604e";
		case MACHO_SUBTYPE_POWERPC_620:	return "PowerPC64 620";
		case MACHO_SUBTYPE_POWERPC_750:	return "PowerPC64 750";
		case MACHO_SUBTYPE_POWERPC_7400:	return "PowerPC64 7400";
		case MACHO_SUBTYPE_POWERPC_7450:	return "PowerPC64 7450";
		case MACHO_SUBTYPE_POWERPC_970:	return "PowerPC64 970";
		default:	return "PowerPC64";
		}
	case MACHO_CPUTYPE_POWERPC:
		switch (subtype) {
		case MACHO_SUBTYPE_POWERPC_601:	return "PowerPC 601";
		case MACHO_SUBTYPE_POWERPC_602:	return "PowerPC 602";
		case MACHO_SUBTYPE_POWERPC_603:	return "PowerPC 603";
		case MACHO_SUBTYPE_POWERPC_603e:	return "PowerPC 603e";
		case MACHO_SUBTYPE_POWERPC_603ev:	return "PowerPC 603ev";
		case MACHO_SUBTYPE_POWERPC_604:	return "PowerPC 604";
		case MACHO_SUBTYPE_POWERPC_604e:	return "PowerPC 604e";
		case MACHO_SUBTYPE_POWERPC_620:	return "PowerPC 620";
		case MACHO_SUBTYPE_POWERPC_750:	return "PowerPC 750";
		case MACHO_SUBTYPE_POWERPC_7400:	return "PowerPC 7400";
		case MACHO_SUBTYPE_POWERPC_7450:	return "PowerPC 7450";
		case MACHO_SUBTYPE_POWERPC_970:	return "PowerPC 970";
		default:	return "PowerPC";
		}
	case MACHO_CPUTYPE_VEO:	return "VEO";
	default:	return "?";
	}
}

const(char)* adbg_object_macho_command_string(uint command) {
	switch (command) {
	case MACHO_LC_REQ_DYLD:	return "LC_REQ_DYLD";
	case MACHO_LC_SEGMENT:	return "LC_SEGMENT";
	case MACHO_LC_SYMTAB:	return "LC_SYMTAB";
	case MACHO_LC_SYMSEG:	return "LC_SYMSEG";
	case MACHO_LC_THREAD:	return "LC_THREAD";
	case MACHO_LC_UNIXTHREAD:	return "LC_UNIXTHREAD";
	case MACHO_LC_LOADFVMLIB:	return "LC_LOADFVMLIB";
	case MACHO_LC_IDFVMLIB:	return "LC_IDFVMLIB";
	case MACHO_LC_IDENT:	return "LC_IDENT";
	case MACHO_LC_FVMFILE:	return "LC_FVMFILE";
	case MACHO_LC_PREPAGE:	return "LC_PREPAGE";
	case MACHO_LC_DYSYMTAB:	return "LC_DYSYMTAB";
	case MACHO_LC_LOAD_DYLIB:	return "LC_LOAD_DYLIB";
	case MACHO_LC_ID_DYLIB:	return "LC_ID_DYLIB";
	case MACHO_LC_LOAD_DYLINKER:	return "LC_LOAD_DYLINKER";
	case MACHO_LC_ID_DYLINKER:	return "LC_ID_DYLINKER";
	case MACHO_LC_PREBOUND_DYLIB:	return "LC_PREBOUND_DYLIB";
	case MACHO_LC_ROUTINES:	return "LC_ROUTINES";
	case MACHO_LC_SUB_FRAMEWORK:	return "LC_SUB_FRAMEWORK";
	case MACHO_LC_SUB_UMBRELLA:	return "LC_SUB_UMBRELLA";
	case MACHO_LC_SUB_CLIENT:	return "LC_SUB_CLIENT";
	case MACHO_LC_SUB_LIBRARY:	return "LC_SUB_LIBRARY";
	case MACHO_LC_TWOLEVEL_HINTS:	return "LC_TWOLEVEL_HINTS";
	case MACHO_LC_PREBIND_CKSUM:	return "LC_PREBIND_CKSUM";
	case MACHO_LC_SEGMENT_64:	return "LC_SEGMENT_64";
	case MACHO_LC_ROUTINES_64:	return "LC_ROUTINES_64";
	case MACHO_LC_UUID:	return "LC_UUID";
	case MACHO_LC_RPATH:	return "LC_RPATH";
	case MACHO_LC_CODE_SIGNATURE:	return "LC_CODE_SIGNATURE";
	case MACHO_LC_SEGMENT_SPLIT_INFO:	return "LC_SEGMENT_SPLIT_INFO";
	case MACHO_LC_REEXPORT_DYLIB:	return "LC_REEXPORT_DYLIB";
	case MACHO_LC_LAZY_LOAD_DYLIB:	return "LC_LAZY_LOAD_DYLIB";
	case MACHO_LC_ENCRYPTION_INFO:	return "LC_ENCRYPTION_INFO";
	case MACHO_LC_DYLD_INFO:	return "LC_DYLD_INFO";
	case MACHO_LC_DYLD_INFO_ONLY:	return "LC_DYLD_INFO_ONLY";
	case MACHO_LC_LOAD_UPWARD_DYLIB:	return "LC_LOAD_UPWARD_DYLIB";
	case MACHO_LC_VERSION_MIN_MACOSX:	return "LC_VERSION_MIN_MACOSX";
	case MACHO_LC_VERSION_MIN_IPHONEOS:	return "LC_VERSION_MIN_IPHONEOS";
	case MACHO_LC_FUNCTION_STARTS:	return "LC_FUNCTION_STARTS";
	case MACHO_LC_DYLD_ENVIRONMENT:	return "LC_DYLD_ENVIRONMENT";
	case MACHO_LC_MAIN:	return "LC_MAIN";
	case MACHO_LC_DATA_IN_CODE:	return "LC_DATA_IN_CODE";
	case MACHO_LC_SOURCE_VERSION:	return "LC_SOURCE_VERSION";
	case MACHO_LC_DYLIB_CODE_SIGN_DRS:	return "LC_DYLIB_CODE_SIGN_DRS";
	case MACHO_LC_ENCRYPTION_INFO_64:	return "LC_ENCRYPTION_INFO_64";
	case MACHO_LC_LINKER_OPTION:	return "LC_LINKER_OPTION";
	case MACHO_LC_LINKER_OPTIMIZATION_HINT:	return "LC_LINKER_OPTIMIZATION_HINT";
	case MACHO_LC_VERSION_MIN_WATCHOS:	return "LC_VERSION_MIN_WATCHOS";
	default:	return "?";
	}
}