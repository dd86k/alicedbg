/// Mach-O format.
///
/// Sources:
/// - Mac OS X ABI Mach-O File Format Reference
/// - https://github.com/opensource-apple/cctools/blob/master/include/mach/machine.h
/// - https://github.com/opensource-apple/cctools/blob/master/include/mach-o/loader.h
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.objects.macho;

import adbg.error;
import adbg.objectserver;
import adbg.machines : AdbgMachine;
import adbg.utils.bit;
import core.stdc.stdlib;

// NOTE: Layout
//
//       +----------------------------------+
//       | Header                           |
//       +----------------------------------+
//       | Load commands                    |
//       | LC_SEGMENT (Segment command 1)   | --+
//       | LC_SEGMENT (Segment command 2)   | - | -+
//       +----------------------------------+   |  |
//       | ...                              |   |  |
//       +----------------------------------+   |  |
//       | Segment 1 | Section 1 data       | <-+  |
//       | Segment 1 | Section 2 data       | <-+  |
//       +----------------------------------+      |
//       | Segment 2 | Section 3 data       | <----+
//       | Segment 2 | Section 4 data       | <----+
//       +----------------------------------+
//
// NOTE: Load commands
//
//       +-------------------+-------------
//       | Command           | Description
//       +-------------------+-------------
//       | LC_UUID           | 128-bit UUID for dSYM file
//       | LC_SEGMENT        | Contains sections to map in memory
//       | LC_SYMTAB         | Symbol table
//       | LC_DYSYMTAB       | Additional dynamic symbols
//       | LC_UNIXTHREAD     | Defines initial thread state
//       | LC_THREAD         | Same as LC_UNIXTHREAD, but without a stack
//       | LC_LOAD_DYLIB     | Dynamic shared library name
//       | LC_ID_DYLIB       | Install name of a dynamic shared library
//       | LC_PREBOUND_DYLIB | Prebound modules for executable shared library
//       | LC_LOAD_DYLINKER  | Use dynamic linker
//       | LC_ID_DYLINKER    | Identifies as a dynamic linker
//       | LC_ROUTINES       | Addresses of shared library
//       | LC_TWOLEVEL_HINTS | Two-level namespace lookups
//       | LC_SUB_FRAMEWORK  | Identifies umbrella subframework
//       | LC_SUB_LIBRARY    | Identifies umbrella sublibrary
//       | LC_SUB_CLIENT     | Identifies umbrella sublibrary

extern (C):

/// Smallest Mach-O size.
// https://codegolf.stackexchange.com/a/154685
private enum MINIMUM_SIZE = 0x1000; // Due to paging
private enum LIMIT_FAT_ARCH = 200;
private enum LIMIT_COMMANDS = 2000;

/*
enum MACHO_MAGIC	= 0xFEEDFACEu; /// Mach-O BE 32-bit magic
enum MACHO_MAGIC64	= 0xFEEDFACFu; /// Mach-O BE 64-bit magic
enum MACHO_CIGAM	= 0xCEFAEDFEu; /// Mach-O LE 32-bit magic
enum MACHO_CIGAM64	= 0xCFFAEDFEu; /// Mach-O LE 64-bit magic
enum MACHO_FATMAGIC	= 0xCAFEBABEu; /// Mach-O FAT BE magic
enum MACHO_FATCIGAM	= 0xBEBAFECAu; /// Mach-O FAT LE magic
*/
enum MACHO_MAGIC	= I32!(0xfe, 0xed, 0xfa, 0xce); /// Mach-O 32-bit magic
enum MACHO_MAGIC64	= I32!(0xfe, 0xed, 0xfa, 0xcf); /// Mach-O 64-bit magic
enum MACHO_CIGAM	= I32!(0xce, 0xfa, 0xed, 0xfe); /// Mach-O 32-bit inverted magic
enum MACHO_CIGAM64	= I32!(0xcf, 0xfa, 0xed, 0xfe); /// Mach-O 64-bit inverted magic
enum MACHO_FATMAGIC	= I32!(0xca, 0xfe, 0xba, 0xbe); /// Mach-O FAT BE magic
enum MACHO_FATCIGAM	= I32!(0xbe, 0xba, 0xfe, 0xca); /// Mach-O FAT LE magic

alias cpu_type_t = int;
enum {
	MACHO_CPUTYPE_ANY	= -1,
	/// Used as a bitmask to mark cputype as 64-bit
	MACHO_CPUTYPE_ABI64	= 0x100_0000,
	MACHO_CPUTYPE_VAX	= 1,
	MACHO_CPUTYPE_ROMP	= 2,
	MACHO_CPUTYPE_NS32032	= 4,
	MACHO_CPUTYPE_NS32332	= 5,
	MACHO_CPUTYPE_MC680x0	= 6,
	MACHO_CPUTYPE_I386	= 7,
	MACHO_CPUTYPE_X86_64	= MACHO_CPUTYPE_I386 | MACHO_CPUTYPE_ABI64,
	MACHO_CPUTYPE_MIPS	= 8,
	MACHO_CPUTYPE_NS32532	= 9,
	MACHO_CPUTYPE_HPPA	= 11,
	MACHO_CPUTYPE_ARM	= 12,
	MACHO_CPUTYPE_ARM64	= MACHO_CPUTYPE_ARM | MACHO_CPUTYPE_ABI64,
	MACHO_CPUTYPE_MC88000	= 13,
	MACHO_CPUTYPE_SPARC	= 14,
	MACHO_CPUTYPE_I860	= 15, // big-endian
	MACHO_CPUTYPE_I860_LITTLE	= 16, // little-endian
	MACHO_CPUTYPE_RS6000	= 17,
	MACHO_CPUTYPE_MC98000	= 18,
	MACHO_CPUTYPE_POWERPC	= 18,
	MACHO_CPUTYPE_POWERPC64	= MACHO_CPUTYPE_POWERPC | MACHO_CPUTYPE_ABI64,
	MACHO_CPUTYPE_VEO	= 255
}

// =============================
// cpu_subtype_t - CPU Subtypes, int
// =============================

// VAX subtypes
enum { // SUBTYPE_VAX
	MACHO_SUBTYPE_VAX_ALL	= 0,
	MACHO_SUBTYPE_VAX780	= 1,
	MACHO_SUBTYPE_VAX785	= 2,
	MACHO_SUBTYPE_VAX750	= 3,
	MACHO_SUBTYPE_VAX730	= 4,
	MACHO_SUBTYPE_UVAXI	= 5,
	MACHO_SUBTYPE_UVAXII	= 6,
	MACHO_SUBTYPE_VAX8200	= 7,
	MACHO_SUBTYPE_VAX8500	= 8,
	MACHO_SUBTYPE_VAX8600	= 9,
	MACHO_SUBTYPE_VAX8650	= 10,
	MACHO_SUBTYPE_VAX8800	= 11,
	MACHO_SUBTYPE_UVAXIII	= 12
}

// ROMP subtypes
enum { // SUBTYPE_ROMP
	MACHO_SUBTYPE_RT_ALL	= 0,
	MACHO_SUBTYPE_RT_PC	= 1,
	MACHO_SUBTYPE_RT_APC	= 2,
	MACHO_SUBTYPE_RT_135	= 3
}

// 32032/32332/32532 subtypes
enum { // SUBTYPE_32032
	MACHO_SUBTYPE_MMAX_ALL	= 0,
	MACHO_SUBTYPE_MMAX_DPC	= 1, /* 032 CPU */
	MACHO_SUBTYPE_SQT	= 2,
	MACHO_SUBTYPE_MMAX_APC_FPU	= 3, /* 32081 FPU */
	MACHO_SUBTYPE_MMAX_APC_FPA	= 4, /* Weitek FPA */
	MACHO_SUBTYPE_MMAX_XPC	= 5, /* 532 CPU */
}

private
template SUBTYPE_INTEL(short f, short m) {
	enum SUBTYPE_INTEL = f + (m << 4);
}

// x86 subtypes
enum { // SUBTYPE_I386
	MACHO_SUBTYPE_I386_ALL	= 3,
	MACHO_SUBTYPE_X86_64_ALL	= MACHO_SUBTYPE_I386_ALL,
	MACHO_SUBTYPE_i386	= 3,
	MACHO_SUBTYPE_i486	= 4,
	MACHO_SUBTYPE_i486SX	= 4 + 128, // "4 + 128"
	MACHO_SUBTYPE_i586	= 5,
	MACHO_SUBTYPE_PENT	= SUBTYPE_INTEL!(5, 0),
	MACHO_SUBTYPE_PENPRO	= SUBTYPE_INTEL!(6, 1),
	MACHO_SUBTYPE_PENTII_M3	= SUBTYPE_INTEL!(6, 3),
	MACHO_SUBTYPE_PENTII_M5	= SUBTYPE_INTEL!(6, 5),
	MACHO_SUBTYPE_PENTIUM_4	= SUBTYPE_INTEL!(10, 0),
}

// MIPS subty
enum { // SUBTYPE_MIPS
	MACHO_SUBTYPE_MIPS_ALL	= 0,
	MACHO_SUBTYPE_R2300	= 1,
	MACHO_SUBTYPE_R2600	= 2,
	MACHO_SUBTYPE_R2800	= 3,
	MACHO_SUBTYPE_R2800a	= 4
}

// 680x0 subtypes (m68k)
enum { // SUBTYPE_680x0
	MACHO_SUBTYPE_MC680x0_ALL	= 1,
	MACHO_SUBTYPE_MC68030	= 1,
	MACHO_SUBTYPE_MC68040	= 2,
	MACHO_SUBTYPE_MC68030_ONLY	= 3,
}

// HPPA subtypes
enum { // SUBTYPE_HPPA
	MACHO_SUBTYPE_HPPA7100	= 0,
	MACHO_SUBTYPE_HPPA7100LC	= 1,
	MACHO_SUBTYPE_HPPA_ALL	= 0,
}

// Acorn subtypes
enum { // SUBTYPE_ARM
	MACHO_SUBTYPE_ACORN_ALL	= 0,
	MACHO_SUBTYPE_A500_ARCH	= 1,
	MACHO_SUBTYPE_A500	= 2,
	MACHO_SUBTYPE_A440	= 3,
	MACHO_SUBTYPE_M4	= 4,
	MACHO_SUBTYPE_V4T	= 5,
	MACHO_SUBTYPE_V6	= 6,
	MACHO_SUBTYPE_V5TEJ	= 7,
	MACHO_SUBTYPE_XSCALE	= 8,
	MACHO_SUBTYPE_V7	= 9,
	MACHO_SUBTYPE_V8	= 13,
}

// MC88000 subtypes
enum { // SUBTYPE_MC88000
	MACHO_SUBTYPE_MC88000_ALL	= 0,
	MACHO_SUBTYPE_MMAX_JPC	= 1,
	MACHO_SUBTYPE_MC88100	= 1,
	MACHO_SUBTYPE_MC88110	= 2,
}

// MC98000 (PowerPC) subtypes
enum { // SUBTYPE_MC98000
	MACHO_SUBTYPE_MC98000_ALL	= 0,
	MACHO_SUBTYPE_MC98601	= 1,
}

// I860 subtypes
enum { // SUBTYPE_I860
	MACHO_SUBTYPE_I860_ALL	= 0,
	MACHO_SUBTYPE_I860	= 1,
}

// I860_LITTLE subtypes
enum { // SUBTYPE_I860_LITTLE
	MACHO_SUBTYPE_I860_LITTLE_ALL	= 0,
	MACHO_SUBTYPE_I860_LITTLE	= 1
}

// RS6000 subtypes
enum { // SUBTYPE_RS6000
	MACHO_SUBTYPE_RS6000_ALL	= 0,
	MACHO_SUBTYPE_RS6000	= 1,
}

// Sun4 subtypes (port done at CMU (?))
enum { // SUBTYPE_Sun4
	MACHO_SUBTYPE_SUN4_ALL	= 0,
	MACHO_SUBTYPE_SUN4_260	= 1,
	MACHO_SUBTYPE_SUN4_110	= 2,
}

// SPARC subtypes
/*enum { // SUBTYPE_SPARC
	ALL = 0
};*/

// PowerPC subtypes
enum { // SUBTYPE_PowerPC
	MACHO_SUBTYPE_POWERPC_ALL	= 0,
	MACHO_SUBTYPE_POWERPC_601	= 1,
	MACHO_SUBTYPE_POWERPC_602	= 2,
	MACHO_SUBTYPE_POWERPC_603	= 3,
	MACHO_SUBTYPE_POWERPC_603e	= 4,
	MACHO_SUBTYPE_POWERPC_603ev	= 5,
	MACHO_SUBTYPE_POWERPC_604	= 6,
	MACHO_SUBTYPE_POWERPC_604e	= 7,
	MACHO_SUBTYPE_POWERPC_620	= 8,
	MACHO_SUBTYPE_POWERPC_750	= 9,
	MACHO_SUBTYPE_POWERPC_7400	= 10,
	MACHO_SUBTYPE_POWERPC_7450	= 11,
	MACHO_SUBTYPE_POWERPC_970	= 100,
}

// VEO subtypes
enum { // SUBTYPE_VEO
	MACHO_SUBTYPE_VEO_1	= 1,
	MACHO_SUBTYPE_VEO_2	= 2,
	MACHO_SUBTYPE_VEO_3	= 3,
	MACHO_SUBTYPE_VEO_4	= 4,
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

// 64-bit version just adds a 32-bit reserved field at the end.
struct macho_header_t {
	uint magic;      /// Mach magic number identifier
	uint cputype;    /// Cpu specifier
	uint subtype;    /// Machine specifier
	uint filetype;   /// Type of file
	uint ncmds;      /// Number of load commands
	uint sizeofcmds; /// The size of all the load commands
	uint flags;      /// Flags
	// NOTE: 64-bit header has an extra uint field, but it's reserved
}

struct macho_fat_header_t {
	uint magic;     /// Magic
	uint nfat_arch; /// Number of architectures (structs) in binary
}

struct macho_fat_arch_entry_t {
	uint cputype;    /// 
	uint subtype;    /// 
	uint offset;     /// File offset to first segment or command?
	uint size;       /// Segments size?
	uint alignment;  /// Page alignment?
}

struct macho_load_command_t {
	uint cmd;	/// type of load command
	uint cmdsize;	/// total size of command in bytes
}

// NOTE: Mach-O structure
//       A load command can lead to a segment command.
//       A segment command can contain multiple sections.

alias int vm_prot_t;

struct macho_segment_command_t { /* for 32-bit architectures */
	uint      cmd;	/// LC_SEGMENT
	uint      cmdsize;	/// includes sizeof section structs
	char[16]  segname;	/// segment name
	uint      vmaddr;	/// memory address of this segment
	uint      vmsize;	/// memory size of this segment
	uint      fileoff;	/// file offset of this segment
	uint      filesize;	/// amount to map from the file
	vm_prot_t maxprot;	/// maximum VM protection
	vm_prot_t initprot;	/// initial VM protection
	uint      nsects;	/// number of sections in segment
	uint      flags;	/// flags
}

struct macho_segment_command_64_t { /* for 64-bit architectures */
	uint      cmd;	/// LC_SEGMENT_64
	uint      cmdsize;	/// includes sizeof section_64 structs
	char[16]  segname;	/// segment name
	ulong     vmaddr;	/// memory address of this segment
	ulong     vmsize;	/// memory size of this segment
	ulong     fileoff;	/// file offset of this segment
	ulong     filesize;	/// amount to map from the file
	vm_prot_t maxprot;	/// maximum VM protection
	vm_prot_t initprot;	/// initial VM protection
	uint      nsects;	/// number of sections in segment
	uint      flags;	/// flags
}

enum MACHO_SECTION_TYPE = 0x000000ff;	/// Section flags type mask
enum MACHO_SECTION_ATTR = 0xffffff00;	/// Section flags attributes mask

// Constants for the section attributes part of the flags field of a section
// structure.

/// User setable attributes
enum MACHO_SECTION_ATTRIBUTES_USR =	0xff000000;
/// section contains only true machine instructions
enum MACHO_S_ATTR_PURE_INSTRUCTIONS =	0x80000000;
/// section contains coalesced symbols that are not to be in a ranlib table of contents
enum MACHO_S_ATTR_NO_TOC =	0x40000000;
/// ok to strip static symbols in this section in files with the MH_DYLDLINK flag
enum MACHO_S_ATTR_STRIP_STATIC_SYMS =	0x20000000;
/// no dead stripping
enum MACHO_S_ATTR_NO_DEAD_STRIP =	0x10000000;
/// blocks are live if they reference live blocks
enum MACHO_S_ATTR_LIVE_SUPPORT =	0x08000000;
/// Used with i386 code stubs written on by dyld
enum MACHO_S_ATTR_SELF_MODIFYING_CODE =	0x04000000;

// Constants for the type of a section

/// regular section
enum MACHO_S_REGULAR		= 0x0;
/// zero fill on demand section
enum MACHO_S_ZEROFILL		= 0x1;
/// section with only literal C strings
enum MACHO_S_CSTRING_LITERALS	= 0x2;
/// section with only 4 byte literals
enum MACHO_S_4BYTE_LITERALS	= 0x3;
/// section with only 8 byte literals
enum MACHO_S_8BYTE_LITERALS	= 0x4;
/// section with only pointers to literals
enum MACHO_S_LITERAL_POINTERS	= 0x5;
/// section with only non-lazy symbol pointers
enum MACHO_S_NON_LAZY_SYMBOL_POINTERS	= 0x6;
/// section with only lazy symbol pointers
enum MACHO_S_LAZY_SYMBOL_POINTERS	= 0x7;
/// section with only symbol stubs, byte size of stub in the reserved2 field
enum MACHO_S_SYMBOL_STUBS	= 0x8;
/// section with only function pointers for initialization
enum MACHO_S_MOD_INIT_FUNC_POINTERS	= 0x9;
/// section with only function pointers for termination
enum MACHO_S_MOD_TERM_FUNC_POINTERS	= 0xa;
/// section contains symbols that are to be coalesced
enum MACHO_S_COALESCED	= 0xb;
/// zero fill on demand section that can be larger than 4 gigabytes
enum MACHO_S_GB_ZEROFILL	= 0xc;
/// section with only pairs of function pointers for interposing
enum MACHO_S_INTERPOSING	= 0xd;
/// section with only 16 byte literals
enum MACHO_S_16BYTE_LITERALS	= 0xe;
/// section contains DTrace Object Format
enum MACHO_S_DTRACE_DOF	= 0xf;
/// section with only lazy symbol pointers to lazy loaded dylibs
enum MACHO_S_LAZY_DYLIB_SYMBOL_POINTERS	= 0x10;
/// TLS: template of initial values for TLVs
enum MACHO_S_THREAD_LOCAL_REGULAR	= 0x11;
/// TLS: template of initial values for TLVs
enum MACHO_S_THREAD_LOCAL_ZEROFILL	= 0x12;
/// TLS: TLV descriptors
enum MACHO_S_THREAD_LOCAL_VARIABLES	= 0x13;
/// TLS: pointers to TLV descriptors
enum MACHO_S_THREAD_LOCAL_VARIABLE_POINTERS	= 0x14;
/// TLS: functions to call to initialize TLV values
enum MACHO_S_THREAD_LOCAL_INIT_FUNCTION_POINTERS	= 0x15;

struct macho_section_t {
	char[16] sectname;	/// Section name
	char[16] segname;	/// Name of parent segment
	uint addr;	/// Memory address
	uint size;	/// Size of section
	uint offset;	/// File offset to this section
	uint align_;	/// Section alignment, power of 2
	uint reloff;	/// File offset to relocation entries
	uint nrelocs;	/// Number of relocation entries
	uint flags;	/// Flags
	uint reserved1;	/// 
	uint reserved2;	/// 
}
struct macho_section64_t {
	char[16] sectname;	/// Section name
	char[16] segname;	/// Name of parent segment
	ulong addr;	/// Memory address
	ulong size;	/// Size of section
	uint offset;	/// File offset to this section
	uint align_;	/// Section alignment, power of 2
	uint reloff;	/// File offset to relocation entries
	uint nrelocs;	/// Number of relocation entries
	uint flags;	/// Flags
	uint reserved1;	/// 
	uint reserved2;	/// 
	uint reserved3;	/// 
}

private
struct internal_macho_t {
	union {
		macho_header_t header;
		macho_fat_header_t fat_header;
	}
	union {
		macho_load_command_t *commands;
		macho_fat_arch_entry_t *fat_entries;
	}
	union {
		bool *r_commands;
		bool *r_fat_entries;
	}
	bool *r_sections;
	
	// Precalculated section pointer positions
	// Auto-reversed and does not depend on `r_sections`
	size_t section_count;
	union {
		void *sections;
		macho_section_t *sections32;
		macho_section64_t *sections64;
	}
}
private enum {
	MACHO_IS_64  = 1 << 16,
	MACHO_IS_FAT = 1 << 17,
}

int adbg_object_macho_load(adbg_object_t *o, uint magic) {
	o.internal = calloc(1, internal_macho_t.sizeof);
	if (o.internal == null)
		return adbg_oops(AdbgError.crt);
	
	// TODO: Fix dumb hack depending on endianness
	// Bit messy but can be made better later
	size_t size = void;
	switch (magic) {
	case MACHO_MAGIC:	// 32-bit BE
		size = macho_header_t.sizeof;
		o.status |= AdbgObjectInternalFlags.reversed;
		break;
	case MACHO_MAGIC64:	// 64-bit BE
		size = macho_header_t.sizeof;
		o.status |= AdbgObjectInternalFlags.reversed | MACHO_IS_64;
		break;
	case MACHO_CIGAM:	// 32-bit LE
		size = macho_header_t.sizeof;
		break;
	case MACHO_CIGAM64:	// 64-bit LE
		size = macho_header_t.sizeof;
		o.status |= MACHO_IS_64;
		break;
	case MACHO_FATMAGIC:	// Fat LE
		size = macho_fat_header_t.sizeof;
		o.status |= AdbgObjectInternalFlags.reversed | MACHO_IS_FAT;
		break;
	case MACHO_FATCIGAM:	// Fat BE
		size = macho_fat_header_t.sizeof;
		o.status |= MACHO_IS_FAT;
		break;
	default: // Unless loader gave a new signature?
		return adbg_oops(AdbgError.objectMalformed);
	}
	if (adbg_object_read_at(o, 0, o.internal, size))
		return adbg_errno();
	
	adbg_object_postload(o, AdbgObject.macho, &adbg_object_macho_unload);
	
	version (Trace) trace("status=%#x", o.status);
	
	// If fields need to be swapped
	with (cast(internal_macho_t*)o.internal)
	if (o.status & AdbgObjectInternalFlags.reversed) {
		if (o.status & MACHO_IS_FAT) {
			fat_header.nfat_arch = adbg_bswap32(fat_header.nfat_arch);
		} else {
			header.cputype = adbg_bswap32(header.cputype);
			header.subtype = adbg_bswap32(header.subtype);
			header.filetype = adbg_bswap32(header.filetype);
			header.ncmds = adbg_bswap32(header.ncmds);
			header.sizeofcmds = adbg_bswap32(header.sizeofcmds);
			header.flags = adbg_bswap32(header.flags);
			
		}
	}
	
	return 0;
}
void adbg_object_macho_unload(adbg_object_t *o) {
	if (o == null) return;
	if (o.internal == null) return;
	
	internal_macho_t *internal = cast(internal_macho_t*)o.internal;
	
	if (internal.commands) free(internal.commands); // and fat_entries
	if (internal.r_commands) free(internal.r_commands); // and r_fat_entries
	if (internal.r_sections) free(internal.r_sections);

	// auto-reversed
	if (internal.sections32) free(internal.sections32);
	
	free(o.internal);
}

int adbg_object_macho_is_64bit(adbg_object_t *o) {
	return o.status & MACHO_IS_64;
}

//
// Fat Mach-O util functions
//

int adbg_object_macho_is_fat(adbg_object_t *o) {
	return o.status & MACHO_IS_FAT;
}

macho_fat_header_t* adbg_object_macho_fat_header(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	return &(cast(internal_macho_t*)o.internal).fat_header;
}

macho_fat_arch_entry_t* adbg_object_macho_fat_arch(adbg_object_t *o, size_t index) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	if ((o.status & MACHO_IS_FAT) == 0) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	internal_macho_t *internal = cast(internal_macho_t*)o.internal;
	
	if (index >= internal.fat_header.nfat_arch) {
		adbg_oops(AdbgError.indexBounds);
		return null;
	}
	
	if (internal.fat_entries == null) with (internal) {
		size_t size = fat_header.nfat_arch * macho_fat_arch_entry_t.sizeof;
		fat_entries = cast(macho_fat_arch_entry_t*)malloc(size);
		if (fat_entries == null) {
			adbg_oops(AdbgError.crt);
			return null;
		}
		if (adbg_object_read_at(o, macho_fat_header_t.sizeof, fat_entries, size))
			return null;
		
		if (o.status & AdbgObjectInternalFlags.reversed) {
			r_fat_entries = cast(bool*)malloc(fat_header.nfat_arch);
			if (r_fat_entries == null) {
				adbg_oops(AdbgError.crt);
				free(fat_entries);
				fat_entries = null;
				return null;
			}
		}
	}
	
	macho_fat_arch_entry_t* entry = internal.fat_entries + index;
	if (o.status & AdbgObjectInternalFlags.reversed && internal.r_fat_entries[index] == false) {
		entry.cputype	= adbg_bswap32(entry.cputype);
		entry.subtype	= adbg_bswap32(entry.subtype);
		entry.offset	= adbg_bswap32(entry.offset);
		entry.size	= adbg_bswap32(entry.size);
		entry.alignment	= adbg_bswap32(entry.alignment);
		internal.r_fat_entries[index] = true;
	}
	return entry;
}

//
// Regular Mach-O functions
//

macho_header_t* adbg_object_macho_header(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	return &(cast(internal_macho_t*)o.internal).header;
}

// Load commands have a type and size.
// Size includes type (4 bytes), size (4 bytes), and anything that follows it
// until next command.
macho_load_command_t* adbg_object_macho_load_command(adbg_object_t *o, size_t index) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	if (o.status & MACHO_IS_FAT) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	internal_macho_t *internal = cast(internal_macho_t*)o.internal;
	
	if (index >= internal.header.ncmds) {
		adbg_oops(AdbgError.indexBounds);
		return null;
	}
	
	// NOTE: Commands
	//       Commands are not organized in a typical table (with offsets),
	//       but each command occupies a tiny header, then data follows.
	//       Thankfully, sizeofcmds includes the entire set of commands.
	
	if (internal.commands == null) with (internal) {
		commands = cast(macho_load_command_t*)malloc(header.sizeofcmds);
		if (commands == null) {
			adbg_oops(AdbgError.crt);
			return null;
		}
		size_t cmdoff = o.status & MACHO_IS_64 ? macho_header_t.sizeof + 4 : macho_header_t.sizeof;
		if (adbg_object_read_at(o, cmdoff, commands, header.sizeofcmds))
			return null;
		
		if (o.status & AdbgObjectInternalFlags.reversed) {
			r_commands = cast(bool*)malloc(header.ncmds);
			if (r_commands == null) {
				adbg_oops(AdbgError.crt);
				free(commands);
				commands = null;
				return null;
			}
		}
	}
	
	// First load command
	macho_load_command_t *command = internal.commands;
	for (size_t i; i < index; ++i) { // up until we reach index we want
		if (o.status & AdbgObjectInternalFlags.reversed && internal.r_commands[i] == false) {
			command.cmd = adbg_bswap32(command.cmd);
			command.cmdsize = adbg_bswap32(command.cmdsize);
			internal.r_commands[i] = true;
		}
		if (adbg_bits_ptrbounds(command, macho_load_command_t.sizeof, internal.commands, internal.header.sizeofcmds)) {
			adbg_oops(AdbgError.offsetBounds);
			return null;
		}
		command = cast(macho_load_command_t*)(cast(void*)command + command.cmdsize);
	}
	
	return command;
}

uint* adbg_object_macho_load_command_count(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	if (o.status & MACHO_IS_FAT) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	internal_macho_t *internal = cast(internal_macho_t*)o.internal;
	return &internal.header.ncmds;
}

void* adbg_object_macho_segment_section(adbg_object_t *o, macho_load_command_t *c, size_t index) {
	if (o == null || c == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	if (o.status & MACHO_IS_FAT) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	//TODO: Swap fields
	
	switch (c.cmd) {
	case MACHO_LC_SEGMENT:
		macho_segment_command_t *seg = cast(macho_segment_command_t*)c;
		
		if (index > seg.nsects) {
			adbg_oops(AdbgError.indexBounds);
			return null;
		}
		
		macho_section_t *section = cast(macho_section_t*)
			(cast(void*)seg + macho_segment_command_t.sizeof) + index;
		if (adbg_bits_ptrbounds(section, macho_section_t.sizeof, c, c.cmdsize)) {
			adbg_oops(AdbgError.offsetBounds);
			return null;
		}
		return section;
	case MACHO_LC_SEGMENT_64:
		macho_segment_command_64_t *seg64 = cast(macho_segment_command_64_t*)c;
		
		if (index > seg64.nsects) {
			adbg_oops(AdbgError.indexBounds);
			return null;
		}
		
		macho_section64_t *section64 = cast(macho_section64_t*)
			(cast(void*)seg64 + macho_segment_command_64_t.sizeof) + index;
		if (adbg_bits_ptrbounds(section64, macho_section64_t.sizeof, c, c.cmdsize)) {
			adbg_oops(AdbgError.offsetBounds);
			return null;
		}
		return section64;
	default:
		adbg_oops(AdbgError.unavailable);
		return null;
	}
}

// TODO: Make system a little more flexible in the case there are both 32+64-bit commands

private
int adbg_object_macho__load_sections(adbg_object_t *o) {
	int m64 = adbg_object_macho_is_64bit(o);
	internal_macho_t *internal = cast(internal_macho_t*)o.internal;
	
	// 1. Go through all segments to get total count
	// TODO: Segments could be loaded in memory
	//       Just the section data should still not use much memory
	size_t totalcount;
	macho_load_command_t *c = void;
	for (size_t ci; (c = adbg_object_macho_load_command(o, ci)) != null; ++ci) {
		switch (c.cmd) {
		case MACHO_LC_SEGMENT_64:
			macho_segment_command_64_t *seg64 = cast(macho_segment_command_64_t*)c;
			totalcount += seg64.nsects;
			break;
		case MACHO_LC_SEGMENT:
			macho_segment_command_t *seg32 = cast(macho_segment_command_t*)c;
			totalcount += seg32.nsects;
			break;
		default: continue;
		}
	}
	
	// 2. Allocate buffer
	size_t totalsize = totalcount * (m64 ? macho_section64_t.sizeof : macho_section_t.sizeof);
	void *buffer = internal.sections = malloc(totalsize);
	if (buffer == null)
		return adbg_oops(AdbgError.crt);
	
	// 3. Go through segments again and copy section header data into buffer
	internal.section_count = totalcount;
	size_t soffset;
	for (size_t ci; (c = adbg_object_macho_load_command(o, ci)) != null; ++ci) {
		switch (c.cmd) {
		case MACHO_LC_SEGMENT_64:
			macho_segment_command_64_t *seg64 = cast(macho_segment_command_64_t*)c;
			size_t ssize = macho_section64_t.sizeof * seg64.nsects;
			if (adbg_object_read_at(o, seg64.fileoff, buffer + soffset, ssize)) {
				free(buffer);
				return adbg_errno();
			}
			soffset += ssize;
			break;
		case MACHO_LC_SEGMENT:
			macho_segment_command_t *seg32 = cast(macho_segment_command_t*)c;
			size_t ssize = macho_section_t.sizeof * seg32.nsects;
			if (adbg_object_read_at(o, seg32.fileoff, buffer + soffset, ssize)) {
				free(buffer);
				return adbg_errno();
			}
			soffset += ssize;
			break;
		default: continue;
		}
	}
	
	return 0;
}

size_t* adbg_object_macho_section_count(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	if (o.status & MACHO_IS_FAT) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	internal_macho_t *internal = cast(internal_macho_t*)o.internal;
	
	if (internal.sections32 == null) {
		int e = adbg_object_macho__load_sections(o);
		if (e) return null;
	}
	
	return &internal.section_count;
}

// Optimized way to get section headers
void* adbg_object_macho_section(adbg_object_t *o, size_t index) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	if (o.status & MACHO_IS_FAT) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	internal_macho_t *internal = cast(internal_macho_t*)o.internal;
	
	// Load sections buffer
	if (internal.sections32 == null) {
		int e = adbg_object_macho__load_sections(o);
		if (e) return null;
	}
	
	if (index >= internal.section_count) {
		adbg_oops(AdbgError.indexBounds);
		return null;
	}
	
	return o.status & MACHO_IS_64 ?
		cast(void*)(internal.sections64 + index) :
		cast(void*)(internal.sections32 + index);
}

const(char) *adbg_object_macho_magic_string(uint signature) {
	switch (signature) {
	case MACHO_MAGIC:	return "MACHO_MAGIC";
	case MACHO_MAGIC64:	return "MACHO_MAGIC_64";
	case MACHO_CIGAM: 	return "MACHO_CIGAM";
	case MACHO_CIGAM64:	return "MACHO_CIGAM_64";
	case MACHO_FATMAGIC:	return "MACHO_FAT_MAGIC";
	case MACHO_FATCIGAM:	return "MACHO_FAT_CIGAM";
	default:	return null;
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
	default:	return null;
	}
}

AdbgMachine adbg_object_macho_machine(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return AdbgMachine.unknown;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return AdbgMachine.unknown;
	}
	
	internal_macho_t *internal = cast(internal_macho_t*)o.internal;
	
	//TODO: Better support fat Mach-Os
	if (o.status & MACHO_IS_FAT) {
		adbg_oops(AdbgError.unavailable);
		return AdbgMachine.unknown;
	}
	
	switch (internal.header.cputype) {
	case MACHO_CPUTYPE_VAX:	return AdbgMachine.vax;
	case MACHO_CPUTYPE_ROMP:	return AdbgMachine.romp;
	case MACHO_CPUTYPE_NS32032:
	case MACHO_CPUTYPE_NS32332:
	case MACHO_CPUTYPE_NS32532:	return AdbgMachine.ns32k;
	case MACHO_CPUTYPE_I386:	return AdbgMachine.i386;
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

const(char)* adbg_object_macho_cputype_string(uint type) {
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
	default:	return null;
	}
}

const(char)* adbg_object_macho_subtype_string(uint type, uint subtype) {
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
	default:	return null;
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
	default:	return null;
	}
}

const(char)* adbg_object_macho_kind_string(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	
	internal_macho_t *internal = cast(internal_macho_t*)o.internal;
	if (o.status & MACHO_IS_FAT) return `Fat Executable`;
	return adbg_object_macho_filetype_string(internal.header.filetype);
}
