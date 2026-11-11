/// COFF format.
///
/// Sources:
/// - https://delorie.com/djgpp/doc/coff/
/// - https://www.ti.com/lit/an/spraao8/spraao8.pdf
/// - https://wiki.osdev.org/COFF
/// - Microsoft PE and COFF Specification (MS COFF, bigobj)
///
/// ECOFF (MIPS) and XCOFF (AIX) aren't supported
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.objects.coff;

import adbg.error;
import adbg.machines;
import adbg.objectserver;
import adbg.objects.mscoff : mscoff_anon_header_bigobj_t, MSCOFF_BIGOBJ_CLSID, MSCOFF_VERSION_ANONV2;
import adbg.symbols;
import adbg.utils.bit;
import core.stdc.stdlib;
import core.stdc.string : memcpy, memset;

extern (C):

// Format
//
// Structure           | Location
// --------------------+-------
// File Header         | Start of file
// Optional Header     | Follows File Header
// Section Headers     | Follows Optional Header, count in File Header
// Section data        | From Section Header
// Relocation Entries  | From Section Header
// Line Number Entries | From Section Header
// Symbol Table        | From File Header
// String Table        | Follows Symbol Table

// NOTE: DJGPP uses unsigned numbers for locations, which makes more sense, and we should too!

enum : ushort {
	/// i386 COFF magic
	COFF_MAGIC_I386	= I16!(0x4c, 0x01),	// 0x14c
	/// i386 AIX COFF magic
	COFF_MAGIC_I386_AIX	= I16!(0x75, 0x01),	// 0x175
	/// amd64 COFF magic
	COFF_MAGIC_AMD64	= I16!(0x64, 0x86),	// 0x8664
	/// Itanium COFF magic
	COFF_MAGIC_IA64	= I16!(0x00, 0x02),
	/// Z80
	COFF_MAGIC_Z80	= I16!('Z', 0x80),	// 0x5a, 0x80
	/// TMS470
	COFF_MAGIC_TMS470	= I16!(0x97, 0x00),	// 0097h
	/// TMS320C5400
	COFF_MAGIC_TMS320C5400	= I16!(0x98, 0x00),	// 0098h
	/// TMS320C6000
	COFF_MAGIC_TMS320C6000	= I16!(0x99, 0x00),	// 0099h
	/// TMS320C5500
	COFF_MAGIC_TMS320C5500	= I16!(0x9c, 0x00),	// 009Ch
	/// TMS320C2800
	COFF_MAGIC_TMS320C2800	= I16!(0x9d, 0x00),	// 009Dh
	/// MSP430
	COFF_MAGIC_MSP430	= I16!(0xa0, 0x00),	// 00A0h
	/// TMS320C5500+
	COFF_MAGIC_TMS320C5500P	= I16!(0xa1, 0x00),	// 00A1h
	/// MIPS Little-Endian
	COFF_MAGIC_MIPSEL	= I16!(0x62, 0x01),	// MIPSELMAGIC 0x0162
	/// AArch64 (MS)
	COFF_MAGIC_ARM64	= I16!(0x64, 0xaa),	// 0xaa64
	
	/// Optional header magic for TI
	COFF_OPT_MAGIC_TI	= I16!(0x08, 0x01),	// 0108h
	/// Optional header magic for MIPSEL
	COFF_OPT_MAGIC_MIPSEL	= I16!(0x07, 0x01),	// SOMAGIC 0x0701
	/// Optional header magic for DJGPP
	COFF_OPT_MAGIC_ZMAGIC	= I16!(0x0b, 0x01),	// 0x010b
	
	// Header flags
	
	/// If set, relocation information has been removed.
	/// This is usually clear for objects and set for executables.
	COFF_F_RELFLG	= LITTLE16!(0x0001),
	/// If set, all unresolved symbols have been resolved and the
	/// file may be considered executable.
	COFF_F_EXEC	= LITTLE16!(0x0002),
	/// If set, all line number information has been removed from the
	/// file (or was never added in the first place).
	COFF_F_LNNO	= LITTLE16!(0x0004),
	/// If set, all the local symbols have been removed from the
	/// file (or were never added in the first place).
	COFF_F_LSYMS	= LITTLE16!(0x0008),
	/// Indicates that the file is little endian (in most cases)
	COFF_F_LSB	= LITTLE16!(0x0100),
	/// Indicates that the file is big endian (in most cases)
	COFF_F_MSB	= LITTLE16!(0x0200),
	
	// Section flags
	
	/// The section contains executable code.
	COFF_STYPE_TEXT	= LITTLE16!(0x0020),
	/// The section contains initialised data.
	COFF_STYPE_DATA	= LITTLE16!(0x0040),
	/// The COFF file contains no data for this section, but needs space to be allocated for it.
	COFF_STYPE_BSS	= LITTLE16!(0x0080),
}

// MS COFF section flags, same values as PE_SECTION_CHARACTERISTIC_*
enum : uint {
	/// Section contains code.
	IMAGE_SCN_CNT_CODE	= 0x00000020,
	/// Section contains initialized data.
	IMAGE_SCN_CNT_INITIALIZED_DATA	= 0x00000040,
	/// Section contains uninitialized data.
	IMAGE_SCN_CNT_UNINITIALIZED_DATA	= 0x00000080,
	/// Section contains linker directives or comments (.drectve).
	IMAGE_SCN_LNK_INFO	= 0x00000200,
	/// Section is not part of the image.
	IMAGE_SCN_LNK_REMOVE	= 0x00000800,
	/// Section is a COMDAT.
	IMAGE_SCN_LNK_COMDAT	= 0x00001000,
	/// Alignment field mask, see adbg_object_coff_section_alignment.
	IMAGE_SCN_ALIGN_MASK	= 0x00F00000,
	/// Relocation count is in the first relocation entry.
	IMAGE_SCN_LNK_NRELOC_OVFL	= 0x01000000,
	/// Section can be discarded.
	IMAGE_SCN_MEM_DISCARDABLE	= 0x02000000,
	/// Section is executable.
	IMAGE_SCN_MEM_EXECUTE	= 0x20000000,
	/// Section is readable.
	IMAGE_SCN_MEM_READ	= 0x40000000,
	/// Section is writable.
	IMAGE_SCN_MEM_WRITE	= 0x80000000,
}

// MS COFF COMDAT selection, from section definition aux entry
enum : ubyte {
	/// Duplicate symbols are an error.
	IMAGE_COMDAT_SELECT_NODUPLICATES	= 1,
	/// Pick any copy.
	IMAGE_COMDAT_SELECT_ANY	= 2,
	/// Pick any copy, copies must have the same size.
	IMAGE_COMDAT_SELECT_SAME_SIZE	= 3,
	/// Pick any copy, copies must have the same checksum.
	IMAGE_COMDAT_SELECT_EXACT_MATCH	= 4,
	/// Linked if the associated section is linked.
	IMAGE_COMDAT_SELECT_ASSOCIATIVE	= 5,
	/// Pick the largest copy.
	IMAGE_COMDAT_SELECT_LARGEST	= 6,
}

// MS COFF weak external search type
enum : uint {
	/// Do not search libraries for the symbol.
	IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY	= 1,
	/// Search libraries for the symbol.
	IMAGE_WEAK_EXTERN_SEARCH_LIBRARY	= 2,
	/// Symbol is an alias of the default symbol.
	IMAGE_WEAK_EXTERN_SEARCH_ALIAS	= 3,
	/// Anti-dependency (ARM64EC).
	IMAGE_WEAK_EXTERN_ANTI_DEPENDENCY	= 4,
}

// MS COFF x86 relocations
enum : ushort {
	IMAGE_REL_I386_ABSOLUTE	= 0x0000,	/// Ignored
	IMAGE_REL_I386_DIR16	= 0x0001,	/// Unsupported
	IMAGE_REL_I386_REL16	= 0x0002,	/// Unsupported
	IMAGE_REL_I386_DIR32	= 0x0006,	/// 32-bit VA
	IMAGE_REL_I386_DIR32NB	= 0x0007,	/// 32-bit RVA
	IMAGE_REL_I386_SEG12	= 0x0009,	/// Unsupported
	IMAGE_REL_I386_SECTION	= 0x000A,	/// 16-bit section index
	IMAGE_REL_I386_SECREL	= 0x000B,	/// 32-bit offset from section start
	IMAGE_REL_I386_TOKEN	= 0x000C,	/// CLR token
	IMAGE_REL_I386_SECREL7	= 0x000D,	/// 7-bit offset from section base
	IMAGE_REL_I386_REL32	= 0x0014,	/// 32-bit relative displacement
}

// MS COFF x86-64 relocations
enum : ushort {
	IMAGE_REL_AMD64_ABSOLUTE	= 0x0000,	/// Ignored
	IMAGE_REL_AMD64_ADDR64	= 0x0001,	/// 64-bit VA
	IMAGE_REL_AMD64_ADDR32	= 0x0002,	/// 32-bit VA
	IMAGE_REL_AMD64_ADDR32NB	= 0x0003,	/// 32-bit RVA
	IMAGE_REL_AMD64_REL32	= 0x0004,	/// 32-bit relative from end of field
	IMAGE_REL_AMD64_REL32_1	= 0x0005,	/// REL32, field followed by 1 byte
	IMAGE_REL_AMD64_REL32_2	= 0x0006,	/// REL32, field followed by 2 bytes
	IMAGE_REL_AMD64_REL32_3	= 0x0007,	/// REL32, field followed by 3 bytes
	IMAGE_REL_AMD64_REL32_4	= 0x0008,	/// REL32, field followed by 4 bytes
	IMAGE_REL_AMD64_REL32_5	= 0x0009,	/// REL32, field followed by 5 bytes
	IMAGE_REL_AMD64_SECTION	= 0x000A,	/// 16-bit section index
	IMAGE_REL_AMD64_SECREL	= 0x000B,	/// 32-bit offset from section start
	IMAGE_REL_AMD64_SECREL7	= 0x000C,	/// 7-bit offset from section base
	IMAGE_REL_AMD64_TOKEN	= 0x000D,	/// CLR token
	IMAGE_REL_AMD64_SREL32	= 0x000E,	/// 32-bit span-dependent value
	IMAGE_REL_AMD64_PAIR	= 0x000F,	/// Follows SREL32
	IMAGE_REL_AMD64_SSPAN32	= 0x0010,	/// 32-bit span-dependent value
}

// MS COFF AArch64 relocations
enum : ushort {
	IMAGE_REL_ARM64_ABSOLUTE	= 0x0000,	/// Ignored
	IMAGE_REL_ARM64_ADDR32	= 0x0001,	/// 32-bit VA
	IMAGE_REL_ARM64_ADDR32NB	= 0x0002,	/// 32-bit RVA
	IMAGE_REL_ARM64_BRANCH26	= 0x0003,	/// 26-bit B/BL displacement
	IMAGE_REL_ARM64_PAGEBASE_REL21	= 0x0004,	/// ADRP page displacement
	IMAGE_REL_ARM64_REL21	= 0x0005,	/// ADR displacement
	IMAGE_REL_ARM64_PAGEOFFSET_12A	= 0x0006,	/// 12-bit page offset for ADD/ADDS
	IMAGE_REL_ARM64_PAGEOFFSET_12L	= 0x0007,	/// 12-bit page offset for LDR
	IMAGE_REL_ARM64_SECREL	= 0x0008,	/// 32-bit offset from section start
	IMAGE_REL_ARM64_SECREL_LOW12A	= 0x0009,	/// Low 12 bits of SECREL for ADD/ADDS
	IMAGE_REL_ARM64_SECREL_HIGH12A	= 0x000A,	/// Bits 12-23 of SECREL for ADD/ADDS
	IMAGE_REL_ARM64_SECREL_LOW12L	= 0x000B,	/// Low 12 bits of SECREL for LDR
	IMAGE_REL_ARM64_TOKEN	= 0x000C,	/// CLR token
	IMAGE_REL_ARM64_SECTION	= 0x000D,	/// 16-bit section index
	IMAGE_REL_ARM64_ADDR64	= 0x000E,	/// 64-bit VA
	IMAGE_REL_ARM64_BRANCH19	= 0x000F,	/// 19-bit conditional branch displacement
	IMAGE_REL_ARM64_BRANCH14	= 0x0010,	/// 14-bit TBZ/TBNZ displacement
	IMAGE_REL_ARM64_REL32	= 0x0011,	/// 32-bit relative from end of field
}


// COFF Class types
enum : ubyte {
	/// No entry
	C_NULL	= 0,
	/// Automatic variable
	C_AUTO	= 1,
	/// External (public) symbol - this covers globals and externs
	C_EXT	= 2,
	/// Static (private) symbol
	C_STAT	= 3,
	/// Register variable
	C_REG	= 4,
	/// External definition
	C_EXTDEF	= 5,
	/// Label
	C_LABEL	= 6,
	/// Undefined label
	C_ULABEL	= 7,
	/// Member of structure
	C_MOS	= 8,
	/// Function argument
	C_ARG	= 9,
	/// Structure tag
	C_STRTAG	= 10,
	/// Member of union
	C_MOU	= 11,
	/// Union tag
	C_UNTAG	= 12,
	/// Type definition
	C_TPDEF	= 13,
	/// Undefined static
	C_USTATIC	= 14,
	/// Enumaration tag
	C_ENTAG	= 15,
	/// Member of enumeration
	C_MOE	= 16,
	/// Register parameter
	C_REGPARM	= 17,
	/// Bit field
	C_FIELD	= 18,
	/// Auto argument
	C_AUTOARG	= 19,
	/// Dummy entry (end of block)
	C_LASTENT	= 20,
	/// ".bb" or ".eb" - beginning or end of block
	C_BLOCK	= 100,
	/// ".bf" or ".ef" - beginning or end of function
	C_FCN	= 101,
	/// End of structure
	C_EOS	= 102,
	/// File name
	C_FILE	= 103,
	/// Line number, reformatted as symbol
	C_LINE	= 104,
	/// Duplicate tag
	C_ALIAS	= 105,
	/// Weak external (MS), same value as C_ALIAS
	C_WEAKEXT	= 105,
	/// Ext symbol in dmert public lib
	C_HIDDEN	= 106,
	/// Physical end of function
	C_EFCN	= 255,
}

// COFF Base and Derived Types
// e_type = base + (derived << N_BTSHIFT=4?);
enum : ushort {
	// Base type (---- xxxx)
	/// No symbol
	T_NULL	= 0b0000,
	/// void function argument (not used)
	T_VOID	= 0b0001,
	/// character
	T_CHAR	= 0b0010,
	/// short integer
	T_SHORT	= 0b0011,
	/// integer
	T_INT	= 0b0100,
	/// long integer
	T_LONG	= 0b0101,
	/// floating point
	T_FLOAT	= 0b0110,
	/// double precision float
	T_DOUBLE	= 0b0111,
	/// structure
	T_STRUCT	= 0b1000,
	/// union
	T_UNION	= 0b1001,
	/// enumeration
	T_ENUM	= 0b1010,
	/// member of enumeration
	T_MOE	= 0b1011,
	/// unsigned character
	T_UCHAR	= 0b1100,
	/// unsigned short
	T_USHORT	= 0b1101,
	/// unsigned integer
	T_UINT	= 0b1110,
	/// unsigned long
	T_ULONG	= 0b1111,
	/// long double (special case bit pattern)
	T_LNGDBL	= 0b1_0000, // special case
	
	// Derived type (--xx ----)
	/// No derived type
	DT_NON	= 0b00_0000,
	/// pointer to T
	DT_PTR	= 0b01_0000,
	/// function returning T
	DT_FCN	= 0b10_0000,
	/// array of T
	DT_ARY	= 0b11_0000,
}

// COFF Relocations
enum : ushort {
	// Base relocations
	
	/// Addition (+)
	RE_ADD	= 0x4000,
	/// Subtraction (-)
	RE_SUB	= 0x4001,
	/// Negate (-)
	RE_NEG	= 0x4002,
	/// Multiplication (*)
	RE_MPY	= 0x4003,
	/// Division (/)
	RE_DIV	= 0x4004,
	/// Modulus (%)
	RE_MOD	= 0x4005,
	/// Logical shift right (unsigned >>)
	RE_SR	= 0x4006,
	/// Arithmetic shift right (signed >>)
	RE_ASR	= 0x4007,
	/// Shift left (<<)
	RE_SL	= 0x4008,
	/// And (&)
	RE_AND	= 0x4009,
	/// Or (|)
	RE_OR	= 0x400A,
	/// Exclusive Or (^)
	RE_XOR	= 0x400B,
	/// Not (~)
	RE_NOTB	= 0x400C,
	/// Unsigned relocation field load
	RE_ULDFLD	= 0x400D,
	/// Signed relocation field load
	RE_SLDFLD	= 0x400E,
	/// Unsigned relocation field store
	RE_USTFLD	= 0x400F,
	/// Signed relocation field store
	RE_SSTFLD	= 0x4010,
	/// Push symbol on the stack
	RE_PUSH	= 0x4011,
	/// Push signed constant on the stack
	RE_PUSHSK	= 0x4012,
	/// Push unsigned constant on the stack
	RE_PUSHUK	= 0x4013,
	/// Push current section PC on the stack
	RE_PUSHPC	= 0x4014,
	/// Duplicate top-of-stack and push a copy
	RE_DUP	= 0x4015,
	/// Relocation field store, signedness is irrelevant
	RE_XSTFLD	= 0x4016,
	
	/// Push symbol: SEGVALUE flag is set
	RE_PUSHSV	= 0xC011,
	
	// C6000 Relocation Types
	
	/// No relocation
	R_C60_ABS	= 0x0000, // "C60" added
	/// 8-bit direct reference to symbol's address
	R_C60_RELBYTE	= 0x000F, // "C60" added
	/// 16-bit direct reference to symbol's address
	R_C60_RELWORD	= 0x0010, // "C60" added
	/// 32-bit direct reference to symbol's address
	R_C60_RELLONG	= 0x0011, // "C60" added
	/// Data page pointer-based offset
	R_C60BASE	= 0x0050,
	/// Load or store long displacement
	R_C60DIR15	= 0x0051,
	/// 21-bit packet, PC relative
	R_C60PCR21	= 0x0052,
	/// 10-bit Packet PC Relative (BDEC, BPOS)
	R_C60PCR10	= 0x0053,
	/// MVK instruction low half register
	R_C60LO16	= 0x0054,
	/// MVKH or MVKLH high half register
	R_C60HI16	= 0x0055,
	/// Section-based offset
	R_C60SECT	= 0x0056,
	/// Signed 16-bit offset for MVK
	R_C60S16	= 0x0057,
	/// 7-bit Packet PC Relative (ADDKPC)
	R_C60PCR7	= 0x0070,
	/// 12-bit Packet PC Relative (BNOP)
	R_C60PCR12	= 0x0071,
	
	// C2800 Relocation Types

	/// No relocation
	R_C28_ABS	= 0x0000, // "C28" added
	/// 8-bit direct reference to symbol's address
	R_C28_RELBYTE	= 0x000F, // "C28" added
	/// 16-bit direct reference to symbol's address
	R_C28_RELWORD	= 0x0010, // "C28" added
	/// 32-bit direct reference to symbol's address
	R_C28_RELLONG	= 0x0011, // "C28" added
	/// 7-bit offset of a 22-bit address
	R_PARTLS7	= 0x0028,
	/// 6-bit offset of a 22-bit address
	R_PARTLS6	= 0x005D,
	/// Middle 10 bits of a 22-bit address
	R_PARTMID10	= 0x005E,
	/// 22-bit direct reference to a symbol's address
	R_REL22	= 0x005F,
	/// Upper 6 bits of an 22-bit address
	R_PARTMS6	= 0x0060,
	/// Upper 16 bits of an 22-bit address
	R_PARTS16	= 0x0061,
	/// PC relative 16-bit address
	R_C28PCR16	= 0x0062,
	/// PC relative 8-bit address
	R_C28PCR8	= 0x0063,
	/// 22-bit pointer
	R_C28PTR	= 0x0064,
	/// High 16 bits of address data
	R_C28HI16	= 0x0065,
	/// Pointer to low 64K
	R_C28LOPTR	= 0x0066,
	/// 16-bit negated relocation
	R_C28NWORD	= 0x0067,
	/// 8-bit negated relocation
	R_C28NBYTE	= 0x0068,
	/// High 8 bits of a 16-bit data
	R_C28HIBYTE	= 0x0069,
	/// Signed 13-bit value relocated as a 16-bit value
	R_C28RELS13	= 0x006A,
	
	// C5400 Relocation Types

	/// No relocation
	R_C54_ABS	= 0x0000, // "C54" added
	/// 24-bit reference to symbol's address
	R_C54_REL24	= 0x0005, // "C54" added
	/// 8-bit direct reference to symbol's address
	R_C54_RELBYTE	= 0x0017, // "C54" added
	/// 16-bit direct reference to symbol's address
	R_C54_RELWORD	= 0x0020, // "C54" added
	/// 32-bit direct reference to symbol's address
	R_C54_RELLONG	= 0x0021, // "C54" added
	/// 9 MSBs of an address
	R_PARTMS9	= 0x0029,
	/// 13-bit direct reference to symbol's address
	R_REL13	= 0x002A,

	// C5500 Relocation Types
	
	/// No relocation
	R_C55_ABS	= 0x0000, // "C55" added
	/// 24-bit direct reference to symbol's address
	R_C55_REL24	= 0x0005, // "C55" added
	/// 8-bit direct reference to symbol's address
	R_C55_RELBYTE	= 0x0017, // "C55" added
	/// 16-bit direct reference to symbol's address
	R_C55_RELWORD	= 0x0020, // "C55" added
	/// 32-bit direct reference to symbol's address
	R_C55_RELLONG	= 0x0021, // "C55" added
	/// 7 MSBs of a byte, unsigned; used in DMA address
	R_LD3_DMA	= 0x0170,
	/// 7 bits spanning 2 bytes, unsigned; used as MDP register value
	R_LD3_MDP	= 0x0172,
	/// 9 bits spanning 2 bytes, unsigned; used as PDP register value
	R_LD3_PDP	= 0x0173,
	/// 23-bit unsigned value in 24-bit field
	R_LD3_REL23	= 0x0174,
	/// 8-bit unsigned direct reference
	R_LD3_k8	= 0x0210,
	/// 16-bit unsigned direct reference
	R_LD3_k16	= 0x0211,
	/// 8-bit signed direct reference
	R_LD3_K8	= 0x0212,
	/// 16-bit signed direct reference
	R_LD3_K16	= 0x0213,
	/// 8-bit unsigned PC-relative reference
	R_LD3_I8	= 0x0214,
	/// 16-bit unsigned PC-relative reference
	R_LD3_I16	= 0x0215,
	/// 8-bit signed PC-relative reference
	R_LD3_L8	= 0x0216,
	/// 16-bit signed PC-relative reference
	R_LD3_L16	= 0x0217,
	/// Unsigned 4-bit shift immediate
	R_LD3_k4	= 0x0220,
	/// Unsigned 5-bit shift immediate
	R_LD3_k5	= 0x0221,
	/// Signed 5-bit shift immediate
	R_LD3_K5	= 0x0222,
	/// Unsigned 6-bit shift immediate
	R_LD3_k6	= 0x0223,
	/// Unigned 12-bit shift immediate
	R_LD3_k12	= 0x0224,
	
	// MSP430 and TMS470 Relocation Types
	
	/// 32-bit direct reference to symbol's address
	R_RELLONG	= 0x0011,
	/// 23-bit PC-relative reference to a symbol's address, in halfwords (divided by 2)
	R_PCR23H	= 0x0016,
	/// 24-bit PC-relative reference to a symbol's address, in words (divided by 4)
	R_PCR24W	= 0x0017,
}

// NOTE: PE32 shares this header
struct coff_header_t { align(1):
	/// Magic.
	ushort f_magic;
	/// Number of sections.
	ushort f_nscns;
	/// Timestamp.
	int f_timedat;
	/// Pointer to symbolic header.
	int f_symptr;
	/// Number of symbol entries.
	int f_nsyms;
	/// Size of optional header.
	ushort f_opthdr;
	/// 
	ushort f_flags;
	
	// NOTE: TI extends this with ushort TargetID.
	//       Create new header (e.g., coff_ti_header_t) in case
}

// Optional header
struct coff_opt_header_t { align(1):
	ushort magic;
	ushort vstamp;
	uint textsize;
	uint datasize;
	uint bss_size;
	uint entry;
	uint text_start;
	uint data_start;
}

// COFF section header
struct coff_section_header_t { align(1):
	char[8] s_name;
	/* c_ulong */ uint s_paddr;	/// Physical address
	/* c_ulong */ uint s_vaddr;	/// Virtual address
	/* c_ulong */ uint s_size;	/// Section size in Bytes
	/* c_ulong */ uint s_scnptr;	/// File offset to section data
	/* c_ulong */ uint s_relptr;	/// File offset to relocation table
	/* c_ulong */ uint s_lnnoptr;	/// File offset to line number table
	ushort s_nreloc;	/// Number of relocation table entries
	ushort s_nlnno;		/// Number of line number entries
	/* c_ulong */ uint s_flags;	/// Flags
}
static assert(coff_section_header_t.sizeof == 40);

// COFF relocation entry
struct coff_reloc_entry_t { align(1):
	/* c_ulong */ uint r_vaddr;	/// Reference virtual address
	/* c_ulong */ uint r_symndx;	/// Symbol index
	ushort r_type;	/// Relocation type
}
static assert(coff_reloc_entry_t.sizeof == 10);

// COFF line number entry
struct coff_linenum_entry_t { align(1):
	union {
		/* c_ulong */ uint l_symndx;	/// Symbol index
		/* c_ulong */ uint l_paddr;	/// Physical address
	}
	ushort l_lnno;	/// Line number
}

enum : short { // e_scnum values
	/// Debugging symbol.
	N_DEBUG	= -2,
	/// Absolute symbol.
	N_ABS	= -1,
	/// Undefined
	N_UNDEF	= 0,
}

// For sections or symbols longer than 8 characters
// String Table Offset = File Header.f_symptr + File Header.f_nsyms * sizeof( Symbol Table Entry )
//                     = File Header.f_symptr + File Header.f_nsyms * 18
// GNU format will have "/4" where 4 is an offset into string table
union coff_string_entry_t { align(1):
	char[8] name;
	struct {
		/// If zeroes == 0, then offset is used.
		/* c_ulong */ uint zeroes;
		/// Offset to string table.
		/* c_ulong */ uint offset;
	}
}
static assert(coff_string_entry_t.sizeof == 8);

private enum SYMESZ = 18; /// Symbol (and Aux) entry size

// COFF symbol table entry
struct coff_symbol_entry_t { align(1): // Same size as aux entries (18 B)
	/// Symbol name entry.
	coff_string_entry_t entry;
	/// Symbol value (relates to e_sclass).
	/// C_AUTO
	/// C_ARG 	Address of the variable, relative to %ebp (C ABI)
	/// C_REG 	The register number assigned to this variable
	/// C_MOS 	Offset of the member from the beginning of the structure
	/// C_MOE 	The value of this enum member
	/// C_FIELD 	The mask for this field
	/// C_EOS 	Size of struct/union/enum
	/// C_EXT
	/// C_STAT
	/// others 	The address of the symbol (e.g., C_LABEL is relative within .text)
	/* c_ulong */ uint e_value;
	/// Section number. (Remember: 1-based, zero and lower have meaning)
	short e_scnum;
	/// Symbol type. (See T_* and DT_* enum)
	ushort e_type;
	/// Storage class. (See C_* enum)
	ubyte e_sclass;
	/// Number of auxiliary entries.
	ubyte e_numaux;
}
static assert(coff_symbol_entry_t.sizeof == SYMESZ);

// TI auxiliary symbol entry
struct coff_aux_ti_t { align(1):
	/// Section length
	uint a_sclen; // 0-3
	/// Count of relocation entries
	ushort a_relocs; // 4-5
	/// Count of line number entries
	ushort a_lncnt; // 6-7
	/// Unused, zero'd
	ubyte[10] a_pad;
}
static assert(coff_aux_ti_t.sizeof == SYMESZ);

// MS Auxiliary Format 1: Function Definitions
// When class is C_EXT (2), type is function (0x20), and section number >0.
struct coff_aux_ms_func_t { align(1):
	/// The symbol-table index of the corresponding .bf
	/// (begin function) symbol record.
	uint TagIndex;
	/// The size of the executable code for the function
	/// itself. If the function is in its own section, the
	/// SizeOfRawData in the section header is greater
	/// or equal to this field, depending on alignment
	/// considerations.
	uint TotalSize;
	/// The file offset of the first COFF line-number
	/// entry for the function, or zero if none exists. For
	/// more information, see “COFF Line Numbers (Deprecated).”
	uint PointerToLinenumber;
	/// The symbol-table index of the record for the next
	/// function. If the function is the last in the symbol
	/// table, this field is set to zero.
	uint PointerToNextFunction;
	/// 
	ushort Unused;
}
static assert(coff_aux_ms_func_t.sizeof == SYMESZ);

// MS Auxiliary Format 2: .bf and .ef Symbols
// When class is FUNCTION (101)
struct coff_aux_ms_funcblk_t { align(1):
	/// 
	uint Unused;
	/// The actual ordinal line number (1, 2, 3, and so
	/// on) within the source file, corresponding to the
	/// .bf or .ef record.
	ushort Linenumber;
	/// 
	ubyte[6] Unused2;
	/// The symbol-table index of the next .bf symbol
	/// record. If the function is the last in the symbol
	/// table, this field is set to zero. It is not used for
	/// .ef records.
	uint PointerToNextFunction; // .bf only
	/// 
	ushort Unused3;
}
static assert(coff_aux_ms_funcblk_t.sizeof == SYMESZ);

// MS Auxiliary Format 3: Weak Externals
// Class is C_EXT (2), UNDEF (0) section number, and value of zero (0).
struct coff_aux_ms_weak_t { align(1):
	/// The symbol-table index of sym2, the symbol to be linked
	/// if sym1 is not found.
	uint TagIndex;
	/// A value of IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY
	/// indicates that no library search for sym1 should be
	/// performed.
	/// A value of IMAGE_WEAK_EXTERN_SEARCH_LIBRARY
	/// indicates that a library search for sym1 should be
	/// performed.
	/// A value of IMAGE_WEAK_EXTERN_SEARCH_ALIAS
	/// indicates that sym1 is an alias for sym2.
	uint Characteristics;
	/// 
	ubyte[10] Unused;
}
static assert(coff_aux_ms_weak_t.sizeof == SYMESZ);

// MS Auxiliary Format 4: Files
// When name is ".file\0". value observed as zero (0).
struct coff_aux_ms_file_t { align(1):
	/// An ANSI string that gives the name of the source file. This
	/// is padded with nulls if it is less than the maximum length.
	char[18] FileName;
}
static assert(coff_aux_ms_file_t.sizeof == SYMESZ);

// MS Auxiliary Format 5: Section Definitions
// When name is of a section and class is STATIC (3).
struct coff_aux_ms_section_t { align(1):
	/// Section size. MSVC sets this for .bss and leaves SizeOfRawData at zero.
	uint Length;
	ushort NumberOfRelocations;
	ushort NumberOfLinenumbers;
	uint Checksum;
	/// Associated section number (low 16 bits) for IMAGE_COMDAT_SELECT_ASSOCIATIVE.
	ushort Number;
	/// COMDAT selection, see IMAGE_COMDAT_SELECT_*.
	ubyte Selection;
	ubyte Reserved;
	/// Associated section number (high 16 bits), bigobj only.
	ushort HighNumber;
}
static assert(coff_aux_ms_section_t.sizeof == SYMESZ);

/// Symbol entry with a 32-bit section number.
///
/// Used by the index API for both regular and bigobj symbol tables.
/// Auxiliary entries keep their regular layout in the first 18 bytes.
struct coff_symbol_ex_t { align(1):
	/// Symbol name entry.
	coff_string_entry_t entry;
	/// Symbol value (relates to e_sclass).
	uint e_value;
	/// Section number. 1-based, see N_* for special values.
	int e_scnum;
	/// Symbol type. (See T_* and DT_* enum)
	ushort e_type;
	/// Storage class. (See C_* enum)
	ubyte e_sclass;
	/// Number of auxiliary entries.
	ubyte e_numaux;
}
static assert(coff_symbol_ex_t.sizeof == 20);

/// Symbol index meaning no symbol.
enum COFF_NO_SYMBOL = uint.max;

/// COMDAT information of a section.
struct coff_comdat_t {
	/// Selection, see IMAGE_COMDAT_SELECT_*.
	ubyte selection;
	/// Associated section number for IMAGE_COMDAT_SELECT_ASSOCIATIVE, otherwise 0.
	uint associated;
	/// Index of the COMDAT symbol, or COFF_NO_SYMBOL (always for associative).
	uint key;
}

/// Linker directive from a .drectve section.
struct coff_directive_t {
	/// Option name without the leading slash or dash. Not null-terminated.
	const(char) *name;
	/// Length of name.
	size_t namelen;
	/// Value after the colon with quotes removed, or null. Not null-terminated.
	const(char) *value;
	/// Length of value.
	size_t valuelen;
}

private
struct internal_coff_t {
	coff_header_t header;
	coff_opt_header_t optheader;
	mscoff_anon_header_bigobj_t bigheader;
	/// Set if object uses the bigobj header and 20-byte symbols.
	bool bigobj;
	
	/// Machine value from either header.
	ushort machine;
	/// Number of sections.
	uint nsections;
	/// Number of symbol entries, including auxiliary entries.
	uint nsymbols;
	/// Size of a symbol entry in file (18 or 20).
	uint symsize;
	/// File offset to the section table.
	long secoff;
	/// File offset to the symbol table.
	long symoff;
	
	/// Current section header buffer
	coff_section_header_t c_sectionbuf;
	/// Current section index
	uint c_sectionidx;
	/// Section header buffer for adbg_object_coff_section_by_number.
	coff_section_header_t n_sectionbuf;
	
	/// Current symbol entry buffer
	coff_symbol_entry_t c_symbolbuf;
	/// Current symbol index
	uint c_symbolidx;
	/// Current symbol offset (due to aux. entry processing)
	long c_symboloff;
	
	/// Symbol table with 20-byte entries, loaded on first use.
	coff_symbol_ex_t *symtab;
	/// Section definition symbol index per section number, loaded on first use.
	uint *secsym;
	/// Second symbol index per section number (COMDAT symbol).
	uint *seckey;
	
	/// String table size, including the size field.
	uint strtblsize;
	/// String table, with an extra null byte at the end.
	char *strtbl;
	
	/// Symbol name buffer, includes name + null.
	char[10] tname;
	/// Section name buffer, includes name + null.
	char[10] sname;
}

/// Load a COFF or MS COFF bigobj object. Returns error code.
int adbg_object_coff_load(adbg_object_t *o) {
	int e = adbg_object_impl_setup(o, AdbgObject.coff,
		internal_coff_t.sizeof,
		&adbg_object_coff_unload);
	if (e) return e;
	
	internal_coff_t *coff = cast(internal_coff_t*)adbg_object_impl_get_buffer(o);
	
	// Read header
	e = adbg_object_read_at(o, 0, &coff.header, coff_header_t.sizeof);
	if (e) return e;
	
	// Bigobj: Sig1 is IMAGE_FILE_MACHINE_UNKNOWN and Sig2 is 0xffff
	if (coff.header.f_magic == 0 && coff.header.f_nscns == 0xffff) {
		with (coff.bigheader) {
		e = adbg_object_read_at(o, 0, &coff.bigheader, mscoff_anon_header_bigobj_t.sizeof);
		if (e) return e;
		if (Version < MSCOFF_VERSION_ANONV2 || ClassID.data != MSCOFF_BIGOBJ_CLSID.data)
			return adbg_oops(AdbgError.objectMalformed);
		
		coff.bigobj = true;
		coff.machine = Machine;
		coff.nsections = NumberOfSections;
		coff.nsymbols = NumberOfSymbols;
		coff.symsize = coff_symbol_ex_t.sizeof;
		coff.secoff = mscoff_anon_header_bigobj_t.sizeof;
		coff.symoff = PointerToSymbolTable;
		}
		return 0;
	}
	
	// Read optional header if opthdr size matches, present on executables
	if (coff.header.f_opthdr == coff_opt_header_t.sizeof) {
		e = adbg_object_read_at(o, coff_header_t.sizeof, &coff.optheader, coff_opt_header_t.sizeof);
		if (e) return e;
	}
	
	with (coff.header) {
	coff.machine = f_magic;
	coff.nsections = f_nscns;
	coff.nsymbols = f_nsyms;
	coff.symsize = SYMESZ;
	coff.secoff = coff_header_t.sizeof + f_opthdr;
	coff.symoff = cast(uint)f_symptr;
	}
	
	// TODO: Support swapping (from magic)
	return 0;
}
/// Free internal COFF buffers.
void adbg_object_coff_unload(adbg_object_t *o, void *u) {
	internal_coff_t *coff = cast(internal_coff_t*)u;
	if (coff.strtbl) free(coff.strtbl);
	if (coff.symtab) free(coff.symtab);
	if (coff.secsym) free(coff.secsym); // seckey shares this allocation
}

/// Regular COFF header, or null for bigobj.
/// Params: o = Object instance.
/// Returns: COFF Header instance; Null on error.
coff_header_t* adbg_object_coff_header(adbg_object_t *o) {
	internal_coff_t *coff = cast(internal_coff_t*)adbg_object_impl_get_buffer(o);
	if (coff == null) return null;
	if (coff.bigobj) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	return &coff.header;
}

/// Bigobj header, or null for regular COFF.
/// Params: o = Object instance.
/// Returns: COFF Header instance; Null on error.
mscoff_anon_header_bigobj_t* adbg_object_coff_bigobj_header(adbg_object_t *o) {
	internal_coff_t *coff = cast(internal_coff_t*)adbg_object_impl_get_buffer(o);
	if (coff == null) return null;
	if (coff.bigobj == false) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	return &coff.bigheader;
}

/// True if object is a MS COFF bigobj.
/// Params: o = Object instance.
/// Returns: True if it's a big object.
bool adbg_object_coff_is_bigobj(adbg_object_t *o) {
	internal_coff_t *coff = cast(internal_coff_t*)adbg_object_impl_get_buffer(o);
	return coff ? coff.bigobj : false;
}

/// Machine type of object, or AdbgMachine.unknown.
/// Params: o = Object instance.
/// Returns: Machine type.
AdbgMachine adbg_object_coff_machine(adbg_object_t *o) {
	internal_coff_t *coff = cast(internal_coff_t*)adbg_object_impl_get_buffer(o);
	if (coff == null) return AdbgMachine.unknown;
	
	switch (coff.machine) {
	case COFF_MAGIC_I386:
	case COFF_MAGIC_I386_AIX:	return AdbgMachine.i386;
	case COFF_MAGIC_AMD64:	return AdbgMachine.amd64;
	case COFF_MAGIC_IA64:	return AdbgMachine.ia64;
	case COFF_MAGIC_ARM64:	return AdbgMachine.aarch64;
	case COFF_MAGIC_Z80:	return AdbgMachine.z80;
//	case COFF_MAGIC_MSP430:	return "MSP430";
//	case COFF_MAGIC_TMS470:	return "TMS470";
//	case COFF_MAGIC_TMS320C5400:	return "TMS320C5400";
//	case COFF_MAGIC_TMS320C5500:	return "TMS320C5500";
//	case COFF_MAGIC_TMS320C2800:	return "TMS320C2800";
//	case COFF_MAGIC_TMS320C5500P:	return "TMS320C5500P";
	case COFF_MAGIC_TMS320C6000:	return AdbgMachine.tic6000;
	case COFF_MAGIC_MIPSEL:	return AdbgMachine.mipsle;
	default:
	}
	
	adbg_oops(AdbgError.objectUnknownFormat);
	return AdbgMachine.unknown;
}

/// Name of COFF magic value.
/// Params: mach = PE Machine value.
/// Returns: Name; Null on error.
const(char)* adbg_object_coff_magic_string(ushort mach) {
	switch (mach) {
	case COFF_MAGIC_I386:	return "I386";
	case COFF_MAGIC_I386_AIX:	return "I386_AIX";
	case COFF_MAGIC_AMD64:	return "AMD64";
	case COFF_MAGIC_IA64:	return "IA64";
	case COFF_MAGIC_ARM64:	return "ARM64";
	case COFF_MAGIC_Z80:	return "Z80";
	case COFF_MAGIC_TMS470:	return "TMS470";
	case COFF_MAGIC_TMS320C5400:	return "TMS320C5400";
	case COFF_MAGIC_TMS320C6000:	return "TMS320C6000";
	case COFF_MAGIC_TMS320C5500:	return "TMS320C5500";
	case COFF_MAGIC_TMS320C2800:	return "TMS320C2800";
	case COFF_MAGIC_MSP430:	return "MSP430";
	case COFF_MAGIC_TMS320C5500P:	return "TMS320C5500P";
	case COFF_MAGIC_MIPSEL:	return "MIPSEL";
	default:	return "Unknown";
	}
}

/// Optional header, or null if absent.
/// Params: o = Object instance.
/// Returns: COFF Optional Header instance; Null on error.
coff_opt_header_t* adbg_object_coff_optional_header(adbg_object_t *o) {
	internal_coff_t *coff = cast(internal_coff_t*)adbg_object_impl_get_buffer(o);
	if (coff == null) return null;
	
	if (coff.bigobj || coff.header.f_opthdr != coff_opt_header_t.sizeof) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	return &coff.optheader;
}

//
// String table
//

/// Load the string table once. Returns error code.
private
int adbg_object_coff_load_strtbl(adbg_object_t *o, internal_coff_t *coff) {
	if (coff.strtbl)
		return 0;
	
	long off = coff.symoff + (cast(long)coff.nsymbols * coff.symsize);
	version(Trace) trace("off=%lld", off);
	uint size = void;
	if (adbg_object_read_at(o, off, &size, uint.sizeof))
		return adbg_error_code();
	if (size <= uint.sizeof) // Empty
		return adbg_oops(AdbgError.unavailable);
	
	version(Trace) trace("strtblsize=%u", size);
	coff.strtbl = cast(char*)malloc(size + 1);
	if (coff.strtbl == null)
		return adbg_oops(AdbgError.crt);
	if (adbg_object_read_at(o, off + uint.sizeof, coff.strtbl + uint.sizeof, size - uint.sizeof)) {
		free(coff.strtbl);
		coff.strtbl = null;
		return adbg_error_code();
	}
	
	// DJGPP unsets bytes 0-3 because strings with an offset of zero
	// are considered valid, but empty.
	memset(coff.strtbl, 0, uint.sizeof);
	coff.strtbl[size] = 0;
	coff.strtblsize = size;
	return 0;
}

/// String at string table offset, or null.
private
const(char)* adbg_object_coff_string(adbg_object_t *o, internal_coff_t *coff, uint offset) {
	if (adbg_object_coff_load_strtbl(o, coff))
		return null;
	if (offset >= coff.strtblsize) {
		adbg_oops(AdbgError.offsetBounds);
		return null;
	}
	return coff.strtbl + offset;
}

/// Name from a name entry, short names are copied into buf. Returns null on error.
private
const(char)* adbg_object_coff_entry_name(adbg_object_t *o, internal_coff_t *coff,
	coff_string_entry_t *entry, ref char[10] buf) {
	// If first four bytes are unset,
	// the latter four bytes is an offset to the string table
	if (entry.zeroes == 0)
		return adbg_object_coff_string(o, coff, entry.offset);
	
	// Copy every character until null or buffer length into
	// temporary buffer, then null it (in case of full buffer used)
	size_t i;
	for (; i < entry.name.sizeof; ++i) {
		if (entry.name[i] == 0)
			break;
		buf[i] = entry.name[i];
	}
	buf[i] = 0;
	return buf.ptr;
}

//
// Section
//

/// Number of sections.
uint adbg_object_coff_section_count(adbg_object_t *o) {
	internal_coff_t *coff = cast(internal_coff_t*)adbg_object_impl_get_buffer(o);
	return coff ? coff.nsections : 0;
}

/// First section header, or null.
coff_section_header_t* adbg_object_coff_section_first(adbg_object_t *o) {
	internal_coff_t *coff = cast(internal_coff_t*)adbg_object_impl_get_buffer(o);
	if (coff == null) return null;
	
	// Check index
	if (coff.nsections == 0) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	// Read first header
	if (adbg_object_read_at(o, coff.secoff, &coff.c_sectionbuf, coff_section_header_t.sizeof, 0))
		return null;
	
	coff.c_sectionidx = 0;
	return &coff.c_sectionbuf;
}

/// Next section header, or null.
coff_section_header_t* adbg_object_coff_section_next(adbg_object_t *o) {
	internal_coff_t *coff = cast(internal_coff_t*)adbg_object_impl_get_buffer(o);
	if (coff == null) return null;
	
	// Check index
	uint newidx = coff.c_sectionidx + 1;
	if (newidx >= coff.nsections) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	// Read next header
	long offset = coff.secoff + (cast(long)coff_section_header_t.sizeof * newidx);
	if (adbg_object_read_at(o, offset, &coff.c_sectionbuf, coff_section_header_t.sizeof, 0))
		return null;
	
	coff.c_sectionidx = newidx;
	return &coff.c_sectionbuf;
}

/// Section header by 1-based section number, or null.
///
/// The returned buffer is reused by the next call.
coff_section_header_t* adbg_object_coff_section_by_number(adbg_object_t *o, uint number) {
	internal_coff_t *coff = cast(internal_coff_t*)adbg_object_impl_get_buffer(o);
	if (coff == null) return null;
	
	if (number == 0 || number > coff.nsections) {
		adbg_oops(AdbgError.indexBounds);
		return null;
	}
	
	long offset = coff.secoff + (cast(long)coff_section_header_t.sizeof * (number - 1));
	if (adbg_object_read_at(o, offset, &coff.n_sectionbuf, coff_section_header_t.sizeof, 0))
		return null;
	
	return &coff.n_sectionbuf;
}

/// Section name with "/N" and "//base64" long names resolved, or null.
///
/// Short names are copied into a buffer reused by the next call.
/// Params:
///     o = Object instance.
///     section = Object instance.
/// Returns: COFF Header instance; Null on error.
const(char)* adbg_object_coff_section_name(adbg_object_t *o, coff_section_header_t *section) {
	internal_coff_t *coff = cast(internal_coff_t*)adbg_object_impl_get_buffer(o);
	if (coff == null) return null;
	if (section == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	
	const(char)[] name = section.s_name[];
	if (name[0] == '/') {
		ulong off;
		if (name[1] == '/') { // "//" + 6 base64 digits
			foreach (char c; name[2..$]) {
				uint v = void;
				if (c >= 'A' && c <= 'Z')	v = c - 'A';
				else if (c >= 'a' && c <= 'z')	v = c - 'a' + 26;
				else if (c >= '0' && c <= '9')	v = c - '0' + 52;
				else if (c == '+')	v = 62;
				else if (c == '/')	v = 63;
				else goto Lmalformed;
				off = (off << 6) | v;
			}
		} else if (name[1] >= '0' && name[1] <= '9') { // "/" + decimal
			foreach (char c; name[1..$]) {
				if (c == 0) break;
				if (c < '0' || c > '9') goto Lmalformed;
				off = (off * 10) + (c - '0');
			}
		} else goto Lshort;
		
		if (off > uint.max) goto Lmalformed;
		return adbg_object_coff_string(o, coff, cast(uint)off);
	Lmalformed:
		adbg_oops(AdbgError.objectMalformed);
		return null;
	}

Lshort:
	size_t i;
	for (; i < name.length; ++i) {
		if (name[i] == 0)
			break;
		coff.sname[i] = name[i];
	}
	coff.sname[i] = 0;
	return coff.sname.ptr;
}

/// Section alignment in bytes from IMAGE_SCN_ALIGN_*, or 0 if unset (linkers default to 16).
uint adbg_object_coff_section_alignment(coff_section_header_t *section) {
	if (section == null) {
		adbg_oops(AdbgError.invalidArgument);
		return 0;
	}
	uint v = (section.s_flags & IMAGE_SCN_ALIGN_MASK) >> 20;
	return v == 0 || v > 14 ? 0 : 1 << (v - 1);
}

/// Read section data. Returns allocated buffer, or null.
void* adbg_object_coff_section_open_data(adbg_object_t *o, coff_section_header_t *section) {
	if (section == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	
	if (section.s_scnptr == 0 || section.s_size == 0) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	return adbg_object_readalloc_at(o, section.s_scnptr, section.s_size);
}
/// Free section data.
void adbg_object_coff_section_close_data(void *buf) {
	if (buf) free(buf);
}

/// Read section relocations, setting count. Returns allocated array, or null.
///
/// Handles IMAGE_SCN_LNK_NRELOC_OVFL.
coff_reloc_entry_t* adbg_object_coff_section_open_relocs(adbg_object_t *o,
	coff_section_header_t *section, uint *count) {
	if (section == null || count == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	*count = 0;
	
	uint n = section.s_nreloc;
	long offset = section.s_relptr;
	if (section.s_flags & IMAGE_SCN_LNK_NRELOC_OVFL && n == ushort.max) {
		// First entry holds the count, including itself
		coff_reloc_entry_t first = void;
		if (adbg_object_read_at(o, offset, &first, coff_reloc_entry_t.sizeof))
			return null;
		if (first.r_vaddr == 0) {
			adbg_oops(AdbgError.objectMalformed);
			return null;
		}
		n = first.r_vaddr - 1;
		offset += coff_reloc_entry_t.sizeof;
	}
	
	if (n == 0 || offset == 0) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	coff_reloc_entry_t *relocs = cast(coff_reloc_entry_t*)
		adbg_object_readalloc_at(o, offset, cast(size_t)n * coff_reloc_entry_t.sizeof);
	if (relocs == null)
		return null;
	
	*count = n;
	return relocs;
}
/// Free section relocations.
void adbg_object_coff_section_close_relocs(coff_reloc_entry_t *relocs) {
	if (relocs) free(relocs);
}

/// Build per-section symbol maps once. Returns error code.
private
int adbg_object_coff_load_secmap(adbg_object_t *o, internal_coff_t *coff) {
	if (coff.secsym)
		return 0;
	if (adbg_object_coff_load_symtab(o, coff))
		return adbg_error_code();
	
	size_t n = cast(size_t)coff.nsections + 1;
	coff.secsym = cast(uint*)malloc(n * 2 * uint.sizeof);
	if (coff.secsym == null)
		return adbg_oops(AdbgError.crt);
	coff.seckey = coff.secsym + n;
	memset(coff.secsym, 0xff, n * 2 * uint.sizeof); // COFF_NO_SYMBOL
	
	// MS COFF: first symbol of a section is its definition, second is the COMDAT symbol
	for (uint i; i < coff.nsymbols; i += 1 + coff.symtab[i].e_numaux) {
		coff_symbol_ex_t *sym = coff.symtab + i;
		if (sym.e_scnum <= 0 || sym.e_scnum > coff.nsections)
			continue;
		
		uint sec = sym.e_scnum;
		if (coff.secsym[sec] == COFF_NO_SYMBOL) {
			if (sym.e_sclass == C_STAT && sym.e_numaux && sym.e_value == 0)
				coff.secsym[sec] = i;
		} else if (coff.seckey[sec] == COFF_NO_SYMBOL)
			coff.seckey[sec] = i;
	}
	return 0;
}

/// Section definition aux entry by section number, or null.
coff_aux_ms_section_t* adbg_object_coff_section_aux(adbg_object_t *o, uint number) {
	internal_coff_t *coff = cast(internal_coff_t*)adbg_object_impl_get_buffer(o);
	if (coff == null) return null;
	
	if (number == 0 || number > coff.nsections) {
		adbg_oops(AdbgError.indexBounds);
		return null;
	}
	if (adbg_object_coff_load_secmap(o, coff))
		return null;
	
	uint i = coff.secsym[number];
	if (i == COFF_NO_SYMBOL || i + 1 >= coff.nsymbols) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	return cast(coff_aux_ms_section_t*)(coff.symtab + i + 1);
}

/// Fill COMDAT information of section number. Returns error code, unavailable if not a COMDAT.
int adbg_object_coff_section_comdat(adbg_object_t *o, uint number, coff_comdat_t *comdat) {
	if (comdat == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	coff_section_header_t *section = adbg_object_coff_section_by_number(o, number);
	if (section == null)
		return adbg_error_code();
	if ((section.s_flags & IMAGE_SCN_LNK_COMDAT) == 0)
		return adbg_oops(AdbgError.unavailable);
	
	coff_aux_ms_section_t *aux = adbg_object_coff_section_aux(o, number);
	if (aux == null)
		return adbg_error_code();
	
	internal_coff_t *coff = cast(internal_coff_t*)adbg_object_impl_get_buffer(o);
	comdat.selection = aux.Selection;
	if (aux.Selection == IMAGE_COMDAT_SELECT_ASSOCIATIVE) {
		comdat.associated = aux.Number;
		if (coff.bigobj)
			comdat.associated |= cast(uint)aux.HighNumber << 16;
		comdat.key = COFF_NO_SYMBOL;
	} else {
		comdat.associated = 0;
		comdat.key = coff.seckey[number];
	}
	return 0;
}

/// Size of section by number, the larger of SizeOfRawData and aux Length, or -1.
long adbg_object_coff_section_size(adbg_object_t *o, uint number) {
	coff_section_header_t *section = adbg_object_coff_section_by_number(o, number);
	if (section == null)
		return -1;
	uint size = section.s_size;
	
	internal_coff_t *coff = cast(internal_coff_t*)adbg_object_impl_get_buffer(o);
	if (adbg_object_coff_load_secmap(o, coff) == 0) {
		uint i = coff.secsym[number];
		if (i != COFF_NO_SYMBOL && i + 1 < coff.nsymbols) {
			coff_aux_ms_section_t *aux = cast(coff_aux_ms_section_t*)(coff.symtab + i + 1);
			if (aux.Length > size)
				size = aux.Length;
		}
	}
	return size;
}

//
// Symbol
//

/// Number of symbol entries, including auxiliary entries.
uint adbg_object_coff_symbol_count(adbg_object_t *o) {
	internal_coff_t *coff = cast(internal_coff_t*)adbg_object_impl_get_buffer(o);
	return coff ? coff.nsymbols : 0;
}

/// Load the symbol table once, widening regular entries to 20 bytes. Returns error code.
private
int adbg_object_coff_load_symtab(adbg_object_t *o, internal_coff_t *coff) {
	if (coff.symtab)
		return 0;
	if (coff.nsymbols == 0 || coff.symoff == 0)
		return adbg_oops(AdbgError.unavailable);
	
	if (coff.bigobj) {
		coff.symtab = cast(coff_symbol_ex_t*)adbg_object_readalloc_at(o,
			coff.symoff, cast(size_t)coff.nsymbols * coff_symbol_ex_t.sizeof);
		return coff.symtab ? 0 : adbg_error_code();
	}
	
	ubyte *raw = cast(ubyte*)adbg_object_readalloc_at(o,
		coff.symoff, cast(size_t)coff.nsymbols * SYMESZ);
	if (raw == null)
		return adbg_error_code();
	scope(exit) free(raw);
	
	coff.symtab = cast(coff_symbol_ex_t*)calloc(coff.nsymbols, coff_symbol_ex_t.sizeof);
	if (coff.symtab == null)
		return adbg_oops(AdbgError.crt);
	
	uint aux;
	for (uint i; i < coff.nsymbols; ++i) {
		ubyte *src = raw + (cast(size_t)i * SYMESZ);
		coff_symbol_ex_t *dst = coff.symtab + i;
		
		if (aux) { // Copied as-is
			memcpy(dst, src, SYMESZ);
			--aux;
			continue;
		}
		
		coff_symbol_entry_t *sym = cast(coff_symbol_entry_t*)src;
		dst.entry = sym.entry;
		dst.e_value = sym.e_value;
		// Section numbers go up to 0xfeff, special values start at 0xff00
		ushort scnum = cast(ushort)sym.e_scnum;
		dst.e_scnum = scnum >= 0xff00 ? sym.e_scnum : scnum;
		dst.e_type = sym.e_type;
		dst.e_sclass = sym.e_sclass;
		dst.e_numaux = sym.e_numaux;
		aux = sym.e_numaux;
	}
	return 0;
}

/// Symbol entry by index, or null. Auxiliary entries follow at index + 1.
///
/// Works with regular and bigobj symbol tables.
coff_symbol_ex_t* adbg_object_coff_symbol_at(adbg_object_t *o, uint index) {
	internal_coff_t *coff = cast(internal_coff_t*)adbg_object_impl_get_buffer(o);
	if (coff == null) return null;
	
	if (index >= coff.nsymbols) {
		adbg_oops(AdbgError.indexBounds);
		return null;
	}
	if (adbg_object_coff_load_symtab(o, coff))
		return null;
	
	return coff.symtab + index;
}

/// Name of symbol by index, or null.
///
/// Short names are copied into a buffer reused by the next call.
const(char)* adbg_object_coff_symbol_name_at(adbg_object_t *o, uint index) {
	coff_symbol_ex_t *sym = adbg_object_coff_symbol_at(o, index);
	if (sym == null) return null;
	internal_coff_t *coff = cast(internal_coff_t*)adbg_object_impl_get_buffer(o);
	return adbg_object_coff_entry_name(o, coff, &sym.entry, coff.tname);
}

/// Weak external aux entry of symbol by index, or null if not a weak external.
///
/// TagIndex is the index of the default symbol.
coff_aux_ms_weak_t* adbg_object_coff_symbol_weak(adbg_object_t *o, uint index) {
	coff_symbol_ex_t *sym = adbg_object_coff_symbol_at(o, index);
	if (sym == null) return null;
	
	internal_coff_t *coff = cast(internal_coff_t*)adbg_object_impl_get_buffer(o);
	if (sym.e_numaux == 0 || index + 1 >= coff.nsymbols)
		goto Lunavailable;
	
	// Spec describes C_EXT, compilers emit C_WEAKEXT
	if (sym.e_sclass == C_WEAKEXT ||
		(sym.e_sclass == C_EXT && sym.e_scnum == N_UNDEF && sym.e_value == 0))
		return cast(coff_aux_ms_weak_t*)(sym + 1);

Lunavailable:
	adbg_oops(AdbgError.unavailable);
	return null;
}

/// First symbol entry, or null. Regular COFF only, includes auxiliary entries.
coff_symbol_entry_t* adbg_object_coff_first_symbol(adbg_object_t *o) {
	internal_coff_t *coff = cast(internal_coff_t*)adbg_object_impl_get_buffer(o);
	if (coff == null) return null;
	
	if (coff.bigobj || coff.nsymbols == 0) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	// Read first entry
	if (adbg_object_read_at(o, coff.symoff, &coff.c_symbolbuf, coff_symbol_entry_t.sizeof, 0))
		return null;
	
	coff.c_symbolidx = 0;
	coff.c_symboloff = coff.symoff;
	return &coff.c_symbolbuf;
}

/// Next symbol entry, or null. Regular COFF only, includes auxiliary entries.
coff_symbol_entry_t* adbg_object_coff_next_symbol(adbg_object_t *o) {
	internal_coff_t *coff = cast(internal_coff_t*)adbg_object_impl_get_buffer(o);
	if (coff == null) return null;
	
	// Check index
	uint newidx = coff.c_symbolidx + 1;
	if (newidx >= coff.nsymbols) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	// Read next entry
	long offset = coff.c_symboloff + coff_symbol_entry_t.sizeof;
	if (adbg_object_read_at(o, offset, &coff.c_symbolbuf, coff_symbol_entry_t.sizeof, 0))
		return null;
	
	coff.c_symbolidx = newidx;
	coff.c_symboloff = offset;
	return &coff.c_symbolbuf;
}

/// Name of symbol entry, or null.
///
/// Short names are copied into a buffer reused by the next call.
const(char)* adbg_object_coff_symbol_name(adbg_object_t *o, coff_symbol_entry_t *symbol) {
	internal_coff_t *coff = cast(internal_coff_t*)adbg_object_impl_get_buffer(o);
	if (coff == null) return null;
	if (symbol == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	return adbg_object_coff_entry_name(o, coff, &symbol.entry, coff.tname);
}

//
// Directives
//

/// Parse the next linker directive of .drectve data at *pos, advancing it.
/// Returns error code, unavailable at end of data.
///
/// Example: `/DEFAULTLIB:"OLDNAMES"` gives name DEFAULTLIB and value OLDNAMES.
int adbg_object_coff_directive_next(const(char) *data, size_t size, size_t *pos, coff_directive_t *dir) {
	if (data == null || pos == null || dir == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	size_t i = *pos;
	
	// UTF-8 BOM
	if (i == 0 && size >= 3 && data[0] == '\xef' && data[1] == '\xbb' && data[2] == '\xbf')
		i = 3;
	
	bool isspace(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == 0; }
	
	while (i < size && isspace(data[i])) ++i;
	if (i >= size) {
		*pos = size;
		return adbg_oops(AdbgError.unavailable);
	}
	
	if (data[i] != '/' && data[i] != '-')
		return adbg_oops(AdbgError.objectMalformed);
	
	size_t start = ++i;
	while (i < size && data[i] != ':' && isspace(data[i]) == false) ++i;
	dir.name = data + start;
	dir.namelen = i - start;
	dir.value = null;
	dir.valuelen = 0;
	
	if (i < size && data[i] == ':') {
		++i;
		if (i < size && data[i] == '"') {
			start = ++i;
			while (i < size && data[i] != '"') ++i;
			dir.value = data + start;
			dir.valuelen = i - start;
			if (i < size) ++i; // Closing quote
		} else {
			start = i;
			while (i < size && isspace(data[i]) == false) ++i;
			dir.value = data + start;
			dir.valuelen = i - start;
		}
		// Skip rest of token
		while (i < size && isspace(data[i]) == false) ++i;
	}
	
	*pos = i;
	return 0;
}
unittest {
	static immutable char[] drectve = "  /DEFAULTLIB:\"OLD NAMES\" -export:foo,DATA /merge:.a=.b /nologo ";
	coff_directive_t dir = void;
	size_t pos;
	
	assert(adbg_object_coff_directive_next(drectve.ptr, drectve.length, &pos, &dir) == 0);
	assert(dir.name[0..dir.namelen] == "DEFAULTLIB");
	assert(dir.value[0..dir.valuelen] == "OLD NAMES");
	assert(adbg_object_coff_directive_next(drectve.ptr, drectve.length, &pos, &dir) == 0);
	assert(dir.name[0..dir.namelen] == "export");
	assert(dir.value[0..dir.valuelen] == "foo,DATA");
	assert(adbg_object_coff_directive_next(drectve.ptr, drectve.length, &pos, &dir) == 0);
	assert(dir.name[0..dir.namelen] == "merge");
	assert(dir.value[0..dir.valuelen] == ".a=.b");
	assert(adbg_object_coff_directive_next(drectve.ptr, drectve.length, &pos, &dir) == 0);
	assert(dir.name[0..dir.namelen] == "nologo");
	assert(dir.value == null);
	assert(adbg_object_coff_directive_next(drectve.ptr, drectve.length, &pos, &dir) == AdbgError.unavailable);
}

// NOTE: The n_value, n_scnum and n_sclass fields need to be considered as interlinked.
//       Source: (wiki.osdev.org/COFF)
//
// Following table is mostly from observations.
//
// n_sclass   | n_scnum          | n_value | Meaning        | Typical use
// -----------+------------------+---------+----------------+--------------
// C_EXT (2)  | 0                | 0       | --             | Unresolved external Symbol
//            | 0                | >0      | Variable size  | Uninitialised global variable (not in BSS)
//            | .text            | Any     | Section offset | Function entry point
//            | .data            | Any     | Section offset | Initialised global variable
// C_STAT (3) | .text/.data/.bss | 0       | --             | Section Symbol indicating start of Section
//            | .data            | Any     | Section offset | Initialised static variable
//            | .bss             | Any     | Section offset | Unitialised static variable

/// Fill symbol list with COFF labels. Returns error code.
int adbg_coff_populate_symbols(adbg_symbol_list_t *list, adbg_object_t *o) {
	if (list == null || o == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	if (adbg_object_format(o) != AdbgObject.coff)
		return adbg_oops(AdbgError.assertion);
	
	uint count = adbg_object_coff_symbol_count(o);
	coff_symbol_ex_t *sym = void;
	for (uint i; i < count; i += 1 + sym.e_numaux) {
		sym = adbg_object_coff_symbol_at(o, i);
		if (sym == null)
			return adbg_error_code();
		
		switch (sym.e_sclass) {
		case C_EXT, C_STAT: // Public or private class
			// HACK: Labels/Functions filtering
			//       Not auxiliary entries and points to section 1 (typically .text)
			if (sym.e_numaux || sym.e_scnum != 1)
				continue;
			char *name = cast(char*)adbg_object_coff_symbol_name_at(o, i);
			if (name == null)
				continue;
			if (adbg_symbol_list_append_label(list, name, 0, sym.e_value))
				return adbg_error_code();
			break;
		default:
		}
	}
	
	return 0;
}
