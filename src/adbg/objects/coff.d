/// COFF format.
///
/// Sources:
/// - https://delorie.com/djgpp/doc/coff/
/// - https://www.ti.com/lit/an/spraao8/spraao8.pdf
/// - https://wiki.osdev.org/COFF
///
/// ECOFF (MIPS) and XCOFF (AIX) aren't supported
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.objects.coff;

import adbg.objectserver;
import adbg.utils.bit;
import adbg.machines;
import adbg.error;
import core.stdc.stdlib;
import core.stdc.string : memset, memcpy;

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

// NOTE: These are pre-swapped but may be wrong on big-endian targets
//       objectserver might have to keep a pre-swapped version for itself
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
	
	/// Optional header magic for TI
	COFF_OPT_MAGIC_TI	= I16!(0x08, 0x01),	// 0108h
	/// Optional header magic for MIPSEL
	COFF_OPT_MAGIC_MIPSEL	= I16!(0x07, 0x01),	// SOMAGIC 0x0701
	/// Optional header magic for DJGPP
	COFF_OPT_MAGIC_ZMAGIC	= I16!(0x0b, 0x01),	// 0x010b
	
	// Header flags
	
	/// If set, relocation information has been removed.
	/// This is usually clear for objects and set for executables.
	COFF_F_RELFLG	= I16!(0x00, 0x01),
	/// If set, all unresolved symbols have been resolved and the
	/// file may be considered executable.
	COFF_F_EXEC	= I16!(0x00, 0x02),
	/// If set, all line number information has been removed from the
	/// file (or was never added in the first place).
	COFF_F_LNNO	= I16!(0x00, 0x04),
	/// If set, all the local symbols have been removed from the
	/// file (or were never added in the first place).
	COFF_F_LSYMS	= I16!(0x00, 0x08),
	/// Indicates that the file is little endian (in most cases)
	COFF_F_LSB	= I16!(0x01, 0x00),
	/// Indicates that the file is big endian (in most cases)
	COFF_F_MSB	= I16!(0x02, 0x00),
	
	// Section flags
	
	/// The section contains executable code.
	COFF_STYPE_TEXT	= LITTLE16!(0x0020),
	/// The section contains initialised data.
	COFF_STYPE_DATA	= LITTLE16!(0x0040),
	/// The COFF file contains no data for this section, but needs space to be allocated for it.
	COFF_STYPE_BSS	= LITTLE16!(0x0080),
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
struct coff_header_t {
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
}

// Optional header
struct coff_opt_header_t {
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
struct coff_section_header_t {
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

// COFF relocation entry
struct coff_reloc_entry_t {
	/* c_ulong */ uint r_vaddr;	/// Reference virtual address
	/* c_ulong */ uint r_symndx;	/// Symbol index
	ushort r_type;	/// Relocation type
}

// COFF line number entry
struct coff_linenum_entry_t {
	union {
		/* c_ulong */ uint l_symndx;	/// Symbol index
		/* c_ulong */ uint l_paddr;	/// Physical address
	}
	ushort l_lnno;	/// Line number
}

// NOTE: The n_value, n_scnum and n_sclass fields need to be considered as interlinked.
//       Source: (wiki.osdev.org/COFF)
//
// A number of the more common combinations of these fields is given in the
// following table. (Much of the information in the following table is from
// observation and not from referenced sources.
// It is incomplete and may not be accurate.) 
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
union coff_string_entry_t {
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
	uint Length;
	ushort NumberOfRelocations;
	ushort NumberOfLinenumbers;
	uint Checksum;
	ushort Number;
	ubyte Selection;
	ubyte[3] Unused;
}

private
struct internal_coff_t {
	coff_header_t header;
	coff_opt_header_t optheader;
	
	/// Current section header buffer
	coff_section_header_t *c_sectionbuf;
	/// Current section index
	ushort c_sectionidx;
	
	/// Current symbol entry buffer
	coff_symbol_entry_t *c_symbolbuf;
	/// Current symbol index
	ushort c_symbolidx;
	/// Current symbol offset (due to aux. entry processing)
	long c_symboloff;
	
	/// String table size
	int strtblsize;
	/// String table
	char *strtbl;
	
	/// Temporary buffer when resolving names,
	/// this includes name + null
	char[10] tname;
}

int adbg_object_coff_load(adbg_object_t *o) {
	o.internal = calloc(1, internal_coff_t.sizeof);
	if (o.internal == null)
		return adbg_oops(AdbgError.crt);
	
	internal_coff_t *internal = cast(internal_coff_t*)o.internal;
	
	// Read header
	int e = adbg_object_read_at(o, 0, &internal.header, coff_header_t.sizeof);
	if (e) return e;
	
	// Read optional header if opthdr size matches, present on executables
	if (internal.header.f_opthdr == coff_opt_header_t.sizeof) {
		e = adbg_object_read_at(o, coff_header_t.sizeof, &internal.optheader, coff_opt_header_t.sizeof);
		if (e) return e;
	}
	
	adbg_object_postload(o, AdbgObject.coff, &adbg_object_coff_unload);
	
	// TODO: Support swapping
	return 0;
}
void adbg_object_coff_unload(adbg_object_t *o) {
	if (o == null) return;
	if (o.internal == null) return;
	
	internal_coff_t *internal = cast(internal_coff_t*)o.internal;
	if (internal.c_sectionbuf) free(internal.c_sectionbuf);
	if (internal.c_symbolbuf) free(internal.c_symbolbuf);
	if (internal.strtbl) free(internal.strtbl);
	
	free(o.internal);
}

coff_header_t* adbg_object_coff_header(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	
	return &(cast(internal_coff_t*)o.internal).header;
}

AdbgMachine adbg_object_coff_machine(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return AdbgMachine.unknown;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return AdbgMachine.unknown;
	}
	
	internal_coff_t *internal = cast(internal_coff_t*)o.internal;
	
	switch (internal.header.f_magic) {
	case COFF_MAGIC_I386:
	case COFF_MAGIC_I386_AIX:	return AdbgMachine.i386;
	case COFF_MAGIC_AMD64:	return AdbgMachine.amd64;
	case COFF_MAGIC_IA64:	return AdbgMachine.ia64;
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

const(char)* adbg_object_coff_magic_string(ushort mach) {
	switch (mach) {
	case COFF_MAGIC_I386:	return "I386";
	case COFF_MAGIC_I386_AIX:	return "I386_AIX";
	case COFF_MAGIC_AMD64:	return "AMD64";
	case COFF_MAGIC_IA64:	return "IA64";
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

coff_opt_header_t* adbg_object_coff_optional_header(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	
	internal_coff_t *internal = cast(internal_coff_t*)o.internal;
	if (internal.header.f_opthdr != coff_opt_header_t.sizeof) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	return &internal.optheader;
}

//
// Section
//

coff_section_header_t* adbg_object_coff_section_first(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	
	// Check index
	internal_coff_t *internal = cast(internal_coff_t*)o.internal;
	if (internal.header.f_nscns <= 0) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	// Allocate buffer for section header
	if (internal.c_sectionbuf == null)
		internal.c_sectionbuf = cast(coff_section_header_t*)malloc(coff_section_header_t.sizeof);
	if (internal.c_sectionbuf == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	// Read first header
	long offset = coff_header_t.sizeof + internal.header.f_opthdr;
	if (adbg_object_read_at(o, offset, internal.c_sectionbuf, coff_section_header_t.sizeof, 0))
		return null;
	
	internal.c_sectionidx = 0;
	return internal.c_sectionbuf;
}

coff_section_header_t* adbg_object_coff_section_next(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	
	// Check index
	internal_coff_t *internal = cast(internal_coff_t*)o.internal;
	if (internal.c_sectionbuf == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	int newidx = internal.c_sectionidx + 1;
	if (newidx >= internal.header.f_nscns) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	if (newidx > ushort.max) {
		adbg_oops(AdbgError.assertion);
		return null;
	}
	
	// Read next header
	long offset =
		coff_header_t.sizeof +
		internal.header.f_opthdr +
		(coff_section_header_t.sizeof * newidx);
	if (adbg_object_read_at(o, offset, internal.c_sectionbuf, coff_section_header_t.sizeof, 0))
		return null;
	
	internal.c_sectionidx = cast(ushort)newidx;
	return internal.c_sectionbuf;
}

// TODO: coff_section_header_t* adbg_object_coff_section_by_index(adbg_object_t *o, short index)

void* adbg_object_coff_section_open_data(adbg_object_t *o, coff_section_header_t *section) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	
	if (section.s_scnptr == 0 || section.s_size == 0) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	return adbg_object_readalloc_at(o, section.s_scnptr, section.s_size, 0);
}
void adbg_object_coff_section_close_data(void *buf) {
	if (buf) free(buf);
}

//
// Symbol
//

// 
coff_symbol_entry_t* adbg_object_coff_first_symbol(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	
	// Allocate buffer for symbol entry buffer
	internal_coff_t *internal = cast(internal_coff_t*)o.internal;
	if (internal.c_symbolbuf == null)
		internal.c_symbolbuf = cast(coff_symbol_entry_t*)malloc(coff_section_header_t.sizeof);
	if (internal.c_symbolbuf == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	// Read first entry
	long offset = internal.header.f_symptr;
	if (adbg_object_read_at(o, offset, internal.c_symbolbuf, coff_symbol_entry_t.sizeof, 0))
		return null;
	
	internal.c_symbolidx = 0;
	internal.c_symboloff = offset;
	return internal.c_symbolbuf;
}

//
coff_symbol_entry_t* adbg_object_coff_next_symbol(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	
	// Check index
	internal_coff_t *internal = cast(internal_coff_t*)o.internal;
	if (internal.c_symbolbuf == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	int newidx = internal.c_symbolidx + 1;
	if (newidx >= internal.header.f_nscns) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	if (newidx > ushort.max) {
		adbg_oops(AdbgError.assertion);
		return null;
	}
	
	// Read next entry
	long offset =
		internal.c_symboloff
		+ coff_symbol_entry_t.sizeof
		+ ( internal.c_symbolbuf.e_numaux * 18 );
	if (adbg_object_read_at(o, offset, internal.c_symbolbuf, coff_symbol_entry_t.sizeof, 0))
		return null;
	
	internal.c_symbolidx = cast(ushort)newidx;
	internal.c_symboloff = offset;
	return internal.c_symbolbuf;
}

// Resolves COFF symbol name
const(char)* adbg_object_coff_symbol_name(adbg_object_t *o, coff_symbol_entry_t *symbol) {
	if (o == null || symbol == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	
	internal_coff_t *internal = cast(internal_coff_t*)o.internal;
	
	// If first four bytes are unset,
	// the latter four bytes is an offset to the string table
	if (symbol.entry.zeroes == 0) {
		// Load string table
		if (internal.strtbl == null) {
			long off =
				internal.header.f_symptr +
				(internal.header.f_nsyms * 18);
			version(Trace) trace("off=%lld", off);
			if (adbg_object_read_at(o, off, &internal.strtblsize, int.sizeof, 0))
				return null;
			
			// Adjust size
			internal.strtblsize -= 4;
			if (internal.strtblsize <= 0) { // Empty
				adbg_oops(AdbgError.unavailable);
				return null;
			}
			
			version(Trace) trace("strtblsize=%u", internal.strtblsize);
			internal.strtbl = cast(char*)malloc(internal.strtblsize + 4);
			if (internal.strtbl == null) {
				adbg_oops(AdbgError.crt);
				return null;
			}
			if (adbg_object_read_at(o, off + 4, internal.strtbl + 4, internal.strtblsize, 0))
				return null;
			
			// DJGPP unsets bytes 0-3 because strings with an offset of zero
			// are considered valid, but empty.
			memset(internal.strtbl, 0, 4);
		}
		
		char *str = internal.strtbl + symbol.entry.offset;
		with (internal) return
			adbg_bits_boundchk(str, 10 /* 8+null+align */,
				internal.strtbl, internal.strtblsize) ?
				null : str;
	}
	
	// Copy every character until null or buffer length into
	// temporary buffer, then null it (in case of full 8 chars used)
	size_t i;
	for (; i < coff_symbol_entry_t.entry.name.sizeof; ++i) {
		if (symbol.entry.name[i] == 0)
			break;
		internal.tname[i] = symbol.entry.name[i];
	}
	internal.tname[i] = 0;
	return internal.tname.ptr;
}

/*
void* adbg_object_coff_first_aux_symbol(adbg_object_t *o, coff_symbol_entry_t *entry) {
	
}
*/