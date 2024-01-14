/// COFF archive format.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.v2.object.format.coff;

import adbg.utils.bit;

// Sources:
// - https://delorie.com/djgpp/doc/coff/
// - https://www.ti.com/lit/an/spraao8/spraao8.pdf

enum : ushort {
	/// i386 COFF magic
	COFF_MAGIC_I386	= I16!(0x4c, 0x01),	// 0x14c
	/// i386 AIX COFF magic
	COFF_MAGIC_I386_AIX	= I16!(0x75, 0x01),	// 0x175
	/// amd64 COFF magic
	COFF_MAGIC_AMD64	= I16!(0x64, 0x86),
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
	
	/// If set, there is no relocation information in this file.
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
}

struct coff_header {
	/// Magic
	ushort f_magic;
	/// Number of sections
	ushort f_nscns;
	/// Timestamp
	int f_timedat;
	/// Pointer to symbolic header
	int f_symptr;
	/// Size of symbolic header
	int f_nsyms;
	/// Size of optional header
	ushort f_opthdr;
	/// 
	ushort f_flags;
	// NOTE: TI COFF has another signature
}