/// COFF format.
///
/// Sources:
/// - https://delorie.com/djgpp/doc/coff/
/// - https://www.ti.com/lit/an/spraao8/spraao8.pdf
///
/// ECOFF (MIPS) and XCOFF (AIX) aren't supported
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.object.format.coff;

import adbg.object.server;
import adbg.utils.bit;
import adbg.machines;
import adbg.error;
import core.stdc.stdlib;

extern (C):

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

// NOTE: PE32 shares this header
struct coff_header_t {
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
	
	// NOTE: Some COFF extensions have an additional magic and/or targetID
	//       TI: extends this with ushort TargetID;
}

private
struct internal_coff_t {
	coff_header_t header;
}

int adbg_object_coff_load(adbg_object_t *o) {
	o.internal = calloc(1, internal_coff_t.sizeof);
	if (o.internal == null)
		return adbg_oops(AdbgError.crt);
	
	internal_coff_t *internal = cast(internal_coff_t*)o.internal;
	
	if (adbg_object_read_at(o, 0, &internal.header, coff_header_t.sizeof))
		return adbg_errno();
	
	adbg_object_postload(o, AdbgObject.coff, &adbg_object_coff_unload);
	
	// TODO: Support swapping
	return 0;
}
void adbg_object_coff_unload(adbg_object_t *o) {
	if (o == null) return;
	if (o.internal == null) return;
	
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
		adbg_oops(AdbgError.invalidArgument);
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
