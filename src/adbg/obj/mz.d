/**
 * MZ executable object format.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.obj.mz;

import adbg.obj.server : AdbgObjFormat, adbg_object_t;
import adbg.disasm.disasm : AdbgPlatform;

private enum ERESWDS = 0x10;

/// MZ header structure
struct mz_hdr {
	ushort e_magic;	/// Magic number
	ushort e_cblp;	/// Bytes on last page of file
	ushort e_cp;	/// Pages in file
	ushort e_crlc;	/// Number of relocation entries in the table
	ushort e_cparh;	/// Size of header in paragraphs
	ushort e_minalloc;	/// Minimum extra paragraphs needed
	ushort e_maxalloc;	/// Maximum extra paragraphs needed
	ushort e_ss;	/// Initial (relative) SS value
	ushort e_sp;	/// Initial SP value
	ushort e_csum;	/// Checksum
	ushort e_ip;	/// Initial IP value
	ushort e_cs;	/// Initial (relative) CS value
	ushort e_lfarlc;	/// File address of relocation table
	ushort e_ovno;	/// Overlay number
	ushort[ERESWDS] e_res;	/// Reserved words
	uint   e_lfanew;	/// File address of new exe header (usually at 3Ch)
}

/// MZ relocation entry
struct mz_reloc {
	ushort offset;
	ushort segment;
}

int adbg_obj_mz_preload(adbg_object_t *obj) {
	obj.format = AdbgObjFormat.MZ;
	obj.platform = AdbgPlatform.x86_16;
	obj.mz.hdr = cast(mz_hdr*)obj.buf;
	if (obj.mz.hdr.e_lfarlc && obj.mz.hdr.e_crlc)
		obj.mz.relocs = cast(mz_reloc*)(obj.buf + obj.mz.hdr.e_lfarlc);
	return 0;
}