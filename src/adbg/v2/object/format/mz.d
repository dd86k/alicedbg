/// MZ executable object format.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.v2.object.format.mz;

import adbg.v2.object.server : adbg_object_t, AdbgObject;
import adbg.utils.bit : CHAR16;

/// Magic number for MZ objects.
enum MAGIC_MZ = CHAR16!"MZ";

private enum ERESWDS = 16;
private enum PAGE = 512;

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
static assert(mz_hdr.e_lfanew.offsetof == 0x3c);

/// MZ relocation entry
struct mz_reloc {
	ushort offset;
	ushort segment;
}

int adbg_object_mz_load(adbg_object_t *obj) {
	obj.type = AdbgObject.mz;
	obj.i.mz.header = cast(mz_hdr*)obj.buffer;
	with (obj.i.mz) if (header.e_lfarlc && header.e_crlc && header.e_lfarlc < obj.file_size)
		relocs = cast(mz_reloc*)(obj.buffer + header.e_lfarlc);
	return 0;
}