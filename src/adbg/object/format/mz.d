/// MZ executable object format.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.object.format.mz;

import adbg.error;
import adbg.object.server : adbg_object_t, AdbgObject;
import adbg.utils.bit;

//TODO: Support compressed MZ files?

/// Minimum file size for an MZ EXE.
// NOTE: Borland EXE about 6K (includes a CRT?).
private enum MINIMUM_SIZE = mz_hdr.sizeof + PAGE;

/// Magic number for MZ objects.
enum MAGIC_MZ = CHAR16!"MZ";
/// Swappged magic for MZ objects.
enum MAGIC_ZM = CHAR16!"ZM";

/// Number of reserved words for e_res.
enum ERESWDS = 16;
/// Size of a MZ paragraph.
enum PARAGRAPH = 16;
/// Size of a MZ page.
enum PAGE = 512;

/// Offset to e_lfanew field in the MZ header, added
/// in NE, LE, and PE32 executable images.
enum LFANEW_OFFSET = 0x3c;

/// Original MZ header structure.
/// 
/// Newer executables add these new fields:
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
}
/// Extended MZ header structure featured with newer executables (NE, LE, PE).
struct mz_hdr_ext {
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
	uint e_lfanew;	/// 
}

/// MZ relocation entry
struct mz_reloc {
	ushort offset;
	ushort segment;
}

int adbg_object_mz_load(adbg_object_t *o) {
	import core.stdc.stdlib : calloc;
	
	if (o.file_size < MINIMUM_SIZE)
		return adbg_oops(AdbgError.objectTooSmall);
	
	with (o.i.mz.header)
	if (o.p.reversed) {
		e_magic	= adbg_bswap16(e_magic);
		e_cblp	= adbg_bswap16(e_cblp);
		e_cp	= adbg_bswap16(e_cp);
		e_crlc	= adbg_bswap16(e_crlc);
		e_cparh	= adbg_bswap16(e_cparh);
		e_minalloc	= adbg_bswap16(e_minalloc);
		e_maxalloc	= adbg_bswap16(e_maxalloc);
		e_ss	= adbg_bswap16(e_ss);
		e_sp	= adbg_bswap16(e_sp);
		e_csum	= adbg_bswap16(e_csum);
		e_ip	= adbg_bswap16(e_ip);
		e_cs	= adbg_bswap16(e_cs);
		e_lfarlc	= adbg_bswap16(e_lfarlc);
		e_ovno	= adbg_bswap16(e_ovno);
	}
	
	o.format = AdbgObject.mz;
	with (o.i.mz)
	if (header.e_lfarlc && header.e_crlc && header.e_lfarlc < o.file_size) {
		relocs = cast(mz_reloc*)(o.buffer + header.e_lfarlc);
		if (o.p.reversed)
			o.i.mz.reversed_relocs = cast(bool*)calloc(header.e_crlc, bool.sizeof);
	}
	return 0;
}

mz_hdr* adbg_object_mz_header(adbg_object_t *o) {
	if (o == null) return null;
	return o.i.mz.header;
}

mz_reloc* adbg_object_mz_reloc(adbg_object_t *o, size_t index) {
	if (o == null) return null;
	if (o.i.mz.relocs == null) return null; // no relocations available
	if (index >= o.i.mz.header.e_crlc) return null;
	
	mz_reloc *reloc = &o.i.mz.relocs[index];
	if (o.p.reversed && o.i.mz.reversed_relocs[index] == false) {
		reloc.offset = adbg_bswap16(reloc.offset);
		reloc.segment = adbg_bswap16(reloc.segment);
		o.i.mz.reversed_relocs[index] = true;
	}
	return reloc;
}