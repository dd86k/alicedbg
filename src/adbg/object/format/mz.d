/// MZ executable object format.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.object.format.mz;

import adbg.error;
import adbg.object.server;
import adbg.utils.bit;
import core.stdc.stdlib : malloc, calloc, free;

//TODO: Support compressed MZ files?

/// Minimum file size for an MZ EXE.
// NOTE: Borland EXE about 6K (includes a CRT?).
private enum MINIMUM_SIZE = mz_header_t.sizeof + PAGE;

/// Minimum, non-extended, header size.
enum MZMHSZ = 28;

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

/// MZ header structure.
struct mz_header_t {
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
	// Extended MZ header fields for newer executables (NE, LX, PE).
	ushort[ERESWDS] e_res;	/// Reserved words
	uint e_lfanew;	/// 
}
static assert(mz_header_t.e_lfanew.offsetof == LFANEW_OFFSET);

// old alias
public alias mz_hdr_ext = mz_header_t;

/// MZ relocation entry
struct mz_reloc_t {
	ushort offset;
	ushort segment;
}

// old alias
alias mz_reloc = mz_reloc_t;

private enum {
	S_RELOCS_REVERSED = 1,
}
private
struct internal_mz_t {
	mz_header_t header;
	bool *r_relocs; /// Reversed relocations
	mz_reloc *relocs;
}

int adbg_object_mz_load(adbg_object_t *o) {
	// Set format and allocate object internals
	o.format = AdbgObject.mz;
	o.internal = calloc(1, internal_mz_t.sizeof);
	if (o.internal == null)
		return adbg_oops(AdbgError.crt);
	if (adbg_object_read_at(o, 0, o.internal, mz_header_t.sizeof) < 0)
		return adbg_errno();
	
	// Inverse header if required
	mz_header_t* header = cast(mz_header_t*)o.internal;
	if (o.status & AdbgObjectInternalFlags.reversed) with (header) {
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
	
	return 0;
}

void adbg_object_mz_unload(adbg_object_t *o) {
	if (o == null) return;
	if (o.internal == null) return;
	
	internal_mz_t *internal = cast(internal_mz_t*)o.internal;
	
	if (internal.r_relocs) free(internal.r_relocs);
	if (internal.relocs) free(internal.relocs);
	
	free(internal);
}

mz_header_t* adbg_object_mz_header(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	return &(cast(internal_mz_t*)o.internal).header;
}

mz_reloc_t* adbg_object_mz_reloc(adbg_object_t *o, size_t index) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	
	internal_mz_t *internal = cast(internal_mz_t*)o.internal;
	
	// Initiate relocs
	with (internal) if (relocs == null) {
		// Any relocations in object and after header?
		if (header.e_crlc == 0 || header.e_lfarlc < MZMHSZ) {
			adbg_oops(AdbgError.unavailable);
			return null;
		}
		// Allocation portion to hold relocations
		size_t size = mz_reloc_t.sizeof * header.e_crlc;
		relocs = cast(mz_reloc_t*)malloc(size);
		if (relocs == null) {
			adbg_oops(AdbgError.crt);
			return null;
		}
		// Error set by function
		if (adbg_object_read_at(o, header.e_lfarlc, relocs, size) < 0) {
			free(relocs);
			relocs = null;
			return null;
		}
		// Initiate reverse info if required
		if (o.status & AdbgObjectInternalFlags.reversed) {
			r_relocs = cast(bool*)malloc(header.e_crlc);
			if (r_relocs == null) {
				free(relocs);
				relocs = null;
				adbg_oops(AdbgError.crt);
				return null;
			}
		}
	}
	
	if (index >= internal.header.e_crlc) {
		adbg_oops(AdbgError.indexBounds);
		return null;
	}
	
	mz_reloc_t *reloc = &internal.relocs[index];
	if (o.status & AdbgObjectInternalFlags.reversed && internal.r_relocs[index] == false) {
		reloc.offset = adbg_bswap16(reloc.offset);
		reloc.segment = adbg_bswap16(reloc.segment);
		internal.r_relocs[index] = true;
	}
	return reloc;
}

const(char)* adbg_object_mz_kind_string(adbg_object_t *o) {
	if (o == null || o.internal == null)
		return null;
	return (cast(mz_header_t*)o.internal).e_ovno ? `Overlayed Executable` : `Executable`;
}