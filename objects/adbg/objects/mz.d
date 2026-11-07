/// MZ executable object format.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.objects.mz;

import adbg.error;
import adbg.objectserver;
import adbg.utils.bit;
import adbg.objects.ne : NE_MAGIC, adbg_object_ne_load;
import adbg.objects.lx : LX_MAGIC, LE_MAGIC, adbg_object_lx_load;
import adbg.objects.pe : PE_MAGIC, adbg_object_pe_load;
import adbg.utils.math : MiB;
import core.stdc.stdlib : malloc, calloc, free;

extern (C):

// TODO: Support compressed MZ files?

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

/// MZ relocation entry
struct mz_reloc_t {
	ushort offset;
	ushort segment;
}

private enum {
	INTERNAL_REVERSED = 1,
}
private
struct internal_mz_t {
	mz_header_t header;
	mz_reloc_t *relocs;
	int status;
}

int adbg_object_mz_load(adbg_object_t *o) {
	version (Trace) trace("o=%p", o);
	uint newsig = void;
	
	// Read MZ header to detect if we're dealing with a newer executable format
	mz_header_t header = void;
	int e = adbg_object_read_at(o, 0, &header, mz_header_t.sizeof);
	if (e) return e;
	version (Trace) trace("e_lfarlc=%#x", header.e_lfarlc);
	
	// If e_lfarlc (relocation table) starts lower than e_lfanew,
	// then assume old MZ, since e_lfarlc can point to 0x40.
	if (header.e_lfarlc < 0x40)
		goto Lmz;
	
	// If e_lfanew points within (extended) MZ header,
	// assume invalid offset
	if (header.e_lfanew <= mz_header_t.sizeof)
		goto Lmz;
	
	// ReactOS checks if NtHeaderOffset is not higher than 256 MiB.
	// If it is higher, it considers the executable to be invalid.
	// See: sdk/lib/rtl/image.c:RtlpImageNtHeaderEx
	if (header.e_lfanew >= MiB!256)
		return adbg_oops(AdbgError.objectMalformed);
	
	e = adbg_object_read_at(o, header.e_lfanew, &newsig, newsig.sizeof);
	if (e) return e;
	
	// 32-bit signature check
	version (Trace) trace("newsig=%#x", newsig);
	switch (newsig) {
	case PE_MAGIC:
		return adbg_object_pe_load(o, &header);
	default:
	}
	
	// 16-bit signature check
	switch (cast(ushort)newsig) {
	case NE_MAGIC:
		return adbg_object_ne_load(o, &header);
	case LX_MAGIC, LE_MAGIC:
		return adbg_object_lx_load(o, &header);
	default:
		// Because e_lfanew is set and reloc
		return adbg_oops(AdbgError.objectMalformed);
	}
	
Lmz:	// Nothing else came up, load as MZ
	e = adbg_object_impl_setup(o, AdbgObject.mz,
		internal_mz_t.sizeof,
		&adbg_object_mz_unload);
	if (e) return e;
	
	internal_mz_t *mz = cast(internal_mz_t*)adbg_object_impl_get_buffer(o);
	
	// Read header
	e = adbg_object_read_at(o, 0, &mz.header, mz_header_t.sizeof);
	if (e) return e;
	
	// HACK: Bad hack to check word endian
	if (mz.header.e_magic == MAGIC_ZM)
		mz.status = INTERNAL_REVERSED;
	
	// Inverse header if required
	if (mz.status & INTERNAL_REVERSED) with (mz.header) {
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

void adbg_object_mz_unload(adbg_object_t *o, void *buffer) {
	internal_mz_t *mz = cast(internal_mz_t*)buffer;
	if (mz.relocs)  free(mz.relocs);
}

mz_header_t* adbg_object_mz_header(adbg_object_t *o) {
	internal_mz_t *mz = cast(internal_mz_t*)adbg_object_impl_get_buffer(o);
	if (mz == null) return null;
	return &mz.header;
}

mz_reloc_t* adbg_object_mz_reloc(adbg_object_t *o, size_t index) {
	internal_mz_t *mz = cast(internal_mz_t*)adbg_object_impl_get_buffer(o);
	if (mz == null) return null;
	
	// Initiate relocation buffer
	if (mz.relocs == null) {
		// Any relocations in object and after header?
		if (mz.header.e_crlc == 0 || mz.header.e_lfarlc < MZMHSZ) {
			adbg_oops(AdbgError.unavailable);
			return null;
		}
		
		// Allocate portion to hold relocations
		size_t size = mz.header.e_crlc * mz_reloc_t.sizeof;
		mz.relocs = cast(mz_reloc_t*)malloc(size);
		if (mz.relocs == null) {
			adbg_oops(AdbgError.crt);
			return null;
		}
		
		// Error set by function
		if (adbg_object_read_at(o, mz.header.e_lfarlc, mz.relocs, size)) {
			free(mz.relocs);
			mz.relocs = null;
			return null;
		}
		
		// Byteswap all relocation entries
		if (mz.status & INTERNAL_REVERSED) {
			for (ushort i; i < mz.header.e_crlc; ++i) {
				mz_reloc_t *reloc = &mz.relocs[index];
				reloc.offset = adbg_bswap16(reloc.offset);
				reloc.segment = adbg_bswap16(reloc.segment);
			}
		}
	}
	
	// Check index bounds
	if (index >= mz.header.e_crlc) {
		adbg_oops(AdbgError.indexBounds);
		return null;
	}
	
	// Get relocation
	return &mz.relocs[index];
}

const(char)* adbg_object_mz_kind_string(adbg_object_t *o) {
	internal_mz_t *mz = cast(internal_mz_t*)adbg_object_impl_get_buffer(o);
	if (mz == null) return null;
	
	return mz.header.e_ovno ? `Overlayed Executable` : `Executable`;
}