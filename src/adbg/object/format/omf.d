/// OMF format.
///
/// This format, made by Intel, dates back to the 8080, and starting with the
/// 8086, Microsoft extensively used it on MS-DOS.
///
/// It was superseeded by COFF objects and libraries, and the MSCOFF format,
/// when Windows Vista was released.
///
/// Sources:
/// - Tool Interface Standards (TIS) Relocatable Object Module Format (OMF) Specification Version 1.1
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.object.format.omf;

import adbg.object.server;
import adbg.error;
import core.stdc.stdlib;

// NOTE: Checksums are either 0 or a modulo 256

/*enum {
	PAGE_SIZE = 16,
	BLOCK_SIZE = 512,
	MAX_RECORD_SIZE = 1024,
}*/

// Flags
enum : ubyte {
	/// Library flag: Case-senstive, if set. Applies to regular and extended dictionaries.
	OMF_LF_CS = 1,
}

// NOTE: Record type numbering
//       "An odd Record Type indicates that certain numeric fields within the record contain 32-bit values;"
//       "an even Record Type indicates that those fields contain 16-bit values."
// NOTE: Record type management
//       Record numbers can be masked by 0xFE, since the first bit is signifiant to mean the 16/32 selector.
/// OMF Record type
enum OMFRecord : ubyte {
	/// Library File Format Record
	LIBRARY = 0xF0,
	
	/// Translator Header Record
	THEADR = 0x80,
	/// Library Module Header Record
	LHEADR = 0x82,
	/// Comment Record
	COMENT = 0x88,
	/// Import Definition Record (Command Class A0, Subtype 01)
	IMPDEF = 0x88,
	/// Export Definition Record (Command Class A0, Subtype 02)
	EXPDEF = 0x88,
	/// Incremental Compilation Record (Command Class A0, Subtype 03)
	INCDEF = 0x88,
	/// Microsoft C++ (Linker) Directives Record (Command Class A0, Subtype 05)
	LNKDIR = 0x88,
	/// Library Module Name Record (Comment Class A3)
	LIBMOD = 0x88,
	/// Executable String Record (Comment Class A4)
	EXESTR = 0x88,
	/// Incremental Compilation error (Command Class A6)
	INCCER = 0x88,
	/// No Segment Padding (Comment Class A7)
	NOPAD  = 0x88,
	/// Weak Extern Record (Comment Class A8)
	WKEXT  = 0x88,
	/// Lazy Extern Record (Comment Class A9)
	LZEXT  = 0x88,
	/// Module End Record
	MODEND = 0x8A, // or 8B
	/// External Names Definition Record
	EXTDEF = 0x8C,
	/// Public Names Definition Record
	PUBDEF = 0x90, // or 91
	/// Line Numbers Record
	LINNUM = 0x94, // or 95 (0x96 is erratum)
	/// List of Names Record
	LNAMES = 0x96,
	/// Segment Definition Record
	SEGDEF = 0x98, // or 99
	/// Group Definition Record
	GRPDEF = 0x9A,
	/// Fixup Record
	FIXUPP = 0x9C, // or 9D
	/// Logical Enumerated Data Record
	LEDATA = 0xA0, // or A1
	/// Logical Iterated Data Record
	LIDATA = 0xA2, // or A3
	/// Communal Names Definition Record
	COMDEF = 0xB0,
	/// Backpatch Record
	BAKPAT = 0xB2, // or B3
	/// Local External Names Definition Record
	LEXTDEF = 0xB4, // or B5
	/// Local Public Names Definition Record
	LPUBDEF = 0xB6, // or B7
	/// Local Communual Names Definition Record
	LCOMFDEF = 0xB8,
	/// COMDAT External Names Definition Record
	CEXTDEF = 0xBC,
	/// Initialized Communual Data Record
	COMDAT = 0xC2, // or C3
	/// Symbol Line Numbers Record
	LINSYM = 0xC4, // or C5
	/// Alias Definition Record
	ALIAS = 0xC6,
	/// Named Backpatch Record
	NBKPAT = 0xC8, // or C9
	/// Local Logical Names Defintion Record
	LLNAMES = 0xCA,
	/// OMF Version Number Record
	VERNUM = 0xCC,
	/// Vendor-specific OMF Extension Record
	VENDEXT = 0xCE,
}

struct omf_lib_header_t { align(1):
	ubyte type;
	ushort size;	/// Size of this record, minus 3
	uint dicoff;	/// Directory offset
	ushort dicsize;	/// Directory size in blocks (512 B for DOS libs, limited to 251)
	ubyte flags;
}

struct omf_entry_header_t { align(1):
	ubyte type;
	ushort size;
}

struct omf_entry_t { align(1):
	ubyte type;
	ushort size;
	void *data;
	ubyte checksum;
}

private
struct internal_omf_t {
	omf_lib_header_t header;
	int firstentry; // Offset to first entry. Libraries have this to non-zero.
	int nextentry;  // Offset to next entry.
	int lastsize;   // Size of last entry.
}

int adbg_object_omf_load(adbg_object_t *o, ubyte first) {
	o.internal = calloc(1, internal_omf_t.sizeof);
	if (o.internal == null)
		return adbg_oops(AdbgError.crt);
	
	o.format = AdbgObject.omf;
	
	// NOTE: No swapping is done because I'm lazy
	
	internal_omf_t *internal = cast(internal_omf_t*)o.internal;
	
	switch (first) with (OMFRecord) {
	case LIBRARY: // Check library header
		if (adbg_object_read_at(o, 0, &internal.header, omf_lib_header_t.sizeof)) {
			free(o.internal);
			return adbg_errno();
		}
		
		// Legal values at >=4 and <=15, typically 0xd (13), since 13+3=16
		with (internal.header) if (size < 4 || size > 15)
			return adbg_oops(AdbgError.objectMalformed);
		
		internal.firstentry = internal.header.size + 3;
		break;
	case THEADR, LHEADR: // Recommended entries by spec
		internal.firstentry = 0;
		break;
	default:
		return adbg_oops(AdbgError.objectMalformed);
	}
	
	return 0;
}

void adbg_object_omf_unload(adbg_object_t *o) {
	if (o == null) return;
	if (o.internal == null) return;
	
	free(o.internal);
}

int adbg_object_omf_is_library(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return -1;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return -1;
	}
	internal_omf_t *internal = cast(internal_omf_t*)o.internal;
	return internal.firstentry;
}

omf_lib_header_t* adbg_object_omf_library_header(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	internal_omf_t *internal = cast(internal_omf_t*)o.internal;
	return internal.firstentry ? &internal.header : null;
}

omf_entry_t* adbg_object_omf_entry_first(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	
	internal_omf_t *internal = cast(internal_omf_t*)o.internal;
	
	// Reset next offset
	internal.nextentry = internal.firstentry;
	
	return adbg_object_omf_get_entry(o, internal.firstentry);
}

omf_entry_t* adbg_object_omf_entry_next(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	
	internal_omf_t *internal = cast(internal_omf_t*)o.internal;
	
	// Last entry was valid, increase to next offset
	if (internal.lastsize)
		internal.nextentry += internal.lastsize + 3;
	
	return adbg_object_omf_get_entry(o, internal.nextentry);
}

private
omf_entry_t* adbg_object_omf_get_entry(adbg_object_t *o, int offset) {
	
	// Ready header for size
	omf_entry_header_t entryhdr = void;
	if (adbg_object_read_at(o, offset, &entryhdr, omf_entry_header_t.sizeof))
		return null;
	
	// Allocate entry
	omf_entry_t* entry = cast(omf_entry_t*)malloc(omf_entry_t.sizeof + entryhdr.size);
	if (entry == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	// Setup entry fields
	entry.type = entryhdr.type;
	entry.size = entryhdr.size;
	entry.data = cast(void*)entry + omf_entry_t.sizeof;
	entry.checksum = (cast(ubyte*)entry.data)[entry.size - 1];
	
	// Read entry data
	if (adbg_object_read_at(o, offset + omf_entry_header_t.sizeof, entry.data, entry.size))
		return null;
	
	internal_omf_t *internal = cast(internal_omf_t*)o.internal;
	internal.lastsize = entry.size;
	return entry;
}

void adbg_object_omf_entry_close(omf_entry_t *entry) {
	if (entry == null)
		return;
	free(entry);
}

int adbg_object_omf_verify(omf_entry_t *entry) {
	if (entry == null)
		return 1;
	if (entry.data == null)
		return 1;
	if (entry.checksum == 0)
		return 0;
	return adbg_object_omf_chksum(entry.data, entry.size) == entry.checksum;
}

// negative sum (modulo 256)
private
ubyte adbg_object_omf_chksum(void* data, int length) {
	ubyte r;
	for (int i; i < length; ++i)
		r += (cast(ubyte*)data)[i];
	return r;
}
unittest {
	static immutable ubyte[] a1 = [ 0x31 ];
	assert(adbg_object_omf_chksum(cast(void*)a1.ptr, a1.length) == 0x31);
	static immutable ubyte[] a2 = [ 0x31, 0x31 ];
	assert(adbg_object_omf_chksum(cast(void*)a2.ptr, a2.length) == 0x62);
}

const(char)* adbg_object_omf_type_string(omf_entry_t *entry) {
	if (entry == null)
		return null;
	switch (entry.type & 0xfe) with (OMFRecord) {
	case THEADR:	return "THEADR";
	case LHEADR:	return "LHEADR";
	case COMENT:	return "COMENT";
	//case IMPDEF:	return "IMPDEF";
	//case EXPDEF:	return "EXPDEF";
	//case INCDEF:	return "INCDEF";
	//case LNKDIR:	return "LNKDIR";
	//case LIBMOD:	return "LIBMOD";
	//case EXESTR:	return "EXESTR";
	//case INCCER:	return "INCCER";
	//case NOPAD:	return "NOPAD";
	//case WKEXT:	return "WKEXT";
	//case LZEXT:	return "LZEXT";
	case MODEND:	return "MODEND";
	case EXTDEF:	return "EXTDEF";
	case PUBDEF:	return "PUBDEF";
	case LINNUM:	return "LINNUM";
	case LNAMES:	return "LNAMES";
	case SEGDEF:	return "SEGDEF";
	case GRPDEF:	return "GRPDEF";
	case FIXUPP:	return "FIXUPP";
	case LEDATA:	return "LEDATA";
	case LIDATA:	return "LIDATA";
	case COMDEF:	return "COMDEF";
	case BAKPAT:	return "BAKPAT";
	case LEXTDEF:	return "LEXTDEF";
	case LPUBDEF:	return "LPUBDEF";
	case LCOMFDEF:	return "LCOMFDEF";
	case CEXTDEF:	return "CEXTDEF";
	case COMDAT:	return "COMDAT";
	case LINSYM:	return "LINSYM";
	case ALIAS:	return "ALIAS";
	case NBKPAT:	return "NBKPAT";
	case LLNAMES:	return "LLNAMES";
	case VERNUM:	return "VERNUM";
	case VENDEXT:	return "VENDEXT";
	default:	return null;
	}
}