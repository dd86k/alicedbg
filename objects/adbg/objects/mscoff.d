/// MS-COFF Import Library format.
///
/// Libraries typically built for the exporting application.
///
/// Sources:
/// - Microsoft Portable Executable and Common Object File Format Specification
//    Revision 11 – January 23, 2017
/// - https://github.com/dlang/dmd/blob/master/compiler/src/dmd/backend/mscoff.d
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.objects.mscoff;

// Layout:
// - UNIX Archive member header
// - Import Header
// - Null-terminated import name string
// - Null-terminated DLL name string

import adbg.objectserver;
import adbg.objects.coff : adbg_object_coff_load;
import adbg.utils.uid;
import adbg.error;
import core.stdc.stdlib;

extern (C):

enum {
	MSCOFF_VERSION_IMPORT = 0,
	MSCOFF_VERSION_ANON   = 1,
	MSCOFF_VERSION_ANONV2 = 2,
}

enum {
	MSCOFF_OBJECT_CODE = 0,
	MSCOFF_OBJECT_DATA = 1,
	MSCOFF_OBJECT_CONST = 2,
}

enum {
	/// Import by ordinal
	MSCOFF_IMPORT_NAME_ORDINAL = 0,
	/// Import name is public symbol name.
	MSCOFF_IMPORT_NAME = 1,
	/// Import name is public symbol name skipping leading "?", "@", or optionally "_".
	MSCOFF_IMPORT_NAME_NO_PREFIX = 2,
	/// Import name is public symbol name skipping leading "?", "@", or optionally "_"
	/// and truncating at first "@".
	MSCOFF_IMPORT_NAME_UNDECORATE = 3,
	/// Import name is a name is explicitly provided after the DLL name.
	MSCOFF_IMPORT_NAME_EXPORTAS = 4,
}

struct mscoff_import_header_t { align(1): // IMPORT_OBJECT_HEADER
	/// Must be IMAGE_FILE_MACHINE_UNKNOWN.
	ushort Sig1;
	/// Must be 0xFFFF.
	ushort Sig2;
	/// Must be 0.
	ushort Version;
	/// PE32 machine.
	ushort Machine;
	/// Seconds since 1970.
	uint TimeStamp;
	/// Size of the strings following the header.
	uint Size;
	/// Ordinal, or hint if imported by name.
	ushort Ordinal;
	/// Type (bits 0-1, MSCOFF_OBJECT_*) and name type (bits 2-4, MSCOFF_IMPORT_*).
	ushort Flags;
}
static assert(mscoff_import_header_t.sizeof == 20);

struct mscoff_anon_header_t { align(1): // ANON_OBJECT_HEADER
	ushort Sig1;            // Must be IMAGE_FILE_MACHINE_UNKNOWN
	ushort Sig2;            // Must be 0xffff
	ushort Version;         // >= 1 (implies the CLSID field is present)
	ushort Machine;
	uint   TimeDateStamp;
	
	/*CLSID*/ UID   ClassID;         // Used to invoke CoCreateInstance
	uint   SizeOfData;      // Size of data that follows the header
}
static assert(mscoff_anon_header_t.sizeof == 32);

struct mscoff_anon_header_v2_t { align(1): // ANON_OBJECT_HEADER_V2
	ushort Sig1;            // Must be IMAGE_FILE_MACHINE_UNKNOWN
	ushort Sig2;            // Must be 0xffff
	ushort Version;         // >= 2 (implies the Flags field is present - otherwise V1)
	ushort Machine;
	uint   TimeDateStamp;
	
	/* CLSID */ UID   ClassID;         // Used to invoke CoCreateInstance
	uint   SizeOfData;      // Size of data that follows the header
	uint   Flags;           // 0x1 -> contains metadata
	uint   MetaDataSize;    // Size of CLR metadata
	uint   MetaDataOffset;  // Offset of CLR metadata
}
static assert(mscoff_anon_header_v2_t.sizeof == 44);

struct mscoff_anon_header_bigobj_t { align(1): // ANON_OBJECT_HEADER_BIGOBJ
	/* same as ANON_OBJECT_HEADER_V2 */
	ushort Sig1;            // Must be IMAGE_FILE_MACHINE_UNKNOWN
	ushort Sig2;            // Must be 0xffff
	ushort Version;         // >= 2 (implies the Flags field is present)
	ushort Machine;         // Actual machine - IMAGE_FILE_MACHINE_xxx
	uint   TimeDateStamp;
	
	/* CLSID */ UID   ClassID;         // {D1BAA1C7-BAEE-4ba9-AF20-FAF66AA4DCB8}
	uint   SizeOfData;      // Size of data that follows the header, could be zero
	uint   Flags;           // 0x1 -> contains metadata
	uint   MetaDataSize;    // Size of CLR metadata
	uint   MetaDataOffset;  // Offset of CLR metadata

	/* bigobj specifics */
	uint   NumberOfSections; // extended from WORD
	uint   PointerToSymbolTable;
	uint   NumberOfSymbols;
}
static assert(mscoff_anon_header_bigobj_t.sizeof == 56);

/// Bigobj class ID, {D1BAA1C7-BAEE-4ba9-AF20-FAF66AA4DCB8}.
immutable UID MSCOFF_BIGOBJ_CLSID = UID(
	0xc7, 0xa1, 0xba, 0xd1, 0xee, 0xba, 0xa9, 0x4b,
	0xaf, 0x20, 0xfa, 0xf6, 0x6a, 0xa4, 0xdc, 0xb8);

// Same as PE32
enum SYMNMLEN = 8;

struct mscoff_anon_symbol_table32_t {
	union {
		ubyte[SYMNMLEN] Name;
		struct {
			uint Zeros;
			uint Offset;
		}
	}
	uint Value;
	int SectionNumber;
	ushort Type;
	ubyte StorageClass;
	ubyte NumberOfAuxSymbols;
}
static assert(mscoff_anon_symbol_table32_t.sizeof == 20);

struct mscoff_anon_symbol_table_t { align(1):
	ubyte[SYMNMLEN] Name;
	uint Value;
	short SectionNumber;
	ushort Type;
	ubyte StorageClass;
	ubyte NumberOfAuxSymbols;
}
static assert(mscoff_anon_symbol_table_t.sizeof == 18);

private
struct internal_mscoff_t {
	union {
		mscoff_import_header_t import_header;
		mscoff_anon_header_t anon_header;
		mscoff_anon_header_v2_t anonv2_header;
	}
	/// Import strings with an extra null byte, import objects only.
	char *strings;
	/// Size of strings, excluding the extra null byte.
	uint stringsize;
}

/// Load an import or anonymous object, bigobj is forwarded to the COFF loader. Returns error code.
int adbg_object_mscoff_load(adbg_object_t *o) {
	// Import header is the smallest, and Version is common to all
	mscoff_anon_header_v2_t hdr = void;
	int e = adbg_object_read_at(o, 0, &hdr, mscoff_import_header_t.sizeof);
	if (e) return e;
	
	if (hdr.Version >= MSCOFF_VERSION_ANONV2) {
		e = adbg_object_read_at(o, 0, &hdr, mscoff_anon_header_v2_t.sizeof);
		if (e) return e;
		if (hdr.ClassID.data == MSCOFF_BIGOBJ_CLSID.data)
			return adbg_object_coff_load(o);
	}
	
	e = adbg_object_impl_setup(o, AdbgObject.mscoff,
		internal_mscoff_t.sizeof,
		&adbg_object_mscoff_unload);
	if (e) return e;
	
	internal_mscoff_t *mscoff = cast(internal_mscoff_t*)adbg_object_impl_get_buffer(o);
	
	switch (hdr.Version) {
	case MSCOFF_VERSION_IMPORT:
		e = adbg_object_read_at(o, 0, &mscoff.import_header, mscoff_import_header_t.sizeof);
		if (e) return e;
		
		uint size = mscoff.import_header.Size;
		if (size == 0)
			return 0;
		mscoff.strings = cast(char*)malloc(size + 1);
		if (mscoff.strings == null)
			return adbg_oops(AdbgError.crt);
		e = adbg_object_read_at(o, mscoff_import_header_t.sizeof, mscoff.strings, size);
		if (e) return e;
		mscoff.strings[size] = 0;
		mscoff.stringsize = size;
		break;
	case MSCOFF_VERSION_ANON:
		e = adbg_object_read_at(o, 0, &mscoff.anon_header, mscoff_anon_header_t.sizeof);
		if (e) return e;
		break;
	default:
		e = adbg_object_read_at(o, 0, &mscoff.anonv2_header, mscoff_anon_header_v2_t.sizeof);
		if (e) return e;
	}
	
	// TODO: Support swapping
	
	return 0;
}
/// Free internal buffers.
void adbg_object_mscoff_unload(adbg_object_t *o, void *u) {
	internal_mscoff_t *mscoff = cast(internal_mscoff_t*)u;
	if (mscoff.strings) free(mscoff.strings);
}

/// Header version, see MSCOFF_VERSION_*.
/// Params: o = Object instance.
/// Returns: MS-COFF version.
uint adbg_object_mscoff_version(adbg_object_t *o) {
	internal_mscoff_t *mscoff = cast(internal_mscoff_t*)adbg_object_impl_get_buffer(o);
	if (mscoff == null) return 0;
	return mscoff.anon_header.Version;
}

/// Header, cast depending on version, or null.
/// Params: o = Object instance.
/// Returns: Header instance.
void* adbg_object_mscoff_header(adbg_object_t *o) {
	internal_mscoff_t *mscoff = cast(internal_mscoff_t*)adbg_object_impl_get_buffer(o);
	if (mscoff == null) return null;
	return &mscoff.anon_header;
}

/// Import header, or null if not an import object.
private
internal_mscoff_t* adbg_object_mscoff_import(adbg_object_t *o) {
	internal_mscoff_t *mscoff = cast(internal_mscoff_t*)adbg_object_impl_get_buffer(o);
	if (mscoff == null) return null;
	if (mscoff.import_header.Version != MSCOFF_VERSION_IMPORT) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	return mscoff;
}

/// Import type, see MSCOFF_OBJECT_*, or -1.
int adbg_object_mscoff_import_type(adbg_object_t *o) {
	internal_mscoff_t *mscoff = adbg_object_mscoff_import(o);
	return mscoff ? mscoff.import_header.Flags & 3 : -1;
}

/// Import name type, see MSCOFF_IMPORT_*, or -1.
int adbg_object_mscoff_import_name_type(adbg_object_t *o) {
	internal_mscoff_t *mscoff = adbg_object_mscoff_import(o);
	return mscoff ? (mscoff.import_header.Flags >> 2) & 7 : -1;
}

/// Nth null-terminated import string, or null.
private
const(char)* adbg_object_mscoff_import_string(adbg_object_t *o, uint n) {
	internal_mscoff_t *mscoff = adbg_object_mscoff_import(o);
	if (mscoff == null) return null;
	
	uint i;
	for (; n; --n) {
		while (i < mscoff.stringsize && mscoff.strings[i]) ++i;
		++i; // null
	}
	if (i >= mscoff.stringsize) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	return mscoff.strings + i;
}

/// Public symbol name of import object, or null.
/// Params: o = Object instance.
/// Returns: Public symbol name of import object, or null.
const(char)* adbg_object_mscoff_import_name(adbg_object_t *o) {
	return adbg_object_mscoff_import_string(o, 0);
}

/// DLL name of import object, or null.
/// Params: o = Object instance.
/// Returns: Public symbol name of import object, or null.
const(char)* adbg_object_mscoff_import_dll(adbg_object_t *o) {
	return adbg_object_mscoff_import_string(o, 1);
}

/// Export name for MSCOFF_IMPORT_NAME_EXPORTAS, or null.
/// Params: o = Object instance.
/// Returns: Public symbol name of import object, or null.
const(char)* adbg_object_mscoff_import_exportas(adbg_object_t *o) {
	if (adbg_object_mscoff_import_name_type(o) != MSCOFF_IMPORT_NAME_EXPORTAS) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	return adbg_object_mscoff_import_string(o, 2);
}
