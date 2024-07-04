/// MS-COFF anonymous object format.
///
/// Sources:
/// - Microsoft documentation
/// - https://github.com/dlang/dmd/blob/master/compiler/src/dmd/backend/mscoff.d
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.objects.mscoff;

// NOTE: PE32/PE-COFF is an extension of COFF and MZ

import adbg.objectserver;
import adbg.utils.uid;
import adbg.utils.math;
import adbg.error;
import core.stdc.stdlib;

extern (C):

//
// Non-COFF Object file headers (.obj from VS2002-VS2015, mscoff)
//

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

struct mscoff_import_header_t { // IMPORT_OBJECT_HEADER
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
	
	uint Size;
	ushort Ordinal; // or Hint
	// Type : 2 -> IMPORT_TYPE
	// NameType : 3 -> IMPORT_NAME_TYPE
	// Reserved : 11
	ulong Flags;
}

struct mscoff_anon_header_t { // ANON_OBJECT_HEADER
	ushort Sig1;            // Must be IMAGE_FILE_MACHINE_UNKNOWN
	ushort Sig2;            // Must be 0xffff
	ushort Version;         // >= 1 (implies the CLSID field is present)
	ushort Machine;
	uint   TimeDateStamp;
	
	/*CLSID*/ UID   ClassID;         // Used to invoke CoCreateInstance
	uint   SizeOfData;      // Size of data that follows the header
}

struct mscoff_anon_header_v2_t { // ANON_OBJECT_HEADER_V2
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

struct mscoff_anon_header_bigobj_t { // ANON_OBJECT_HEADER_BIGOBJ
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
}

private enum MAX1 = MAX!(mscoff_anon_header_t.sizeof, mscoff_anon_header_v2_t.sizeof);
private enum MAX2 = MAX!(MAX1, mscoff_import_header_t.sizeof);

int adbg_object_mscoff_load(adbg_object_t *o) {
	o.internal = calloc(1, internal_mscoff_t.sizeof);
	if (o.internal == null)
		return adbg_oops(AdbgError.crt);
	if (adbg_object_read_at(o, 0, o.internal, MAX2))
		return adbg_errno();
	
	adbg_object_postload(o, AdbgObject.mscoff, &adbg_object_mscoff_unload);
	
	// TODO: Support swapping
	
	return 0;
}
void adbg_object_mscoff_unload(adbg_object_t *o) {
	if (o == null) return;
	if (o.internal == null) return;
	free(o.internal);
}

uint adbg_object_mscoff_version(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return -1;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return -1;
	}
	internal_mscoff_t *internal = cast(internal_mscoff_t*)o.internal;
	return internal.anon_header.Version;
}

void* adbg_object_mscoff_header(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	return o.internal;
}
