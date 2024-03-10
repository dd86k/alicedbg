/// MS-COFF format.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.object.format.mscoff;

import adbg.utils.uid;

//
// Non-COFF Object file headers (.obj from VS2002-VS2015, mscoff)
//

// NOTE: Version
//       0 -> Import
//       1 -> Anonymous
//       2 -> Anonymous V2

/*
typedef enum IMPORT_OBJECT_TYPE
{
    IMPORT_OBJECT_CODE = 0,
    IMPORT_OBJECT_DATA = 1,
    IMPORT_OBJECT_CONST = 2,
} IMPORT_OBJECT_TYPE;

typedef enum IMPORT_OBJECT_NAME_TYPE
{
    IMPORT_OBJECT_ORDINAL = 0,          // Import by ordinal
    IMPORT_OBJECT_NAME = 1,             // Import name == public symbol name.
    IMPORT_OBJECT_NAME_NO_PREFIX = 2,   // Import name == public symbol name skipping leading ?, @, or optionally _.
    IMPORT_OBJECT_NAME_UNDECORATE = 3,  // Import name == public symbol name skipping leading ?, @, or optionally _
                                        //  and truncating at first @.
    IMPORT_OBJECT_NAME_EXPORTAS = 4,    // Import name == a name is explicitly provided after the DLL name.
} IMPORT_OBJECT_NAME_TYPE;
*/

struct mscoff_import_header { // IMPORT_OBJECT_HEADER
	/// Must be IMAGE_FILE_MACHINE_UNKNOWN.
	ushort Sig1;
	/// Must be 0xFFFF.
	ushort Sig2;
	ushort Version;
	ushort Machine;
	uint TimeStamp;
	uint Size;
	ushort Ordinal; // or Hint
	// Type : 2 -> IMPORT_TYPE
	// NameType : 3 -> IMPORT_NAME_TYPE
	// Reserved : 11
	ulong Flags;
}

struct mscoff_anon_header { // ANON_OBJECT_HEADER
	ushort Sig1;            // Must be IMAGE_FILE_MACHINE_UNKNOWN
	ushort Sig2;            // Must be 0xffff
	ushort Version;         // >= 1 (implies the CLSID field is present)
	ushort Machine;
	uint   TimeDateStamp;
	/*CLSID*/ UID   ClassID;         // Used to invoke CoCreateInstance
	uint   SizeOfData;      // Size of data that follows the header
}

struct mscoff_anon_header_v2 { // ANON_OBJECT_HEADER_V2
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

struct mscoff_anon_header_bigobj { // ANON_OBJECT_HEADER_BIGOBJ
	/* same as ANON_OBJECT_HEADER_V2 */
	ushort Sig1;            // Must be IMAGE_FILE_MACHINE_UNKNOWN
	ushort Sig2;            // Must be 0xffff
	ushort Version;         // >= 2 (implies the Flags field is present)
	ushort Machine;         // Actual machine - IMAGE_FILE_MACHINE_xxx
	uint   TimeDateStamp;
	/* CLSID */ UID   ClassID;         // {D1BAA1C7-BAEE-4ba9-AF20-FAF66AA4DCB8}
	uint   SizeOfData;      // Size of data that follows the header
	uint   Flags;           // 0x1 -> contains metadata
	uint   MetaDataSize;    // Size of CLR metadata
	uint   MetaDataOffset;  // Offset of CLR metadata

	/* bigobj specifics */
	uint   NumberOfSections; // extended from WORD
	uint   PointerToSymbolTable;
	uint   NumberOfSymbols;
}
