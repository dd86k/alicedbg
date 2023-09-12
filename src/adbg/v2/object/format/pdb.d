/// Windows Program Database (PDB), Portable PDB (.NET), and Mono Database (MDB).
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.v2.object.format.pdb;

import adbg.utils.uid;

//
// Windows PDB
//

// Based on speculations
struct pdb70_header {
	// "Microsoft C/C++ MSF 7.00\r\n"
	char[28] Magic;
}

//
// Portable PDB and CILDB
//
// Introduced with .NET Core and used in .NET 5 and later
//

// Sources:
// - ECMA-335
// - https://github.com/dotnet/runtime/blob/main/docs/design/specs/PortablePdb-Metadata.md
// - https://github.com/mono/mono/blob/main/mono/metadata/debug-mono-ppdb.c

// 
struct MetadataRootHeader {
	/// Magic signature for physical metadata : 0x424A5342.
	// or "BSJB"
	char[4] Magic;
	/// Major version, 1 (ignore on read)
	ushort MajorVersion;
	/// Minor version, 1 (ignore on read)
	ushort MinorVersion;
	/// Reserved, always 0.
	uint Reserved;
	/// Length of version string, multi
	uint Length;
	/// UTF-8 "Version" string.
	// 4-Byte aligned, maximum 255 (?).
	// Values:
	// - "PDB v1.00" with a value of 12 (.NET 6)
	// - "Standard CLI 2002" (17 chars, so rounded to 20 chars)
	char[1] Version;
}
// After MetadataRootHeader + Version string
struct MetadataRootHeader_Flags {
	ushort Flags;
	ushort Streams;
}

struct MetadataRootStream {
	uint Offset;
	uint Size;
	char[1] Name;
}

struct pdb_stream {
	char[20] id;
	uint EntryPoint;
	ulong ReferencedTypeSystemTables;
	uint *TypeSystemTableRows;
}

private
immutable UID CILDB_GUID_V1 = UID(
	0x7F, 0x55, 0xE7, 0xF1, 0x3C, 0x42, 0x17, 0x41,
	0x8D, 0xA9, 0xC7, 0xA3, 0xCD, 0x98, 0x8D, 0xF1);

// Portable PDB header
struct cildb_header {
	// "_ildb_signature\0"
	char[16] Signature;
	// 0x7F 0x55 0xE7 0xF1 0x3C 0x42 0x17 0x41 
	// 0x8D 0xA9 0xC7 0xA3 0xCD 0x98 0x8D 0xF1
	UID GUID;
	uint UserEntryPoint;
	uint CountOfMethods;
	uint CountOfScopes;
	uint CountOfVars;
	uint CountOfUsing;
	uint CountOfConstants;
	uint CountOfDocuments;
	uint CountOfSequencePoints;
	uint CountOfMiscBytes;
	uint CountOfStringBytes;
}