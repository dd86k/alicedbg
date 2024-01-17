/// Windows Program Database (PDB), Portable PDB (.NET), and Mono Database (MDB).
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.v2.object.format.pdb;

import adbg.error;
import adbg.v2.object.server;
import adbg.utils.uid;
import adbg.utils.bit;

// Sources:
// - https://llvm.org/docs/PDB/MsfFile.html
// - https://github.com/microsoft/microsoft-pdb
// - https://github.com/ziglang/zig/blob/master/lib/std/pdb.zig
// - https://github.com/MolecularMatters/raw_pdb

//
// Windows PDB
//

/// 
enum PDB_DEFAULT_PAGESIZE = 0x400;

immutable string PDB20_MAGIC = "Microsoft C/C++ program database 2.00\r\n\x1aJG\0\0";

// Speculation
struct pdb20_file_header {
	char[44] Magic;
	uint PageSize;	// Usually 0x400
}

int adbg_object_pdb20_load(adbg_object_t *o, size_t offset = 0) {
	
	//o.format = AdbgObject.pdb20;
	//o.p.debug_offset = offset;
	//
	//with (o.i.pdb20.header)
	//if (PageCount * PageSize != o.file_size)
	//	return adbg_oops(AdbgError.assertion);
	
	return adbg_oops(AdbgError.unimplemented);
}

pdb20_file_header* adbg_object_pdb20_header(adbg_object_t *o) {
	return o.i.pdb20.header;
}

//
// Microsoft PDB 7.0
//

// Structure:
// file header
// +- stream directory
//    +- count of streams
//    stream size (repeats n times)
//    +- size
//    stream offsets (dir size - ((num streams + 1) * 4))
//    +- page location
//       +- type?

/* LLDB: llvm/include/llvm/DebugInfo/PDB/Native/RawConstants.h
enum PdbRaw_ImplVer : uint32_t {
  PdbImplVC2 = 19941610,
  PdbImplVC4 = 19950623,
  PdbImplVC41 = 19950814,
  PdbImplVC50 = 19960307,
  PdbImplVC98 = 19970604,
  PdbImplVC70Dep = 19990604, // deprecated
  PdbImplVC70 = 20000404,
  PdbImplVC80 = 20030901,
  PdbImplVC110 = 20091201,
  PdbImplVC140 = 20140508,
};

enum PdbRaw_Features : uint32_t {
  PdbFeatureNone = 0x0,
  PdbFeatureContainsIdStream = 0x1,
  PdbFeatureMinimalDebugInfo = 0x2,
  PdbFeatureNoTypeMerging = 0x4,
};

enum PdbRaw_DbiVer : uint32_t {
  PdbDbiVC41 = 930803,
  PdbDbiV50 = 19960307,
  PdbDbiV60 = 19970606,
  PdbDbiV70 = 19990903,
  PdbDbiV110 = 20091201
};

enum PdbRaw_TpiVer : uint32_t {
  PdbTpiV40 = 19950410,
  PdbTpiV41 = 19951122,
  PdbTpiV50 = 19961031,
  PdbTpiV70 = 19990903,
  PdbTpiV80 = 20040203,
};

enum PdbRaw_DbiSecContribVer : uint32_t {
  DbiSecContribVer60 = 0xeffe0000 + 19970605,
  DbiSecContribV2 = 0xeffe0000 + 20140516
};
*/

immutable string PDB70_MAGIC = "Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";

enum {
	/// Pdb (header)
	PDB_STREAM_HEADER	= 1,
	/// Tpi (Type manager)
	PDB_STREAM_TPI	= 2,
	/// Dbi (Debug information)
	PDB_STREAM_DBI	= 3,
	/// NameMap
	PDB_STREAM_NAMEMAP	= 4,
}

// 
struct pdb70_file_header {
	char[32] Magic;
	uint PageSize;	// Usually 0x400
	uint FreeIndex;	// Index where block is free, only 1 or 2
	uint PageCount; // * PAGESIZE = Byte size
	uint DirectorySize;
	uint Unknown2;
	uint DirectoryOffset; // * PAGESIZE = Byte offset in file
}

struct pdb70_stream_header {
	uint Version;
	uint Signature;
	uint Age;
	UID UniqueId;
}

int adbg_object_pdb70_load(adbg_object_t *o, size_t offset = 0) {
	
	o.format = AdbgObject.pdb70;
	o.p.debug_offset = offset;
	
	with (o.i.pdb70.header)
	if (PageSize < 512 || // Cannot be lower than 512 bytes
		PageSize > 4096 || // Not observed to be higher than 4,096 bytes
		PageSize % 512 != 0 || // Must be a multiple of "sectors"
		PageCount * PageSize != o.file_size || // Must fit file length
		((FreeIndex == 1 || FreeIndex == 2) == false))
		return adbg_oops(AdbgError.assertion);
	
	return 0;
}

pdb70_file_header* adbg_object_pdb70_header(adbg_object_t *o) {
	return o.i.pdb70.header;
}

/+ubyte* adbg_object_pdb70_get_stream(adbg_object_t *o, int num) {
}+/

//
// Portable PDB and CILDB
//
// Introduced with .NET Core and used in .NET 5 and later
//

// Sources:
// - ECMA-335
// - https://github.com/dotnet/runtime/blob/main/docs/design/specs/PortablePdb-Metadata.md
// - https://github.com/mono/mono/blob/main/mono/metadata/debug-mono-ppdb.c

struct pdb_stream {
	char[20] id;
	uint EntryPoint;
	ulong ReferencedTypeSystemTables;
	uint *TypeSystemTableRows;
}

immutable string CILDB_MAGIC = "_ildb_signature\0";

private
immutable UID CILDB_GUID_V1 = UID(
	0x7F, 0x55, 0xE7, 0xF1, 0x3C, 0x42, 0x17, 0x41,
	0x8D, 0xA9, 0xC7, 0xA3, 0xCD, 0x98, 0x8D, 0xF1);

// Portable PDB header
struct cildb_file_header {
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