/// Windows Program Database (PDB), Portable PDB (.NET), and Mono Database (MDB).
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.object.format.pdb;

import adbg.error;
import adbg.object.server;
import adbg.utils.uid;
import adbg.utils.bit;
import core.stdc.stdlib : malloc, free;
import core.stdc.string : memcpy;

// Sources:
// - https://llvm.org/docs/PDB/MsfFile.html
// - llvm/include/llvm/DebugInfo/PDB/ and llvm-pdbutil(1)
//   llvm-pdbutil dump --summary PDBFILE
// - https://github.com/microsoft/microsoft-pdb
// - https://github.com/ziglang/zig/blob/master/lib/std/pdb.zig
// - https://github.com/MolecularMatters/raw_pdb

//TODO: Find better memory management strategies
//      Since the PDB file is loaded entirely in memory (by us),
//      instead of allocating memory and copying blocks,
//      it could make sense to move blocks and modify the indexes,
//      but would require a *lot* of maintenance...

/// Default (smallest?) size of a PDB 2.0 and 7.0 page.
enum PDB_DEFAULT_PAGESIZE = 0x400;

//
// Microsoft PDB 2.0
//
// Similar to PDB 7.0, but the root stream contains:
// - ushort streamCount
// - ushort reserved
// - { uint Size; uint Reserved }[StreamCount] stream1;
// - ushort[StreamCount] pageNumber;

immutable string PDB20_MAGIC = "Microsoft C/C++ program database 2.00\r\n\x1aJG\0\0";

struct pdb20_file_header {
	char[44] Magic;
	uint PageSize;	// Usually 0x400
	ushort StartPage;	// 
	ushort PageCount;	// Number of file pages
	uint RootSize;	// Root stream size
	uint Reserved;
	ushort RootNumber;	// Root stream page number list
}

int adbg_object_pdb20_load(adbg_object_t *o) {
	o.format = AdbgObject.pdb20;
	//o.p.debug_offset = offset;
	//
	//with (o.i.pdb20.header)
	//if (PageCount * PageSize != o.file_size)
	//	return adbg_oops(AdbgError.assertion);
	
	return 0;
}

pdb20_file_header* adbg_object_pdb20_header(adbg_object_t *o) {
	return o.i.pdb20.header;
}

//
// Microsoft PDB 7.0
//
// # Glossary
//
// Block
// 	Building blocks (also known as pages). The size of the block is given
// 	by the Superblock (the very first block of the file).
//
// Stream
// 	A Stream is contained in multiple blocks.
//
// # Structure
//
// 1. The Superblock is read, going to block directory
//    Directory offset: DirectoryOffset * PageSize
//    Directory block count: ceil(DirectorySize / PageSize)
//    Selects FPM by index
// 2. Directory blocks are read (by n count), giving Stream 0
// 3. Stream 0 entries contains n count of streams, their sizes, and offsets
//
//        Blocks
//         vvv
// 1      +---+ -+
// +----- |   |  +- B[0]: Superblock
// |      +---+ -+        Contains FPM index used, BlockSize, and directory offset (by page)
// |      |   |  |
// |      +---+  +- B[1..2]: Two FPM blocks, acts as a huge array of bitfields
// |      |   |  |           1-bit/block: 0=unallocated/unused, 1=allocated/used
// | 2    +---+ -+
// | +--> |   |  |
// | | 3  +---+  +- B[3..4095]: Data blocks (1 or more or any block)
// | | +- |   |  |              Stream 0 will redirect to other streams
// | | |  +---+  |
// | | +> |   |  |
// | |    +---+ -+
// | |    ...       If there are more than 4096 blocks:
// | |    +---+ -+
// | |    |   |  +- B[4096]: Data
// | |    +---+ -+
// | |    |   |  |
// | |    +---+  +- B[4097..4098]: FPM blocks. Kept for compatibility
// | |    |   |  |
// | |    +---+ -+
// | |    |   |  |
// | |    +---+  +- B[4099..8191]: Data blocks (1 or more)
// | |    |   |  |
// | |    +---+ -+
// | |    ...
// | |    +---+ -+- Block directory, usually at the end
// | +--- |   |  |  Contains block IDs pointing to Stream 0:
// |      +---+  +  - uint streamcount;
// +----> |   |  |  - uint[streamcount] sizes; (by stream)
//        +---+ -+  - uint[streamcount] offsets;
//

immutable string PDB70_MAGIC = "Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";

// MSF container
struct pdb70_file_header {
	char[32] Magic;	/// Magic string
	uint PageSize;	/// Usually 0x1000
	uint FreeIndex;	/// FPM index
	uint PageCount;	/// Block count * PAGESIZE = Byte size
	uint DirectorySize;	/// Size of block directory
	uint Unknown;	/// Reserved
	uint DirectoryOffset; /// Offset (in block) * PAGESIZE = Byte offset in file
}

/// Meta structure used internally
struct pdb70_stream {
	/// Number of blocks stream occupies
	uint count;
	/// Points to stream's first block from directory (Stream 0)
	uint *blocks;
}

/// Fixed streams
enum PdbStream : uint {
	/// PDB fixed stream 1
	///
	/// Contains: Basic file information, named streams
	pdb	= 1,
	/// TPI fixed stream 2
	///
	/// Contains: CodeView type records, TPI hash stream
	tpi	= 2,
	/// DBI fixed stream 3
	///
	/// Contains: Module info and streams, section contribs, source, FPO/PGO
	dbi	= 3,
	/// PIP fixed stream 4
	///
	/// Contains: CodeView type records, index of ipi hash stream
	ipi	= 4,
}

enum : uint {
	/// Unallocated block size.
	PDB_BLOCK_SIZE_UNUSED	= 0xffff_ffff,
}

//
// Stream 1 (PDB) structures
//

/// Stream 1 PDB header::version
enum PdbRaw_PdbVersion : uint { // PdbRaw_ImplVer
	vc2	= 19941610,
	vc4	= 19950623,
	vc41	= 19950814,
	vc50	= 19960307,
	vc98	= 19970604,
	vc70_old	= 19990604, // deprecated
	vc70	= 20000404,
	vc80	= 20030901,
	vc110	= 20091201,
	vc140	= 20140508,
}

/// Stream 1 PDB feature codes (after named stream map)
enum PdbRaw_PdbFeatures : uint {
	none = 0x0,
	containsIdStream = 0x1,
	minimalDebugInfo = 0x2,
	noTypeMerging = 0x4,
}

/// Stream 1 structure
struct pdb70_pdb_header {
	/// Contains VC version
	uint Version;
	/// Timestamp (Using time(3))
	uint Signature;
	/// Incremental number
	uint Age;
	/// Unique GUID, used to match PDB and EXE
	UID UniqueId;
}

//
// Stream 2 (TPI) structures
//

/// Stream 2 TPI
enum PdbRaw_TpiVer : uint {
	v40 = 19950410,
	v41 = 19951122,
	v50 = 19961031,
	v70 = 19990903,
	v80 = 20040203,
}

/// Stream 2 TPI header
struct pdb70_tpi_header {
	/// Maps to PdbRaw_TpiVer, usually v80.
	uint Version;
	/// Usually size of this header.
	uint HeaderSize;
	/// First index of first type record.
	///
	/// Usually 0x1000 (page size?), since lower is reserved.
	uint TypeIndexBegin;
	/// Last index for the last type record.
	///
	/// To get total count: TypeIndexEnd - TypeIndexBegin.
	uint TypeIndexEnd;
	/// Size of type record data following header.
	uint TypeRecordBytes;
	
	/// Index of a stream containing list of hashes for every
	/// type record.
	///
	/// If -1 (0xffff), unused.
	ushort HashStreamIndex;
	/// 
	ushort HashAuxStreamIndex;
	/// Size of a hash, usually 4 (bytes).
	uint HashKeySize;
	/// 
	uint NumHashBuckets;
	
	int HashValueBufferOffset;
	// Malformed: HashBufferLength != (TypeIndexEnd - TypeEndBegin) * HashKeySize
	uint HashValueBufferLength;
	
	int IndexOffsetBufferOffset;
	uint IndexOffsetBufferLength;
	
	int HashAdjBufferOffset;
	uint HashAdjBufferLength;
}


//
// Stream 3 (DBI)
//

// Stream 3 DBI header::version
enum PdbRaw_DbiVer : uint {
	v41	= 930803,
	v50	= 19960307,
	v60	= 19970606,
	v70	= 19990903,
	v110	= 20091201,
}

// Stream DBI
enum PdbRaw_DbiSecContribVer : uint {
	ver60 = 0xeffe0000 + 19970605,
	v2 = 0xeffe0000 + 20140516
}

// 
enum PdbRaw_DbiFlags : ushort {
	IncrementallyLinked	= 1,	/// WasIncrementallyLinked
	PrivateSymbolsStripped	= 2,	/// ArePrivateSymbolsStripped
	ConflictingTypes	= 4,	/// HasConflictingTypes
}

/// Stream 3 DBI header
struct pdb70_dbi_header {
	/// Seems to be always -1.
	int VersonSignature;
	/// Maps to PdbRaw_DbiVersion.
	uint VersionHeader;
	/// Incremental age.
	uint Age;
	/// Global Symbol Stream index;
	ushort GlobalStreamIndex;
	/// Toolchain version.
	///
	/// bits 15-8: MinorVersion
	/// bits 7-1: MajorVersion
	/// bits 0: NewVersionFormat, assume to be set, or consult source.
	ushort BuildNumber;
	/// Public Symbol Stream index.
	ushort PublicStreamIndex;
	/// Version for mspdbXXXX.dll.
	ushort PdbDllVersion;
	/// Deduplication stream containing CodeView symbols.
	ushort SymRecordStream;
	/// 
	ushort PdbDllRbld;
	
	// Substream info
	
	/// The length of the Module Info Substream. (Substream 1)
	int ModInfoSize;
	/// The length of the Section Contribution Substream. (Substream 2)
	int SectionContributionSize;
	/// The length of the Section Map Substream. (Substream 3)
	int SectionMapSize;
	/// The length of the File Info Substream. (Substream 4)
	int SourceInfoSize;
	/// The length of the Type Server Map Substream. (Substream 5)
	int TypeServerMapSize;
	/// MFC type server in Type Server Map Substream.
	uint MFCTypeServerIndex;
	/// The length of the Optional Debug Header Stream. (Substream 6)
	int OptionalDbgHeaderSize;
	/// The length of the EC Substream. (Substream 7)
	int ECSubstreamSize;
	
	/// Program information bit field.
	///
	/// uint16_t WasIncrementallyLinked : 1;
	/// uint16_t ArePrivateSymbolsStripped : 1;
	/// uint16_t HasConflictingTypes : 1;
	/// uint16_t Reserved : 13;
	ushort Flags;
	/// A PE32 Machine value. from the CV_CPU_TYPE_e enumeration.
	///
	/// LLVM says "A value from the CV_CPU_TYPE_e enumeration.
	/// Common values are 0x8664 (x86-64) and 0x14C (x86).", but these are
	/// PE32 Machine values.
	ushort Machine;
	/// ?
	uint Padding;
}

/// Follows the DBI header, substream information
struct pdb70_dbi_modinfo {
	/// 
	uint Unused1;
	struct pdb70_dbi_mod_contrib_entry {
		uint Section;
		char[2] Padding1;
		int Offset;
		int Size;
		uint Characteristics;
		ushort ModuleIndex;
		char[2] Padding2;
		uint DataCrc;
		uint RelocCrc;
	}
	/// Matches Characteristics from IMAGE_SECTION_HEADER
	pdb70_dbi_mod_contrib_entry SectionContr;
	// int16_t Dirty : 1;  // Likely due to incremental linking.
	// int16_t EC : 1;     // Edit & Continue
	// int16_t Unused : 6;
	// int16_t TSM : 8;    // Type Server Index for module.
	/// Flags.
	ushort Flags;
	ushort ModuleSysStream;
	uint SymByteSize;
	uint C11ByteSize;
	uint C13ByteSize;
	ushort SourceFileCount;
	char[2] Padding;
	uint Unused2;
	uint SourceFileNameIndex;
	uint PdbFilePathNameIndex;
	// char[] ModuleName
	// char[] ObjFileName
}

//
// Stream 4 (IPI)
//

enum PdbSubsectionKind : uint {
	none	= 0,
	symbols	= 0xf1,
	lines	= 0xf2,
	stringTable	= 0xf3,
	fileChecksums	= 0xf4,
	frameData	= 0xf5,
	inlineeLines	= 0xf6,
	crossScopeImports	= 0xf7,
	crossScopeExports	= 0xf8,

	// Related to .NET
	illines	= 0xf9,	// CIL lines
	funcMDTokenMap	= 0xfa,
	typeMDTokenMap	= 0xfb,
	mergedAssemblyInput	= 0xfc,

	coffSymbolRVA	= 0xfd,
}

struct pdb70_subsection_header {
	PdbSubsectionKind Kind;
	uint Length;
}

struct pdb70_stringtable_header {
	uint Signature;
	uint HashVersion;
	uint ByteSize;
}

int adbg_object_pdb70_load(adbg_object_t *o, size_t offset = 0) {
	
	o.format = AdbgObject.pdb70;
	o.p.debug_offset = offset;
	
	with (o.i.pdb70) {
	
	// Check SuperBlock
	if (header.PageSize < 512 || // Cannot be lower than 512 bytes
		header.PageSize > 4096 || // Not observed to be higher than 4,096 bytes
		header.PageSize % 512 != 0 || // Must be a multiple of "sectors"
		header.PageCount * header.PageSize != o.file_size || // Must fit file length
		header.Unknown || // Must be empty (for now)
		((header.FreeIndex == 1 || header.FreeIndex == 2) == false)) // Can only be block 1 or 2
		return adbg_oops(AdbgError.assertion);
	
	// Cache FPM pointer
	with (o.i.pdb70)
	if (adbg_object_offsetl(o, cast(void**)&fpm,
		header.FreeIndex * header.PageSize, header.PageSize))
		return adbg_oops(AdbgError.assertion);
	
	//
	// Load Stream 0 into memory
	//
	
	// block count used by block directory = ceil(DirectorySize / PageSize)
	uint dircnt = (header.DirectorySize + header.PageSize - 1) / header.PageSize;
	// block id ptr = Superblock::DirectoryOffset * ::PageSize
	uint diroff = header.DirectoryOffset * header.PageSize;
	
	version (Trace) trace("dircnt=%u diroff=%u", dircnt, diroff);
	
	//TODO: dircnt > PageSize / uint.sizeof -> Unhandled BigDirectoryStream
	
	// Allocate buffer for block directory
	// DirectorySize is smaller but makes it harder to copy blocks
	dir = cast(uint*)malloc(dircnt * header.PageSize);
	if (dir == null)
		return adbg_oops(AdbgError.crt);
	
	// 
	uint *dirblk = void;
	if (adbg_object_offsetl(o, cast(void**)&dirblk, diroff, header.PageSize)) {
		free(dir);
		return adbg_oops(AdbgError.assertion);
	}
	
	// Load stream directory blocks into the memory buffer
	for (uint dirblkidx; dirblkidx < dircnt; ++dirblkidx) {
		version (Trace) trace("dirblk[%u]=%u", dirblkidx, dirblk[dirblkidx]);
		uint blockoff = dirblk[dirblkidx] * header.PageSize;
		void *block = void;
		if (adbg_object_offsetl(o, &block, blockoff, header.PageSize)) {
			free(dir);
			return adbg_oops(AdbgError.assertion);
		}
		
		memcpy(dir + (dirblkidx * header.PageSize), block, header.PageSize);
	}
	
	// Setup stream directory information
	uint *direntry = cast(uint*)dir;
	strcnt  = *direntry;
	strsize = direntry + 1;
	stroff  = direntry + 1 + strcnt;
	
	//
	// Map stream information (count and IDs)
	// This helps to avoid recalculating the block offsets everytime
	//
	
	// Allocate buffer for the stream map
	strmap = cast(pdb70_stream*)malloc(strcnt * pdb70_stream.sizeof);
	if (strmap == null) {
		free(dir);
		return adbg_oops(AdbgError.crt);
	}
	// Map stream block IDs to memory buffer
	uint *blkcur = stroff;
	for (uint stri; stri < strcnt; ++stri) {
		pdb70_stream *stream = &strmap[stri];
		
		uint size = strsize[stri];
		if (size == 0 || size == 0xffff_ffff) {
			stream.count = 0;
			continue;
		}
		
		// Block count for stream
		stream.count  = (size + header.PageSize - 1) / header.PageSize;
		stream.blocks = blkcur;
		
		version (Trace)
			trace("stream[%u] count=%u blk0=%u",
			stri, stream.count, *stream.blocks);
		
		blkcur += stream.count;
	}
	
	} // with (o.i.pdb70)
	
	return 0;
}

pdb70_file_header* adbg_object_pdb70_header(adbg_object_t *o) {
	return o.i.pdb70.header;
}

// true=unallocated
bool adbg_object_pdb70_block_free(adbg_object_t *o, uint num) {
	if (o == null)
		return true;
	
	uint bi = num / 8; // block byte index
	uint br = 7 - (num % 8); // block reminder shift
	bool free = (o.i.pdb70.fpm[bi] & 1 << br) == 0;
	return free == 0;
}

ubyte* adbg_object_pdb70_get_block(adbg_object_t *o, uint num) {
	if (o == null)
		return null;
	
	pdb70_file_header *header = o.i.pdb70.header;
	
	// Check with selected FPM if block is allocated
	if (adbg_object_pdb70_block_free(o, num))
		return null;
	
	// Get block
	ubyte *block = void;
	if (adbg_object_offsetl(o, cast(void**)&block,
		num * header.PageSize, header.PageSize))
		return null;
	
	return block;
}

int adbg_object_pdb70_stream_open(adbg_object_t *o, void **ubuffer, uint *usize, uint num) {
	if (o == null || ubuffer == null || usize == null)
		return adbg_oops(AdbgError.invalidArgument);
	if (num >= o.i.pdb70.strcnt)
		return adbg_oops(AdbgError.assertion);
	
	// Get stream size and availability
	uint ssize = *usize = o.i.pdb70.strsize[num];
	version (Trace) trace("stream size=%u", ssize);
	if (ssize == 0 || ssize == PDB_BLOCK_SIZE_UNUSED) {
		*ubuffer = null;
		return 0;
	}
	
	// Allocate buffer
	void *sbuffer = *ubuffer = malloc(ssize);
	if (sbuffer == null)
		return adbg_oops(AdbgError.crt);
	
	// Read blocks into buffer
	pdb70_stream *stream = &o.i.pdb70.strmap[num];
	uint pagesize = o.i.pdb70.header.PageSize;
	uint offset; // read count
	uint readsz = pagesize;
	version (Trace) trace("stream counts %u blocks", stream.count);
	for (uint blki; blki < stream.count; ++blki) {
		version (Trace) trace("stream block[%u]=%u", blki, stream.blocks[blki]);
		
		//TODO: Check if block is allocated !!!
		uint fileoff = stream.blocks[blki] * pagesize;
		void *block = void;
		if (adbg_object_offsetl(o, &block, fileoff, readsz)) {
			free(sbuffer);
			*ubuffer = null;
			return adbg_oops(AdbgError.assertion);
		}
		
		// Adjust read size on last block
		if (offset + readsz > ssize) readsz = ssize - offset;
		
		version (Trace) trace("offset=%p", sbuffer);
		memcpy(sbuffer + offset, block, readsz);
		
		offset += readsz;
	}
	
	return 0;
}
void adbg_object_pdb70_stream_close(adbg_object_t *o, void **ubuffer) {
	if (o == null || ubuffer == null)
		return;
	
	if (*ubuffer) {
		free(*ubuffer);
	}
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