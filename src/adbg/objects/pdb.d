/// Windows Program Database (PDB), Portable PDB (.NET), and Mono Database (MDB).
///
/// Supports Multi-Stream Format (MSF) Program Database (PDB) 7.0, known as the "Big MSF".
///
/// Sources:
/// - https://llvm.org/docs/PDB/MsfFile.html
/// - llvm/include/llvm/DebugInfo/PDB/
/// - llvm-pdbutil(1): llvm-pdbutil dump --summary PDBFILE
/// - https://github.com/microsoft/microsoft-pdb
/// - https://github.com/ziglang/zig/blob/master/lib/std/pdb.zig
/// - https://github.com/MolecularMatters/raw_pdb
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.objects.pdb;

import adbg.error;
import adbg.objectserver;
import adbg.utils.bit;
import adbg.utils.uid;
import adbg.utils.math;
import core.stdc.stdlib;
import core.stdc.string : memset;

extern (C):

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

struct pdb20_file_header_t {
	char[44] Magic;
	uint BlockSize;	// Usually 0x400, multiply with BlockCount to get filesize
	ushort StartPage;	// 
	ushort BlockCount;	// Number of file pages
	uint RootSize;	// Root stream size
	uint Reserved;
	ushort RootNumber;	// Root stream page number list
}

private
struct internal_pdb20_t {
	pdb20_file_header_t header;
}

int adbg_object_pdb20_load(adbg_object_t *o) {
	o.internal = calloc(1, internal_pdb20_t.sizeof);
	if (o.internal == null)
		return adbg_oops(AdbgError.crt);
	if (adbg_object_read_at(o, 0, o.internal, pdb20_file_header_t.sizeof)) {
		free(o.internal);
		return adbg_errno();
	}
	
	adbg_object_postload(o, AdbgObject.pdb20, &adbg_object_pdb20_unload);
	return 0;
}
void adbg_object_pdb20_unload(adbg_object_t *o) {
	if (o == null) return;
	if (o.internal == null) return;
	free(o.internal);
}

pdb20_file_header_t* adbg_object_pdb20_header(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	internal_pdb20_t *internal = cast(internal_pdb20_t*)o.internal;
	return &internal.header;
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
// # PDB 7.0 Structure
//
// 1. The very first block containing the file header, the Superblock, is read.
// 2. The FPM (for block index usage) is read. This is to see which blocks are used.
//    FPM offset: FPMIndex * BlockSize
//    The FPM is always one BlockSize of size.
// 3. The offset to the block directory is calculated.
//    This directory only contains information to load Stream 0.
//    Directory offset: DirectoryOffset * BlockSize
//    Directory block count: ceil(DirectorySize / BlockSize)
// 4. Load Stream 0 into memory.
//    Layout of Stream 0:
//    uint StreamCount;
//    uint[Count] StreamSize;
//    uint[Count * ceil(StreamSize / BlockSize)] StreamBlockIDs;
// 5. Now possible to load a stream using an index.
//    StreamSize[n]: Size of stream n in bytes.
//    StreamBlockIDs[n]: Holds a list of block IDs to load.
//
// Blocks
//  vvv
// +---+  -+
// |   |   +- B[0]: Superblock
// +---+  -+        Contains FPM index used, BlockSize, and directory page offset
// |   |   |
// +---+   +- B[1..2]: Two FPM blocks, acts as a huge array of bitfields
// |   |   |           1-bit/block: 0=unallocated/unused, 1=allocated/used
// +---+  -+
// |   |   |
// +---+   +- B[3..4095]: Data blocks (1 or more or any block)
// |   |   |              Stream 0 contains information to load streams
// +---+   |
// |   |   |
// +---+  -+
//  ...       If there are more than 4096 blocks:
// +---+  -+
// |   |   +- B[4096]: Data
// +---+  -+
// |   |   |
// +---+   +- B[4097..4098]: FPM blocks. Kept for compatibility
// |   |   |
// +---+  -+
// |   |   |
// +---+   +- B[4099..8191]: Data blocks (1 or more)
// |   |   |
// +---+  -+
//  ...
// +---+  -+
// |   |   |  Block directory and Stream 0 usually at the end.
// +---+   +- Header points to block directory.
// |   |   |  Block directory points to Stream 0.
// +---+  -+
//
// Block    Description
// 0        Contains PDB layout information. AKA SuperBlock
// 1-2      FPM tables
// last     Usually the directory for Stream 0
//
// Stream   Description
// 0        List of blocks to streams.
// 1 (PDB)  Holds basic PDB information
// 2 (TPI)  (CodeView) Type Indices (< 0x1600 record types) for types
// 3 (DBI)  Debug Information
// 4 (IPI)  (CodeView) Index Info? (>=0x1600 record types) for module/line?

/// "Big MSF" signature
immutable string PDB70_MAGIC = "Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";

// MSF container
struct pdb70_file_header_t {
	char[32] Magic;	/// Magic string
	uint BlockSize;	/// Usually 0x1000
	uint FreeIndex;	/// FPM index
	uint BlockCount;	/// Total block count. Multiply with BlockSize and you get filesize
	uint DirectorySize;	/// Size of block directory, in bytes
	uint Unknown;	/// Reserved
	/// Offset in blocks to directory. Multiply with BlockSize for true file offset.
	uint DirectoryOffset;
}

/// Represents a stream.
struct pdb70_stream_t {
	size_t size;
	void *data;
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
	/// IPI fixed stream 4
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
struct pdb70_pdb_header_t {
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

/// CodeView record header for Stream 2 (TPI) and Stream 4 (IPI)
struct pdb70_tpi_header_t {
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
struct pdb70_dbi_header_t {
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

/// Follows the DBI header, substream information.
///
/// One per module.
struct pdb70_dbi_modinfo_t { align(1):
	/// 
	uint Unused1;
	struct pdb70_dbi_mod_contrib_entry { align(1):
		ushort Section;
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
	/// Flags.
	// int16_t Dirty : 1;  // Likely due to incremental linking.
	// int16_t EC : 1;     // Edit & Continue
	// int16_t Unused : 6;
	// int16_t TSM : 8;    // Type Server Index for module.
	ushort Flags;
	/// Stream index to its symbols. -1 (0xffffffff) means no symbols.
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

enum {
	PDB_DBI_MOD_DIRTY = 1,
	PDB_DBI_MOD_EC = 2,
}

/// File information substream header.
///
/// One per file.
struct pdb70_dbi_fileinfo_t {
	ushort NumModules;
	ushort NumSourceFiles;
	//ushort[NumModules] ModIndices;
	//ushort[NumModules] ModFileCounts;
	//uint­[NumSourceFiles] FileNameOffsets;
	//char*[NumSourceFiles] NamesBuffer;
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

/// Used for TPI (2) and IPI (4) streams, after the header.
struct pdb70_subsection_header_t {
	PdbSubsectionKind Kind;
	uint Length;
}

struct pdb70_stringtable_header_t {
	uint Signature;
	uint HashVersion;
	uint ByteSize;
}

private
struct internal_pdb70_t {
	pdb70_file_header_t header; /// Superblock
	
	ubyte *fpm;	/// Points to used FPM block
	size_t fpmcnt;
	size_t fpmoffset;
	
	// Buffer for Stream 0
	void *stream0;	/// Buffer to hold Stream 0
	size_t stream0size;	/// Buffer size of Stream 0
	
	// Stream 0: Holds stream information
	uint stream_count;	/// Number of streams in PDB
	uint *stream_sizes;	/// Pointer to stream sizes in Stream 0
	uint **stream_blocks;	/// Allocated index buffer to 
}

int adbg_object_pdb70_load(adbg_object_t *o) {
	o.internal = calloc(1, internal_pdb70_t.sizeof);
	if (o.internal == null)
		return adbg_oops(AdbgError.crt);
	if (adbg_object_read_at(o, 0, o.internal, pdb70_file_header_t.sizeof)) {
		free(o.internal);
		return adbg_errno();
	}
	
	internal_pdb70_t *internal = cast(internal_pdb70_t*)o.internal;
	pdb70_file_header_t *header = &internal.header;
	
	// Check SuperBlock
	// header.BlockCount * header.BlockSize must be file length, but can't have that yet
	if (header.BlockSize < 512 || header.BlockSize > 4096 || // Not observed to be higher than 4,096 bytes
		header.BlockSize % 512 != 0 || // Multiple of "sector"
		header.Unknown || // This must be empty
		header.FreeIndex < 1 || header.FreeIndex > 2) { // 1 or 2 only
		free(o.internal);
		return adbg_oops(AdbgError.objectMalformed);
	}
	
	// NOTE: This loads the first (current) FPM. Other FPMs may be loaded later.
	// Load FPM, being the block after the superblock
	internal.fpmoffset = header.FreeIndex * header.BlockSize;
	version (Trace) trace("fpm offset=%zu", internal.fpmoffset);
	internal.fpm = cast(ubyte*)malloc(header.BlockSize);
	internal.fpmcnt = header.BlockCount / 8; // Assuming
	if (internal.fpm == null) {
		free(o.internal);
		return adbg_oops(AdbgError.crt);
	}
	if (adbg_object_read_at(o, internal.fpmoffset, internal.fpm, header.BlockSize)) {
		free(internal.fpm);
		free(o.internal);
		return adbg_errno();
	}
	
	// Load block directory, we'll need this to load Stream 0
	
	// Get number of offsets for Stream 0.
	uint dircount = ceildiv32(header.DirectorySize, header.BlockSize);
	version (Trace) trace("dircount=%u", dircount);
	
	// Big directory stream check
	// If the number of offsets for Stream 0 is beyond the number of offsets
	// allowed in the directory block, it is a "big" directory stream, which
	// we don't support yet.
	if (dircount > header.BlockSize / uint.sizeof) {
		free(internal.fpm);
		free(o.internal);
		return adbg_oops(AdbgError.objectUnsupportedFormat);
	}
	
	// block id ptr = Superblock::DirectoryOffset * ::BlockSize
	size_t diroffset = header.DirectoryOffset * header.BlockSize;
	// Directory size
	// Do note that most cases, the indices for Stream 0 fit one block.
	// NumberOfEntries = ceil(DirSize / BlockSize)
	// EffectiveSize = NumberOfEntries * 4
	size_t dirsize = dircount * uint.sizeof;
	version (Trace) trace("dir offset=%u size=%u effective=%zu",
		header.DirectoryOffset, header.DirectorySize, diroffset);
	
	// Allocate and read block directory
	void *dir = adbg_object_readalloc_at(o, diroffset, dirsize);
	if (dir == null) {
		free(internal.fpm);
		free(o.internal);
		return adbg_errno();
	}
	scope(exit) free(dir); // Since it is a temp buffer
	
	// Load Stream 0
	
	// From the main directory, get stream 0
	uint *s0blocks = cast(uint*)dir;
	
	// Allocate buffer for Stream 0
	internal.stream0size = header.DirectorySize;
	internal.stream0 = malloc(header.DirectorySize);
	if (internal.stream0 == null) {
		free(internal.fpm);
		free(o.internal);
		return adbg_oops(AdbgError.crt);
	}
	
	// Read every block into Stream 0 buffer
	size_t o0; // Offset to stream 0 so far
	for (uint i; i < dircount; ++i) {
		long blkoffset = s0blocks[i] * header.BlockSize;
		
		// Last read
		bool last = o0 + header.BlockSize >= header.DirectorySize;
		size_t rdsize = last ? header.DirectorySize - o0 : header.BlockSize;
		
		if (adbg_object_read_at(o, blkoffset, internal.stream0 + o0, rdsize)) {
			free(internal.fpm);
			free(o.internal);
			return adbg_errno();
		}
		
		if (last) break;
		
		o0 += header.BlockSize;
	}
	
	// Setup Stream 0 data: Sizes and block IDs
	uint *s0 = cast(uint*)internal.stream0;
	internal.stream_count  = *s0;
	internal.stream_sizes  = s0 + 1;
	uint *blocks = s0 + 1 + internal.stream_count;
	version (Trace) trace("stream_count=%u", internal.stream_count);
	with (internal)
	if (adbg_bits_boundchk(blocks, stream_count * uint.sizeof, stream0, stream0size)) {
		free(internal.fpm);
		free(internal.stream0);
		free(o.internal);
		return adbg_oops(AdbgError.offsetBounds);
	}
	
	// To avoid cycling through stream block IDs when loading streams,
	// we have to remap them as they don't linearly align with stream indexes,
	// unlike stream_sizes:
	// Stream: |-1-| |-2-| |----3----| |-------4-------| ...
	// Blocks:     1     2     3     4     5     6     7 ...
	internal.stream_blocks = cast(uint**)malloc(size_t.sizeof * internal.stream_count);
	if (internal.stream_blocks == null) {
		free(internal.fpm);
		free(internal.stream0);
		free(o.internal);
		return adbg_oops(AdbgError.crt);
	}
	for (uint b; b < internal.stream_count; ++b) {
		// Size of stream in bytes
		uint ssz = internal.stream_sizes[b];
		// Block count
		uint bcnt = ceildiv32(ssz, header.BlockSize);
		// Assign blocks pointer
		internal.stream_blocks[b] = blocks;
		// Next set of blocks
		blocks += bcnt;
	}
	
	adbg_object_postload(o, AdbgObject.pdb70, &adbg_object_pdb70_unload);
	return 0;
}

void adbg_object_pdb70_unload(adbg_object_t *o) {
	if (o == null) return;
	if (o.internal == null) return;
	
	internal_pdb70_t *internal = cast(internal_pdb70_t*)o.internal;
	
	if (internal.fpm) free(internal.fpm);
	if (internal.stream0) free(internal.stream0);
	
	free(o.internal);
}

// Return PDB 7.0 file header
pdb70_file_header_t* adbg_object_pdb70_header(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	internal_pdb70_t *internal = cast(internal_pdb70_t*)o.internal;
	return &internal.header;
}

// Get FPM table
ubyte* adbg_object_pdb70_fpm(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	internal_pdb70_t *internal = cast(internal_pdb70_t*)o.internal;
	return internal.fpm;
}
// Get FPM entries in bytes
size_t adbg_object_pdb70_fpmcount(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return 0;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return 0;
	}
	internal_pdb70_t *internal = cast(internal_pdb70_t*)o.internal;
	return internal.fpmcnt;
}

// Total count of streams
uint adbg_object_pdb70_total_count(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return 0;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return 0;
	}
	internal_pdb70_t *internal = cast(internal_pdb70_t*)o.internal;
	return internal.stream_count;
}
// Return the Stream size in bytes
//TODO: Could be a uint*
uint adbg_object_pdb70_stream_size(adbg_object_t *o, size_t i) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return 0;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return 0;
	}
	internal_pdb70_t *internal = cast(internal_pdb70_t*)o.internal;
	if (i >= internal.stream_count) {
		adbg_oops(AdbgError.indexBounds);
		return 0;
	}
	return internal.stream_sizes[i];
}
// Return the Stream number of blocks used
//TODO: Could be a uint*
uint adbg_object_pdb70_stream_block_count(adbg_object_t *o, size_t i) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return 0;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return 0;
	}
	internal_pdb70_t *internal = cast(internal_pdb70_t*)o.internal;
	if (i >= internal.stream_count) {
		adbg_oops(AdbgError.indexBounds);
		return 0;
	}
	// ceil(StreamSize / BlockSize) -> Number of Blocks used
	with (internal.header) return ceildiv32(internal.stream_sizes[i], BlockSize);
}
// Return array of blocks for Stream
uint* adbg_object_pdb70_stream_blocks(adbg_object_t *o, size_t i) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	internal_pdb70_t *internal = cast(internal_pdb70_t*)o.internal;
	if (i >= internal.stream_count) {
		adbg_oops(AdbgError.indexBounds);
		return null;
	}
	return internal.stream_blocks[ i ];
}

/// Get the status of a block.
/// Params:
/// 	o = Object instance.
/// 	id = Block ID.
/// Returns: True if block is either unallocated or unused.
private
bool adbg_object_pdb70_is_block_free(adbg_object_t *o, uint id) {
	internal_pdb70_t *internal = cast(internal_pdb70_t*)o.internal;
	
	uint bi = id >> 3; // block byte index (id / 8)
	uint br = 7 - (id % 8); // block reminder shift
	return (internal.fpm[bi] & (1 << br)) != 0; // set=free
}

// Open by stream number id
pdb70_stream_t* adbg_object_pdb70_stream_open(adbg_object_t *o, uint num) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	
	version (Trace) trace("stream index=%u", num);
	
	internal_pdb70_t *internal = cast(internal_pdb70_t*)o.internal;
	
	if (num >= internal.stream_count) {
		adbg_oops(AdbgError.indexBounds);
		return null;
	}
	
	uint streamsize = internal.stream_sizes[num];
	version (Trace) trace("stream size=%u", streamsize);
	if (streamsize == 0 || streamsize == PDB_BLOCK_SIZE_UNUSED) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	uint BlockSize = internal.header.BlockSize;
	
	// Get number of blocks
	size_t blockcount = ceildiv32(streamsize, BlockSize);
	//
	size_t size = blockcount * BlockSize;
	
	void *buffer = malloc(pdb70_stream_t.sizeof + size);
	if (buffer == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	pdb70_stream_t *stream = cast(pdb70_stream_t*)buffer;
	stream.size = streamsize;
	stream.data = buffer + pdb70_stream_t.sizeof;
	
	// Copy blocks into stream buffer
	uint *blocks = internal.stream_blocks[num];
	size_t of;
	for (size_t bidx; bidx < blockcount; ++bidx, of += BlockSize) {
		// If block is unallocated/free, then there is no need to
		// perform I/O.
		if (adbg_object_pdb70_is_block_free(o, blocks[bidx])) {
			memset(stream.data + of, 0, BlockSize);
			continue;
		}
		
		// Read block into stream data.
		long boffset = blocks[bidx] * BlockSize;
		if (adbg_object_read_at(o, boffset, stream.data + of, BlockSize)) {
			free(buffer);
			return null;
		}
	}
	
	return stream;
}
void adbg_object_pdb70_stream_close(pdb70_stream_t *stream) {
	if (stream) free(stream);
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

/*
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
*/
