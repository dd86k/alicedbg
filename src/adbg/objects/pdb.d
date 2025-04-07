/// Manage Program Databases (PDB).
///
/// Supported: Program Database 2.0 and "Big Multi-Stream Format" 7.0 (PDB).
/// Unsupported: Portable PDB (.NET), Mono Database (MDB), Fastlink (VS2017).
///
/// A PDB file is made up of a series of blocks (also known as pages). These
/// blocks contain parts of streams, spread throughout the file.
///
/// Typically, PDB 2.0 will have public symbols in Stream 7 and
/// PDB 7.0 will have public symbols in Stream 2 and 4.
///
/// Sources:
/// - https://llvm.org/docs/PDB/MsfFile.html
/// - llvm/include/llvm/DebugInfo/PDB/ and llvm-pdbutil(1) (llvm-pdbutil dump --summary FILE)
/// - https://github.com/microsoft/microsoft-pdb
/// - https://github.com/ziglang/zig/blob/master/lib/std/pdb.zig
/// - https://github.com/MolecularMatters/raw_pdb
/// - https://devblogs.microsoft.com/cppblog/faster-c-build-cycle-in-vs-15-with-debugfastlink/
/// - https://web.archive.org/web/20250318100020/https://www.informit.com/articles/article.aspx?p=22685
/// - http://www.godevtool.com/Other/pdb.htm
/// - http://www.debuginfo.com/articles/debuginfomatch.html
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

enum PdbVersion {
	pdb20 = 2,	/// PDB 2.0
	pdb70 = 7,	/// PDB 7.0 "BigMSF"
}

/// Default (smallest?) size of a PDB 2.0 and 7.0 page in Bytes.
enum PDB_DEFAULT_PAGESIZE = 1024;
/// Largest page size of a PDB in Bytes.
enum PDB_LARGEST_PAGESIZE = 4096;

// Microsoft PDB 2.0
//
// 1. The first few blocks contain header and reserved space for growth
// 2. Right after header, there are block IDs that makes up the root directory
// 3. 
//
// Similar to PDB 7.0, but the root stream contains:
// - ushort streamCount
// - ushort reserved
// - { uint Size; uint Reserved }[StreamCount] stream1;
// - ushort[StreamCount] pageNumber;

// For each stream:
// - ushort streamSize; // in pages
// - ushort 

/// PDB 2.0 signature
immutable string PDB20_MAGIC = "Microsoft C/C++ program database 2.00\r\n\x1aJG\0\0"; // 44

enum Pdb20Stream {
	directory = 0,
	pdb       = 1, // pdb info
	pubsym    = 7, // public symbols
}
struct pdb20_file_header_t {
	char[44] Magic;
	uint BlockSize;	// Usually 1024, multiply with BlockCount to get filesize
	ushort StartPage;	// First usable block index (9, 5, or 2)
	ushort BlockCount;	// Number of total blocks for file
	uint RootSize;	// Root stream size in bytes
	uint Reserved;
}
private
struct pdb20_root_t {
	short count; // pages?
	short reserved;
}
private
struct pdb20_root_entry_t {
	uint size; // in bytes
	uint reserved; // 
}

struct pdb20_pdb_stream_t {
	PdbRaw_PdbVersion Version;
	uint Signature;
	uint[3] Unknown1;
	uint Age;
	uint[3] Unknown2;
}

int adbg_object_pdb20_load(adbg_object_t *o) {
	int e = adbg_object_impl_setup(o, AdbgObject.pdb,
		internal_pdb_t.sizeof,
		&adbg_object_pdb20_unload);
	if (e) return e;
	
	internal_pdb_t *pdb = cast(internal_pdb_t*)adbg_object_impl_get_buffer(o);
	pdb.pdbversion = PdbVersion.pdb20;
	
	pdb20_file_header_t *header = &pdb.pdb20_header;
	
	e = adbg_object_read_at(o, 0, header, pdb20_file_header_t.sizeof);
	if (e) return e;
	
	// Check header
	switch (header.BlockSize) {
	case 1024, 2048, 4096: break;
	default:
		return adbg_oops(AdbgError.objectMalformed);
	}
	// for a 128 MiB PDB with 4096 pages, it might top at 32768 blocks
	if (header.BlockCount < 3 || header.BlockCount > 32768) // potentially
		return adbg_oops(AdbgError.objectMalformed);
	if (header.RootSize < 12 || header.RootSize > 32768 * header.BlockSize) // potentially
		return adbg_oops(AdbgError.objectMalformed);
	
	// Allocate for root directory
	uint sets = ceildiv32(header.RootSize, header.BlockSize);
	void *stream0 = pdb.stream0 = malloc(sets * header.BlockSize);
	if (stream0 == null)
		return adbg_oops(AdbgError.crt);
	
	// Read stream 0 by block indexes after header
	long off = cast(long)pdb20_file_header_t.sizeof;
	for (uint i; i < sets; ++i, off += ushort.sizeof, stream0 += header.BlockSize) {
		// Read block id
		ushort block = void;
		if (adbg_object_read_at(o, off, &block, block.sizeof))
			return adbg_error_code();
		
		// Read block into buffer
		if (adbg_object_read_at(o, block * header.BlockSize, stream0, header.BlockSize))
			return adbg_error_code();
	}
	pdb.stream0size = header.RootSize;
	
	// Process stream information
	pdb20_root_t *root = cast(pdb20_root_t*)pdb.stream0;
	if (root.count >= 32768) // arbitrary
		return adbg_oops(AdbgError.objectMalformed);
	pdb.stream_count = root.count;
	pdb.streams = cast(pdb_stream_t*)malloc(root.count * pdb_stream_t.sizeof);
	if (pdb.streams == null)
		return adbg_oops(AdbgError.crt);
	
	// Here each entry has a ushort field of stream size in Bytes
	// following page numbers (irrelevant?)
	//
	// Layout:
	//   ushort count (of streams)
	//   ushort reserved
	//   for count (each stream):
	//     uint size (in bytes)
	//     uint id? offset? (first one matches Reserved in header)
	//   for count (each stream):
	//     ushort block (block offset)
	pdb20_root_entry_t *entry = cast(pdb20_root_entry_t*)(pdb.stream0 + pdb20_root_t.sizeof);
	ushort *blocks = cast(ushort*)(pdb.stream0 + pdb20_root_t.sizeof + (root.count * pdb20_root_entry_t.sizeof));
	for (ushort i; i < root.count; ++i) {
		pdb_stream_t *stream = pdb.streams + i;
		stream.size = entry.size;
		stream.blkcnt = ceildiv32(stream.size, header.BlockSize);
		stream.blocks16 = blocks;
		stream.data = null;
		
		++entry;
		blocks += stream.blkcnt;
	}
	
	return 0;
}
void adbg_object_pdb20_unload(adbg_object_t *o, void *u) {
	internal_pdb_t *pdb = cast(internal_pdb_t*)u;
	
	if (pdb.stream0) free(pdb.stream0);
	if (pdb.streams) free(pdb.streams);
}

pdb20_file_header_t* adbg_object_pdb20_header(adbg_object_t *o) {
	internal_pdb_t *pdb = cast(internal_pdb_t*)adbg_object_impl_get_buffer(o);
	if (pdb == null) return null;
	
	if (pdb.pdbversion != PdbVersion.pdb20) {
		adbg_oops(AdbgError.objectInvalidVersion);
		return null;
	}
	
	return &pdb.pdb20_header;
}

// Get PDB stream info only, does not load data
pdb_stream_t* adbg_object_pdb_stream_info(adbg_object_t *o, uint number) {
	internal_pdb_t *pdb = cast(internal_pdb_t*)adbg_object_impl_get_buffer(o);
	if (pdb == null) return null;
	
	if (number >= pdb.stream_count) {
		adbg_oops(AdbgError.indexBounds);
		return null;
	}
	
	return pdb.streams + number;
}

// Multiple streams can be opened at the same time.
pdb_stream_t* adbg_object_pdb_open_stream(adbg_object_t *o, uint number) {
	internal_pdb_t *pdb = cast(internal_pdb_t*)adbg_object_impl_get_buffer(o);
	if (pdb == null) return null;
	
	pdb_stream_t *stream = adbg_object_pdb_stream_info(o, number);
	if (stream == null)
		return null;
	if (stream.data) // Buffer already opened?
		return stream;
	
	// Remember, it's safer and faster to just read and copy blocks
	// instead of attempting to read and trim the exact amount of bytes
	final switch (pdb.pdbversion) {
	case PdbVersion.pdb20:
		uint blksize = pdb.pdb20_header.BlockSize;
		void *data = stream.data = malloc(stream.blkcnt * blksize);
		if (data == null) {
			adbg_oops(AdbgError.crt);
			return null;
		}
		
		for (ushort i; i < stream.blkcnt; ++i) {
			ushort block = stream.blocks16[i];
			// These might indicate maximum block size?
			// #define PDB_PAGE_COUNT_1K 0xFFFF // page number < PDB_PAGE_COUNT_*
			// #define PDB_PAGE_COUNT_2K 0xFFFF
			// #define PDB_PAGE_COUNT_4K 0x7FFF
			if (block == 0xffff) {
				memset(data, 0, blksize);
				data += blksize;
				continue;
			}
			
			long off = block * blksize;
			if (adbg_object_read_at(o, off, data, blksize)) {
				free(stream.data);
				return null;
			}
			data += blksize;
		}
		break;
	case PdbVersion.pdb70:
		uint blksize = pdb.pdb70_header.BlockSize;
		void *data = stream.data = malloc(stream.blkcnt * blksize);
		if (data == null) {
			adbg_oops(AdbgError.crt);
			return null;
		}
		
		for (uint i; i < stream.blkcnt; ++i) {
			uint block = stream.blocks32[i];
			
			if (block == PDB_BLOCK_SIZE_UNUSED) {
				memset(data, 0, blksize);
				data += blksize;
				continue;
			}
			
			final switch (adbg_object_pdb70_free_block(o, block)) {
			case -1: // error
				adbg_oops(AdbgError.crt);
				free(stream.data);
				return null;
			case 0: // used
				long off = block * blksize;
				if (adbg_object_read_at(o, off, data, blksize)) {
					free(stream.data);
					return null;
				}
				data += blksize;
				break;
			case 1: // free
				memset(data, 0, blksize);
				data += blksize;
				break;
			}
		}
		break;
	}
	
	return stream;
}
void adbg_object_pdb_close_stream(pdb_stream_t *stream) {
	if (stream == null)
		return;
	if (stream.data) {
		free(stream.data);
		stream.data = null;
	}
}

// Microsoft PDB 7.0
//
// 1. The very first block containing the file header, the Superblock, is read.
// 2. The FPM (Free Page Map) is read. This is to see which blocks are used.
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
// |   |   |           Only one FPM block is used, indicated in the Superblock header
// +---+  -+           1-bit/block: 0=unallocated/unused, 1=allocated/used
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
// |   |   |
// +---+   +- Header points to this, the block directory.
// |   |   |  Loaded as Stream 0.
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

/// PDB 7.0 "Big MSF" signature
immutable string PDB70_MAGIC = "Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"; // 32

// MSF container
struct pdb70_file_header_t {
	char[32] Magic;	/// Magic string
	uint BlockSize;	/// Usually 4096
	uint FreeIndex;	/// FPM block index
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
enum Pdb70Stream : uint {
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
const(char)* adbg_object_pdb_pdbversion_string(uint ver) {
	switch (ver) with (PdbRaw_PdbVersion) {
	case vc2:	return "VC2";
	case vc4:	return "VC4";
	case vc41:	return "VC41";
	case vc50:	return "VC50";
	case vc98:	return "VC60";
	case vc70_old:	return "VC70_OLD";
	case vc70:	return "VC70";
	case vc80:	return "VC80";
	case vc110:	return "VC110";
	case vc140:	return "VC140";
	default:	return null;
	}
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
	/// COFF and PE32 Machine values.
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

// PDB 2.0 and 7.0 stream information
struct pdb_stream_t {
	uint size; /// Size of stream in Bytes
	uint blkcnt; /// Number of blocks used (pre-calculated)
	union {
		ushort *blocks16; /// Block IDs for this PDB 2.0 stream
		uint   *blocks32; /// Block IDs for this PDB 7.0 stream
	}
	void *data;
}

// TODO: Consider function pointers to specific functions
//       e.g., PDB 2.0 functions that handle this version
//       + Saves the trouble of checking specific version per call
//       + Generalized API
private
struct internal_pdb_t {
	// 2: PDB 2.0
	// 7: PDB 7.0
	// (todo): CILDB
	PdbVersion pdbversion; // aka subtype
	
	union { // Superblock / headers
		pdb20_file_header_t pdb20_header;
		pdb70_file_header_t pdb70_header;
	}
	
	// Buffer for Stream 0
	void *stream0;	/// Buffer to hold Stream 0
	size_t stream0size;	/// Buffer size of Stream 0
	
	// Streamlined stream information
	uint stream_count; /// Number of streams in PDB
	pdb_stream_t *streams;
	
	// Free Page Map (PDB 7.0 only)
	ubyte *fpm;	/// Points to completed FPM in use
	size_t fpmcnt;	/// Size in bytes
}

int adbg_object_pdb70_load(adbg_object_t *o) {
	int e = adbg_object_impl_setup(o, AdbgObject.pdb,
		internal_pdb_t.sizeof,
		&adbg_object_pdb70_unload);
	if (e) return e;
	
	internal_pdb_t *pdb = cast(internal_pdb_t*)adbg_object_impl_get_buffer(o);
	pdb.pdbversion = PdbVersion.pdb70;
	
	pdb70_file_header_t *header = &pdb.pdb70_header;
	
	e = adbg_object_read_at(o, 0, header, pdb70_file_header_t.sizeof);
	if (e) return e;
	
	// Check SuperBlock
	// BlockCount * BlockSize == File Length (usually)
	with (header)
	if (BlockSize < 512 ||          // Minimum of 512 bytes
		BlockSize > 4096 ||     // Not observed to be higher than 4,096 bytes
		BlockSize % 512 != 0 || // Multiple of "sector"
		Unknown ||              // This must be empty (zero)
		FreeIndex < 1 || FreeIndex > 2) // 1 or 2 only
		return adbg_oops(AdbgError.objectMalformed);
	
	// Preload the currently used FPM.
	// FPMs can span across clusters of blocks if there are more blocks
	// in total than the blocksize (e.g., 5000 blocks at 4096 size means
	// there will be at least two sets of FPM blocks).
	// Reading blocks in full is safer, but wastes a little memory.
	size_t fpm_sets = ceildiv32(header.BlockCount, header.BlockSize);
	size_t fpm_size = fpm_sets * header.BlockSize;
	ubyte *fpm = pdb.fpm = cast(ubyte*)malloc(fpm_size);
	if (fpm == null)
		return adbg_oops(AdbgError.crt);
	long fpm_off  = header.FreeIndex * header.BlockSize;
	long fpm_clu  = header.BlockSize * header.BlockSize;
	pdb.fpmcnt    = ceildiv32(header.BlockCount, 8); // 8 bits per byte
	version (Trace)
		trace("fpm_sets=%zu fpm_size=%zu fpm_off=%lld fpm_clu=%lld",
			fpm_sets, fpm_size, fpm_off, fpm_clu);
	for (size_t i; i < fpm_sets; ++i) {
		if (adbg_object_read_at(o, fpm_off, fpm, header.BlockSize, 0))
			return adbg_error_code();
		
		// Increment FPM memory buffer offset by blocksize, as we are reading blocks
		fpm     += header.BlockSize;
		// Increment FPM offset in file
		fpm_off += fpm_clu;
	}
	
	// Load root directory, contains blocks IDs that contains Stream 0
	// The number of block IDs is the number of blocks that can be
	// contained depending on BlockSize
	// DirectorySize=1140 -> 1 block ID
	// DirectorySize=5530 -> 2 block IDs
	pdb.stream0size = header.DirectorySize;
	uint rootcnt = ceildiv32(header.DirectorySize, header.BlockSize);
	long rootoff = header.DirectoryOffset * header.BlockSize;
	size_t rootsz = rootcnt * uint.sizeof;
	// Allocate and read offsets to Stream 0
	uint *dirblocks = cast(uint*)adbg_object_readalloc_at(o, rootoff, rootsz);
	if (dirblocks == null)
		return adbg_error_code();
	scope(exit) free(dirblocks); // Since it is a temp buffer
	
	// Load Stream 0 blocks into memory
	void *stream0 = pdb.stream0 = malloc(rootcnt * header.BlockSize);
	if (stream0 == null)
		return adbg_oops(AdbgError.crt);
	uint *root = cast(uint*)stream0;
	for (uint i; i < rootcnt; ++i, stream0 += header.BlockSize) {
		uint block = dirblocks[i];
		if (adbg_object_read_at(o, block * header.BlockSize, stream0, header.BlockSize))
			return adbg_error_code();
	}
	
	// Load information for streams (size and block locations)
	// - uint StreamCount
	//   foreach Stream:
	//     - uint StreamSize
	//   foreach Stream:
	//     - uint Blocks...
	// Following StreamCount is all StreamSizes (uint each)
	// Then all blocks for each stream
	pdb.stream_count = *cast(uint*)pdb.stream0;
	pdb.streams = cast(pdb_stream_t*)malloc(pdb.stream_count * pdb_stream_t.sizeof);
	if (pdb.streams == null)
		return adbg_oops(AdbgError.crt);
	uint *sizes  = cast(uint*)(pdb.stream0 + uint.sizeof); // stream size
	uint *blocks = sizes + pdb.stream_count;
	for (uint i; i < pdb.stream_count; ++i) {
		pdb_stream_t *stream = pdb.streams + i;
		stream.size     = sizes[i];
		stream.blkcnt   = ceildiv32(stream.size, header.BlockSize);
		stream.blocks32 = blocks;
		stream.data     = null;
		version (Trace)
			trace("stream=%u size=%u blkcnt=%u", i, stream.size, stream.blkcnt);
		
		blocks += stream.blkcnt;
	}
	
	return 0;
}

void adbg_object_pdb70_unload(adbg_object_t *o, void *buffer) {
	internal_pdb_t *pdb = cast(internal_pdb_t*)buffer;
	
	if (pdb.fpm) free(pdb.fpm);
	if (pdb.stream0) free(pdb.stream0);
	if (pdb.streams) free(pdb.streams);
}

/// Get the PDB version loaded.
/// Params: o = Object instance.
/// Returns: PdbVersion enum value or zero on error.
PdbVersion adbg_object_pdb_version(adbg_object_t *o) {
	internal_pdb_t *pdb = cast(internal_pdb_t*)adbg_object_impl_get_buffer(o);
	if (pdb == null)
		return cast(PdbVersion)0;
	return pdb.pdbversion;
}

// Return PDB 7.0 file header
pdb70_file_header_t* adbg_object_pdb70_header(adbg_object_t *o) {
	internal_pdb_t *pdb = cast(internal_pdb_t*)adbg_object_impl_get_buffer(o);
	if (pdb == null)
		return null;
	if (pdb.pdbversion != PdbVersion.pdb70) {
		adbg_oops(AdbgError.objectInvalidVersion);
		return null;
	}
	return &pdb.pdb70_header;
}

// Get FPM table
ubyte* adbg_object_pdb70_fpm(adbg_object_t *o) {
	internal_pdb_t *pdb = cast(internal_pdb_t*)adbg_object_impl_get_buffer(o);
	if (pdb == null)
		return null;
	if (pdb.pdbversion != PdbVersion.pdb70) {
		adbg_oops(AdbgError.objectInvalidVersion);
		return null;
	}
	if (pdb.fpm == null) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	return pdb.fpm;
}
// Get FPM entries in bytes
size_t adbg_object_pdb70_fpmcount(adbg_object_t *o) {
	internal_pdb_t *pdb = cast(internal_pdb_t*)adbg_object_impl_get_buffer(o);
	if (pdb == null)
		return 0;
	if (pdb.pdbversion != PdbVersion.pdb70) {
		adbg_oops(AdbgError.objectInvalidVersion);
		return 0;
	}
	if (pdb.fpm == null) {
		adbg_oops(AdbgError.unavailable);
		return 0;
	}
	return pdb.fpmcnt;
}

// Total count of streams
uint adbg_object_pdb_stream_count(adbg_object_t *o) {
	internal_pdb_t *pdb = cast(internal_pdb_t*)adbg_object_impl_get_buffer(o);
	if (pdb == null)
		return 0;
	return pdb.stream_count;
}

/// Get the status of a block.
/// Params:
/// 	o = Object instance.
/// 	id = Block ID.
/// Returns: 1=Free, 0=Used, -1=Error
private
int adbg_object_pdb70_free_block(adbg_object_t *o, uint id) {
	internal_pdb_t *pdb = cast(internal_pdb_t*)adbg_object_impl_get_buffer(o);
	if (pdb.pdbversion != PdbVersion.pdb70) {
		adbg_oops(AdbgError.objectInvalidVersion);
		return -1;
	}
	
	if (id >= pdb.pdb70_header.BlockCount) {
		adbg_oops(AdbgError.indexBounds);
		return -1;
	}
	
	uint bi = id >> 3; // block byte index (id / 8)
	uint br = 7 - (id % 8); // block reminder shift
	return (pdb.fpm[bi] & (1 << br)) != 0; // if set, free block
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
