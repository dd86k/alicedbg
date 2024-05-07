/// Minidump file format.
///
/// Sources:
/// - https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/
/// - Windows Kits\10\Include\10.0.22621.0\um\minidumpapiset.h
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.object.format.mdmp;

import adbg.object.server : AdbgObject, adbg_object_t;
import adbg.utils.bit : CHAR32;

/// Signature value
enum MDMP_MAGIC = CHAR32!"MDMP";
/// Minidump version defined by WinNT 10.0.22621.0
// Version SDK
// 41053   Unknown - Target is 64-bit, Windows 11
// 41057   Unknown - Target was 32-bit on WoW64
// 42899   5.0
// 42899   6.0
// 42899   7.0
// 42899   7.1
// 42899   8.0
// 42899   10.0.22000.0
// 42899   10.0.22621.0
enum ushort MDMP_VERSION	= 42899;

alias MINIDUMP_STREAM_TYPE = int;
enum : MINIDUMP_STREAM_TYPE {
	UnusedStream                = 0,
	ReservedStream0             = 1,
	ReservedStream1             = 2,
	ThreadListStream            = 3,
	ModuleListStream            = 4,
	MemoryListStream            = 5,
	ExceptionStream             = 6,
	SystemInfoStream            = 7,
	ThreadExListStream          = 8,
	Memory64ListStream          = 9,
	CommentStreamA              = 10,
	CommentStreamW              = 11,
	HandleDataStream            = 12,
	FunctionTableStream         = 13,
	UnloadedModuleListStream    = 14,
	MiscInfoStream              = 15,
	MemoryInfoListStream        = 16,
	ThreadInfoListStream        = 17,
	HandleOperationListStream   = 18,
	TokenStream                 = 19,
	JavaScriptDataStream        = 20,
	SystemMemoryInfoStream      = 21,
	ProcessVmCountersStream     = 22,
	IptTraceStream              = 23,
	ThreadNamesStream           = 24,

	// .NET stuff?

	ceStreamNull                = 0x8000,
	ceStreamSystemInfo          = 0x8001,
	ceStreamException           = 0x8002,
	ceStreamModuleList          = 0x8003,
	ceStreamProcessList         = 0x8004,
	ceStreamThreadList          = 0x8005,
	ceStreamThreadContextList   = 0x8006,
	ceStreamThreadCallStackList = 0x8007,
	ceStreamMemoryVirtualList   = 0x8008,
	ceStreamMemoryPhysicalList  = 0x8009,
	ceStreamBucketParameters    = 0x800A,
	ceStreamProcessModuleMap    = 0x800B,
	ceStreamDiagnosisList       = 0x800C,

	LastReservedStream          = 0xffff
}

alias MINIDUMP_TYPE = int;
enum : MINIDUMP_TYPE {
	/// Include just the information necessary to capture stack traces
	/// for all existing threads in a process.
	MiniDumpNormal	= 0x00000000,
	/// Include the data sections from all loaded modules. This results in
	/// the inclusion of global variables, which can make the minidump file
	/// significantly larger. For per-module control, use the
	/// ModuleWriteDataSeg enumeration value from MODULE_WRITE_FLAGS.
	MiniDumpWithDataSegs	= 0x00000001,
	/// Include all accessible memory in the process. The raw memory data
	/// is included at the end, so that the initial structures can be mapped
	/// directly without the raw memory information. This option can result
	/// in a very large file.
	MiniDumpWithFullMemory	= 0x00000002,
	/// Include high-level information about the operating system handles
	/// that are active when the minidump is made.
	MiniDumpWithHandleData	= 0x00000004,
	/// Stack and backing store memory written to the minidump file should
	/// be filtered to remove all but the pointer values necessary to
	/// reconstruct a stack trace.
	MiniDumpFilterMemory	= 0x00000008,
	/// Stack and backing store memory should be scanned for pointer
	/// references to modules in the module list. If a module is referenced
	/// by stack or backing store memory, the ModuleWriteFlags member of
	/// the MINIDUMP_CALLBACK_OUTPUT structure is set to ModuleReferencedByMemory.
	MiniDumpScanMemory	= 0x00000010,
	/// Include information from the list of modules that were recently unloaded,
	/// if this information is maintained by the operating system.
	MiniDumpWithUnloadedModules	= 0x00000020,
	/// Include pages with data referenced by locals or other stack memory.
	/// This option can increase the size of the minidump file significantly.
	MiniDumpWithIndirectlyReferencedMemory	= 0x00000040,
	/// Filter module paths for information such as user names or important
	/// directories. This option may prevent the system from locating the
	/// image file and should be used only in special situations.
	MiniDumpFilterModulePaths	= 0x00000080,
	/// Include complete per-process and per-thread information from the
	/// operating system.
	MiniDumpWithProcessThreadData	= 0x00000100,
	/// Scan the virtual address space for PAGE_READWRITE memory to be included.
	MiniDumpWithPrivateReadWriteMemory	= 0x00000200,
	/// Reduce the data that is dumped by eliminating memory regions that are
	/// not essential to meet criteria specified for the dump. This can avoid
	/// dumping memory that may contain data that is private to the user.
	/// However, it is not a guarantee that no private information will be present.
	MiniDumpWithoutOptionalData	= 0x00000400,
	/// Include memory region information. For more information, see
	/// MINIDUMP_MEMORY_INFO_LIST.
	MiniDumpWithFullMemoryInfo	= 0x00000800,
	/// Include thread state information. For more information, see
	/// MINIDUMP_THREAD_INFO_LIST.
	MiniDumpWithThreadInfo	= 0x00001000,
	/// Include all code and code-related sections from loaded modules to
	/// capture executable content. For per-module control, use the
	/// ModuleWriteCodeSegs enumeration value from MODULE_WRITE_FLAGS.
	MiniDumpWithCodeSegs	= 0x00002000,
	/// Turns off secondary auxiliary-supported memory gathering.
	MiniDumpWithoutAuxiliaryState	= 0x00004000,
	/// Requests that auxiliary data providers include their state in the
	/// dump image; the state data that is included is provider dependent.
	/// This option can result in a large dump image.
	MiniDumpWithFullAuxiliaryState	= 0x00008000,
	/// Scans the virtual address space for PAGE_WRITECOPY memory to be included.
	MiniDumpWithPrivateWriteCopyMemory	= 0x00010000,
	/// If you specify MiniDumpWithFullMemory, the MiniDumpWriteDump function will
	/// fail if the function cannot read the memory regions; however, if you include
	/// MiniDumpIgnoreInaccessibleMemory, the MiniDumpWriteDump function will ignore
	/// the memory read failures and continue to generate the dump. Note that the
	/// inaccessible memory regions are not included in the dump.
	MiniDumpIgnoreInaccessibleMemory	= 0x00020000,
	/// Adds security token related data. This will make the "!token" extension
	/// work when processing a user-mode dump.
	MiniDumpWithTokenInformation	= 0x00040000,
	/// Adds module header related data.
	MiniDumpWithModuleHeaders	= 0x00080000,
	/// Adds filter triage related data.
	MiniDumpFilterTriage	= 0x00100000,
	/// Adds AVX crash state context registers.
	MiniDumpWithAvxXStateContext	= 0x00200000,
	/// Adds Intel Processor Trace related data.
	MiniDumpWithIptTrace	= 0x00400000,
	/// Scans inaccessible partial memory pages.
	MiniDumpScanInaccessiblePartialPages	= 0x00800000,
	/// Asks to exclude all memory with the virtual protection attribute
	/// of PAGE_WRITECOMBINE.
	MiniDumpFilterWriteCombinedMemory	= 0x01000000,
	/// Valid flag mask
	MiniDumpValidTypeFlags	= 0x01ffffff
}

struct mdmp_location_descriptor {
	uint Size;
	uint Rva;
}
struct mdmp_location_descriptor64 {
	ulong Size;
	ulong Rva;
}
struct mdmp_memory_descriptor {
	ulong RangeStart;
	mdmp_location_descriptor Memory;
}
// Used for full-memory minidumps
struct mdmp_memory_descriptor64 {
	ulong RangeStart;
	ulong Size;
}

struct mdump_header {
	/// "MDMP" string.
	uint Signature;
	/// Used internally. Typically 0xa793.
	ushort Magic;
	/// Typically 42899 these days.
	ushort Version;
	/// The number of streams in this minidump.
	uint StreamCount;
	/// Stream Directory RVA.
	uint StreamRva;
	/// 
	uint Checksum;
	union {
		uint Reserved;
		uint Timestamp;
	}
	ulong Flags;
}

struct mdmp_vs_fixedfileinfo {
	/// 0xFEEF04BD
	uint dwSignature;
	uint dwStrucVersion;
	uint dwFileVersionMS;
	uint dwFileVersionLS;
	uint dwProductVersionMS;
	uint dwProductVersionLS;
	uint dwFileFlagsMask;
	uint dwFileFlags;
	uint dwFileOS;
	uint dwFileType;
	uint dwFileSubtype;
	uint dwFileDateMS;
	uint dwFileDateLS;
}
/* // Pseudo-structure
struct mdmp_vs_versioninfo {
	ushort             wLength;
	ushort             wValueLength;
	ushort             wType;
	wchar              szKey;
	ushort             Padding1;
	mdmp_vs_fixedfileinfo Value;
	ushort             Padding2;
	ushort             Children;
}*/

//
// Type 3 - Thread list
//

struct mdmp_directory_entry {
	uint StreamType;
	uint Size;
	uint Rva;
}

struct mdmp_thread {
	uint ID;
	uint SuspendCount;
	uint PriorityClass;
	uint Priority;
	ulong Teb;
	mdmp_memory_descriptor Stack;
	mdmp_location_descriptor ThreadContext;
}
struct mdmp_threadlist {
	uint Count;
	mdmp_thread[0] Threads;
}

struct mdmp_thread_ex {
	uint ID;
	uint SuspendCount;
	uint PriorityClass;
	uint Priority;
	ulong Teb;
	mdmp_memory_descriptor Stack;
	mdmp_location_descriptor ThreadContext;
	mdmp_memory_descriptor BackingStore;
}
struct mdmp_threadlist_ex {
	uint Count;
	mdmp_thread_ex[1] Threads;
}

//
// Type 4 - Module list
//

struct mdmp_module {
	ulong Imagebase;
	uint ImageSize;
	uint Checksum;
	uint Timestamp;
	uint ModuleNameRva;
	mdmp_vs_fixedfileinfo VersionInfo;
	mdmp_location_descriptor CvRecord;
	mdmp_location_descriptor MiscRecord;
	ulong Reserved0;
	ulong Reserved1;
}
struct mdmp_module_list {
	uint Count;
	mdmp_module[1] Modules;
}

//
// Functions
//

int adbg_object_mdmp_load(adbg_object_t *o) {
	o.format = AdbgObject.mdmp;
	
	//if (o.i.mdmp.header.Version != MDMP
	
	return 0;
}
