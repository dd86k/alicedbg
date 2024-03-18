/// Microsoft Portable Executable format.
///
/// PE32 format for both images (executables) and objects (mscoff object files).
///
/// Loosely based on Windows Kits\10\Include\10.0.17763.0\um\winnt.h
///
/// Sources:
/// - Microsoft Corporation, Microsoft Portable Executable and Common Object File Format Specification, Revision 6.0 - February 1999
/// - Microsoft Corporation, Microsoft Portable Executable and Common Object File Format Specification, Revision 8.3 – February 6, 2013
/// - Microsoft Corporation, PE Format, 2019-08-26
/// - https://github.com/Microsoft/microsoft-pdb/
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.object.format.pe;

import core.stdc.inttypes;
import core.stdc.stdlib;
import adbg.error;
import adbg.object.server;
import adbg.object.machines : AdbgMachine;
import adbg.utils.uid : UID;
import adbg.utils.bit;

// NOTE: Avoid the Windows base types as they are not defined outside "version (Windows)"
// NOTE: Microsoft loader limits sections to 96 maximum

//TODO: Function to check RVA bounds (within file_size)
//TODO: Return everything as const(type)*
//      Memory implementation will potentially be read-only

extern (C):

/// Magic number for PE32 object files.
enum MAGIC_PE32 = CHAR32!"PE\0\0";

private enum {
	/// Minimum file size for PE32.
	/// See: https://stackoverflow.com/a/47311684
	MINIMUM_SIZE = 97,
	/// Specifications limit number of sections to 96.
	MAXIMUM_SECTIONS = 96,
}

enum : ushort { // PE_HEADER.Machine, likely all little-endian
	PE_MACHINE_UNKNOWN	= 0,	/// Any machine
	PE_MACHINE_ALPHAOLD	= 0x183,	/// Alpha (old value), unused
	PE_MACHINE_ALPHA	= 0x184,	/// Alpha AXP
	PE_MACHINE_ALPHA64	= 0x284,	/// Alpha AXP 64-bit
	PE_MACHINE_AM33	= 0x1d3,	/// Matsushita AM33
	PE_MACHINE_AMD64	= 0x8664,	/// x86-64
	PE_MACHINE_ARM	= 0x1c0,	/// ARM little endian
	PE_MACHINE_ARMNT	= 0x1c4,	/// arm_a32 (ARMv7+ with thumb2)
	PE_MACHINE_ARM64	= 0xaa64,	/// arm_a64 (AArch64)
	PE_MACHINE_EBC	= 0xebc,	/// EFI Byte-Code
	PE_MACHINE_I386	= 0x14c,	/// x86
	PE_MACHINE_IA64	= 0x200,	/// Itanium
	PE_MACHINE_LOONGARCH32	= 0x6232,	/// LoongArch32
	PE_MACHINE_LOONGARCH64	= 0x6264,	/// LoongArch64
	PE_MACHINE_M32R	= 0x9041,	/// Mitsubishi M32R LSB
	PE_MACHINE_MIPS16	= 0x266,	/// 
	PE_MACHINE_MIPSFPU	= 0x366,	/// 
	PE_MACHINE_MIPSFPU16	= 0x466,	/// 
	PE_MACHINE_POWERPC	= 0x1f0,	/// 
	PE_MACHINE_POWERPCFP	= 0x1f1,	/// 
	PE_MACHINE_R3000	= 0x162,	/// MIPS I
	PE_MACHINE_R4000	= 0x166,	/// MIPS II
	PE_MACHINE_R10000	= 0x168,	/// MIPS III
	PE_MACHINE_RISCV32	= 0x5032,	/// RISC-V (32-bit)
	PE_MACHINE_RISCV64	= 0x5064,	/// RISC-V (64-bit)
	PE_MACHINE_RISCV128	= 0x5128,	/// RISC-V (128-bit)
	PE_MACHINE_SH3	= 0x1a2,	/// SuperH
	PE_MACHINE_SH3DSP	= 0x1a3,	/// SuperH + DSP
	PE_MACHINE_SH4	= 0x1a6,	/// SuperH 4
	PE_MACHINE_SH5	= 0x1a8,	/// SuperH 5
	PE_MACHINE_THUMB	= 0x1c2,	/// arm_t32
	PE_MACHINE_WCEMIPSV2	= 0x169,	/// MIPS WCE
	PE_MACHINE_CHPE_X86	= 0x3a64,	/// ARM64X, source: SystemInformer
	// https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files
	PE_MACHINE_CLR	= 0xC0EE,	/// Pure MSIL. aka COM+ EE?
}

enum : ushort { // PE_HEADER.Characteristics flags
	PE_CHARACTERISTIC_RELOCS_STRIPPED	= 0x0001,
	PE_CHARACTERISTIC_EXECUTABLE_IMAGE	= 0x0002,
	PE_CHARACTERISTIC_LINE_NUMS_STRIPPED	= 0x0004,
	PE_CHARACTERISTIC_LOCAL_SYMS_STRIPPED	= 0x0008,
	PE_CHARACTERISTIC_AGGRESSIVE_WS_TRIM	= 0x0010, // obsolete
	PE_CHARACTERISTIC_LARGE_ADDRESS_AWARE	= 0x0020,
	PE_CHARACTERISTIC_16BIT_MACHINE	= 0x0040,
	PE_CHARACTERISTIC_BYTES_REVERSED_LO	= 0x0080, // obsolete
	PE_CHARACTERISTIC_32BIT_MACHINE	= 0x0100,
	PE_CHARACTERISTIC_DEBUG_STRIPPED	= 0x0200,
	PE_CHARACTERISTIC_REMOVABLE_RUN_FROM_SWAP	= 0x0400,
	PE_CHARACTERISTIC_NET_RUN_FROM_SWAP	= 0x0800,
	PE_CHARACTERISTIC_SYSTEM	= 0x1000,
	PE_CHARACTERISTIC_DLL	= 0x2000,
	PE_CHARACTERISTIC_UP_SYSTEM_ONLY	= 0x4000,
	PE_CHARACTERISTIC_BYTES_REVERSED_HI	= 0x8000 // obsolete
}

enum : ushort { // PE_OPTIONAL_HEADER.DllCharacteristics flags
	PE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA	= 0x0020,
	PE_DLLCHARACTERISTICS_DYNAMIC_BASE	= 0x0040,
	PE_DLLCHARACTERISTICS_FORCE_INTEGRITY	= 0x0080,
	PE_DLLCHARACTERISTICS_NX_COMPAT	= 0x0100,
	PE_DLLCHARACTERISTICS_NO_ISOLATION	= 0x0200,
	PE_DLLCHARACTERISTICS_NO_SEH	= 0x0400,
	PE_DLLCHARACTERISTICS_NO_BIND	= 0x0800,
	PE_DLLCHARACTERISTICS_APPCONTAINER	= 0x1000,
	PE_DLLCHARACTERISTICS_WDM_DRIVER	= 0x2000,
	PE_DLLCHARACTERISTICS_GUARD_CF	= 0x4000,
	PE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE	= 0x8000,
}

/// To be used with SECTION_CHARACTERISTIC_ALIGN fields.
enum PE_SECTION_CHARACTERISTIC_ALIGN_MASK = 0x00F00000;

enum { // PE_SECTION_ENTRY.Characteristics flags
	PE_SECTION_CHARACTERISTIC_TYPE_DSECT	= 0x00000001,	/// Reserved, undocumented
	PE_SECTION_CHARACTERISTIC_TYPE_NOLOAD	= 0x00000002,	/// Reserved, undocumented
	PE_SECTION_CHARACTERISTIC_TYPE_GROUP	= 0x00000004,	/// Reserved, undocumented
	PE_SECTION_CHARACTERISTIC_NO_PAD	= 0x00000008,
	PE_SECTION_CHARACTERISTIC_TYPE_COPY	= 0x00000010,	/// Reserved, undocumented
	PE_SECTION_CHARACTERISTIC_CODE	= 0x00000020,
	PE_SECTION_CHARACTERISTIC_INITIALIZED_DATA	= 0x00000040,
	PE_SECTION_CHARACTERISTIC_UNINITIALIZED_DATA	= 0x00000080,
	PE_SECTION_CHARACTERISTIC_LNK_OTHER	= 0x00000100,	/// Reserved
	PE_SECTION_CHARACTERISTIC_LNK_INFO	= 0x00000200,
	PE_SECTION_CHARACTERISTIC_LNK_REMOVE	= 0x00000800,
	PE_SECTION_CHARACTERISTIC_LNK_COMDAT	= 0x00001000,
	PE_SECTION_CHARACTERISTIC_MEM_PROTECTED	= 0x00004000,	/// Reserved, undocumented
	PE_SECTION_CHARACTERISTIC_GPREL	= 0x00008000,
	PE_SECTION_CHARACTERISTIC_MEM_PURGEABLE	= 0x00010000,	/// Reserved, aka SYSHEAP
	PE_SECTION_CHARACTERISTIC_MEM_16BIT	= 0x00020000,	/// Reserved
	PE_SECTION_CHARACTERISTIC_MEM_LOCKED	= 0x00040000,	/// Reserved
	PE_SECTION_CHARACTERISTIC_PRELOAD	= 0x00080000,	/// Reserved
	PE_SECTION_CHARACTERISTIC_ALIGN_1BYTES	= 0x00100000,
	PE_SECTION_CHARACTERISTIC_ALIGN_2BYTES	= 0x00200000,
	PE_SECTION_CHARACTERISTIC_ALIGN_4BYTES	= 0x00300000,
	PE_SECTION_CHARACTERISTIC_ALIGN_8BYTES	= 0x00400000,
	PE_SECTION_CHARACTERISTIC_ALIGN_16BYTES	= 0x00500000,
	PE_SECTION_CHARACTERISTIC_ALIGN_32BYTES	= 0x00600000,
	PE_SECTION_CHARACTERISTIC_ALIGN_64BYTES	= 0x00700000,
	PE_SECTION_CHARACTERISTIC_ALIGN_128BYTES	= 0x00800000,
	PE_SECTION_CHARACTERISTIC_ALIGN_256BYTES	= 0x00900000,
	PE_SECTION_CHARACTERISTIC_ALIGN_512BYTES	= 0x00A00000,
	PE_SECTION_CHARACTERISTIC_ALIGN_1024BYTES	= 0x00B00000,
	PE_SECTION_CHARACTERISTIC_ALIGN_2048BYTES	= 0x00C00000,
	PE_SECTION_CHARACTERISTIC_ALIGN_4096BYTES	= 0x00D00000,
	PE_SECTION_CHARACTERISTIC_ALIGN_8192BYTES	= 0x00E00000,
	PE_SECTION_CHARACTERISTIC_LNK_NRELOC_OVFL	= 0x01000000,
	PE_SECTION_CHARACTERISTIC_MEM_DISCARDABLE	= 0x02000000,
	PE_SECTION_CHARACTERISTIC_MEM_NOT_CACHED	= 0x04000000,
	PE_SECTION_CHARACTERISTIC_MEM_NOT_PAGED	= 0x08000000,
	PE_SECTION_CHARACTERISTIC_MEM_SHARED	= 0x10000000,
	PE_SECTION_CHARACTERISTIC_MEM_EXECUTE	= 0x20000000,
	PE_SECTION_CHARACTERISTIC_MEM_READ	= 0x40000000,
	PE_SECTION_CHARACTERISTIC_MEM_WRITE	= 0x80000000,
}

enum : ushort { // PE image format/magic
	PE_FMT_ROM	= 0x0107,	// No longer used? Docs no longer have it
	PE_FMT_32	= 0x010B,	/// PE32
	PE_FMT_64	= 0x020B,	/// PE32+
}

enum : ushort { // PE_HEADER
	PE_SUBSYSTEM_NATIVE	= 1,
	PE_SUBSYSTEM_WINDOWS_GUI	= 2,
	PE_SUBSYSTEM_WINDOWS_CUI	= 3,
	PE_SUBSYSTEM_OS2_CUI	= 5,
	PE_SUBSYSTEM_POSIX_CUI	= 7,
	PE_SUBSYSTEM_NATIVE_WINDOWS	= 8,
	PE_SUBSYSTEM_WINDOWS_CE_GUI	= 9,
	PE_SUBSYSTEM_EFI_APPLICATION	= 10,
	PE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER	= 11,
	PE_SUBSYSTEM_EFI_RUNTIME_DRIVER	= 12,
	PE_SUBSYSTEM_EFI_ROM	= 13,
	PE_SUBSYSTEM_XBOX	= 14,
	PE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION	= 16,
}

/// COFF file header (object and image)
struct PE_HEADER { align(1):
	union {
		uint8_t[4] Signature;
		uint32_t   Signature32;
	}
	uint16_t Machine;
	uint16_t NumberOfSections;
	uint32_t TimeDateStamp; // C time_t
	uint32_t PointerToSymbolTable;
	uint32_t NumberOfSymbols;
	uint16_t SizeOfOptionalHeader;
	uint16_t Characteristics;
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
// Image only
struct PE_OPTIONAL_HEADER { align(1):
	uint16_t Magic; // "Format"
	uint8_t  MajorLinkerVersion;
	uint8_t  MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint;
	uint32_t BaseOfCode;
	uint32_t BaseOfData;
	uint32_t ImageBase;
	uint32_t SectionAlignment;
	uint32_t FileAlignment;
	uint16_t MajorOperatingSystemVersion;
	uint16_t MinorOperatingSystemVersion;
	uint16_t MajorImageVersion;
	uint16_t MinorImageVersion;
	uint16_t MajorSubsystemVersion;
	uint16_t MinorSubsystemVersion;
	uint32_t Win32VersionValue;
	uint32_t SizeOfImage;
	uint32_t SizeOfHeaders;
	uint32_t CheckSum;
	uint16_t Subsystem;
	uint16_t DllCharacteristics;
	uint32_t SizeOfStackReserve;
	uint32_t SizeOfStackCommit;
	uint32_t SizeOfHeapReserve;
	uint32_t SizeOfHeapCommit;
	uint32_t LoaderFlags;	/// Obsolete
	uint32_t NumberOfRvaAndSizes;
}
struct PE_OPTIONAL_HEADER64 { align(1):
	uint16_t Magic; // "Format"
	uint8_t  MajorLinkerVersion;
	uint8_t  MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint;
	uint32_t BaseOfCode;
	uint64_t ImageBase;
	uint32_t SectionAlignment;
	uint32_t FileAlignment;
	uint16_t MajorOperatingSystemVersion;
	uint16_t MinorOperatingSystemVersion;
	uint16_t MajorImageVersion;
	uint16_t MinorImageVersion;
	uint16_t MajorSubsystemVersion;
	uint16_t MinorSubsystemVersion;
	uint32_t Win32VersionValue;
	uint32_t SizeOfImage;
	uint32_t SizeOfHeaders;
	uint32_t CheckSum;
	uint16_t Subsystem;
	uint16_t DllCharacteristics;
	uint64_t SizeOfStackReserve;
	uint64_t SizeOfStackCommit;
	uint64_t SizeOfHeapReserve;
	uint64_t SizeOfHeapCommit;
	uint32_t LoaderFlags; // Obsolete
	uint32_t NumberOfRvaAndSizes;
}

struct PE_OPTIONAL_HEADERROM {
	uint16_t Magic;
	uint8_t  MajorLinkerVersion;
	uint8_t  MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint;
	uint32_t BaseOfCode;
	uint32_t BaseOfData;
	uint32_t BaseOfBss;
	uint32_t GprMask;
	uint32_t[4] CprMask;
	uint32_t GpValue;
}

struct PE_DIRECTORY_ENTRY { align(1):
	uint32_t rva;	/// Relative Virtual Address
	uint32_t size;	/// Size in bytes
}

// IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
// MS recommends checking NumberOfRvaAndSizes but it always been 16
struct PE_IMAGE_DATA_DIRECTORY { align(1):
	PE_DIRECTORY_ENTRY ExportTable;
	PE_DIRECTORY_ENTRY ImportTable;
	PE_DIRECTORY_ENTRY ResourceTable;
	PE_DIRECTORY_ENTRY ExceptionTable;
	PE_DIRECTORY_ENTRY CertificateTable;	// File Pointer (instead of RVA)
	PE_DIRECTORY_ENTRY BaseRelocationTable;
	PE_DIRECTORY_ENTRY DebugDirectory;
	PE_DIRECTORY_ENTRY ArchitectureData;
	PE_DIRECTORY_ENTRY GlobalPtr;
	PE_DIRECTORY_ENTRY TLSTable;
	PE_DIRECTORY_ENTRY LoadConfigurationTable;
	PE_DIRECTORY_ENTRY BoundImportTable;
	PE_DIRECTORY_ENTRY ImportAddressTable;
	PE_DIRECTORY_ENTRY DelayImport;
	PE_DIRECTORY_ENTRY CLRHeader;	// Used to be (or alias to) COM+ Runtime Header
	PE_DIRECTORY_ENTRY Reserved;
}

//
// ANCHOR Directory structures
//

struct PE_EXPORT_DESCRIPTOR { align(1):
	uint32_t ExportFlags;
	uint32_t Timestamp;
	uint16_t MajorVersion;
	uint16_t MinorVersion;
	uint32_t Name;	/// RVA
	uint32_t OrdinalBase;
	uint32_t AddressTableEntries;	/// Number of export entries
	uint32_t NumberOfNamePointers;	/// Same amount for ordinal
	uint32_t ExportAddressTable;	/// RVA
	uint32_t NamePointer;	/// RVA, "The address of the export name pointer table"
	uint32_t OrdinalTable;	/// RVA
}

union PE_EXPORT_ENTRY { align(1):
	uint32_t Export;	/// RVA
	uint32_t Forwarder;	/// RVA
}

// IMAGE_IMPORT_DESCRIPTOR
struct PE_IMPORT_DESCRIPTOR { align(1):
	uint32_t Characteristics; // used in WINNT.H but no longer descriptive
	uint32_t TimeDateStamp; // time_t
	uint32_t ForwarderChain;
	uint32_t Name;
	uint32_t FirstThunk;
}

/// Import Lookup Table entry structure
struct PE_IMPORT_ENTRY32 { align(1):
	union {
		uint ordinal;	/// Ordinal/Name Flag
		ushort number;	/// Ordinal Number (val[31] is set)
		uint rva;	/// Hint/Name Table RVA (val[31] is clear)
	}
}
/// Import Lookup Table entry structure
struct PE_IMPORT_ENTRY64 { align(1):
	union {
		ulong ordinal;	/// Ordinal/Name Flag
		ushort number;	/// Ordinal Number (val2[31] is set)
		uint rva;	/// Hint/Name Table RVA (val2[31] is clear)
	}
}

/// DEBUG Directory
struct PE_DEBUG_DIRECTORY { align(1):
	uint32_t Characteristics;	/// reserved, must be zero
	uint32_t TimeDateStamp;	/// time and date that the debug data was created
	uint16_t MajorVersion;	/// The major version number of the debug data format
	uint16_t MinorVersion;	/// The minor version number of the debug data format
	uint32_t Type;	/// The format of debugging information
	uint32_t SizeOfData;	/// The size of the debug data (not including the debug directory itself)
	uint32_t AddressOfRawData;	/// The address of the debug data relative to the image base
	uint32_t PointerToRawData;	/// The file pointer to the debug data
}

// Debug Types
enum : uint {
	/// An unknown value that is ignored by all tools
	PE_IMAGE_DEBUG_TYPE_UNKNOWN	= 0,
	/// The COFF debug information (line numbers, symbol table, and string table).
	/// This type of debug information is also pointed to by fields in the file headers.
	PE_IMAGE_DEBUG_TYPE_COFF	= 1,
	/// The Visual C++ debug information
	PE_IMAGE_DEBUG_TYPE_CODEVIEW	= 2,
	/// The frame pointer omission (FPO) information. This information tells the
	/// debugger how to interpret nonstandard stack frames, which use the EBP
	/// register for a purpose other than as a frame pointer.
	PE_IMAGE_DEBUG_TYPE_FPO	= 3,
	/// The location of DBG file.
	PE_IMAGE_DEBUG_TYPE_MISC	= 4,
	/// A copy of .pdata section.
	PE_IMAGE_DEBUG_TYPE_EXCEPTION	= 5,
	/// Reserved.
	PE_IMAGE_DEBUG_TYPE_FIXUP	= 6,
	/// The mapping from an RVA in image to an RVA in source image.
	PE_IMAGE_DEBUG_TYPE_OMAP_TO_SRC	= 7,
	/// The mapping from an RVA in source image to an RVA in image.
	PE_IMAGE_DEBUG_TYPE_OMAP_FROM_SRC	= 8,
	/// Reserved for Borland.
	PE_IMAGE_DEBUG_TYPE_BORLAND	= 9,
	/// Reserved.
	PE_IMAGE_DEBUG_TYPE_RESERVED10	= 10,
	/// Reserved.
	PE_IMAGE_DEBUG_TYPE_CLSID	= 11,
	/// Undocumented, from winnt.h
	PE_IMAGE_DEBUG_TYPE_VC_FEATURE	= 12,
	/// Profile Guided Optimization.
	/// See: https://devblogs.microsoft.com/cppblog/pogo/
	PE_IMAGE_DEBUG_TYPE_POGO	= 13,
	/// Incremental Link Time Code Generation.
	/// See: https://devblogs.microsoft.com/cppblog/speeding-up-the-incremental-developer-build-scenario/
	PE_IMAGE_DEBUG_TYPE_ILTCG	= 14,
	/// Uses Intel MPX
	PE_IMAGE_DEBUG_TYPE_MPX	= 15,
	/// PE determinism or reproducibility.
	PE_IMAGE_DEBUG_TYPE_REPRO	= 16,
	/// Embedded Portable PDB Debug Directory Entry
	PE_IMAGE_DEBUG_TYPE_EMBEDDED	= 17,
	/// Crypto hash of the content of the symbol file the PE/COFF file was built with.
	PE_IMAGE_DEBUG_TYPE_HASH	= 19,
	/// Extended DLL characteristics bits.
	PE_IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS	= 20,
	/// R2R PerfMap Debug Directory Entry
	PE_IMAGE_DEBUG_TYPE_R2R_PERFMAP	= 21,
}

// Magics for debug structures
enum : uint {
	PE_IMAGE_DEBUG_MAGIC_CODEVIEW_LINK510	= CHAR32!"NB02", /// MS LINK 5.10
	PE_IMAGE_DEBUG_MAGIC_CODEVIEW_LINK520	= CHAR32!"NB05", /// MS LINK 5.20
	PE_IMAGE_DEBUG_MAGIC_CODEVIEW_QUICKC	= CHAR32!"NB07", /// Quick C for Windows 1.0
	PE_IMAGE_DEBUG_MAGIC_CODEVIEW_CV400	= CHAR32!"NB08", /// PDB 2.0+ / CodeView 4.00-4.05
	PE_IMAGE_DEBUG_MAGIC_CODEVIEW_CV410	= CHAR32!"NB09", /// PDB 2.0+ / CodeView 4.10
	PE_IMAGE_DEBUG_MAGIC_CODEVIEW_PDB20PLUS	= CHAR32!"NB10", /// PDB 2.0+ / MS C/C++ PDB 2.0
	PE_IMAGE_DEBUG_MAGIC_CODEVIEW_CV500	= CHAR32!"NB11", /// PDB 2.0+ / CodeView 5.0
	PE_IMAGE_DEBUG_MAGIC_CODEVIEW_CV700	= CHAR32!"RSDS", /// PDB 7.0 / CodeView 7.0
	// Mono source has it set as 0x4244504d
	PE_IMAGE_DEBUG_MAGIC_EMBEDDED_PPDB	= CHAR32!"MPDB", /// Portable PDB
	PE_IMAGE_DEBUG_MAGIC_PPDB	= CHAR32!"BSJB", /// Portable PDB
	// Source: SystemInformer, except for full names
	PE_IMAGE_DEBUG_MAGIC_POGO_LTCG	= CHAR32!"LTCG",  /// Link-Time Code Generation
	PE_IMAGE_DEBUG_MAGIC_POGO_PGU	= CHAR32!"PGU\0", /// Profile Guided Update (/LTCG:PGUPDATE)
}

struct PE_DEBUG_DATA_MISC { align(1):
	char[4] Signature;	/// 
	uint DataType;	/// Must be 1
	uint Length;	/// Multiple of four; Total length of data block
	bool Unicode;	/// If true, Unicode string
	byte[3] Reserved;
	byte[1] Data;
}

/// CodeView format for PDB 2.0 and above
// See http://www.debuginfo.com/articles/debuginfomatch.html
struct PE_DEBUG_DATA_CODEVIEW_PDB20 { align(1):
	// Old PE32 doc mentions "NB05" -- CodeView 4.0 or earlier?
	char[4] Signature;	/// Magic: "NB09"/"NB10"/"NB11" bytes
	/// Offset to the start of the actual debug information from the
	/// beginning of the CodeView data. Zero if it's another file.
	uint32_t Offset;
	uint32_t Timestamp;	///
	uint32_t Age;	/// incremented each time the executable is remade by the linker
	char[1] Path;	/// Path to PDB (0-terminated)
}

/// CodeView format for PDB 7.0
// See http://www.godevtool.com/Other/pdb.htm
// and http://www.debuginfo.com/articles/debuginfomatch.html
struct PE_DEBUG_DATA_CODEVIEW_PDB70 { align(1):
	char[4] Signature;	/// Magic: "RSDS" bytes
	UID Guid;	/// GUID of PDB file, matches with PDB file
	uint32_t Age;	/// incremented each time the executable is remade by the linker
	char[1] Path;	/// Path to PDB (0-terminated UTF-8)
}

/// Declares that debugging information is embedded in the PE file at location
/// specified by PointerToRawData.
// https://github.com/dotnet/runtime/blob/main/docs/design/specs/PE-COFF.md
// Version Major=any, Minor=0x0100 of the data format:
struct PE_DEBUG_DATA_EMBEDDED { align(1):
	char[4] Signature;	/// Magic: "MPDB"
	uint UncompressedSize;
	// SizeOfData - 8: PortablePdbImage
	//                 Portable PDB image compressed using Deflate algorithm
	ubyte[1] PortablePdbImage;
}

/// POGO Entry containing filename. Should be ending with .PGD (Profile-Guided Database).
struct PE_DEBUG_POGO_ENTRY {
	uint Magic;
	uint Rva;
	uint Size;
	char[1] Name;
}

// aka MetadataRootHeader
struct PE_DEBUG_DATA_PPDB {
	/// Magic signature for physical metadata : 0x424A5342.
	// or "BSJB"
	char[4] Signature;
	/// Major version, 1 (ignore on read)
	ushort MajorVersion;
	/// Minor version, 1 (ignore on read)
	ushort MinorVersion;
	/// Reserved, always 0.
	uint Reserved;
	/// Length of version string, multi-byte.
	uint Length;
	/// UTF-8 "Version" string.
	// 4-Byte aligned, maximum 255 (?).
	// Values:
	// - "PDB v1.00" with a value of 12 (.NET 6)
	// - "Standard CLI 2002" (17 chars, so rounded to 20 chars)
	char[1] Version;
}
// After MetadataRootHeader + Version string
struct PE_DEBUG_DATA_PPDB_FLAGS {
	ushort Flags;
	ushort Streams;
}

struct PE_DEBUG_DATA_PPDB_STREAM {
	uint Offset;
	uint Size;
	char[1] Name;
}

/// Declares that the image has an associated PerfMap file containing a table
/// mapping symbols to offsets for ready to run compilations.
// Version Major=0x0001, Minor=0x0000 of the entry data format is following:
struct PE_DEBUG_DATA_R2R_PERFMAP { align(1):
	char[4] Magic;	/// "R2RM"
	/// Byte sequence uniquely identifying the associated PerfMap.
	ubyte[16] Signature;
	/// Version number of the PerfMap. Currently only version 1 is supported.
	uint Version;
	/// UTF-8 NUL-terminated path to the associated .r2rmap file.
	char[1] Path;
}

struct PE_LOAD_CONFIG_CODE_INTEGRITY { align(1):
	uint16_t Flags;	// Flags to indicate if CI information is available, etc.
	uint16_t Catalog;	// 0xFFFF means not available
	uint32_t CatalogOffset;
	uint32_t Reserved;	// Additional bitmask to be defined later
}

/// IMAGE_LOAD_CONFIG_DIRECTORY32
//TODO: Map sizes to WindowsNT versions
//      Or very likely MSVC linker versions
struct PE_LOAD_CONFIG_DIR32 { align(1):
	// Windows XP and after
	uint32_t Size; // Doc: Characteristics, header: Size, Windows XP=64
	uint32_t TimeDateStamp; // time_t
	uint16_t MajorVersion;
	uint16_t MinorVersion;
	uint32_t GlobalFlagsClear;
	uint32_t GlobalFlagsSet;
	uint32_t CriticalSectionDefaultTimeout;
	uint32_t DeCommitFreeBlockThreshold;
	uint32_t DeCommitTotalBlockThreshold;
	uint32_t LockPrefixTable;
	uint32_t MaximumAllocationSize;
	uint32_t VirtualMemoryThreshold;
	uint32_t ProcessHeapFlags;
	uint32_t ProcessAffinityMask;
	uint16_t CSDVersion;
	uint16_t Reserved1;
	uint32_t EditList;
	// Windows 7 and later
	uint32_t SecurityCookie;
	uint32_t SEHandlerTable;
	uint32_t SEHandlerCount;
	uint32_t GuardCFCheckFunctionPointer; // Control Flow
	uint32_t GuardCFDispatchFunctionPointer;
	uint32_t GuardCFFunctionTable;
	uint32_t GuardCFFunctionCount;
	// Windows 8 and later?
	uint32_t GuardFlags;
	PE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
	uint32_t GuardAddressTakenIatEntryTable;
	uint32_t GuardAddressTakenIatEntryCount;
	uint32_t GuardLongJumpTargetTable;
	uint32_t GuardLongJumpTargetCount; // Windows 8's limit?
	// Windows 10 and later?
	uint32_t DynamicValueRelocTable;	// VA
	uint32_t CHPEMetadataPointer;
	uint32_t GuardRFFailureRoutine;	// VA
	uint32_t GuardRFFailureRoutineFunctionPointer;	// VA
	uint32_t DynamicValueRelocTableOffset;
	uint16_t DynamicValueRelocTableSection;
	uint16_t Reserved2;
	uint32_t GuardRFVerifyStackPointerFunctionPointer;	// VA
	uint32_t HotPatchTableOffset;
	uint32_t Reserved3;
	uint32_t EnclaveConfigurationPointer;	// VA
	uint32_t VolatileMetadataPointer;	// VA
}

/// IMAGE_LOAD_CONFIG_DIRECTORY64
//TODO: Map sizes to WindowsNT versions
//      Or MSVC linker versions
struct PE_LOAD_CONFIG_DIR64 { align(1):
	uint32_t Size; // Characteristics
	uint32_t TimeDateStamp; // time_t
	uint16_t MajorVersion;
	uint16_t MinorVersion;
	uint32_t GlobalFlagsClear;
	uint32_t GlobalFlagsSet;
	uint32_t CriticalSectionDefaultTimeout;
	uint64_t DeCommitFreeBlockThreshold;
	uint64_t DeCommitTotalBlockThreshold;
	uint64_t LockPrefixTable;
	uint64_t MaximumAllocationSize;
	uint64_t VirtualMemoryThreshold;
	uint64_t ProcessAffinityMask;
	uint32_t ProcessHeapFlags;
	uint16_t CSDVersion;
	uint16_t Reserved1;
	uint64_t EditList;
	// Windows 7 and later
	uint64_t SecurityCookie;
	uint64_t SEHandlerTable;
	uint64_t SEHandlerCount;
	uint64_t GuardCFCheckFunctionPointer; // Control Flow
	uint64_t GuardCFDispatchFunctionPointer;
	uint64_t GuardCFFunctionTable;
	uint64_t GuardCFFunctionCount;
	uint32_t GuardFlags;
	// Windows 8 and later?
	PE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
	uint64_t GuardAddressTakenIatEntryTable;
	uint64_t GuardAddressTakenIatEntryCount;
	uint64_t GuardLongJumpTargetTable;
	uint64_t GuardLongJumpTargetCount;
	// Windows 10 and later?
	uint64_t DynamicValueRelocTable;         // VA
	uint64_t CHPEMetadataPointer;            // VA
	uint64_t GuardRFFailureRoutine;          // VA
	uint64_t GuardRFFailureRoutineFunctionPointer; // VA
	uint32_t DynamicValueRelocTableOffset;
	uint16_t DynamicValueRelocTableSection;
	uint16_t Reserved2;
	uint64_t GuardRFVerifyStackPointerFunctionPointer; // VA
	uint32_t HotPatchTableOffset;
	uint32_t Reserved3;
	uint64_t EnclaveConfigurationPointer;     // VA
	uint64_t VolatileMetadataPointer;         // VA
}

struct PE_SECTION_ENTRY { align(1):
	/// An 8-byte, null-padded UTF-8 encoded string. If
	/// the string is exactly 8 characters long, there is
	/// no terminating null. For longer names, this field
	/// contains a slash (/) that is followed by an ASCII
	/// representation of a decimal number that is an
	/// offset into the string table. Executable images
	/// do not use a string table and do not support
	/// section names longer than 8 characters. Long
	/// names in object files are truncated if they are
	/// emitted to an executable file.
	char[8] Name;
	/// The total size of the section when loaded into
	/// memory. If this value is greater than
	/// SizeOfRawData, the section is zero-padded. This
	/// field is valid only for executable images and
	/// should be set to zero for object files.
	uint32_t VirtualSize;
	/// For executable images, the address of the first
	/// byte of the section relative to the image base
	/// when the section is loaded into memory. For
	/// object files, this field is the address of the first
	/// byte before relocation is applied; for simplicity,
	/// compilers should set this to zero. Otherwise, it
	/// is an arbitrary value that is subtracted from
	/// offsets during relocation.
	uint32_t VirtualAddress;
	/// The size of the section (for object files) or the
	/// size of the initialized data on disk (for image
	/// files). For executable images, this must be a
	/// multiple of FileAlignment from the optional
	/// header. If this is less than VirtualSize, the
	/// remainder of the section is zero-filled. Because
	/// the SizeOfRawData field is rounded but the
	/// VirtualSize field is not, it is possible for
	/// SizeOfRawData to be greater than VirtualSize as
	/// well. When a section contains only uninitialized
	/// data, this field should be zero.
	uint32_t SizeOfRawData;
	/// The file pointer to the first page of the section
	/// within the COFF file. For executable images, this
	/// must be a multiple of FileAlignment from the
	/// optional header. For object files, the value
	/// should be aligned on a 4-byte boundary for best
	/// performance. When a section contains only
	/// uninitialized data, this field should be zero.
	uint32_t PointerToRawData;
	/// The file pointer to the beginning of relocation
	/// entries for the section. This is set to zero for
	/// executable images or if there are no
	/// relocations.
	uint32_t PointerToRelocations;
	/// The file pointer to the beginning of line-number
	/// entries for the section. This is set to zero if
	/// there are no COFF line numbers. This value
	/// should be zero for an image because COFF
	/// debugging information is deprecated.
	uint32_t PointerToLinenumbers;
	/// The number of relocation entries for the
	/// section. This is set to zero for executable
	/// images.
	uint16_t NumberOfRelocations;
	/// The number of line-number entries for the
	/// section. This value should be zero for an image
	/// because COFF debugging information is
	/// deprecated.
	uint16_t NumberOfLinenumbers;
	/// The flags that describe the characteristics of the
	/// section.
	uint32_t Characteristics;
}

/// (Internal) Called by the server to preload a PE object.
/// Params: o = Object instance.
/// Returns: Error code.
int adbg_object_pe_load(adbg_object_t *o) {
	if (o.file_size < MINIMUM_SIZE)
		return adbg_oops(AdbgError.objectTooSmall);
	
	o.format = AdbgObject.pe;
	
	// Boundchecks are done later
	void *base = o.i.mz.newbase;
	o.i.pe.header = cast(PE_HEADER*)base;
	o.i.pe.opt_header = cast(PE_OPTIONAL_HEADER*)(base + PE_OFFSET_OPTHDR);
	
	with (o.i.pe.header)
	if (o.p.reversed) {
		Signature32	= adbg_bswap32(Signature32);
		Machine	= adbg_bswap16(Machine);
		NumberOfSections	= adbg_bswap16(NumberOfSections);
		TimeDateStamp	= adbg_bswap32(TimeDateStamp);
		PointerToSymbolTable	= adbg_bswap32(PointerToSymbolTable);
		NumberOfSymbols	= adbg_bswap32(NumberOfSymbols);
		SizeOfOptionalHeader	= adbg_bswap16(SizeOfOptionalHeader);
		Characteristics	= adbg_bswap16(Characteristics);
		
		with (o.i.pe.opt_header) Magic = adbg_bswap16(Magic);
	}
	
	switch (o.i.pe.opt_header.Magic) {
	case PE_FMT_32:
		if (adbg_object_outboundpl(o, o.i.pe.opt_header, PE_OPTIONAL_HEADER.sizeof))
			return adbg_oops(AdbgError.objectOutsideBounds);
		
		o.i.pe.directory = cast(PE_IMAGE_DATA_DIRECTORY*)(base + PE_OFFSET_DIR_OPTHDR32);
		if (adbg_object_outboundpl(o, o.i.pe.directory, PE_IMAGE_DATA_DIRECTORY.sizeof))
			return adbg_oops(AdbgError.objectOutsideBounds);
		
		o.i.pe.sections = cast(PE_SECTION_ENTRY*)(base + PE_OFFSET_SEC_OPTHDR32);
		if (adbg_object_outboundpl(o, o.i.pe.sections,
			PE_SECTION_ENTRY.sizeof * o.i.pe.header.NumberOfSections))
			return adbg_oops(AdbgError.objectOutsideBounds);
		
		if (o.p.reversed) {
			PE_OPTIONAL_HEADER *hdr = o.i.pe.opt_header;
			hdr.SizeOfCode	= adbg_bswap32(hdr.SizeOfCode);
			hdr.SizeOfInitializedData	= adbg_bswap32(hdr.SizeOfInitializedData);
			hdr.SizeOfUninitializedData	= adbg_bswap32(hdr.SizeOfUninitializedData);
			hdr.AddressOfEntryPoint	= adbg_bswap32(hdr.AddressOfEntryPoint);
			hdr.BaseOfCode	= adbg_bswap32(hdr.BaseOfCode);
			hdr.BaseOfData	= adbg_bswap32(hdr.BaseOfData);
			hdr.ImageBase	= adbg_bswap32(hdr.ImageBase);
			hdr.SectionAlignment	= adbg_bswap32(hdr.SectionAlignment);
			hdr.FileAlignment	= adbg_bswap32(hdr.FileAlignment);
			hdr.MajorOperatingSystemVersion	= adbg_bswap16(hdr.MajorOperatingSystemVersion);
			hdr.MinorOperatingSystemVersion	= adbg_bswap16(hdr.MinorOperatingSystemVersion);
			hdr.MajorImageVersion	= adbg_bswap16(hdr.MajorImageVersion);
			hdr.MinorImageVersion	= adbg_bswap16(hdr.MinorImageVersion);
			hdr.MajorSubsystemVersion	= adbg_bswap16(hdr.MajorSubsystemVersion);
			hdr.MinorSubsystemVersion	= adbg_bswap16(hdr.MinorSubsystemVersion);
			hdr.Win32VersionValue	= adbg_bswap32(hdr.Win32VersionValue);
			hdr.SizeOfImage	= adbg_bswap32(hdr.SizeOfImage);
			hdr.SizeOfHeaders	= adbg_bswap32(hdr.SizeOfHeaders);
			hdr.CheckSum	= adbg_bswap32(hdr.CheckSum);
			hdr.Subsystem	= adbg_bswap16(hdr.Subsystem);
			hdr.DllCharacteristics	= adbg_bswap16(hdr.DllCharacteristics);
			hdr.SizeOfStackReserve	= adbg_bswap32(hdr.SizeOfStackReserve);
			hdr.SizeOfStackCommit	= adbg_bswap32(hdr.SizeOfStackCommit);
			hdr.SizeOfHeapReserve	= adbg_bswap32(hdr.SizeOfHeapReserve);
			hdr.SizeOfHeapCommit	= adbg_bswap32(hdr.SizeOfHeapCommit);
			hdr.LoaderFlags	= adbg_bswap32(hdr.LoaderFlags);
			hdr.NumberOfRvaAndSizes	= adbg_bswap32(hdr.NumberOfRvaAndSizes);
		}
		break;
	case PE_FMT_64:
		if (adbg_object_outboundpl(o, o.i.pe.opt_header, PE_OPTIONAL_HEADER64.sizeof))
			return adbg_oops(AdbgError.objectOutsideBounds);
		
		o.i.pe.directory = cast(PE_IMAGE_DATA_DIRECTORY*)(base + PE_OFFSET_DIR_OPTHDR64);
		if (adbg_object_outboundpl(o, o.i.pe.directory, PE_IMAGE_DATA_DIRECTORY.sizeof))
			return adbg_oops(AdbgError.objectOutsideBounds);
		
		o.i.pe.sections = cast(PE_SECTION_ENTRY*)(base + PE_OFFSET_SEC_OPTHDR64);
		if (adbg_object_outboundpl(o, o.i.pe.sections,
			PE_SECTION_ENTRY.sizeof * o.i.pe.header.NumberOfSections))
			return adbg_oops(AdbgError.objectOutsideBounds);
		
		if (o.p.reversed) {
			PE_OPTIONAL_HEADER64 *hdr = o.i.pe.opt_header64;
			hdr.SizeOfCode	= adbg_bswap32(hdr.SizeOfCode);
			hdr.SizeOfInitializedData	= adbg_bswap32(hdr.SizeOfInitializedData);
			hdr.SizeOfUninitializedData	= adbg_bswap32(hdr.SizeOfUninitializedData);
			hdr.AddressOfEntryPoint	= adbg_bswap32(hdr.AddressOfEntryPoint);
			hdr.BaseOfCode	= adbg_bswap32(hdr.BaseOfCode);
			hdr.ImageBase	= adbg_bswap64(hdr.ImageBase);
			hdr.SectionAlignment	= adbg_bswap32(hdr.SectionAlignment);
			hdr.FileAlignment	= adbg_bswap32(hdr.FileAlignment);
			hdr.MajorOperatingSystemVersion	= adbg_bswap16(hdr.MajorOperatingSystemVersion);
			hdr.MinorOperatingSystemVersion	= adbg_bswap16(hdr.MinorOperatingSystemVersion);
			hdr.MajorImageVersion	= adbg_bswap16(hdr.MajorImageVersion);
			hdr.MinorImageVersion	= adbg_bswap16(hdr.MinorImageVersion);
			hdr.MajorSubsystemVersion	= adbg_bswap16(hdr.MajorSubsystemVersion);
			hdr.MinorSubsystemVersion	= adbg_bswap16(hdr.MinorSubsystemVersion);
			hdr.Win32VersionValue	= adbg_bswap32(hdr.Win32VersionValue);
			hdr.SizeOfImage	= adbg_bswap32(hdr.SizeOfImage);
			hdr.SizeOfHeaders	= adbg_bswap32(hdr.SizeOfHeaders);
			hdr.CheckSum	= adbg_bswap32(hdr.CheckSum);
			hdr.Subsystem	= adbg_bswap16(hdr.Subsystem);
			hdr.DllCharacteristics	= adbg_bswap16(hdr.DllCharacteristics);
			hdr.SizeOfStackReserve	= adbg_bswap64(hdr.SizeOfStackReserve);
			hdr.SizeOfStackCommit	= adbg_bswap64(hdr.SizeOfStackCommit);
			hdr.SizeOfHeapReserve	= adbg_bswap64(hdr.SizeOfHeapReserve);
			hdr.SizeOfHeapCommit	= adbg_bswap64(hdr.SizeOfHeapCommit);
			hdr.LoaderFlags	= adbg_bswap32(hdr.LoaderFlags);
			hdr.NumberOfRvaAndSizes	= adbg_bswap32(hdr.NumberOfRvaAndSizes);
		}
		break;
	case PE_FMT_ROM: // NOTE: ROM have no optional header and directories
		o.i.pe.directory = null;
		o.i.pe.sections = cast(PE_SECTION_ENTRY*)(base + PE_OFFSET_SEC_OPTHDRROM);
		if (adbg_object_outboundpl(o, o.i.pe.sections,
			PE_SECTION_ENTRY.sizeof * o.i.pe.header.NumberOfSections))
			return adbg_oops(AdbgError.objectOutsideBounds);
		
		if (o.p.reversed) {
			PE_OPTIONAL_HEADERROM *hdr = o.i.pe.opt_headerrom;
			hdr.SizeOfCode	= adbg_bswap32(hdr.SizeOfCode);
			hdr.SizeOfInitializedData	= adbg_bswap32(hdr.SizeOfInitializedData);
			hdr.SizeOfUninitializedData	= adbg_bswap32(hdr.SizeOfUninitializedData);
			hdr.AddressOfEntryPoint	= adbg_bswap32(hdr.AddressOfEntryPoint);
			hdr.BaseOfCode	= adbg_bswap32(hdr.BaseOfCode);
			hdr.BaseOfData	= adbg_bswap32(hdr.BaseOfData);
			hdr.BaseOfBss	= adbg_bswap32(hdr.BaseOfBss);
			hdr.GprMask	= adbg_bswap32(hdr.GprMask);
			hdr.CprMask[0]	= adbg_bswap32(hdr.CprMask[0]);
			hdr.CprMask[1]	= adbg_bswap32(hdr.CprMask[1]);
			hdr.CprMask[2]	= adbg_bswap32(hdr.CprMask[2]);
			hdr.CprMask[3]	= adbg_bswap32(hdr.CprMask[3]);
			hdr.GpValue	= adbg_bswap32(hdr.GpValue);
		}
		return 0;
	default:
		return adbg_oops(AdbgError.unsupportedObjFormat);
	}
	
	if (o.p.reversed && o.i.pe.directory) with (o.i.pe.directory) {
		ExportTable.rva	= adbg_bswap32(ExportTable.rva);
		ExportTable.size	= adbg_bswap32(ExportTable.size);
		ImportTable.rva	= adbg_bswap32(ImportTable.rva);
		ImportTable.size	= adbg_bswap32(ImportTable.size);
		ResourceTable.rva	= adbg_bswap32(ResourceTable.rva);
		ResourceTable.size	= adbg_bswap32(ResourceTable.size);
		ExceptionTable.rva	= adbg_bswap32(ExceptionTable.rva);
		ExceptionTable.size	= adbg_bswap32(ExceptionTable.size);
		CertificateTable.rva	= adbg_bswap32(CertificateTable.rva);
		CertificateTable.size	= adbg_bswap32(CertificateTable.size);
		BaseRelocationTable.rva	= adbg_bswap32(BaseRelocationTable.rva);
		BaseRelocationTable.size	= adbg_bswap32(BaseRelocationTable.size);
		DebugDirectory.rva	= adbg_bswap32(DebugDirectory.rva);
		DebugDirectory.size	= adbg_bswap32(DebugDirectory.size);
		ArchitectureData.rva	= adbg_bswap32(ArchitectureData.rva);
		ArchitectureData.size	= adbg_bswap32(ArchitectureData.size);
		GlobalPtr.rva	= adbg_bswap32(GlobalPtr.rva);
		GlobalPtr.size	= adbg_bswap32(GlobalPtr.size);
		TLSTable.rva	= adbg_bswap32(TLSTable.rva);
		TLSTable.size	= adbg_bswap32(TLSTable.size);
		LoadConfigurationTable.rva	= adbg_bswap32(LoadConfigurationTable.rva);
		LoadConfigurationTable.size	= adbg_bswap32(LoadConfigurationTable.size);
		BoundImportTable.rva	= adbg_bswap32(BoundImportTable.rva);
		BoundImportTable.size	= adbg_bswap32(BoundImportTable.size);
		ImportAddressTable.rva	= adbg_bswap32(ImportAddressTable.rva);
		ImportAddressTable.size	= adbg_bswap32(ImportAddressTable.size);
		DelayImport.rva	= adbg_bswap32(DelayImport.rva);
		DelayImport.size	= adbg_bswap32(DelayImport.size);
		CLRHeader.rva	= adbg_bswap32(CLRHeader.rva);
		CLRHeader.size	= adbg_bswap32(CLRHeader.size);
		Reserved.rva	= adbg_bswap32(Reserved.rva);
		Reserved.size	= adbg_bswap32(Reserved.size);
	}
	
	if (o.p.reversed) {
		if (o.i.pe.header.NumberOfSections) {
			o.i.pe.reversed_sections = cast(bool*)
				calloc(o.i.pe.header.NumberOfSections, bool.sizeof);
			if (o.i.pe.reversed_sections == null)
				return adbg_oops(AdbgError.crt);
		}
		with (o.i.pe.directory.ExportTable) if (size && rva) {
			size_t count = size / PE_EXPORT_DESCRIPTOR.sizeof;
			o.i.pe.reversed_dir_exports = false;
			o.i.pe.reversed_dir_export_entries = cast(bool*)calloc(count, bool.sizeof);
			if (o.i.pe.reversed_dir_export_entries == null)
				return adbg_oops(AdbgError.crt);
		}
		with (o.i.pe.directory.ImportTable) if (size && rva) {
			size_t count = size / PE_IMPORT_DESCRIPTOR.sizeof;
			o.i.pe.reversed_dir_imports = cast(bool*)calloc(count, bool.sizeof);
			if (o.i.pe.reversed_dir_imports == null)
				return adbg_oops(AdbgError.crt);
		}
		with (o.i.pe.directory.DebugDirectory) if (size && rva) {
			size_t count = size / PE_DEBUG_DIRECTORY.sizeof;
			o.i.pe.reversed_dir_debug = cast(bool*)calloc(count, bool.sizeof);
			if (o.i.pe.reversed_dir_debug == null)
				return adbg_oops(AdbgError.crt);
		}
	}
	
	return 0;
}

//TODO: Calculate VA function
//      FileOffset = Section.RawPtr + (Directory.RVA - Section.RVA)

// maps rva to section if found
void* adbg_object_pe_locate(adbg_object_t *o, uint rva) {
	if (o == null) return null;
	
	uint sections = o.i.pe.header.NumberOfSections;
	for (uint si; si < sections; ++si) {
		PE_SECTION_ENTRY s = o.i.pe.sections[si];
		
		uint va = s.VirtualAddress;
		
		version (Trace) trace("va=%x rva=%x", va, rva);
		
		if (va > rva || va + s.SizeOfRawData <= rva)
			continue;
		
		void* a = o.buffer + (s.PointerToRawData + (rva - va));
		if (adbg_object_outboundp(o, a)) {
			adbg_oops(AdbgError.objectOutsideBounds);
			return null;
		}
		return a;
	}
	
	version (Trace) trace("null");
	return null;
}

PE_HEADER* adbg_object_pe_header(adbg_object_t *o) {
	if (o == null) return null;
	return o.i.pe.header;
}

PE_OPTIONAL_HEADER* adbg_object_pe_optheader(adbg_object_t *o) {
	if (o == null) return null;
	return o.i.pe.opt_header;
}

PE_OPTIONAL_HEADER64* adbg_object_pe_optheader64(adbg_object_t *o) {
	if (o == null) return null;
	return o.i.pe.opt_header64;
}

PE_OPTIONAL_HEADERROM* adbg_object_pe_optheaderrom(adbg_object_t *o) {
	if (o == null) return null;
	return o.i.pe.opt_headerrom;
}

PE_SECTION_ENTRY* adbg_object_pe_section(adbg_object_t *o, size_t index) {
	version (Trace) trace("o=%p index=%u", o, cast(uint)index);
	
	if (o == null) return null;
	if (o.i.pe.sections == null) return null;
	if (index > MAXIMUM_SECTIONS) return null;
	if (index >= o.i.pe.header.NumberOfSections) return null;
	
	PE_SECTION_ENTRY *section = &o.i.pe.sections[index];
	if (o.p.reversed && o.i.pe.reversed_sections[index] == false) with (section) {
		VirtualSize	= adbg_bswap32(VirtualSize);
		VirtualAddress	= adbg_bswap32(VirtualAddress);
		SizeOfRawData	= adbg_bswap32(SizeOfRawData);
		PointerToRawData	= adbg_bswap32(PointerToRawData);
		PointerToRelocations	= adbg_bswap32(PointerToRelocations);
		PointerToLinenumbers	= adbg_bswap32(PointerToLinenumbers);
		NumberOfRelocations	= adbg_bswap16(NumberOfRelocations);
		NumberOfLinenumbers	= adbg_bswap16(NumberOfLinenumbers);
		Characteristics	= adbg_bswap32(Characteristics);
		o.i.pe.reversed_sections[index] = true;
	}
	return section;
}

// TODO:
// - [x] ExportTable
// - [x] ImportTable
// - [ ] ResourceTable
// - [ ] ExceptionTable
// - [ ] CertificateTable
// - [ ] BaseRelocationTable
// - [x] DebugDirectory
// - [ ] ArchitectureData
// - [ ] GlobalPtr
// - [ ] TLSTable
// - [ ] LoadConfigurationTable
// - [ ] BoundImportTable
// - [ ] ImportAddressTable
// - [ ] DelayImport
// - [ ] CLRHeader

//
// Export directory functions
//
// One descriptortable, multiple entries, because one module can emit one table.
//   Name -> Name of the module
//   ExportAddressTable -> raw address to RVAs
//     AddressTableEntries for count
//     RVA -> hint + entry

PE_EXPORT_DESCRIPTOR* adbg_object_pe_export(adbg_object_t *o) {
	if (o == null) return null;
	if (o.i.pe.directory == null) return null;
	
	// Set base
	with (o.i.pe)
	if (directory_exports == null) {
		directory_exports = cast(PE_EXPORT_DESCRIPTOR*)
			adbg_object_pe_locate(o, directory.ExportTable.rva);
		// Not found
		if (directory_exports == null) return null;
	}
	
	// adbg_object_pe_locate checked pointer bounds
	PE_EXPORT_DESCRIPTOR* exportdir = o.i.pe.directory_exports;
	
	// ExportFlags must be zero
	if (exportdir.ExportFlags != 0) return null;
	
	if (o.p.reversed && o.i.pe.reversed_dir_exports == false) with (exportdir) {
		ExportFlags	= adbg_bswap32(ExportFlags);
		Timestamp	= adbg_bswap32(Timestamp);
		MajorVersion	= adbg_bswap16(MajorVersion);
		MinorVersion	= adbg_bswap16(MinorVersion);
		Name	= adbg_bswap32(Name);
		OrdinalBase	= adbg_bswap32(OrdinalBase);
		AddressTableEntries	= adbg_bswap32(AddressTableEntries);
		NumberOfNamePointers	= adbg_bswap32(NumberOfNamePointers);
		ExportAddressTable	= adbg_bswap32(ExportAddressTable);
		NamePointer	= adbg_bswap32(NamePointer);
		OrdinalTable	= adbg_bswap32(OrdinalTable);
		o.i.pe.reversed_dir_exports = true;
	}
	
	return exportdir;
}

const(char)* adbg_object_pe_export_name(adbg_object_t *o, PE_EXPORT_DESCRIPTOR *export_) {
	if (o == null || export_ == null) return null;
	if (o.i.pe.directory == null) return null;
	if (o.i.pe.directory_exports == null) return null;
	
	const(char) *name =
		cast(const(char)*)o.i.pe.directory_exports
		- o.i.pe.directory.ExportTable.rva
		+ export_.Name;
	
	if (adbg_object_outboundp(o, cast(void*)name)) {
		adbg_oops(AdbgError.objectOutsideBounds);
		return null;
	}
	
	return name;
}

PE_EXPORT_ENTRY* adbg_object_pe_export_name_entry(adbg_object_t *o, PE_EXPORT_DESCRIPTOR *export_, size_t index) {
	if (o == null || export_ == null) return null;
	if (o.i.pe.directory == null) return null;
	if (o.i.pe.directory_exports == null) return null;
	if (index >= export_.NumberOfNamePointers) return null;
	
	// Check bounds with table RVA
	void *base = cast(void*)o.i.pe.directory_exports
		- o.i.pe.directory.ExportTable.rva
		+ export_.NamePointer;
	if (adbg_object_outboundp(o, base)) {
		adbg_oops(AdbgError.objectOutsideBounds);
		return null;
	}
	
	// Check bounds with name pointer and requested index
	PE_EXPORT_ENTRY *entry = cast(PE_EXPORT_ENTRY*)base + index;
	if (adbg_object_outboundp(o, entry)) {
		adbg_oops(AdbgError.objectOutsideBounds);
		return null;
	}
	
	if (o.p.reversed && o.i.pe.reversed_dir_export_entries[index] == false) with (entry) {
		entry.Export = adbg_bswap32(entry.Export);
		o.i.pe.reversed_dir_export_entries[index] = true;
	}
	
	return entry;
}

const(char)* adbg_object_pe_export_name_string(adbg_object_t *o, PE_EXPORT_DESCRIPTOR *export_, PE_EXPORT_ENTRY *entry) {
	if (o == null || export_ == null || entry == null)
		return null;
	
	// NOTE: Export Table bounds
	//       If the address specified is not within the export section (as
	//       defined by the address and length that are indicated in the
	//       optional header), the field is an Export RVA: an actual
	//       address in code or data. Otherwise, the field is a Forwarder
	//       RVA, which names a symbol in another DLL.
	
	//TODO: Forwarder check
	//if (entry.Export >= o.i.pe.directory.ExportTable.size)
	//	return null;
	
	// Check bounds with table RVA
	void *base = cast(void*)o.i.pe.directory_exports -
		o.i.pe.directory.ExportTable.rva + entry.Export;
	if (adbg_object_outboundp(o, base)) {
		adbg_oops(AdbgError.objectOutsideBounds);
		return null;
	}
	return cast(const(char)*)base;
}

//
// Import directory functions
//

PE_IMPORT_DESCRIPTOR* adbg_object_pe_import(adbg_object_t *o, size_t index) {
	if (o == null) return null;
	if (o.i.pe.directory == null) return null;
	size_t count = o.i.pe.directory.ImportTable.size / PE_IMPORT_DESCRIPTOR.sizeof;
	if (index >= count) return null;
	
	// Set base
	if (o.i.pe.directory_imports == null) {
		o.i.pe.directory_imports = cast(PE_IMPORT_DESCRIPTOR*)
			adbg_object_pe_locate(o, o.i.pe.directory.ImportTable.rva);
		// Not found
		if (o.i.pe.directory_imports == null) return null;
	}
	
	PE_IMPORT_DESCRIPTOR* import_ = o.i.pe.directory_imports + index;
	if (o.p.reversed && o.i.pe.reversed_dir_imports[index] == false) with (import_) {
		Characteristics	= adbg_bswap32(Characteristics);
		TimeDateStamp	= adbg_bswap32(TimeDateStamp);
		ForwarderChain	= adbg_bswap32(ForwarderChain);
		Name	= adbg_bswap32(Name);
		FirstThunk	= adbg_bswap32(FirstThunk);
		o.i.pe.reversed_dir_imports[index] = true;
	}
	if (import_.Characteristics == 0) return null;
	return import_;
}

char* adbg_object_pe_import_name(adbg_object_t *o, PE_IMPORT_DESCRIPTOR *import_) {
	if (o == null || import_ == null) return null;
	if (o.i.pe.directory == null) return null;
	
	char *s = cast(char*)o.i.pe.directory_imports - o.i.pe.directory.ImportTable.rva + import_.Name;
	
	if (adbg_object_outboundp(o, s)) {
		adbg_oops(AdbgError.objectOutsideBounds);
		return null;
	}
	
	return s;
}

//TODO: Byte-swap import look-up table entries

PE_IMPORT_ENTRY32* adbg_object_pe_import_entry32(adbg_object_t *o, PE_IMPORT_DESCRIPTOR *import_, size_t index) {
	if (o == null || import_ == null) return null;
	if (o.i.pe.directory_imports == null) return null;
	
	PE_IMPORT_ENTRY32* lte32 = cast(PE_IMPORT_ENTRY32*)
		(cast(char*)o.i.pe.directory_imports + (import_.Characteristics - o.i.pe.directory.ImportTable.rva))
		+ index;
	
	if (adbg_object_outboundp(o, lte32) || lte32.ordinal == 0) {
		adbg_oops(AdbgError.objectOutsideBounds);
		return null;
	}
	
	return lte32;
}

ushort* adbg_object_pe_import_entry32_hint(adbg_object_t *o, PE_IMPORT_DESCRIPTOR *import_, PE_IMPORT_ENTRY32 *im32) {
	if (o == null || import_ == null) return null;
	if (o.i.pe.directory_imports == null) return null;
	
	ushort* base = cast(ushort*)
		((cast(char*)o.i.pe.directory_imports - o.i.pe.directory.ImportTable.rva) + im32.rva);
	if (adbg_object_outboundp(o, base)) {
		adbg_oops(AdbgError.objectOutsideBounds);
		return null;
	}
	
	return base;
}

PE_IMPORT_ENTRY64* adbg_object_pe_import_entry64(adbg_object_t *o, PE_IMPORT_DESCRIPTOR *import_, size_t index) {
	if (o == null || import_ == null) return null;
	if (o.i.pe.directory_imports == null) return null;
	
	PE_IMPORT_ENTRY64* lte64 = cast(PE_IMPORT_ENTRY64*)
		(cast(char*)o.i.pe.directory_imports + (import_.Characteristics - o.i.pe.directory.ImportTable.rva))
		+ index;
	
	version (Trace) trace("imports=%p lte64=%p fs=%zx", o.i.pe.directory_imports, lte64, o.file_size);
	
	if (adbg_object_outboundp(o, lte64) || lte64.ordinal == 0) {
		adbg_oops(AdbgError.objectOutsideBounds);
		return null;
	}
	
	return lte64;
}

ushort* adbg_object_pe_import_entry64_hint(adbg_object_t *o, PE_IMPORT_DESCRIPTOR *import_, PE_IMPORT_ENTRY64 *im64) {
	if (o == null || import_ == null) return null;
	if (o.i.pe.directory_imports == null) return null;
	
	ushort* base = cast(ushort*)
		((cast(char*)o.i.pe.directory_imports - o.i.pe.directory.ImportTable.rva) + im64.rva);
	
	version (Trace) trace("base=%p fs=%zx", base, o.file_size);
	
	if (adbg_object_outboundp(o, base)) {
		adbg_oops(AdbgError.objectOutsideBounds);
		return null;
	}
	
	return base;
}

// Import Directory Table -1,*-> lookup tables -1,1-> hint
// Helper function
/+const(char)* adbg_object_pe_import_string_entry(adbg_object_t *o, PE_IMPORT_DESCRIPTOR *import_, size_t index) {
	if (o == null || import_ == null) return null;
	if (o.i.pe.directory_imports == null) return null;
	
	
	switch (o.i.pe.opt_header.Magic) {
	case PE_FMT_32:
		PE_IMPORT_LTE32 *t32 = adbg_object_pe_import_lte32(o, import_, index);
		if (t32 == null) return null;
		return;
	case PE_FMT_64:
		return;
	default:
		return null;
	}
}+/

//
// Debug directory functions
//

PE_DEBUG_DIRECTORY* adbg_object_pe_debug_directory(adbg_object_t *o, size_t index) {
	if (o == null) return null;
	if (o.i.pe.directory == null) return null;
	size_t count = o.i.pe.directory.DebugDirectory.size / PE_DEBUG_DIRECTORY.sizeof;
	if (index >= count) return null;
	
	// Set base
	if (o.i.pe.directory_debug == null) {
		o.i.pe.directory_debug = cast(PE_DEBUG_DIRECTORY*)
			adbg_object_pe_locate(o, o.i.pe.directory.DebugDirectory.rva);
		// Not found
		if (o.i.pe.directory_debug == null) return null;
	}
	
	PE_DEBUG_DIRECTORY* debug_ = o.i.pe.directory_debug + index;
	if (o.p.reversed && o.i.pe.reversed_dir_debug[index] == false) with (debug_) {
		Characteristics	= adbg_bswap32(Characteristics);
		TimeDateStamp	= adbg_bswap32(TimeDateStamp);
		MajorVersion	= adbg_bswap16(MajorVersion);
		MinorVersion	= adbg_bswap16(MinorVersion);
		Type	= adbg_bswap32(Type);
		SizeOfData	= adbg_bswap32(SizeOfData);
		AddressOfRawData	= adbg_bswap32(AddressOfRawData);
		PointerToRawData	= adbg_bswap32(PointerToRawData);
		o.i.pe.reversed_dir_debug[index] = true;
	}
	return debug_;
}

//
// Other helpers
//

AdbgMachine adbg_object_pe_machine(ushort machine) {
	switch (machine) {
	case PE_MACHINE_I386:	return AdbgMachine.x86;
	case PE_MACHINE_AMD64:	return AdbgMachine.amd64;
	case PE_MACHINE_ALPHAOLD, PE_MACHINE_ALPHA:	return AdbgMachine.alpha;
	case PE_MACHINE_ALPHA64:	return AdbgMachine.alpha64;
	case PE_MACHINE_AM33:	return AdbgMachine.am33;
	case PE_MACHINE_ARM:
	case PE_MACHINE_ARMNT:	return AdbgMachine.arm;
	case PE_MACHINE_ARM64:	return AdbgMachine.aarch64;
	case PE_MACHINE_EBC:	return AdbgMachine.ebc;
	case PE_MACHINE_IA64:	return AdbgMachine.ia64;
	case PE_MACHINE_LOONGARCH32:	return AdbgMachine.loongarch32;
	case PE_MACHINE_LOONGARCH64:	return AdbgMachine.loongarch64;
	case PE_MACHINE_M32R:	return AdbgMachine.m32r;
	case PE_MACHINE_MIPS16:	return AdbgMachine.mips16;
	case PE_MACHINE_MIPSFPU:	return AdbgMachine.mipsfpu;
	case PE_MACHINE_MIPSFPU16:	return AdbgMachine.mips16fpu;
	case PE_MACHINE_POWERPC:	return AdbgMachine.ppc;
	case PE_MACHINE_POWERPCFP:	return AdbgMachine.ppcfpu;
	case PE_MACHINE_R3000:	return AdbgMachine.mips;
	case PE_MACHINE_R4000:	return AdbgMachine.mipsii;
	case PE_MACHINE_R10000:	return AdbgMachine.mipsiv;
	case PE_MACHINE_RISCV32:	return AdbgMachine.riscv32;
	case PE_MACHINE_RISCV64:	return AdbgMachine.riscv64;
	case PE_MACHINE_RISCV128:	return AdbgMachine.riscv128;
	case PE_MACHINE_SH3:	return AdbgMachine.sh3;
	case PE_MACHINE_SH3DSP:	return AdbgMachine.sh3dsp;
	case PE_MACHINE_SH4:	return AdbgMachine.sh4;
	case PE_MACHINE_SH5:	return AdbgMachine.sh5;
	case PE_MACHINE_THUMB:	return AdbgMachine.thumb;
	case PE_MACHINE_WCEMIPSV2:	return AdbgMachine.mipswcele;
	case PE_MACHINE_CLR:	return AdbgMachine.clr;
	default:	return AdbgMachine.unknown;
	}
}

const(char) *adbg_object_pe_machine_string(ushort machine) {
	switch (machine) {
	case PE_MACHINE_UNKNOWN:	return "None";
	case PE_MACHINE_ALPHA:	return "DEC Alpha";
	case PE_MACHINE_ALPHA64:	return "DEC Alpha (64-bit)";
	case PE_MACHINE_AM33:	return "Mitsubishi MN10300 (AM33)";
	case PE_MACHINE_AMD64:	return "x86-64";
	case PE_MACHINE_ARM:	return "ARM (32-bit)";
	case PE_MACHINE_ARMNT:	return "ARM Thumb-2 (32-bit)";
	case PE_MACHINE_ARM64:	return "ARM (64-bit)";
	case PE_MACHINE_EBC:	return "EFI Byte Code";
	case PE_MACHINE_I386:	return "Intel x86";
	case PE_MACHINE_IA64:	return "Intel Itanium Architecture 64";
	case PE_MACHINE_LOONGARCH32:	return "LoongArch32";
	case PE_MACHINE_LOONGARCH64:	return "LoongArch64";
	case PE_MACHINE_M32R:	return "Mitsubishi M32R";
	case PE_MACHINE_MIPS16:	return "MIPS16";
	case PE_MACHINE_MIPSFPU:	return "MIPS I with FPU";
	case PE_MACHINE_MIPSFPU16:	return "MIPS16 with FPU";
	case PE_MACHINE_POWERPC:	return "PowerPC";
	case PE_MACHINE_POWERPCFP:	return "PowerPC with FPU";
	case PE_MACHINE_R3000:	return "MIPS I (RS3000) Little-Endian";
	case PE_MACHINE_R4000:	return "MIPS III (R4000)";
	case PE_MACHINE_R10000:	return "MIPS IV (R10000)";
	case PE_MACHINE_RISCV32:	return "RISC-V (32-bit)";
	case PE_MACHINE_RISCV64:	return "RISC-V (64-bit)";
	case PE_MACHINE_RISCV128:	return "RISC-V (128-bit)";
	case PE_MACHINE_SH3:	return "Hitachi SuperH 3";
	case PE_MACHINE_SH3DSP:	return "Hitachi SuperH 3 DSP";
	case PE_MACHINE_SH4:	return "Hitachi SuperH 4";
	case PE_MACHINE_SH5:	return "Hitachi SuperH 5";
	case PE_MACHINE_THUMB:	return "ARM Thumb";
	case PE_MACHINE_WCEMIPSV2:	return "MIPS little-endian WCE v2";
	case PE_MACHINE_CLR:	return "Common Language Runtime";
	default:	return null;
	}
}

const(char) *adbg_object_pe_magic_string(ushort magic) {
	switch (magic) {
	case PE_FMT_32:	return "PE32";
	case PE_FMT_64:	return "PE32+";
	case PE_FMT_ROM:	return "PE-ROM";
	default:	return null;
	}
}

const(char) *adbg_object_pe_subsys_string(ushort subsystem) {
	switch (subsystem) {
	case PE_SUBSYSTEM_NATIVE:	return "Native";
	case PE_SUBSYSTEM_WINDOWS_GUI:	return "Windows GUI";
	case PE_SUBSYSTEM_WINDOWS_CUI:	return "Windows Console";
	case PE_SUBSYSTEM_POSIX_CUI:	return "Posix Console";
	case PE_SUBSYSTEM_NATIVE_WINDOWS:	return "Native Windows 9x Driver";
	case PE_SUBSYSTEM_WINDOWS_CE_GUI:	return "Windows CE GUI";
	case PE_SUBSYSTEM_EFI_APPLICATION:	return "EFI";
	case PE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:	return "EFI Boot Service Driver";
	case PE_SUBSYSTEM_EFI_RUNTIME_DRIVER:	return "EFI Runtime Driver";
	case PE_SUBSYSTEM_EFI_ROM:	return "EFI ROM";
	case PE_SUBSYSTEM_XBOX:	return "XBOX";
	case PE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:	return "Windows Boot";
	default:	return null;
	}
}

const(char) *adbg_object_pe_debug_type_string(uint type) {
	switch (type) {
	case PE_IMAGE_DEBUG_TYPE_UNKNOWN:	return "Unknown";
	case PE_IMAGE_DEBUG_TYPE_COFF:	return "COFF";
	case PE_IMAGE_DEBUG_TYPE_CODEVIEW:	return "CodeView / VC++";
	case PE_IMAGE_DEBUG_TYPE_FPO:	return "FPO (Frame Pointer Omission) Information";
	case PE_IMAGE_DEBUG_TYPE_MISC:	return "DBG File Location";
	case PE_IMAGE_DEBUG_TYPE_EXCEPTION:	return "Exception";
	case PE_IMAGE_DEBUG_TYPE_FIXUP:	return "FIXUP";
	case PE_IMAGE_DEBUG_TYPE_OMAP_TO_SRC:	return "Map RVA to source image RVA";
	case PE_IMAGE_DEBUG_TYPE_OMAP_FROM_SRC:	return "Map source image RVA to RVA";
	case PE_IMAGE_DEBUG_TYPE_BORLAND:	return "Borland";
	case PE_IMAGE_DEBUG_TYPE_RESERVED10:	return "RESERVED10";
	case PE_IMAGE_DEBUG_TYPE_CLSID:	return "CLSID";
	case PE_IMAGE_DEBUG_TYPE_VC_FEATURE:	return "VC FEATURE";
	case PE_IMAGE_DEBUG_TYPE_POGO:	return "Profile Guided Optimization (POGO)";
	case PE_IMAGE_DEBUG_TYPE_ILTCG:	return "Incremental Link Time Code Generation (ILTCG)";
	case PE_IMAGE_DEBUG_TYPE_MPX:	return "Memory protection (Intel MPX)";
	case PE_IMAGE_DEBUG_TYPE_REPRO:	return "PE Reproducibility";
	case PE_IMAGE_DEBUG_TYPE_EMBEDDED:	return "Embedded Portable PDB Debug Directory Entry";
	case PE_IMAGE_DEBUG_TYPE_HASH:	return "PDB Hash";
	case PE_IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS:	return "DLL characteristics";
	case PE_IMAGE_DEBUG_TYPE_R2R_PERFMAP:	return "R2R PerfMap Debug Directory Entry";
	default:	return null;
	}
}

private:

// Rough guesses for OS limits, offsets+4 since missing Size (already read)
// If the count is still misleading, the size check will be performed by field
//TODO: Shouldn't this depend more or less on the linker version?
// Examples:
// putty-x86 0.73: 92
// putty-amd64 0.73: 148
enum PE_LOAD_CONFIG32_LIMIT_XP = 64;
enum PE_LOAD_CONFIG32_LIMIT_7 = PE_LOAD_CONFIG_DIR32.GuardFlags.offsetof + 4;
enum PE_LOAD_CONFIG32_LIMIT_8 = PE_LOAD_CONFIG_DIR32.GuardLongJumpTargetCount.offsetof + 4;
enum PE_LOAD_CONFIG64_LIMIT_XP = PE_LOAD_CONFIG_DIR64.SecurityCookie.offsetof + 4;
enum PE_LOAD_CONFIG64_LIMIT_7 = PE_LOAD_CONFIG_DIR64.GuardFlags.offsetof + 4;
enum PE_LOAD_CONFIG64_LIMIT_8 = PE_LOAD_CONFIG_DIR64.GuardLongJumpTargetCount.offsetof + 4;

enum int PE_DIRECTORY_SIZE = PE_IMAGE_DATA_DIRECTORY.sizeof;
enum int PE_OHDR_SIZE = PE_OPTIONAL_HEADER.sizeof + PE_DIRECTORY_SIZE; // PE32
enum int PE_OHDR64_SIZE = PE_OPTIONAL_HEADER64.sizeof + PE_DIRECTORY_SIZE; // PE32+
enum int PE_OHDRROM_SIZE = PE_OPTIONAL_HEADERROM.sizeof + PE_DIRECTORY_SIZE; // PE-ROM

enum PE_OFFSET_OPTHDR        = PE_HEADER.sizeof;
enum PE_OFFSET_DIR_OPTHDR32  = PE_OFFSET_OPTHDR + PE_OPTIONAL_HEADER.sizeof;
enum PE_OFFSET_DIR_OPTHDR64  = PE_OFFSET_OPTHDR + PE_OPTIONAL_HEADER64.sizeof;
enum PE_OFFSET_DIR_OPTHDRROM = PE_OFFSET_OPTHDR + PE_OPTIONAL_HEADERROM.sizeof;
enum PE_OFFSET_SEC_OPTHDR32  = PE_OFFSET_DIR_OPTHDR32 + PE_IMAGE_DATA_DIRECTORY.sizeof;
enum PE_OFFSET_SEC_OPTHDR64  = PE_OFFSET_DIR_OPTHDR64 + PE_IMAGE_DATA_DIRECTORY.sizeof;
enum PE_OFFSET_SEC_OPTHDRROM = PE_OFFSET_DIR_OPTHDRROM + PE_IMAGE_DATA_DIRECTORY.sizeof;
