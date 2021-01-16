/**
 * Microsoft Portable Executable loader.
 *
 * PE32 format for both images (executables) and objects (mscoff object files).
 *
 * Loosely based on Windows Kits\10\Include\10.0.17763.0\um\winnt.h
 *
 * Sources:
 * - Microsoft Corporation, Microsoft Portable Executable and Common Object File Format Specification, Revision 6.0 - February 1999
 * - Microsoft Corporation, Microsoft Portable Executable and Common Object File Format Specification, Revision 8.3 – February 6, 2013
 * - Microsoft Corporation, PE Format, 2019-08-26
 *
 * License: BSD-3-Clause
 */
module adbg.obj.pe;

import core.stdc.stdio, core.stdc.inttypes;
import core.stdc.string : memset;
import adbg.error;
import adbg.obj.loader : obj_info_t, ObjType;
import adbg.disasm.disasm : AdbgDisasmPlatform; // ISA translation
import adbg.obj.loader;
import adbg.utils.uid : UID;

extern (C):

enum int PE_DIRECTORY_SIZE = PE_IMAGE_DATA_DIRECTORY.sizeof;
enum int PE_OHDR_SIZE = PE_OPTIONAL_HEADER.sizeof + PE_DIRECTORY_SIZE; // PE32
enum int PE_OHDR64_SIZE = PE_OPTIONAL_HEADER64.sizeof + PE_DIRECTORY_SIZE; // PE32+
enum int PE_OHDRROM_SIZE = PE_OPTIONAL_HEADERROM.sizeof + PE_DIRECTORY_SIZE; // PE-ROM

enum : ushort { // PE_HEADER.Machine, likely all little-endian
	PE_MACHINE_UNKNOWN	= 0,
	PE_MACHINE_ALPHA	= 0x184,	// Alpha AXP
	PE_MACHINE_ALPHA64	= 0x284,	// Alpha AXP 64-bit
	PE_MACHINE_AM33	= 0x1d3,	// Matsushita AM33
	PE_MACHINE_AMD64	= 0x8664,	// x86-64
	PE_MACHINE_ARM	= 0x1c0,	// "ARM little endian", so, ARM7/ARM9?
	PE_MACHINE_ARMNT	= 0x1c4,	// arm_a32 (ARMv7+ with thumb2)
	PE_MACHINE_ARM64	= 0xaa64,	// arm_a64
	PE_MACHINE_EBC	= 0xebc,	// EFI Byte-Code
	PE_MACHINE_I386	= 0x14c,	// x86
	PE_MACHINE_IA64	= 0x200,	// Itanium (not x86-64!)
	PE_MACHINE_M32R	= 0x9041,	// lsb
	PE_MACHINE_MIPS16	= 0x266,
	PE_MACHINE_MIPSFPU	= 0x366,
	PE_MACHINE_MIPSFPU16	= 0x466,
	PE_MACHINE_POWERPC	= 0x1f0,
	PE_MACHINE_POWERPCFP	= 0x1f1,
	PE_MACHINE_R3000	= 0x162,	// mips
	PE_MACHINE_R4000	= 0x166,	// mips
	PE_MACHINE_R10000	= 0x168,	// mips
	PE_MACHINE_RISCV32	= 0x5032,	// risc-v-32
	PE_MACHINE_RISCV64	= 0x5064,	// risc-v-64
	PE_MACHINE_RISCV128	= 0x5128,	// risc-v-128
	PE_MACHINE_SH3	= 0x1a2,	// SuperH
	PE_MACHINE_SH3DSP	= 0x1a3,	// SuperH DSP
	PE_MACHINE_SH4	= 0x1a6,	// SuperH
	PE_MACHINE_SH5	= 0x1a8,	// SuperH
	PE_MACHINE_THUMB	= 0x1c2,	// arm_t32
	PE_MACHINE_WCEMIPSV2	= 0x169,
	// https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files
	PE_MACHINE_CLR	= 0xC0EE,
	//TODO: Missing CEE machine type "COM+ EE"
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

/// PE32 META structure for use in the object loader
struct PE_META { align(1):
	//
	// Header
	//
	union {
		PE_HEADER *hdr;
		uint fo_hdr;
	}
	union {
		PE_OPTIONAL_HEADER *ohdr;
		PE_OPTIONAL_HEADER64 *ohdr64;
		PE_OPTIONAL_HEADERROM *ohdrrom;
		uint fo_ohdr;
	}
	union {
		PE_IMAGE_DATA_DIRECTORY *dir;
		uint fo_dir;
	}
	//
	// Directories
	//
	union {
		PE_EXPORT_DESCRIPTOR *exports;
		uint fo_exports;
	}
	union {
		PE_IMPORT_DESCRIPTOR *imports;
		uint fo_imports;
	}
	union {
		uint fo_resources;
	}
	union {
		uint fo_exception;
	}
	union {
		uint fo_certitiface;
	}
	union {
		uint fo_basereloc;
	}
	union {
		PE_DEBUG_DIRECTORY *debugs;
		uint fo_debug;
	}
	union {
		uint fo_architecture;
	}
	union {
		uint fo_globalptr;
	}
	union {
		uint fo_tls;
	}
	union {
		PE_LOAD_CONFIG_META *loadconf;
		uint fo_loadcfg;
	}
	union {
		uint fo_boundimport;
	}
	union {
		uint fo_importaddress;	/// "IAT"
	}
	union {
		uint fo_delayimport;
	}
	union {
		uint fo_clr;
	}
	union {
		uint fo_reserved;
	}
	//
	// Data
	//
	union {
		PE_SECTION_ENTRY *sections;
		uint fo_sections;
	}
	
/*	union {
		PE_LOAD_CONFIG_CODE_INTEGRITY *loadcfg_integrity;
		uint fo_loadcfg_integrity;
	}*/
}

/// COFF file header (object and image)
struct PE_HEADER { align(1):
	uint8_t  [4]Signature;
	uint16_t Machine;
	uint16_t NumberOfSections;
	uint32_t TimeDateStamp;
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
	PE_DIRECTORY_ENTRY CLRHeader;	// Used to be COM+ Runtime Header
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

struct PE_EXPORT_ENTRY { align(1):
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
struct PE_IMPORT_LTE32 { align(1):
	union {
		uint val;
		ushort num; /// Ordinal Number (val[31] is clear)
		uint rva; /// Hint/Name Table RVA (val[31] is set)
	}
}
/// Import Lookup Table entry structure
struct PE_IMPORT_LTE64 { align(1):
	union {
		ulong val;
		struct { uint val1, val2; }
		ushort num; /// Ordinal Number (val2[31] is clear)
		uint rva; /// Hint/Name Table RVA (val2[31] is set)
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
	IMAGE_DEBUG_TYPE_UNKNOWN	= 0,
	/// The COFF debug information (line numbers, symbol table, and string table).
	/// This type of debug information is also pointed to by fields in the file headers.
	IMAGE_DEBUG_TYPE_COFF	= 1,
	/// The Visual C++ debug information
	IMAGE_DEBUG_TYPE_CODEVIEW	= 2,
	/// The frame pointer omission (FPO) information. This information tells the
	/// debugger how to interpret nonstandard stack frames, which use the EBP
	/// register for a purpose other than as a frame pointer.
	IMAGE_DEBUG_TYPE_FPO	= 3,
	IMAGE_DEBUG_TYPE_MISC	= 4, /// The location of DBG file.
	IMAGE_DEBUG_TYPE_EXCEPTION	= 5, /// A copy of .pdata section.
	IMAGE_DEBUG_TYPE_FIXUP	= 6, /// Reserved.
	IMAGE_DEBUG_TYPE_OMAP_TO_SRC	= 7, /// The mapping from an RVA in image to an RVA in source image.
	IMAGE_DEBUG_TYPE_OMAP_FROM_SRC	= 8, /// The mapping from an RVA in source image to an RVA in image.
	IMAGE_DEBUG_TYPE_BORLAND	= 9, /// Reserved for Borland.
	IMAGE_DEBUG_TYPE_RESERVED10	= 10, /// Reserved.
	IMAGE_DEBUG_TYPE_CLSID	= 11, /// Reserved.
	IMAGE_DEBUG_TYPE_VC_FEATURE	= 12, /// Undocumented, from winnt.h
	// See https://devblogs.microsoft.com/cppblog/pogo/
	IMAGE_DEBUG_TYPE_POGO	= 13, /// Profile Guided Optimization
	// See https://devblogs.microsoft.com/cppblog/speeding-up-the-incremental-developer-build-scenario/
	IMAGE_DEBUG_TYPE_ILTCG	= 14, /// Incremental Link Time Code Generation
	IMAGE_DEBUG_TYPE_MPX	= 15, /// Uses Intel MPX
	IMAGE_DEBUG_TYPE_REPRO	= 16, /// PE determinism or reproducibility.
	IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS	= 20, /// Extended DLL characteristics bits.
}

/// CodeView format for PDB 2.0 and above
// See http://www.debuginfo.com/articles/debuginfomatch.html
struct PE_DEBUG_DATA_CODEVIEW_PDB20 { align(1):
	uint8_t[4] Signature;	// Magic: "NB09"/"NB10"/"NB11" bytes
	/// Offset to the start of the actual debug information from the
	/// beginning of the CodeView data
	uint32_t Offset;
	uint32_t Timestamp;	/// 
	uint32_t Age;	/// incremented each time the executable is remade by the linker
	char[1] Path;	/// Path to PDB (0-terminated)
}

/// CodeView format for PDB 7.0
// See http://www.godevtool.com/Other/pdb.htm
// and http://www.debuginfo.com/articles/debuginfomatch.html
struct PE_DEBUG_DATA_CODEVIEW_PDB70 { align(1):
	uint8_t[4] Signature;	/// Magic: "RSDS" bytes
	UID PDB_GUID;	/// GUID of PDB file, matches with PDB file
	uint32_t Age;	/// incremented each time the executable is remade by the linker
	char[1] Path;	/// Path to PDB (0-terminated)
}

// Rough guesses for OS limits, offsets+4 since missing Size (already read)
// If the count is still misleading, the size check will be performed by field
// Examples:
// putty-x86 0.73: 92
// putty-amd64 0.73: 148
enum PE_LOAD_CONFIG32_LIMIT_XP = 64;
enum PE_LOAD_CONFIG32_LIMIT_VI = PE_LOAD_CONFIG_DIR32.GuardFlags.offsetof + 4;
enum PE_LOAD_CONFIG32_LIMIT_8 = PE_LOAD_CONFIG_DIR32.GuardLongJumpTargetCount.offsetof + 4;
enum PE_LOAD_CONFIG64_LIMIT_XP = PE_LOAD_CONFIG_DIR64.SecurityCookie.offsetof + 4;
enum PE_LOAD_CONFIG64_LIMIT_VI = PE_LOAD_CONFIG_DIR64.GuardFlags.offsetof + 4;
enum PE_LOAD_CONFIG64_LIMIT_8 = PE_LOAD_CONFIG_DIR64.GuardLongJumpTargetCount.offsetof + 4;

struct PE_LOAD_CONFIG_CODE_INTEGRITY { align(1):
	uint16_t Flags;	// Flags to indicate if CI information is available, etc.
	uint16_t Catalog;	// 0xFFFF means not available
	uint32_t CatalogOffset;
	uint32_t Reserved;	// Additional bitmask to be defined later
}

/// IMAGE_LOAD_CONFIG_DIRECTORY32
struct PE_LOAD_CONFIG_DIR32 { align(1):
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
	uint32_t SecurityCookie; // Windows XP's limit
	uint32_t SEHandlerTable;
	uint32_t SEHandlerCount;
	uint32_t GuardCFCheckFunctionPointer; // Control Flow
	uint32_t GuardCFDispatchFunctionPointer;
	uint32_t GuardCFFunctionTable;
	uint32_t GuardCFFunctionCount;
	uint32_t GuardFlags; // Windows 7's limit?
	PE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
	uint32_t GuardAddressTakenIatEntryTable;
	uint32_t GuardAddressTakenIatEntryCount;
	uint32_t GuardLongJumpTargetTable;
	uint32_t GuardLongJumpTargetCount; // Windows 8's limit?
	// Windows 10?
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
	uint64_t SecurityCookie;
	uint64_t SEHandlerTable;
	uint64_t SEHandlerCount;
	uint64_t GuardCFCheckFunctionPointer; // Control Flow
	uint64_t GuardCFDispatchFunctionPointer;
	uint64_t GuardCFFunctionTable;
	uint64_t GuardCFFunctionCount;
	uint32_t GuardFlags; // Windows 7's limit?
	PE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
	uint64_t GuardAddressTakenIatEntryTable;
	uint64_t GuardAddressTakenIatEntryCount;
	uint64_t GuardLongJumpTargetTable;
	uint64_t GuardLongJumpTargetCount;
	// Windows 10?
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

struct PE_LOAD_CONFIG_META { align(1):
	union {
		PE_LOAD_CONFIG_DIR32 dir32;
		PE_LOAD_CONFIG_DIR64 dir64;
	}
}

struct PE_SECTION_ENTRY { align(1):
	char[8] Name;
	uint32_t VirtualSize;
	uint32_t VirtualAddress;
	uint32_t SizeOfRawData;
	uint32_t PointerToRawData;
	uint32_t PointerToRelocations;
	uint32_t PointerToLinenumbers;
	uint16_t NumberOfRelocations;
	uint16_t NumberOfLinenumbers;
	uint32_t Characteristics;
}

int adbg_obj_pe_load(obj_info_t *info, int flags) {
	void* offset = info.b + info.offset;
	info.pe.hdr = cast(PE_HEADER*)offset;
	info.pe.ohdr = cast(PE_OPTIONAL_HEADER*)(offset + PE_OFFSET_OPTHDR);
	switch (info.pe.ohdr.Magic) {
	case PE_FMT_32:
		info.pe.dir = cast(PE_IMAGE_DATA_DIRECTORY*)(offset + PE_OFFSET_DIR_OPTHDR32);
		info.pe.sections = cast(PE_SECTION_ENTRY*)(offset + PE_OFFSET_SEC_OPTHDR32);
		break;
	case PE_FMT_64:
		info.pe.dir = cast(PE_IMAGE_DATA_DIRECTORY*)(offset + PE_OFFSET_DIR_OPTHDR64);
		info.pe.sections = cast(PE_SECTION_ENTRY*)(offset + PE_OFFSET_SEC_OPTHDR64);
		break;
	case PE_FMT_ROM:
		info.pe.dir = cast(PE_IMAGE_DATA_DIRECTORY*)(offset + PE_OFFSET_DIR_OPTHDRROM);
		info.pe.sections = cast(PE_SECTION_ENTRY*)(offset + PE_OFFSET_SEC_OPTHDRROM);
		break;
	default: return adbg_error_set(AdbgError.unsupportedObjFormat);
	}
	uint secs = info.pe.hdr.NumberOfSections;
	info.pe.fo_imports = 0;
	info.pe.fo_debug = 0;
	for (uint si; si < secs; ++si) {
		PE_SECTION_ENTRY s = info.pe.sections[si];

		if (info.pe.fo_imports == 0)
		if (s.VirtualAddress <= info.pe.dir.ImportTable.rva &&
			s.VirtualAddress + s.SizeOfRawData > info.pe.dir.ImportTable.rva) {
			info.pe.imports = cast(PE_IMPORT_DESCRIPTOR*)(info.b +
				(s.PointerToRawData +
				(info.pe.dir.ImportTable.rva - s.VirtualAddress)));
		}

		if (info.pe.fo_debug == 0)
		if (s.VirtualAddress <= info.pe.dir.DebugDirectory.rva &&
			s.VirtualAddress + s.SizeOfRawData > info.pe.dir.DebugDirectory.rva) {
			info.pe.debugs = cast(PE_DEBUG_DIRECTORY*)(info.b +
				(s.PointerToRawData +
				(info.pe.dir.DebugDirectory.rva - s.VirtualAddress)));
		}
	}

	switch (info.pe.hdr.Machine) {
	case PE_MACHINE_I386:	info.platform = AdbgDisasmPlatform.x86; break;
	case PE_MACHINE_AMD64:	info.platform = AdbgDisasmPlatform.x86_64; break;
	case PE_MACHINE_RISCV32:	info.platform = AdbgDisasmPlatform.rv32; break;
	default:	info.platform = AdbgDisasmPlatform.native;
	}

	return 0;
}

//TODO: adbg_obj_pe_get_section_by_name
/*int adbg_obj_pe_get_section_by_name(obj_info_t *info, ubyte *sptr, const(char) *text) {
}*/

//TODO: adbg_obj_pe_get_section_by_rva
/*int adbg_obj_pe_get_section_by_rva(obj_info_t *info, ubyte *sptr, uint rva) {
}*/

//TODO: adbg_obj_pe_get_section_by_index
/*int adbg_obj_pe_get_section_by_index(obj_info_t *info, ubyte *sptr, uint index) {
}*/

const(char) *adbg_obj_pe_mach(ushort mach) {
	switch (mach) {
	case PE_MACHINE_UNKNOWN:	return "UNKNOWN";
	case PE_MACHINE_ALPHA:	return "ALPHA";
	case PE_MACHINE_ALPHA64:	return "ALPHA64";
	case PE_MACHINE_AM33:	return "AM33";
	case PE_MACHINE_AMD64:	return "AMD64";
	case PE_MACHINE_ARM:	return "ARM";
	case PE_MACHINE_ARMNT:	return "ARMNT";
	case PE_MACHINE_ARM64:	return "ARM64";
	case PE_MACHINE_EBC:	return "EBC";
	case PE_MACHINE_I386:	return "I386";
	case PE_MACHINE_IA64:	return "IA64";
	case PE_MACHINE_M32R:	return "M32R";
	case PE_MACHINE_MIPS16:	return "MIPS16";
	case PE_MACHINE_MIPSFPU:	return "MIPSFPU";
	case PE_MACHINE_MIPSFPU16:	return "MIPSFPU16";
	case PE_MACHINE_POWERPC:	return "POWERPC";
	case PE_MACHINE_POWERPCFP:	return "POWERPCFP";
	case PE_MACHINE_R3000:	return "R3000";
	case PE_MACHINE_R4000:	return "R4000";
	case PE_MACHINE_R10000:	return "R10000";
	case PE_MACHINE_RISCV32:	return "RISCV32";
	case PE_MACHINE_RISCV64:	return "RISCV64";
	case PE_MACHINE_RISCV128:	return "RISCV128";
	case PE_MACHINE_SH3:	return "SH3";
	case PE_MACHINE_SH3DSP:	return "SH3DSP";
	case PE_MACHINE_SH4:	return "SH4";
	case PE_MACHINE_SH5:	return "SH5";
	case PE_MACHINE_THUMB:	return "THUMB";
	case PE_MACHINE_WCEMIPSV2:	return "WCEMIPSV2";
	case PE_MACHINE_CLR:	return "CLR";
	default:	return null;
	}
}

const(char) *adbg_obj_pe_magic(ushort mag) {
	switch (mag) {
	case PE_FMT_32:	return "PE32";
	case PE_FMT_64:	return "PE32+";
	case PE_FMT_ROM:	return "PE-ROM";
	default:	return null;
	}
}

const(char) *adbg_obj_pe_subsys(ushort subs) {
	switch (subs) {
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

const(char) *adbg_obj_debug_type(uint type) {
	switch (type) {
	case IMAGE_DEBUG_TYPE_UNKNOWN:	return "Unknown";
	case IMAGE_DEBUG_TYPE_COFF:	return "COFF";
	case IMAGE_DEBUG_TYPE_CODEVIEW:	return "CodeView / VC++";
	case IMAGE_DEBUG_TYPE_FPO:	return "FPO (Frame Pointer Omission) Information";
	case IMAGE_DEBUG_TYPE_MISC:	return "DBG File Location";
	case IMAGE_DEBUG_TYPE_EXCEPTION:	return "Exception";
	case IMAGE_DEBUG_TYPE_FIXUP:	return "FIXUP";
	case IMAGE_DEBUG_TYPE_OMAP_TO_SRC:	return "Map RVA to source image RVA";
	case IMAGE_DEBUG_TYPE_OMAP_FROM_SRC:	return "Map source image RVA to RVA";
	case IMAGE_DEBUG_TYPE_BORLAND:	return "Borland";
	case IMAGE_DEBUG_TYPE_RESERVED10:	return "RESERVED10";
	case IMAGE_DEBUG_TYPE_CLSID:	return "CLSID";
	case IMAGE_DEBUG_TYPE_VC_FEATURE:	return "VC FEATURE";
	case IMAGE_DEBUG_TYPE_POGO:	return "Profile Guided Optimization (POGO)";
	case IMAGE_DEBUG_TYPE_ILTCG:	return "Incremental Link Time Code Generation (ILTCG)";
	case IMAGE_DEBUG_TYPE_MPX:	return "Memory protection (Intel MPX)";
	case IMAGE_DEBUG_TYPE_REPRO:	return "PE Reproducibility";
	case IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS:	return "DLL characteristics";
	default:	return null;
	}
}

private:

enum PE_OFFSET_OPTHDR        = PE_HEADER.sizeof;
enum PE_OFFSET_DIR_OPTHDR32  = PE_OFFSET_OPTHDR + PE_OPTIONAL_HEADER.sizeof;
enum PE_OFFSET_DIR_OPTHDR64  = PE_OFFSET_OPTHDR + PE_OPTIONAL_HEADER64.sizeof;
enum PE_OFFSET_DIR_OPTHDRROM = PE_OFFSET_OPTHDR + PE_OPTIONAL_HEADERROM.sizeof;
enum PE_OFFSET_SEC_OPTHDR32  = PE_OFFSET_DIR_OPTHDR32 + PE_IMAGE_DATA_DIRECTORY.sizeof;
enum PE_OFFSET_SEC_OPTHDR64  = PE_OFFSET_DIR_OPTHDR64 + PE_IMAGE_DATA_DIRECTORY.sizeof;
enum PE_OFFSET_SEC_OPTHDRROM = PE_OFFSET_DIR_OPTHDRROM + PE_IMAGE_DATA_DIRECTORY.sizeof;
