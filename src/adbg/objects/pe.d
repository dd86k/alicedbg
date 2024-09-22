/// Microsoft Portable Executable format.
///
/// PE32 format for both images (executables) and objects (mscoff object files).
///
/// Sources:
/// - Windows Kits\10\Include\10.0.17763.0\um\winnt.h
/// - Microsoft Corporation, Microsoft Portable Executable and Common Object File Format Specification, Revision 6.0 - February 1999
/// - Microsoft Corporation, Microsoft Portable Executable and Common Object File Format Specification, Revision 8.3 – February 6, 2013
/// - Microsoft Corporation, PE Format, 2019-08-26
/// - https://github.com/dotnet/runtime/blob/main/docs/design/specs/PE-COFF.md
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.objects.pe;

import core.stdc.stdlib;
import core.stdc.string : memcpy;
import adbg.error;
import adbg.objectserver;
import adbg.machines : AdbgMachine;
import adbg.utils.uid : UID;
import adbg.utils.bit;
import adbg.utils.math : min, MiB;
import adbg.objects.mz : mz_header_t;

// NOTE: Avoid the Windows base types as they are not defined outside "version (Windows)"
// NOTE: Microsoft loader limits sections to 96 maximum
// NOTE: Load Configuration depends on Linker version, Windows depend on that to load PE32 images

extern (C):

/// Magic number for PE32 object files.
enum MAGIC_PE32 = CHAR32!"PE\0\0";
/// Rich PE Header start ID
enum MAGIC_RICH_BEGID = CHAR32!"DanS";
/// Rich PE Header end ID
enum MAGIC_RICH_ENDID = CHAR32!"Rich";

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
	PE_CLASS_ROM	= 0x0107,	// No longer used? Docs no longer have it
	PE_CLASS_32	= 0x010B,	/// PE32
	PE_CLASS_64	= 0x020B,	/// PE32+
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
	PE_SUBSYSTEM_XBOX_CODE_CATALOG	= 17,
}

/// COFF file header (object and image)
struct pe_header_t { align(1):
	union {
		ubyte[4] Signature;
		uint   Signature32;
	}
	ushort Machine;
	ushort NumberOfSections;
	uint TimeDateStamp; // C time_t
	uint PointerToSymbolTable;
	uint NumberOfSymbols;
	ushort SizeOfOptionalHeader;
	ushort Characteristics;
}
alias PE_HEADER = pe_header_t;

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
// Image only
struct pe_optional_header_t { align(1):
	ushort Magic; // "Format"
	ubyte  MajorLinkerVersion;
	ubyte  MinorLinkerVersion;
	uint SizeOfCode;
	uint SizeOfInitializedData;
	uint SizeOfUninitializedData;
	uint AddressOfEntryPoint;
	uint BaseOfCode;
	uint BaseOfData;
	uint ImageBase;
	uint SectionAlignment;
	uint FileAlignment;
	ushort MajorOperatingSystemVersion;
	ushort MinorOperatingSystemVersion;
	ushort MajorImageVersion;
	ushort MinorImageVersion;
	ushort MajorSubsystemVersion;
	ushort MinorSubsystemVersion;
	uint Win32VersionValue;
	uint SizeOfImage;
	uint SizeOfHeaders;
	uint CheckSum;
	ushort Subsystem;
	ushort DllCharacteristics;
	uint SizeOfStackReserve;
	uint SizeOfStackCommit;
	uint SizeOfHeapReserve;
	uint SizeOfHeapCommit;
	uint LoaderFlags;	/// Obsolete
	uint NumberOfRvaAndSizes;
}
alias PE_OPTIONAL_HEADER = pe_optional_header_t;

struct pe_optional_header64_t { align(1):
	ushort Magic; // "Format"
	ubyte  MajorLinkerVersion;
	ubyte  MinorLinkerVersion;
	uint SizeOfCode;
	uint SizeOfInitializedData;
	uint SizeOfUninitializedData;
	uint AddressOfEntryPoint;
	uint BaseOfCode;
	ulong ImageBase;
	uint SectionAlignment;
	uint FileAlignment;
	ushort MajorOperatingSystemVersion;
	ushort MinorOperatingSystemVersion;
	ushort MajorImageVersion;
	ushort MinorImageVersion;
	ushort MajorSubsystemVersion;
	ushort MinorSubsystemVersion;
	uint Win32VersionValue;
	uint SizeOfImage;
	uint SizeOfHeaders;
	uint CheckSum;
	ushort Subsystem;
	ushort DllCharacteristics;
	ulong SizeOfStackReserve;
	ulong SizeOfStackCommit;
	ulong SizeOfHeapReserve;
	ulong SizeOfHeapCommit;
	uint LoaderFlags; // Obsolete
	uint NumberOfRvaAndSizes;
}
alias PE_OPTIONAL_HEADER64 = pe_optional_header64_t;

struct pe_optional_headerrom_t {
	ushort Magic;
	ubyte  MajorLinkerVersion;
	ubyte  MinorLinkerVersion;
	uint SizeOfCode;
	uint SizeOfInitializedData;
	uint SizeOfUninitializedData;
	uint AddressOfEntryPoint;
	uint BaseOfCode;
	uint BaseOfData;
	uint BaseOfBss;
	uint GprMask;
	uint[4] CprMask;
	uint GpValue;
}
alias PE_OPTIONAL_HEADERROM = pe_optional_headerrom_t;

struct pe_directory_entry_t { align(1):
	uint rva;	/// Relative Virtual Address
	uint size;	/// Size in bytes
}
alias PE_DIRECTORY_ENTRY = pe_directory_entry_t;

// IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
// MS recommends checking NumberOfRvaAndSizes but it always been 16
struct pe_image_data_directory_t { align(1):
	pe_directory_entry_t ExportTable;
	pe_directory_entry_t ImportTable;
	pe_directory_entry_t ResourceTable;
	pe_directory_entry_t ExceptionTable;
	pe_directory_entry_t CertificateTable;	// File Pointer (instead of RVA)
	pe_directory_entry_t BaseRelocationTable;
	pe_directory_entry_t DebugDirectory;
	pe_directory_entry_t ArchitectureData;
	pe_directory_entry_t GlobalPtr;
	pe_directory_entry_t TLSTable;
	pe_directory_entry_t LoadConfigurationTable;
	pe_directory_entry_t BoundImportTable;
	pe_directory_entry_t ImportAddressTable;
	pe_directory_entry_t DelayImport;
	pe_directory_entry_t CLRHeader;	// Used to be (or alias to) COM+ Runtime Header
	pe_directory_entry_t Reserved;
}
alias PE_IMAGE_DATA_DIRECTORY = pe_image_data_directory_t;

//
// ANCHOR Directory structures
//

struct pe_export_descriptor_t { align(1):
	uint ExportFlags;
	uint Timestamp;
	ushort MajorVersion;
	ushort MinorVersion;
	uint Name;	/// RVA
	uint OrdinalBase;
	uint AddressTableEntries;	/// Number of export entries
	uint NumberOfNamePointers;	/// Same amount for ordinal
	uint ExportAddressTable;	/// RVA
	uint NamePointer;	/// RVA, "The address of the export name pointer table"
	uint OrdinalTable;	/// RVA
}
alias PE_EXPORT_DESCRIPTOR = pe_export_descriptor_t;

union pe_export_entry_t { align(1):
	uint Export;	/// RVA
	uint Forwarder;	/// RVA
}
alias PE_EXPORT_ENTRY = pe_export_entry_t;

// IMAGE_IMPORT_DESCRIPTOR
struct pe_import_descriptor_t { align(1):
	uint Characteristics; // used in WINNT.H but no longer descriptive
	uint TimeDateStamp; // time_t
	uint ForwarderChain;
	uint Name;
	uint FirstThunk;
}
alias PE_IMPORT_DESCRIPTOR = pe_import_descriptor_t;

/// Import Lookup Table entry structure
struct pe_import_entry32_t { align(1):
	union {
		uint ordinal;	/// Ordinal/Name Flag
		ushort number;	/// Ordinal Number (val[31] is set)
		uint rva;	/// Hint/Name Table RVA (val[31] is clear)
	}
}
alias PE_IMPORT_ENTRY32 = pe_import_entry32_t;

/// Import Lookup Table entry structure
struct pe_import_entry64_t { align(1):
	union {
		ulong ordinal;	/// Ordinal/Name Flag
		ushort number;	/// Ordinal Number (val2[31] is set)
		uint rva;	/// Hint/Name Table RVA (val2[31] is clear)
	}
}
alias PE_IMPORT_ENTRY64 = pe_import_entry64_t;

struct pe_debug_directory_entry_t { align(1):
	uint Characteristics;	/// reserved, must be zero
	uint TimeDateStamp;	/// time and date that the debug data was created
	ushort MajorVersion;	/// The major version number of the debug data format
	ushort MinorVersion;	/// The minor version number of the debug data format
	uint Type;	/// The format of debugging information
	uint SizeOfData;	/// The size of the debug data (not including the debug directory itself)
	uint AddressOfRawData;	/// The address of the debug data relative to the image base
	uint PointerToRawData;	/// The file pointer to the debug data
}
alias PE_DEBUG_DIRECTORY = pe_debug_directory_entry_t;

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
	/// Visual C++ features
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
	/// SPGo debug types
	PE_IMAGE_DEBUG_TYPE_SPGO	= 18,
	/// Crypto hash of the content of the symbol file the PE/COFF file was built with.
	PE_IMAGE_DEBUG_TYPE_HASH	= 19,
	/// Extended DLL characteristics bits.
	PE_IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS	= 20,
	/// R2R PerfMap Debug Directory Entry
	PE_IMAGE_DEBUG_TYPE_R2R_PERFMAP	= 21,
}

// Debug entry 2: CodeView/PDB stuff

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

/// PDB 2.0 and above
struct pe_debug_data_codeview_pdb20_t { align(1):
	// Old PE32 doc mentions "NB05" -- CodeView 4.0 or earlier?
	char[4] Signature;	/// Magic: "NB09"/"NB10"/"NB11" bytes
	/// Offset to the start of the actual debug information from the
	/// beginning of the CodeView data. Zero if it's another file.
	uint Offset;
	uint Timestamp;	///
	uint Age;	/// incremented each time the executable is remade by the linker
	char[1] Path;	/// Path to PDB (0-terminated)
}
alias PE_DEBUG_DATA_CODEVIEW_PDB20 = pe_debug_data_codeview_pdb20_t;

/// PDB 7.0
struct pe_debug_data_codeview_pdb70_t { align(1):
	char[4] Signature;	/// Magic: "RSDS" bytes
	UID Guid;	/// GUID of PDB file, matches with PDB file
	uint Age;	/// incremented each time the executable is remade by the linker
	char[1] Path;	/// Path to PDB (0-terminated UTF-8)
}
alias PE_DEBUG_DATA_CODEVIEW_PDB70 = pe_debug_data_codeview_pdb70_t;

// Debug entry 3: The frame pointer omission (FPO) information.

// This information tells the debugger how to interpret nonstandard stack frames,
// which use the EBP register for a purpose other than as a frame pointer. 
enum FRAME_FPO  = 0;
enum FRAME_TRAP = 1;
enum FRAME_TSS  = 2; // i286 Task Switch
struct pe_debug_data_fpo_t { // struct _FPO_DATA
	uint ulOffStart; // offset 1st byte of function code
	uint cbProcSize; // # bytes in function
	uint cdwLocals; // # bytes in locals/4
	ushort cdwParams; // # bytes in params/4
	ushort Flags;
	//WORD cbProlog : 8; // # bytes in prolog
	//WORD cbRegs : 3; // # regs saved
	//WORD fHasSEH : 1; // TRUE if SEH in func
	//WORD fUseBP : 1; // TRUE if EBP has been allocated
	//WORD reserved : 1; // reserved for future use
	//WORD cbFrame : 2; // frame type
}

// Debug entry 4: The location of a DBG file.

struct pe_debug_data_misc_t { align(1):
	union {
		char[4] Signature;	/// 
		uint Signature32;
	}
	uint DataType;	/// Must be 1
	uint Length;	/// Multiple of four; Total length of data block
	bool Unicode;	/// If true, Unicode string
	byte[3] Reserved;
	byte[1] Data;
}
alias PE_DEBUG_DATA_MISC = pe_debug_data_misc_t;

// Debug entry 12: VC Features

/// VC Featured data
struct pe_debug_data_vc_feat_t { align(1):
	uint PreVC11;	/// Pre-VC11
	uint CCpp;	/// C/C++
	uint GS;	/// /GS
	uint SDL;	/// /SDL
	uint GuardN;	/// guardN
}
alias PE_DEBUG_DATA_VC_FEAT = pe_debug_data_vc_feat_t;

// Debug entry 13: POGO

/// POGO Entry containing filename. Should be ending with .PGD (Profile-Guided Database).
struct pe_debug_data_pogo_entry_t {
	uint Magic;
	uint Rva;
	uint Size;
	char[1] Name;
}
alias PE_DEBUG_POGO_ENTRY = pe_debug_data_pogo_entry_t;

// Debug entry 17: Embedded PDB

/// Declares that debugging information is embedded in the PE file at location
/// specified by PointerToRawData.
// Version Major=any, Minor=0x0100 of the data format:
struct pe_debug_data_embedded_t { align(1):
	char[4] Signature;	/// Magic: "MPDB"
	uint UncompressedSize;
	// SizeOfData - 8: PortablePdbImage
	//                 Portable PDB image compressed using Deflate algorithm
	ubyte[1] PortablePdbImage;
}
alias PE_DEBUG_DATA_EMBEDDED = pe_debug_data_embedded_t;

// aka MetadataRootHeader
struct pe_debug_data_ppdb_t {
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
alias PE_DEBUG_DATA_PPDB = pe_debug_data_ppdb_t;

// After MetadataRootHeader + Version string
struct pe_debug_data_ppdb_flags_t {
	ushort Flags;
	ushort Streams;
}
alias PE_DEBUG_DATA_PPDB_FLAGS = pe_debug_data_ppdb_flags_t;

struct pe_debug_data_ppdb_stream_t {
	uint Offset;
	uint Size;
	char[1] Name;
}
alias PE_DEBUG_DATA_PPDB_STREAM = pe_debug_data_ppdb_stream_t;

// Debug type 21: R2R PerfMap

/// Declares that the image has an associated PerfMap file containing a table
/// mapping symbols to offsets for ready to run compilations.
// Version Major=0x0001, Minor=0x0000 of the entry data format is following:
struct pe_debug_data_r2r_perfmap_t { align(1):
	union {
		char[4] Magic;	/// "R2RM"
		uint Magic32;
	}
	/// Byte sequence uniquely identifying the associated PerfMap.
	UID Signature; // Used to be ubyte[16]
	/// Version number of the PerfMap. Currently only version 1 is supported.
	uint Version;
	/// UTF-8 NUL-terminated path to the associated .r2rmap file.
	char[1] Path;
}
alias PE_DEBUG_DATA_R2R_PERFMAP = pe_debug_data_r2r_perfmap_t;

//
// Load configuration directory
//

struct pe_load_config_code_integrity_t { align(1):
	ushort Flags;	// Flags to indicate if CI information is available, etc.
	ushort Catalog;	// 0xFFFF means not available
	uint CatalogOffset;
	uint Reserved;	// Additional bitmask to be defined later
}
alias PE_LOAD_CONFIG_CODE_INTEGRITY = pe_load_config_code_integrity_t;

/// IMAGE_LOAD_CONFIG_DIRECTORY32
//TODO: Map sizes to WindowsNT versions
//      Or very likely MSVC linker versions
struct pe_load_config_dir32_t { align(1):
	// Windows XP and after
	uint Size; // Doc: Characteristics, header: Size, Windows XP=64
	uint TimeDateStamp; // time_t
	ushort MajorVersion;
	ushort MinorVersion;
	uint GlobalFlagsClear;
	uint GlobalFlagsSet;
	uint CriticalSectionDefaultTimeout;
	uint DeCommitFreeBlockThreshold;
	uint DeCommitTotalBlockThreshold;
	uint LockPrefixTable;
	uint MaximumAllocationSize;
	uint VirtualMemoryThreshold;
	uint ProcessHeapFlags;
	uint ProcessAffinityMask;
	ushort CSDVersion;
	ushort Reserved1;
	uint EditList;
	// Windows 7 and later
	uint SecurityCookie;
	uint SEHandlerTable;
	uint SEHandlerCount;
	uint GuardCFCheckFunctionPointer; // Control Flow
	uint GuardCFDispatchFunctionPointer;
	uint GuardCFFunctionTable;
	uint GuardCFFunctionCount;
	// Windows 8 and later?
	uint GuardFlags;
	PE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
	uint GuardAddressTakenIatEntryTable;
	uint GuardAddressTakenIatEntryCount;
	uint GuardLongJumpTargetTable;
	uint GuardLongJumpTargetCount; // Windows 8's limit?
	// Windows 10 and later?
	uint DynamicValueRelocTable;	// VA
	uint CHPEMetadataPointer;
	uint GuardRFFailureRoutine;	// VA
	uint GuardRFFailureRoutineFunctionPointer;	// VA
	uint DynamicValueRelocTableOffset;
	ushort DynamicValueRelocTableSection;
	ushort Reserved2;
	uint GuardRFVerifyStackPointerFunctionPointer;	// VA
	uint HotPatchTableOffset;
	uint Reserved3;
	uint EnclaveConfigurationPointer;	// VA
	uint VolatileMetadataPointer;	// VA
	// 10.0.2261.0
	uint GuardEHContinuationTable;	// VA
	uint GuardEHContinuationCount;
	uint GuardXFGCheckFunctionPointer;	// VA
	uint GuardXFGDispatchFunctionPointer;	// VA
	uint GuardXFGTableDispatchFunctionPointer;	// VA
	uint CastGuardOsDeterminedFailureMode;	// VA
	uint GuardMemcpyFunctionPointer;	// VA
}
alias PE_LOAD_CONFIG_DIR32 = pe_load_config_dir32_t;

/// IMAGE_LOAD_CONFIG_DIRECTORY64
//TODO: Map sizes to WindowsNT versions
//      Or MSVC linker versions
struct pe_load_config_dir64_t { align(1):
	uint Size; // Characteristics
	uint TimeDateStamp; // time_t
	ushort MajorVersion;
	ushort MinorVersion;
	uint GlobalFlagsClear;
	uint GlobalFlagsSet;
	uint CriticalSectionDefaultTimeout;
	ulong DeCommitFreeBlockThreshold;
	ulong DeCommitTotalBlockThreshold;
	ulong LockPrefixTable;
	ulong MaximumAllocationSize;
	ulong VirtualMemoryThreshold;
	ulong ProcessAffinityMask;
	uint ProcessHeapFlags;
	ushort CSDVersion;
	ushort Reserved1;
	ulong EditList;
	// Windows 7 and later
	ulong SecurityCookie;
	ulong SEHandlerTable;
	ulong SEHandlerCount;
	ulong GuardCFCheckFunctionPointer; // Control Flow
	ulong GuardCFDispatchFunctionPointer;
	ulong GuardCFFunctionTable;
	ulong GuardCFFunctionCount;
	uint GuardFlags;
	// Windows 8 and later?
	PE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
	ulong GuardAddressTakenIatEntryTable;
	ulong GuardAddressTakenIatEntryCount;
	ulong GuardLongJumpTargetTable;
	ulong GuardLongJumpTargetCount;
	// Windows 10 and later?
	ulong DynamicValueRelocTable;         // VA
	ulong CHPEMetadataPointer;            // VA
	ulong GuardRFFailureRoutine;          // VA
	ulong GuardRFFailureRoutineFunctionPointer; // VA
	uint DynamicValueRelocTableOffset;
	ushort DynamicValueRelocTableSection;
	ushort Reserved2;
	ulong GuardRFVerifyStackPointerFunctionPointer; // VA
	uint HotPatchTableOffset;
	uint Reserved3;
	ulong EnclaveConfigurationPointer;     // VA
	ulong VolatileMetadataPointer;         // VA
	// 10.0.22621.0
	ulong GuardEHContinuationTable;	// VA
	ulong GuardEHContinuationCount;
	ulong GuardXFGCheckFunctionPointer;	// VA
	ulong GuardXFGDispatchFunctionPointer;	// VA
	ulong GuardXFGTableDispatchFunctionPointer;	// VA
	ulong CastGuardOsDeterminedFailureMode;	// VA
	ulong GuardMemcpyFunctionPointer;	// VA
}
alias PE_LOAD_CONFIG_DIR64 = pe_load_config_dir64_t;

struct pe_section_entry_t { align(1):
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
	uint VirtualSize;
	/// For executable images, the address of the first
	/// byte of the section relative to the image base
	/// when the section is loaded into memory. For
	/// object files, this field is the address of the first
	/// byte before relocation is applied; for simplicity,
	/// compilers should set this to zero. Otherwise, it
	/// is an arbitrary value that is subtracted from
	/// offsets during relocation.
	uint VirtualAddress;
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
	uint SizeOfRawData;
	/// The file pointer to the first page of the section
	/// within the COFF file. For executable images, this
	/// must be a multiple of FileAlignment from the
	/// optional header. For object files, the value
	/// should be aligned on a 4-byte boundary for best
	/// performance. When a section contains only
	/// uninitialized data, this field should be zero.
	uint PointerToRawData;
	/// The file pointer to the beginning of relocation
	/// entries for the section. This is set to zero for
	/// executable images or if there are no
	/// relocations.
	uint PointerToRelocations;
	/// The file pointer to the beginning of line-number
	/// entries for the section. This is set to zero if
	/// there are no COFF line numbers. This value
	/// should be zero for an image because COFF
	/// debugging information is deprecated.
	uint PointerToLinenumbers;
	/// The number of relocation entries for the
	/// section. This is set to zero for executable
	/// images.
	ushort NumberOfRelocations;
	/// The number of line-number entries for the
	/// section. This value should be zero for an image
	/// because COFF debugging information is
	/// deprecated.
	ushort NumberOfLinenumbers;
	/// The flags that describe the characteristics of the
	/// section.
	uint Characteristics;
}
alias PE_SECTION_ENTRY = pe_section_entry_t;

struct pe_rich_header_item_t {
	union {
		uint id;
		struct {
			ushort buildId;
			ushort prodId;
		}
	}
	uint count;
}
struct pe_rich_header_t {
	uint[4] magic; // and padding
	size_t itemcount;
	pe_rich_header_item_t *items;
}

private
struct internal_pe_t {
	pe_header_t header;
	union {
		pe_optional_header_t optheader;
		pe_optional_header64_t optheader64;
		pe_optional_headerrom_t optheaderrom;
	}
	
	mz_header_t mz_header;
	
	pe_image_data_directory_t directory;
	uint locsections;
	pe_section_entry_t *sections;
	bool *r_sections;
	// export directory
	pe_export_descriptor_t *export_directory;
	bool *r_export_entries;
	// import directory
	pe_import_descriptor_t *import_directory; // not allocated
	pe_section_entry_t *import_section; // associated section, not allocated
	void *import_buffer; // section buffer
	//bool *r_import_desc;
	//bool *r_import_entries; // Current only, cleared when selecting other descriptor
	// debug directory
	pe_debug_directory_entry_t *debug_directory; // not allocated
	pe_section_entry_t *debug_section;
	void *debug_buffer; // section buffer
	bool *r_debug_entries;
	// load configuration directory
	union {
		pe_load_config_dir32_t *load32_directory;
		pe_load_config_dir64_t *load64_directory;
	}
	bool r_loaddir;
	
	void *rich_header_buffer;
	size_t rich_buffer_size;
	pe_rich_header_t rich_header;
}

/// (Internal) Called by the server to preload a PE object.
/// Params:
/// 	o = Object instance.
/// 	mzhdr = MZ Header instance.
/// Returns: Error code.
int adbg_object_pe_load(adbg_object_t *o, mz_header_t *mzhdr) {
	assert(o);
	assert(mzhdr);
	o.internal = calloc(1, internal_pe_t.sizeof);
	if (o.internal == null)
		return adbg_oops(AdbgError.crt);
	if (adbg_object_read_at(o, mzhdr.e_lfanew, o.internal, pe_header_t.sizeof)) {
		free(o.internal);
		o.internal = null;
		return adbg_errno();
	}
	internal_pe_t* internal = cast(internal_pe_t*)o.internal;
	
	pe_header_t *header = &internal.header;
	with (header)
	if (o.status & AdbgObjectInternalFlags.reversed) {
		Signature32	= adbg_bswap32(Signature32);
		Machine	= adbg_bswap16(Machine);
		NumberOfSections	= adbg_bswap16(NumberOfSections);
		TimeDateStamp	= adbg_bswap32(TimeDateStamp);
		PointerToSymbolTable	= adbg_bswap32(PointerToSymbolTable);
		NumberOfSymbols	= adbg_bswap32(NumberOfSymbols);
		SizeOfOptionalHeader	= adbg_bswap16(SizeOfOptionalHeader);
		Characteristics	= adbg_bswap16(Characteristics);
	}
	
	long e_lfanew = mzhdr.e_lfanew + pe_header_t.sizeof; // adjust to optional header
	ushort optmagic = void;
	if (adbg_object_read_at(o, e_lfanew, &optmagic, ushort.sizeof)) {
		free(o.internal);
		o.internal = null;
		return adbg_errno();
	}
	
	switch (optmagic) {
	case PE_CLASS_32:
		if (adbg_object_read_at(o, e_lfanew, &internal.optheader, pe_optional_header_t.sizeof)) {
			free(o.internal);
			o.internal = null;
			return adbg_errno();
		}
		
		e_lfanew += pe_optional_header_t.sizeof; // adjust to directory
		if (adbg_object_read_at(o, e_lfanew, &internal.directory, pe_image_data_directory_t.sizeof)) {
			free(o.internal);
			o.internal = null;
			return adbg_errno();
		}
		
		e_lfanew += pe_image_data_directory_t.sizeof; // adjust to sections
		
		if (o.status & AdbgObjectInternalFlags.reversed) with (internal.optheader) {
			SizeOfCode	= adbg_bswap32(SizeOfCode);
			SizeOfInitializedData	= adbg_bswap32(SizeOfInitializedData);
			SizeOfUninitializedData	= adbg_bswap32(SizeOfUninitializedData);
			AddressOfEntryPoint	= adbg_bswap32(AddressOfEntryPoint);
			BaseOfCode	= adbg_bswap32(BaseOfCode);
			BaseOfData	= adbg_bswap32(BaseOfData);
			ImageBase	= adbg_bswap32(ImageBase);
			SectionAlignment	= adbg_bswap32(SectionAlignment);
			FileAlignment	= adbg_bswap32(FileAlignment);
			MajorOperatingSystemVersion	= adbg_bswap16(MajorOperatingSystemVersion);
			MinorOperatingSystemVersion	= adbg_bswap16(MinorOperatingSystemVersion);
			MajorImageVersion	= adbg_bswap16(MajorImageVersion);
			MinorImageVersion	= adbg_bswap16(MinorImageVersion);
			MajorSubsystemVersion	= adbg_bswap16(MajorSubsystemVersion);
			MinorSubsystemVersion	= adbg_bswap16(MinorSubsystemVersion);
			Win32VersionValue	= adbg_bswap32(Win32VersionValue);
			SizeOfImage	= adbg_bswap32(SizeOfImage);
			SizeOfHeaders	= adbg_bswap32(SizeOfHeaders);
			CheckSum	= adbg_bswap32(CheckSum);
			Subsystem	= adbg_bswap16(Subsystem);
			DllCharacteristics	= adbg_bswap16(DllCharacteristics);
			SizeOfStackReserve	= adbg_bswap32(SizeOfStackReserve);
			SizeOfStackCommit	= adbg_bswap32(SizeOfStackCommit);
			SizeOfHeapReserve	= adbg_bswap32(SizeOfHeapReserve);
			SizeOfHeapCommit	= adbg_bswap32(SizeOfHeapCommit);
			LoaderFlags	= adbg_bswap32(LoaderFlags);
			NumberOfRvaAndSizes	= adbg_bswap32(NumberOfRvaAndSizes);
		}
		break;
	case PE_CLASS_64:
		if (adbg_object_read_at(o, e_lfanew, &internal.optheader64, pe_optional_header64_t.sizeof)) {
			free(o.internal);
			o.internal = null;
			return adbg_errno();
		}
		
		e_lfanew += pe_optional_header64_t.sizeof; // adjust to directory
		if (adbg_object_read_at(o, e_lfanew, &internal.directory, pe_image_data_directory_t.sizeof)) {
			free(o.internal);
			o.internal = null;
			return adbg_errno();
		}
		
		e_lfanew += pe_image_data_directory_t.sizeof; // adjust to sections
		
		if (o.status & AdbgObjectInternalFlags.reversed) with (internal.optheader64) {
			SizeOfCode	= adbg_bswap32(SizeOfCode);
			SizeOfInitializedData	= adbg_bswap32(SizeOfInitializedData);
			SizeOfUninitializedData	= adbg_bswap32(SizeOfUninitializedData);
			AddressOfEntryPoint	= adbg_bswap32(AddressOfEntryPoint);
			BaseOfCode	= adbg_bswap32(BaseOfCode);
			ImageBase	= adbg_bswap64(ImageBase);
			SectionAlignment	= adbg_bswap32(SectionAlignment);
			FileAlignment	= adbg_bswap32(FileAlignment);
			MajorOperatingSystemVersion	= adbg_bswap16(MajorOperatingSystemVersion);
			MinorOperatingSystemVersion	= adbg_bswap16(MinorOperatingSystemVersion);
			MajorImageVersion	= adbg_bswap16(MajorImageVersion);
			MinorImageVersion	= adbg_bswap16(MinorImageVersion);
			MajorSubsystemVersion	= adbg_bswap16(MajorSubsystemVersion);
			MinorSubsystemVersion	= adbg_bswap16(MinorSubsystemVersion);
			Win32VersionValue	= adbg_bswap32(Win32VersionValue);
			SizeOfImage	= adbg_bswap32(SizeOfImage);
			SizeOfHeaders	= adbg_bswap32(SizeOfHeaders);
			CheckSum	= adbg_bswap32(CheckSum);
			Subsystem	= adbg_bswap16(Subsystem);
			DllCharacteristics	= adbg_bswap16(DllCharacteristics);
			SizeOfStackReserve	= adbg_bswap64(SizeOfStackReserve);
			SizeOfStackCommit	= adbg_bswap64(SizeOfStackCommit);
			SizeOfHeapReserve	= adbg_bswap64(SizeOfHeapReserve);
			SizeOfHeapCommit	= adbg_bswap64(SizeOfHeapCommit);
			LoaderFlags	= adbg_bswap32(LoaderFlags);
			NumberOfRvaAndSizes	= adbg_bswap32(NumberOfRvaAndSizes);
		}
		break;
	case PE_CLASS_ROM: // NOTE: ROM have no optional header and directories
		if (adbg_object_read_at(o, e_lfanew, &internal.optheaderrom, pe_optional_headerrom_t.sizeof)) {
			free(o.internal);
			o.internal = null;
			return adbg_errno();
		}
		e_lfanew += pe_optional_headerrom_t.sizeof; // adjust to sections, no directories
		
		if (o.status & AdbgObjectInternalFlags.reversed) with (internal.optheaderrom) {
			SizeOfCode	= adbg_bswap32(SizeOfCode);
			SizeOfInitializedData	= adbg_bswap32(SizeOfInitializedData);
			SizeOfUninitializedData	= adbg_bswap32(SizeOfUninitializedData);
			AddressOfEntryPoint	= adbg_bswap32(AddressOfEntryPoint);
			BaseOfCode	= adbg_bswap32(BaseOfCode);
			BaseOfData	= adbg_bswap32(BaseOfData);
			BaseOfBss	= adbg_bswap32(BaseOfBss);
			GprMask	= adbg_bswap32(GprMask);
			CprMask[0]	= adbg_bswap32(CprMask[0]);
			CprMask[1]	= adbg_bswap32(CprMask[1]);
			CprMask[2]	= adbg_bswap32(CprMask[2]);
			CprMask[3]	= adbg_bswap32(CprMask[3]);
			GpValue	= adbg_bswap32(GpValue);
		}
		return 0;
	default:
		return adbg_oops(AdbgError.objectInvalidClass);
	}
	
	internal.locsections = mzhdr.e_lfanew; // updated to point at section headers
	
	// If reversed and it's not a "rom" image, swap dictionary entries
	if (o.status & AdbgObjectInternalFlags.reversed && optmagic != PE_CLASS_ROM) with (internal.directory) {
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
	
	memcpy(&internal.mz_header, mzhdr, mz_header_t.sizeof);
	
	adbg_object_postload(o, AdbgObject.pe, &adbg_object_pe_unload);
	
	return 0;
}

void adbg_object_pe_unload(adbg_object_t *o) {
	if (o == null) return;
	if (o.internal == null) return;
	
	with (cast(internal_pe_t*)o.internal) {
	if (sections) free(sections);
	if (r_sections) free(r_sections);
	
	if (export_directory) free(export_directory);
	if (r_export_entries) free(r_export_entries);
	
	if (import_buffer) free(import_buffer);
	
	if (debug_buffer) free(debug_buffer);
	if (r_debug_entries) free(r_debug_entries);
	
	if (load32_directory) free(load32_directory);
	
	if (rich_header_buffer) free(rich_header_buffer);
	}
	
	free(o.internal);
}

// NOTE: Mapping directory RVAs to file offsets
//       1. Given the Directory RVA, map it to a section
//       2. Calculate the Section RVA with the Directory RVA

// Given the directory RVA, map it to a section
private
pe_section_entry_t* adbg_object_pe_directory_section(adbg_object_t *o, uint rva) {
	version (Trace) trace("o=%p rva=%#x", o, rva);
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	
	internal_pe_t* internal = cast(internal_pe_t*)o.internal;
	ushort seccnt = internal.header.NumberOfSections;
	for (ushort i; i < seccnt; ++i) {
		// Function sets error
		pe_section_entry_t *section = adbg_object_pe_section(o, i);
		if (section == null) return null;
		
		// If RVA is outside section's VA and range
		with (section) if (rva < VirtualAddress || rva > VirtualAddress + SizeOfRawData)
			continue;
		
		return section;
	}
	
	adbg_oops(AdbgError.unfindable);
	return null;
}

// Given a section and directory RVA, return absolute file offset
private
uint adbg_object_pe_directory_offset_section(pe_section_entry_t *section, uint dirrva) {
	version (Trace) trace("dir_rva=%#x", dirrva);
	if (section == null) return 0;
	with (section) return PointerToRawData + (dirrva - VirtualAddress);
}

// Given a directory RVA, return absolute file offset
private
uint adbg_object_pe_directory_offset(adbg_object_t *o, uint dirrva) {
	version (Trace) trace("dir_rva=%#x", dirrva);
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return 0;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return 0;
	}
	// Function checks null
	return adbg_object_pe_directory_offset_section(
		adbg_object_pe_directory_section(o, dirrva), dirrva);
}

pe_header_t* adbg_object_pe_header(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	return cast(pe_header_t*)o.internal;
}

// void* to force a pointer cast
// NOTE: then shouldn't there be a function to return the type of optional header?
void* adbg_object_pe_optional_header(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	internal_pe_t* internal = cast(internal_pe_t*)o.internal;
	if (internal.header.SizeOfOptionalHeader == 0) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	return &internal.optheader;
}

pe_image_data_directory_t* adbg_object_pe_directories(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	internal_pe_t* internal = cast(internal_pe_t*)o.internal;
	if (internal.header.SizeOfOptionalHeader == 0) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	return &internal.directory;
}

mz_header_t* adbg_object_pe_mz_header(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	
	internal_pe_t* internal = cast(internal_pe_t*)o.internal;
	return &internal.mz_header;
}

// NOTE: Observed offsets are all 4-byte aligned compatible
pe_rich_header_t* adbg_object_pe_rich_header(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	
	internal_pe_t* internal = cast(internal_pe_t*)o.internal;
	if (internal.rich_buffer_size)
		return &internal.rich_header;
	
	// The rich signature is in-between the DOS stub and the PE header.
	// We'll need at least that much memory, but usually not after 1.5 KiB.
	with (internal) {
		size_t bsize = adbg_aligndown(mz_header.e_lfanew - mz_header_t.sizeof, uint.sizeof);
		rich_buffer_size = min(bsize, MiB!1);
		version(Trace) trace("bsize=%zu ebsize=%zu", bsize, rich_buffer_size);
		rich_header_buffer = adbg_object_readalloc_at(o, mz_header_t.sizeof, rich_buffer_size, 0);
		if (rich_header_buffer == null)
			return null;
	}
	
	// 1. Starting from the DOS stub, go upwards to locate header end
	// 2. Downwards, try the XOR key on 4-byte values until we find header start
	// 3. Verify NULL padding
	// 4. Get entries by XOR'ing the key
	uint *p = cast(uint*)internal.rich_header_buffer;
	uint *max = cast(uint*)(internal.rich_header_buffer + internal.rich_buffer_size);
	void *min = void;
	size_t c = void;
	
	// Find end of header
	uint k; // xor key
	for (; p < max; ++p) {
		if (*p != MAGIC_RICH_ENDID)
			continue;
		if (p + 3 >= max) // key position + padding
			goto Lnotfound;
		if (p[2] || p[3]) continue; // padding must be null
		k = p[1];
		version(Trace) trace("k=%x", k);
		break;
	}
	
	if (k == 0)
		goto Lnotfound;
	
	// Find start of header
	min = cast(uint*)internal.rich_header_buffer;
	for (c = 0, p -= 2; p >= min; p -= 2, ++c) {
		// Match signature and 3 null paddings
		version(Trace) trace("m=%x p1=%x p2=%x p3=%x xor m=%x p1=%x p2=%x p3=%x",
			*p, p[1], p[2], p[3],
			(*p ^ k), p[1]^k, p[2]^k, p[3]^k);
		if ((*p ^ k) != MAGIC_RICH_BEGID || p[1] ^ k || p[2] ^ k || p[3] ^ k)
			continue;
		
		// Found starting signature
		version(Trace) trace("count=%zu", c);
		internal.rich_header.itemcount = c;
		internal.rich_header.items = cast(pe_rich_header_item_t*)(p + 4);
		
		// Pass XOR key to values
		pe_rich_header_item_t *item = internal.rich_header.items;
		for (size_t i; i < c; ++i, ++item) {
			item.id    ^= k;
			item.count ^= k;
		}
		
		return &internal.rich_header;
	}
	
Lnotfound:
	adbg_oops(AdbgError.objectItemNotFound);
	free(internal.rich_header_buffer);
	internal.rich_header_buffer = null;
	return null;
}

const(char)* adbg_object_pe_rich_prodid_string(ushort prodid) {
	switch (prodid) {
	case 0x0001:	return "Linker generated import object version 0";
	case 0x0002:	return "LINK 5.10 (Visual Studio 97 SP3)";
	case 0x0003:	return "LINK 5.10 (Visual Studio 97 SP3) OMF to COFF conversion";
	case 0x0004:	return "LINK 6.00 (Visual Studio 98)";
	case 0x0005:	return "LINK 6.00 (Visual Studio 98) OMF to COFF conversion";
	case 0x0006:	return "CVTRES 5.00";
	case 0x0007:	return "VB 5.0 native code";
	case 0x0008:	return "VC++ 5.0 C/C++";
	case 0x0009:	return "VB 6.0 native code";
	case 0x000A:	return "VC++ 6.0 C";
	case 0x000B:	return "VC++ 6.0 C++";
	case 0x000C:	return "ALIASOBJ.EXE (CRT Tool that builds OLDNAMES.LIB)";
	case 0x000D:	return "VB 6.0 generated object";
	case 0x000E:	return "MASM 6.13";
	case 0x000F:	return "MASM 7.01";
	case 0x0010:	return "LINK 5.11";
	case 0x0011:	return "LINK 5.11 OMF to COFF conversion";
	case 0x0012:	return "MASM 6.14 (MMX2 support)";
	case 0x0013:	return "LINK 5.12";
	case 0x0014:	return "LINK 5.12 OMF to COFF conversion";
	default:	return null;
	}
}

pe_section_entry_t* adbg_object_pe_section(adbg_object_t *o, size_t index) {
	version (Trace) trace("o=%p index=%u", o, cast(uint)index);
	
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	if (index >= MAXIMUM_SECTIONS) {
		adbg_oops(AdbgError.indexBounds);
		return null;
	}
	
	internal_pe_t *internal = cast(internal_pe_t*)o.internal;
	
	ushort count = internal.header.NumberOfSections;
	if (index >= count || index >= MAXIMUM_SECTIONS) {
		adbg_oops(AdbgError.indexBounds);
		return null;
	}
	
	// Otherwise, load section headers
	if (internal.sections == null) {
		size_t totsize = count * pe_section_entry_t.sizeof;
		internal.sections = cast(pe_section_entry_t*)malloc(totsize);
		if (internal.sections == null) {
			adbg_oops(AdbgError.crt);
			return null;
		}
		if (adbg_object_read_at(o, internal.locsections, internal.sections, totsize)) { // sets error
			free(internal.sections);
			internal.sections = null;
			return null;
		}
		
		// Init swapping stuff if required
		if (o.status & AdbgObjectInternalFlags.reversed) {
			internal.r_sections = cast(bool*)malloc(count);
			if (internal.r_sections == null) {
				adbg_oops(AdbgError.crt);
				free(internal.sections);
				internal.sections = null;
				return null;
			}
		}
	}
	
	pe_section_entry_t *section = &internal.sections[index];
	
	// If needs to be swapped
	if (o.status & AdbgObjectInternalFlags.reversed && internal.r_sections[index] == false) with (section) {
		VirtualSize	= adbg_bswap32(VirtualSize);
		VirtualAddress	= adbg_bswap32(VirtualAddress);
		SizeOfRawData	= adbg_bswap32(SizeOfRawData);
		PointerToRawData	= adbg_bswap32(PointerToRawData);
		PointerToRelocations	= adbg_bswap32(PointerToRelocations);
		PointerToLinenumbers	= adbg_bswap32(PointerToLinenumbers);
		NumberOfRelocations	= adbg_bswap16(NumberOfRelocations);
		NumberOfLinenumbers	= adbg_bswap16(NumberOfLinenumbers);
		Characteristics	= adbg_bswap32(Characteristics);
		internal.r_sections[index] = true;
	}
	
	return section;
}

// TODO:
// - [x] ExportTable: Size includes everything
// - [x] ImportTable: Size only includes descriptor tables
// - [ ] ResourceTable
// - [ ] ExceptionTable
// - [ ] CertificateTable
// - [ ] BaseRelocationTable
// - [x] DebugDirectory
// - [ ] ArchitectureData
// - [ ] GlobalPtr
// - [ ] TLSTable: Size includes everything
// - [ ] LoadConfigurationTable: Size includes everything
// - [ ] BoundImportTable
// - [ ] ImportAddressTable
// - [ ] DelayImport
// - [ ] CLRHeader

//
// Export directory functions
//

// One descriptor table, multiple entries, because one module emits one table.
//   Name -> Name of the module
//   ExportAddressTable -> raw address to RVAs
//     AddressTableEntries for count
//     RVA -> hint + entry
pe_export_descriptor_t* adbg_object_pe_export(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	
	internal_pe_t *internal = cast(internal_pe_t*)o.internal;
	if (internal.header.SizeOfOptionalHeader == 0 ||
		internal.directory.ExportTable.size == 0) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	// If not already loaded
	if (internal.export_directory == null) {
		// Function sets error
		uint offset = adbg_object_pe_directory_offset(o, internal.directory.ExportTable.rva);
		if (offset == 0)
			return null;
		
		// Load exports in memory
		uint size = internal.directory.ExportTable.size;
		internal.export_directory = cast(pe_export_descriptor_t*)malloc(size);
		if (internal.export_directory == null) {
			adbg_oops(AdbgError.crt);
			return null;
		}
		if (adbg_object_read_at(o, offset, internal.export_directory, size)) // sets error
			return null;
		
		// If need to be swapped
		if (o.status & AdbgObjectInternalFlags.reversed) with (internal.export_directory) {
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
		}
	}
	
	// ExportFlags must be zero
	if (internal.export_directory.ExportFlags != 0) {
		adbg_oops(AdbgError.unavailable);
		free(internal.export_directory);
		internal.export_directory = null;
		return null;
	}
	
	return internal.export_directory;
}

const(char)* adbg_object_pe_export_module_name(adbg_object_t *o, pe_export_descriptor_t *export_) {
	if (o == null || export_ == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.unimplemented);
		return null;
	}
	internal_pe_t *internal = cast(internal_pe_t*)o.internal;
	if (internal.header.SizeOfOptionalHeader == 0 ||
		internal.directory.ExportTable.size == 0) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	// directory_exports (offset) - ExportTable.rva + export.Name
	// or try: directory_exports + sizeof(export_descriptor_t) ?
	void* base = cast(void*)export_ -
		internal.directory.ExportTable.rva +
		export_.Name;
	if (adbg_bits_ptrbounds(base, 2, export_, internal.directory.ExportTable.size)) {
		adbg_oops(AdbgError.offsetBounds); // or assertion?
		return null;
	}
	
	return cast(const(char)*)base;
}

pe_export_entry_t* adbg_object_pe_export_entry_name(adbg_object_t *o, PE_EXPORT_DESCRIPTOR *export_, size_t index) {
	if (o == null || export_ == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.unimplemented);
		return null;
	}
	
	if (index >= export_.NumberOfNamePointers) {
		adbg_oops(AdbgError.indexBounds);
		return null;
	}
	
	internal_pe_t *internal = cast(internal_pe_t*)o.internal;
	if (internal.header.SizeOfOptionalHeader == 0 ||
		internal.directory.ExportTable.size == 0) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	// Entry table
	void* base = cast(void*)export_ -
		internal.directory.ExportTable.rva +
		export_.NamePointer;
	if (adbg_bits_ptrbounds(base, pe_export_entry_t.sizeof, export_, internal.directory.ExportTable.size)) {
		adbg_oops(AdbgError.offsetBounds); // or assertion?
		return null;
	}
	
	// Check bounds with name pointer and requested index
	pe_export_entry_t *entry = cast(pe_export_entry_t*)base + index;
	if (adbg_bits_ptrbounds(entry, pe_export_entry_t.sizeof, export_, internal.directory.ExportTable.size)) {
		adbg_oops(AdbgError.offsetBounds); // or assertion?
		return null;
	}
	
	if (o.status & AdbgObjectInternalFlags.reversed && internal.r_export_entries[index] == false) with (entry) {
		entry.Export = adbg_bswap32(entry.Export);
		internal.r_export_entries[index] = true;
	}
	
	return entry;
}

const(char)* adbg_object_pe_export_name_string(adbg_object_t *o,
	pe_export_descriptor_t *export_, pe_export_entry_t *entry) {
	if (o == null || export_ == null || entry == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.unimplemented);
		return null;
	}
	
	internal_pe_t *internal = cast(internal_pe_t*)o.internal;
	if (internal.header.SizeOfOptionalHeader == 0 ||
		internal.directory.ExportTable.size == 0) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	// NOTE: Export Table bounds
	//       If the address specified is not within the export section (as
	//       defined by the address and length that are indicated in the
	//       optional header), the field is an Export RVA: an actual
	//       address in code or data. Otherwise, the field is a Forwarder
	//       RVA, which names a symbol in another DLL.
	
	//TODO: Forwarder check
	//if (entry.Export >= o.i.pe.directory.ExportTable.size)
	//	return null;
	
	void *base = cast(void*)export_ -
		internal.directory.ExportTable.rva +
		entry.Export;
	if (adbg_bits_ptrbounds(base, 2, export_, internal.directory.ExportTable.size)) {
		adbg_oops(AdbgError.offsetBounds); // or assertion?
		return null;
	}
	
	return cast(const(char)*)base;
}

//
// Import directory functions
//

// NOTE: Import directory handling
//       Because the import directory is not self-contained (its size only reflects headers),
//       the entire section is loaded in memory, hoping that nothing 
// Multiple tables, multiple entries per table
pe_import_descriptor_t* adbg_object_pe_import(adbg_object_t *o, size_t index) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.unimplemented);
		return null;
	}
	
	internal_pe_t *internal = cast(internal_pe_t*)o.internal;
	if (internal.header.SizeOfOptionalHeader == 0 ||
		internal.directory.ImportTable.size <= pe_import_descriptor_t.sizeof) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	// NOTE: The last directory entry is empty (filled with null values),
	//       which indicates the end of the directory table.
	// NOTE: In theory, the entire set of import tables and names should be in the same section
	//       But, name RVA *could* point outside of it as Windows loads the entire image in memory
	
	// If zero, or just "one" entry
	if (internal.directory.ImportTable.size <= pe_import_descriptor_t.sizeof) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	size_t count = (internal.directory.ImportTable.size / pe_import_descriptor_t.sizeof) - 1;
	version (Trace) trace("count=%zu", count);
	if (index >= count) {
		adbg_oops(AdbgError.indexBounds);
		return null;
	}
	
	// Load the section associated with the import directory
	if (internal.import_directory == null) {
		internal.import_section = adbg_object_pe_directory_section(o, internal.directory.ImportTable.rva);
		if (internal.import_section == null) {
			adbg_oops(AdbgError.unavailable);
			return null;
		}
		
		uint secsize = internal.import_section.SizeOfRawData;
		uint secoffs = internal.import_section.PointerToRawData;
		
		// Get file offset of import descriptors
		uint offset = adbg_object_pe_directory_offset_section(internal.import_section, internal.directory.ImportTable.rva);
		
		//TODO: Check if section already loaded
		//      While Load Config and TLS tables might be in the same section,
		//      they also could not be. So let's just hope this fuckery is only for imports.
		// Load the section because import table only contains descriptors
		internal.import_buffer = malloc(secsize);
		if (internal.import_buffer == null) {
			adbg_oops(AdbgError.crt);
			return null;
		}
		if (adbg_object_read_at(o, secoffs, internal.import_buffer, secsize)) {
			free(internal.import_buffer);
			internal.import_buffer = null;
			return null;
		}
		
		// Adjust offset to point from base of section to import descritor tables
		internal.import_directory = cast(pe_import_descriptor_t*)(internal.import_buffer + (offset - secoffs));
		if (adbg_bits_ptrbounds(internal.import_directory, pe_import_descriptor_t.sizeof,
			internal.import_buffer, secsize)) {
			adbg_oops(AdbgError.offsetBounds);
			free(internal.import_buffer);
			internal.import_buffer = null;
			return null;
		}
	}
	
	// Select descriptor
	pe_import_descriptor_t *import_ = internal.import_directory + index;
	if (adbg_bits_ptrbounds(import_, pe_import_descriptor_t.sizeof,
		internal.import_buffer, internal.import_section.SizeOfRawData)) {
		adbg_oops(AdbgError.offsetBounds);
		return null;
	}
	if (import_.Characteristics == 0) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	//TODO: swap import directory entries
	/*if (o.status & AdbgObjectInternalFlags.reversed && internal.r_import_desc[index] == false) with (import_) {
		Characteristics	= adbg_bswap32(Characteristics);
		TimeDateStamp	= adbg_bswap32(TimeDateStamp);
		ForwarderChain	= adbg_bswap32(ForwarderChain);
		Name	= adbg_bswap32(Name);
		FirstThunk	= adbg_bswap32(FirstThunk);
		internal.r_import_desc[index] = true;
	}*/
	
	return import_;
}

// get module name out of import descriptor
const(char)* adbg_object_pe_import_module_name(adbg_object_t *o, pe_import_descriptor_t *import_) {
	if (o == null || import_ == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.unimplemented);
		return null;
	}
	
	internal_pe_t *internal = cast(internal_pe_t*)o.internal;
	if (internal.header.SizeOfOptionalHeader == 0 ||
		internal.directory.ImportTable.size <= pe_import_descriptor_t.sizeof) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	void* name = cast(void*)internal.import_directory -
		internal.directory.ImportTable.rva +
		import_.Name;
	with (internal)
	if (adbg_bits_ptrbounds(name, 2, import_buffer, import_section.SizeOfRawData)) {
		adbg_oops(AdbgError.offsetBounds);
		return null;
	}
	
	return cast(const(char)*)name;
}

//TODO: Byte-swap import look-up table entries

pe_import_entry32_t* adbg_object_pe_import_entry32(adbg_object_t *o, pe_import_descriptor_t *import_, size_t index) {
	if (o == null || import_ == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.unimplemented);
		return null;
	}
	
	internal_pe_t *internal = cast(internal_pe_t*)o.internal;
	if (internal.header.SizeOfOptionalHeader == 0 ||
		internal.directory.ImportTable.size <= pe_import_descriptor_t.sizeof) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	pe_import_entry32_t* entry = cast(pe_import_entry32_t*)(
		cast(void*)internal.import_directory +
		(import_.Characteristics - internal.directory.ImportTable.rva)) +
		index;
	with (internal)
	if (adbg_bits_ptrbounds(entry, pe_import_entry32_t.sizeof, import_buffer, import_section.SizeOfRawData)) {
		adbg_oops(AdbgError.offsetBounds);
		return null;
	}
	
	//TODO: Swap import entry
	/*if (o.status & AdbgObjectInternalFlags.reversed && internal.r_import_entries[index] == false) {
		entry.ordinal = adbg_bswap32(entry.ordinal);
		internal.r_import_entries[index] = true;
	}*/
	
	// Not supported
	if (entry.ordinal == 0) {
		adbg_oops(AdbgError.unimplemented);
		return null;
	}
	
	return entry;
}

/*ushort* adbg_object_pe_import_entry32_hint(adbg_object_t *o, PE_IMPORT_DESCRIPTOR *import_, PE_IMPORT_ENTRY32 *im32) {
	if (o == null || import_ == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.unimplemented);
		return null;
	}
	
	internal_pe_t *internal = cast(internal_pe_t*)o.internal;
	if (internal.header.SizeOfOptionalHeader == 0 ||
		internal.directory.ImportTable.size <= pe_import_descriptor_t.sizeof) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	void* base =
		internal.import_directory -
		internal.directory.ImportTable.rva +
		im32.rva;
	with (internal)
	if (adbg_bits_ptr_outside(entry, import_buffer, import_section.SizeOfRawData)) {
		adbg_oops(AdbgError.offsetBounds);
		return null;
	}
	
	return cast(ushort*)base;
}*/

pe_import_entry64_t* adbg_object_pe_import_entry64(adbg_object_t *o, pe_import_descriptor_t *import_, size_t index) {
	if (o == null || import_ == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.unimplemented);
		return null;
	}
	
	internal_pe_t *internal = cast(internal_pe_t*)o.internal;
	if (internal.header.SizeOfOptionalHeader == 0 ||
		internal.directory.ImportTable.size <= pe_import_descriptor_t.sizeof) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	pe_import_entry64_t* entry = cast(pe_import_entry64_t*)(
		cast(void*)internal.import_directory +
		(import_.Characteristics - internal.directory.ImportTable.rva)) +
		index;
	with (internal)
	if (adbg_bits_ptrbounds(entry, pe_import_entry64_t.sizeof, import_buffer, import_section.SizeOfRawData)) {
		adbg_oops(AdbgError.offsetBounds);
		return null;
	}
	
	//TODO: Swap import entry
	
	// Not supported
	if (entry.ordinal == 0) {
		adbg_oops(AdbgError.unimplemented);
		return null;
	}
	
	return entry;
}

/*ushort* adbg_object_pe_import_entry64_hint(adbg_object_t *o, PE_IMPORT_DESCRIPTOR *import_, PE_IMPORT_ENTRY64 *im64) {
	if (o == null || import_ == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.i.pe.directory_imports == null) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	ushort* base = cast(ushort*)
		((cast(char*)o.i.pe.directory_imports - o.i.pe.directory.ImportTable.rva) + im64.rva);
	
	version (Trace) trace("base=%p fs=%zx", base, o.file_size);
	
	if (adbg_object_outboundp(o, base)) {
		adbg_oops(AdbgError.offsetBounds);
		return null;
	}
	
	return base;
}*/

// Classless functions
// TODO: Optimize these, maybe cache the last result in internals

void* adbg_object_pe_import_entry(adbg_object_t *o, pe_import_descriptor_t *import_, size_t index) {
	if (o == null || import_ == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.unimplemented);
		return null;
	}
	
	internal_pe_t *internal = cast(internal_pe_t*)o.internal;
	if (internal.header.SizeOfOptionalHeader == 0 ||
		internal.directory.ImportTable.size <= pe_import_descriptor_t.sizeof) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	switch (internal.optheader.Magic) {
	case PE_CLASS_32:
		return adbg_object_pe_import_entry32(o, import_, index);
	case PE_CLASS_64:
		return adbg_object_pe_import_entry64(o, import_, index);
	default:
		adbg_oops(AdbgError.objectInvalidClass);
		return null;
	}
}

uint adbg_object_pe_import_entry_rva(adbg_object_t *o, pe_import_descriptor_t *import_, void *entry) {
	if (o == null || import_ == null || entry == null) {
		adbg_oops(AdbgError.invalidArgument);
		return 0;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.unimplemented);
		return 0;
	}
	
	internal_pe_t *internal = cast(internal_pe_t*)o.internal;
	if (internal.header.SizeOfOptionalHeader == 0 ||
		internal.directory.ImportTable.size <= pe_import_descriptor_t.sizeof) {
		adbg_oops(AdbgError.unavailable);
		return 0;
	}
	
	switch (internal.optheader.Magic) {
	case PE_CLASS_32:
		return (cast(pe_import_entry32_t*)entry).rva;
	case PE_CLASS_64:
		return (cast(pe_import_entry64_t*)entry).rva;
	default:
		adbg_oops(AdbgError.objectInvalidClass);
		return 0;
	}
}

ushort adbg_object_pe_import_entry_hint(adbg_object_t *o, pe_import_descriptor_t *import_, void *entry) {
	if (o == null || import_ == null || entry == null) {
		adbg_oops(AdbgError.invalidArgument);
		return 0;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.unimplemented);
		return 0;
	}
	
	internal_pe_t *internal = cast(internal_pe_t*)o.internal;
	if (internal.header.SizeOfOptionalHeader == 0 ||
		internal.directory.ImportTable.size <= pe_import_descriptor_t.sizeof) {
		adbg_oops(AdbgError.unavailable);
		return 0;
	}
	
	ushort *hint = void;
	switch (internal.optheader.Magic) {
	case PE_CLASS_32:
		pe_import_entry32_t *entry32 = cast(pe_import_entry32_t*)entry;
		
		// By ordinal
		if (entry32.ordinal >= 0x8000_0000) {
			adbg_oops(AdbgError.unavailable);
			return 0;
		}
		
		// By RVA
		hint = cast(ushort*)(
			cast(void*)internal.import_directory -
			internal.directory.ImportTable.rva +
			entry32.rva);
		break;
	case PE_CLASS_64:
		pe_import_entry64_t *entry64 = cast(pe_import_entry64_t*)entry;
		
		// By ordinal
		if (entry64.ordinal >= 0x8000_0000) {
			adbg_oops(AdbgError.unavailable);
			return 0;
		}
		
		// By RVA
		hint = cast(ushort*)(
			cast(void*)internal.import_directory -
			internal.directory.ImportTable.rva +
			entry64.rva);
		break;
	default:
		adbg_oops(AdbgError.objectInvalidClass);
		return 0;
	}
	
	with (internal)
	if (adbg_bits_ptrbounds(hint, ushort.sizeof, import_buffer, import_section.SizeOfRawData)) {
		adbg_oops(AdbgError.offsetBounds);
		return 0;
	}
	
	return *hint;
}

const(char)* adbg_object_pe_import_entry_string(adbg_object_t *o, pe_import_descriptor_t *import_, void *entry) {
	if (o == null || import_ == null || entry == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.unimplemented);
		return null;
	}
	
	internal_pe_t *internal = cast(internal_pe_t*)o.internal;
	if (internal.header.SizeOfOptionalHeader == 0 ||
		internal.directory.ImportTable.size <= pe_import_descriptor_t.sizeof) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	ushort *hint = void;
	switch (internal.optheader.Magic) {
	case PE_CLASS_32:
		pe_import_entry32_t *entry32 = cast(pe_import_entry32_t*)entry;
		
		// By ordinal
		if (entry32.ordinal >= 0x8000_0000) {
			adbg_oops(AdbgError.unavailable);
			return null;
		}
		
		// By RVA
		hint = cast(ushort*)(
			cast(void*)internal.import_directory -
			internal.directory.ImportTable.rva +
			entry32.rva);
		break;
	case PE_CLASS_64:
		pe_import_entry64_t *entry64 = cast(pe_import_entry64_t*)entry;
		
		// By ordinal
		if (entry64.ordinal >= 0x8000_0000_0000_0000L) {
			adbg_oops(AdbgError.unavailable);
			return null;
		}
		
		// By RVA
		hint = cast(ushort*)(
			cast(void*)internal.import_directory -
			internal.directory.ImportTable.rva +
			entry64.rva);
		break;
	default:
		adbg_oops(AdbgError.objectInvalidClass);
		return null;
	}
	
	hint++;
	
	with (internal)
	if (adbg_bits_ptrbounds(hint, 2, import_buffer, import_section.SizeOfRawData)) {
		adbg_oops(AdbgError.offsetBounds);
		return null;
	}
	
	return cast(const(char)*)hint;
}
//
// Debug directory functions
//

pe_debug_directory_entry_t* adbg_object_pe_debug_directory(adbg_object_t *o, size_t index) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	
	internal_pe_t *internal = cast(internal_pe_t*)o.internal;
	if (internal.header.SizeOfOptionalHeader == 0 ||
		internal.directory.DebugDirectory.size == 0) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	size_t count = internal.directory.DebugDirectory.size / PE_DEBUG_DIRECTORY.sizeof;
	if (index >= count) {
		adbg_oops(AdbgError.indexBounds);
		return null;
	}
	
	// Load debug directory
	if (internal.debug_directory == null) {
		// Same as imports, load the section
		internal.debug_section = adbg_object_pe_directory_section(o, internal.directory.DebugDirectory.rva);
		if (internal.debug_section == null) {
			adbg_oops(AdbgError.unavailable);
			return null;
		}
		
		uint secsize = internal.debug_section.SizeOfRawData;
		uint secoffs = internal.debug_section.PointerToRawData;
		
		// Get file offset of debug descriptors
		uint offset = adbg_object_pe_directory_offset_section(internal.debug_section, internal.directory.DebugDirectory.rva);
		
		version (Trace) trace("ssize=%u soff=%u off=%u", secsize, secoffs, offset);
		
		// Load the section because debug table only contains descriptors
		internal.debug_buffer = malloc(secsize);
		if (internal.debug_buffer == null) {
			adbg_oops(AdbgError.crt);
			return null;
		}
		if (adbg_object_read_at(o, secoffs, internal.debug_buffer, secsize)) {
			free(internal.debug_buffer);
			internal.debug_buffer = null;
			return null;
		}
		
		// Adjust offset to point from base of section to import descritor tables
		internal.debug_directory =
			cast(pe_debug_directory_entry_t*)(cast(void*)internal.debug_buffer + (offset - secoffs));
		if (adbg_bits_ptrbounds(internal.debug_directory, pe_debug_directory_entry_t.sizeof,
			internal.debug_buffer, secsize)) {
			adbg_oops(AdbgError.offsetBounds);
			free(internal.debug_buffer);
			internal.debug_buffer = null;
			return null;
		}
		
		// Allocate reverse status bools
		internal.r_debug_entries = cast(bool*)malloc(count);
		if (internal.r_debug_entries == null) {
			adbg_oops(AdbgError.crt);
			free(internal.debug_buffer);
			internal.debug_buffer = null;
			return null;
		}
	}
	
	// Select directory entry
	pe_debug_directory_entry_t *debug_ = internal.debug_directory + index;
	if (adbg_bits_ptrbounds(debug_, pe_debug_directory_entry_t.sizeof,
		internal.debug_buffer, internal.debug_section.SizeOfRawData)) {
		adbg_oops(AdbgError.offsetBounds);
		return null;
	}
	
	if (o.status & AdbgObjectInternalFlags.reversed && internal.r_debug_entries[index] == false) with (debug_) {
		Characteristics	= adbg_bswap32(Characteristics);
		TimeDateStamp	= adbg_bswap32(TimeDateStamp);
		MajorVersion	= adbg_bswap16(MajorVersion);
		MinorVersion	= adbg_bswap16(MinorVersion);
		Type	= adbg_bswap32(Type);
		SizeOfData	= adbg_bswap32(SizeOfData);
		AddressOfRawData	= adbg_bswap32(AddressOfRawData);
		PointerToRawData	= adbg_bswap32(PointerToRawData);
		internal.r_debug_entries[index] = true;
	}
	return debug_;
}

void* adbg_object_pe_debug_directory_data(adbg_object_t *o, pe_debug_directory_entry_t *entry) {
	if (o == null || entry == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	
	internal_pe_t *internal = cast(internal_pe_t*)o.internal;
	if (internal.header.SizeOfOptionalHeader == 0 ||
		internal.directory.DebugDirectory.size == 0) {
		adbg_oops(AdbgError.unavailable);
		return null;
	}
	
	//TODO: Type size checking (minimum fulfillment)?
	void* data = malloc(entry.SizeOfData);
	if (data == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	if (adbg_object_read_at(o, entry.PointerToRawData, data, entry.SizeOfData))
		return null;
	
	return data;
}
void adbg_object_pe_debug_directory_data_close(void* entry) {
	if (entry) free(entry);
}

//
// Other helpers
//

AdbgMachine adbg_object_pe_machine(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return AdbgMachine.unknown;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return AdbgMachine.unknown;
	}
	pe_header_t* header = cast(pe_header_t*)o.internal;
	switch (header.Machine) {
	case PE_MACHINE_I386:	return AdbgMachine.i386;
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

const(char)* adbg_object_pe_machine_value_string(ushort Machine) {
	switch (Machine) {
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
	default:
		adbg_oops(AdbgError.objectInvalidMachine);
		return null;
	}
}

const(char)* adbg_object_pe_machine_string(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	return adbg_object_pe_machine_value_string((cast(pe_header_t*)o.internal).Machine);
}

const(char)* adbg_object_pe_magic_string(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	pe_optional_header_t* opthdr = &(cast(internal_pe_t*)o.internal).optheader;
	switch (opthdr.Magic) {
	case PE_CLASS_32:	return "PE32";
	case PE_CLASS_64:	return "PE32+";
	case PE_CLASS_ROM:	return "PE-ROM";
	default:
		adbg_oops(AdbgError.objectMalformed);
		return null;
	}
}

const(char)* adbg_object_pe_subsys_string(adbg_object_t *o) {
	if (o == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	if (o.internal == null) {
		adbg_oops(AdbgError.uninitiated);
		return null;
	}
	pe_optional_header_t* opthdr = &(cast(internal_pe_t*)o.internal).optheader;
	ushort subsystem = void;
	switch (opthdr.Magic) {
	case PE_CLASS_32: subsystem = opthdr.Subsystem; break;
	case PE_CLASS_64: subsystem = (cast(pe_optional_header64_t*)opthdr).Subsystem; break;
	default:
		adbg_oops(AdbgError.unavailable);
		return null;
	}
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
	case PE_SUBSYSTEM_XBOX_CODE_CATALOG:	return "XBOX Code Catalog";
	default:
		adbg_oops(AdbgError.objectInvalidType);
		return null;
	}
}

const(char)* adbg_object_pe_debug_type_string(uint type) {
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

const(char)* adbg_object_pe_kind_string(adbg_object_t *o) {
	if (o == null) return null;
	if (o.internal == null) return null;
	internal_pe_t *internal = cast(internal_pe_t*)o.internal;
	return internal.header.Characteristics & PE_CHARACTERISTIC_DLL ?
		`Dynamically Linked Library` : `Executable`;
}

private:

//TODO: Map linker version with load configuration sizes
// Exec        Version   Size
// putty-x86      0.73     92
// putty-amd64    0.73    148
