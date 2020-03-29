/**
 * Portable Executable loader.
 *
 * PE32 format for both images (executables) and objects (mscoff object files).
 *
 * Loosely based on Windows Kits\10\Include\10.0.17763.0\um\winnt.h
 *
 * License: BSD 3-Clause
 */
module debugger.file.objs.pe;

import core.stdc.stdio, core.stdc.inttypes;
import core.stdc.string : memset;
import debugger.file.loader : file_info_t, FileType;
import debugger.disasm.core : DisasmISA, disasm_msbisa; // ISA translation

extern (C):

//enum PE_OHDR_SIZE = 0xE0; // PE32
//enum PE_OHDR64_SIZE = 0xF0; // PE32+
//enum PE_OHDRROM_SIZE = 0x38; // PE-ROM
enum PE_OHDR_SIZE = PE_OPTIONAL_HEADER.sizeof + PE_IMAGE_DATA_DIRECTORY.sizeof; // PE32
enum PE_OHDR64_SIZE = PE_OPTIONAL_HEADER64.sizeof + PE_IMAGE_DATA_DIRECTORY.sizeof; // PE32+
enum PE_OHDRROM_SIZE = PE_OPTIONAL_HEADERROM.sizeof + PE_IMAGE_DATA_DIRECTORY.sizeof; // PE-ROM

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
	PE_FMT_ROM	= 0x0107,	// No longer used?
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

/// PE32 headers under one neat struct
struct PE_META { align(1):
	PE_HEADER hdr;
	// D can't do unions in functions (i.e. directly on stack)
	union {
		PE_OPTIONAL_HEADER ohdr;
		PE_OPTIONAL_HEADER64 ohdr64;
	}
	PE_IMAGE_DATA_DIRECTORY dir;
}

/// COFF file header (object and image)
struct PE_HEADER { align(1):
//	uint8_t  [4]Signature;
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
	uint32_t LoaderFlags; // Obsolete
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
	uint32_t va;	/// Relative Virtual Address
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

// IMAGE_IMPORT_DESCRIPTOR
struct PE_IMPORT_DESCRIPTOR { align(1):
	uint32_t OriginalFirstThunk;
	uint32_t TimeDateStamp; // time_t
	uint32_t ForwarderChain;
	uint32_t Name;
	uint32_t FirstThunk;
}

// Rough guesses for OS limits, offsets+4 since missing Size (already read)
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

int file_load_pe(file_info_t *fi) {
	if (fi.handle == null)
		return 1;

	if (fread(&fi.pe.hdr, PE_HEADER.sizeof, 1, fi.handle) == 0)
		return 1;

	fi.type = FileType.PE;

	// Image only: PE Optional Header + directories
	//TODO: MS recommends checking Size with Magic (e.g. Size=0xF0 = Magic=PE32+)
	if (fi.pe.hdr.SizeOfOptionalHeader) {
		int osz = fi.pe.hdr.SizeOfOptionalHeader -
			cast(int)PE_IMAGE_DATA_DIRECTORY.sizeof;
		if (osz <= 0)
			return 2;
		if (fread(&fi.pe.ohdr, osz, 1, fi.handle) == 0)
			return 1;
		if (fread(&fi.pe.dir, PE_IMAGE_DATA_DIRECTORY.sizeof, 1, fi.handle) == 0)
			return 1;
	}

	// Translate Machine field into DisasmABI
	switch (fi.pe.hdr.Machine) {
	case PE_MACHINE_I386: fi.isa = DisasmISA.x86; break;
	case PE_MACHINE_AMD64: fi.isa = DisasmISA.x86_64; break;
	case PE_MACHINE_RISCV32: fi.isa = DisasmISA.rv32; break;
	default:
	}
	fi.endian = disasm_msbisa(fi.isa);

	return 0;
}

const(char) *file_pe_str_mach(ushort mach) {
	const(char) *str_mach = void;
	switch (mach) {
	case PE_MACHINE_UNKNOWN:	str_mach = "UNKNOWN"; break;
	case PE_MACHINE_ALPHA:	str_mach = "ALPHA"; break;
	case PE_MACHINE_ALPHA64:	str_mach = "ALPHA64"; break;
	case PE_MACHINE_AM33:	str_mach = "AM33"; break;
	case PE_MACHINE_AMD64:	str_mach = "AMD64"; break;
	case PE_MACHINE_ARM:	str_mach = "ARM"; break;
	case PE_MACHINE_ARMNT:	str_mach = "ARMNT"; break;
	case PE_MACHINE_ARM64:	str_mach = "ARM64"; break;
	case PE_MACHINE_EBC:	str_mach = "EBC"; break;
	case PE_MACHINE_I386:	str_mach = "I386"; break;
	case PE_MACHINE_IA64:	str_mach = "IA64"; break;
	case PE_MACHINE_M32R:	str_mach = "M32R"; break;
	case PE_MACHINE_MIPS16:	str_mach = "MIPS16"; break;
	case PE_MACHINE_MIPSFPU:	str_mach = "MIPSFPU"; break;
	case PE_MACHINE_MIPSFPU16:	str_mach = "MIPSFPU16"; break;
	case PE_MACHINE_POWERPC:	str_mach = "POWERPC"; break;
	case PE_MACHINE_POWERPCFP:	str_mach = "POWERPCFP"; break;
	case PE_MACHINE_R3000:	str_mach = "R3000"; break;
	case PE_MACHINE_R4000:	str_mach = "R4000"; break;
	case PE_MACHINE_R10000:	str_mach = "R10000"; break;
	case PE_MACHINE_RISCV32:	str_mach = "RISCV32"; break;
	case PE_MACHINE_RISCV64:	str_mach = "RISCV64"; break;
	case PE_MACHINE_RISCV128:	str_mach = "RISCV128"; break;
	case PE_MACHINE_SH3:	str_mach = "SH3"; break;
	case PE_MACHINE_SH3DSP:	str_mach = "SH3DSP"; break;
	case PE_MACHINE_SH4:	str_mach = "SH4"; break;
	case PE_MACHINE_SH5:	str_mach = "SH5"; break;
	case PE_MACHINE_THUMB:	str_mach = "THUMB"; break;
	case PE_MACHINE_WCEMIPSV2:	str_mach = "WCEMIPSV2"; break;
	case PE_MACHINE_CLR:	str_mach = "CLR"; break;
	default: str_mach = null;
	}
	return str_mach;
}

const(char) *file_pe_str_magic(ushort mag) {
	const(char) *str_mag = void;
	switch (mag) {
	case PE_FMT_32: str_mag = "PE32"; break;
	case PE_FMT_64: str_mag = "PE32+"; break;
	case PE_FMT_ROM: str_mag = "PE-ROM"; break;
	default: str_mag = null;
	}
	return str_mag;
}

const(char) *file_pe_str_subsys(ushort subs) {
	const(char) *str_sys = void;
	switch (subs) {
	case PE_SUBSYSTEM_NATIVE:	str_sys = "Native"; break;
	case PE_SUBSYSTEM_WINDOWS_GUI:	str_sys = "Windows GUI"; break;
	case PE_SUBSYSTEM_WINDOWS_CUI:	str_sys = "Windows Console"; break;
	case PE_SUBSYSTEM_POSIX_CUI:	str_sys = "Posix Console"; break;
	case PE_SUBSYSTEM_NATIVE_WINDOWS:	str_sys = "Native Windows 9x Driver"; break;
	case PE_SUBSYSTEM_WINDOWS_CE_GUI:	str_sys = "Windows CE GUI"; break;
	case PE_SUBSYSTEM_EFI_APPLICATION:	str_sys = "EFI"; break;
	case PE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:	str_sys = "EFI Boot Service Driver"; break;
	case PE_SUBSYSTEM_EFI_RUNTIME_DRIVER:	str_sys = "EFI Runtime Driver"; break;
	case PE_SUBSYSTEM_EFI_ROM:	str_sys = "EFI ROM"; break;
	case PE_SUBSYSTEM_XBOX:	str_sys = "XBOX"; break;
	case PE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:	str_sys = "Windows Boot"; break;
	default: str_sys = null;
	}
	return str_sys;
}
