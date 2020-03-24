/**
 * Portable Executable loader.
 *
 * PE32 format for both images (executables) and objects (mscoff object files).
 *
 * License: BSD 3-Clause
 */
module debugger.file.objs.pe;

import core.stdc.stdio, core.stdc.inttypes;
import core.stdc.string : memset;
import debugger.file.loader : file_info_t, FileType;
import debugger.disasm.core : DisasmABI; // ISA translation

extern (C):

int file_load_pe(file_info_t *fi) {
	if (fi.handle == null)
		return 1;

	if (fread(&fi.pe.hdr, PE_HEADER.sizeof, 1, fi.handle) == 0)
		return 1;

	fi.type = FileType.PE;

	// Image only: PE Optional Header + directories
	//TODO: MS recommends checking Size with Magic (e.g. Size=0xF0 = Magic=PE32+)
	switch (fi.pe.hdr.SizeOfOptionalHeader) {
	case 0xE0: // PE32
		if (fread(&fi.pe.ohdr, PE_OPTIONAL_HEADER.sizeof, 1, fi.handle) == 0)
			return 1;
		break;
	case 0xF0: // PE32+
		if (fread(&fi.pe.ohdr64, PE_OPTIONAL_HEADER64.sizeof, 1, fi.handle) == 0)
			return 1;
		break;
	default:
		// zero the larger structs
		memset(&fi.pe.ohdr64, 0, PE_OPTIONAL_HEADER64.sizeof);
		memset(&fi.pe.dir, 0, PE_IMAGE_DATA_DIRECTORY.sizeof);
	}
	// union'd pointer
	if (fi.pe.hdr.SizeOfOptionalHeader) {
		if (fread(&fi.pe.dir, PE_IMAGE_DATA_DIRECTORY.sizeof, 1, fi.handle) == 0)
			return 1;
	}

	// Translate Machine field into DisasmABI
	switch (fi.pe.hdr.Machine) {
	case PE_MACHINE_I386: fi.isa = DisasmABI.x86; break;
	case PE_MACHINE_AMD64: fi.isa = DisasmABI.x86_64; break;
	case PE_MACHINE_RISCV32: fi.isa = DisasmABI.rv32; break;
	default:
	}

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
	case PE_HDR32: str_mag = "32"; break;
	case PE_HDR64: str_mag = "32+"; break;
	case PE_HDRROM: str_mag = "-ROM"; break;
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

struct PE_DIRECTORY { align(1):
	uint32_t va;	/// Relative Virtual Address
	uint32_t size;	/// Size in bytes
}

// IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
// MS recommends checking NumberOfRvaAndSizes but it always been 16
struct PE_IMAGE_DATA_DIRECTORY { align(1):
	PE_DIRECTORY ExportTable;
	PE_DIRECTORY ImportTable;
	PE_DIRECTORY ResourceTable;
	PE_DIRECTORY ExceptionTable;
	PE_DIRECTORY CertificateTable;	// File Pointer (instead of RVA)
	PE_DIRECTORY BaseRelocationTable;
	PE_DIRECTORY DebugDirectory;
	PE_DIRECTORY ArchitectureData;
	PE_DIRECTORY GlobalPtr;
	PE_DIRECTORY TLSTable;
	PE_DIRECTORY LoadConfigurationTable;
	PE_DIRECTORY BoundImportTable;
	PE_DIRECTORY ImportAddressTable;
	PE_DIRECTORY DelayImport;
	PE_DIRECTORY CLRHeader;	// Used to be COM+ Runtime Header
	PE_DIRECTORY Reserved;
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
	PE_SECTION_CHARACTERISTIC_NO_PAD	= 0x00000008,
	PE_SECTION_CHARACTERISTIC_CODE	= 0x00000020,
	PE_SECTION_CHARACTERISTIC_INITIALIZED_DATA	= 0x00000040,
	PE_SECTION_CHARACTERISTIC_UNINITIALIZED_DATA	= 0x00000080,
	PE_SECTION_CHARACTERISTIC_LNK_OTHER	= 0x00000100,	/// Reserved
	PE_SECTION_CHARACTERISTIC_LNK_INFO	= 0x00000200,
	PE_SECTION_CHARACTERISTIC_LNK_REMOVE	= 0x00000800,
	PE_SECTION_CHARACTERISTIC_LNK_COMDAT	= 0x00001000,
	PE_SECTION_CHARACTERISTIC_GPREL	= 0x00008000,
	PE_SECTION_CHARACTERISTIC_MEM_PURGEABLE	= 0x00010000,	/// Reserved
	PE_SECTION_CHARACTERISTIC_MEM_16BIT	= 0x00020000,	/// Reserved
	PE_SECTION_CHARACTERISTIC_MEM_LOCKED	= 0x00040000,	/// Reserved
	PE_SECTION_CHARACTERISTIC_PRELOAD	= 0x00080000,	/// Reserved
	PE_SECTION_CHARACTERISTIC_ALIGN_1BYTES	= 0x00100000,
	PE_SECTION_CHARACTERISTIC_ALIGN_2BYTES	= 0x00200000,
	PE_SECTION_CHARACTERISTIC_ALIGN_4BYTES	= 0x00300000,
	PE_SECTION_CHARACTERISTIC_ALIGN_8BYTES	= 0x00400000,
	PE_SECTION_CHARACTERISTIC_ALIGN_161BYTES	= 0x00500000,
	PE_SECTION_CHARACTERISTIC_ALIGN_32BYTES	= 0x00600000,
	PE_SECTION_CHARACTERISTIC_ALIGN_64BYTES	= 0x00700000,
	PE_SECTION_CHARACTERISTIC_ALIGN_128BYTES	= 0x00800000,
	PE_SECTION_CHARACTERISTIC_ALIGN_256BYTES	= 0x00900000,
	PE_SECTION_CHARACTERISTIC_ALIGN_5121BYTES	= 0x00A00000,
	PE_SECTION_CHARACTERISTIC_ALIGN_10241BYTES	= 0x00B00000,
	PE_SECTION_CHARACTERISTIC_ALIGN_20481BYTES	= 0x00C00000,
	PE_SECTION_CHARACTERISTIC_ALIGN_40961BYTES	= 0x00D00000,
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

enum : ushort {
	PE_HDRROM	= 0x0107,
	PE_HDR32	= 0x010B,
	PE_HDR64	= 0x020B,
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