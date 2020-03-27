/**
 * Imitates objdump functionality
 *
 * License: BSD 3-Clause
 */
module dumper;

import core.stdc.stdio;
import core.stdc.stdlib : strtol, EXIT_SUCCESS, EXIT_FAILURE;
import core.stdc.config : c_long;
import core.stdc.stdlib : malloc, realloc;
import debugger.disasm, debugger.file.loader;

extern (C):

enum { // Dumper flags (-show)
	/// File is raw, do not attempt to detect its format
	DUMPER_FILE_RAW	= 1,
	/// Include headers (image headers, optional headers, directories) in
	/// output.
	DUMPER_SHOW_HEADERS	= 0x0100,
	/// Include sections in output.
	DUMPER_SHOW_SECTIONS	= 0x0200,
	/// Include imports in output. This includes dynamic libraries such as
	/// DLL files (for Windows, under `.rdata`) and SO files.
	DUMPER_SHOW_IMPORTS	= 0x0400,
	/// Include symbols in output.
	DUMPER_SHOW_SYMBOLS	= 0x0800,
	/// Include section disassembly in output.
	DUMPER_SHOW_DISASSEMBLY	= 0x8000,
}

/// Disassemble given file to stdout. Currently only supports flat binary
/// files.
/// Params:
/// 	file = File path
/// 	disopt = Disassembler settings
/// 	flags = Dumper options
/// Returns: Error code if non-zero
int dump_file(const(char) *file, disasm_params_t *dp, int flags) {
	if (file == null) {
		puts("dump: file is null");
		return EXIT_FAILURE;
	}
	FILE *f = fopen(file, "rb");
	if (f == null) {
		puts("dump: could not open file");
		return EXIT_FAILURE;
	}

	if (flags & DUMPER_FILE_RAW) {
		if (fseek(f, 0, SEEK_END)) {
			puts("dump: could not seek file");
			return EXIT_FAILURE;
		}
		c_long fl = ftell(f);
		fseek(f, 0, SEEK_SET); // rewind is broken

		void *m = cast(void*)malloc(fl);
		if (fread(m, fl, 1, f) == 0) {
			puts("cli: could not read file");
			return EXIT_FAILURE;
		}

		dp.addr = m;
		for (c_long fi; fi < fl; fi += dp.addrv - dp.lastaddr) {
			disasm_line(dp, DisasmMode.File);
			printf("%08X %-30s %-30s\n",
				cast(uint)fi,
				&dp.mcbuf, &dp.mnbuf);
		}
		return EXIT_SUCCESS;
	} else {
		file_info_t finfo = void;
		if (file_load(f, &finfo, 0)) {
			puts("loader: could not load file");
			return EXIT_FAILURE;
		}

		if (dp.isa == DisasmISA.Default)
			dp.isa = finfo.isa;

		with (FileType)
		switch (finfo.type) {
		case PE: return dumper_print_pe32(&finfo, dp, flags);
		default:
			puts("loader: format not supported");
			return EXIT_FAILURE;
		}
	}
}

// ANCHOR PE32
/// Print PE32 info to stdout, a file_info_t structure must be loaded before
/// calling this function.
/// Params:
/// 	fi = File information
/// 	dp = Disassembler parameters
/// Returns: Non-zero on error
int dumper_print_pe32(file_info_t *fi, disasm_params_t *dp, int flags) {
	import debugger.file.objs.pe; // @suppress(dscanner.suspicious.local_imports)
	import core.stdc.time : time_t, tm, localtime, strftime;

	ushort Machine = fi.pe.hdr.Machine;
	ushort NumberOfSections = fi.pe.hdr.NumberOfSections;
	uint TimeDateStamp = fi.pe.hdr.TimeDateStamp;
	uint PointerToSymbolTable = fi.pe.hdr.PointerToSymbolTable;
	uint NumberOfSymbols = fi.pe.hdr.NumberOfSymbols;
	ushort SizeOfOptionalHeader = fi.pe.hdr.SizeOfOptionalHeader;
	ushort Characteristics = fi.pe.hdr.Characteristics;

	const(char) *str_mach = file_pe_str_mach(Machine);
	if (str_mach == null) {
		printf("dumper: (PE32) Unknown Machine: %04X\n", Machine);
		return EXIT_FAILURE;
	}

	char[32] tbuffer = void;
	strftime(cast(char*)tbuffer, 32, "%c",
		localtime(cast(time_t*)&TimeDateStamp));

	//
	// PE Header
	//

	printf("Microsoft Portable Executable format\n\n"~
		"*\n* Header\n*\n\n"~
		"Machine               %04X\t(%s)\n"~
		"NumberOfSections      %04X\t(%u)\n"~
		"TimeDateStamp         %04X\t(%s)\n"~
		"PointerToSymbolTable  %08X\n"~
		"NumberOfSymbols       %08X\t(%u)\n"~
		"SizeOfOptionalHeader  %04X\t(%u)\n"~
		"Characteristics       %04X\t(",
		Machine, str_mach,
		NumberOfSections, NumberOfSections,
		TimeDateStamp, cast(char*)tbuffer,
		PointerToSymbolTable,
		NumberOfSymbols, NumberOfSymbols,
		SizeOfOptionalHeader, SizeOfOptionalHeader,
		Characteristics);

	// Characteristics flags
	if (Characteristics & PE_CHARACTERISTIC_RELOCS_STRIPPED)
		printf("RELOCS_STRIPPED,");
	if (Characteristics & PE_CHARACTERISTIC_EXECUTABLE_IMAGE)
		printf("EXECUTABLE_IMAGE,");
	if (Characteristics & PE_CHARACTERISTIC_LINE_NUMS_STRIPPED)
		printf("LINE_NUMS_STRIPPED,");
	if (Characteristics & PE_CHARACTERISTIC_LOCAL_SYMS_STRIPPED)
		printf("LOCAL_SYMS_STRIPPED,");
	if (Characteristics & PE_CHARACTERISTIC_AGGRESSIVE_WS_TRIM)
		printf("AGGRESSIVE_WS_TRIM,");
	if (Characteristics & PE_CHARACTERISTIC_LARGE_ADDRESS_AWARE)
		printf("LARGE_ADDRESS_AWARE,");
	if (Characteristics & PE_CHARACTERISTIC_16BIT_MACHINE)
		printf("16BIT_MACHINE,");
	if (Characteristics & PE_CHARACTERISTIC_BYTES_REVERSED_LO)
		printf("BYTES_REVERSED_LO,");
	if (Characteristics & PE_CHARACTERISTIC_32BIT_MACHINE)
		printf("32BIT_MACHINE,");
	if (Characteristics & PE_CHARACTERISTIC_DEBUG_STRIPPED)
		printf("DEBUG_STRIPPED,");
	if (Characteristics & PE_CHARACTERISTIC_REMOVABLE_RUN_FROM_SWAP)
		printf("REMOVABLE_RUN_FROM_SWAP,");
	if (Characteristics & PE_CHARACTERISTIC_NET_RUN_FROM_SWAP)
		printf("NET_RUN_FROM_SWAP,");
	if (Characteristics & PE_CHARACTERISTIC_SYSTEM)
		printf("SYSTEM,");
	if (Characteristics & PE_CHARACTERISTIC_DLL)
		printf("DLL,");
	if (Characteristics & PE_CHARACTERISTIC_UP_SYSTEM_ONLY)
		printf("UP_SYSTEM_ONLY,");
	if (Characteristics & PE_CHARACTERISTIC_BYTES_REVERSED_HI)
		printf("BYTES_REVERSED_HI,");
	puts(")\n");

	//
	// PE Optional Header, and Directory
	//

	if (SizeOfOptionalHeader) { // No gotos here, it could skip declarations
		ushort OptMagic = fi.pe.ohdr.Magic;
		const(char)* str_mag = file_pe_str_magic(OptMagic);
		if (str_mag == null) {
			printf("dumper: (PE32) Unknown Magic: %04X\n", OptMagic);
			return EXIT_FAILURE;
		}
		ushort OptSubsystem = fi.pe.ohdr.Subsystem; // same offset
		const(char) *str_sys = file_pe_str_subsys(OptSubsystem);
		if (str_sys == null) {
			printf("dumper: (PE32) Unknown Subsystem: %04X\n", OptSubsystem);
			return EXIT_FAILURE;
		}

		// same offsets
		ubyte MajorLinkerVersion = fi.pe.ohdr.MajorLinkerVersion;
		ubyte MinorLinkerVersion = fi.pe.ohdr.MinorLinkerVersion;
		uint SizeOfCode = fi.pe.ohdr.SizeOfCode;
		uint SizeOfInitializedData = fi.pe.ohdr.SizeOfInitializedData;
		uint SizeOfUninitializedData = fi.pe.ohdr.SizeOfUninitializedData;
		uint SectionAlignment = fi.pe.ohdr.SectionAlignment;
		uint FileAlignment = fi.pe.ohdr.FileAlignment;
		ushort MajorOperatingSystemVersion = fi.pe.ohdr.MajorOperatingSystemVersion;
		ushort MinorOperatingSystemVersion = fi.pe.ohdr.MinorOperatingSystemVersion;
		ushort MajorImageVersion = fi.pe.ohdr.MajorImageVersion;
		ushort MinorImageVersion = fi.pe.ohdr.MinorImageVersion;
		ushort MajorSubsystemVersion = fi.pe.ohdr.MajorSubsystemVersion;
		ushort MinorSubsystemVersion = fi.pe.ohdr.MinorSubsystemVersion;
		uint SizeOfImage = fi.pe.ohdr.SizeOfImage;
		uint SizeOfHeaders = fi.pe.ohdr.SizeOfHeaders;
		ushort DllCharacteristics = void;
		uint NumberOfRvaAndSizes = void;
		uint LoaderFlags = void;

		printf(	// Optional Header
		"*\n* Optional Header\n*\n\n"~
		"Type                         Image\n"~
		"Magic                        %04X\t(PE%s)\n"~
		"MajorLinkerVersion           %02X\t(%u)\n"~
		"MinorLinkerVersion           %02X\t(%u)\n"~
		"SizeOfCode                   %08X\t(%u)\n"~
		"SizeOfInitializedData        %08X\t(%u)\n"~
		"SizeOfUninitializedData      %08X\t(%u)\n"~
		"AddressOfEntryPoint          %08X\n"~
		"BaseOfCode                   %08X\n"~
		"SectionAlignment             %08X\t(%u)\n"~
		"FileAlignment                %08X\t(%u)\n"~
		"MajorOperatingSystemVersion  %04X\t(%u)\n"~
		"MinorOperatingSystemVersion  %04X\t(%u)\n"~
		"MajorImageVersion            %04X\t(%u)\n"~
		"MinorImageVersion            %04X\t(%u)\n"~
		"MajorSubsystemVersion        %04X\t(%u)\n"~
		"MinorSubsystemVersion        %04X\t(%u)\n"~
		"Win32VersionValue            %08X\n"~
		"SizeOfImage                  %08X\t(%u)\n"~
		"SizeOfHeaders                %08X\t(%u)\n"~
		"CheckSum                     %08X\n"~
		"Subsystem                    %04X\t(%s)\n",
		OptMagic, str_mag,
		MajorLinkerVersion, MajorLinkerVersion,
		MinorLinkerVersion, MinorLinkerVersion,
		SizeOfCode, SizeOfCode,
		SizeOfInitializedData, SizeOfInitializedData,
		SizeOfUninitializedData, SizeOfUninitializedData,
		fi.pe.ohdr.AddressOfEntryPoint,
		fi.pe.ohdr.BaseOfCode,
		SectionAlignment, SectionAlignment,
		FileAlignment, FileAlignment,
		MajorOperatingSystemVersion, MajorOperatingSystemVersion,
		MinorOperatingSystemVersion, MinorOperatingSystemVersion,
		MajorImageVersion, MajorImageVersion,
		MinorImageVersion, MinorImageVersion,
		MajorSubsystemVersion, MajorSubsystemVersion,
		MinorSubsystemVersion, MinorSubsystemVersion,
		fi.pe.ohdr.Win32VersionValue,
		SizeOfImage, SizeOfImage,
		SizeOfHeaders, SizeOfHeaders,
		fi.pe.ohdr.CheckSum,
		OptSubsystem, str_sys);

		switch (SizeOfOptionalHeader) {
		case 0xE0: // 32
			uint BaseOfData = fi.pe.ohdr.BaseOfData;
			uint ImageBase = fi.pe.ohdr.ImageBase;
			uint SizeOfStackReserve = fi.pe.ohdr.SizeOfStackReserve;
			uint SizeOfStackCommit = fi.pe.ohdr.SizeOfStackCommit;
			uint SizeOfHeapReserve = fi.pe.ohdr.SizeOfHeapReserve;
			uint SizeOfHeapCommit = fi.pe.ohdr.SizeOfHeapCommit;
			printf(
			"BaseOfData                   %08X\n"~
			"ImageBase                    %08X\n"~
			"SizeOfStackReserve           %08X\t(%u)\n"~
			"SizeOfStackCommit            %08X\t(%u)\n"~
			"SizeOfHeapReserve            %08X\t(%u)\n"~
			"SizeOfHeapCommit             %08X\t(%u)\n",
			BaseOfData,
			ImageBase,
			SizeOfStackReserve, SizeOfStackReserve,
			SizeOfStackCommit, SizeOfStackCommit,
			SizeOfHeapReserve, SizeOfHeapReserve,
			SizeOfHeapCommit, SizeOfHeapCommit);
			LoaderFlags = fi.pe.ohdr.LoaderFlags;
			DllCharacteristics = fi.pe.ohdr.DllCharacteristics;
			NumberOfRvaAndSizes = fi.pe.ohdr.NumberOfRvaAndSizes;
			break;
		case 0xF0: // 64
			ulong ImageBase = fi.pe.ohdr64.ImageBase;
			ulong SizeOfStackReserve = fi.pe.ohdr64.SizeOfStackReserve;
			ulong SizeOfStackCommit = fi.pe.ohdr64.SizeOfStackCommit;
			ulong SizeOfHeapReserve = fi.pe.ohdr64.SizeOfHeapReserve;
			ulong SizeOfHeapCommit = fi.pe.ohdr64.SizeOfHeapCommit;
			printf(
			"ImageBase                    %016llX\n"~
			"SizeOfStackReserve           %016llX\t(%llu)\n"~
			"SizeOfStackCommit            %016llX\t(%llu)\n"~
			"SizeOfHeapReserve            %016llX\t(%llu)\n"~
			"SizeOfHeapCommit             %016llX\t(%llu)\n",
			ImageBase,
			SizeOfStackReserve, SizeOfStackReserve,
			SizeOfStackCommit, SizeOfStackCommit,
			SizeOfHeapReserve, SizeOfHeapReserve,
			SizeOfHeapCommit, SizeOfHeapCommit);
			LoaderFlags = fi.pe.ohdr64.LoaderFlags;
			DllCharacteristics = fi.pe.ohdr64.DllCharacteristics;
			NumberOfRvaAndSizes = fi.pe.ohdr64.NumberOfRvaAndSizes;
			break;
		default: goto L_SECTIONS;
		}

		printf(
		"LoaderFlags                  %08X\n"~
		"NumberOfRvaAndSizes          %08X\n"~
		"DllCharacteristics           %04X\t(",
		LoaderFlags,
		NumberOfRvaAndSizes,
		DllCharacteristics);

		// DllCharacteristics flags
		if (DllCharacteristics & PE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)
			printf("HIGH_ENTROPY_VA,");
		if (DllCharacteristics & PE_DLLCHARACTERISTICS_DYNAMIC_BASE)
			printf("DYNAMIC_BASE,");
		if (DllCharacteristics & PE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
			printf("FORCE_INTEGRITY,");
		if (DllCharacteristics & PE_DLLCHARACTERISTICS_NX_COMPAT)
			printf("NX_COMPAT,");
		if (DllCharacteristics & PE_DLLCHARACTERISTICS_NO_ISOLATION)
			printf("NO_ISOLATION,");
		if (DllCharacteristics & PE_DLLCHARACTERISTICS_NO_SEH)
			printf("NO_SEH,");
		if (DllCharacteristics & PE_DLLCHARACTERISTICS_NO_BIND)
			printf("NO_BIND,");
		if (DllCharacteristics & PE_DLLCHARACTERISTICS_APPCONTAINER)
			printf("APPCONTAINER,");
		if (DllCharacteristics & PE_DLLCHARACTERISTICS_WDM_DRIVER)
			printf("WDM_DRIVER,");
		if (DllCharacteristics & PE_DLLCHARACTERISTICS_GUARD_CF)
			printf("GUARD_CF,");
		if (DllCharacteristics & PE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE)
			printf("TERMINAL_SERVER_AWARE,");

		printf(	// Directory
		")\n\n*\n* Directories\n*\n\n"~
		"Export Table             %08X  %08X  (%u)\n"~
		"Import Table             %08X  %08X  (%u)\n"~
		"Resource Table           %08X  %08X  (%u)\n"~
		"Exception Table          %08X  %08X  (%u)\n"~
		"Certificate Table        %08X  %08X  (%u)\n"~
		"Base Relocation Table    %08X  %08X  (%u)\n"~
		"Debug Directory          %08X  %08X  (%u)\n"~
		"Architecture             %08X  %08X  (%u)\n"~
		"Global Ptr               %08X  %08X  (%u)\n"~
		"TLS Table                %08X  %08X  (%u)\n"~
		"Load Config Table        %08X  %08X  (%u)\n"~
		"Bound Import             %08X  %08X  (%u)\n"~
		"Import Address Table     %08X  %08X  (%u)\n"~
		"Delay Import Descriptor  %08X  %08X  (%u)\n"~
		"CLR Header               %08X  %08X  (%u)\n"~
		"Reserved                 %08X  %08X  (%u)\n",
		fi.pe.dir.ExportTable.va, fi.pe.dir.ExportTable.size, fi.pe.dir.ExportTable.size,
		fi.pe.dir.ImportTable.va, fi.pe.dir.ImportTable.size, fi.pe.dir.ImportTable.size,
		fi.pe.dir.ResourceTable, fi.pe.dir.ResourceTable.size, fi.pe.dir.ResourceTable.size,
		fi.pe.dir.ExceptionTable.va, fi.pe.dir.ExceptionTable.size, fi.pe.dir.ExceptionTable.size,
		fi.pe.dir.CertificateTable.va, fi.pe.dir.CertificateTable.size, fi.pe.dir.CertificateTable.size,
		fi.pe.dir.BaseRelocationTable.va, fi.pe.dir.BaseRelocationTable.size, fi.pe.dir.BaseRelocationTable.size,
		fi.pe.dir.DebugDirectory.va, fi.pe.dir.DebugDirectory.size, fi.pe.dir.DebugDirectory.size,
		fi.pe.dir.ArchitectureData.va, fi.pe.dir.ArchitectureData.size, fi.pe.dir.ArchitectureData.size,
		fi.pe.dir.GlobalPtr.va, fi.pe.dir.GlobalPtr.size, fi.pe.dir.GlobalPtr.size,
		fi.pe.dir.TLSTable.va, fi.pe.dir.TLSTable.size, fi.pe.dir.TLSTable.size,
		fi.pe.dir.LoadConfigurationTable.va, fi.pe.dir.LoadConfigurationTable.size, fi.pe.dir.LoadConfigurationTable.size,
		fi.pe.dir.BoundImportTable.va, fi.pe.dir.BoundImportTable.size, fi.pe.dir.BoundImportTable.size,
		fi.pe.dir.ImportAddressTable.va, fi.pe.dir.ImportAddressTable.size, fi.pe.dir.ImportAddressTable.size,
		fi.pe.dir.DelayImport.va, fi.pe.dir.DelayImport.size, fi.pe.dir.DelayImport.size,
		fi.pe.dir.CLRHeader.va, fi.pe.dir.CLRHeader.size, fi.pe.dir.CLRHeader.size,
		fi.pe.dir.Reserved.va, fi.pe.dir.Reserved.size, fi.pe.dir.Reserved.size);
	} else {
		printf("Type                         Object\n");
	}

L_SECTIONS:
	//
	// Sections
	//

	puts("\n*\n* Sections\n*");
	c_long pos_section = ftell(fi.handle);	/// Saved position for sections
	for (ushort si; si < NumberOfSections; ++si) {
		PE_SECTION_ENTRY section = void;

		if (fread(&section, section.sizeof, 1, fi.handle) == 0)
			return EXIT_FAILURE;

		printf(
		"\n%u. %.8s\n"~
		"VirtualAddress        %08X\n"~
		"VirtualSize           %08X\t(%u)\n"~
		"PointerToRawData      %08X\n"~
		"SizeOfRawData         %08X\t(%u)\n"~
		"PointerToRelocations  %08X\n"~
		"NumberOfRelocations   %04X\t(%u)\n"~
		"PointerToLinenumbers  %08X\n"~
		"NumberOfLinenumbers   %04X\t(%u)\n"~
		"Characteristics       %08X\t(",
		si, &section.Name,
		section.VirtualAddress,
		section.VirtualSize, section.VirtualSize,
		section.PointerToRawData,
		section.SizeOfRawData, section.SizeOfRawData,
		section.PointerToRelocations,
		section.NumberOfRelocations, section.NumberOfRelocations,
		section.PointerToLinenumbers,
		section.NumberOfLinenumbers, section.NumberOfLinenumbers,
		section.Characteristics);

		// Section Characteristics flags
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_NO_PAD)
			printf("NO_PAD,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_CODE)
			printf("CODE,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_INITIALIZED_DATA)
			printf("INITIALIZED_DATA,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_UNINITIALIZED_DATA)
			printf("UNINITIALIZED_DATA,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_LNK_OTHER)
			printf("LNK_OTHER,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_LNK_INFO)
			printf("LNK_INFO,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_LNK_REMOVE)
			printf("LNK_REMOVE,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_LNK_COMDAT)
			printf("LNK_COMDAT,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_GPREL)
			printf("GPREL,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_MEM_PURGEABLE)
			printf("MEM_PURGEABLE,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_MEM_16BIT)
			printf("MEM_16BIT,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_MEM_LOCKED)
			printf("MEM_LOCKED,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_PRELOAD)
			printf("PRELOAD,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_ALIGN_1BYTES)
			printf("ALIGN_1BYTES,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_ALIGN_2BYTES)
			printf("ALIGN_2BYTES,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_ALIGN_4BYTES)
			printf("ALIGN_4BYTES,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_ALIGN_8BYTES)
			printf("ALIGN_8BYTES,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_ALIGN_16BYTES)
			printf("ALIGN_16BYTES,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_ALIGN_32BYTES)
			printf("ALIGN_32BYTES,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_ALIGN_64BYTES)
			printf("ALIGN_64BYTES,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_ALIGN_128BYTES)
			printf("ALIGN_128BYTES,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_ALIGN_256BYTES)
			printf("ALIGN_256BYTES,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_ALIGN_5121BYTES)
			printf("ALIGN_5121BYTES,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_ALIGN_10241BYTES)
			printf("ALIGN_10241BYTES,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_ALIGN_20481BYTES)
			printf("ALIGN_20481BYTES,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_ALIGN_40961BYTES)
			printf("ALIGN_40961BYTES,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_ALIGN_8192BYTES)
			printf("ALIGN_8192BYTES,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_LNK_NRELOC_OVFL)
			printf("LNK_NRELOC_OVFL,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_MEM_DISCARDABLE)
			printf("MEM_DISCARDABLE,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_MEM_NOT_CACHED)
			printf("MEM_NOT_CACHED,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_MEM_NOT_PAGED)
			printf("MEM_NOT_PAGED,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_MEM_SHARED)
			printf("MEM_SHARED,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_MEM_EXECUTE)
			printf("MEM_EXECUTE,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_MEM_READ)
			printf("MEM_READ,");
		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_MEM_WRITE)
			printf("MEM_WRITE,");

		puts(")");
	}

	//
	// Symbols
	//



	//
	// Disassembly
	//

	//TODO: Measure by section length

	puts("\n*\n* Disassembly\n*");
	void *mem = cast(void*)malloc(64);
	fseek(fi.handle, pos_section, SEEK_SET);
	for (ushort si; si < NumberOfSections; ++si) {
		PE_SECTION_ENTRY section = void;

		if (fread(&section, section.sizeof, 1, fi.handle) == 0)
			return EXIT_FAILURE;

		if (section.Characteristics & PE_SECTION_CHARACTERISTIC_MEM_EXECUTE) {
			pos_section = ftell(fi.handle);

			if (fseek(fi.handle, section.PointerToRawData, SEEK_SET))
				return EXIT_FAILURE;

			if (fread(mem, 64, 1, fi.handle) == 0) {
				puts("cli: could not read file");
				return EXIT_FAILURE;
			}

			printf("\n<%.8s>\n", &section.Name);
			dp.addr = mem;
			for (uint i; i < 32; i += dp.addrv - dp.lastaddr) {
				disasm_line(dp, DisasmMode.File);
				printf("%08X %-30s %-30s\n",
					cast(uint)i,
					&dp.mcbuf, &dp.mnbuf);
			}

			fseek(fi.handle, pos_section, SEEK_SET);
		}
	}

	return EXIT_SUCCESS;
}

// ANCHOR MZ
/// Print MZ info to stdout, a file_info_t structure must be loaded before
/// calling this function.
/// Params:
/// 	fi = File information
/// 	dp = Disassembler parameters
/// Returns: Non-zero on error
int dumper_print_mz(file_info_t *fi, disasm_params_t *dp, int flags) {
	//TODO: MZ
	
	return EXIT_SUCCESS;
}