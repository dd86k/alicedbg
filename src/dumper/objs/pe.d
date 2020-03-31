/**
 * PE32 file dumper
 *
 * License: BSD 3-Clause
 */
module dumper.objs.pe;

import core.stdc.stdio;
import core.stdc.config : c_long;
import core.stdc.stdlib : EXIT_SUCCESS, EXIT_FAILURE, malloc, realloc;
import core.stdc.time : time_t, tm, localtime, strftime;
import dumper.core;
import debugger.obj.loader : obj_info_t;
import debugger.disasm.core : disasm_params_t, disasm_line, DisasmMode;
import debugger.file.objs.pe;

extern (C):

/// Print PE32 info to stdout, a file_info_t structure must be loaded before
/// calling this function. If an unknown Machine type is detected, this only
/// prints the first header. FILE handle must be pointing to section table.
/// Params:
/// 	fi = File information
/// 	dp = Disassembler parameters
/// 	flags = Show X flags
/// Returns: Non-zero on error
int dumper_print_pe32(obj_info_t *fi, disasm_params_t *dp, int flags) {
	bool unkmach = void;
	const(char) *str_mach = file_pe_str_mach(fi.pe.hdr.Machine);
	if (str_mach == null) {
		str_mach = "UNKNOWN";
		unkmach = true;
	} else
		unkmach = false;

	char[32] tbuffer = void;
	if (strftime(cast(char*)tbuffer, 32, "%c",
		localtime(cast(time_t*)&fi.pe.hdr.TimeDateStamp)) == 0) {
		const(char)* l = cast(char*)&tbuffer;
		l = "strftime:err";
	}

	// variables are declared here because compiler whines about GOTO
	// skipping declarations
	ushort OptMagic; /// For future references, 0 means there is no optheader
	c_long pos_section = ftell(fi.handle);	/// Saved position for sections
	uint fo_loadcf, fo_import; // unset means not found

	//
	// PE Header
	//

	if ((flags & DUMPER_SHOW_HEADERS) == 0)
		goto L_SECTIONS;

	with (fi.pe.hdr)
	printf(
	"Microsoft Portable Executable format\n\n"~
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
	TimeDateStamp, &tbuffer,
	PointerToSymbolTable,
	NumberOfSymbols, NumberOfSymbols,
	SizeOfOptionalHeader, SizeOfOptionalHeader,
	Characteristics);

	with (fi.pe.hdr) { // Characteristics flags
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
	}
	puts(")\n");

	if (unkmach)
		return EXIT_SUCCESS;

	//
	// PE Optional Header, and Directory
	//

	if (fi.pe.hdr.SizeOfOptionalHeader) { // No gotos here, it could skip declarations
		const(char)* str_mag = file_pe_str_magic(fi.pe.ohdr.Magic);
		if (str_mag == null) {
			printf("dumper: (PE32) Unknown Magic: %04X\n", fi.pe.ohdr.Magic);
			return EXIT_FAILURE;
		}
		const(char) *str_sys = file_pe_str_subsys(fi.pe.ohdr.Subsystem);
		if (str_sys == null) {
			printf("dumper: (PE32) Unknown Subsystem: %04X\n", fi.pe.ohdr.Subsystem);
			return EXIT_FAILURE;
		}

		//
		// Standard fields
		//

		with (fi.pe.ohdr)
		printf(
		"*\n* Optional Header\n*\n\n"~
		"Type                         Image\n"~
		"Magic                        %04X\t(%s)\n"~
		"MajorLinkerVersion           %02X\t(%u)\n"~
		"MinorLinkerVersion           %02X\t(%u)\n"~
		"SizeOfCode                   %08X\t(%u)\n"~
		"SizeOfInitializedData        %08X\t(%u)\n"~
		"SizeOfUninitializedData      %08X\t(%u)\n"~
		"AddressOfEntryPoint          %08X\n"~
		"BaseOfCode                   %08X\n",
		Magic, str_mag,
		MajorLinkerVersion, MajorLinkerVersion,
		MinorLinkerVersion, MinorLinkerVersion,
		SizeOfCode, SizeOfCode,
		SizeOfInitializedData, SizeOfInitializedData,
		SizeOfUninitializedData, SizeOfUninitializedData,
		AddressOfEntryPoint,
		BaseOfCode);

		ushort DllCharacteristics = void;
		uint NumberOfRvaAndSizes = void;
		uint LoaderFlags = void;

		//
		// NT additional fields
		//

		switch (fi.pe.ohdr.Magic) {
		case PE_FMT_32: // 32
			with (fi.pe.ohdr)
			printf(
			"BaseOfData                   %08X\n"~
			"ImageBase                    %08X\n"~
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
			"Subsystem                    %04X\t(%s)\n"~
			"SizeOfStackReserve           %08X\t(%u)\n"~
			"SizeOfStackCommit            %08X\t(%u)\n"~
			"SizeOfHeapReserve            %08X\t(%u)\n"~
			"SizeOfHeapCommit             %08X\t(%u)\n",
			BaseOfData,
			ImageBase,
			SectionAlignment, SectionAlignment,
			FileAlignment, FileAlignment,
			MajorOperatingSystemVersion, MajorOperatingSystemVersion,
			MinorOperatingSystemVersion, MinorOperatingSystemVersion,
			MajorImageVersion, MajorImageVersion,
			MinorImageVersion, MinorImageVersion,
			MajorSubsystemVersion, MajorSubsystemVersion,
			MinorSubsystemVersion, MinorSubsystemVersion,
			Win32VersionValue,
			SizeOfImage, SizeOfImage,
			SizeOfHeaders, SizeOfHeaders,
			CheckSum,
			Subsystem, str_sys,
			SizeOfStackReserve, SizeOfStackReserve,
			SizeOfStackCommit, SizeOfStackCommit,
			SizeOfHeapReserve, SizeOfHeapReserve,
			SizeOfHeapCommit, SizeOfHeapCommit);

			LoaderFlags = fi.pe.ohdr.LoaderFlags;
			DllCharacteristics = fi.pe.ohdr.DllCharacteristics;
			NumberOfRvaAndSizes = fi.pe.ohdr.NumberOfRvaAndSizes;
			break;
		case PE_FMT_64: // 64
			with (fi.pe.ohdr64)
			printf(
			"ImageBase                    %016llX\n"~
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
			"Subsystem                    %04X\t(%s)\n"~
			"SizeOfStackReserve           %016llX\t(%llu)\n"~
			"SizeOfStackCommit            %016llX\t(%llu)\n"~
			"SizeOfHeapReserve            %016llX\t(%llu)\n"~
			"SizeOfHeapCommit             %016llX\t(%llu)\n",
			ImageBase,
			SectionAlignment, SectionAlignment,
			FileAlignment, FileAlignment,
			MajorOperatingSystemVersion, MajorOperatingSystemVersion,
			MinorOperatingSystemVersion, MinorOperatingSystemVersion,
			MajorImageVersion, MajorImageVersion,
			MinorImageVersion, MinorImageVersion,
			MajorSubsystemVersion, MajorSubsystemVersion,
			MinorSubsystemVersion, MinorSubsystemVersion,
			Win32VersionValue,
			SizeOfImage, SizeOfImage,
			SizeOfHeaders, SizeOfHeaders,
			CheckSum,
			Subsystem, str_sys,
			SizeOfStackReserve, SizeOfStackReserve,
			SizeOfStackCommit, SizeOfStackCommit,
			SizeOfHeapReserve, SizeOfHeapReserve,
			SizeOfHeapCommit, SizeOfHeapCommit);

			LoaderFlags = fi.pe.ohdr64.LoaderFlags;
			DllCharacteristics = fi.pe.ohdr64.DllCharacteristics;
			NumberOfRvaAndSizes = fi.pe.ohdr64.NumberOfRvaAndSizes;
			break;
		case PE_FMT_ROM: // ROM has no flags/directories
			with (fi.pe.ohdrrom)
			printf(
			"BaseOfData                   %08X\n"~
			"BaseOfBss                    %08X\n"~
			"GprMask                      %08X\n"~
			"CprMask                      %08X %08X %08X %08X\n"~
			"GpValue                      %08X\n",
			BaseOfData,
			BaseOfBss,
			GprMask,
			CprMask[0], CprMask[1],
			CprMask[2], CprMask[3],
			GpValue,
			);
			return EXIT_SUCCESS;
		default:
			printf("dumper: unknown Magic %04X\n",
				fi.pe.ohdr.Magic);
			return EXIT_FAILURE;
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

		with (fi.pe.dir)
		printf(	// Directory
		")\n\n*\n* Directories\n*\n\n"~
		"Directory                RVA       Size\n"~
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
		ExportTable.va,	ExportTable.size, ExportTable.size,
		ImportTable.va,	ImportTable.size, ImportTable.size,
		ResourceTable.va,	ResourceTable.size, ResourceTable.size,
		ExceptionTable.va,	ExceptionTable.size, ExceptionTable.size,
		CertificateTable.va,	CertificateTable.size, CertificateTable.size,
		BaseRelocationTable.va,	BaseRelocationTable.size, BaseRelocationTable.size,
		DebugDirectory.va,	DebugDirectory.size, DebugDirectory.size,
		ArchitectureData.va,	ArchitectureData.size, ArchitectureData.size,
		GlobalPtr.va,	GlobalPtr.size, GlobalPtr.size,
		TLSTable.va,	TLSTable.size, TLSTable.size,
		LoadConfigurationTable.va,	LoadConfigurationTable.size, LoadConfigurationTable.size,
		BoundImportTable.va,	BoundImportTable.size, BoundImportTable.size,
		ImportAddressTable.va,	ImportAddressTable.size, ImportAddressTable.size,
		DelayImport.va,	DelayImport.size, DelayImport.size,
		CLRHeader.va,	CLRHeader.size, CLRHeader.size,
		Reserved.va,	Reserved.size, Reserved.size);
	} else {
		//TODO: PE-OBJ: ANON_OBJECT_HEADER, ANON_OBJECT_HEADER_V2
		printf("Type                         Object\n");
		return EXIT_SUCCESS;
	}

	//
	// Sections
	//
L_SECTIONS:

	if ((flags & DUMPER_SHOW_SECTIONS) == 0)
		goto L_SYMBOLS;

	puts("\n*\n* Sections\n*");
	for (ushort si; si < fi.pe.hdr.NumberOfSections; ++si) {
		PE_SECTION_ENTRY section = void;

		if (fread(&section, section.sizeof, 1, fi.handle) == 0)
			return EXIT_FAILURE;

		with (section)
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
		si + 1, &Name,
		VirtualAddress,
		VirtualSize, section.VirtualSize,
		PointerToRawData,
		SizeOfRawData, section.SizeOfRawData,
		PointerToRelocations,
		NumberOfRelocations, section.NumberOfRelocations,
		PointerToLinenumbers,
		NumberOfLinenumbers, section.NumberOfLinenumbers,
		Characteristics);

		with (section) { // Section Characteristics flags
		if (Characteristics & PE_SECTION_CHARACTERISTIC_NO_PAD)
			printf("NO_PAD,");
		if (Characteristics & PE_SECTION_CHARACTERISTIC_CODE)
			printf("CODE,");
		if (Characteristics & PE_SECTION_CHARACTERISTIC_INITIALIZED_DATA)
			printf("INITIALIZED_DATA,");
		if (Characteristics & PE_SECTION_CHARACTERISTIC_UNINITIALIZED_DATA)
			printf("UNINITIALIZED_DATA,");
		if (Characteristics & PE_SECTION_CHARACTERISTIC_LNK_OTHER)
			printf("LNK_OTHER,");
		if (Characteristics & PE_SECTION_CHARACTERISTIC_LNK_INFO)
			printf("LNK_INFO,");
		if (Characteristics & PE_SECTION_CHARACTERISTIC_LNK_REMOVE)
			printf("LNK_REMOVE,");
		if (Characteristics & PE_SECTION_CHARACTERISTIC_LNK_COMDAT)
			printf("LNK_COMDAT,");
		if (Characteristics & PE_SECTION_CHARACTERISTIC_GPREL)
			printf("GPREL,");
		if (Characteristics & PE_SECTION_CHARACTERISTIC_MEM_PURGEABLE)
			printf("MEM_PURGEABLE,");
		if (Characteristics & PE_SECTION_CHARACTERISTIC_MEM_16BIT)
			printf("MEM_16BIT,");
		if (Characteristics & PE_SECTION_CHARACTERISTIC_MEM_LOCKED)
			printf("MEM_LOCKED,");
		if (Characteristics & PE_SECTION_CHARACTERISTIC_PRELOAD)
			printf("PRELOAD,");
		const(char) *scn_align = void;
		switch (Characteristics & 0x00F00000) {
//		case 0: // "ALIGN_DEFAULT(16)"? seen under PEDUMP (1997)
		case PE_SECTION_CHARACTERISTIC_ALIGN_1BYTES: scn_align = "ALIGN_1BYTES,"; break;
		case PE_SECTION_CHARACTERISTIC_ALIGN_2BYTES: scn_align = "ALIGN_2BYTES,"; break;
		case PE_SECTION_CHARACTERISTIC_ALIGN_4BYTES: scn_align = "ALIGN_4BYTES,"; break;
		case PE_SECTION_CHARACTERISTIC_ALIGN_8BYTES: scn_align = "ALIGN_8BYTES,"; break;
		case PE_SECTION_CHARACTERISTIC_ALIGN_16BYTES: scn_align = "ALIGN_16BYTES,"; break;
		case PE_SECTION_CHARACTERISTIC_ALIGN_32BYTES: scn_align = "ALIGN_32BYTES,"; break;
		case PE_SECTION_CHARACTERISTIC_ALIGN_64BYTES: scn_align = "ALIGN_64BYTES,"; break;
		case PE_SECTION_CHARACTERISTIC_ALIGN_128BYTES: scn_align = "ALIGN_128BYTES,"; break;
		case PE_SECTION_CHARACTERISTIC_ALIGN_256BYTES: scn_align = "ALIGN_256BYTES,"; break;
		case PE_SECTION_CHARACTERISTIC_ALIGN_512BYTES: scn_align = "ALIGN_512BYTES,"; break;
		case PE_SECTION_CHARACTERISTIC_ALIGN_1024BYTES: scn_align = "ALIGN_1024BYTES,"; break;
		case PE_SECTION_CHARACTERISTIC_ALIGN_2048BYTES: scn_align = "ALIGN_2048BYTES,"; break;
		case PE_SECTION_CHARACTERISTIC_ALIGN_4096BYTES: scn_align = "ALIGN_4096BYTES,"; break;
		case PE_SECTION_CHARACTERISTIC_ALIGN_8192BYTES: scn_align = "ALIGN_8192BYTES,"; break;
		default: scn_align = ""; break;
		}
		printf(scn_align);
		if (Characteristics & PE_SECTION_CHARACTERISTIC_LNK_NRELOC_OVFL)
			printf("LNK_NRELOC_OVFL,");
		if (Characteristics & PE_SECTION_CHARACTERISTIC_MEM_DISCARDABLE)
			printf("MEM_DISCARDABLE,");
		if (Characteristics & PE_SECTION_CHARACTERISTIC_MEM_NOT_CACHED)
			printf("MEM_NOT_CACHED,");
		if (Characteristics & PE_SECTION_CHARACTERISTIC_MEM_NOT_PAGED)
			printf("MEM_NOT_PAGED,");
		if (Characteristics & PE_SECTION_CHARACTERISTIC_MEM_SHARED)
			printf("MEM_SHARED,");
		if (Characteristics & PE_SECTION_CHARACTERISTIC_MEM_EXECUTE)
			printf("MEM_EXECUTE,");
		if (Characteristics & PE_SECTION_CHARACTERISTIC_MEM_READ)
			printf("MEM_READ,");
		if (Characteristics & PE_SECTION_CHARACTERISTIC_MEM_WRITE)
			printf("MEM_WRITE,");
		}

		puts(")");
	}

	//
	//TODO: Symbols
	//
L_SYMBOLS:

/*	if ((flags & DUMPER_SHOW_SYMBOLS) == 0)
		goto L_IMPORTS;*/


	//
	// LoadConfig/Imports
	//
	// NOTE: FileOffset = Section.RawPtr + (Directory.RVA - Section.RVA)
	//
L_IMPORTS:

	if ((flags & DUMPER_SHOW_IMPORTS) == 0)
		goto L_DISASM;

	fseek(fi.handle, pos_section, SEEK_SET);
	for (ushort si; si < fi.pe.hdr.NumberOfSections; ++si) {
		PE_SECTION_ENTRY section = void;

		if (fread(&section, section.sizeof, 1, fi.handle) == 0)
			return EXIT_FAILURE;

		if (fo_loadcf == 0)
		if (section.VirtualAddress <= fi.pe.dir.LoadConfigurationTable.va &&
			section.VirtualAddress + section.SizeOfRawData > fi.pe.dir.LoadConfigurationTable.va) {
			fo_loadcf = section.PointerToRawData +
				(fi.pe.dir.LoadConfigurationTable.va - section.VirtualAddress);
		}

		if (fo_import == 0)
		if (section.VirtualAddress <= fi.pe.dir.ImportTable.va &&
			section.VirtualAddress + section.SizeOfRawData > fi.pe.dir.ImportTable.va) {
			fo_import = section.PointerToRawData +
				(fi.pe.dir.ImportTable.va - section.VirtualAddress);
		}

		if (fo_loadcf && fo_import)
			break;
	}
	if (fo_loadcf) {
		if (fseek(fi.handle, fo_loadcf, SEEK_SET))
			return EXIT_FAILURE;

		PE_LOAD_CONFIG_META lconf = void;
		char[32] lcbuffer = void;

		if (fread(&lconf, 4, 1, fi.handle) == 0)
			return EXIT_FAILURE;
		if (fread(&lconf.dir32.TimeDateStamp, lconf.dir32.Size, 1, fi.handle) == 0)
			return EXIT_FAILURE;

		if (strftime(cast(char*)lcbuffer, 32, "%c",
			localtime(cast(time_t*)&lconf.dir64.TimeDateStamp)) == 0) {
			const(char)* l = cast(char*)&lcbuffer;
			l = "strftime:err";
		}

		with (lconf.dir32)
		printf( // Same sizes/offsets
		"\n*\n* Load Config\n*\n\n"~
		"Size                            %08X\t(%u)\n"~
		"TimeDateStamp                   %08X\t(%s)\n"~
		"MajorVersion                    %04X\t(%u)\n"~
		"MinorVersion                    %04X\t(%u)\n"~
		"GlobalFlagsClear                %08X\n"~
		"GlobalFlagsSet                  %08X\n"~
		"CriticalSectionDefaultTimeout   %08X\n",
		Size, Size,
		TimeDateStamp, &lcbuffer,
		MajorVersion, lconf.dir32.MajorVersion,
		MinorVersion, lconf.dir32.MinorVersion,
		GlobalFlagsClear,
		GlobalFlagsSet,
		CriticalSectionDefaultTimeout);
		

		if (OptMagic != PE_FMT_64) { // 32
			with (lconf.dir32)
			printf(
			"DeCommitFreeBlockThreshold      %08X\n"~
			"DeCommitTotalBlockThreshold     %08X\n"~
			"LockPrefixTable                 %08X\n"~
			"MaximumAllocationSize           %08X\t(%u)\n"~
			"VirtualMemoryThreshold          %08X\n"~
			"ProcessHeapFlags                %08X\n"~
			"ProcessAffinityMask             %08X\n"~
			"CSDVersion                      %04X\n"~
			"Reserved1                       %04X\n"~
			"EditList                        %08X\n"~
			"SecurityCookie                  %08X\n",
			DeCommitFreeBlockThreshold,
			DeCommitTotalBlockThreshold,
			LockPrefixTable,
			MaximumAllocationSize, lconf.dir32.MaximumAllocationSize,
			VirtualMemoryThreshold,
			ProcessHeapFlags,
			ProcessAffinityMask,
			CSDVersion,
			Reserved1,
			EditList,
			SecurityCookie);
			
			if (lconf.dir32.Size <= PE_LOAD_CONFIG32_LIMIT_XP)
				goto L_LOAD_CONFIG_EXIT;

			with (lconf.dir32)
			printf(
			"SEHandlerTable                  %08X\n"~
			"SEHandlerCount                  %08X\n"~
			"GuardCFCheckFunctionPointer     %08X\n"~
			"GuardCFDispatchFunctionPointer  %08X\n"~
			"GuardCFFunctionTable            %08X\n"~
			"GuardCFFunctionCount            %08X\n"~
			"GuardFlags                      %08X\n",
			SEHandlerTable,
			SEHandlerCount,
			GuardCFCheckFunctionPointer,
			GuardCFDispatchFunctionPointer,
			GuardCFFunctionTable,
			GuardCFFunctionCount,
			GuardFlags);

			if (lconf.dir32.Size <= PE_LOAD_CONFIG32_LIMIT_VI)
				goto L_LOAD_CONFIG_EXIT;

			with (lconf.dir32)
			printf(
			"CodeIntegrity.Flags             %04X\n"~
			"CodeIntegrity.Catalog           %04X\n"~
			"CodeIntegrity.CatalogOffset     %08X\n"~
			"CodeIntegrity.Reserved          %08X\n"~
			"GuardAddressTakenIatEntryTable  %08X\n"~
			"GuardAddressTakenIatEntryCount  %08X\n"~
			"GuardLongJumpTargetTable        %08X\n"~
			"GuardLongJumpTargetCount        %08X\n",
			CodeIntegrity.Flags,
			CodeIntegrity.Catalog,
			CodeIntegrity.CatalogOffset,
			CodeIntegrity.Reserved,
			GuardAddressTakenIatEntryTable,
			GuardAddressTakenIatEntryCount,
			GuardLongJumpTargetTable,
			GuardLongJumpTargetCount);

			if (lconf.dir32.Size <= PE_LOAD_CONFIG32_LIMIT_8)
				goto L_LOAD_CONFIG_EXIT;

			with (lconf.dir32)
			printf(
			"DynamicValueRelocTable                    %08X\n"~
			"CHPEMetadataPointer                       %08X\n"~
			"GuardRFFailureRoutine                     %08X\n"~
			"GuardRFFailureRoutineFunctionPointer      %08X\n"~
			"DynamicValueRelocTableOffset              %08X\n"~
			"DynamicValueRelocTableSection             %04X\n"~
			"Reserved2                                 %04X\n"~
			"GuardRFVerifyStackPointerFunctionPointer  %08X\n"~
			"HotPatchTableOffset                       %08X\n"~
			"Reserved3                                 %08X\n"~
			"EnclaveConfigurationPointer               %08X\n"~
			"VolatileMetadataPointer                   %08X\n",
			DynamicValueRelocTable,
			CHPEMetadataPointer,
			GuardRFFailureRoutine,
			GuardRFFailureRoutineFunctionPointer,
			DynamicValueRelocTableOffset,
			DynamicValueRelocTableSection,
			Reserved2,
			GuardRFVerifyStackPointerFunctionPointer,
			HotPatchTableOffset,
			Reserved3,
			EnclaveConfigurationPointer,
			VolatileMetadataPointer);
		} else { // 64
			with (lconf.dir64)
			printf(
			"DeCommitFreeBlockThreshold      %016llX\n"~
			"DeCommitTotalBlockThreshold     %016llX\n"~
			"LockPrefixTable                 %016llX\n"~
			"MaximumAllocationSize           %016llX\t(%u)\n"~
			"VirtualMemoryThreshold          %016llX\n"~
			"ProcessAffinityMask             %016llX\n"~
			"ProcessHeapFlags                %08X\n"~
			"CSDVersion                      %04X\n"~
			"Reserved1                       %04X\n"~
			"EditList                        %016llX\n"~
			"SecurityCookie                  %016llX\n",
			DeCommitFreeBlockThreshold,
			DeCommitTotalBlockThreshold,
			LockPrefixTable,
			MaximumAllocationSize, MaximumAllocationSize,
			VirtualMemoryThreshold,
			ProcessAffinityMask,
			ProcessHeapFlags,
			CSDVersion,
			Reserved1,
			EditList,
			SecurityCookie);

			if (lconf.dir64.Size <= PE_LOAD_CONFIG64_LIMIT_XP)
				goto L_LOAD_CONFIG_EXIT;

			with (lconf.dir64)
			printf(
			"SEHandlerTable                  %016llX\n"~
			"SEHandlerCount                  %016llX\n"~
			"GuardCFCheckFunctionPointer     %016llX\n"~
			"GuardCFDispatchFunctionPointer  %016llX\n"~
			"GuardCFFunctionTable            %016llX\n"~
			"GuardCFFunctionCount            %016llX\n"~
			"GuardFlags                      %08X\n",
			SEHandlerTable,
			SEHandlerCount,
			GuardCFCheckFunctionPointer,
			GuardCFDispatchFunctionPointer,
			GuardCFFunctionTable,
			GuardCFFunctionCount,
			GuardFlags);

			if (lconf.dir64.Size <= PE_LOAD_CONFIG64_LIMIT_VI)
				goto L_LOAD_CONFIG_EXIT;

			with (lconf.dir64)
			printf(
			"CodeIntegrity.Flags             %04X\n"~
			"CodeIntegrity.Catalog           %04X\n"~
			"CodeIntegrity.CatalogOffset     %08X\n"~
			"CodeIntegrity.Reserved          %08X\n"~
			"GuardAddressTakenIatEntryTable  %016llX\n"~
			"GuardAddressTakenIatEntryCount  %016llX\n"~
			"GuardLongJumpTargetTable        %016llX\n"~
			"GuardLongJumpTargetCount        %016llX\n",
			CodeIntegrity.Flags,
			CodeIntegrity.Catalog,
			CodeIntegrity.CatalogOffset,
			CodeIntegrity.Reserved,
			GuardAddressTakenIatEntryTable,
			GuardAddressTakenIatEntryCount,
			GuardLongJumpTargetTable,
			GuardLongJumpTargetCount);

			if (lconf.dir64.Size <= PE_LOAD_CONFIG64_LIMIT_8)
				goto L_LOAD_CONFIG_EXIT;

			with (lconf.dir64)
			printf(
			"DynamicValueRelocTable                    %016llX\n"~
			"CHPEMetadataPointer                       %016llX\n"~
			"GuardRFFailureRoutine                     %016llX\n"~
			"GuardRFFailureRoutineFunctionPointer      %016llX\n"~
			"DynamicValueRelocTableOffset              %08X\n"~
			"DynamicValueRelocTableSection             %04X\n"~
			"Reserved2                                 %04X\n"~
			"GuardRFVerifyStackPointerFunctionPointer  %08X\n"~
			"HotPatchTableOffset                       %016llX\n"~
			"Reserved3                                 %08X\n"~
			"EnclaveConfigurationPointer               %016llX\n"~
			"VolatileMetadataPointer                   %016llX\n",
			DynamicValueRelocTable,
			CHPEMetadataPointer,
			GuardRFFailureRoutine,
			GuardRFFailureRoutineFunctionPointer,
			DynamicValueRelocTableOffset,
			DynamicValueRelocTableSection,
			Reserved2,
			GuardRFVerifyStackPointerFunctionPointer,
			HotPatchTableOffset,
			Reserved3,
			EnclaveConfigurationPointer,
			VolatileMetadataPointer);
		}
	}
L_LOAD_CONFIG_EXIT:

	if (fo_import) {
		PE_LOAD_CONFIG_DIR32 loaddir = void;
		fseek(fi.handle, fo_loadcf, SEEK_SET);
		fread(&loaddir, PE_LOAD_CONFIG_DIR32.sizeof, 1, fi.handle);
	}


	//
	// Disassembly
	//
L_DISASM:

	if ((flags & DUMPER_SHOW_DISASSEMBLY) == 0)
		return EXIT_SUCCESS;

	//TODO: Measure by section length

	puts("\n*\n* Disassembly\n*");
	void *mem = cast(void*)malloc(64);
	fseek(fi.handle, pos_section, SEEK_SET);
	for (ushort si; si < fi.pe.hdr.NumberOfSections; ++si) {
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