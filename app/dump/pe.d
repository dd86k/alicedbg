/// PE32 file dumper
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module dump.pe;

import core.stdc.stdlib : EXIT_SUCCESS, EXIT_FAILURE;
import adbg.disassembler.core;
import adbg.object.server;
import adbg.object.machines : AdbgMachine;
import adbg.object.format.pe;
import adbg.utils.date : ctime32;
import adbg.utils.uid, adbg.utils.bit;
import common, dumper;

extern (C):

/// Print PE object.
/// Params:
///   o = Object.
///   flags = Dump settings.
/// Returns: Non-zero on error.
int dump_pe(ref Dumper dump, adbg_object_t *o) {
	if (dump.selected_headers())
		dump_pe_hdr(dump, o);
	
	if (dump.selected_sections())
		dump_pe_sections(dump, o);
	
	if (dump.selected_exports())
		dump_pe_exports(dump, o);
	
	if (dump.selected_imports())
		dump_pe_imports(dump, o);
	
	if (dump.selected_debug())
		dump_pe_debug(dump, o);
	
	if (dump.selected_disasm_any())
		dump_pe_disasm(dump, o);
	
	return EXIT_SUCCESS;
}

private:

// Returns true if the machine value is unknown
void dump_pe_hdr(ref Dumper dump, adbg_object_t *o) {
	print_header("Header");
	
	const(char) *str_mach = adbg_object_pe_machine_string(o.i.pe.header.Machine);
	
	if (str_mach == null)
		str_mach = "Unknown";
	
	with (o.i.pe.header) {
	print_x32("Machine", Machine, str_mach);
	print_u32("NumberOfSections", NumberOfSections);
	print_x32("TimeDateStamp", TimeDateStamp, ctime32(TimeDateStamp));
	print_x32("PointerToSymbolTable", PointerToSymbolTable);
	print_u32("NumberOfSymbols", NumberOfSymbols);
	print_u32("SizeOfOptionalHeader", SizeOfOptionalHeader);
	print_flags32("Characteristics", Characteristics,
		"RELOCS_STRIPPED".ptr,	PE_CHARACTERISTIC_RELOCS_STRIPPED,
		"EXECUTABLE_IMAGE".ptr,	PE_CHARACTERISTIC_EXECUTABLE_IMAGE,
		"LINE_NUMS_STRIPPED".ptr,	PE_CHARACTERISTIC_LINE_NUMS_STRIPPED,
		"LOCAL_SYMS_STRIPPED".ptr,	PE_CHARACTERISTIC_LOCAL_SYMS_STRIPPED,
		"AGGRESSIVE_WS_TRIM".ptr,	PE_CHARACTERISTIC_AGGRESSIVE_WS_TRIM,
		"LARGE_ADDRESS_AWARE".ptr,	PE_CHARACTERISTIC_LARGE_ADDRESS_AWARE,
		"16BIT_MACHINE".ptr,	PE_CHARACTERISTIC_16BIT_MACHINE,
		"BYTES_REVERSED_LO".ptr,	PE_CHARACTERISTIC_BYTES_REVERSED_LO,
		"32BIT_MACHINE".ptr,	PE_CHARACTERISTIC_32BIT_MACHINE,
		"DEBUG_STRIPPED".ptr,	PE_CHARACTERISTIC_DEBUG_STRIPPED,
		"REMOVABLE_RUN_FROM_SWAP".ptr,	PE_CHARACTERISTIC_REMOVABLE_RUN_FROM_SWAP,
		"NET_RUN_FROM_SWAP".ptr,	PE_CHARACTERISTIC_NET_RUN_FROM_SWAP,
		"SYSTEM".ptr,	PE_CHARACTERISTIC_SYSTEM,
		"DLL".ptr,	PE_CHARACTERISTIC_DLL,
		"UP_SYSTEM_ONLY".ptr,	PE_CHARACTERISTIC_UP_SYSTEM_ONLY,
		"BYTES_REVERSED_HI".ptr,	PE_CHARACTERISTIC_BYTES_REVERSED_HI,
		null);
	}
	
	if (str_mach == null)
		return;
	//TODO: Could be a server check
	if (o.i.pe.header.SizeOfOptionalHeader == 0)
		return;
	
	dump_pe_opthdr(dump, o);
}

void dump_pe_opthdr(ref Dumper dump, adbg_object_t *o) {
	print_header("Optional Header");
	
	// NOTE: Server already checks magic format
	const(char) *str_mag = adbg_object_pe_magic_string(o.i.pe.opt_header.Magic);
	const(char) *str_sys = adbg_object_pe_subsys_string(o.i.pe.opt_header.Subsystem);
	if (str_sys == null)
		str_sys = "Unknown";
	
	// Common in all magic formats
	with (o.i.pe.opt_header) {
	print_x16("Magic", Magic, str_mag);
	print_u8("MajorLinkerVersion", MajorLinkerVersion);
	print_u8("MinorLinkerVersion", MinorLinkerVersion);
	print_u32("SizeOfCode", SizeOfCode);
	print_u32("SizeOfInitializedData", SizeOfInitializedData);
	print_u32("SizeOfUninitializedData", SizeOfUninitializedData);
	print_x32("AddressOfEntryPoint", AddressOfEntryPoint);
	print_x32("BaseOfCode", BaseOfCode);
	}
	
	switch (o.i.pe.opt_header.Magic) {
	case PE_FMT_32: // 32
		with (o.i.pe.opt_header) {
		print_x32("BaseOfData", BaseOfData);
		print_x32("ImageBase", ImageBase);
		print_u32("SectionAlignment", SectionAlignment);
		print_u32("FileAlignment", FileAlignment);
		print_u16("MajorOperatingSystemVersion", MajorOperatingSystemVersion);
		print_u16("MinorOperatingSystemVersion", MinorOperatingSystemVersion);
		print_u16("MajorImageVersion", MajorImageVersion);
		print_u16("MinorImageVersion", MinorImageVersion);
		print_u16("MajorSubsystemVersion", MajorSubsystemVersion);
		print_u16("MinorSubsystemVersion", MinorSubsystemVersion);
		print_x32("Win32VersionValue", Win32VersionValue);
		print_u32("SizeOfImage", SizeOfImage);
		print_u32("SizeOfHeaders", SizeOfHeaders);
		print_x32("CheckSum", CheckSum);
		print_x16("Subsystem", Subsystem, str_sys);
		dump_pe_dllcharactiristics(DllCharacteristics);
		print_x32("SizeOfStackReserve", SizeOfStackReserve);
		print_x32("SizeOfStackCommit", SizeOfStackCommit);
		print_x32("SizeOfHeapReserve", SizeOfHeapReserve);
		print_x32("SizeOfHeapCommit", SizeOfHeapCommit);
		print_x32("LoaderFlags", LoaderFlags);
		print_u32("NumberOfRvaAndSizes", NumberOfRvaAndSizes);
		}
		break;
	case PE_FMT_64: // 64
		with (o.i.pe.opt_header64) {
		print_x64("ImageBase", ImageBase);
		print_x32("SectionAlignment", SectionAlignment);
		print_x32("FileAlignment", FileAlignment);
		print_u16("MajorOperatingSystemVersion", MajorOperatingSystemVersion);
		print_u16("MinorOperatingSystemVersion", MinorOperatingSystemVersion);
		print_u16("MajorImageVersion", MajorImageVersion);
		print_u16("MinorImageVersion", MinorImageVersion);
		print_u16("MajorSubsystemVersion", MajorSubsystemVersion);
		print_u16("MinorSubsystemVersion", MinorSubsystemVersion);
		print_x32("Win32VersionValue", Win32VersionValue);
		print_u32("SizeOfImage", SizeOfImage);
		print_u32("SizeOfHeaders", SizeOfHeaders);
		print_x32("CheckSum", CheckSum);
		print_u32("Subsystem", Subsystem, str_sys);
		dump_pe_dllcharactiristics(DllCharacteristics);
		print_u64("SizeOfStackReserve", SizeOfStackReserve);
		print_u64("SizeOfStackCommit", SizeOfStackCommit);
		print_u64("SizeOfHeapReserve", SizeOfHeapReserve);
		print_u64("SizeOfHeapCommit", SizeOfHeapCommit);
		print_x32("LoaderFlags", LoaderFlags);
		print_u32("NumberOfRvaAndSizes", NumberOfRvaAndSizes);
		}
		break;
	case PE_FMT_ROM: // ROM has no flags/directories
		with (o.i.pe.opt_headerrom) {
		print_x32("BaseOfData", BaseOfData);
		print_x32("BaseOfBss", BaseOfBss);
		print_x32("GprMask", GprMask);
		print_x32("CprMask[0]", CprMask[0]);
		print_x32("CprMask[1]", CprMask[1]);
		print_x32("CprMask[2]", CprMask[2]);
		print_x32("CprMask[3]", CprMask[3]);
		print_x32("GpValue", GpValue);
		}
		return;
	default:
	}
	
	dump_pe_dirs(dump, o);
}

void dump_pe_dllcharactiristics(ushort dllchars) {
	print_flags16("DllCharacteristics", dllchars,
		"HIGH_ENTROPY_VA".ptr,	PE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,
		"DYNAMIC_BASE".ptr,	PE_DLLCHARACTERISTICS_DYNAMIC_BASE,
		"FORCE_INTEGRITY".ptr,	PE_DLLCHARACTERISTICS_FORCE_INTEGRITY,
		"NX_COMPAT".ptr,	PE_DLLCHARACTERISTICS_NX_COMPAT,
		"NO_ISOLATION".ptr,	PE_DLLCHARACTERISTICS_NO_ISOLATION,
		"NO_SEH".ptr,	PE_DLLCHARACTERISTICS_NO_SEH,
		"NO_BIND".ptr,	PE_DLLCHARACTERISTICS_NO_BIND,
		"APPCONTAINER".ptr,	PE_DLLCHARACTERISTICS_APPCONTAINER,
		"WDM_DRIVER".ptr,	PE_DLLCHARACTERISTICS_WDM_DRIVER,
		"GUARD_CF".ptr,	PE_DLLCHARACTERISTICS_GUARD_CF,
		"TERMINAL_SERVER_AWARE".ptr,	PE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE,
		null);
}

void dump_pe_dirs(ref Dumper dump, adbg_object_t *o) {
	// ROM check
	//TODO: Make this a server check
	if (o.i.pe.directory == null)
		return;
	
	print_header("Directories");
	
	with (o.i.pe.directory) {
	print_directory_entry("ExportTable", ExportTable.rva, ExportTable.size);
	print_directory_entry("ImportTable", ImportTable.rva, ImportTable.size);
	print_directory_entry("ResourceTable", ResourceTable.rva, ResourceTable.size);
	print_directory_entry("ExceptionTable", ExceptionTable.rva, ExceptionTable.size);
	print_directory_entry("CertificateTable", CertificateTable.rva, CertificateTable.size);
	print_directory_entry("BaseRelocationTable", BaseRelocationTable.rva, BaseRelocationTable.size);
	print_directory_entry("DebugDirectory", DebugDirectory.rva, DebugDirectory.size);
	print_directory_entry("ArchitectureData", ArchitectureData.rva, ArchitectureData.size);
	print_directory_entry("GlobalPtr", GlobalPtr.rva, GlobalPtr.size);
	print_directory_entry("TLSTable", TLSTable.rva, TLSTable.size);
	print_directory_entry("LoadConfigurationTable", LoadConfigurationTable.rva, LoadConfigurationTable.size);
	print_directory_entry("BoundImportTable", BoundImportTable.rva, BoundImportTable.size);
	print_directory_entry("ImportAddressTable", ImportAddressTable.rva, ImportAddressTable.size);
	print_directory_entry("DelayImport", DelayImport.rva, DelayImport.size);
	print_directory_entry("CLRHeader", CLRHeader.rva, CLRHeader.size);
	print_directory_entry("Reserved", Reserved.rva, Reserved.size);
	}
}

void dump_pe_sections(ref Dumper dump, adbg_object_t *o) {
	print_header("Sections");
	
	PE_SECTION_ENTRY *section = void;
	size_t i;
	while ((section = adbg_object_pe_section(o, i++)) != null) with (section) {
		print_section(cast(uint)i, Name.ptr, 8);
		print_x32("VirtualAddress", VirtualAddress);
		print_x32("VirtualSize", VirtualSize);
		print_x32("PointerToRawData", PointerToRawData);
		print_x32("SizeOfRawData", SizeOfRawData);
		print_x32("PointerToRelocations", PointerToRelocations);
		print_x32("PointerToLinenumbers", PointerToLinenumbers);
		print_u16("NumberOfRelocations", NumberOfRelocations);
		print_u16("NumberOfLinenumbers", NumberOfLinenumbers);
		//TODO: Integrate with rest of Characteristics
		static immutable const(char)*[] pe32alignments = [
			"ALIGN_DEFAULT(16)", // PEDUMP (1997)
			"ALIGN_1BYTES",
			"ALIGN_2BYTES",
			"ALIGN_4BYTES",
			"ALIGN_8BYTES",
			"ALIGN_16BYTES",
			"ALIGN_32BYTES",
			"ALIGN_64BYTES",
			"ALIGN_128BYTES",
			"ALIGN_256BYTES",
			"ALIGN_512BYTES",
			"ALIGN_1024BYTES",
			"ALIGN_2048BYTES",
			"ALIGN_4096BYTES",
			"ALIGN_8192BYTES",
			"ALIGN_RESERVED",
		];
		uint alignment = Characteristics & PE_SECTION_CHARACTERISTIC_ALIGN_MASK;
		print_x32("Alignment", alignment, pe32alignments[alignment >> 20]);
		print_flags32("Characteristics", Characteristics,
			"TYPE_DSECT".ptr,	PE_SECTION_CHARACTERISTIC_TYPE_DSECT,
			"TYPE_NOLOAD".ptr,	PE_SECTION_CHARACTERISTIC_TYPE_NOLOAD,
			"TYPE_GROUP".ptr,	PE_SECTION_CHARACTERISTIC_TYPE_GROUP,
			"NO_PAD".ptr,	PE_SECTION_CHARACTERISTIC_NO_PAD,
			"TYPE_COPY".ptr,	PE_SECTION_CHARACTERISTIC_TYPE_COPY,
			"CODE".ptr,	PE_SECTION_CHARACTERISTIC_CODE,
			"INITIALIZED_DATA".ptr,	PE_SECTION_CHARACTERISTIC_INITIALIZED_DATA,
			"UNINITIALIZED_DATA".ptr,	PE_SECTION_CHARACTERISTIC_UNINITIALIZED_DATA,
			"LNK_OTHER".ptr,	PE_SECTION_CHARACTERISTIC_LNK_OTHER,
			"LNK_INFO".ptr,	PE_SECTION_CHARACTERISTIC_LNK_INFO,
			"LNK_REMOVE".ptr,	PE_SECTION_CHARACTERISTIC_LNK_REMOVE,
			"LNK_COMDAT".ptr,	PE_SECTION_CHARACTERISTIC_LNK_COMDAT,
			"MEM_PROTECTED".ptr,	PE_SECTION_CHARACTERISTIC_MEM_PROTECTED,
			"GPREL".ptr,	PE_SECTION_CHARACTERISTIC_GPREL,
			"MEM_PURGEABLE".ptr,	PE_SECTION_CHARACTERISTIC_MEM_PURGEABLE,
			"MEM_16BIT".ptr,	PE_SECTION_CHARACTERISTIC_MEM_16BIT,
			"MEM_LOCKED".ptr,	PE_SECTION_CHARACTERISTIC_MEM_LOCKED,
			"PRELOAD".ptr,	PE_SECTION_CHARACTERISTIC_PRELOAD,
			"LNK_NRELOC_OVFL".ptr,	PE_SECTION_CHARACTERISTIC_LNK_NRELOC_OVFL,
			"MEM_DISCARDABLE".ptr,	PE_SECTION_CHARACTERISTIC_MEM_DISCARDABLE,
			"MEM_NOT_CACHED".ptr,	PE_SECTION_CHARACTERISTIC_MEM_NOT_CACHED,
			"MEM_NOT_PAGED".ptr,	PE_SECTION_CHARACTERISTIC_MEM_NOT_PAGED,
			"MEM_SHARED".ptr,	PE_SECTION_CHARACTERISTIC_MEM_SHARED,
			"MEM_EXECUTE".ptr,	PE_SECTION_CHARACTERISTIC_MEM_EXECUTE,
			"MEM_READ".ptr,	PE_SECTION_CHARACTERISTIC_MEM_READ,
			"MEM_WRITE".ptr,	PE_SECTION_CHARACTERISTIC_MEM_WRITE,
			null);
		
	}
}

/*void dump_pe_loadconfig(ref Dumper dump) {
	
	dump_h1("Load Configuration");
	
	if (dump.obj.pe.loadconfig == null) { // LOAD_CONFIGURATION
		puts("No 
	}
		if (fseek(dump.obj.handle, fo_loadcf, SEEK_SET))
			return EXIT_FAILURE;

		PE_LOAD_CONFIG_META lconf = void;
		char[32] lcbuffer = void;

		if (fread(&lconf, 4, 1, obj.handle) == 0)
			return EXIT_FAILURE;
		if (fread(&lconf.dir32.TimeDateStamp, lconf.dir32.Size, 1, obj.handle) == 0)
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

		if (dump.optMagic != PE_FMT_64) { // 32
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
				goto L_LOADCFG_EXIT;

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
				goto L_LOADCFG_EXIT;

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
				goto L_LOADCFG_EXIT;

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
				goto L_LOADCFG_EXIT;

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
				goto L_LOADCFG_EXIT;

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
				goto L_LOADCFG_EXIT;

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
}*/

void dump_pe_exports(ref Dumper dump, adbg_object_t *o) {
	print_header("Exports");
	
	PE_EXPORT_DESCRIPTOR *export_ = adbg_object_pe_export(o);
	if (export_ == null)
		return;
	
	with (export_) {
	print_x32("ExportFlags", ExportFlags);
	print_x32("Timestamp", Timestamp);
	print_x16("MajorVersion", MajorVersion);
	print_x16("MinorVersion", MinorVersion);
	print_x32("Name", Name, adbg_object_pe_export_name(o, export_));
	print_x32("OrdinalBase", OrdinalBase);
	print_x32("AddressTableEntries", AddressTableEntries);
	print_x32("NumberOfNamePointers", NumberOfNamePointers);
	print_x32("ExportAddressTable", ExportAddressTable);
	print_x32("NamePointer", NamePointer);
	print_x32("OrdinalTable", OrdinalTable);
	}
	
	PE_EXPORT_ENTRY *entry = void;
	size_t ie;
	while ((entry = adbg_object_pe_export_name_entry(o, export_, ie++)) != null) {
		print_x32("Export", entry.Export, adbg_object_pe_export_name_string(o, export_, entry));
	}
}

void dump_pe_imports(ref Dumper dump, adbg_object_t *o) {
	print_header("Imports");
	PE_IMPORT_DESCRIPTOR *import_ = void;
	size_t i;
	while ((import_ = adbg_object_pe_import(o, i++)) != null) with (import_) {
		char* name = adbg_object_pe_import_name(o, import_);
		print_section(cast(uint)i, name, 128);
		
		print_x32("Characteristics", Characteristics);
		print_x32("TimeDateStamp", TimeDateStamp);
		print_x32("ForwarderChain", ForwarderChain);
		print_x32("Name", Name);
		print_x32("FirstThunk", FirstThunk);
		
		//TODO: Function to get import name+hint from lte directly
		//      adbg_object_pe_import_entry_string(o, import_, i++);
		
		size_t il;
		switch (o.i.pe.opt_header.Magic) {
		case PE_FMT_32:
			PE_IMPORT_ENTRY32 *t32 = adbg_object_pe_import_entry32(o, import_, il);
			if (t32 == null) continue;
			do with (t32) {
				if (ordinal >= 0x8000_0000) { // Ordinal
					print_section(cast(uint)il);
					print_x16("Number", number);
				} else { // RVA
					ushort *hint = adbg_object_pe_import_entry32_hint(o, import_, t32);
					if (hint == null) {
				LBADINDEX32:
						print_string("warning", "String index outside buffer");
						continue;
					}
					const(char)* import_name = cast(const(char)*)hint + ushort.sizeof;
					if (adbg_object_outboundp(o, cast(void*)import_name))
						goto LBADINDEX32;
					print_x32("RVA", rva);
					print_x16l("Hint", *hint, import_name, 64);
				}
			} while ((t32 = adbg_object_pe_import_entry32(o, import_, ++il)) != null);
			continue;
		case PE_FMT_64:
			PE_IMPORT_ENTRY64 *t64 = adbg_object_pe_import_entry64(o, import_, il);
			if (t64 == null) continue;
			do with (t64) {
				if (ordinal >= 0x8000_0000_0000_0000) { // Ordinal
					print_section(cast(uint)il);
					print_x16("Number", number);
				} else { // RVA
					ushort *hint = adbg_object_pe_import_entry64_hint(o, import_, t64);
					if (hint == null) {
				LBADINDEX64:
						print_string("warning", "String index outside buffer");
						continue;
					}
					const(char)* import_name = cast(const(char)*)hint + ushort.sizeof;
					if (adbg_object_outboundp(o, cast(void*)import_name))
						goto LBADINDEX64;
					print_x32("RVA", rva);
					print_x16l("Hint", *hint, import_name, 64);
				}
			} while ((t64 = adbg_object_pe_import_entry64(o, import_, ++il)) != null);
			continue;
		default:
		}
	}
}

void dump_pe_debug(ref Dumper dump, adbg_object_t *o) {
	print_header("Debug");
	
	PE_DEBUG_DIRECTORY *debug_ = void;
	size_t i;
	while ((debug_ = adbg_object_pe_debug_directory(o, i++)) != null) with (debug_) {
		print_section(cast(uint)i);
		print_x32("Characteristics", Characteristics);
		print_x32("TimeDateStamp", TimeDateStamp);
		print_u16("MajorVersion", MajorVersion);
		print_u16("MinorVersion", MinorVersion);
		print_u32("Type", Type, adbg_object_pe_debug_type_string(Type));
		print_u32("SizeOfData", SizeOfData);
		print_x32("AddressOfRawData", AddressOfRawData);
		print_x32("PointerToRawData", PointerToRawData);
		
		uint sig = void;
		if (adbg_object_offsett!uint(o, &sig, PointerToRawData)) {
			print_string("error", "PointerToRawData out of bounds");
			return;
		}
		
		const(char) *sigstr = void;
		switch (Type) {
		case PE_IMAGE_DEBUG_TYPE_CODEVIEW:
			//TODO: Check MajorVersion/MinorVersion
			//      For example, a modern D program use 0.0
			//      Probably meaningless
			
			switch (sig) {
			case PE_IMAGE_DEBUG_MAGIC_CODEVIEW_CV410: // PDB 2.0+ / CodeView 4.10
				sigstr = "PDB 2.0+ / CodeView 4.10";
				goto L_DEBUG_PDB20;
			case PE_IMAGE_DEBUG_MAGIC_CODEVIEW_PDB20PLUS: // PDB 2.0+
				sigstr = "PDB 2.0+ / NB10";
				goto L_DEBUG_PDB20;
			case PE_IMAGE_DEBUG_MAGIC_CODEVIEW_CV500: // PDB 2.0+ / CodeView 5.0
				sigstr = "PDB 2.0+ / CodeView 5.0";
			L_DEBUG_PDB20:
				print_x32("Signature", sig, sigstr);
				PE_DEBUG_DATA_CODEVIEW_PDB20* pdb = void;
				if (adbg_object_offsetl(o, cast(void**)&pdb,
					PointerToRawData, PE_DEBUG_DATA_CODEVIEW_PDB20.sizeof + 256)) {
					print_string("error", "PE_DEBUG_DATA_CODEVIEW_PDB20 out of bounds");
					continue;
				}
				print_x32("Offset", pdb.Offset);
				print_x32("Timestamp", pdb.Timestamp, ctime32(pdb.Timestamp));
				print_u32("Age", pdb.Age);
				if (pdb.Offset == 0) print_stringl("Path", pdb.Path.ptr, 256);
				break;
			case PE_IMAGE_DEBUG_MAGIC_CODEVIEW_CV700: // PDB 7.0 / CodeView 7.0
				PE_DEBUG_DATA_CODEVIEW_PDB70* pdb = void;
				if (adbg_object_offsetl(o, cast(void**)&pdb,
					PointerToRawData, PE_DEBUG_DATA_CODEVIEW_PDB70.sizeof + 256)) {
					print_string("error", "PE_DEBUG_DATA_CODEVIEW_PDB70 out of bounds");
					continue;
				}
				char[UID_TEXTLEN] guid = void;
				uid_text(pdb.Guid, guid, UID_GUID);
				print_x32("Signature", sig, "PDB 7.0 / CodeView 7.0");
				print_stringl("GUID", guid.ptr, UID_TEXTLEN);
				print_u32("Age", pdb.Age); // ctime32?
				print_stringl("Path", pdb.Path.ptr, 256);
				break;
			case PE_IMAGE_DEBUG_MAGIC_EMBEDDED_PPDB: // Portable PDB
				// NOTE: major_version >= 0x100 && minor_version == 0x100
				print_x32("Signature", sig, "Embedded Portable PDB");
				break;
			case PE_IMAGE_DEBUG_MAGIC_PPDB:
				PE_DEBUG_DATA_PPDB *ppdb = void;
				if (adbg_object_offsetl(o, cast(void**)&ppdb,
					PointerToRawData, PE_DEBUG_DATA_PPDB.sizeof + 64)) {
					print_string("error", "PE_DEBUG_DATA_PPDB out of bounds");
					continue;
				}
				print_x32("Signature", sig, "Portable PDB");
				print_u16("MajorVersion", ppdb.MajorVersion);
				print_u16("MinorVersion", ppdb.MinorVersion);
				print_x32("Reserved", ppdb.Reserved);
				print_u32("Length", ppdb.Length);
				print_stringl("Version", ppdb.Version.ptr,
					ppdb.Length > 64 ? 64 : ppdb.Length);
				break;
			default:
				print_x32("Signature", sig, "Unknown");
				break;
			}
			break;
		case PE_IMAGE_DEBUG_TYPE_MISC:
			PE_DEBUG_DATA_MISC* misc = void;
			if (adbg_object_offsetl(o, cast(void**)&misc,
				PointerToRawData, PE_DEBUG_DATA_MISC.sizeof + 256)) {
				print_string("error", "PE_DEBUG_DATA_MISC out of bounds");
				continue;
			}
			if (misc.DataType != 1) { // IMAGE_DEBUG_MISC_EXENAME
				print_string("error", "PE_DEBUG_DATA_MISC.DataType is not set to 1.");
				continue;
			}
			print_x32("Signature", sig, "Misc. Debug Data");
			print_x32("DataType", misc.DataType);
			print_x32("Length", misc.Length);
			print_u8("Unicode", misc.Unicode);
			print_u8("Reserved[0]", misc.Reserved[0]);
			print_u8("Reserved[1]", misc.Reserved[1]);
			print_u8("Reserved[2]", misc.Reserved[2]);
			if (misc.Unicode == false)
				print_stringl("Data", cast(char*)misc.Data.ptr, 256);
			break;
		case PE_IMAGE_DEBUG_TYPE_FPO:
			// TODO: PE_IMAGE_DEBUG_TYPE_FPO
			break;
		case PE_IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS:
			// TODO: PE_IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS
			break;
		case PE_IMAGE_DEBUG_TYPE_POGO:
			const(char) *pgotypestr = void;
			switch (sig) {
			case PE_IMAGE_DEBUG_MAGIC_POGO_LTCG:
				pgotypestr = "POGO LTCG (Link-Time Code Generation)";
				break;
			case PE_IMAGE_DEBUG_MAGIC_POGO_PGU:
				pgotypestr = "POGO PGU (Profile Guided Update)";
				break;
			default:
				pgotypestr = "POGO (Unknown)";
			}
			print_x32("Signature", sig, pgotypestr);
			
			PE_DEBUG_POGO_ENTRY* pogoentry = void;
			if (adbg_object_offsetl(o, cast(void**)&pogoentry,
				PointerToRawData, PE_DEBUG_POGO_ENTRY.sizeof + 256)) { // Guess
				print_string("error", "PE_DEBUG_POGO_ENTRY out of bounds");
			}
			
			print_x32("RVA", pogoentry.Rva);
			print_x32("Size", pogoentry.Size);
			print_stringl("Size", pogoentry.Name.ptr, 256); // Guess
			break;
		case PE_IMAGE_DEBUG_TYPE_R2R_PERFMAP:
			break;
		default:
		}
	}
}

void dump_pe_disasm(ref Dumper dump, adbg_object_t *o) {
	print_header("Disassembly");
	
	bool all = dump.selected_disasm_all();
	PE_SECTION_ENTRY *section = void;
	size_t i;
	while ((section = adbg_object_pe_section(o, i++)) != null) with (section) {
		if (all || Characteristics & PE_SECTION_CHARACTERISTIC_MEM_EXECUTE) {
			dump_disassemble_object(dump, o, Name.ptr, 8,
				o.buffer + PointerToRawData, SizeOfRawData, 0);
		}
	}
}