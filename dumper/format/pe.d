/// PE32 file dumper
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module format.pe;

import adbg.disassembler;
import adbg.object.server;
import adbg.machines : AdbgMachine;
import adbg.object.format.pe;
import adbg.object.format.mz : mz_hdr_ext;
import adbg.utils.date : ctime32;
import adbg.utils.uid, adbg.utils.bit;
import adbg.error;
import core.stdc.stdlib;
import core.stdc.string : strncmp;
import dumper;
import common.errormgmt;

extern (C):

/// Print PE object.
/// Params:
///   o = Object instance.
/// Returns: Non-zero on error.
int dump_pe(adbg_object_t *o) {
	if (SELECTED(Select.headers))
		dump_pe_hdr(o);
	if (SELECTED(Select.sections))
		dump_pe_sections(o);
	if (SELECTED(Select.exports))
		dump_pe_exports(o);
	if (SELECTED(Select.imports))
		dump_pe_imports(o);
	if (SELECTED(Select.debug_))
		dump_pe_debug(o);
	if (SETTING(Setting.disasmAny))
		dump_pe_disasm(o);
	return 0;
}

private:

// Returns true if the machine value is unknown
void dump_pe_hdr(adbg_object_t *o) {
	pe_header_t *header = adbg_object_pe_header(o);
	
	// NOTE: Optional header selection
	//       This is kind of hard to fix without a dedicated switch
	//       And the base address for e_lfanew is needed
	// TODO: 
	if (SETTING(Setting.extractAny)) {
		print_data("Header", header, pe_header_t.sizeof, 0);
		return;
	}
	
	print_header("Header");
	
	with (header) {
	print_x32("Machine", Machine, adbg_object_pe_machine_string(o));
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
	
	dump_pe_opthdr(o);
}

void dump_pe_opthdr(adbg_object_t *o) {
	pe_optional_header_t *opthdr = cast(pe_optional_header_t*)adbg_object_pe_optional_header(o);
	if (opthdr == null) {
		print_warningf("Optional header: %s", adbg_error_message());
		return;
	}
	
	if (SETTING(Setting.extractAny)) {
		pe_header_t* header = adbg_object_pe_header(o);
		print_data("Optional Header", opthdr, header.SizeOfOptionalHeader);
		return;
	}
	
	print_header("Optional Header");
	
	// NOTE: Server already checks magic format
	const(char) *subsystem = SAFEVAL(adbg_object_pe_subsys_string(o));
	
	// Common in all magic formats
	with (opthdr) {
	print_x16("Magic", Magic, SAFEVAL(adbg_object_pe_magic_string(o)));
	print_u8("MajorLinkerVersion", MajorLinkerVersion);
	print_u8("MinorLinkerVersion", MinorLinkerVersion);
	print_u32("SizeOfCode", SizeOfCode);
	print_u32("SizeOfInitializedData", SizeOfInitializedData);
	print_u32("SizeOfUninitializedData", SizeOfUninitializedData);
	print_x32("AddressOfEntryPoint", AddressOfEntryPoint);
	print_x32("BaseOfCode", BaseOfCode);
	}
	
	switch (opthdr.Magic) {
	case PE_CLASS_32: // 32
		with (opthdr) {
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
		print_x16("Subsystem", Subsystem, subsystem);
		dump_pe_dllcharactiristics(DllCharacteristics);
		print_x32("SizeOfStackReserve", SizeOfStackReserve);
		print_x32("SizeOfStackCommit", SizeOfStackCommit);
		print_x32("SizeOfHeapReserve", SizeOfHeapReserve);
		print_x32("SizeOfHeapCommit", SizeOfHeapCommit);
		print_x32("LoaderFlags", LoaderFlags);
		print_u32("NumberOfRvaAndSizes", NumberOfRvaAndSizes);
		}
		break;
	case PE_CLASS_64: // 64
		with (cast(pe_optional_header64_t*)opthdr) {
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
		print_u32("Subsystem", Subsystem, subsystem);
		dump_pe_dllcharactiristics(DllCharacteristics);
		print_u64("SizeOfStackReserve", SizeOfStackReserve);
		print_u64("SizeOfStackCommit", SizeOfStackCommit);
		print_u64("SizeOfHeapReserve", SizeOfHeapReserve);
		print_u64("SizeOfHeapCommit", SizeOfHeapCommit);
		print_x32("LoaderFlags", LoaderFlags);
		print_u32("NumberOfRvaAndSizes", NumberOfRvaAndSizes);
		}
		break;
	case PE_CLASS_ROM: // ROM has no flags/directories
		with (cast(pe_optional_headerrom_t*)opthdr) {
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
	
	dump_pe_dirs(o);
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

void dump_pe_dirs(adbg_object_t *o) {
	pe_image_data_directory_t *directories = adbg_object_pe_directories(o);
	
	print_header("Directories");
	
	with (directories) {
	with (ExportTable)            print_directory_entry("ExportTable", rva, size);
	with (ImportTable)            print_directory_entry("ImportTable", rva, size);
	with (ResourceTable)          print_directory_entry("ResourceTable", rva, size);
	with (ExceptionTable)         print_directory_entry("ExceptionTable", rva, size);
	with (CertificateTable)       print_directory_entry("CertificateTable", rva, size);
	with (BaseRelocationTable)    print_directory_entry("BaseRelocationTable", rva, size);
	with (DebugDirectory)         print_directory_entry("DebugDirectory", rva, size);
	with (ArchitectureData)       print_directory_entry("ArchitectureData", rva, size);
	with (GlobalPtr)              print_directory_entry("GlobalPtr", rva, size);
	with (TLSTable)               print_directory_entry("TLSTable", rva, size);
	with (LoadConfigurationTable) print_directory_entry("LoadConfigurationTable", rva, size);
	with (BoundImportTable)       print_directory_entry("BoundImportTable", rva, size);
	with (ImportAddressTable)     print_directory_entry("ImportAddressTable", rva, size);
	with (DelayImport)            print_directory_entry("DelayImport", rva, size);
	with (CLRHeader)              print_directory_entry("CLRHeader", rva, size);
	with (Reserved)               print_directory_entry("Reserved", rva, size);
	}
}

void dump_pe_sections(adbg_object_t *o) {
	print_header("Sections");
	
	PE_SECTION_ENTRY *section = void;
	size_t i;
	while ((section = adbg_object_pe_section(o, i++)) != null) with (section) {
		// If we're searching sections, match and don't print yet
		if (opt_section_name && strncmp(Name.ptr, opt_section_name, Name.sizeof))
			continue;
		
		if (SETTING(Setting.extractAny)) {
			char[8] name = void;
			cast(void)strncmp(name.ptr, Name.ptr, Name.sizeof);
			print_data(name.ptr, section, SizeOfRawData, PointerToRawData);
			continue;
		}
		
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
		print_x32("Alignment", alignment, pe32alignments[(alignment >> 20) & 15]);
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
		
		if (opt_section_name) break;
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

void dump_pe_exports(adbg_object_t *o) {
	print_header("Exports");
	
	pe_export_descriptor_t *export_ = adbg_object_pe_export(o);
	if (export_ == null)
		panic_adbg();
	
	with (export_) {
	print_x32("ExportFlags", ExportFlags);
	print_x32("Timestamp", Timestamp);
	print_x16("MajorVersion", MajorVersion);
	print_x16("MinorVersion", MinorVersion);
	print_x32("Name", Name, adbg_object_pe_export_module_name(o, export_));
	print_x32("OrdinalBase", OrdinalBase);
	print_x32("AddressTableEntries", AddressTableEntries);
	print_x32("NumberOfNamePointers", NumberOfNamePointers);
	print_x32("ExportAddressTable", ExportAddressTable);
	print_x32("NamePointer", NamePointer);
	print_x32("OrdinalTable", OrdinalTable);
	}
	
	PE_EXPORT_ENTRY *entry = void;
	size_t ie;
	while ((entry = adbg_object_pe_export_entry_name(o, export_, ie++)) != null) {
		print_x32("Export", entry.Export, adbg_object_pe_export_name_string(o, export_, entry));
	}
}

void dump_pe_imports(adbg_object_t *o) {
	print_header("Imports");
	pe_import_descriptor_t *import_ = void;
	size_t i;
	while ((import_ = adbg_object_pe_import(o, i)) != null) with (import_) {
		i++;
		const(char)* module_name = adbg_object_pe_import_module_name(o, import_);
		if (module_name == null)
			panic_adbg();
		
		print_section(cast(uint)i);
		
		print_x32("Characteristics", Characteristics);
		print_x32("TimeDateStamp", TimeDateStamp);
		print_x32("ForwarderChain", ForwarderChain);
		print_x32l("Name", Name, module_name, 128);
		print_x32("FirstThunk", FirstThunk);
		
		size_t i2;
		void* entry = void;
		while ((entry = adbg_object_pe_import_entry(o, import_, i2)) != null) {
			i2++;
			// Custom formatting for alignment purposes
			print_stringf("Import", "0x%08x 0x%04x %s",
				adbg_object_pe_import_entry_rva(o, import_, entry),
				adbg_object_pe_import_entry_hint(o, import_, entry),
				adbg_object_pe_import_entry_string(o, import_, entry));
		}
		// A PE32 image with an import table and no symbols would be weird
		if (i2 == 0)
			panic_adbg();
	}
}

void dump_pe_debug(adbg_object_t *o) {
	print_header("Debug");
	
	// Mutiple directories. One directory points to one entry.
	pe_debug_directory_entry_t *debug_ = void;
	size_t i;
	while ((debug_ = adbg_object_pe_debug_directory(o, i++)) != null) {
		print_section(cast(uint)i);
		print_x32("Characteristics", debug_.Characteristics);
		print_x32("TimeDateStamp", debug_.TimeDateStamp);
		print_u16("MajorVersion", debug_.MajorVersion);
		print_u16("MinorVersion", debug_.MinorVersion);
		print_u32("Type", debug_.Type, adbg_object_pe_debug_type_string(debug_.Type));
		print_u32("SizeOfData", debug_.SizeOfData);
		print_x32("AddressOfRawData", debug_.AddressOfRawData);
		print_x32("PointerToRawData", debug_.PointerToRawData);
		
		if (debug_.SizeOfData < uint.sizeof) {
			print_warningf("Debug entry too small: Needed %u, got %u",
				cast(uint)uint.sizeof, debug_.SizeOfData);
			continue;
		}
		
		void *data = adbg_object_pe_debug_directory_data(o, debug_);
		if (data == null)
			panic_adbg();
		
		const(char) *sigstr = void;
		switch (debug_.Type) {
		case PE_IMAGE_DEBUG_TYPE_CODEVIEW:
			//TODO: Check MajorVersion/MinorVersion
			//      For example, a modern D program use 0.0
			//      Probably meaningless
			
			uint sig = *cast(uint*)data;
			
			switch (sig) {
			case PE_IMAGE_DEBUG_MAGIC_CODEVIEW_CV410: // PDB 2.0+ / CodeView 4.10
				sigstr = "PDB 2.0+ / CodeView 4.10";
				goto L_DEBUG_PDB20;
			case PE_IMAGE_DEBUG_MAGIC_CODEVIEW_PDB20PLUS: // PDB 2.0+
				sigstr = "PDB 2.0+ / NB10";
				goto L_DEBUG_PDB20;
			case PE_IMAGE_DEBUG_MAGIC_CODEVIEW_CV500: // PDB 2.0+ / CodeView 5.0
				if (debug_.SizeOfData < pe_debug_data_codeview_pdb20_t.sizeof) {
					print_warningf("Size too small for pe_debug_data_codeview_pdb20_t (%u v. %u)",
						debug_.SizeOfData, cast(uint)pe_debug_data_codeview_pdb20_t.sizeof);
					continue;
				}
				sigstr = "PDB 2.0+ / CodeView 5.0";
			L_DEBUG_PDB20:
				pe_debug_data_codeview_pdb20_t* pdb = cast(pe_debug_data_codeview_pdb20_t*)data;
				print_x32("Signature", sig, sigstr);
				print_x32("Offset", pdb.Offset);
				print_x32("Timestamp", pdb.Timestamp, ctime32(pdb.Timestamp));
				print_u32("Age", pdb.Age);
				if (pdb.Offset == 0) // ?
					print_stringl("Path", pdb.Path.ptr,
						cast(int)(debug_.SizeOfData - pe_debug_data_codeview_pdb20_t.sizeof));
				break;
			case PE_IMAGE_DEBUG_MAGIC_CODEVIEW_CV700: // PDB 7.0 / CodeView 7.0
				if (debug_.SizeOfData < pe_debug_data_codeview_pdb70_t.sizeof) {
					print_warningf("Size too small for pe_debug_data_codeview_pdb70_t (%u v. %u)",
						debug_.SizeOfData, cast(uint)pe_debug_data_codeview_pdb70_t.sizeof);
					continue;
				}
				pe_debug_data_codeview_pdb70_t* pdb = cast(pe_debug_data_codeview_pdb70_t*)data;
				char[UID_TEXTLEN] guid = void;
				uid_text(pdb.Guid, guid, UID_GUID);
				print_x32("Signature", sig, "PDB 7.0 / CodeView 7.0");
				print_stringl("GUID", guid.ptr, UID_TEXTLEN);
				print_u32("Age", pdb.Age); // ctime32?
				print_stringl("Path", pdb.Path.ptr,
					cast(int)(debug_.SizeOfData - pe_debug_data_codeview_pdb70_t.sizeof));
				break;
			case PE_IMAGE_DEBUG_MAGIC_EMBEDDED_PPDB: // Portable PDB
				// NOTE: major_version >= 0x100 && minor_version == 0x100
				print_x32("Signature", sig, "Embedded Portable PDB");
				break;
			case PE_IMAGE_DEBUG_MAGIC_PPDB:
				if (debug_.SizeOfData < pe_debug_data_ppdb_t.sizeof) {
					print_warningf("Size too small for pe_debug_data_ppdb_t (%u v. %u)",
						debug_.SizeOfData, cast(uint)pe_debug_data_ppdb_t.sizeof);
					continue;
				}
				pe_debug_data_ppdb_t *ppdb = cast(pe_debug_data_ppdb_t*)data;
				print_x32("Signature", sig, "Portable PDB");
				print_u16("MajorVersion", ppdb.MajorVersion);
				print_u16("MinorVersion", ppdb.MinorVersion);
				print_x32("Reserved", ppdb.Reserved);
				print_u32("Length", ppdb.Length);
				// Forgot why I limited that to 64 chars
				print_stringl("Version", ppdb.Version.ptr,
					ppdb.Length > 64 ? 64 : ppdb.Length);
				break;
			default:
				print_x32("Signature", sig, "Unknown");
				break;
			}
			break;
		case PE_IMAGE_DEBUG_TYPE_MISC:
			if (debug_.SizeOfData < pe_debug_data_misc_t.sizeof) {
				print_warningf("Size too small for pe_debug_data_misc_t (%u v. %u)",
					debug_.SizeOfData, cast(uint)pe_debug_data_misc_t.sizeof);
				continue;
			}
			pe_debug_data_misc_t *misc = cast(pe_debug_data_misc_t*)data;
			if (misc.DataType != 1) // IMAGE_DEBUG_MISC_EXENAME
				panic(1, "Unknown PE_DEBUG_DATA_MISC.DataType value.");
			print_x32("Signature", misc.Signature32, "Misc. Debug Data");
			print_x32("DataType", misc.DataType, "MISC_EXENAME");
			print_x32("Length", misc.Length);
			print_u8("Unicode", misc.Unicode);
			print_u8("Reserved[0]", misc.Reserved[0]);
			print_u8("Reserved[1]", misc.Reserved[1]);
			print_u8("Reserved[2]", misc.Reserved[2]);
			// TODO: Support wide strings
			if (misc.Unicode == false)
				print_stringl("Data", cast(char*)misc.Data.ptr,
					cast(int)(debug_.SizeOfData - pe_debug_data_misc_t.sizeof));
			break;
		case PE_IMAGE_DEBUG_TYPE_FPO:
			if (debug_.SizeOfData < pe_debug_data_fpo_t.sizeof) {
				print_warningf("Size too small for pe_debug_data_fpo_t (%u v. %u)",
					debug_.SizeOfData, cast(uint)pe_debug_data_fpo_t.sizeof);
				continue;
			}
			pe_debug_data_fpo_t *fpo = cast(pe_debug_data_fpo_t*)data;
			print_x32("ulOffStart", fpo.ulOffStart);
			print_x32("cbProcSize", fpo.cbProcSize);
			print_x32("cdwLocals", fpo.cdwLocals);
			print_x16("cdwParams", fpo.cdwParams);
			print_x16("Flags", fpo.Flags);
			break;
		case PE_IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS:
			// TODO: PE_IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS
			break;
		case PE_IMAGE_DEBUG_TYPE_VC_FEATURE:
			if (debug_.SizeOfData < pe_debug_data_vc_feat_t.sizeof) {
				print_warningf("Size too small for pe_debug_data_vc_feat_t (%u v. %u)",
					debug_.SizeOfData, cast(uint)pe_debug_data_vc_feat_t.sizeof);
				continue;
			}
			pe_debug_data_vc_feat_t* vc = cast(pe_debug_data_vc_feat_t*)data;
			print_u32("PreVC11", vc.PreVC11);
			print_u32("C/C++", vc.CCpp);
			print_u32("/GS", vc.GS);
			print_u32("/SDL", vc.SDL);
			print_u32("GuardN", vc.GuardN);
			break;
		case PE_IMAGE_DEBUG_TYPE_POGO:
			if (debug_.SizeOfData < pe_debug_data_pogo_entry_t.sizeof) {
				print_warningf("Size too small for pe_debug_data_pogo_entry_t (%u v. %u)",
					debug_.SizeOfData, cast(uint)pe_debug_data_pogo_entry_t.sizeof);
				continue;
			}
			uint sig = *cast(uint*)data;
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
			
			//TODO: Check if multiple entries.
			pe_debug_data_pogo_entry_t* pogo = cast(pe_debug_data_pogo_entry_t*)data;
			print_x32("RVA", pogo.Rva);
			print_x32("Size", pogo.Size);
			print_stringl("Size", pogo.Name.ptr,
				cast(int)(debug_.SizeOfData - pe_debug_data_pogo_entry_t.sizeof));
			break;
		case PE_IMAGE_DEBUG_TYPE_R2R_PERFMAP:
			if (debug_.SizeOfData < pe_debug_data_r2r_perfmap_t.sizeof) {
				print_warningf("Size too small for pe_debug_data_r2r_perfmap_t (%u v. %u)",
					debug_.SizeOfData, cast(uint)pe_debug_data_r2r_perfmap_t.sizeof);
				continue;
			}
			pe_debug_data_r2r_perfmap_t* r2r = cast(pe_debug_data_r2r_perfmap_t*)data;
			char[UID_TEXTLEN] buf = void;
			uid_text(r2r.Signature, buf, UID_GUID);
			print_x32("Magic", r2r.Magic32, "R2R PerfMap");
			print_string("Signature", buf.ptr);
			print_x32("Version", r2r.Version);
			print_stringl("Path", r2r.Path.ptr,
				cast(int)(debug_.SizeOfData - pe_debug_data_r2r_perfmap_t.sizeof));
			break;
		default:
		}
		
		adbg_object_pe_debug_directory_data_close(data);
	}
}

void dump_pe_disasm(adbg_object_t *o) {
	print_header("Disassembly");
	
	int all = SETTING(Setting.disasmAll);
	size_t i;
	pe_section_entry_t *section = void;
	while ((section = adbg_object_pe_section(o, i++)) != null) {
		//
		if (all == 0 && (section.Characteristics & PE_SECTION_CHARACTERISTIC_MEM_EXECUTE) == 0)
			continue;
		// Compare section string if mentionned
		if (opt_section_name && strncmp(opt_section_name, section.Name.ptr, section.Name.sizeof))
			continue;
		void *buffer = malloc(section.SizeOfRawData);
		if (buffer == null)
			panic_crt();
		if (adbg_object_read_at(o, section.PointerToRawData, buffer, section.SizeOfRawData))
			panic_adbg();
		with (section) dump_disassemble_object(o, Name.ptr, Name.sizeof, buffer, SizeOfRawData, 0);
		free(buffer);
	}
}