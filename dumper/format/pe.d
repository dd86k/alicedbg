/// PE32 file dumper
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module format.pe;

import adbg.disassembler;
import adbg.objectserver;
import adbg.machines : AdbgMachine;
import adbg.objects.pe;
import adbg.objects.mz : mz_header_t;
import adbg.utils.date : ctime32;
import adbg.utils.uid, adbg.utils.bit;
import adbg.error;
import core.stdc.stdlib;
import core.stdc.string : strncmp;
import core.stdc.stdio : snprintf;
import dumper;
import format.mz : dump_mz_ext_header;
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
	if (SELECTED(Select.loadconfig))
		dump_pe_loadconfig(o);
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
	if (SETTING(Setting.extractAny)) {
		print_data("Header", header, pe_header_t.sizeof, 0);
		return;
	}
	
	// Print legacy header
	dump_mz_ext_header(adbg_object_pe_mz_header(o));
	
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
	dump_pe_richhdr(o);
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

void dump_pe_richhdr(adbg_object_t *o) {
	pe_rich_header_t *rich = adbg_object_pe_rich_header(o);
	if (rich == null) {
		debug print_warningf("Cannot get rich header: %s", adbg_error_message());
		return;
	}
	
	print_header("Rich Header");
	for (size_t i; i < rich.itemcount; ++i) with (rich.items[i]) {
		char[32] b = void;
		snprintf(b.ptr, 32, "count=%u", count);
		print_u16("buildId", buildId, b.ptr);
		print_x16("prodId", prodId, adbg_object_pe_rich_prodid_string(prodId));
	}
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
	
	pe_section_entry_t *section = void;
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

// Weird contraption to auto cut off fields according to loadconfig size
// TODO: could do with string mixin, but too lazy
struct fieldt {
	string name;
	size_t foffset;
	size_t fsize;
}
template LC32(string f) {
	enum LC32 = mixin("fieldt(pe_loadconfig32_t."~f~".stringof,"~
		"pe_loadconfig32_t."~f~".offsetof,"~
		"pe_loadconfig32_t."~f~".sizeof)");
}
static immutable fieldt[] lc32 = [
	LC32!"Size",
	LC32!"TimeDateStamp",
	LC32!"MajorVersion",
	LC32!"MinorVersion",
	LC32!"GlobalFlagsClear",
	LC32!"GlobalFlagsSet",
	LC32!"CriticalSectionDefaultTimeout",
	LC32!"DeCommitFreeBlockThreshold",
	LC32!"DeCommitTotalBlockThreshold",
	LC32!"LockPrefixTable",
	LC32!"MaximumAllocationSize",
	LC32!"VirtualMemoryThreshold",
	LC32!"ProcessHeapFlags",
	LC32!"ProcessAffinityMask",
	LC32!"CSDVersion",
	LC32!"Reserved1",
	LC32!"EditList",
	LC32!"SecurityCookie",
	LC32!"SEHandlerTable",
	LC32!"SEHandlerCount",
	LC32!"GuardCFCheckFunctionPointer",
	LC32!"GuardCFDispatchFunctionPointer",
	LC32!"GuardCFFunctionTable",
	LC32!"GuardCFFunctionCount",
	LC32!"GuardFlags",
	LC32!"CodeIntegrity",
	LC32!"GuardAddressTakenIatEntryTable",
	LC32!"GuardAddressTakenIatEntryCount",
	LC32!"GuardLongJumpTargetTable",
	LC32!"GuardLongJumpTargetCount",
	LC32!"DynamicValueRelocTable",
	LC32!"CHPEMetadataPointer",
	LC32!"GuardRFFailureRoutine",
	LC32!"GuardRFFailureRoutineFunctionPointer",
	LC32!"DynamicValueRelocTableOffset",
	LC32!"DynamicValueRelocTableSection",
	LC32!"Reserved2",
	LC32!"GuardRFVerifyStackPointerFunctionPointer",
	LC32!"HotPatchTableOffset",
	LC32!"Reserved3",
	LC32!"EnclaveConfigurationPointer",
	LC32!"VolatileMetadataPointer",
	LC32!"GuardEHContinuationTable",
	LC32!"GuardEHContinuationCount",
	LC32!"GuardXFGCheckFunctionPointer",
	LC32!"GuardXFGDispatchFunctionPointer",
	LC32!"GuardXFGTableDispatchFunctionPointer",
	LC32!"CastGuardOsDeterminedFailureMode",
	LC32!"GuardMemcpyFunctionPointer",
];
template LC64(string f) {
	enum LC64 = mixin("fieldt(pe_loadconfig64_t."~f~".stringof,"~
		"pe_loadconfig64_t."~f~".offsetof,"~
		"pe_loadconfig64_t."~f~".sizeof)");
}
static immutable fieldt[] lc64 = [
	LC64!"Size",
	LC64!"TimeDateStamp",
	LC64!"MajorVersion",
	LC64!"MinorVersion",
	LC64!"GlobalFlagsClear",
	LC64!"GlobalFlagsSet",
	LC64!"CriticalSectionDefaultTimeout",
	LC64!"DeCommitFreeBlockThreshold",
	LC64!"DeCommitTotalBlockThreshold",
	LC64!"LockPrefixTable",
	LC64!"MaximumAllocationSize",
	LC64!"VirtualMemoryThreshold",
	LC64!"ProcessAffinityMask",
	LC64!"ProcessHeapFlags",
	LC64!"CSDVersion",
	LC64!"Reserved1",
	LC64!"EditList",
	LC64!"SecurityCookie",
	LC64!"SEHandlerTable",
	LC64!"SEHandlerCount",
	LC64!"GuardCFCheckFunctionPointer",
	LC64!"GuardCFDispatchFunctionPointer",
	LC64!"GuardCFFunctionTable",
	LC64!"GuardCFFunctionCount",
	LC64!"GuardFlags",
	LC64!"CodeIntegrity",
	LC64!"GuardAddressTakenIatEntryTable",
	LC64!"GuardAddressTakenIatEntryCount",
	LC64!"GuardLongJumpTargetTable",
	LC64!"GuardLongJumpTargetCount",
	LC64!"DynamicValueRelocTable",
	LC64!"CHPEMetadataPointer",
	LC64!"GuardRFFailureRoutine",
	LC64!"GuardRFFailureRoutineFunctionPointer",
	LC64!"DynamicValueRelocTableOffset",
	LC64!"DynamicValueRelocTableSection",
	LC64!"Reserved2",
	LC64!"GuardRFVerifyStackPointerFunctionPointer",
	LC64!"HotPatchTableOffset",
	LC64!"Reserved3",
	LC64!"EnclaveConfigurationPointer",
	LC64!"VolatileMetadataPointer",
	LC64!"GuardEHContinuationTable",
	LC64!"GuardEHContinuationCount",
	LC64!"GuardXFGCheckFunctionPointer",
	LC64!"GuardXFGDispatchFunctionPointer",
	LC64!"GuardXFGTableDispatchFunctionPointer",
	LC64!"CastGuardOsDeterminedFailureMode",
	LC64!"GuardMemcpyFunctionPointer",
];
int print_loadconfig_field(void *base, ref immutable(fieldt) field) {
	assert(base);
	uint *Size = cast(uint*)base; // first field is Size (of loadconfig struct)
	if (field.foffset + field.fsize > *Size) return 0;
	
	const(char) *name = cast(const(char)*)field.name.ptr;
	void *data = base + field.foffset;
	switch (field.fsize) {
	case ushort.sizeof:
		print_x16(name, *cast(ushort*)data);
		break;
	case uint.sizeof:
		print_x32(name, *cast(uint*)data);
		break;
	case ulong.sizeof:
		print_x64(name, *cast(ulong*)data);
		break;
	default:
		print_datainline(name, data, pe_load_config_code_integrity_t.sizeof);
	}
	return 1;
}

void dump_pe_loadconfig(adbg_object_t *o) {
	print_header("Load Configuration");
	
	void *lc = adbg_object_pe_loadconfig(o);
	if (lc == null) {
		debug print_warningf("%s", adbg_error_message());
		return;
	}
	
	pe_optional_header_t *opt = cast(pe_optional_header_t*)adbg_object_pe_optional_header(o);
	switch (opt.Magic) {
	case PE_CLASS_32:
		foreach (ref immutable(fieldt) field; lc32) {
			if (print_loadconfig_field(lc, field) == 0)
				break;
		}
		break;
	case PE_CLASS_64:
		foreach (ref immutable(fieldt) field; lc64) {
			if (print_loadconfig_field(lc, field) == 0)
				break;
		}
		break;
	default:
	}
}

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
	
	pe_export_entry_t *entry = void;
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
				goto Lpdb20;
			case PE_IMAGE_DEBUG_MAGIC_CODEVIEW_PDB20PLUS: // PDB 2.0+
				sigstr = "PDB 2.0+ / NB10";
				goto Lpdb20;
			case PE_IMAGE_DEBUG_MAGIC_CODEVIEW_CV500: // PDB 2.0+ / CodeView 5.0
				if (debug_.SizeOfData < pe_debug_data_codeview_pdb20_t.sizeof) {
					print_warningf("Size too small for pe_debug_data_codeview_pdb20_t (%u v. %u)",
						debug_.SizeOfData, cast(uint)pe_debug_data_codeview_pdb20_t.sizeof);
					continue;
				}
				sigstr = "PDB 2.0+ / CodeView 5.0";
			Lpdb20:
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
		with (section) dump_disassemble_object(o, Name.ptr, Name.sizeof, buffer, SizeOfRawData, section.PointerToRawData);
		free(buffer);
	}
}