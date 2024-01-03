/// OS/2 / Windows 9x LX file dumper
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module dump.lx;

import adbg.v2.disassembler.core;
import adbg.v2.object.server;
import adbg.v2.object.machines : AdbgMachine;
import adbg.v2.object.format.lx;
import dumper;

extern (C):

int dump_lx(ref Dumper dump, adbg_object_t *o) {
	if (dump.selected_headers())
		dump_lx_hdr(dump, o);
	return 0;
}

private:

union lxmagic {
	ushort raw;
	char[4] str;
}

void dump_lx_hdr(ref Dumper dump, adbg_object_t *o) {
	print_header("Header");
	
	with (o.i.lx.header) {
	char[4] mstr = void;
	*cast(ushort*)mstr.ptr = Magic;
	mstr[2] = mstr[3] = 0;
	print_x16("Magic", Magic, mstr.ptr);
	print_x8("ByteOrder", ByteOrder);
	print_x8("WordOrder", WordOrder);
	print_x32("FormatLevel", FormatLevel);
	print_x32("CPUType", CPUType, adbg_object_lx_cputype_string(CPUType));
	print_x32("OSType", OSType, adbg_object_lx_ostype_string(OSType));
	print_x32("Version", Version);
	print_flags32("Flags", Flags,
		"PROCLIBINIT".ptr, LX_FLAG_PROCLIBINIT,
		"INTFIXUPS".ptr, LX_FLAG_INTFIXUPS,
		"EXTFIXUPS".ptr, LX_FLAG_EXTFIXUPS,
		"INCOMPATPMWIN".ptr, LX_FLAG_INCOMPATPMWIN,
		"COMPATPMWIN".ptr, LX_FLAG_COMPATPMWIN,
		"USESPMWIN".ptr, LX_FLAG_USESPMWIN,
		"MODUNLOADABLE".ptr, LX_FLAG_MODUNLOADABLE,
		"PROCLIBTERM".ptr, LX_FLAG_PROCLIBTERM,
		null);
	print_x32("ModuleType", Flags, adbg_object_lx_modtype_string(Flags));
	print_u32("Pages", Pages);
	print_x32("EIPObject", EIPObject);
	print_x32("EIP", EIP);
	print_x32("ESP", ESP);
	print_u32("PageSize", PageSize);
	print_x32("PageOffset", PageOffset);
	print_u32("FixupSectionSize", FixupSectionSize);
	print_x32("FixupSectionChecksum", FixupSectionChecksum);
	print_u32("LoaderSectionSize", LoaderSectionSize);
	print_x32("LoaderSectionChecksum", LoaderSectionChecksum);
	print_x32("ObjectTableOffset", ObjectTableOffset);
	print_x32("ObjectTableCount", ObjectTableCount);
	print_x32("ObjectPageTableOffset", ObjectPageTableOffset);
	print_x32("ObjectIteratedPagesOffset", ObjectIteratedPagesOffset);
	print_x32("ResourceTableOffset", ResourceTableOffset);
	print_x32("ResourceTableCount", ResourceTableCount);
	print_x32("ResidentNameTableOffset", ResidentNameTableOffset);
	print_x32("EntryTableOffset", EntryTableOffset);
	print_x32("ModuleDirectivesOffset", ModuleDirectivesOffset);
	print_x32("ModuleDirectivesCount", ModuleDirectivesCount);
	print_x32("FixupPageTableOffset", FixupPageTableOffset);
	print_x32("FixupRecordTableOffset", FixupRecordTableOffset);
	print_x32("ImportModuleTableOffset", ImportModuleTableOffset);
	print_x32("ImportModuleTableCount", ImportModuleTableCount);
	print_x32("ImportProcTableOffset", ImportProcTableOffset);
	print_x32("PageChecksumOffset", PageChecksumOffset);
	print_x32("DataPagesOffset", DataPagesOffset);
	print_x32("PreloadPageCount", PreloadPageCount);
	print_x32("NonResNameTableOffset", NonResNameTableOffset);
	print_u32("NonResNameTableSize", NonResNameTableSize);
	print_x32("NonResNameTableChecksum", NonResNameTableChecksum);
	print_x32("AutoDSObjectNumber", AutoDSObjectNumber);
	print_x32("DebugInfoOffset", DebugInfoOffset);
	print_u32("DebugInfoSize", DebugInfoSize);
	print_x32("InstancePageCount", InstancePageCount);
	print_x32("InstanceDemandCount", InstanceDemandCount);
	print_u32("HeapSize", HeapSize);
	}
}