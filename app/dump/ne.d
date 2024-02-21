/// Windows 1.x NE file dumper
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module dump.ne;

import adbg.disassembler;
import adbg.object.server;
import adbg.object.machines : AdbgMachine;
import adbg.object.format.ne;
import dumper;

extern (C):

int dump_ne(ref Dumper dump, adbg_object_t *o) {
	if (dump.selected_headers())
		dump_ne_hdr(dump, o);
	return 0;
}

private:

void dump_ne_hdr(ref Dumper dump, adbg_object_t *o) {
	print_header("Header");
	
	with (o.i.ne.header) {
	print_u8("LinkerVersion", LinkerVersion);
	print_u8("LinkerRevision", LinkerRevision);
	print_x16("EntryTableOffset", EntryTableOffset);
	print_u16("EntryTableSize", EntryTableSize);
	print_x32("Checksum", Checksum);
	print_flags16("Flags", Flags,
		"SINGLEDATA".ptr, NE_HFLAG_SINGLEDATA,
		"MULTIPLEDATA".ptr, NE_HFLAG_MULTIPLEDATA,
		"LINKERERROR".ptr, NE_HFLAG_LINKERERROR,
		"LIBMODULE".ptr, NE_HFLAG_LIBMODULE,
		null);
	print_u16("Segment", Segment);
	print_u16("HeapSize", HeapSize);
	print_u16("StackSize", StackSize);
	print_x32("CSIP", CSIP);
	print_x32("SSSP", SSSP);
	print_u16("SegmentCount", SegmentCount);
	print_u16("ModuleCount", ModuleCount);
	print_u16("NonResidentSize", NonResidentSize);
	print_x16("SegmentOffset", SegmentOffset);
	print_x16("ResourceOffset", ResourceOffset);
	print_x16("ResidentOffset", ResidentOffset);
	print_x16("ModuleOffset", ModuleOffset);
	print_x16("ImportedOffset", ImportedOffset);
	print_x32("NonResidentOffset", NonResidentOffset);
	print_u16("Movable", Movable);
	print_u16("SectorAlign", SectorAlign);
	print_u16("ResourceCount", ResourceCount);
	print_u8("Type", Type, adbg_object_ne_type(Type));
	print_x8("Reserved[0]", Reserved[0]);
	print_x8("Reserved[1]", Reserved[1]);
	print_x8("Reserved[2]", Reserved[2]);
	print_x8("Reserved[3]", Reserved[3]);
	print_x8("Reserved[4]", Reserved[4]);
	print_x8("Reserved[5]", Reserved[5]);
	print_x8("Reserved[6]", Reserved[6]);
	print_x8("Reserved[7]", Reserved[7]);
	}
}