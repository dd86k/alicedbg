/// MS-COFF dumper
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module dump.mscoff;

import adbg.disassembler;
import adbg.object.server;
import adbg.object.machines;
import adbg.object.format.mscoff;
import adbg.object.format.pe : adbg_object_pe_machine_string;
import adbg.utils.bit : adbg_bswap32;
import adbg.utils.uid;
import core.stdc.ctype : isdigit;
import dumper;
import utils : realstring;

int dump_mscoff(ref Dumper dump, adbg_object_t *o) {
	if (dump.selected_headers())
		dump_mscoff_hdr(dump, o);
	
	return 0;
}

private:

void dump_mscoff_hdr(ref Dumper dump, adbg_object_t *o) {
	switch (o.i.mscoff.import_header.Version) {
	case MSCOFF_VERSION_IMPORT: // 0
		with (o.i.mscoff.import_header) {
		print_x16("Sig1", Sig1);
		print_x16("Sig2", Sig2);
		print_u16("Version", Version);
		print_x16("Machine", Machine, adbg_object_pe_machine_string(Machine));
		print_x32("TimeStamp", TimeStamp);
		print_x32("Size", Size);
		print_x16("Ordinal", Ordinal);
		print_x64("Flags", Flags);
		}
		break;
	case MSCOFF_VERSION_ANON: // 1
		with (o.i.mscoff.anon_header) {
		print_x16("Sig1", Sig1);
		print_x16("Sig2", Sig2);
		print_u16("Version", Version);
		print_x16("Machine", Machine, adbg_object_pe_machine_string(Machine));
		print_x32("TimeDateStamp", TimeDateStamp);
		char[UID_TEXTLEN] uid = void;
		uid_text(ClassID, uid, UID_GUID);
		print_string("ClassID", uid.ptr);
		print_x32("SizeOfData", SizeOfData);
		}
		break;
	case MSCOFF_VERSION_ANONV2: // 2
		with (o.i.mscoff.anon_v2_header) {
		print_x16("Sig1", Sig1);
		print_x16("Sig2", Sig2);
		print_u16("Version", Version);
		print_x16("Machine", Machine, adbg_object_pe_machine_string(Machine));
		print_x32("TimeDateStamp", TimeDateStamp);
		char[UID_TEXTLEN] uid = void;
		uid_text(ClassID, uid, UID_GUID);
		print_string("ClassID", uid.ptr);
		print_x32("SizeOfData", SizeOfData);
		print_x32("Flags", Flags);
		print_x32("MetaDataSize", MetaDataSize);
		}
		break;
	default:
	}
}