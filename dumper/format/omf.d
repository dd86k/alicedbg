/// OMF dumper.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module format.omf;

import adbg.object.server;
import adbg.object.format.omf;
import dumper;
import common.errormgmt;

extern (C):

int dump_omf(adbg_object_t *o) {
	if (SELECTED(Select.headers))
		dump_omf_header(o);
	if (SELECTED(Select.debug_))
		dump_omf_debug(o);
	return 0;
}

private:

void dump_omf_header(adbg_object_t *o) {
	print_header("Library Header");
	
	omf_lib_header_t *libheader = adbg_object_omf_library_header(o);
	
	if (libheader == null) {
		print_warningf("Not a library, so no header");
		return;
	}
	
	with (libheader) {
	print_x8("Type", type);
	print_u16("RecordLength", size);
	print_x32("DictionaryOffset", dicoff);
	print_u16("DictionarySize", dicsize);
	print_flags8("Flags", flags,
		"CaseSensitive".ptr, OMF_LF_CS,
		null);
	}
	
	/*
	print_header("First Object Entry");
	omf_entry* entry = adbg_object_omf_entry(o, 0);
	dump_omf_print_entry(entry);
	adbg_object_omf_entry_close(o, entry);
	*/
}

void dump_omf_debug(adbg_object_t *o) {
	omf_entry_t *entry = adbg_object_omf_entry_first(o);
	if (entry == null)
		panic_adbg();
	
	do {
		dump_omf_print_entry(entry);
		adbg_object_omf_entry_close(entry);
	} while ((entry = adbg_object_omf_entry_next(o)) != null);
}

// print entry
int dump_omf_print_entry(omf_entry_t *entry) {
	__gshared uint i;
	print_section(i++);
	print_x8("Type", entry.type, adbg_object_omf_type_string(entry));
	print_u16("Size", entry.size);
	print_x8("Checksum", entry.checksum);
	switch (entry.type) with (OMFRecord) {
	case THEADR, LHEADR:
		int len = (cast(ubyte*)entry.data)[0]; // string size
		if (len >= entry.size)
			panic(3, "String length outside bounds");
		const(char)* str = cast(const(char)*)entry.data + 1;
		print_stringl("Name", str, len);
		break;
	default:
	}
	return 0;
}
