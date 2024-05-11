/// OMF dumper.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module format.omf;

import adbg.object.server;
import adbg.object.format.omf;
import dumper;

extern (C):

int dump_omf(adbg_object_t *o) {
	if (SELECTED(Select.headers))
		dump_omf_hdr(o);
	if (SELECTED(Select.debug_))
		dump_omf_debug(o);
	return 0;
}

private:

void dump_omf_hdr(adbg_object_t *o) {
	// Library
	if (o.i.omf.firstentry) {
		print_header("Library Header");
		with (o.i.omf.header) {
		print_x8("Type", type);
		print_u16("RecordLength", size);
		print_x32("DictionaryOffset", dicoff);
		print_u16("DictionarySize", dicsize);
		print_flags8("Flags", flags,
			"CaseSensitive".ptr, OMF_LF_CS,
			null);
		}
	}
	
	print_header("First Object Entry");
	omf_entry* entry = adbg_object_omf_entry(o, 0);
	dump_omf_print_entry(entry);
	adbg_object_omf_entry_free(o, entry);
}

void dump_omf_debug(adbg_object_t *o) {
	int offset = o.i.omf.firstentry;
	
Lentry:
	omf_entry* entry = adbg_object_omf_entry(o, offset);
	if (entry == null)
		return;
	
	print_header("Entry");
	if (dump_omf_print_entry(entry)) // print entry
		return;
	offset += entry.size + 3; // advance
	adbg_object_omf_entry_free(o, entry); // free
	goto Lentry;
}

// print entry
int dump_omf_print_entry(omf_entry *entry) {
	print_x8("Type", entry.type, adbg_object_omf_type_string(entry));
	print_u16("Size", entry.size);
	print_x8("Checksum", entry.checksum);
	switch (entry.type) with (OMFRecord) {
	case THEADR, LHEADR:
		ubyte len = (cast(ubyte*)entry.data)[0];
		if (len >= entry.size) {
			print_string("error", "String length outside bounds");
			return 1;
		}
		const(char)* str = cast(const(char)*)entry.data + 1;
		print_stringl("Name", str, len);
		break;
	default:
	}
	return 0;
}