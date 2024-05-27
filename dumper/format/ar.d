/// Library archive dumper
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module format.ar;

import adbg.disassembler;
import adbg.object.server;
import adbg.machines;
import adbg.object.format.ar;
import adbg.error;
import adbg.utils.bit : adbg_bswap32;
import core.stdc.ctype : isdigit;
import dumper;
import common.utils : realstring;
import common.error;

extern (C):

int dump_archive(adbg_object_t *o) {
	if (SELECTED(Select.headers))
		dump_archive_firstheader(o);
	if (SELECTED(Select.exports))
		dump_archive_allheaders(o);
	return 0;
}

private:

void dump_archive_header(ar_member_header *member) {
	with (member) {
	print_stringl("Name", Name.ptr, Name.sizeof);
	print_stringl("Date", Date.ptr, Date.sizeof);
	print_stringl("UserID", UserID.ptr, UserID.sizeof);
	print_stringl("GroupID", GroupID.ptr, GroupID.sizeof);
	print_stringl("Mode", Mode.ptr, Mode.sizeof);
	print_stringl("Size", Size.ptr, Size.sizeof);
	
	char[10] b = void;
	int l = realstring(b.ptr, 10, End.ptr, 2);
	print_x16l("End", EndMarker, b.ptr, l);
	}
}

// First header only
void dump_archive_firstheader(adbg_object_t *o) {
	print_header("Header");
	
	ar_member_header *member = adbg_object_ar_first_header(o);
	if (member == null)
		panic_adbg();
	dump_archive_header(member);
}

void dump_archive_memberdata(adbg_object_t *o, ar_member_header *member) {
	if (SETTING(Setting.extractAny) == false)
		return;
	
	ar_member_data m = adbg_object_ar_data(o, member);
	if (m.data == null)
		panic_adbg();
	print_data("data", m.data, m.size);
}

void dump_archive_allheaders(adbg_object_t *o) {
	print_header("Debug data");

	ar_member_header *member = adbg_object_ar_first_header(o);
	if (member == null)
		panic_adbg();

	uint i;
	do {
		print_section(i++);
		dump_archive_header(member);
		dump_archive_memberdata(o, member);
		adbg_object_ar_free(o, member);
	} while ((member = adbg_object_ar_next_header(o)) != null);
}