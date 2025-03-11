/// Library archive dumper
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module format_ar;

import adbg.disassembler;
import adbg.objectserver;
import adbg.machines;
import adbg.objects.ar;
import adbg.error;
import adbg.utils.bit : adbg_bswap32;
import core.stdc.ctype : isdigit;
import dumper;
import common.utils : realstring;
import common.errormgmt;

extern (C):

int dump_archive(adbg_object_t *o) {
	if (SELECTED(Select.headers))
		dump_archive_firstheader(o);
	if (SELECTED(Select.debug_))
		dump_archive_allheaders(o);
	if (SELECTED(Select.exports))
		dump_archive_symbols(o);
	return 0;
}

private:

void dump_archive_header(ar_member_header_t *member) {
	with (member) {
	print_stringl("Name", Name.ptr, Name.sizeof);
	print_stringl("Date", Date.ptr, Date.sizeof);
	print_stringl("UserID", UserID.ptr, UserID.sizeof);
	print_stringl("GroupID", GroupID.ptr, GroupID.sizeof);
	print_stringl("Mode", Mode.ptr, Mode.sizeof);
	print_stringl("Size", Size.ptr, Size.sizeof);
	// NOTE: Printing the end marker is pretty pointless
	}
}

// First header only
void dump_archive_firstheader(adbg_object_t *o) {
	print_header("Header");
	
	ar_member_header_t *member = adbg_object_ar_first_member(o);
	if (member == null)
		panic_adbg();
	dump_archive_header(member);
}

void dump_archive_memberdata(adbg_object_t *o, ar_member_header_t *member) {
	if (SETTING(Setting.extractAny) == false)
		return;
	
	ar_member_data_t *m = adbg_object_ar_member_data(o, member);
	if (m == null)
		panic_adbg();
	print_data("data", m.pointer, m.size);
	adbg_object_ar_member_data_close(m);
}

void dump_archive_allheaders(adbg_object_t *o) {
	print_header("Debug data");
	
	ar_member_header_t *member = adbg_object_ar_first_member(o);
	if (member == null)
		panic_adbg();
	
	uint i;
	do {
		print_section(i++);
		dump_archive_header(member);
		dump_archive_memberdata(o, member);
	} while ((member = adbg_object_ar_next_member(o)) != null);
}

void dump_archive_symbols(adbg_object_t *o) {
	print_header("Symbols");
	
	ar_member_header_t *member = adbg_object_ar_first_member(o);
	if (member == null)
		panic_adbg();
	
	uint i;
	do {
		// HACK: Ignore special members, doing it here saves some filtering headaches
		//       This should include "/", "//", "/EXAMPLE/", "__.SYMDEF" stuff
		//       And exclude "/70" (long name member entry)
		// TODO: Check by Archive kind instead, or member kind
		if (member.Name[0] == '/' && isdigit( member.Name[1] ) == 0) {
			i++;
			continue;
		}
		
		// Resolve long-name
		char[120] namebuf = void;
		if (adbg_object_ar_member_name(namebuf.ptr, namebuf.sizeof, o, member) < 0) {
			print_warningf("Member index #%d name issue: %s", i++, adbg_error_message());
			continue;
		}
		
		/*
		// Get member object data buffer
		ar_member_data_t *memdat = adbg_object_ar_member_data(o, member);
		if (memdat == null) {
			print_warningf("Member index #%d data issue: %s", i++, adbg_error_message());
			continue;
		}
		scope(exit) adbg_object_ar_member_data_close(memdat); // closed later
		
		// Open it, it could be COFF, ELF, anything as a relocatable object
		adbg_object_t *obj = adbg_object_open_buffer(memdat.pointer, memdat.size, 0);
		if (memdat == null) {
			print_warningf("Member index #%d object issue: %s", i++, adbg_error_message());
			continue;
		}
		scope(exit) adbg_object_close(obj); // closed first
		*/
		
		print_section(i++, namebuf.ptr);
	} while ((member = adbg_object_ar_next_member(o)) != null);
}
