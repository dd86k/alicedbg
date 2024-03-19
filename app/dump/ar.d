/// Library archive dumper
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module dump.ar;

import adbg.disassembler;
import adbg.object.server;
import adbg.object.machines;
import adbg.object.format.ar;
import adbg.utils.bit : adbg_bswap32;
import core.stdc.ctype : isdigit;
import dumper;
import utils : realstring;

extern (C):

int dump_archive(ref Dumper dump, adbg_object_t *o) {
	if (dump.selected_headers())
		dump_archive_headers(dump, o);
	
	return 0;
}

private:

void dump_archive_headers(ref Dumper dump, adbg_object_t *o) {
	print_header("Header");
	
	ar_member_header *rhdr = void; // Root headers
	for (size_t i; (rhdr = adbg_object_ar_header(o, i)) != null; ++i) {
		print_section(cast(uint)i);
		print_stringl("Name", rhdr.Name.ptr, rhdr.Name.sizeof);
		print_stringl("Date", rhdr.Date.ptr, rhdr.Date.sizeof);
		print_stringl("UserID", rhdr.UserID.ptr, rhdr.UserID.sizeof);
		print_stringl("GroupID", rhdr.GroupID.ptr, rhdr.GroupID.sizeof);
		print_stringl("Mode", rhdr.Mode.ptr, rhdr.Mode.sizeof);
		print_stringl("Size", rhdr.Size.ptr, rhdr.Size.sizeof);
		
		char[10] b = void;
		int l = realstring(b.ptr, 10, rhdr.End.ptr, 2);
		print_x16l("End", rhdr.EndMarker, b.ptr, l);
		
		/+void *data = adbg_object_ar_data(o, rhdr);
		if (data == null) {
			print_string("warning", "Could not get data pointer");
			continue;
		}
		
		int size = adbg_object_ar_header_size(o, rhdr);
		if (size <= 0) {
			print_string("warning", "Could not get size of data");
			continue;
		}
		
		import core.stdc.stdio : printf;
		
		int symcnt   = *cast(int*)data;
		int *symoffs = cast(int*)data + 1;
		for (int isym; isym < symcnt; ++isym) {
			int off = adbg_bswap32(symoffs[isym]);
			
			ar_member_header *table = void;
			if (adbg_object_offset(o, cast(void**)&table, off)) {
				print_string("warning", "aaaaaaaaaaa cringe");
				printf("there was %d headers\n", isym);
				return;
			}
			
			print_stringl("Name", table.Name.ptr, table.Name.sizeof);
			print_stringl("Date", table.Date.ptr, table.Date.sizeof);
			print_stringl("UserID", table.UserID.ptr, table.UserID.sizeof);
			print_stringl("GroupID", table.GroupID.ptr, table.GroupID.sizeof);
			print_stringl("Mode", table.Mode.ptr, table.Mode.sizeof);
			print_stringl("Size", table.Size.ptr, table.Size.sizeof);
			l = realstring(b.ptr, 10, table.End.ptr, 2, '"', '"');
			print_x16l("End", table.EndMarker, b.ptr, l);
			
			if (table.Name[0] != '/' || isdigit(table.Name[1]) == 0)
				continue;
			
			
		}+/
	}
}