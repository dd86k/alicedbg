/// PDB 2.00 dumper
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module dump.pdb20;

import adbg.disassembler;
import adbg.object.server;
import adbg.object.machines;
import adbg.object.format.pdb;
import dumper;

extern (C):

int dump_pdb20(ref Dumper dump, adbg_object_t *o) {
	if (dump.selected_headers())
		dump_pdb20_header(dump, o);
	
	return 0;
}

private:

void dump_pdb20_header(ref Dumper dump, adbg_object_t *o) {
	print_header("Header");
	
	pdb20_file_header *header = adbg_object_pdb20_header(o);
	
	with (header) {
	print_stringl("Magic", header.Magic.ptr, 37);
	print_x32("PageSize", PageSize);
	print_x16("StartPage", StartPage);
	print_x16("PageCount", PageCount);
	print_x32("RootSize", RootSize);
	print_x32("Reserved", Reserved);
	print_x16("RootNumber", RootNumber);
	}
}