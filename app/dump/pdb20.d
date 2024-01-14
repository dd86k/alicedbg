/// PDB 2.00 dumper
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module dump.pdb20;

import adbg.v2.disassembler.core;
import adbg.v2.object.server;
import adbg.v2.object.machines;
import adbg.v2.object.format.pdb;
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
	}
}