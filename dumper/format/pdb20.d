/// PDB 2.00 dumper
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module format.pdb20;

import adbg.disassembler;
import adbg.objectserver;
import adbg.machines;
import adbg.objects.pdb;
import dumper;

extern (C):

int dump_pdb20(adbg_object_t *o) {
	if (SELECTED(Select.headers))
		dump_pdb20_header(o);
	
	return 0;
}

private:

void dump_pdb20_header(adbg_object_t *o) {
	print_header("Header");
	
	pdb20_file_header_t *header = adbg_object_pdb20_header(o);
	
	with (header) {
	print_stringl("Magic", header.Magic.ptr, 37);
	print_u32("BlockSize", BlockSize);
	print_u16("StartPage", StartPage);
	print_u16("BlockCount", BlockCount);
	print_u32("RootSize", RootSize);
	print_x32("Reserved", Reserved);
	print_u16("RootNumber", RootNumber);
	}
}