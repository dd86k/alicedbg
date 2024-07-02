/// COFF dumper.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module format.coff;

import adbg.disassembler;
import adbg.object.server;
import adbg.machines;
import adbg.object.format.coff;
import adbg.object.format.pe : adbg_object_pe_machine_string;
import adbg.utils.bit : adbg_bswap32;
import adbg.utils.uid;
import core.stdc.ctype : isdigit;
import dumper;
import common.utils : realstring;

int dump_coff(adbg_object_t *o) {
	if (SELECTED(Select.headers))
		dump_coff_hdr(o);
	
	return 0;
}

private:

void dump_coff_hdr(adbg_object_t *o) {
	print_header("Header");
	
	coff_header_t *header = adbg_object_coff_header(o);
	
	with (header) {
	print_x16("f_magic", f_magic, adbg_object_coff_magic_string(f_magic));
	print_u16("f_nscns", f_nscns);
	print_u32("f_timedat", f_timedat);
	print_u32("f_symptr", f_symptr);
	print_u32("f_nsyms", f_nsyms);
	print_u16("f_opthdr", f_opthdr);
	print_flags16("f_flags", f_flags,
		"RELFLG".ptr, COFF_F_RELFLG,
		"EXEC".ptr, COFF_F_EXEC,
		"LNNO".ptr, COFF_F_LNNO,
		"LSYMS".ptr, COFF_F_LSYMS,
		"LSB".ptr, COFF_F_LSB,
		"MSB".ptr, COFF_F_MSB,
		null);
	}
}
