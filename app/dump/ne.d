/// Windows 1.x NE file dumper
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module dump.ne;

import adbg.disassembler;
import adbg.object.server;
import adbg.machines : AdbgMachine;
import adbg.object.format.ne;
import dumper;

extern (C):

int dump_ne(ref Dumper dump, adbg_object_t *o) {
	if (dump.selected_headers())
		dump_ne_hdr(dump, o);
	return 0;
}

private:

void dump_ne_hdr(ref Dumper dump, adbg_object_t *o) {
	print_header("Header");
	
	with (o.i.ne.header) {
	print_x16("ne_magic", ne_magic);
	print_u8("ne_ver", ne_ver);
	print_u8("ne_rev", ne_rev);
	print_x16("ne_enttab", ne_enttab);
	print_u16("ne_cbenttab", ne_cbenttab);
	print_x32("ne_crc", ne_crc);
	print_flags16("ne_flags", ne_flags,
		"SINGLEDATA".ptr, NE_HFLAG_SINGLEDATA,
		"MULTIPLEDATA".ptr, NE_HFLAG_MULTIPLEDATA,
		"LINKERERROR".ptr, NE_HFLAG_LINKERERROR,
		"LIBMODULE".ptr, NE_HFLAG_LIBMODULE,
		null);
	print_u16("ne_autodata", ne_autodata);
	print_u16("ne_heap", ne_heap);
	print_u16("ne_stack", ne_stack);
	print_x32("ne_csip", ne_csip);
	print_x32("ne_sssp", ne_sssp);
	print_u16("ne_cseg", ne_cseg);
	print_u16("ne_cmod", ne_cmod);
	print_u16("ne_cbnrestab", ne_cbnrestab);
	print_x16("ne_segtab", ne_segtab);
	print_x16("ne_rsrctab", ne_rsrctab);
	print_x16("ne_restab", ne_restab);
	print_x16("ne_modtab", ne_modtab);
	print_x16("ne_imptab", ne_imptab);
	print_x32("ne_nrestab", ne_nrestab);
	print_u16("ne_cmovent", ne_cmovent);
	print_u16("ne_align", ne_align);
	print_u16("ne_cres", ne_cres);
	print_u8("ne_exetyp", ne_exetyp, adbg_object_ne_type(ne_exetyp));
	print_x8("ne_flagsothers", ne_flagsothers);
	print_x16("ne_pretthunks", ne_pretthunks);
	print_x16("ne_psegrefbytes", ne_psegrefbytes);
	print_x16("ne_swaparea", ne_swaparea);
	print_x16("ne_expver", ne_expver);
	}
}