/// Windows 1.x NE file dumper
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module format.ne;

import adbg.disassembler;
import adbg.objectserver;
import adbg.machines : AdbgMachine;
import adbg.objects.ne;
import dumper;

extern (C):

int dump_ne(adbg_object_t *o) {
	if (SELECTED(Select.headers))
		dump_ne_hdr(o);
	return 0;
}

private:

void dump_ne_hdr(adbg_object_t *o) {
	print_header("Header");
	
	ne_header_t* header = adbg_object_ne_header(o);
	
	with (header) {
	print_x16("ne_magic", ne_magic);
	print_u8("ne_ver", ne_ver);
	print_u8("ne_rev", ne_rev);
	print_x16("ne_enttab", ne_enttab);
	print_u16("ne_cbenttab", ne_cbenttab);
	print_x32("ne_crc", ne_crc);
	print_flags16("ne_flags", ne_flags,
		"GLOBALINIT".ptr, NE_HFLAG_GLOBALINIT,
		"PROTECTED".ptr, NE_HFLAG_PROTECTED,
		"INT8086".ptr, NE_HFLAG_INT8086,
		"INTI286".ptr, NE_HFLAG_INTI286,
		"INTI386".ptr, NE_HFLAG_INTI386,
		"INTX87".ptr, NE_HFLAG_INTX87,
		"OS2".ptr, NE_HFLAG_OS2,
		"LINKERERROR".ptr, NE_HFLAG_LINKERERROR,
		"LIBMODULE".ptr, NE_HFLAG_LIBMODULE,
		null);
	ushort dgroup = ne_flags & NE_HFLAG_DGROUP_MASK;
	switch (dgroup) {
	case NE_HFLAG_DGROUP_SINGLEDATA:
		print_x16("ne_flags:dgroup", dgroup, "SINGLEDATA");
		break;
	case NE_HFLAG_DGROUP_MULTIPLEDATA:
		print_x16("ne_flags:dgroup", dgroup, "MULTIPLEDATA");
		break;
	default:
	}
	ushort app = ne_flags & NE_HFLAG_APP_MASK;
	switch (app) {
	case NE_HFLAG_APP_FULLSCREEN:
		print_x16("ne_flags:app", app, "FULLSCREEN");
		break;
	case NE_HFLAG_APP_COMPATPM:
		print_x16("ne_flags:app", app, "COMPATPM");
		break;
	case NE_HFLAG_APP_USINGPM:
		print_x16("ne_flags:app", app, "USINGPM");
		break;
	default:
	}
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