/// OS/2 / Windows 9x LX file dumper
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module dump.lx;

import adbg.v2.disassembler.core;
import adbg.v2.object.server;
import adbg.v2.object.machines : AdbgMachine;
import adbg.v2.object.format.lx;
import dumper;

extern (C):

int dump_lx(ref Dumper dump, adbg_object_t *o) {
	if (dump.selected_headers())
		dump_lx_hdr(dump, o);
	return 0;
}

private:

union lxmagic {
	ushort raw;
	char[4] str;
}

void dump_lx_hdr(ref Dumper dump, adbg_object_t *o) {
	print_header("Header");
	
	with (o.i.lx.header) {
	char[4] mstr = void;
	*cast(ushort*)mstr.ptr = magic;
	mstr[2] = mstr[3] = 0;
	print_x16("e32_magic", magic, mstr.ptr);
	print_x8("e32_border", border);
	print_x8("e32_worder", worder);
	print_x32("e32_level", level);
	print_u16("e32_cpu", cpu, adbg_object_lx_cputype_string(cpu));
	print_u16("e32_os", os, adbg_object_lx_ostype_string(os));
	print_x32("e32_ver", ver);
	print_flags32("e32_mflags", mflags,
		"PROCLIBINIT".ptr, LX_FLAG_PROCLIBINIT,
		"INTFIXUPS".ptr, LX_FLAG_INTFIXUPS,
		"EXTFIXUPS".ptr, LX_FLAG_EXTFIXUPS,
		"INCOMPATPMWIN".ptr, LX_FLAG_INCOMPATPMWIN,
		"COMPATPMWIN".ptr, LX_FLAG_COMPATPMWIN,
		"USESPMWIN".ptr, LX_FLAG_USESPMWIN,
		"MODUNLOADABLE".ptr, LX_FLAG_MODUNLOADABLE,
		"PROCLIBTERM".ptr, LX_FLAG_PROCLIBTERM,
		null);
	print_x32("e32_mflags:ModuleType", mflags, adbg_object_lx_modtype_string(mflags));
	print_u32("e32_mpages", mpages);
	print_x32("e32_startobj", startobj);
	print_x32("e32_eip", eip);
	print_x32("e32_stackobj", stackobj);
	print_x32("e32_esp", esp);
	print_u32("e32_pagesize", pagesize);
	print_x32("e32_pageshift", pageshift);
	print_u32("e32_fixupsize", fixupsize);
	print_x32("e32_fixupsum", fixupsum);
	print_u32("e32_ldrsize", ldrsize);
	print_x32("e32_ldrsum", ldrsum);
	print_x32("e32_objtab", objtab);
	print_x32("e32_objcnt", objcnt);
	print_x32("e32_objmap", objmap);
	print_x32("e32_itermap", itermap);
	print_x32("e32_rsrctab", rsrctab);
	print_x32("e32_rsrccnt", rsrccnt);
	print_x32("e32_restab", restab);
	print_x32("e32_enttab", enttab);
	print_x32("e32_dirtab", dirtab);
	print_x32("e32_dircnt", dircnt);
	print_x32("e32_fpagetab", fpagetab);
	print_x32("e32_frectab", frectab);
	print_x32("e32_impmod", impmod);
	print_x32("e32_impmodcnt", impmodcnt);
	print_x32("e32_impproc", impproc);
	print_x32("e32_pagesum", pagesum);
	print_x32("e32_datapage", datapage);
	print_x32("e32_preload", preload);
	print_x32("e32_nrestab", nrestab);
	print_u32("e32_cbnrestab", cbnrestab);
	print_x32("e32_nressum", nressum);
	print_x32("e32_autodata", autodata);
	print_x32("e32_debuginfo", debuginfo);
	print_u32("e32_debuglen", debuglen);
	print_x32("e32_instpreload", instpreload);
	print_x32("e32_instdemand", instdemand);
	print_u32("e32_heapsize", heapsize);
	print_u32("e32_stacksize", stacksize);
	print_x8("e32_res3[0]", res3[0]);
	print_x8("e32_res3[1]", res3[1]);
	print_x8("e32_res3[2]", res3[2]);
	print_x8("e32_res3[3]", res3[3]);
	print_x8("e32_res3[4]", res3[4]);
	print_x8("e32_res3[5]", res3[5]);
	print_x8("e32_res3[6]", res3[6]);
	print_x8("e32_res3[7]", res3[7]);
	print_x8("e32_res3[8]", res3[8]);
	print_x8("e32_res3[9]", res3[9]);
	print_x8("e32_res3[10]", res3[10]);
	print_x8("e32_res3[11]", res3[11]);
	print_x8("e32_res3[12]", res3[12]);
	print_x8("e32_res3[13]", res3[13]);
	print_x8("e32_res3[14]", res3[14]);
	print_x8("e32_res3[15]", res3[15]);
	print_x8("e32_res3[16]", res3[16]);
	print_x8("e32_res3[17]", res3[17]);
	print_x8("e32_res3[18]", res3[18]);
	print_x8("e32_res3[19]", res3[19]);
	}
}