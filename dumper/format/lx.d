/// OS/2 / Windows 9x LX file dumper
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module format.lx;

import adbg.disassembler;
import adbg.objectserver;
import adbg.machines : AdbgMachine;
import adbg.objects.lx;
import dumper;

extern (C):

int dump_lx(adbg_object_t *o) {
	if (SELECTED(Select.headers))
		dump_lx_hdr(o);
	return 0;
}

private:

void dump_lx_hdr(adbg_object_t *o) {
	print_header("Header");
	
	lx_header_t* header = adbg_object_lx_header(o);
	
	with (header) {
	print_x16("e32_magic", magic, magic == LE_MAGIC ? "LE" : "LX");
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
		"MPUNSAFE".ptr, LX_FLAG_MPUNSAFE,
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
	print_x8("e32_res[0]", res1[0]);
	print_x8("e32_res[1]", res1[1]);
	print_x8("e32_res[2]", res1[2]);
	print_x8("e32_res[3]", res1[3]);
	print_x8("e32_res[4]", res1[4]);
	print_x8("e32_res[5]", res1[5]);
	print_x8("e32_res[6]", res1[6]);
	print_x8("e32_res[7]", res1[7]);
	if (magic == LE_MAGIC) {
		print_x32("winresoff", winresoff);
		print_u32("winreslen", winreslen);
		print_x16("device_id", device_id);
		print_x16("ddk_version", ddk_version);
		return;
	}
	print_x8("e32_res[8]",  res[8]);
	print_x8("e32_res[9]",  res[9]);
	print_x8("e32_res[10]", res[10]);
	print_x8("e32_res[11]", res[11]);
	print_x8("e32_res[12]", res[12]);
	print_x8("e32_res[13]", res[13]);
	print_x8("e32_res[14]", res[14]);
	print_x8("e32_res[15]", res[15]);
	print_x8("e32_res[16]", res[16]);
	print_x8("e32_res[17]", res[17]);
	print_x8("e32_res[18]", res[18]);
	print_x8("e32_res[19]", res[19]);
	}
}