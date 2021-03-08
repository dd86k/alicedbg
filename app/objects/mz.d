/**
 * MS-DOS MZ file dumper
 *
 * License: BSD-3-Clause
 */
module objects.mz;

import core.stdc.stdio;
import adbg.obj.server;
import adbg.disasm.disasm : adbg_disasm_t, adbg_disasm, AdbgDisasmMode;
import adbg.obj.mz;
import dumper;

extern (C):

/// Print MZ info to stdout, a file_info_t structure must be loaded before
/// calling this function.
/// Params:
/// 	fi = File information
/// 	disasm_opts = Disassembler options
/// 	flags = DumpOpt flags
/// Returns: Non-zero on error
int dump_mz(adbg_object_t *obj, adbg_disasm_t *disasm_opts, int flags) {
	dump_title("MS-DOS MZ");
	
	if (flags & DumpOpt.header)
		dump_mz_hdr(obj);
	
	if (flags & DumpOpt.relocs)
		dump_mz_relocs(obj);
	
	if (flags & (DumpOpt.disasm | DumpOpt.disasm_all | DumpOpt.stats)) {
		int start = obj.mz.hdr.e_cparh * 16;
		int len = (obj.mz.hdr.e_cp * 16) - obj.mz.hdr.e_cblp;
		dump_disasm(disasm_opts, obj.buf + start, len, flags);
	}
	
	return 0;
}

private:

void dump_mz_hdr(adbg_object_t *obj) {
	dump_chapter("Header");
	printf(
	"e_cblp      %04Xh\n"~
	"e_cp        %04Xh\n"~
	"e_crlc      %04Xh\n"~
	"e_cparh     %04Xh\n"~
	"e_minalloc  %04Xh\n"~
	"e_maxalloc  %04Xh\n"~
	"e_ss        %04Xh\n"~
	"e_sp        %04Xh\n"~
	"e_csum      %04Xh\n"~
	"e_ip        %04Xh\n"~
	"e_cs        %04Xh\n"~
	"e_lfarlc    %04Xh\n"~
	"e_ovno      %04Xh\n"~
	"e_lfanew    %08Xh\n",
	obj.mz.hdr.e_cblp,
	obj.mz.hdr.e_cp,
	obj.mz.hdr.e_crlc,
	obj.mz.hdr.e_cparh,
	obj.mz.hdr.e_minalloc,
	obj.mz.hdr.e_maxalloc,
	obj.mz.hdr.e_ss,
	obj.mz.hdr.e_sp,
	obj.mz.hdr.e_csum,
	obj.mz.hdr.e_ip,
	obj.mz.hdr.e_cs,
	obj.mz.hdr.e_lfarlc,
	obj.mz.hdr.e_ovno,
	obj.mz.hdr.e_lfanew
	);
}

void dump_mz_relocs(adbg_object_t *obj) {
	dump_chapter("Relocations");
	
	ushort relocs = obj.mz.hdr.e_crlc;
	mz_reloc *reloc = obj.mz.relocs;
	
	if (relocs == 0 || reloc == null) {
		puts("No relocations");
		return;
	}
	
	for (ushort i; i < relocs; ++i)
		printf("%u. segment=%04X offset=%04X\n",
			i, reloc[i].segment, reloc[i].offset);
}