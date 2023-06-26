/**
 * MS-DOS MZ file dumper
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2022 dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module dump.mz;

import core.stdc.stdio;
import adbg.v1.disassembler : adbg_disasm_t, adbg_disasm, AdbgDisasmMode;
import adbg.v1.server.mz;
import adbg.v1.server : adbg_object_t;
import dumper;

extern (C):

/// Print MZ info to stdout, a file_info_t structure must be loaded before
/// calling this function.
/// Params: dump = Dump structure
/// Returns: Non-zero on error
int dump_mz(dump_t *dump) {
	dump_title("MS-DOS MZ");
	
	if (dump.flags & DumpOpt.header)
		dump_mz_hdr(dump.obj);
	
	if (dump.flags & DumpOpt.relocs)
		dump_mz_relocs(dump.obj);
	
	if (dump.flags & DumpOpt.disasm)
		dump_mz_disasm(dump);
	
	return 0;
}

private:

void dump_mz_hdr(adbg_object_t *obj) {
	dump_h1("Header");
	printf(
	"e_cblp      %04Xh\t(%u)\n"~
	"e_cp        %04Xh\t(%u)\n"~
	"e_crlc      %04Xh\t(%u)\n"~
	"e_cparh     %04Xh\n"~
	"e_minalloc  %04Xh\n"~
	"e_maxalloc  %04Xh\n"~
	"e_ss        %04Xh\n"~
	"e_sp        %04Xh\n"~
	"e_csum      %04Xh\n"~
	"e_ip        %04Xh\n"~
	"e_cs        %04Xh\n"~
	"e_lfarlc    %04Xh\n"~
	"e_ovno      %04Xh\t(%u)\n"~
	"e_lfanew    %08Xh\n",
	obj.mz.hdr.e_cblp, obj.mz.hdr.e_cblp,
	obj.mz.hdr.e_cp, obj.mz.hdr.e_cp,
	obj.mz.hdr.e_crlc, obj.mz.hdr.e_crlc,
	obj.mz.hdr.e_cparh,
	obj.mz.hdr.e_minalloc,
	obj.mz.hdr.e_maxalloc,
	obj.mz.hdr.e_ss,
	obj.mz.hdr.e_sp,
	obj.mz.hdr.e_csum,
	obj.mz.hdr.e_ip,
	obj.mz.hdr.e_cs,
	obj.mz.hdr.e_lfarlc,
	obj.mz.hdr.e_ovno, obj.mz.hdr.e_ovno,
	obj.mz.hdr.e_lfanew
	);
}

void dump_mz_relocs(adbg_object_t *obj) {
	dump_h1("Relocations");
	
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

void dump_mz_disasm(dump_t *dump) {
	dump_h1("Disassembly");
	
	uint start = dump.obj.mz.hdr.e_cparh << 4; // *16
	if (start < mz_hdr.sizeof || start >= dump.obj.fsize) {
		printf("dump_mz_disasm: Data start outside of exe (%u)", start);
	}
	
	uint blks = void;
	uint len  = void;
	with (dump.obj.mz.hdr) {
		blks = e_cblp ? e_cp - 1 : e_cp;
		len  = (blks * 16) + e_cblp;
	}
	if (len > dump.obj.fsize) {
		printf("dump_mz_disasm: Data length cannot be bigger than file (%u)", len);
		return;
	}
	
	dump_disasm(dump.dopts, dump.obj.buf + start, len, dump.flags);
}
