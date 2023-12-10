/// MS-DOS MZ file dumper
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module dump.mz;

import adbg.v2.disassembler.core;
import adbg.v2.object.server;
import adbg.v2.object.machines : AdbgMachine;
import adbg.v2.object.format.mz;
import dumper;

extern (C):

/// Print MZ object.
/// Params:
///   o = Object.
///   flags = Dump settings.
/// Returns: Non-zero on error.
int dump_mz(adbg_object_t *o, uint flags) {
	if (flags & DumpOpt.header)
		dump_mz_hdr(o);
	
	if (flags & DumpOpt.relocs)
		dump_mz_relocs(o);
	
	if (flags & DumpOpt.disasm)
		dump_mz_disasm(o, flags);
	
	return 0;
}

private:

void dump_mz_hdr(adbg_object_t *o) {
	dprint_header("MZ Header");
	
	with (o.i.mz.header) {
	dprint_u16("e_cblp", e_cblp);
	dprint_u16("e_cp", e_cp);
	dprint_u16("e_crlc", e_crlc);
	dprint_u16("e_cparh", e_cparh);
	dprint_u16("e_minalloc", e_minalloc);
	dprint_u16("e_maxalloc", e_maxalloc);
	dprint_x16("e_ss", e_ss);
	dprint_x16("e_sp", e_sp);
	dprint_x16("e_csum", e_csum);
	dprint_x16("e_ip", e_ip);
	dprint_x16("e_cs", e_cs);
	dprint_x16("e_lfarlc", e_lfarlc);
	dprint_u16("e_ovno", e_ovno);
	}
}

void dump_mz_relocs(adbg_object_t *o) {
	import core.stdc.stdio : printf;
	
	dprint_header("Relocations");
	
	mz_reloc *reloc = void;
	size_t i;
	while ((reloc = adbg_object_mz_reloc(o, i++)) != null) with (reloc)
		printf("%u. segment=%04X offset=%04X\n", cast(uint)i, segment, offset);
}

void dump_mz_disasm(adbg_object_t *o, uint flags) {
	dprint_header("Disassembly");
	
	uint start = o.i.mz.header.e_cparh << 4; // *16
	if (start < mz_hdr.sizeof || start >= o.file_size) {
		dprint_warn("Data start outside of exe");
		return;
	}
	
	uint blks = void;
	uint len  = void;
	with (o.i.mz.header) {
	blks = e_cblp ? e_cp - 1 : e_cp;
	len  = (blks * PARAGRAPH) + e_cblp;
	}
	if (len == 0)
		return;
	if (len > o.file_size) {
		dprint_warn("Data length cannot be bigger than file");
		return;
	}
	
	dprint_disassemble_object(o, null, 0, o.buffer + start, len, 0, flags);
}
