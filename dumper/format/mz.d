/// MS-DOS MZ file dumper
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module format.mz;

import adbg.disassembler;
import adbg.object.server;
import adbg.machines : AdbgMachine;
import adbg.object.format.mz;
import dumper;
import common.error;

extern (C):

/// Print MZ object.
/// Params:
///   dump = Dumper instance.
///   o = Object instance.
/// Returns: Non-zero on error.
int dump_mz(adbg_object_t *o) {
	if (SELECTED(Select.headers))
		dump_mz_hdr(o);
	if (SELECTED(Select.relocs))
		dump_mz_relocs(o);
	if (SETTING(Setting.disasmAny))
		dump_mz_disasm(o);
	return 0;
}

private:

void dump_mz_hdr(adbg_object_t *o) {
	print_header("Header");
	
	with (o.i.mz.header) {
	print_u16("e_cblp", e_cblp);
	print_u16("e_cp", e_cp);
	print_u16("e_crlc", e_crlc);
	print_u16("e_cparh", e_cparh);
	print_u16("e_minalloc", e_minalloc);
	print_u16("e_maxalloc", e_maxalloc);
	print_x16("e_ss", e_ss);
	print_x16("e_sp", e_sp);
	print_x16("e_csum", e_csum);
	print_x16("e_ip", e_ip);
	print_x16("e_cs", e_cs);
	print_x16("e_lfarlc", e_lfarlc);
	print_u16("e_ovno", e_ovno);
	}
}

void dump_mz_relocs(adbg_object_t *o) {
	print_header("Relocations");
	
	mz_reloc *reloc = void;
	size_t i;
	while ((reloc = adbg_object_mz_reloc(o, i++)) != null) with (reloc)
		print_reloc16(cast(uint)i, segment, offset);
}

void dump_mz_disasm(adbg_object_t *o) {
	// Get start of data
	uint start = (o.i.mz.header.e_cparh << 4) + o.i.mz.header.e_cblp; // paragraphs * 16
	if (start < mz_hdr.sizeof || start >= o.file_size)
		panic(1, "Data start outside of file buffer");
	
	// Get data length, disassembler takes care of error checking
	uint len = (o.i.mz.header.e_cp << 4) + o.i.mz.header.e_cblp; // paragraphs * 16
	dump_disassemble_object(o, null, 0, o.buffer + start, len, 0);
}
