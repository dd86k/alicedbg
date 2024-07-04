/// MS-DOS MZ file dumper
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module format.mz;

import adbg.disassembler;
import adbg.objectserver;
import adbg.machines : AdbgMachine;
import adbg.objects.mz;
import core.stdc.stdlib;
import dumper;
import common.errormgmt;

extern (C):

/// Print MZ object.
/// Params: o = Object instance.
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
	
	//TODO: If start of code or relocs start within extended header,
	//      manually cut it off from the header prints (reserved words and newloc)
	mz_header_t* header = adbg_object_mz_header(o);
	
	with (header) {
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
	
	mz_reloc_t *reloc = void;
	size_t i;
	while ((reloc = adbg_object_mz_reloc(o, i++)) != null)
		with (reloc) print_reloc16(cast(uint)i, segment, offset);
}

void dump_mz_disasm(adbg_object_t *o) {
	mz_header_t* header = adbg_object_mz_header(o);
	
	// Get data location
	uint start = (header.e_cparh << 4) + header.e_cblp; // (paragraphs * 16) + rest
	if (start < mz_header_t.sizeof)
		panic(1, "Data start outside of file buffer");
	
	// Get data length
	uint len = (header.e_cp << 4) + header.e_cblp; // (paragraphs * 16) + rest
	
	void* buffer = malloc(len);
	if (buffer == null)
		panic_crt();
	if (adbg_object_read_at(o, start, buffer, len))
		panic_adbg();
	
	dump_disassemble_object(o, null, 0, buffer, len, 0);
}
