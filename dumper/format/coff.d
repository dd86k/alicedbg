/// COFF dumper.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module format.coff;

import adbg.disassembler;
import adbg.objectserver;
import adbg.machines;
import adbg.objects.coff;
import adbg.error : adbg_error_message;
import core.stdc.ctype : isdigit;
import dumper;
import common.errormgmt;
import common.utils : realstring;

int dump_coff(adbg_object_t *o) {
	if (SELECTED(Select.headers))
		dump_coff_headers(o);
	if (SELECTED(Select.sections))
		dump_coff_sections(o);
	if (SELECTED(Select.exports))
		dump_coff_symbols(o);
	// TODO: "--debug" -> .debug$T (CodeView)
	return 0;
}

private:

void dump_coff_headers(adbg_object_t *o) {
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
	
	coff_opt_header_t *optheader = adbg_object_coff_optional_header(o);
	if (optheader) {
		print_header("Optional Header");
		
		with (optheader) {
		print_x16("magic", magic);
		print_x16("vstamp", vstamp);
		print_u32("textsize", textsize);
		print_u32("datasize", datasize);
		print_u32("bss_size", bss_size);
		print_x32("entry", entry);
		print_x32("text_start", text_start);
		print_x32("data_start", data_start);
		}
	}
}

void dump_coff_sections(adbg_object_t *o) {
	print_header("Sections");
	
	coff_section_header_t *section = adbg_object_coff_section_first(o);
	if (section == null)
		panic_adbg();
	
	uint i;
	do with (section) {
		print_section(++i);
		print_stringl("s_name",	s_name.ptr, s_name.sizeof);
		print_x32("s_paddr",	s_paddr);
		print_x32("s_vaddr",	s_vaddr);
		print_u32("s_size",	s_size);
		print_x32("s_scnptr",	s_scnptr);
		print_x32("s_relptr",	s_relptr);
		print_x32("s_lnnoptr",	s_lnnoptr);
		print_u16("s_nreloc",	s_nreloc);
		print_u16("s_nlnno",	s_nlnno);
		print_flags32("s_flags", s_flags,
			"STYPE_TEXT".ptr, COFF_STYPE_TEXT,
			"STYPE_DATA".ptr, COFF_STYPE_DATA,
			"STYPE_BSS".ptr, COFF_STYPE_BSS,
		);
		
		if (SETTING(Setting.extractAny)) {
			void *buf = adbg_object_coff_section_open_data(o, section);
			if (buf == null) {
				print_warningf("Open failed: %s", adbg_error_message());
				continue;
			}
			
			print_data("section data", buf, s_size);
			adbg_object_coff_section_close_data(buf);
		}
	} while ((section = adbg_object_coff_section_next(o)) != null);
}

void dump_coff_symbols(adbg_object_t *o) {
	print_header("Symbols");
	
	coff_symbol_entry_t *symbol = adbg_object_coff_first_symbol(o);
	if (symbol == null)
		panic_adbg();
	
	uint i;
	A: do with (symbol) {
		print_section(i++);
		const(char) *e_name = adbg_object_coff_symbol_name(o, symbol);
		print_string("e_name", e_name);
		print_x32("e_zeroes", entry.zeroes);
		print_x32("e_offset", entry.offset);
		print_x32("e_value", e_value);
		print_d16("e_scnum", e_scnum);
		print_u16("e_type", e_type);
		print_u8("e_sclass", e_sclass);
		print_u8("e_numaux", e_numaux);
		
		// Auxiliary entries
		// TODO: continuous data dump
		for (ubyte a; a < e_numaux; ++a) {
			// assume pure binary data
			symbol = adbg_object_coff_next_symbol(o);
			if (symbol == null)
				break A;
			
			if (SETTING(Setting.extractAny))
				print_data("auxiliary symbol", symbol, coff_symbol_entry_t.sizeof);
		}
	} while ((symbol = adbg_object_coff_next_symbol(o)) != null);
}
