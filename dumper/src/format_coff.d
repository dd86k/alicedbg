/// COFF dumper.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module format_coff;

import adbg.disassembler;
import adbg.objectserver;
import adbg.machines;
import adbg.objects.coff;
import adbg.objects.mscoff : mscoff_anon_header_bigobj_t;
import adbg.utils.uid;
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
	if (SELECTED(Select.relocs))
		dump_coff_relocs(o);
	// TODO: SELECTED(Select.debug_) ("--debug") -> .debug$T (CodeView)
	if (SELECTED(Select.exports))
		dump_coff_symbols(o);
	if (SETTING(Setting.disasmAny))
		dump_coff_disasm(o);
	return 0;
}

private:

void dump_coff_headers(adbg_object_t *o) {
	print_header("Header");
	
	if (adbg_object_coff_is_bigobj(o)) {
		dump_coff_bigobj_header(o);
		return;
	}
	
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
		const(char) *name = adbg_object_coff_section_name(o, section);
		if (name)
			print_string("s_name", name);
		else
			print_stringl("s_name", s_name.ptr, s_name.sizeof);
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
			null);
		
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
	
	uint count = adbg_object_coff_symbol_count(o);
	coff_symbol_ex_t *symbol = void;
	for (uint i; i < count; i += 1 + symbol.e_numaux) {
		symbol = adbg_object_coff_symbol_at(o, i);
		if (symbol == null)
			panic_adbg();
		
		with (symbol) {
		print_section(i);
		const(char) *e_name = adbg_object_coff_symbol_name_at(o, i);
		if (e_name)
			print_string("e_name", e_name);
		else
			print_warningf("e_name null: %s", adbg_error_message());
		print_x32("e_zeroes", entry.zeroes);
		print_x32("e_offset", entry.offset);
		print_x32("e_value", e_value);
		print_d32("e_scnum", e_scnum);
		print_u16("e_type", e_type);
		print_u8("e_sclass", e_sclass);
		print_u8("e_numaux", e_numaux);
		
		if (SETTING(Setting.extractAny) && e_numaux && i + 1 < count)
			print_data("auxiliary symbols", symbol + 1,
				coff_symbol_ex_t.sizeof * (e_numaux < count - i - 1 ? e_numaux : count - i - 1));
		}
	}
}

void dump_coff_relocs(adbg_object_t *o) {
	print_header("Relocations");
	
	uint seccount = adbg_object_coff_section_count(o);
	for (uint n = 1; n <= seccount; ++n) {
		coff_section_header_t *section = adbg_object_coff_section_by_number(o, n);
		if (section == null)
			panic_adbg();
		
		uint count = void;
		coff_reloc_entry_t *relocs = adbg_object_coff_section_open_relocs(o, section, &count);
		if (relocs == null)
			continue;
		
		print_section(n, adbg_object_coff_section_name(o, section));
		for (uint r; r < count; ++r) with (relocs[r]) {
			const(char) *symname = adbg_object_coff_symbol_name_at(o, r_symndx);
			print_x32("r_vaddr", r_vaddr);
			print_u32("r_symndx", r_symndx, symname);
			print_x16("r_type", r_type);
		}
		adbg_object_coff_section_close_relocs(relocs);
	}
}

void dump_coff_bigobj_header(adbg_object_t *o) {
	mscoff_anon_header_bigobj_t *header = adbg_object_coff_bigobj_header(o);
	if (header == null)
		panic_adbg();
	
	with (header) {
	print_x16("Sig1", Sig1);
	print_x16("Sig2", Sig2);
	print_u16("Version", Version);
	print_x16("Machine", Machine, adbg_object_coff_magic_string(Machine));
	print_x32("TimeDateStamp", TimeDateStamp);
	char[UID_TEXTLEN] uid = void;
	uid_text(ClassID, uid, UID_GUID);
	print_string("ClassID", uid.ptr);
	print_x32("SizeOfData", SizeOfData);
	print_x32("Flags", Flags);
	print_x32("MetaDataSize", MetaDataSize);
	print_x32("MetaDataOffset", MetaDataOffset);
	print_u32("NumberOfSections", NumberOfSections);
	print_x32("PointerToSymbolTable", PointerToSymbolTable);
	print_u32("NumberOfSymbols", NumberOfSymbols);
	}
}


void dump_coff_disasm(adbg_object_t *o) {
	coff_section_header_t *section = adbg_object_coff_section_first(o);
	if (section == null)
		panic_adbg();
	
	ushort flg = SETTING(Setting.disasmAny) ? 0x00f0 : COFF_STYPE_TEXT;
	
	uint i;
	do with (section) {
		if ((s_flags & flg) == 0)
			continue;
		
		void *secdata = adbg_object_coff_section_open_data(o, section);
		if (secdata == null) {
			print_warningf("section null: %s", adbg_error_message());
			continue;
		}
		
		dump_disassemble_object(o, s_name.ptr, s_name.sizeof, secdata, s_size, 0);
		adbg_object_coff_section_close_data(secdata);
	} while ((section = adbg_object_coff_section_next(o)) != null);
}