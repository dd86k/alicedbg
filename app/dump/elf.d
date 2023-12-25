/// ELF dumper
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module dump.elf;

import adbg.v2.disassembler.core;
import adbg.v2.object.server;
import adbg.v2.object.machines;
import adbg.v2.object.format.elf;
import dumper;

extern (C):

int dump_elf(ref Dumper dump, adbg_object_t *o) {
	if (dump.selected_headers()) {
		dump_elf_ehdr(dump, o);
		dump_elf_phdr(dump, o);
	}
	
	if (dump.selected_sections())
		dump_elf_sections(dump, o);
	
	if (dump.selected_disasm_any())
		dump_elf_disasm(dump, o);
	
	return 0;
}

private:

void dump_elf_ehdr(ref Dumper dump, adbg_object_t *o) {
	print_header("Header");
	
	ubyte ei_class	= o.i.elf32.ehdr.e_ident[ELF_EI_CLASS];
	
	with (o.i.elf32.ehdr) {
	ubyte ei_data	= e_ident[ELF_EI_DATA];
	ubyte ei_version	= e_ident[ELF_EI_VERSION];
	ubyte ei_osabi	= e_ident[ELF_EI_OSABI];
	ubyte ei_abiversion	= e_ident[ELF_EI_ABIVERSION];
	
	print_x8("e_ident[0]", '\x7f', "\\x7f");
	print_x8("e_ident[1]", 'E', "E");
	print_x8("e_ident[2]", 'L', "L");
	print_x8("e_ident[3]", 'F', "F");
	print_u8("e_ident[EI_CLASS]", ei_class, adbg_object_elf_class_string(ei_class));
	print_u8("e_ident[EI_DATA]", ei_data, adbg_object_elf_data_string(ei_data));
	print_u8("e_ident[EI_VERSION]", ei_version);
	print_u8("e_ident[EI_OSABI]", ei_osabi, adbg_object_elf_abi_string(ei_osabi));
	print_u8("e_ident[EI_ABIVERSION]", ei_abiversion);
	print_u8("e_ident[9]", e_ident[9]);
	print_u8("e_ident[10]", e_ident[10]);
	print_u8("e_ident[11]", e_ident[11]);
	print_u8("e_ident[12]", e_ident[12]);
	print_u8("e_ident[13]", e_ident[13]);
	print_u8("e_ident[14]", e_ident[14]);
	print_u8("e_ident[15]", e_ident[15]);
	print_u16("e_type", e_type, adbg_object_elf_et_string(e_type));
	print_u16("e_machine", e_machine, adbg_object_elf_em_string(e_machine));
	}
	
	switch (ei_class) {
	case ELF_CLASS_32:
		with (o.i.elf32.ehdr) {
		print_x32("e_entry", e_entry);
		print_x32("e_phoff", e_phoff);
		print_x32("e_shoff", e_shoff);
		dump_elf_e_flags(e_machine, e_flags);
		print_u16("e_ehsize", e_ehsize);
		print_u16("e_phentsize", e_phentsize);
		print_u16("e_phnum", e_phnum);
		print_u16("e_shentsize", e_shentsize);
		print_u16("e_shnum", e_shnum);
		print_u16("e_shstrndx", e_shstrndx);
		}
		break;
	case ELF_CLASS_64:
		with (o.i.elf64.ehdr) {
		print_x64("e_entry", e_entry);
		print_x64("e_phoff", e_phoff);
		print_x64("e_shoff", e_shoff);
		dump_elf_e_flags(e_machine, e_flags);
		print_u16("e_ehsize", e_ehsize);
		print_u16("e_phentsize", e_phentsize);
		print_u16("e_phnum", e_phnum);
		print_u16("e_shentsize", e_shentsize);
		print_u16("e_shnum", e_shnum);
		print_u16("e_shstrndx", e_shstrndx);
		}
		break;
	default:
	}
}

void dump_elf_e_flags(ushort e_machine, uint e_flags) {
	switch (e_machine) {
	case ELF_EM_ARM:
		print_flags32("e_flags", e_flags,
			"EF_ARM_RELEXEC".ptr,	ELF_EF_ARM_RELEXEC,
			"EF_ARM_HASENTRY".ptr,	ELF_EF_ARM_HASENTRY,
			"EF_ARM_INTERWORK".ptr,	ELF_EF_ARM_INTERWORK,
			"EF_ARM_APCS_26".ptr,	ELF_EF_ARM_APCS_26,
			"EF_ARM_APCS_FLOAT".ptr,	ELF_EF_ARM_APCS_FLOAT,
			"EF_ARM_PIC".ptr,	ELF_EF_ARM_PIC,
			"EF_ARM_ALIGN8".ptr,	ELF_EF_ARM_ALIGN8,
			"EF_ARM_NEW_ABI".ptr,	ELF_EF_ARM_NEW_ABI,
			"EF_ARM_OLD_ABI".ptr,	ELF_EF_ARM_OLD_ABI,
			"EF_ARM_SOFT_FLOAT".ptr,	ELF_EF_ARM_SOFT_FLOAT,
			"EF_ARM_VFP_FLOAT".ptr,	ELF_EF_ARM_VFP_FLOAT,
			"EF_ARM_MAVERICK_FLOAT".ptr,	ELF_EF_ARM_MAVERICK_FLOAT,
			null);
		break;
	case ELF_EM_SPARC:
	case ELF_EM_SPARC32PLUS:
	case ELF_EM_SPARCV9:
		print_flags32("e_flags", e_flags,
			"EF_SPARC_32PLUS".ptr,	ELF_EF_SPARC_32PLUS,
			"EF_SPARC_SUN_US1".ptr,	ELF_EF_SPARC_SUN_US1,
			"EF_SPARC_HAL_R1".ptr,	ELF_EF_SPARC_HAL_R1,
			"EF_SPARC_SUN_US3".ptr,	ELF_EF_SPARC_SUN_US3,
			"EF_SPARCV9_MM".ptr,	ELF_EF_SPARCV9_MM,
			"EF_SPARCV9_TSO".ptr,	ELF_EF_SPARCV9_TSO,
			"EF_SPARCV9_PSO".ptr,	ELF_EF_SPARCV9_PSO,
			"EF_SPARCV9_RMO".ptr,	ELF_EF_SPARCV9_RMO,
			null);
		break;
	default:
		print_x32("e_flags", e_flags);
	}
}

void dump_elf_phdr(ref Dumper dump, adbg_object_t *o) {
	print_header("Program Headers");
	
	//TODO: Warn and set an upper number limit (e.g. 1000)
	
	switch (o.i.elf32.ehdr.e_ident[ELF_EI_CLASS]) {
	case ELF_CLASS_32:
		if (o.i.elf32.phdr == null ||
			o.i.elf32.ehdr.e_phnum == 0)
			return;
		
		//TODO: adbg_object_elf32_phnum function?
		for (uint i; i < o.i.elf32.ehdr.e_phnum; ++i) {
			Elf32_Phdr *phdr = adbg_object_elf_phdr32(o, i);
			with (phdr) {
			print_section(i);
			print_u32("p_type", p_type, adbg_object_elf_pt_string(p_type));
			print_x32("p_offset", p_offset);
			print_x32("p_vaddr", p_vaddr);
			print_x32("p_paddr", p_paddr);
			print_x32("p_filesz", p_filesz);
			print_x32("p_memsz", p_memsz);
			print_flags32("p_flags", p_flags,
				"PF_R".ptr, ELF_PF_R,
				"PF_W".ptr, ELF_PF_W,
				"PF_X".ptr, ELF_PF_X,
				null);
			print_x32("p_align", p_align);
			}
			
			//TODO: coredump
			// if (p_type == ELF_PT_NOTE && p_pflags == 0)
			// Elf32_Nhdr (like NT_X86_XSTATE)
		}
		break;
	case ELF_CLASS_64:
		if (o.i.elf64.phdr == null ||
			o.i.elf64.ehdr.e_phnum == 0)
			return;
		
		for (uint i; i < o.i.elf64.ehdr.e_phnum; ++i) {
			Elf64_Phdr *phdr = adbg_object_elf_phdr64(o, i);
			with (phdr) {
			print_section(i);
			print_u32("p_type", p_type, adbg_object_elf_pt_string(p_type));
			print_flags32("p_flags", p_flags,
				"PF_R".ptr, ELF_PF_R,
				"PF_W".ptr, ELF_PF_W,
				"PF_X".ptr, ELF_PF_X,
				null);
			print_x64("p_offset", p_offset);
			print_x64("p_vaddr", p_vaddr);
			print_x64("p_paddr", p_paddr);
			print_x64("p_filesz", p_filesz);
			print_x64("p_memsz", p_memsz);
			print_x64("p_align", p_align);
			}
			
			//TODO: coredump
			// if (p_type == ELF_PT_NOTE && p_pflags == 0)
			// Elf32_Nhdr (like NT_X86_XSTATE)
		}
		break;
	default:
	}
}

void dump_elf_sections(ref Dumper dump, adbg_object_t *o) {
	print_header("Sections");
	
	//TODO: Functions to get section + section name safely
	
	switch (o.i.elf32.ehdr.e_ident[ELF_EI_CLASS]) {
	case ELF_CLASS_32:
		if (o.i.elf32.ehdr == null)
			return;
		
		ushort section_count = o.i.elf32.ehdr.e_shnum;
		if (section_count == 0)
			return;
		
		// Check id is without section count
		ushort id = o.i.elf32.ehdr.e_shstrndx;
		if (id >= section_count) {
			print_string("error", "String table index out of bounds");
			return;
		}
		
		uint offset = o.i.elf32.shdr[id].sh_offset;
		if (offset < Elf32_Ehdr.sizeof || offset > o.file_size) {
			print_string("error", "String table offset out of bounds");
			return;
		}
		
		char *table = o.bufferc + offset; // string table
		for (uint i; i < section_count; ++i) {
			Elf32_Shdr *shdr = adbg_object_elf_shdr32(o, i);
			with (shdr) {
			print_section(i, table + sh_name, 32);
			print_x32("sh_name", sh_name);
			print_x32("sh_type", sh_type, adbg_object_elf_sht_string(sh_type));
			print_x32("sh_flags", sh_flags);
			print_flags32("sh_flags", sh_flags,
				"SHF_WRITE".ptr,	ELF_SHF_WRITE,
				"SHF_ALLOC".ptr,	ELF_SHF_ALLOC,
				"SHF_EXECINSTR".ptr,	ELF_SHF_EXECINSTR,
				"SHF_MERGE".ptr,	ELF_SHF_MERGE,
				"SHF_STRINGS".ptr,	ELF_SHF_STRINGS,
				"SHF_INFO_LINK".ptr,	ELF_SHF_INFO_LINK,
				"SHF_LINK_ORDER".ptr,	ELF_SHF_LINK_ORDER,
				"SHF_OS_NONCONFORMING".ptr,	ELF_SHF_OS_NONCONFORMING,
				"SHF_GROUP".ptr,	ELF_SHF_GROUP,
				"SHF_TLS".ptr,	ELF_SHF_TLS,
				"SHF_COMPRESSED".ptr,	ELF_SHF_COMPRESSED,
				null);
			print_x32("sh_addr", sh_addr);
			print_x32("sh_offset", sh_offset);
			print_x32("sh_size", sh_size);
			print_x32("sh_link", sh_link);
			print_x32("sh_info", sh_info);
			print_x32("sh_addralign", sh_addralign);
			print_x32("sh_entsize", sh_entsize);
			}
		}
		break;
	case ELF_CLASS_64:
		if (o.i.elf64.ehdr == null)
			return;
		
		ushort section_count = o.i.elf64.ehdr.e_shnum;
		if (section_count == 0)
			return;
		
		// Check id is without section count
		ushort id = o.i.elf64.ehdr.e_shstrndx;
		if (id >= section_count) {
			print_string("error", "String table index out of bounds");
			return;
		}
		
		ulong offset = o.i.elf64.shdr[id].sh_offset;
		if (offset < Elf64_Ehdr.sizeof || offset > o.file_size) {
			print_string("error", "String table offset out of bounds");
			return;
		}
		
		char *table = o.bufferc + offset; // string table
		for (uint i; i < section_count; ++i) {
			Elf64_Shdr *shdr = adbg_object_elf_shdr64(o, i);
			with (shdr) {
			print_section(i, table + sh_name, 32);
			print_x32("sh_name", sh_name);
			print_x32("sh_type", sh_type, adbg_object_elf_sht_string(sh_type));
			print_flags64("sh_flags", sh_flags,
				"SHF_WRITE".ptr,	ELF_SHF_WRITE,
				"SHF_ALLOC".ptr,	ELF_SHF_ALLOC,
				"SHF_EXECINSTR".ptr,	ELF_SHF_EXECINSTR,
				"SHF_MERGE".ptr,	ELF_SHF_MERGE,
				"SHF_STRINGS".ptr,	ELF_SHF_STRINGS,
				"SHF_INFO_LINK".ptr,	ELF_SHF_INFO_LINK,
				"SHF_LINK_ORDER".ptr,	ELF_SHF_LINK_ORDER,
				"SHF_OS_NONCONFORMING".ptr,	ELF_SHF_OS_NONCONFORMING,
				"SHF_GROUP".ptr,	ELF_SHF_GROUP,
				"SHF_TLS".ptr,	ELF_SHF_TLS,
				"SHF_COMPRESSED".ptr,	ELF_SHF_COMPRESSED,
				null);
			print_x64("sh_addr", sh_addr);
			print_x64("sh_offset", sh_offset);
			print_x64("sh_size", sh_size);
			print_x32("sh_link", sh_link);
			print_x32("sh_info", sh_info);
			print_x64("sh_addralign", sh_addralign);
			print_x64("sh_entsize", sh_entsize);
			}
		}
		break;
	default:
	}
}

void dump_elf_disasm(ref Dumper dump, adbg_object_t *o) {
	import core.stdc.stdlib : malloc;
	print_header("Disassembly");
	
	bool all = dump.selected_disasm_all();
	
	switch (o.i.elf32.ehdr.e_ident[ELF_EI_CLASS]) {
	case ELF_CLASS_32:
		ushort section_count = o.i.elf32.ehdr.e_shnum;
		
		if (section_count == 0)
			return;
		
		// Check id is without section count
		ushort id = o.i.elf32.ehdr.e_shstrndx;
		if (id >= section_count) {
			print_string("error", "String table index out of bounds");
			return;
		}
		
		Elf32_Shdr *shdr = o.i.elf32.shdr;
		uint offset = shdr[id].sh_offset;
		if (offset < Elf32_Ehdr.sizeof || offset > o.file_size) {
			print_string("error", "String table offset out of bounds");
			return;
		}
		
		Elf32_Shdr *max = shdr + section_count;
		char *table = o.bufferc + offset; // string table
		while (shdr++ < max) with (shdr) {
			if (all || sh_flags & ELF_SHF_EXECINSTR)
				dump_disassemble_object(dump, o,
					table + sh_name, 32,
					o.buffer8 + sh_offset, sh_size, 0);
		}
		break;
	case ELF_CLASS_64:
		ushort section_count = o.i.elf64.ehdr.e_shnum;
		
		if (section_count == 0)
			return;
		
		// Check id is without section count
		ushort id = o.i.elf64.ehdr.e_shstrndx;
		if (id >= section_count) {
			print_string("error", "String table index out of bounds");
			return;
		}
		
		Elf64_Shdr *shdr = o.i.elf64.shdr;
		ulong offset = shdr[id].sh_offset;
		if (offset < Elf64_Ehdr.sizeof || offset > o.file_size) {
			print_string("error", "String table offset out of bounds");
			return;
		}
		
		Elf64_Shdr *max = shdr + section_count;
		char *table = o.bufferc + offset; // string table
		while (shdr++ < max) with (shdr) {
			if (all || sh_flags & ELF_SHF_EXECINSTR)
				dump_disassemble_object(dump, o,
					table + sh_name, 32,
					o.buffer8 + sh_offset, sh_size, 0);
		}
		break;
	default:
	}
}
