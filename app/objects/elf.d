/**
 * ELF dumper
 *
 * License: BSD-3-Clause
 */
module objects.elf;

import core.stdc.stdio;
import adbg.obj.server;
import adbg.disasm.disasm : adbg_disasm_t, adbg_disasm, AdbgDisasmMode;
import adbg.obj.elf;
import dumper;

extern (C):

int dump_elf(adbg_object_t *obj, adbg_disasm_t *disasm_opts, int flags) {
	dump_title("Executable and Linkable Format");
	
	if (flags & DumpOpt.header)
		dump_elf_hdr(obj);
	
	if (flags & DumpOpt.sections)
		dump_elf_sections(obj);
	
	return 0;
}

private:

void dump_elf_hdr(adbg_object_t *obj) {
	dump_chapter("Header");
	
	ubyte h_class = obj.elf.hdr32.e_ident[ELF_EI_CLASS];
	ubyte h_data = obj.elf.hdr32.e_ident[ELF_EI_DATA];
	ubyte h_version = obj.elf.hdr32.e_ident[ELF_EI_VERSION];
	ubyte h_osabi = obj.elf.hdr32.e_ident[ELF_EI_OSABI];
	ubyte h_abiversion = obj.elf.hdr32.e_ident[ELF_EI_ABIVERSION];
	
	with (obj.elf.hdr32)
	printf(
	"e_ident[EI_CLASS]       %02X\t(%s)\n"~
	"e_ident[EI_DATA]        %02X\t(%s)\n"~
	"e_ident[EI_VERSION]     %02X\t(%u)\n"~
	"e_ident[EI_OSABI]       %02X\t(%s)\n"~
	"e_ident[EI_ABIVERSION]  %02X\t(%u)\n"~
	"e_ident[9]              %02X\n"~
	"e_ident[10]             %02X\n"~
	"e_ident[11]             %02X\n"~
	"e_ident[12]             %02X\n"~
	"e_ident[13]             %02X\n"~
	"e_ident[14]             %02X\n"~
	"e_ident[15]             %02X\n"~
	"e_type                  %04X\t(%s)\n"~
	"e_machine               %04X\t(%s)\n",
	h_class, adbg_obj_elf_class(h_class),
	h_data, adbg_obj_elf_data(h_data),
	h_version, h_version,
	h_osabi, adbg_obj_elf_osabi(h_osabi),
	h_abiversion, h_abiversion,
	e_ident[9],
	e_ident[10],
	e_ident[11],
	e_ident[12],
	e_ident[13],
	e_ident[14],
	e_ident[15],
	e_type, adbg_obj_elf_type(e_type),
	e_machine, adbg_obj_elf_machine(e_machine),
	);
	
	switch (h_class) {
	case ELFCLASS32:
		with (obj.elf.hdr32)
		printf(
		"e_entry                 %08X\n"~
		"e_phoff                 %08X\n"~
		"e_shoff                 %08X\n"~
		"e_flags                 %08X\t(...)\n"~
		"e_ehsize                %04X\t(%u)\n"~
		"e_phentsize             %04X\t(%u)\n"~
		"e_phnum                 %04X\t(%u)\n"~
		"e_shentsize             %04X\t(%u)\n"~
		"e_shnum                 %04X\t(%u)\n"~
		"e_shstrndx              %04X\n",
		e_entry,
		e_phoff,
		e_shoff,
		e_flags,
		e_ehsize, e_ehsize,
		e_phentsize, e_phentsize,
		e_phnum, e_phnum,
		e_shentsize, e_shentsize,
		e_shnum, e_shnum,
		e_shstrndx
		);
		return;
	case ELFCLASS64:
		with (obj.elf.hdr64)
		printf(
		"e_entry                 %016llX\n"~
		"e_phoff                 %016llX\n"~
		"e_shoff                 %016llX\n"~
		"e_flags                 %08X\n"~
		"e_ehsize                %04X\t(%u)\n"~
		"e_phentsize             %04X\t(%u)\n"~
		"e_phnum                 %04X\t(%u)\n"~
		"e_shentsize             %04X\t(%u)\n"~
		"e_shnum                 %04X\t(%u)\n"~
		"e_shstrndx              %04X\n",
		e_entry,
		e_phoff,
		e_shoff,
		e_flags,
		e_ehsize, e_ehsize,
		e_phentsize, e_phentsize,
		e_phnum, e_phnum,
		e_shentsize, e_shentsize,
		e_shnum, e_shnum,
		e_shstrndx
		);
		return;
	default:
	}
}

void dump_elf_phdr(adbg_object_t *obj) {
	dump_chapter("Segments");
	
	ushort nb = void;
	ushort i;
	switch (obj.elf.hdr32.e_ident[ELF_EI_CLASS]) {
	case ELFCLASS32:
		nb = obj.elf.hdr32.e_phnum;
		
		if (nb == 0) {
			puts("No segments");
			return;
		}
		
		Elf32_Phdr *p32 = obj.elf.phdr32;
		for (; i < nb; ++i, ++p32) {
			with (p32)
			printf(
			"p_type    %08X\n"~
			"p_flags   %08X\n"~
			"p_offset  %08X\n"~
			"p_vaddr   %08X\n"~
			"p_paddr   %08X\n"~
			"p_filesz  %08X\n"~
			"p_memsz   %08X\n"~
			"p_align   %08X\n",
			p_type,
			p_flags,
			p_offset,
			p_vaddr,
			p_paddr,
			p_filesz,
			p_memsz,
			p_align
			);
		}
		return;
	case ELFCLASS64:
		nb = obj.elf.hdr64.e_phnum;
		
		if (nb == 0) {
			puts("No segments");
			return;
		}
		
		Elf64_Phdr *p64 = obj.elf.phdr64;
		for (; i < nb; ++i, ++p64) {
			with (p64)
			printf(
			"p_type    %08X\n"~
			"p_flags   %08X\n"~
			"p_offset  %016llX\n"~
			"p_vaddr   %016llX\n"~
			"p_paddr   %016llX\n"~
			"p_filesz  %016llX\n"~
			"p_memsz   %016llX\n"~
			"p_align   %016llX\n",
			p_type,
			p_flags,
			p_offset,
			p_vaddr,
			p_paddr,
			p_filesz,
			p_memsz,
			p_align
			);
		}
		return;
	default:
	}
}

void dump_elf_sections(adbg_object_t *obj) {
	dump_chapter("Sections");
	
	char *strtable = void;	/// string table location
	ushort nb = void;	/// number of sections
	
	ushort i = 1;
	switch (obj.elf.hdr32.e_ident[ELF_EI_CLASS]) {
	case ELFCLASS32:
		nb = obj.elf.hdr32.e_shnum;
		
		if (nb == 0) {
			puts("No sections");
			return;
		}
		
		uint shstrndx32 = obj.elf.hdr32.e_shstrndx;
		
		if (shstrndx32 >= nb) {
			puts("String table index out of bounds");
			return;
		}
		
		Elf32_Shdr *s32 = obj.elf.shdr32;
		shstrndx32 = s32[shstrndx32].sh_offset;
		
		if (shstrndx32 == 0) {
			puts("String table offset is zero");
			return;
		}
		
		strtable = cast(char*)(obj.buf + shstrndx32);
		for (++s32; i < nb; ++i, ++s32) {
			with (s32)
			printf(
			"%u. %.32s\n"~
			"sh_name       %08X\n"~
			"sh_type       %08X\t(%s)\n"~
			"sh_flags      %08X\n"~
			"sh_addr       %08X\n"~
			"sh_offset     %08X\n"~
			"sh_size       %08X\n"~
			"sh_link       %08X\n"~
			"sh_info       %08X\n"~
			"sh_addralign  %08X\n"~
			"sh_entsize    %08X\n\n",
			i, strtable + sh_name,
			sh_name,
			sh_type, adbg_obj_elf_s_type(sh_type),
			sh_flags,
			sh_addr,
			sh_offset,
			sh_size,
			sh_link,
			sh_info,
			sh_addralign,
			sh_entsize
			);
		}
		return;
	case ELFCLASS64:
		nb = obj.elf.hdr64.e_shnum;
		
		if (nb == 0) {
			puts("No sections");
			return;
		}
		
		ulong shstrndx64 = obj.elf.hdr64.e_shstrndx;
		
		if (shstrndx64 >= nb) {
			puts("String table index out of bounds");
			return;
		}
		
		Elf64_Shdr *s64 = obj.elf.shdr64;
		shstrndx64 = s64[shstrndx64].sh_offset;
		
		if (shstrndx64 == 0) {
			puts("String table offset is zero");
			return;
		}
		
		strtable = cast(char*)(obj.buf + shstrndx64);
		for (++s64; i < nb; ++i, ++s64) {
			with (s64)
			printf(
			"%u. %.32s\n"~
			"sh_name       %08X\n"~
			"sh_type       %08X\t(%s)\n"~
			"sh_flags      %016llX\n"~
			"sh_addr       %016llX\n"~
			"sh_offset     %016llX\n"~
			"sh_size       %016llX\n"~
			"sh_link       %08X\n"~
			"sh_info       %08X\n"~
			"sh_addralign  %016llX\n"~
			"sh_entsize    %016llX\n\n",
			i, strtable + sh_name,
			sh_name,
			sh_type, adbg_obj_elf_s_type(sh_type),
			sh_flags,
			sh_addr,
			sh_offset,
			sh_size,
			sh_link,
			sh_info,
			sh_addralign,
			sh_entsize
			);
		}
		return;
	default:
	}
}