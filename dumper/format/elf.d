/// ELF dumper
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module format.elf;

import adbg.utils.bit : adbg_alignup;
import adbg.disassembler;
import adbg.object.server;
import adbg.machines;
import adbg.object.format.elf;
import adbg.utils.bit;
import core.stdc.string : memcmp, strncmp;
import core.stdc.stdlib;
import core.stdc.stdio : snprintf;
import dumper;
import common.utils : realchar, hexstr;
import common.errormgmt;

extern (C):

int dump_elf(adbg_object_t *o) {
	if (SELECTED(Select.headers)) {
		dump_elf_ehdr(o);
		dump_elf_phdr(o);
	}
	
	if (SELECTED(Select.sections))
		dump_elf_sections(o);
	
	if (SELECTED(Select.exports))
		dump_elf_exports(o);
	
	if (SETTING(Setting.disasmAny))
		dump_elf_disasm(o);
	
	return 0;
}

private:

__gshared immutable(char)[] SIG_CORE = "CORE\0\0\0";

void dump_elf_ehdr(adbg_object_t *o) {
	print_header("Header");
	
	int class_ = adbg_object_elf_class(o);
	if (class_ < 0)
		panic_adbg();
	
	Elf32_Ehdr *header = adbg_object_elf_ehdr32(o);
	
	ubyte ei_class	= header.e_ident[ELF_EI_CLASS];
	ubyte ei_data	= header.e_ident[ELF_EI_DATA];
	ubyte ei_version	= header.e_ident[ELF_EI_VERSION];
	ubyte ei_osabi	= header.e_ident[ELF_EI_OSABI];
	ubyte ei_abiversion	= header.e_ident[ELF_EI_ABIVERSION];

	with (header) {
	print_x8("e_ident[0]", '\x7f', `\x7f`);
	print_x8("e_ident[1]", 'E', `E`);
	print_x8("e_ident[2]", 'L', `L`);
	print_x8("e_ident[3]", 'F', `F`);
	print_u8("e_ident[EI_CLASS]", ei_class, adbg_object_elf_class_string(ei_class));
	print_u8("e_ident[EI_DATA]", ei_data, adbg_object_elf_data_string(ei_data));
	print_u8("e_ident[EI_VERSION]", ei_version);
	print_u8("e_ident[EI_OSABI]", ei_osabi, adbg_object_elf_abi_string(ei_osabi));
	print_u8("e_ident[EI_ABIVERSION]", ei_abiversion);
	print_u8("e_ident[9]",  e_ident[9]);
	print_u8("e_ident[10]", e_ident[10]);
	print_u8("e_ident[11]", e_ident[11]);
	print_u8("e_ident[12]", e_ident[12]);
	print_u8("e_ident[13]", e_ident[13]);
	print_u8("e_ident[14]", e_ident[14]);
	print_u8("e_ident[15]", e_ident[15]);
	print_u16("e_type", e_type, adbg_object_elf_et_string(e_type));
	print_u16("e_machine", e_machine, adbg_object_elf_em_string(e_machine));
	print_u32("e_version", e_version);
	}
	
	switch (ei_class) {
	case ELF_CLASS_32:
		with (header) {
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
		Elf64_Ehdr *header64 = cast(Elf64_Ehdr*)header;
		with (header64) {
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
			"EF_SPARCV9_TSO".ptr,	ELF_EF_SPARCV9_TSO,
			"EF_SPARCV9_PSO".ptr,	ELF_EF_SPARCV9_PSO,
			"EF_SPARCV9_RMO".ptr,	ELF_EF_SPARCV9_RMO,
			null);
		break;
	default:
		print_x32("e_flags", e_flags);
	}
}

void dump_elf_phdr(adbg_object_t *o) {
	print_header("Program Headers");
	
	Elf32_Ehdr *header = adbg_object_elf_ehdr32(o);
	
	switch (header.e_ident[ELF_EI_CLASS]) {
	case ELF_CLASS_32:
		Elf32_Phdr *p = void;
		for (size_t i; (p = adbg_object_elf_phdr32(o, i)) != null; ++i) {
			print_section(cast(uint)i);
			print_u32("p_type",   p.p_type, adbg_object_elf_pt_string(p.p_type));
			print_x32("p_offset", p.p_offset);
			print_x32("p_vaddr",  p.p_vaddr);
			print_x32("p_paddr",  p.p_paddr);
			print_x32("p_filesz", p.p_filesz);
			print_x32("p_memsz",  p.p_memsz);
			print_flags32("p_flags", p.p_flags,
				"PF_R".ptr, ELF_PF_R,
				"PF_W".ptr, ELF_PF_W,
				"PF_X".ptr, ELF_PF_X,
				null);
			print_x32("p_align", p.p_align);
		}
		break;
	case ELF_CLASS_64:
		Elf64_Phdr *p = void;
		for (size_t i; (p = adbg_object_elf_phdr64(o, i)) != null; ++i) {
			print_section(cast(uint)i);
			print_u32("p_type", p.p_type, adbg_object_elf_pt_string(p.p_type));
			print_flags32("p_flags", p.p_flags,
				"PF_R".ptr, ELF_PF_R,
				"PF_W".ptr, ELF_PF_W,
				"PF_X".ptr, ELF_PF_X,
				null);
			print_x64("p_offset", p.p_offset);
			print_x64("p_vaddr",  p.p_vaddr);
			print_x64("p_paddr",  p.p_paddr);
			print_x64("p_filesz", p.p_filesz);
			print_x64("p_memsz",  p.p_memsz);
			print_x64("p_align",  p.p_align);
			
			// ELF is a coredump and program header is a note?
			// Worth checking if it is really a coredump
			// Notes usually have no flags
			if (header.e_type == ELF_ET_CORE &&
				p.p_type == ELF_PT_NOTE &&
				p.p_flags == 0) {
				dump_elf_coredump64(o, p);
			}
		}
		break;
	default:
	}
}

void dump_elf_coredump32(adbg_object_t *o, Elf32_Phdr *phdr) {
	
}
void dump_elf_coredump64(adbg_object_t *o, Elf64_Phdr *phdr) {
	// NOTE: 8-byte aligned
	// NOTE: A note program segment contains multiple notes
	
	void *nbuffer = malloc(phdr.p_filesz);
	if (nbuffer == null)
		panic_crt();
	scope(exit) free(nbuffer);
	
	if (adbg_object_read_at(o, phdr.p_offset, nbuffer, phdr.p_filesz))
		panic_adbg();
	
	uint index;
	void *current = nbuffer;
	void *maxlength = nbuffer + phdr.p_filesz;
	for (; current < maxlength; ) {
		Elf64_Nhdr *note = cast(Elf64_Nhdr*)current;
		if (adbg_bits_ptrbounds(note, Elf64_Nhdr.sizeof, nbuffer, phdr.p_filesz))
			panic(2, "Elf64_Nhdr header does not fit note");
		
		// NOTE: Note names
		//       If zero, it's reserved
		//       If name is "CORE", standard coredump stuff, like NT_PRSTATUS
		//       If name is "LINUX", Linux-specific note, like NT_X86_XSTATE
		if (note.n_namesz == 0)
			return;
		
		const(char)* name = cast(const(char)*)note + Elf64_Nhdr.sizeof;
		if (adbg_bits_ptrbounds(cast(void*)name, note.n_namesz, nbuffer, phdr.p_filesz))
			panic(2, "Elf64_Nhdr:n_namesz points outside of note bounds");
		
		print_section(++index, name, note.n_namesz);
		print_u32("n_namesz", note.n_namesz);
		print_u32("n_descsz", note.n_descsz);
		print_u32("n_type", note.n_type, adbg_object_elf_nt_type_string(note.n_type));
		
		size_t nnamesz = adbg_alignup(note.n_namesz, ulong.sizeof);
		void *data = cast(void*)note + Elf64_Nhdr.sizeof + nnamesz;
		ulong notesize = Elf64_Nhdr.sizeof + nnamesz + adbg_alignup(note.n_descsz, uint.sizeof);
		
		switch (note.n_type) {
		case ELF_NT_PRSTATUS:
			if (adbg_bits_ptrbounds(data, elf_prstatus64.sizeof, nbuffer, phdr.p_filesz))
				return;
			elf_prstatus64 *prstatus = cast(elf_prstatus64*)data;
			print_u32("pr_info.si_signo", prstatus.pr_info.si_signo);
			print_u32("pr_info.si_code", prstatus.pr_info.si_code);
			print_u32("pr_info.si_errno", prstatus.pr_info.si_errno);
			print_u16("pr_cursig", prstatus.pr_cursig);
			print_u64("pr_sigpend", prstatus.pr_sigpend);
			print_u64("pr_sighold", prstatus.pr_sighold);
			print_u32("pr_pid", prstatus.pr_pid);
			print_u32("pr_ppid", prstatus.pr_ppid);
			print_u32("pr_pgrp", prstatus.pr_pgrp);
			print_u32("pr_sid", prstatus.pr_sid);
			print_u64("pr_utime.tv_sec", prstatus.pr_utime.tv_sec);
			print_u64("pr_utime.tv_usec", prstatus.pr_utime.tv_usec);
			print_u64("pr_stime.tv_sec", prstatus.pr_stime.tv_sec);
			print_u64("pr_stime.tv_usec", prstatus.pr_stime.tv_usec);
			print_u64("pr_cutime.tv_sec", prstatus.pr_cutime.tv_sec);
			print_u64("pr_cutime.tv_usec", prstatus.pr_cutime.tv_usec);
			print_u64("pr_cstime.tv_sec", prstatus.pr_cstime.tv_sec);
			print_u64("pr_cstime.tv_usec", prstatus.pr_cstime.tv_usec);
			print_x64("pr_reg[r15]", prstatus.pr_reg[0]);
			print_x64("pr_reg[r14]", prstatus.pr_reg[1]);
			print_x64("pr_reg[r13]", prstatus.pr_reg[2]);
			print_x64("pr_reg[r12]", prstatus.pr_reg[3]);
			print_x64("pr_reg[rbp]", prstatus.pr_reg[4]);
			print_x64("pr_reg[rbx]", prstatus.pr_reg[5]);
			print_x64("pr_reg[r11]", prstatus.pr_reg[6]);
			print_x64("pr_reg[r10]", prstatus.pr_reg[7]);
			print_x64("pr_reg[r9]",  prstatus.pr_reg[8]);
			print_x64("pr_reg[r8]",  prstatus.pr_reg[9]);
			print_x64("pr_reg[rax]", prstatus.pr_reg[10]);
			print_x64("pr_reg[rcx]", prstatus.pr_reg[11]);
			print_x64("pr_reg[rdx]", prstatus.pr_reg[12]);
			print_x64("pr_reg[rsi]", prstatus.pr_reg[13]);
			print_x64("pr_reg[rdi]", prstatus.pr_reg[14]);
			print_x64("pr_reg[orig_rax]", prstatus.pr_reg[15]);
			print_x64("pr_reg[rip]", prstatus.pr_reg[16]);
			print_x64("pr_reg[cs]", prstatus.pr_reg[17]);
			print_x64("pr_reg[eflags]", prstatus.pr_reg[18]);
			print_x64("pr_reg[rsp]", prstatus.pr_reg[19]);
			print_x64("pr_reg[ss]", prstatus.pr_reg[20]);
			print_x64("pr_reg[fs_base]", prstatus.pr_reg[21]);
			print_x64("pr_reg[gs_base]", prstatus.pr_reg[22]);
			print_x64("pr_reg[ds]", prstatus.pr_reg[23]);
			print_x64("pr_reg[es]", prstatus.pr_reg[24]);
			print_x64("pr_reg[fs]", prstatus.pr_reg[25]);
			print_x64("pr_reg[gs]", prstatus.pr_reg[26]);
			print_u64("pr_fpvalid", prstatus.pr_fpvalid);
			break;
		case ELF_NT_PRPSINFO:
			elf_prpsinfo64 *prpsinfo = cast(elf_prpsinfo64*)data;
			if (adbg_bits_ptrbounds(data, elf_prpsinfo64.sizeof + prpsinfo.pr_sname, nbuffer, phdr.p_filesz))
				return;
			char[4] pr_sname = void;
			int l = realchar(pr_sname.ptr, 4, prpsinfo.pr_sname);
			print_u8("pr_state", prpsinfo.pr_state);
			print_stringl("pr_sname", pr_sname.ptr, l);
			print_u8("pr_zomb", prpsinfo.pr_zomb);
			print_u8("pr_nice", prpsinfo.pr_nice);
			print_u64("pr_flag", prpsinfo.pr_flag);
			print_u32("pr_uid", prpsinfo.pr_uid);
			print_u32("pr_gid", prpsinfo.pr_gid);
			print_u32("pr_pid", prpsinfo.pr_pid);
			print_u32("pr_ppid", prpsinfo.pr_ppid);
			print_u32("pr_pgrp", prpsinfo.pr_pgrp);
			print_u32("pr_sid", prpsinfo.pr_sid);
			print_stringl("pr_fname", prpsinfo.pr_fname.ptr, prpsinfo.pr_fname.sizeof);
			print_stringl("pr_psargs", prpsinfo.pr_psargs.ptr, prpsinfo.pr_psargs.sizeof);
			break;
		case ELF_NT_SIGINFO: // siginfo
			// NOTE: SI_MAX_SIZE is defined with 128, must be same size
			goto default;
		case ELF_NT_FPREGSET:
			if (adbg_bits_ptrbounds(data, user_i387_struct64.sizeof, nbuffer, phdr.p_filesz))
				return;
			user_i387_struct64 *fregset = cast(user_i387_struct64*)data;
			print_x16("cwd", fregset.cwd);
			print_x16("swd", fregset.swd);
			print_x16("twd", fregset.twd);
			print_x16("fop", fregset.fop);
			print_x64("rip", fregset.rip);
			print_x64("rdp", fregset.rdp);
			print_x32("mxcsr", fregset.mxcsr);
			print_x32("mxcsr_mask", fregset.mxcsr_mask);
			enum FPBSZ = 2 * 16; // cell * bytes
			char[FPBSZ] fpbuf = void; // Value buffer
			int fplen = void;
			enum NBFSZ = 16; // "xmm_space[15]".length = 13
			char[NBFSZ] nmbuf = void; // Name buffer
			// x87
			for (size_t i; i < 8; ++i) {
				snprintf(nmbuf.ptr, NBFSZ, "st_space[%zu]", i);
				fplen = hexstr(fpbuf.ptr, FPBSZ, fregset.st_space128[i].data.ptr, 16);
				print_stringl(nmbuf.ptr, fpbuf.ptr, fplen);
			}
			// sse
			for (size_t i; i < 16; ++i) {
				snprintf(nmbuf.ptr, NBFSZ, "xmm_space[%zu]", i);
				fplen = hexstr(fpbuf.ptr, FPBSZ, fregset.st_space128[i].data.ptr, 16);
				print_stringl(nmbuf.ptr, fpbuf.ptr, fplen);
			}
			break;
		default:
		}
		
		// Adjust to next note header
		current += notesize;
	}
}

void dump_elf_sections(adbg_object_t *o) {
	print_header("Sections");
	
	int class_ = adbg_object_elf_class(o);
	
	enum SNMLEN = 32; /// Arbritrary maximum section name length
	uint i;
	switch (class_) {
	case ELF_CLASS_32:
		for (Elf32_Shdr *s = void; (s = adbg_object_elf_shdr32(o, i)) != null; ++i) {
			dump_elf_section32(s, i,
				adbg_object_elf_shdr32_name(o, s), SNMLEN);
		}
		break;
	case ELF_CLASS_64:
		for (Elf64_Shdr *s = void; (s = adbg_object_elf_shdr64(o, i)) != null; ++i) {
			dump_elf_section64(s, i,
				adbg_object_elf_shdr64_name(o, s), SNMLEN);
		}
		break;
	default:
		panic_adbg();
	}
}

void dump_elf_section32(Elf32_Shdr *shdr, uint idx, const(char)* name, int nmax) {
	with (shdr) {
	print_section(idx, name, nmax);
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
void dump_elf_section64(Elf64_Shdr *shdr, uint idx, const(char)* name, int nmax) {
	with (shdr) {
	print_section(idx, name, nmax);
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

//TODO: Section machine-specific flags (like SHF_X86_64_LARGE)

void dump_elf_exports(adbg_object_t *o) {
	adbg_section_t *dynsym = adbg_object_search_section_by_name(o, ".dynsym");
	if (dynsym == null)
		panic(1, ".dynsym section missing");
	adbg_section_t *dynstr = adbg_object_search_section_by_name(o, ".dynstr");
	if (dynstr == null)
		panic(1, ".dynstr section missing");
	
	print_header("Dynamic Symbols");
	
	//TODO: Interface for dynamic symbols
	
	switch (o.i.elf32.ehdr.e_ident[ELF_EI_CLASS]) {
	case ELF_CLASS_32:
		Elf32_Sym* entry = cast(Elf32_Sym*)dynsym.data;
		int count = cast(int)(dynsym.data_size / Elf32_Sym.sizeof);
		
		for (int i; i < count; ++i, ++entry) with (entry) {
			//TODO: Check bounds
			if (st_name + 1 >= dynstr.data_size) // +null
				panic(1, "Name outside dynstr section");
			print_section(i, "test");
			print_x32("st_name", st_name, cast(char*)dynstr.data + st_name);
			print_x8("st_info", st_info);
			print_x16("st_other", st_other);
			print_x32("st_shndx", st_shndx);
			print_x32("st_value", st_value);
			print_x32("st_size", st_size);
		}
		break;
	case ELF_CLASS_64:
		Elf64_Sym* entry = cast(Elf64_Sym*)dynsym.data;
		int count = cast(int)(dynsym.data_size / Elf64_Sym.sizeof);
		
		for (int i; i < count; ++i, ++entry) with (entry) {
			//TODO: Check bounds
			if (st_name + 1 >= dynstr.data_size) // +null
				panic(1, "Name outside dynstr section");
			print_section(i, "test");
			print_x32("st_name", st_name, cast(char*)dynstr.data + st_name);
			print_x8("st_info", st_info);
			print_x16("st_other", st_other);
			print_x64("st_shndx", st_shndx);
			print_x64("st_value", st_value);
			print_x64("st_size", st_size);
		}
		break;
	default:
	}
	
}

void dump_elf_disasm(adbg_object_t *o) {
	print_header("Disassembly");
	
	int all = SETTING(Setting.disasmAll); /// dump all
	
	switch (o.i.elf32.ehdr.e_ident[ELF_EI_CLASS]) {
	case ELF_CLASS_32:
		ushort section_count = o.i.elf32.ehdr.e_shnum;
		
		if (section_count == 0)
			return;
		
		// Check id is without section count
		ushort id = o.i.elf32.ehdr.e_shstrndx;
		if (id >= section_count)
			panic(1, "String table index out of bounds");
		
		Elf32_Shdr *shdr = o.i.elf32.shdr;
		uint offset = shdr[id].sh_offset;
		if (offset < Elf32_Ehdr.sizeof || offset > o.file_size)
			panic(1, "String table offset out of bounds");
		
		Elf32_Shdr *max = shdr + section_count;
		char *table = o.bufferc + offset; // string table
		while (shdr++ < max) with (shdr) {
			if (all || sh_flags & ELF_SHF_EXECINSTR)
				dump_disassemble_object(o,
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
		if (id >= section_count)
			panic(1, "String table index out of bounds");
		
		Elf64_Shdr *shdr = o.i.elf64.shdr;
		ulong offset = shdr[id].sh_offset;
		if (offset < Elf64_Ehdr.sizeof || offset > o.file_size)
			panic(1, "String table offset out of bounds");
		
		Elf64_Shdr *max = shdr + section_count;
		char *table = o.bufferc + offset; // string table
		while (shdr++ < max) with (shdr) {
			if (all || sh_flags & ELF_SHF_EXECINSTR)
				dump_disassemble_object(o,
					table + sh_name, 32,
					o.buffer8 + sh_offset, sh_size, 0);
		}
		break;
	default:
	}
}
