/**
 * ELF format.
 *
 * Sources:
 * - http://www.sco.com/developers/gabi/latest/ch4.eheader.html
 * - linux/include/uapi/linux/elf.h
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.obj.elf;

import adbg.error;
import adbg.obj.def;
import adbg.obj.server : adbg_object_t, AdbgObjFormat;
import adbg.disassembler : AdbgPlatform;

// NOTE: The string table section is typically named .shstrtab

// ELF32
private alias uint	Elf32_Addr;
private alias ushort	Elf32_Half;
private alias uint	Elf32_Off;
private alias int	Elf32_Sword;
private alias uint	Elf32_Word;

// ELF64
private alias ulong	Elf64_Addr;
private alias ushort	Elf64_Half;
private alias short	Elf64_SHalf;
private alias ulong	Elf64_Off;
private alias int	Elf64_Sword;
private alias uint	Elf64_Word;
private alias ulong	Elf64_Xword;
private alias long	Elf64_Sxword;

extern (C):

// Constants

enum ELF_EI_NIDENT	= 16;	/// Size of the initial pad (e_ident[])

// ELF Indexes

// 0..3 is "ELF\0" magic
enum ELF_EI_CLASS	= 4;	/// Class index
enum ELF_EI_DATA	= 5;	/// Data index
enum ELF_EI_VERSION	= 6;	/// File version index
enum ELF_EI_OSABI	= 7;	/// OS/ABI type index
enum ELF_EI_ABIVERSION	= 8;	/// ABI version index

// ELF Class identifiers

enum ELFCLASSNONE	= 0;	/// No class
enum ELFCLASS32	= 1;	/// 32-bit ELF
enum ELFCLASS64	= 2;	/// 64-bit ELF

// ELF Data identifiers

enum ELFDATANONE	= 0;	/// Invalid value
enum ELFDATA2LSB	= 1;	/// Little-endian
enum ELFDATA2MSB	= 2;	/// Big-endian

// ELF Version identifiers

enum ELF_EV_NONE	= 0;	/// No ELF version
enum ELF_EV_CURRENT	= 1;	/// ELF Version 1

// ELF OSABI identifiers

enum ELF_OSABI_NONE	= 0;	/// System V
enum ELF_OSABI_HPUX	= 1;	/// HP-UX
enum ELF_OSABI_NETBSD	= 2;	/// NetBSD
enum ELF_OSABI_GNU	= 3;	/// GNU
enum ELF_OSABI_LINUX	= ELF_OSABI_GNU;	/// Linux
enum ELF_OSABI_SOLARIS	= 6;	/// Solaris
enum ELF_OSABI_AIX	= 7;	/// AIX
enum ELF_OSABI_IRIX	= 8;	/// IRIX
enum ELF_OSABI_FREEBSD	= 9;	/// FreeBSD
enum ELF_OSABI_TRU64	= 10;	/// Compaq TRU64 UNIX
enum ELF_OSABI_MODESTO	= 11;	/// Novell Modesto
enum ELF_OSABI_OPENBSD	= 12;	/// OpenBSD
enum ELF_OSABI_OPENVMS	= 13;	/// OpenVMS
enum ELF_OSABI_NSK	= 14;	/// Hewlett-Packard Non-Stop Kernel
enum ELF_OSABI_AROS	= 15;	/// Amiga Research OS
enum ELF_OSABI_FENIXOS	= 16;	/// FenixOS
enum ELF_OSABI_CLOUDABI	= 17;	/// Nuxi CloudABI
enum ELF_OSABI_OPENVOS	= 18;	/// Stratus Technologies OpenVOS

// ELF Type values

enum ELF_ET_NONE	= 0;	/// No file type
enum ELF_ET_REL	= 1;	/// Relocatable file
enum ELF_ET_EXEC	= 2;	/// Executable file
enum ELF_ET_DYN	= 3;	/// Shared object file
enum ELF_ET_CORE	= 4;	/// Core file
enum ELF_ET_LOOS	= 0xFE00;	/// OS-specific
enum ELF_ET_HIOS	= 0xFEFF;	/// OS-specific
enum ELF_ET_LOPROC	= 0xFF00;	/// Processor-specific
enum ELF_ET_HIPROC	= 0xFFFF;	/// Processor-specific

// ELF Machine values
// FatELF also uses this

enum ELF_EM_NONE	= 0;	/// No machine
enum ELF_EM_M32	= 1;	/// AT&T WE 32100
enum ELF_EM_SPARC	= 2;	/// SPARC
enum ELF_EM_386	= 3;	/// Intel x86
enum ELF_EM_68K	= 4;	/// Motorola 68000
enum ELF_EM_88K	= 5;	/// Motorola 88000
enum ELF_EM_MCU	= 6;	/// Intel MCU
enum ELF_EM_860	= 7;	/// Intel 80860
enum ELF_EM_MIPS	= 8;	/// MIPS I (RS3000)
enum ELF_EM_S370	= 9;	/// IBM System/370
enum ELF_EM_MIPS_RS3_LE	= 10;	/// MIPS RS3000 Little-Endian
enum ELF_EM_PARISC	= 15;	/// Hewlett-Packard PA-RISC
enum ELF_EM_VPP500	= 17;	/// Fujitsu VPP500
enum ELF_EM_SPARC32PLUS	= 18;	/// Enhanced SPARC
enum ELF_EM_960	= 19;	/// Intel 80960
enum ELF_EM_PPC	= 20;	/// PowerPC
enum ELF_EM_PPC64	= 21;	/// 64-bit PowerPC
enum ELF_EM_S390	= 22;	/// IBM System/390
enum ELF_EM_SPU	= 23;	/// IBM SPU/SPC
enum ELF_EM_V800	= 36;	/// NEC V800
enum ELF_EM_FR20	= 37;	/// Fujitsu FR20
enum ELF_EM_RH32	= 38;	/// TRW
enum ELF_EM_RCE	= 39;	/// Motorola RCE
enum ELF_EM_ARM	= 40;	/// ARM 32-bit
enum ELF_EM_ALPHA	= 41;	/// DEC Alpha
enum ELF_EM_SH	= 42;	/// Hitachi SuperH
enum ELF_EM_SPARCV9	= 43;	/// SPARC Version 9
enum ELF_EM_TRICORE	= 44;	/// Siemens TriCore embedded
enum ELF_EM_ARC	= 45;	/// Argonaut RISC Core
enum ELF_EM_H8_300	= 46;	/// Hitachi H8/300
enum ELF_EM_H8_300H	= 47;	/// Hitachi H8/300H
enum ELF_EM_H8S	= 48;	/// Hitachi H8S
enum ELF_EM_H8_500	= 49;	/// Hitachi H8/500
enum ELF_EM_IA_64	= 50;	/// Intel Itanium Architecture 64
enum ELF_EM_MIPS_X	= 51;	/// Stanford MIPS-X
enum ELF_EM_COLDFIRE	= 52;	/// Motorola ColdFire
enum ELF_EM_68HC12	= 53;	/// Motorola M68HC12
enum ELF_EM_MMA	= 54;	/// Fujitsu MMA Multimedia Accelerator
enum ELF_EM_PCP = 55;	/// Siemens PCP
enum ELF_EM_NCPU	= 56;	/// Sony nCPU embedded RISC
enum ELF_EM_NDR1	= 57;	/// Denso NDR1
enum ELF_EM_STARCODE	= 58;	/// Motorola Star*Core
enum ELF_EM_ME16	= 59;	/// Toyota ME16
enum ELF_EM_ST100	= 60;	/// STMicroelectronics ST100
enum ELF_EM_TINYJ	= 61;	/// Advanced Logic Corp. TinyJ
enum ELF_EM_X86_64	= 62;	/// AMD x86-64
enum ELF_EM_PDSP	= 63;	/// Sony DSP
enum ELF_EM_PDP10	= 64;	/// DEC PDP-10
enum ELF_EM_PDP11	= 65;	/// DEC PDP-11
enum ELF_EM_FX66	= 66;	/// Siemens FX66
enum ELF_EM_ST9PLUS	= 67;	/// STMicroelectronics ST9+ (8/16-bit)
enum ELF_EM_ST7	= 68;	/// STMicroelectronics ST7 (8-bit)
enum ELF_EM_68HC16	= 69;	/// Motorola 68HC16
enum ELF_EM_68HC11	= 70;	/// Motorola 68HC11
enum ELF_EM_68HC08	= 71;	/// Motorola 68HC08
enum ELF_EM_68HC05	= 72;	/// Motorola 68HC05
enum ELF_EM_SVX	= 73;	/// Silicon Graphics SVx
enum ELF_EM_ST19	= 74;	/// STMicroelectronics ST19 (8-bit)
enum ELF_EM_VAX	= 75;	/// DEC VAX
enum ELF_EM_CRIS	= 76;	/// Axis Communications (32-bit)
enum ELF_EM_JAVELIN	= 77;	/// Infineon Technologies (32-bit)
enum ELF_EM_FIREPATH	= 78;	/// Element 14 DSP (64-bit)
enum ELF_EM_ZSP	= 79;	/// LSI Logic DSP (16-bit)
enum ELF_EM_MMIX	= 80;	/// Donald Knuth's educational processor (64-bit)
enum ELF_EM_HUANY	= 81;	/// Harvard University machine-independent object files
enum ELF_EM_PRISM	= 82;	/// SiTera Prism
enum ELF_EM_AVR	= 83;	/// Atmel AVR (8-bit)
enum ELF_EM_FR30	= 84;	/// Fujitsu FR30
enum ELF_EM_D10V	= 85;	/// Mitsubishi D10V
enum ELF_EM_D30V	= 86;	/// Mitsubishi D30V
enum ELF_EM_V850	= 87;	/// NEC V850
enum ELF_EM_M32R	= 88;	/// Mitsubishi M32R
enum ELF_EM_MN10300	= 89;	/// Mitsubishi MN10300
enum ELF_EM_MN10200	= 90;	/// Mitsubishi MN10200
enum ELF_EM_PJ	= 91;	/// picoJava
enum ELF_EM_OPENRISC	= 92;	/// OpenRISC (32-bit)
enum ELF_EM_ARC_COMPACT	= 93;	/// ARC International ARCompact
enum ELF_EM_XTENSA	= 94;	/// Tensilica Xtensa Architecture
enum ELF_EM_VIDEOCORE	= 95;	/// Alphamosaic VideoCore
enum ELF_EM_TMM_GPP	= 96;	/// Thompson Multimedia General Purpose
enum ELF_EM_NS32K	= 97;	/// National Semiconductor 32000
enum ELF_EM_TPC	= 98;	/// Tenor Network TPC
enum ELF_EM_SNP1K	= 99;	/// Trebia SNP 1000
enum ELF_EM_ST200	= 100;	/// STMicroelectronics ST200
enum ELF_EM_IP2K	= 101;	/// Ubicom IP2xxx
enum ELF_EM_MAX	= 102;	/// MAX
enum ELF_EM_CR	= 103;	/// National Semiconductor CompactRISC
enum ELF_EM_F2MC16	= 104;	/// Fujitsu F2MC16
enum ELF_EM_MSP430	= 105;	/// Texas Instruments MSP430
enum ELF_EM_BLACKFIN	= 106;	/// Analog Devices Blackfin DSP
enum ELF_EM_SE_C33	= 107;	/// Seiko Epson S1C33
enum ELF_EM_SEP	= 108;	/// Sharp
enum ELF_EM_ARCA	= 109;	/// Arca RISC
enum ELF_EM_UNICORE	= 110;	/// PKU-Unity/Pekin Unicore
enum ELF_EM_EXCESS	= 111;	/// eXcess (16/32/64-bit)
enum ELF_EM_DXP	= 112;	/// Icera Semiconductor Inc. Deep Execution
enum ELF_EM_ALTERA_NIOS2	= 113;	/// Altera Nios II soft-core
enum ELF_EM_CRX	= 114;	/// national Semiconductor CompactRISC CRX
enum ELF_EM_XGATE	= 115;	/// Motorola XGATE
enum ELF_EM_C116	= 116;	/// Infineon C16x/XC16x
enum ELF_EM_M16C	= 117;	/// Renesas M32C
enum ELF_EM_DSPIC30F	= 118;	/// Microchip Technology DSPIC30F
enum ELF_EM_CE	= 119;	/// Freescale Communication Engine RISC
enum ELF_EM_M32C	= 120;	/// Renesas M32C
enum ELF_EM_TSK3000	= 131;	/// Altium TSK3000
enum ELF_EM_RS08	= 132;	/// Freescale RS08
enum ELF_EM_SHARC	= 133;	/// SHARC (32-bit)
enum ELF_EM_ECOG2	= 134;	/// Cyan Technology eCOG2
enum ELF_EM_SCORE7	= 135;	/// Sunplus S+core7 RISC
enum ELF_EM_DSP24	= 136;	/// New Japan Radio (NJR) DSP (24-bit)
enum ELF_EM_VIDEOCORE3	= 137;	/// Broadcom VideoCore III
enum ELF_EM_LATTICEMICO32	= 138;	/// Lattice FPGA
enum ELF_EM_SE_C17	= 139;	/// Seiko Epson C17
enum ELF_EM_TI_C6000	= 140;	/// Texas Instruments TMS320C6000
enum ELF_EM_TI_C2000	= 141;	/// Texas Instruments TMS320C2000
enum ELF_EM_TI_C5500	= 142;	/// Texas Instruments TMS320C55xx
enum ELF_EM_TI_ARP32	= 143;	/// Texas Instruments Application Specific RISC (32-bit)
enum ELF_EM_TI_PRU	= 144;	/// Texas Instruments Programmable Realtime Unit
enum ELF_EM_MMDSP_PLUS	= 160;	/// STMicroelectronics VLIW DSP (64-bit)
enum ELF_EM_CYPRESS_M8C	= 161;	/// Cypress M8C
enum ELF_EM_R32C	= 162;	/// Renesas R32C
enum ELF_EM_TRIMEDIA	= 163;	/// NXP Semiconductors TriMedia
enum ELF_EM_QDSP6	= 164;	/// QUALCOMM DSP6
enum ELF_EM_8051	= 165;	/// Intel 8051
enum ELF_EM_STXP7X	= 166;	/// STMicroelectronics STxP7x
enum ELF_EM_NDS32	= 167;	/// Andes Technology RISC
enum ELF_EM_ECOG1X	= 168;	/// Cyan Technology eCOG1X
enum ELF_EM_MAXQ30	= 169;	/// Dallas Semiconductor MAXQ30
enum ELF_EM_XIMO16	= 170;	/// New Japan Radio (NJR) DSP (16-bit)
enum ELF_EM_MANIK	= 171;	/// M2000 Reconfigurable RISC
enum ELF_EM_CRAYNV2	= 172;	/// Cray Inc. NV2
enum ELF_EM_RX	= 173;	/// Renesas RX
enum ELF_EM_METAG	= 174;	/// Imagination Technologies META
enum ELF_EM_MCST_ELBRUS	= 175;	/// MCST Elbrus general purpose hardware
enum ELF_EM_ECOG16	= 176;	/// Cyan Technology eCOG16
enum ELF_EM_CR16	= 177;	/// National Semiconductor CompactRISC CR16 (16-bit)
enum ELF_EM_ETPU	= 178;	/// Freescale Extended Time Processing Unit
enum ELF_EM_SLE9X	= 179;	/// Infineon Technologies SLE9X
enum ELF_EM_L10M	= 180;	/// Intel L10M
enum ELF_EM_K10M	= 181;	/// Intel K10M
enum ELF_EM_AARCH64	= 183;	/// ARM (64-bit)
enum ELF_EM_AVR32	= 185;	/// Atmel Corporation (32-bit)
enum ELF_EM_STM8	= 186;	/// STMicroeletronics STM8 (8-bit)
enum ELF_EM_TILE64	= 187;	/// Tilera TILE64
enum ELF_EM_TILEPRO	= 188;	/// Tilera TILEPro
enum ELF_EM_MICROBLAZE	= 189;	/// Xilinx MicroBlaze RISC soft core (32-bit)
enum ELF_EM_CUDA	= 190;	/// NVIDIA CUDA
enum ELF_EM_TILEGX	= 191;	/// Tilera TILE-Gx
enum ELF_EM_CLOUDSHIELD	= 192;	/// CloudShield
enum ELF_EM_COREA_1ST	= 193;	/// KIPO-KAIST Core-A 1st generation
enum ELF_EM_COREA_2ND	= 194;	/// KIPO-KAIST Core-A 2nd generation
enum ELF_EM_ARC_COMPACT2	= 195;	/// Synopsys ARCompact V2
enum ELF_EM_OPEN8	= 196;	/// Open8 RISC soft core (8-bit)
enum ELF_EM_RL78	= 197;	/// Renesas RL78
enum ELF_EM_VIDEOCORE5	= 198;	/// Broadcom VideoCore V
enum ELF_EM_78KOR	= 199;	/// Renesas 78KOR
enum ELF_EM_56800EX	= 200;	/// Freescale 56800EX DSC
enum ELF_EM_BA1	= 201;	/// Beyond BA1
enum ELF_EM_BA2	= 202;	/// Beyond BA2
enum ELF_EM_XCORE	= 203;	/// XMOS xCORE
enum ELF_EM_MCHP_PIC	= 204;	/// Microchip PIC(r) (8-bit)
enum ELF_EM_INTEL205	= 205;	/// Reserved by Intel
enum ELF_EM_INTEL206	= 206;	/// Reserved by Intel
enum ELF_EM_INTEL207	= 207;	/// Reserved by Intel
enum ELF_EM_INTEL208	= 208;	/// Reserved by Intel
enum ELF_EM_INTEL209	= 209;	/// Reserved by Intel
enum ELF_EM_KM32	= 210;	/// KM211 KM32 (32-bit)
enum ELF_EM_KMX32	= 211;	/// KM211 KMX32 (32-bit)
enum ELF_EM_KMX16	= 212;	/// KM211 KMX16 (16-bit)
enum ELF_EM_KMX8	= 213;	/// KM211 KMX8 (8-bit)
enum ELF_EM_KVARC	= 214;	/// KM211 KVARC
enum ELF_EM_CDP	= 215;	/// Paneve CDP
enum ELF_EM_COGE	= 216;	/// Cognitive Smart Memory
enum ELF_EM_COOL	= 217;	/// Bluechip Systems
enum ELF_EM_NORC	= 218;	/// Nanoradio Optimized RISC
enum ELF_EM_CSR_KALIMBA	= 219;	/// CSR Kalimba
enum ELF_EM_Z80	= 220;	/// Zilog Z80
enum ELF_EM_VISIUM	= 221;	/// VISIUMcore
enum ELF_EM_FT32	= 222;	/// FTDI Chip FT32 RISC (32-bit)
enum ELF_EM_MOXIE	= 223;	/// Moxie
enum ELF_EM_AMDGPU	= 224;	/// AMD GPU
enum ELF_EM_RISCV	= 225;	/// RISC-V

// Section type values

enum ELF_SHT_NULL	= 0;	/// Inactive
enum ELF_SHT_PROGBITS	= 1;	/// Program bits
enum ELF_SHT_SYMTAB	= 2;	/// Symbol table
enum ELF_SHT_STRTAB	= 3;	/// String table
enum ELF_SHT_RELA	= 4;	/// Relocation entries (with addends)
enum ELF_SHT_HASH	= 5;	/// Symbol hash table
enum ELF_SHT_DYNAMIC	= 6;	/// Dynamic linking information
enum ELF_SHT_NOTE	= 7;	/// File information
enum ELF_SHT_NOBITS	= 8;	/// Empty section
enum ELF_SHT_REL	= 9;	/// Relocation entries (without addends)
enum ELF_SHT_SHLIB	= 10;	/// Reserved
enum ELF_SHT_DYNSYM	= 11;	/// Dynamic symbol table
enum ELF_SHT_INIT_ARRAY	= 12;	/// Array of pointers to initialization functions
enum ELF_SHT_FINI_ARRAY	= 13;	/// Array of pointers to termination functions
enum ELF_SHT_PREINIT_ARRAY	= 14;	/// Array of pointers to pre-initialization functions
enum ELF_SHT_GROUP	= 15;	/// Section group
enum ELF_SHT_SYNTAB_SHNDX	= 16;	/// Symbol table pointed by e_shstrndx
enum ELF_SHT_LOOS	= 0x60000000;	/// Operating system specific
enum ELF_SHT_HIOS	= 0x6fffffff;	/// Operating system specific
enum ELF_SHT_LOPROC	= 0x70000000;	/// Processor specific
enum ELF_SHT_HIPROC	= 0x7fffffff;	/// Processor specific
enum ELF_SHT_LOUSER	= 0x80000000;	/// Application specific
enum ELF_SHT_HIUSER	= 0xffffffff;	/// Application specific

// Section flags

enum ELF_SHF_WRITE	= 0x1;	/// Section should be writable
enum ELF_SHF_ALLOC	= 0x2;	/// Section occupies memory during executing
enum ELF_SHF_EXECINSTR	= 0x4;	/// Section contains executable machine instructions
enum ELF_SHF_MERGE	= 0x10;	/// Section may be merged to eleminate duplication
enum ELF_SHF_STRINGS	= 0x20;	/// Section is string table
enum ELF_SHF_INFO_LINK	= 0x40;	/// sh_info field in this section holds a section header table value
enum ELF_SHF_LINK_ORDER	= 0x80;	/// Adds special ordering for link editors
enum ELF_SHF_OS_NONCONFORMING	= 0x100;	/// OS-specific
enum ELF_SHF_GROUP	= 0x200;	/// Section is part of a group
enum ELF_SHF_TLS	= 0x400;	/// Section contains Thread Local Storage data
enum ELF_SHF_COMPRESSED	= 0x800;	/// Section is compressed
enum ELF_SHF_MASKOS	= 0x0ff00000;	/// OS-specific
enum ELF_SHF_MASKPROC	= 0xf0000000;	/// Processor-specific

//
// ELF32 meta
//

/// ELF32 header structure
struct Elf32_Ehdr {
	ubyte[ELF_EI_NIDENT] e_ident;	/// Identification bytes
	Elf32_Half e_type;	/// Object file type
	Elf32_Half e_machine;	/// Object file machine
	Elf32_Word e_version;	/// Object version
	Elf32_Addr e_entry;	/// Object entry address
	Elf32_Off  e_phoff;	/// Program header offset
	Elf32_Off  e_shoff;	/// Section header offset
	Elf32_Word e_flags;	/// Architecture flags
	Elf32_Half e_ehsize;	/// Header size in bytes
	Elf32_Half e_phentsize;	/// Program header size
	Elf32_Half e_phnum;	/// Number of entries in the program header table
	Elf32_Half e_shentsize;	/// Section header size
	Elf32_Half e_shnum;	/// Number of entries in the section header table
	Elf32_Half e_shstrndx;	/// Index of the section header table entry that has section names
}

/// Program 32-bit header
struct Elf32_Phdr {
	Elf32_Word p_type;	/// Segment type
	Elf32_Off  p_offset;	/// Segment file offset
	Elf32_Addr p_vaddr;	/// Segment virtual address
	Elf32_Addr p_paddr;	/// Segment physical address
	Elf32_Word p_filesz;	/// Segment size in file
	Elf32_Word p_memsz;	/// Segment size in memory
	Elf32_Word p_flags;	
	Elf32_Word p_align;	/// Segment alignment, file & memory
}

/// Section 32-bit header
struct Elf32_Shdr {
	Elf32_Word sh_name;	/// Section name, index in string table
	Elf32_Word sh_type;	/// Type of section
	Elf32_Word sh_flags;	/// Miscellaneous section attributes
	Elf32_Addr sh_addr;	/// Section virtual addr at execution
	Elf32_Off  sh_offset;	/// Section file offset
	Elf32_Word sh_size;	/// Size of section in bytes
	Elf32_Word sh_link;	/// Index of another section
	Elf32_Word sh_info;	/// Additional section information
	Elf32_Word sh_addralign;	/// Section alignment
	Elf32_Word sh_entsize;	/// Entry size if section holds table
}

/// Note 32-bit header
struct Elf32_Nhdr {
	Elf32_Word n_namesz;	/// Name size
	Elf32_Word n_descsz;	/// Content size
	Elf32_Word n_type;	/// Content type
}

struct Elf32_Dyn {
	Elf32_Sword d_tag;
	union {
		Elf32_Sword d_val;
		Elf32_Addr  d_ptr;
	}
}

struct Elf32_Rel {
	Elf32_Addr r_offset;
	Elf32_Word r_info;
}

struct Elf32_Rela {
	Elf32_Addr  r_offset;
	Elf32_Word  r_info;
	Elf32_Sword r_addend;
}

struct Elf32_Sym {
	Elf32_Word st_name;
	Elf32_Addr st_value;
	Elf32_Word st_size;
	ubyte      st_info;
	ubyte      st_other;
	Elf32_Half st_shndx;
}

/// ELF32 Compressed header
struct Elf32_Chdr {
	Elf32_Word ch_type;	/// Compression algorithm
	Elf32_Word ch_size;	/// Uncompressed data size
	Elf32_Word ch_addralign;	/// Uncompressed data alignment
}

//
// ELF64 meta
//

/// ELF64 header structure
struct Elf64_Ehdr {
	ubyte[ELF_EI_NIDENT] e_ident;	/// Identification bytes
	Elf64_Half e_type;	/// Object file type
	Elf64_Half e_machine;	/// Object file machine
	Elf64_Word e_version;	/// Object version
	Elf64_Addr e_entry;	/// Object entry address
	Elf64_Off  e_phoff;	/// Program header offset
	Elf64_Off  e_shoff;	/// Section header offset
	Elf64_Word e_flags;	/// Architecture flags
	Elf64_Half e_ehsize;	/// Header size in bytes
	Elf64_Half e_phentsize;	/// Program header size
	Elf64_Half e_phnum;	/// Number of entries in the program header table
	Elf64_Half e_shentsize;	/// Section header size
	Elf64_Half e_shnum;	/// Number of entries in the section header table
	Elf64_Half e_shstrndx;	/// Index of the section header table entry that has section names
}

/// Program 64-bit header
struct Elf64_Phdr {
	Elf64_Word  p_type;	/// Segment type
	Elf64_Word  p_flags;	/// Segment flags
	Elf64_Off   p_offset;	/// Segment file offset
	Elf64_Addr  p_vaddr;	/// Segment virtual address
	Elf64_Addr  p_paddr;	/// Segment physical address
	Elf64_Xword p_filesz;	/// Segment size in file
	Elf64_Xword p_memsz;	/// Segment size in memory
	Elf64_Xword p_align;	/// Segment alignment, file & memory
}

/// Section 64-bit header
struct Elf64_Shdr {
	Elf64_Word  sh_name;	/// Section name, index in string table
	Elf64_Word  sh_type;	/// Type of section
	Elf64_Xword sh_flags;	/// Miscellaneous section attributes
	Elf64_Addr  sh_addr;	/// Section virtual addr at execution
	Elf64_Off   sh_offset;	/// Section file offset
	Elf64_Xword sh_size;	/// Size of section in bytes
	Elf64_Word  sh_link;	/// Index of another section
	Elf64_Word  sh_info;	/// Additional section information
	Elf64_Xword sh_addralign;	/// Section alignment
	Elf64_Xword sh_entsize;	/// Entry size if section holds table
}

/// Note 64-bit header
struct Elf64_Nhdr {
	Elf64_Word n_namesz;	/// Name size
	Elf64_Word n_descsz;	/// Content size
	Elf64_Word n_type;	/// Content type
}

struct Elf64_Dyn {
	Elf64_Sxword d_tag;
	union {
		Elf64_Xword d_val;
		Elf64_Addr  d_ptr;
	}
}

struct Elf64_Rel {
	Elf64_Addr  r_offset;	/// Location at which to apply the action
	Elf64_Xword r_info;	/// Index and type of relocation
}

struct Elf64_Rela {
	Elf32_Addr  offset;
	Elf32_Word  info;
	Elf32_Sword addend;
}

/// ELF64 Compressed header
struct Elf64_Chdr {
	Elf64_Word  ch_type;	/// Compression algorithm
	Elf64_Word  ch_reserved;	/// Reserved, obviously
	Elf64_Xword ch_size;	/// Uncompressed size
	Elf64_Xword ch_addralign;	/// Uncompressed alignment
}

//
// Functions
//

int adbg_obj_elf_preload(adbg_object_t *obj) {
	obj.format = AdbgObjFormat.ELF;
	obj.elf.hdr32 = cast(Elf32_Ehdr*)obj.buf;
	
	ubyte e_class = obj.elf.hdr32.e_ident[ELF_EI_CLASS];
	
	switch (e_class) {
	case ELFCLASS32:
		obj.elf.phdr32 = cast(Elf32_Phdr*)(obj.buf + obj.elf.hdr32.e_phoff);
		obj.elf.shdr32 = cast(Elf32_Shdr*)(obj.buf + obj.elf.hdr32.e_shoff);
		break;
	case ELFCLASS64:
		obj.elf.phdr64 = cast(Elf64_Phdr*)(obj.buf + obj.elf.hdr64.e_phoff);
		obj.elf.shdr64 = cast(Elf64_Shdr*)(obj.buf + obj.elf.hdr64.e_shoff);
		break;
	default:
		return adbg_oops(AdbgError.invalidObjClass);
	}
	
	ushort e_machine = obj.elf.hdr32.e_machine;
	
	with (obj)
	with (AdbgPlatform)
	switch (e_machine) {
	case ELF_EM_386: platform = x86_32; break;
	case ELF_EM_X86_64: platform = x86_64; break;
	case ELF_EM_RISCV:
		switch (e_class) {
		case ELFCLASS32: platform = riscv32; break;
		default:
		}
		break;
	default:
	}
	
	return 0;
}

const(char) *adbg_obj_elf_class(ubyte c) {
	switch (c) {
	case ELFCLASS32: return "ELF32";
	case ELFCLASS64: return "ELF64";
	default: return null;
	}
}

const(char) *adbg_obj_elf_data(ubyte d) {
	switch (d) {
	case ELFDATA2LSB: return "LSB";
	case ELFDATA2MSB: return "MSB";
	default: return null;
	}
}

const(char) *adbg_obj_elf_osabi(ubyte o) {
	switch (o) {
	case ELF_OSABI_NONE:	return "NONE";
	case ELF_OSABI_HPUX:	return "HPUX";
	case ELF_OSABI_NETBSD:	return "NETBSD";
	case ELF_OSABI_GNU:	return "GNU";
	case ELF_OSABI_SOLARIS:	return "SOLARIS";
	case ELF_OSABI_AIX:	return "AIX";
	case ELF_OSABI_IRIX:	return "IRIX";
	case ELF_OSABI_FREEBSD:	return "FREEBSD";
	case ELF_OSABI_TRU64:	return "TRU64";
	case ELF_OSABI_MODESTO:	return "MODESTO";
	case ELF_OSABI_OPENBSD:	return "OPENBSD";
	case ELF_OSABI_OPENVMS:	return "OPENVMS";
	case ELF_OSABI_NSK:	return "NSK";
	case ELF_OSABI_AROS:	return "AROS";
	case ELF_OSABI_FENIXOS:	return "FENIXOS";
	case ELF_OSABI_CLOUDABI:	return "CLOUDABI";
	case ELF_OSABI_OPENVOS:	return "OPENVOS";
	default: return null;
	}
}

const(char) *adbg_obj_elf_type(ushort t) {
	switch (t) {
	case ELF_ET_NONE:	return "NONE";
	case ELF_ET_REL:	return "REL";
	case ELF_ET_EXEC:	return "EXEC";
	case ELF_ET_DYN:	return "DYN";
	case ELF_ET_CORE:	return "CORE";
	case ELF_ET_LOOS:	return "LOOS";
	case ELF_ET_HIOS:	return "HIOS";
	case ELF_ET_LOPROC:	return "LOPROC";
	case ELF_ET_HIPROC:	return "HIPROC";
	default: return null;
	}
}

const(char) *adbg_obj_elf_machine(ushort m) {
	switch (m) {
	case ELF_EM_NONE:	return OBJ_MACH_NONE;
	case ELF_EM_M32:	return OBJ_MACH_M32;
	case ELF_EM_SPARC:	return OBJ_MACH_SPARC;
	case ELF_EM_386:	return OBJ_MACH_386;
	case ELF_EM_68K:	return OBJ_MACH_68K;
	case ELF_EM_88K:	return OBJ_MACH_88K;
	case ELF_EM_MCU:	return OBJ_MACH_MCU;
	case ELF_EM_860:	return OBJ_MACH_860;
	case ELF_EM_MIPS:	return OBJ_MACH_MIPS;
	case ELF_EM_S370:	return OBJ_MACH_S370;
	case ELF_EM_MIPS_RS3_LE:	return OBJ_MACH_MIPS_RS3_LE;
	case ELF_EM_PARISC:	return OBJ_MACH_PARISC;
	case ELF_EM_VPP500:	return OBJ_MACH_VPP500;
	case ELF_EM_SPARC32PLUS:	return OBJ_MACH_SPARC32PLUS;
	case ELF_EM_960:	return OBJ_MACH_960;
	case ELF_EM_PPC:	return OBJ_MACH_PPC;
	case ELF_EM_PPC64:	return OBJ_MACH_PPC64;
	case ELF_EM_S390:	return OBJ_MACH_S390;
	case ELF_EM_SPU:	return OBJ_MACH_SPU;
	case ELF_EM_V800:	return OBJ_MACH_V800;
	case ELF_EM_FR20:	return OBJ_MACH_FR20;
	case ELF_EM_RH32:	return OBJ_MACH_RH32;
	case ELF_EM_RCE:	return OBJ_MACH_RCE;
	case ELF_EM_ARM:	return OBJ_MACH_ARM;
	case ELF_EM_ALPHA:	return OBJ_MACH_ALPHA;
	case ELF_EM_SH:	return OBJ_MACH_SH;
	case ELF_EM_SPARCV9:	return OBJ_MACH_SPARCV9;
	case ELF_EM_TRICORE:	return OBJ_MACH_TRICORE;
	case ELF_EM_ARC:	return OBJ_MACH_ARC;
	case ELF_EM_H8_300:	return OBJ_MACH_H8_300;
	case ELF_EM_H8_300H:	return OBJ_MACH_H8_300H;
	case ELF_EM_H8S:	return OBJ_MACH_H8S;
	case ELF_EM_H8_500:	return OBJ_MACH_H8_500;
	case ELF_EM_IA_64:	return OBJ_MACH_IA64;
	case ELF_EM_MIPS_X:	return OBJ_MACH_MIPS_X;
	case ELF_EM_COLDFIRE:	return OBJ_MACH_COLDFIRE;
	case ELF_EM_68HC12:	return OBJ_MACH_68HC12;
	case ELF_EM_MMA:	return OBJ_MACH_MMA;
	case ELF_EM_PCP:	return OBJ_MACH_PCP;
	case ELF_EM_NCPU:	return OBJ_MACH_NCPU;
	case ELF_EM_NDR1:	return OBJ_MACH_NDR1;
	case ELF_EM_STARCODE:	return OBJ_MACH_STARCODE;
	case ELF_EM_ME16:	return OBJ_MACH_ME16;
	case ELF_EM_ST100:	return OBJ_MACH_ST100;
	case ELF_EM_TINYJ:	return OBJ_MACH_TINYJ;
	case ELF_EM_X86_64:	return OBJ_MACH_X86_64;
	case ELF_EM_PDSP:	return OBJ_MACH_PDSP;
	case ELF_EM_PDP10:	return OBJ_MACH_PDP10;
	case ELF_EM_PDP11:	return OBJ_MACH_PDP11;
	case ELF_EM_FX66:	return OBJ_MACH_FX66;
	case ELF_EM_ST9PLUS:	return OBJ_MACH_ST9PLUS;
	case ELF_EM_ST7:	return OBJ_MACH_ST7;
	case ELF_EM_68HC16:	return OBJ_MACH_68HC16;
	case ELF_EM_68HC11:	return OBJ_MACH_68HC11;
	case ELF_EM_68HC08:	return OBJ_MACH_68HC08;
	case ELF_EM_68HC05:	return OBJ_MACH_68HC05;
	case ELF_EM_SVX:	return OBJ_MACH_SVX;
	case ELF_EM_ST19:	return OBJ_MACH_ST19;
	case ELF_EM_VAX:	return OBJ_MACH_VAX;
	case ELF_EM_CRIS:	return OBJ_MACH_CRIS;
	case ELF_EM_JAVELIN:	return OBJ_MACH_JAVELIN;
	case ELF_EM_FIREPATH:	return OBJ_MACH_FIREPATH;
	case ELF_EM_ZSP:	return OBJ_MACH_ZSP;
	case ELF_EM_MMIX:	return OBJ_MACH_MMIX;
	case ELF_EM_HUANY:	return OBJ_MACH_HUANY;
	case ELF_EM_PRISM:	return OBJ_MACH_PRISM;
	case ELF_EM_AVR:	return OBJ_MACH_AVR;
	case ELF_EM_FR30:	return OBJ_MACH_FR30;
	case ELF_EM_D10V:	return OBJ_MACH_D10V;
	case ELF_EM_D30V:	return OBJ_MACH_D30V;
	case ELF_EM_V850:	return OBJ_MACH_V850;
	case ELF_EM_M32R:	return OBJ_MACH_M32R;
	case ELF_EM_MN10300:	return OBJ_MACH_MN10300;
	case ELF_EM_MN10200:	return OBJ_MACH_MN10200;
	case ELF_EM_PJ:	return OBJ_MACH_PJ;
	case ELF_EM_OPENRISC:	return OBJ_MACH_OPENRISC;
	case ELF_EM_ARC_COMPACT:	return OBJ_MACH_ARC_COMPACT;
	case ELF_EM_XTENSA:	return OBJ_MACH_XTENSA;
	case ELF_EM_VIDEOCORE:	return OBJ_MACH_VIDEOCORE;
	case ELF_EM_TMM_GPP:	return OBJ_MACH_TMM_GPP;
	case ELF_EM_NS32K:	return OBJ_MACH_NS32K;
	case ELF_EM_TPC:	return OBJ_MACH_TPC;
	case ELF_EM_SNP1K:	return OBJ_MACH_SNP1K;
	case ELF_EM_ST200:	return OBJ_MACH_ST200;
	case ELF_EM_IP2K:	return OBJ_MACH_IP2K;
	case ELF_EM_MAX:	return OBJ_MACH_MAX;
	case ELF_EM_CR:	return OBJ_MACH_CR;
	case ELF_EM_F2MC16:	return OBJ_MACH_F2MC16;
	case ELF_EM_MSP430:	return OBJ_MACH_MSP430;
	case ELF_EM_BLACKFIN:	return OBJ_MACH_BLACKFIN;
	case ELF_EM_SE_C33:	return OBJ_MACH_SE_C33;
	case ELF_EM_SEP:	return OBJ_MACH_SEP;
	case ELF_EM_ARCA:	return OBJ_MACH_ARCA;
	case ELF_EM_UNICORE:	return OBJ_MACH_UNICORE;
	case ELF_EM_EXCESS:	return OBJ_MACH_EXCESS;
	case ELF_EM_DXP:	return OBJ_MACH_DXP;
	case ELF_EM_ALTERA_NIOS2:	return OBJ_MACH_ALTERA_NIOS2;
	case ELF_EM_CRX:	return OBJ_MACH_CRX;
	case ELF_EM_XGATE:	return OBJ_MACH_XGATE;
	case ELF_EM_C116:	return OBJ_MACH_C116;
	case ELF_EM_M16C:	return OBJ_MACH_M16C;
	case ELF_EM_DSPIC30F:	return OBJ_MACH_DSPIC30F;
	case ELF_EM_CE:	return OBJ_MACH_CE;
	case ELF_EM_M32C:	return OBJ_MACH_M32C;
	case ELF_EM_TSK3000:	return OBJ_MACH_TSK3000;
	case ELF_EM_RS08:	return OBJ_MACH_RS08;
	case ELF_EM_SHARC:	return OBJ_MACH_SHARC;
	case ELF_EM_ECOG2:	return OBJ_MACH_ECOG2;
	case ELF_EM_SCORE7:	return OBJ_MACH_SCORE7;
	case ELF_EM_DSP24:	return OBJ_MACH_DSP24;
	case ELF_EM_VIDEOCORE3:	return OBJ_MACH_VIDEOCORE3;
	case ELF_EM_LATTICEMICO32:	return OBJ_MACH_LATTICEMICO32;
	case ELF_EM_SE_C17:	return OBJ_MACH_SE_C17;
	case ELF_EM_TI_C6000:	return OBJ_MACH_TI_C6000;
	case ELF_EM_TI_C2000:	return OBJ_MACH_TI_C2000;
	case ELF_EM_TI_C5500:	return OBJ_MACH_TI_C5500;
	case ELF_EM_TI_ARP32:	return OBJ_MACH_TI_ARP32;
	case ELF_EM_TI_PRU:	return OBJ_MACH_TI_PRU;
	case ELF_EM_MMDSP_PLUS:	return OBJ_MACH_MMDSP_PLUS;
	case ELF_EM_CYPRESS_M8C:	return OBJ_MACH_CYPRESS_M8C;
	case ELF_EM_R32C:	return OBJ_MACH_R32C;
	case ELF_EM_TRIMEDIA:	return OBJ_MACH_TRIMEDIA;
	case ELF_EM_QDSP6:	return OBJ_MACH_QDSP6;
	case ELF_EM_8051:	return OBJ_MACH_8051;
	case ELF_EM_STXP7X:	return OBJ_MACH_STXP7X;
	case ELF_EM_NDS32:	return OBJ_MACH_NDS32;
	case ELF_EM_ECOG1X:	return OBJ_MACH_ECOG1X;
	case ELF_EM_MAXQ30:	return OBJ_MACH_MAXQ30;
	case ELF_EM_XIMO16:	return OBJ_MACH_XIMO16;
	case ELF_EM_MANIK:	return OBJ_MACH_MANIK;
	case ELF_EM_CRAYNV2:	return OBJ_MACH_CRAYNV2;
	case ELF_EM_RX:	return OBJ_MACH_RX;
	case ELF_EM_METAG:	return OBJ_MACH_METAG;
	case ELF_EM_MCST_ELBRUS:	return OBJ_MACH_MCST_ELBRUS;
	case ELF_EM_ECOG16:	return OBJ_MACH_ECOG16;
	case ELF_EM_CR16:	return OBJ_MACH_CR16;
	case ELF_EM_ETPU:	return OBJ_MACH_ETPU;
	case ELF_EM_SLE9X:	return OBJ_MACH_SLE9X;
	case ELF_EM_L10M:	return OBJ_MACH_L10M;
	case ELF_EM_K10M:	return OBJ_MACH_K10M;
	case ELF_EM_AARCH64:	return OBJ_MACH_AARCH64;
	case ELF_EM_AVR32:	return OBJ_MACH_AVR32;
	case ELF_EM_STM8:	return OBJ_MACH_STM8;
	case ELF_EM_TILE64:	return OBJ_MACH_TILE64;
	case ELF_EM_TILEPRO:	return OBJ_MACH_TILEPRO;
	case ELF_EM_MICROBLAZE:	return OBJ_MACH_MICROBLAZE;
	case ELF_EM_CUDA:	return OBJ_MACH_CUDA;
	case ELF_EM_TILEGX:	return OBJ_MACH_TILEGX;
	case ELF_EM_CLOUDSHIELD:	return OBJ_MACH_CLOUDSHIELD;
	case ELF_EM_COREA_1ST:	return OBJ_MACH_COREA_1ST;
	case ELF_EM_COREA_2ND:	return OBJ_MACH_COREA_2ND;
	case ELF_EM_ARC_COMPACT2:	return OBJ_MACH_ARC_COMPACT2;
	case ELF_EM_OPEN8:	return OBJ_MACH_OPEN8;
	case ELF_EM_RL78:	return OBJ_MACH_RL78;
	case ELF_EM_VIDEOCORE5:	return OBJ_MACH_VIDEOCORE5;
	case ELF_EM_78KOR:	return OBJ_MACH_78KOR;
	case ELF_EM_56800EX:	return OBJ_MACH_56800EX;
	case ELF_EM_BA1:	return OBJ_MACH_BA1;
	case ELF_EM_BA2:	return OBJ_MACH_BA2;
	case ELF_EM_XCORE:	return OBJ_MACH_XCORE;
	case ELF_EM_MCHP_PIC:	return OBJ_MACH_MCHP_PIC;
	case ELF_EM_INTEL205:	return OBJ_MACH_INTEL205;
	case ELF_EM_INTEL206:	return OBJ_MACH_INTEL206;
	case ELF_EM_INTEL207:	return OBJ_MACH_INTEL207;
	case ELF_EM_INTEL208:	return OBJ_MACH_INTEL208;
	case ELF_EM_INTEL209:	return OBJ_MACH_INTEL209;
	case ELF_EM_KM32:	return OBJ_MACH_KM32;
	case ELF_EM_KMX32:	return OBJ_MACH_KMX32;
	case ELF_EM_KMX16:	return OBJ_MACH_KMX16;
	case ELF_EM_KMX8:	return OBJ_MACH_KMX8;
	case ELF_EM_KVARC:	return OBJ_MACH_KVARC;
	case ELF_EM_CDP:	return OBJ_MACH_CDP;
	case ELF_EM_COGE:	return OBJ_MACH_COGE;
	case ELF_EM_COOL:	return OBJ_MACH_COOL;
	case ELF_EM_NORC:	return OBJ_MACH_NORC;
	case ELF_EM_CSR_KALIMBA:	return OBJ_MACH_CSR_KALIMBA;
	case ELF_EM_Z80:	return OBJ_MACH_Z80;
	case ELF_EM_VISIUM:	return OBJ_MACH_VISIUM;
	case ELF_EM_FT32:	return OBJ_MACH_FT32;
	case ELF_EM_MOXIE:	return OBJ_MACH_MOXIE;
	case ELF_EM_AMDGPU:	return OBJ_MACH_AMDGPU;
	case ELF_EM_RISCV:	return OBJ_MACH_RISCV;
	default: return null;
	}
}

const(char) *adbg_obj_elf_s_type(int t) {
	switch (t) {
	case ELF_SHT_NULL:	return "NULL";
	case ELF_SHT_PROGBITS:	return "PROGBITS";
	case ELF_SHT_SYMTAB:	return "SYMTAB";
	case ELF_SHT_STRTAB:	return "STRTAB";
	case ELF_SHT_RELA:	return "RELA";
	case ELF_SHT_HASH:	return "HASH";
	case ELF_SHT_DYNAMIC:	return "DYNAMIC";
	case ELF_SHT_NOTE:	return "NOTE";
	case ELF_SHT_NOBITS:	return "NOBITS";
	case ELF_SHT_REL:	return "REL";
	case ELF_SHT_SHLIB:	return "SHLIB";
	case ELF_SHT_DYNSYM:	return "DYNSYM";
	case ELF_SHT_INIT_ARRAY:	return "INIT_ARRAY";
	case ELF_SHT_FINI_ARRAY:	return "FINI_ARRAY";
	case ELF_SHT_PREINIT_ARRAY:	return "PREINIT_ARRAY";
	case ELF_SHT_GROUP:	return "GROUP";
	case ELF_SHT_SYNTAB_SHNDX:	return "SYNTAB_SHNDX";
	case ELF_SHT_LOOS:	return "LOOS";
	case ELF_SHT_HIOS:	return "HIOS";
	case ELF_SHT_LOPROC:	return "LOPROC";
	case ELF_SHT_HIPROC:	return "HIPROC";
	case ELF_SHT_LOUSER:	return "LOUSER";
	case ELF_SHT_HIUSER:	return "HIUSER";
	default: return null;
	}
}