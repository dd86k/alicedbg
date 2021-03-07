/**
 * ELF format.
 *
 * Source: http://www.sco.com/developers/gabi/latest/ch4.eheader.html
 *
 * License: BSD-3-Clause
 */
module adbg.obj.elf;

// Constants

enum ELF_EI_NIDENT	= 16;	/// Size of the initial pad (e_ident[])

// ELF Indexes

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

/// ELF32 header structure
struct Elf32_Ehdr {
	ubyte[ELF_EI_NIDENT] e_ident;	/// Identification bytes
	ushort e_type;	/// Object file type
	ushort e_machine;	/// Object file machine
	uint e_version;	/// Object version
	uint e_entry;	/// Object entry address
	uint e_phoff;	/// Program header offset
	uint e_shoff;	/// Section header offset
	uint e_flags;	/// Architecture flags
	ushort e_ehsize;	/// Header size in bytes
	ushort e_phentsize;	/// Program header size
	ushort e_phnum;	/// Number of entries in program header table
	ushort e_shentsize;	/// Number of entries in the section header table
	ushort e_shstrndx;	/// Index of the section header table entry that has section names
}

/// ELF64 header structure
struct Elf64_Ehdr {
	ubyte[ELF_EI_NIDENT] e_ident;	/// Identification bytes
	ushort e_type;	/// Object file type
	ushort e_machine;	/// Object file machine
	uint e_version;	/// Object version
	ulong e_entry;	/// Object entry address
	ulong e_phoff;	/// Program header offset
	ulong e_shoff;	/// Section header offset
	uint e_flags;	/// Architecture flags
	ushort e_ehsize;	/// Header size in bytes
	ushort e_phentsize;	/// Program header size
	ushort e_phnum;	/// Number of entries in program header table
	ushort e_shentsize;	/// Number of entries in the section header table
	ushort e_shstrndx;	/// Index of the section header table entry that has section names
}
