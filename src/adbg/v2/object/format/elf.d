/// ELF format.
///
/// Sources:
/// - http://www.sco.com/developers/gabi/latest/ch4.eheader.html
/// - linux/include/uapi/linux/elf.h
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.v2.object.format.elf;

import adbg.v2.object.server;
import adbg.v2.object.machines : AdbgMachine;
import adbg.error;
import adbg.utils.bit;
import adbg.include.c.stdlib : calloc, free;

// NOTE: The string table section is typically named .shstrtab

/// Signature magic for ELF.
enum ELF_MAGIC = CHAR32!"\x7FELF";

/// Minimum file size for ELF.
// https://stackoverflow.com/a/53383541
private enum MINIMUM_SIZE = 130;

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

enum ELF_CLASS_NONE	= 0;	/// No class
enum ELF_CLASS_32	= 1;	/// 32-bit ELF
enum ELF_CLASS_64	= 2;	/// 64-bit ELF

// ELF Data identifiers

enum ELF_DATA_NONE	= 0;	/// Invalid value
enum ELF_DATA_LSB	= 1;	/// Little-endian
enum ELF_DATA_MSB	= 2;	/// Big-endian

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

// GDB has the full list of machines under include/elf/common.h
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
enum ELF_EM_STARCORE	= 58;	/// Motorola Star*Core
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
enum ELF_EM_M16C	= 117;	/// Renesas M16C
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
enum ELF_EM_RISCV	= 243;	/// RISC-V
enum ELF_EM_LOONGARCH	= 258;	/// LoongArch

//
// ehdr e_flags
//

// ARM
enum ELF_EF_ARM_RELEXEC	= 0x01; /// 
enum ELF_EF_ARM_HASENTRY	= 0x02; /// 
enum ELF_EF_ARM_INTERWORK	= 0x04; /// 
enum ELF_EF_ARM_APCS_26	= 0x08; /// 
enum ELF_EF_ARM_APCS_FLOAT	= 0x10; /// 
enum ELF_EF_ARM_PIC	= 0x20; /// 
enum ELF_EF_ARM_ALIGN8	= 0x40; /// 8-bit structure alignment is in use
enum ELF_EF_ARM_NEW_ABI	= 0x80; /// 
enum ELF_EF_ARM_OLD_ABI	= 0x100; /// 
enum ELF_EF_ARM_SOFT_FLOAT	= 0x200; /// 
enum ELF_EF_ARM_VFP_FLOAT	= 0x400; /// 
enum ELF_EF_ARM_MAVERICK_FLOAT	= 0x800; /// 

// MIPS
enum ELF_EF_MIPS_NOREORDER	= 1;	/// A .noreorder directive was used
enum ELF_EF_MIPS_PIC	= 2;	/// Contains PIC code
enum ELF_EF_MIPS_CPIC	= 4;	/// Uses PIC calling sequence
enum ELF_EF_MIPS_XGOT	= 8;	/// 
enum ELF_EF_MIPS_64BIT_WHIRL	= 16;	/// 
enum ELF_EF_MIPS_ABI2	= 32;	/// 
enum ELF_EF_MIPS_ABI_ON32	= 64;	/// 
enum ELF_EF_MIPS_ARCH	= 0xf0000000;	/// MIPS architecture level

// SPARC
// https://docs.oracle.com/cd/E19120-01/open.solaris/819-0690/chapter6-43405/index.html
enum ELF_EF_SPARC_EXT_MARK	= 0xffff00;	/// Vendor Extension mask
enum ELF_EF_SPARC_32PLUS	= 0x000100;	/// Generic V8+ features
enum ELF_EF_SPARC_SUN_US1	= 0x000200;	/// Sun UltraSPARC 1 Extensions 
enum ELF_EF_SPARC_HAL_R1	= 0x000400;	/// HAL R1 Extensions 
enum ELF_EF_SPARC_SUN_US3	= 0x000800;	/// Sun UltraSPARC 3 Extensions 
enum ELF_EF_SPARCV9_MM	= 0x3;	/// Mask for Memory Model 
enum ELF_EF_SPARCV9_TSO	= 0x0;	/// Total Store Ordering 
enum ELF_EF_SPARCV9_PSO	= 0x1;	/// Partial Store Ordering 
enum ELF_EF_SPARCV9_RMO	= 0x2;	/// Relaxed Memory Ordering 

// Program segment header values

enum ELF_PT_NULL	= 0;
enum ELF_PT_LOAD	= 1;
enum ELF_PT_DYNAMIC	= 2;
enum ELF_PT_INTERP	= 3;
enum ELF_PT_NOTE	= 4;
enum ELF_PT_SHLIB	= 5;
enum ELF_PT_PHDR	= 6;
enum ELF_PT_TLS	= 7;	/// Thread local storage segment
enum ELF_PT_LOOS	= 0x60000000;	/// OS-specific
enum ELF_PT_HIOS	= 0x6fffffff;	/// OS-specific
enum ELF_PT_LOPROC	= 0x70000000;
enum ELF_PT_HIPROC	= 0x7fffffff;
enum ELF_PT_GNU_EH_FRAME	= (ELF_PT_LOOS + 0x474e550);
enum ELF_PT_GNU_STACK	= (ELF_PT_LOOS + 0x474e551);
enum ELF_PT_GNU_RELRO	= (ELF_PT_LOOS + 0x474e552);
enum ELF_PT_GNU_PROPERTY	= (ELF_PT_LOOS + 0x474e553);

enum ELF_PF_R	= 4;	/// p_flags value for Read permission
enum ELF_PF_W	= 2;	/// p_flags value for Write permission
enum ELF_PF_X	= 1;	/// p_flags value for Execute permission

// ELF Relocation types
enum R_386_NONE	= 0;
enum R_386_32	= 1;
enum R_386_PC32	= 2;
enum R_386_GOT32	= 3;
enum R_386_PLT32	= 4;
enum R_386_COPY	= 5;
enum R_386_GLOB_DAT	= 6;
enum R_386_JMP_SLOT	= 7;
enum R_386_RELATIVE	= 8;
enum R_386_GOTOFF	= 9;
enum R_386_GOTPC	= 10;
enum R_386_NUM	= 11;
enum R_X86_64_NONE	= 0;	/// No reloc
enum R_X86_64_64	= 1;	/// Direct 64 bit
enum R_X86_64_PC32	= 2;	/// PC relative 32 bit signed
enum R_X86_64_GOT32	= 3;	/// 32 bit GOT entry
enum R_X86_64_PLT32	= 4;	/// 32 bit PLT address
enum R_X86_64_COPY	= 5;	/// Copy symbol at runtime
enum R_X86_64_GLOB_DAT	= 6;	/// Create GOT entry
enum R_X86_64_JUMP_SLOT	= 7;	/// Create PLT entry
enum R_X86_64_RELATIVE	= 8;	/// Adjust by program base
enum R_X86_64_GOTPCREL	= 9;	/// 32 bit signed pc relative offset to GOT
enum R_X86_64_32	= 10;	/// Direct 32 bit zero extended
enum R_X86_64_32S	= 11;	/// Direct 32 bit sign extended
enum R_X86_64_16	= 12;	/// Direct 16 bit zero extended
enum R_X86_64_PC16	= 13;	/// 16 bit sign extended pc relative
enum R_X86_64_8	= 14;	/// Direct 8 bit sign extended 
enum R_X86_64_PC8	= 15;	/// 8 bit sign extended pc relative
enum R_X86_64_PC64	= 24;	/// Place relative 64-bit signed

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
// ET_CORE
// elf.h values off musl 1.20
//

enum ELF_NT_PRSTATUS	= 1;	/// 
enum ELF_NT_PRFPREG	= 2;	/// 
enum ELF_NT_FPREGSET	= 2;	/// 
enum ELF_NT_PRPSINFO	= 3;	/// 
enum ELF_NT_PRXREG	= 4;	/// 
enum ELF_NT_TASKSTRUCT	= 4;	/// 
enum ELF_NT_PLATFORM	= 5;	/// 
enum ELF_NT_AUXV	= 6;	/// 
enum ELF_NT_GWINDOWS	= 7;	/// 
enum ELF_NT_ASRS	= 8;	/// 
enum ELF_NT_PSTATUS	= 10;	/// 
enum ELF_NT_PSINFO	= 13;	/// 
enum ELF_NT_PRCRED	= 14;	/// 
enum ELF_NT_UTSNAME	= 15;	/// 
enum ELF_NT_LWPSTATUS	= 16;	/// 
enum ELF_NT_LWPSINFO	= 17;	/// 
enum ELF_NT_PRFPXREG	= 20;	/// 
enum ELF_NT_SIGINFO	= 0x53494749;	/// 
enum ELF_NT_FILE	= 0x46494c45;	/// 
enum ELF_NT_PRXFPREG	= 0x46e62b7f;	/// 
enum ELF_NT_PPC_VMX	= 0x100;	/// 
enum ELF_NT_PPC_SPE	= 0x101;	/// 
enum ELF_NT_PPC_VSX	= 0x102;	/// 
enum ELF_NT_PPC_TAR	= 0x103;	/// 
enum ELF_NT_PPC_PPR	= 0x104;	/// 
enum ELF_NT_PPC_DSCR	= 0x105;	/// 
enum ELF_NT_PPC_EBB	= 0x106;	/// 
enum ELF_NT_PPC_PMU	= 0x107;	/// 
enum ELF_NT_PPC_TM_CGPR	= 0x108;	/// 
enum ELF_NT_PPC_TM_CFPR	= 0x109;	/// 
enum ELF_NT_PPC_TM_CVMX	= 0x10a;	/// 
enum ELF_NT_PPC_TM_CVSX	= 0x10b;	/// 
enum ELF_NT_PPC_TM_SPR	= 0x10c;	/// 
enum ELF_NT_PPC_TM_CTAR	= 0x10d;	/// 
enum ELF_NT_PPC_TM_CPPR	= 0x10e;	/// 
enum ELF_NT_PPC_TM_CDSCR	= 0x10f;	/// 
enum ELF_NT_386_TLS	= 0x200;	/// 
enum ELF_NT_386_IOPERM	= 0x201;	/// 
enum ELF_NT_X86_XSTATE	= 0x202;	/// 
enum ELF_NT_S390_HIGH_GPRS	= 0x300;	/// 
enum ELF_NT_S390_TIMER	= 0x301;	/// 
enum ELF_NT_S390_TODCMP	= 0x302;	/// 
enum ELF_NT_S390_TODPREG	= 0x303;	/// 
enum ELF_NT_S390_CTRS	= 0x304;	/// 
enum ELF_NT_S390_PREFIX	= 0x305;	/// 
enum ELF_NT_S390_LAST_BREAK	= 0x306;	/// 
enum ELF_NT_S390_SYSTEM_CALL	= 0x307;	/// 
enum ELF_NT_S390_TDB	= 0x308;	/// 
enum ELF_NT_S390_VXRS_LOW	= 0x309;	/// 
enum ELF_NT_S390_VXRS_HIGH	= 0x30a;	/// 
enum ELF_NT_S390_GS_CB	= 0x30b;	/// 
enum ELF_NT_S390_GS_BC	= 0x30c;	/// 
enum ELF_NT_S390_RI_CB	= 0x30d;	/// 
enum ELF_NT_ARM_VFP	= 0x400;	/// 
enum ELF_NT_ARM_TLS	= 0x401;	/// 
enum ELF_NT_ARM_HW_BREAK	= 0x402;	/// 
enum ELF_NT_ARM_HW_WATCH	= 0x403;	/// 
enum ELF_NT_ARM_SYSTEM_CALL	= 0x404;	/// 
enum ELF_NT_ARM_SVE	= 0x405;	/// 
enum ELF_NT_ARM_PAC_MASK	= 0x406;	/// 
enum ELF_NT_ARM_PACA_KEYS	= 0x407;	/// 
enum ELF_NT_ARM_PACG_KEYS	= 0x408;	/// 
enum ELF_NT_METAG_CBUF	= 0x500;	/// 
enum ELF_NT_METAG_RPIPE	= 0x501;	/// 
enum ELF_NT_METAG_TLS	= 0x502;	/// 
enum ELF_NT_ARC_V2	= 0x600;	/// 
enum ELF_NT_VMCOREDD	= 0x700;	/// 
enum ELF_NT_MIPS_DSP	= 0x800;	/// 
enum ELF_NT_MIPS_FP_MODE	= 0x801;	/// 
enum ELF_NT_MIPS_MSA	= 0x802;	/// 
enum ELF_NT_VERSION	= 1;	/// 
enum ELF_NT_LOONGARCH_CPUCFG	= 0xa00;	/// LoongArch CPU config registers
enum ELF_NT_LOONGARCH_CSR	= 0xa01;	/// LoongArch control and status registers
enum ELF_NT_LOONGARCH_LSX	= 0xa02;	/// LoongArch Loongson SIMD Extension registers
enum ELF_NT_LOONGARCH_LASX	= 0xa03;	/// LoongArch Loongson Advanced SIMD Extension registers
enum ELF_NT_LOONGARCH_LBT	= 0xa04;	/// LoongArch Loongson Binary Translation registers
enum ELF_NT_LOONGARCH_HW_BREAK	= 0xa05;   /// LoongArch hardware breakpoint registers
enum ELF_NT_LOONGARCH_HW_WATCH	= 0xa06;   /// LoongArch hardware watchpoint registers


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
	Elf32_Word p_flags;	/// Segment flags
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

version (BigEndian)
	private enum PLATFORM_DATA = ELF_DATA_MSB;
else
	private enum PLATFORM_DATA = ELF_DATA_LSB;

int adbg_object_elf_load(adbg_object_t *o) {
	if (o.file_size < MINIMUM_SIZE)
		return adbg_oops(AdbgError.objectTooSmall);
	
	o.format = AdbgObject.elf;
	
	o.p.reversed = o.i.elf32.ehdr.e_ident[ELF_EI_DATA] != PLATFORM_DATA;
	version (Trace) trace("reversed=%d", o.p.reversed);
	
	switch (o.i.elf32.ehdr.e_ident[ELF_EI_CLASS]) {
	case ELF_CLASS_32:
		with (o.i.elf32) {
			if (o.p.reversed) {
				ehdr.e_type	= adbg_bswap16(ehdr.e_type);
				ehdr.e_machine	= adbg_bswap16(ehdr.e_machine);
				ehdr.e_version	= adbg_bswap32(ehdr.e_version);
				ehdr.e_entry	= adbg_bswap32(ehdr.e_entry);
				ehdr.e_phoff	= adbg_bswap32(ehdr.e_phoff);
				ehdr.e_shoff	= adbg_bswap32(ehdr.e_shoff);
				ehdr.e_flags	= adbg_bswap32(ehdr.e_flags);
				ehdr.e_ehsize	= adbg_bswap16(ehdr.e_ehsize);
				ehdr.e_phentsize	= adbg_bswap16(ehdr.e_phentsize);
				ehdr.e_phnum	= adbg_bswap16(ehdr.e_phnum);
				ehdr.e_shentsize	= adbg_bswap16(ehdr.e_shentsize);
				ehdr.e_shnum	= adbg_bswap16(ehdr.e_shnum);
				ehdr.e_shstrndx	= adbg_bswap16(ehdr.e_shstrndx);
			}
			
			if (ehdr.e_version != ELF_EV_CURRENT)
				return adbg_oops(AdbgError.assertion);
			
			if (ehdr.e_phoff && ehdr.e_phnum) {
				if (ehdr.e_phoff >= o.file_size) {
					return adbg_oops(AdbgError.assertion);
				}
				phdr = cast(Elf32_Phdr*)(o.buffer + ehdr.e_phoff);
				if (adbg_object_ptrbnds(o, phdr) == false)
					return adbg_oops(AdbgError.assertion);
				reversed_phdr = cast(bool*)calloc(ehdr.e_phnum, bool.sizeof);
				if (reversed_phdr == null)
					return adbg_oops(AdbgError.crt);
			} else {
				reversed_phdr = null;
				phdr = null;
			}
			if (ehdr.e_shoff && ehdr.e_shnum) {
				if (ehdr.e_shoff >= o.file_size) {
					return adbg_oops(AdbgError.assertion);
				}
				shdr = cast(Elf32_Shdr*)(o.buffer + ehdr.e_shoff);
				if (adbg_object_ptrbnds(o, shdr) == false)
					return adbg_oops(AdbgError.assertion);
				reversed_shdr = cast(bool*)calloc(ehdr.e_shnum, bool.sizeof);
				if (reversed_shdr == null)
					return adbg_oops(AdbgError.crt);
			} else {
				reversed_shdr = null;
				shdr = null;
			}
		}
		break;
	case ELF_CLASS_64:
		with (o.i.elf64) {
			if (o.p.reversed) {
				ehdr.e_type	= adbg_bswap16(ehdr.e_type);
				ehdr.e_machine	= adbg_bswap16(ehdr.e_machine);
				ehdr.e_version	= adbg_bswap32(ehdr.e_version);
				ehdr.e_entry	= adbg_bswap64(ehdr.e_entry);
				ehdr.e_phoff	= adbg_bswap64(ehdr.e_phoff);
				ehdr.e_shoff	= adbg_bswap64(ehdr.e_shoff);
				ehdr.e_flags	= adbg_bswap32(ehdr.e_flags);
				ehdr.e_ehsize	= adbg_bswap16(ehdr.e_ehsize);
				ehdr.e_phentsize	= adbg_bswap16(ehdr.e_phentsize);
				ehdr.e_phnum	= adbg_bswap16(ehdr.e_phnum);
				ehdr.e_shentsize	= adbg_bswap16(ehdr.e_shentsize);
				ehdr.e_shnum	= adbg_bswap16(ehdr.e_shnum);
				ehdr.e_shstrndx	= adbg_bswap16(ehdr.e_shstrndx);
			}
			
			if (ehdr.e_version != ELF_EV_CURRENT)
				return adbg_oops(AdbgError.assertion);
			
			if (ehdr.e_phoff && ehdr.e_phnum) {
				if (ehdr.e_phoff >= o.file_size) {
					return adbg_oops(AdbgError.assertion);
				}
				phdr = cast(Elf64_Phdr*)(o.buffer + ehdr.e_phoff);
				if (adbg_object_ptrbnds(o, phdr) == false)
					return adbg_oops(AdbgError.assertion);
				reversed_phdr = cast(bool*)calloc(ehdr.e_phnum, bool.sizeof);
				if (reversed_phdr == null)
					return adbg_oops(AdbgError.crt);
			} else {
				reversed_phdr = null;
				phdr = null;
			}
			
			if (ehdr.e_shoff && ehdr.e_shnum) {
				if (ehdr.e_shoff >= o.file_size) {
					return adbg_oops(AdbgError.assertion);
				}
				shdr = cast(Elf64_Shdr*)(o.buffer + ehdr.e_shoff);
				if (adbg_object_ptrbnds(o, shdr) == false)
					return adbg_oops(AdbgError.assertion);
				reversed_shdr = cast(bool*)calloc(ehdr.e_shnum, bool.sizeof);
				if (reversed_shdr == null)
					return adbg_oops(AdbgError.crt);
			} else {
				reversed_shdr = null;
				shdr = null;
			}
		}
		break;
	default:
		return adbg_oops(AdbgError.invalidObjClass);
	}
	
	return 0;
}

Elf32_Ehdr* adbg_object_elf_ehdr32(adbg_object_t *o) {
	if (o == null) return null;
	// Return as-is, already swapped
	return o.i.elf32.ehdr;
}

Elf32_Phdr* adbg_object_elf_phdr32(adbg_object_t *o, size_t index) {
	if (o == null) return null;
	if (o.i.elf32.phdr == null) return null;
	if (index >= o.i.elf32.ehdr.e_phnum) return null;
	
	Elf32_Phdr *phdr = &o.i.elf32.phdr[index];
	if (o.p.reversed && o.i.elf32.reversed_phdr[index] == false) {
		phdr.p_type	= adbg_bswap32(phdr.p_type);
		phdr.p_offset	= adbg_bswap32(phdr.p_offset);
		phdr.p_vaddr	= adbg_bswap32(phdr.p_vaddr);
		phdr.p_paddr	= adbg_bswap32(phdr.p_paddr);
		phdr.p_filesz	= adbg_bswap32(phdr.p_filesz);
		phdr.p_memsz	= adbg_bswap32(phdr.p_memsz);
		phdr.p_flags	= adbg_bswap32(phdr.p_flags);
		phdr.p_align	= adbg_bswap32(phdr.p_align);
		o.i.elf32.reversed_phdr[index] = true;
	}
	return phdr;
}

Elf32_Shdr* adbg_object_elf_shdr32(adbg_object_t *o, size_t index) {
	if (o == null) return null;
	if (o.i.elf32.shdr == null) return null;
	if (index >= o.i.elf32.ehdr.e_shnum) return null;
	
	Elf32_Shdr *shdr = &o.i.elf32.shdr[index];
	if (o.p.reversed && o.i.elf32.reversed_phdr[index] == false) {
		shdr.sh_name	= adbg_bswap32(shdr.sh_name);
		shdr.sh_type	= adbg_bswap32(shdr.sh_type);
		shdr.sh_flags	= adbg_bswap32(shdr.sh_flags);
		shdr.sh_addr	= adbg_bswap32(shdr.sh_addr);
		shdr.sh_offset	= adbg_bswap32(shdr.sh_offset);
		shdr.sh_size	= adbg_bswap32(shdr.sh_size);
		shdr.sh_link	= adbg_bswap32(shdr.sh_link);
		shdr.sh_info	= adbg_bswap32(shdr.sh_info);
		shdr.sh_addralign	= adbg_bswap32(shdr.sh_addralign);
		shdr.sh_entsize	= adbg_bswap32(shdr.sh_entsize);
		o.i.elf32.reversed_shdr[index] = true;
	}
	return shdr;
}

Elf64_Ehdr* adbg_object_elf_ehdr64(adbg_object_t *o) {
	if (o == null) return null;
	// Return as-is, already swapped
	return o.i.elf64.ehdr;
}

Elf64_Phdr* adbg_object_elf_phdr64(adbg_object_t *o, size_t index) {
	if (o == null) return null;
	if (o.i.elf64.phdr == null) return null;
	if (index >= o.i.elf64.ehdr.e_phnum) return null;
	
	Elf64_Phdr *phdr = &o.i.elf64.phdr[index];
	if (o.p.reversed && o.i.elf64.reversed_phdr[index] == false) {
		phdr.p_type	= adbg_bswap32(phdr.p_type);
		phdr.p_offset	= adbg_bswap64(phdr.p_offset);
		phdr.p_vaddr	= adbg_bswap64(phdr.p_vaddr);
		phdr.p_paddr	= adbg_bswap64(phdr.p_paddr);
		phdr.p_filesz	= adbg_bswap64(phdr.p_filesz);
		phdr.p_memsz	= adbg_bswap64(phdr.p_memsz);
		phdr.p_flags	= adbg_bswap32(phdr.p_flags);
		phdr.p_align	= adbg_bswap64(phdr.p_align);
		o.i.elf32.reversed_phdr[index] = true;
	}
	return phdr;
}

Elf64_Shdr* adbg_object_elf_shdr64(adbg_object_t *o, size_t index) {
	if (o == null) return null;
	if (o.i.elf64.shdr == null) return null;
	if (index >= o.i.elf64.ehdr.e_shnum) return null;
	
	Elf64_Shdr *shdr = &o.i.elf64.shdr[index];
	if (o.p.reversed && o.i.elf64.reversed_phdr[index] == false) {
		shdr.sh_name	= adbg_bswap32(shdr.sh_name);
		shdr.sh_type	= adbg_bswap32(shdr.sh_type);
		shdr.sh_flags	= adbg_bswap64(shdr.sh_flags);
		shdr.sh_addr	= adbg_bswap64(shdr.sh_addr);
		shdr.sh_offset	= adbg_bswap64(shdr.sh_offset);
		shdr.sh_size	= adbg_bswap64(shdr.sh_size);
		shdr.sh_link	= adbg_bswap32(shdr.sh_link);
		shdr.sh_info	= adbg_bswap32(shdr.sh_info);
		shdr.sh_addralign	= adbg_bswap64(shdr.sh_addralign);
		shdr.sh_entsize	= adbg_bswap64(shdr.sh_entsize);
		o.i.elf32.reversed_shdr[index] = true;
	}
	return shdr;
}

AdbgMachine adbg_object_elf_machine(ushort machine, ubyte class_) {
	// NOTE: Many reserved values are excluded
	switch (machine) {
	case ELF_EM_M32:	return AdbgMachine.we32100;
	case ELF_EM_SPARC:	return AdbgMachine.sparc;
	case ELF_EM_386:	return AdbgMachine.x86;
	case ELF_EM_68K:	return AdbgMachine.m68k;
	case ELF_EM_88K:	return AdbgMachine.m88k;
	case ELF_EM_MCU:	return AdbgMachine.mcu;
	case ELF_EM_860:	return AdbgMachine.i860;
	case ELF_EM_MIPS:	return AdbgMachine.mips;
	case ELF_EM_S370:	return AdbgMachine.s370;
	case ELF_EM_MIPS_RS3_LE:	return AdbgMachine.mipsle;
	case ELF_EM_PARISC:	return AdbgMachine.parisc;
	case ELF_EM_VPP500:	return AdbgMachine.vpp500;
	case ELF_EM_SPARC32PLUS:	return AdbgMachine.sparc8p;
	case ELF_EM_960:	return AdbgMachine.i960;
	case ELF_EM_PPC:	return AdbgMachine.ppc;
	case ELF_EM_PPC64:	return AdbgMachine.ppc64;
	case ELF_EM_S390:	return AdbgMachine.s390;
	case ELF_EM_SPU:	return AdbgMachine.spu;
	case ELF_EM_V800:	return AdbgMachine.v800;
	case ELF_EM_FR20:	return AdbgMachine.fr20;
	case ELF_EM_RH32:	return AdbgMachine.rh32;
	case ELF_EM_RCE:	return AdbgMachine.rce;
	case ELF_EM_ARM:	return AdbgMachine.arm;
	case ELF_EM_ALPHA:	return AdbgMachine.alpha;
	case ELF_EM_SH:	return AdbgMachine.sh;
	case ELF_EM_SPARCV9:	return AdbgMachine.sparc9;
	case ELF_EM_TRICORE:	return AdbgMachine.tricore;
	case ELF_EM_ARC:	return AdbgMachine.arc;
	case ELF_EM_H8_300:	return AdbgMachine.h8300;
	case ELF_EM_H8_300H:	return AdbgMachine.h8300h;
	case ELF_EM_H8S:	return AdbgMachine.h8s;
	case ELF_EM_H8_500:	return AdbgMachine.h8500;
	case ELF_EM_IA_64:	return AdbgMachine.ia64;
	case ELF_EM_MIPS_X:	return AdbgMachine.mipsx;
	case ELF_EM_COLDFIRE:	return AdbgMachine.coldfire;
	case ELF_EM_68HC12:	return AdbgMachine.m68hc12;
	case ELF_EM_MMA:	return AdbgMachine.mma;
	case ELF_EM_PCP:	return AdbgMachine.pcp;
	case ELF_EM_NCPU:	return AdbgMachine.ncpu;
	case ELF_EM_NDR1:	return AdbgMachine.ndr1;
	case ELF_EM_STARCORE:	return AdbgMachine.starcore;
	case ELF_EM_ME16:	return AdbgMachine.me16;
	case ELF_EM_ST100:	return AdbgMachine.st100;
	case ELF_EM_TINYJ:	return AdbgMachine.tinyj;
	case ELF_EM_X86_64:	return AdbgMachine.amd64;
	case ELF_EM_PDSP:	return AdbgMachine.sonydsp;
	case ELF_EM_PDP10:	return AdbgMachine.pdp10;
	case ELF_EM_PDP11:	return AdbgMachine.pdp11;
	case ELF_EM_FX66:	return AdbgMachine.fx66;
	case ELF_EM_ST9PLUS:	return AdbgMachine.st9;
	case ELF_EM_ST7:	return AdbgMachine.st7;
	case ELF_EM_68HC16:	return AdbgMachine.m68hc16;
	case ELF_EM_68HC11:	return AdbgMachine.m68hc11;
	case ELF_EM_68HC08:	return AdbgMachine.m68hc08;
	case ELF_EM_68HC05:	return AdbgMachine.m68hc05;
	case ELF_EM_SVX:	return AdbgMachine.svx;
	case ELF_EM_ST19:	return AdbgMachine.st19;
	case ELF_EM_VAX:	return AdbgMachine.vax;
	case ELF_EM_CRIS:	return AdbgMachine.axis;
	case ELF_EM_JAVELIN:	return AdbgMachine.sle9x;
	case ELF_EM_FIREPATH:	return AdbgMachine.firepath;
	case ELF_EM_ZSP:	return AdbgMachine.zsp;
	case ELF_EM_MMIX:	return AdbgMachine.mmix;
	case ELF_EM_HUANY:	return AdbgMachine.harvard;
	case ELF_EM_PRISM:	return AdbgMachine.prism;
	case ELF_EM_AVR:	return AdbgMachine.avr;
	case ELF_EM_FR30:	return AdbgMachine.fr30;
	case ELF_EM_D10V:	return AdbgMachine.d10v;
	case ELF_EM_D30V:	return AdbgMachine.d30v;
	case ELF_EM_V850:	return AdbgMachine.v850;
	case ELF_EM_M32R:	return AdbgMachine.m32r;
	case ELF_EM_MN10300:	return AdbgMachine.mn10300;
	case ELF_EM_MN10200:	return AdbgMachine.mn10200;
	case ELF_EM_PJ:	return AdbgMachine.pj;
	case ELF_EM_OPENRISC:	return AdbgMachine.openrisc;
	case ELF_EM_ARC_COMPACT:	return AdbgMachine.arc;
	case ELF_EM_XTENSA:	return AdbgMachine.xtensa;
	case ELF_EM_VIDEOCORE:	return AdbgMachine.videocore;
	case ELF_EM_TMM_GPP:	return AdbgMachine.tmm;
	case ELF_EM_NS32K:	return AdbgMachine.ns32k;
	case ELF_EM_TPC:	return AdbgMachine.tpc;
	case ELF_EM_SNP1K:	return AdbgMachine.snp1k;
	case ELF_EM_ST200:	return AdbgMachine.st200;
	case ELF_EM_IP2K:	return AdbgMachine.ip2k;
	case ELF_EM_MAX:	return AdbgMachine.max;
	case ELF_EM_CR:	return AdbgMachine.cr;
	case ELF_EM_F2MC16:	return AdbgMachine.f2mc16;
	case ELF_EM_MSP430:	return AdbgMachine.msp430;
	case ELF_EM_BLACKFIN:	return AdbgMachine.blackfin;
	case ELF_EM_SE_C33:	return AdbgMachine.s1c33;
	case ELF_EM_SEP:	return AdbgMachine.sep;
	case ELF_EM_ARCA:	return AdbgMachine.arca;
	case ELF_EM_UNICORE:	return AdbgMachine.unicore;
	case ELF_EM_EXCESS:	return AdbgMachine.excess;
	case ELF_EM_DXP:	return AdbgMachine.dxp;
	case ELF_EM_ALTERA_NIOS2:	return AdbgMachine.nios2;
	case ELF_EM_CRX:	return AdbgMachine.crx;
	case ELF_EM_XGATE:	return AdbgMachine.xgate;
	case ELF_EM_C116:	return AdbgMachine.c166;
	case ELF_EM_M16C:	return AdbgMachine.m16c;
	case ELF_EM_DSPIC30F:	return AdbgMachine.dspic30f;
	case ELF_EM_CE:	return AdbgMachine.ce;
	case ELF_EM_M32C:	return AdbgMachine.m32c;
	case ELF_EM_TSK3000:	return AdbgMachine.tsk3000;
	case ELF_EM_RS08:	return AdbgMachine.rs08;
	case ELF_EM_SHARC:	return AdbgMachine.sharc;
	case ELF_EM_ECOG2:	return AdbgMachine.ecog2;
	case ELF_EM_SCORE7:	return AdbgMachine.score7;
	case ELF_EM_DSP24:	return AdbgMachine.dsp24;
	case ELF_EM_VIDEOCORE3:	return AdbgMachine.videocore3;
	case ELF_EM_LATTICEMICO32:	return AdbgMachine.mico32;
	case ELF_EM_SE_C17:	return AdbgMachine.c17;
	case ELF_EM_TI_C6000:	return AdbgMachine.tic6000;
	case ELF_EM_TI_C2000:	return AdbgMachine.tic2000;
	case ELF_EM_TI_C5500:	return AdbgMachine.tic55xx;
	case ELF_EM_TI_ARP32:	return AdbgMachine.asrisc;
	case ELF_EM_TI_PRU:	return AdbgMachine.pru;
	case ELF_EM_MMDSP_PLUS:	return AdbgMachine.vdsp;
	case ELF_EM_CYPRESS_M8C:	return AdbgMachine.m8c;
	case ELF_EM_R32C:	return AdbgMachine.r32c;
	case ELF_EM_TRIMEDIA:	return AdbgMachine.trimedia;
	case ELF_EM_QDSP6:	return AdbgMachine.dsp6;
	case ELF_EM_8051:	return AdbgMachine.i8051;
	case ELF_EM_STXP7X:	return AdbgMachine.stxp7x;
	case ELF_EM_NDS32:	return AdbgMachine.nds32;
	case ELF_EM_ECOG1X:	return AdbgMachine.ecog1x;
	case ELF_EM_MAXQ30:	return AdbgMachine.maxq30;
	case ELF_EM_XIMO16:	return AdbgMachine.dsp16;
	case ELF_EM_MANIK:	return AdbgMachine.m2000;
	case ELF_EM_CRAYNV2:	return AdbgMachine.nv2;
	case ELF_EM_RX:	return AdbgMachine.rx;
	case ELF_EM_METAG:	return AdbgMachine.meta;
	case ELF_EM_MCST_ELBRUS:	return AdbgMachine.elbrus;
	case ELF_EM_ECOG16:	return AdbgMachine.ecog16;
	case ELF_EM_CR16:	return AdbgMachine.cr16;
	case ELF_EM_ETPU:	return AdbgMachine.etpu;
	case ELF_EM_SLE9X:	return AdbgMachine.sle9x; // javelin?
	case ELF_EM_L10M:	return AdbgMachine.l10m;
	case ELF_EM_K10M:	return AdbgMachine.k10m;
	case ELF_EM_AARCH64:	return AdbgMachine.aarch64;
	case ELF_EM_AVR32:	return AdbgMachine.avr32;
	case ELF_EM_STM8:	return AdbgMachine.stm8;
	case ELF_EM_TILE64:	return AdbgMachine.tile64;
	case ELF_EM_TILEPRO:	return AdbgMachine.tilepro;
	case ELF_EM_MICROBLAZE:	return AdbgMachine.microblaze;
	case ELF_EM_CUDA:	return AdbgMachine.cuda;
	case ELF_EM_TILEGX:	return AdbgMachine.tilegx;
	case ELF_EM_CLOUDSHIELD:	return AdbgMachine.cloudshield;
	case ELF_EM_COREA_1ST:	return AdbgMachine.corea1;
	case ELF_EM_COREA_2ND:	return AdbgMachine.corea2;
	case ELF_EM_ARC_COMPACT2:	return AdbgMachine.arcc2;
	case ELF_EM_OPEN8:	return AdbgMachine.open8;
	case ELF_EM_RL78:	return AdbgMachine.rl78;
	case ELF_EM_VIDEOCORE5:	return AdbgMachine.videocore5;
	case ELF_EM_78KOR:	return AdbgMachine.r78kor;
	case ELF_EM_56800EX:	return AdbgMachine.dsc;
	case ELF_EM_BA1:	return AdbgMachine.ba1;
	case ELF_EM_BA2:	return AdbgMachine.ba2;
	case ELF_EM_XCORE:	return AdbgMachine.xcore;
	case ELF_EM_MCHP_PIC:	return AdbgMachine.picr8;
	case ELF_EM_KM32:	return AdbgMachine.km32;
	case ELF_EM_KMX32:	return AdbgMachine.kmx32;
	case ELF_EM_KMX16:	return AdbgMachine.kmx16;
	case ELF_EM_KMX8:	return AdbgMachine.kmx8;
	case ELF_EM_KVARC:	return AdbgMachine.kvarc;
	case ELF_EM_CDP:	return AdbgMachine.cdp;
	case ELF_EM_COGE:	return AdbgMachine.csm;
	case ELF_EM_COOL:	return AdbgMachine.bluechip;
	case ELF_EM_NORC:	return AdbgMachine.nano;
	case ELF_EM_CSR_KALIMBA:	return AdbgMachine.csr;
	case ELF_EM_Z80:	return AdbgMachine.z80;
	case ELF_EM_VISIUM:	return AdbgMachine.visium;
	case ELF_EM_FT32:	return AdbgMachine.ftdi;
	case ELF_EM_MOXIE:	return AdbgMachine.moxie;
	case ELF_EM_AMDGPU:	return AdbgMachine.amdgpu;
	case ELF_EM_RISCV:	return AdbgMachine.riscv;
	case ELF_EM_LOONGARCH:
		switch (class_) {
		case ELF_CLASS_32: return AdbgMachine.loongarch32;
		case ELF_CLASS_64: return AdbgMachine.loongarch64;
		default:
		}
		goto default;
	default:	return AdbgMachine.unknown;
	}
}

const(char) *adbg_object_elf_class_string(ubyte class_) {
	switch (class_) {
	case ELF_CLASS_32:	return "ELF32";
	case ELF_CLASS_64:	return "ELF64";
	default:	return null;
	}
}

const(char) *adbg_object_elf_data_string(ubyte data) {
	switch (data) {
	case ELF_DATA_LSB:	return "LSB";
	case ELF_DATA_MSB:	return "MSB";
	default:	return null;
	}
}

const(char) *adbg_object_elf_abi_string(ubyte object_) {
	switch (object_) {
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
	default:	return null;
	}
}

const(char) *adbg_object_elf_et_string(ushort type) {
	switch (type) {
	case ELF_ET_NONE:	return "NONE";
	case ELF_ET_REL:	return "REL";
	case ELF_ET_EXEC:	return "EXEC";
	case ELF_ET_DYN:	return "DYN";
	case ELF_ET_CORE:	return "CORE";
	case ELF_ET_LOOS:	return "LOOS";
	case ELF_ET_HIOS:	return "HIOS";
	case ELF_ET_LOPROC:	return "LOPROC";
	case ELF_ET_HIPROC:	return "HIPROC";
	default:	return null;
	}
}

const(char) *adbg_object_elf_pt_string(uint type) {
	switch (type) {
	case ELF_PT_NULL:	return "NULL";
	case ELF_PT_LOAD:	return "LOAD";
	case ELF_PT_DYNAMIC:	return "DYNAMIC";
	case ELF_PT_INTERP:	return "INTERP";
	case ELF_PT_NOTE:	return "NOTE";
	case ELF_PT_SHLIB:	return "SHLIB";
	case ELF_PT_PHDR:	return "PHDR";
	case ELF_PT_TLS:	return "TLS";
	case ELF_PT_LOOS:	return "LOOS";
	case ELF_PT_HIOS:	return "HIOS";
	case ELF_PT_LOPROC:	return "LOPROC";
	case ELF_PT_HIPROC:	return "HIPROC";
	case ELF_PT_GNU_EH_FRAME:	return "GNU_EH_FRAME";
	case ELF_PT_GNU_STACK:	return "GNU_STACK";
	case ELF_PT_GNU_RELRO:	return "GNU_RELRO";
	case ELF_PT_GNU_PROPERTY:	return "GNU_PROPERTY";
	default:	return null;
	}
}

const(char) *adbg_object_elf_em_string(ushort machine) {
	switch (machine) {
	case ELF_EM_NONE:	return "No machine";
	case ELF_EM_M32:	return "AT&T WE 32100";
	case ELF_EM_SPARC:	return "SPARC";
	case ELF_EM_386:	return "Intel x86";
	case ELF_EM_68K:	return "Motorola 68000";
	case ELF_EM_88K:	return "Motorola 88000";
	case ELF_EM_MCU:	return "Intel MCU";
	case ELF_EM_860:	return "Intel 80860";
	case ELF_EM_MIPS:	return "MIPS I (RS3000)";
	case ELF_EM_S370:	return "IBM System/370";
	case ELF_EM_MIPS_RS3_LE:	return "MIPS RS3000 Little-Endian";
	case ELF_EM_PARISC:	return "Hewlett-Packard PA-RISC";
	case ELF_EM_VPP500:	return "Fujitsu VPP500";
	case ELF_EM_SPARC32PLUS:	return "Enhanced SPARC";
	case ELF_EM_960:	return "Intel 80960";
	case ELF_EM_PPC:	return "IBM PowerPC";
	case ELF_EM_PPC64:	return "IBM PowerPC64";
	case ELF_EM_S390:	return "IBM System/390";
	case ELF_EM_SPU:	return "IBM SPU/SPC";
	case ELF_EM_V800:	return "NEC V800";
	case ELF_EM_FR20:	return "Fujitsu FR20";
	case ELF_EM_RH32:	return "TRW RH-32";
	case ELF_EM_RCE:	return "Motorola RCE";
	case ELF_EM_ARM:	return "ARM 32-bit";
	case ELF_EM_ALPHA:	return "DEC Alpha";
	case ELF_EM_SH:	return "Hitachi SuperH";
	case ELF_EM_SPARCV9:	return "SPARC Version 9";
	case ELF_EM_TRICORE:	return "Siemens TriCore embedded";
	case ELF_EM_ARC:	return "Argonaut RISC Core";
	case ELF_EM_H8_300:	return "Hitachi H8/300";
	case ELF_EM_H8_300H:	return "Hitachi H8/300H";
	case ELF_EM_H8S:	return "Hitachi H8S";
	case ELF_EM_H8_500:	return "Hitachi H8/500";
	case ELF_EM_IA_64:	return "Intel Itanium";
	case ELF_EM_MIPS_X:	return "Stanford MIPS-X";
	case ELF_EM_COLDFIRE:	return "Motorola ColdFire";
	case ELF_EM_68HC12:	return "Motorola M68HC12";
	case ELF_EM_MMA:	return "Fujitsu MMA Multimedia Accelerator";
	case ELF_EM_PCP:	return "Siemens PCP";
	case ELF_EM_NCPU:	return "Sony nCPU embedded RISC";
	case ELF_EM_NDR1:	return "Denso NDR1";
	case ELF_EM_STARCORE:	return "Motorola Star*Core";
	case ELF_EM_ME16:	return "Toyota ME16";
	case ELF_EM_ST100:	return "STMicroelectronics ST100";
	case ELF_EM_TINYJ:	return "Advanced Logic Corp. TinyJ";
	case ELF_EM_X86_64:	return "AMD x86-64";
	case ELF_EM_PDSP:	return "Sony DSP";
	case ELF_EM_PDP10:	return "DEC PDP-10";
	case ELF_EM_PDP11:	return "DEC PDP-11";
	case ELF_EM_FX66:	return "Siemens FX66";
	case ELF_EM_ST9PLUS:	return "STMicroelectronics ST9+ (8/16-bit)";
	case ELF_EM_ST7:	return "STMicroelectronics ST7 (8-bit)";
	case ELF_EM_68HC16:	return "Motorola 68HC16";
	case ELF_EM_68HC11:	return "Motorola 68HC11";
	case ELF_EM_68HC08:	return "Motorola 68HC08";
	case ELF_EM_68HC05:	return "Motorola 68HC05";
	case ELF_EM_SVX:	return "Silicon Graphics SVx";
	case ELF_EM_ST19:	return "STMicroelectronics ST19 (8-bit)";
	case ELF_EM_VAX:	return "DEC VAX";
	case ELF_EM_CRIS:	return "Axis Communications (32-bit)";
	case ELF_EM_JAVELIN:	return "Infineon Technologies (32-bit)";
	case ELF_EM_FIREPATH:	return "Element 14 DSP (64-bit)";
	case ELF_EM_ZSP:	return "LSI Logic DSP (16-bit)";
	case ELF_EM_MMIX:	return "Donald Knuth's educational processor (64-bit)";
	case ELF_EM_HUANY:	return "Harvard University machine-independent object files";
	case ELF_EM_PRISM:	return "SiTera Prism";
	case ELF_EM_AVR:	return "Atmel AVR (8-bit)";
	case ELF_EM_FR30:	return "Fujitsu FR30";
	case ELF_EM_D10V:	return "Mitsubishi D10V";
	case ELF_EM_D30V:	return "Mitsubishi D30V";
	case ELF_EM_V850:	return "NEC V850";
	case ELF_EM_M32R:	return "Mitsubishi M32R";
	case ELF_EM_MN10300:	return "Mitsubishi MN10300";
	case ELF_EM_MN10200:	return "Mitsubishi MN10200";
	case ELF_EM_PJ:	return "picoJava";
	case ELF_EM_OPENRISC:	return "OpenRISC (32-bit)";
	case ELF_EM_ARC_COMPACT:	return "ARC International ARCompact";
	case ELF_EM_XTENSA:	return "Tensilica Xtensa Architecture";
	case ELF_EM_VIDEOCORE:	return "Alphamosaic VideoCore";
	case ELF_EM_TMM_GPP:	return "Thompson Multimedia General Purpose";
	case ELF_EM_NS32K:	return "National Semiconductor 32000";
	case ELF_EM_TPC:	return "Tenor Network TPC";
	case ELF_EM_SNP1K:	return "Trebia SNP 1000";
	case ELF_EM_ST200:	return "STMicroelectronics ST200";
	case ELF_EM_IP2K:	return "Ubicom IP2xxx";
	case ELF_EM_MAX:	return "MAX";
	case ELF_EM_CR:	return "National Semiconductor CompactRISC";
	case ELF_EM_F2MC16:	return "Fujitsu F2MC16";
	case ELF_EM_MSP430:	return "Texas Instruments MSP430";
	case ELF_EM_BLACKFIN:	return "Analog Devices Blackfin DSP";
	case ELF_EM_SE_C33:	return "Seiko Epson S1C33";
	case ELF_EM_SEP:	return "Sharp";
	case ELF_EM_ARCA:	return "Arca RISC";
	case ELF_EM_UNICORE:	return "PKU-Unity/Pekin Unicore";
	case ELF_EM_EXCESS:	return "eXcess (16/32/64-bit)";
	case ELF_EM_DXP:	return "Icera Semiconductor Inc. Deep Execution";
	case ELF_EM_ALTERA_NIOS2:	return "Altera Nios II soft-core";
	case ELF_EM_CRX:	return "national Semiconductor CompactRISC CRX";
	case ELF_EM_XGATE:	return "Motorola XGATE";
	case ELF_EM_C116:	return "Infineon C16x/XC16x";
	case ELF_EM_M16C:	return "Renesas M32C";
	case ELF_EM_DSPIC30F:	return "Microchip Technology DSPIC30F";
	case ELF_EM_CE:	return "Freescale Communication Engine RISC";
	case ELF_EM_M32C:	return "Renesas M32C";
	case ELF_EM_TSK3000:	return "Altium TSK3000";
	case ELF_EM_RS08:	return "Freescale RS08";
	case ELF_EM_SHARC:	return "SHARC (32-bit)";
	case ELF_EM_ECOG2:	return "Cyan Technology eCOG2";
	case ELF_EM_SCORE7:	return "Sunplus S+core7 RISC";
	case ELF_EM_DSP24:	return "New Japan Radio (NJR) DSP (24-bit)";
	case ELF_EM_VIDEOCORE3:	return "Broadcom VideoCore III";
	case ELF_EM_LATTICEMICO32:	return "Lattice FPGA";
	case ELF_EM_SE_C17:	return "Seiko Epson C17";
	case ELF_EM_TI_C6000:	return "Texas Instruments TMS320C6000";
	case ELF_EM_TI_C2000:	return "Texas Instruments TMS320C2000";
	case ELF_EM_TI_C5500:	return "Texas Instruments TMS320C55xx";
	case ELF_EM_TI_ARP32:	return "Texas Instruments Application Specific RISC (32-bit)";
	case ELF_EM_TI_PRU:	return "Texas Instruments Programmable Realtime Unit";
	case ELF_EM_MMDSP_PLUS:	return "STMicroelectronics VLIW DSP (64-bit)";
	case ELF_EM_CYPRESS_M8C:	return "Cypress M8C";
	case ELF_EM_R32C:	return "Renesas R32C";
	case ELF_EM_TRIMEDIA:	return "NXP Semiconductors TriMedia";
	case ELF_EM_QDSP6:	return "QUALCOMM DSP6";
	case ELF_EM_8051:	return "Intel 8051";
	case ELF_EM_STXP7X:	return "STMicroelectronics STxP7x";
	case ELF_EM_NDS32:	return "Andes Technology RISC";
	case ELF_EM_ECOG1X:	return "Cyan Technology eCOG1X";
	case ELF_EM_MAXQ30:	return "Dallas Semiconductor MAXQ30";
	case ELF_EM_XIMO16:	return "New Japan Radio (NJR) DSP (16-bit)";
	case ELF_EM_MANIK:	return "M2000 Reconfigurable RISC";
	case ELF_EM_CRAYNV2:	return "Cray Inc. NV2";
	case ELF_EM_RX:	return "Renesas RX";
	case ELF_EM_METAG:	return "Imagination Technologies META";
	case ELF_EM_MCST_ELBRUS:	return "MCST Elbrus general purpose hardware";
	case ELF_EM_ECOG16:	return "Cyan Technology eCOG16";
	case ELF_EM_CR16:	return "National Semiconductor CompactRISC CR16 (16-bit)";
	case ELF_EM_ETPU:	return "Freescale Extended Time Processing Unit";
	case ELF_EM_SLE9X:	return "Infineon Technologies SLE9X";
	case ELF_EM_L10M:	return "Intel L10M";
	case ELF_EM_K10M:	return "Intel K10M";
	case ELF_EM_AARCH64:	return "ARM (64-bit)";
	case ELF_EM_AVR32:	return "Atmel Corporation (32-bit)";
	case ELF_EM_STM8:	return "STMicroeletronics STM8 (8-bit)";
	case ELF_EM_TILE64:	return "Tilera TILE64";
	case ELF_EM_TILEPRO:	return "Tilera TILEPro";
	case ELF_EM_MICROBLAZE:	return "Xilinx MicroBlaze RISC soft core (32-bit)";
	case ELF_EM_CUDA:	return "NVIDIA CUDA";
	case ELF_EM_TILEGX:	return "Tilera TILE-Gx";
	case ELF_EM_CLOUDSHIELD:	return "CloudShield";
	case ELF_EM_COREA_1ST:	return "KIPO-KAIST Core-A 1st generation";
	case ELF_EM_COREA_2ND:	return "KIPO-KAIST Core-A 2nd generation";
	case ELF_EM_ARC_COMPACT2:	return "Synopsys ARCompact V2";
	case ELF_EM_OPEN8:	return "Open8 RISC soft core (8-bit)";
	case ELF_EM_RL78:	return "Renesas RL78";
	case ELF_EM_VIDEOCORE5:	return "Broadcom VideoCore V";
	case ELF_EM_78KOR:	return "Renesas 78KOR";
	case ELF_EM_56800EX:	return "Freescale 56800EX DSC";
	case ELF_EM_BA1:	return "Beyond BA1";
	case ELF_EM_BA2:	return "Beyond BA2";
	case ELF_EM_XCORE:	return "XMOS xCORE";
	case ELF_EM_MCHP_PIC:	return "Microchip PIC(r) (8-bit)";
	case ELF_EM_INTEL205:	return "Reserved by Intel";
	case ELF_EM_INTEL206:	return "Reserved by Intel";
	case ELF_EM_INTEL207:	return "Reserved by Intel";
	case ELF_EM_INTEL208:	return "Reserved by Intel";
	case ELF_EM_INTEL209:	return "Reserved by Intel";
	case ELF_EM_KM32:	return "KM211 KM32 (32-bit)";
	case ELF_EM_KMX32:	return "KM211 KMX32 (32-bit)";
	case ELF_EM_KMX16:	return "KM211 KMX16 (16-bit)";
	case ELF_EM_KMX8:	return "KM211 KMX8 (8-bit)";
	case ELF_EM_KVARC:	return "KM211 KVARC";
	case ELF_EM_CDP:	return "Paneve CDP";
	case ELF_EM_COGE:	return "Cognitive Smart Memory";
	case ELF_EM_COOL:	return "Bluechip Systems";
	case ELF_EM_NORC:	return "Nanoradio Optimized RISC";
	case ELF_EM_CSR_KALIMBA:	return "CSR Kalimba";
	case ELF_EM_Z80:	return "Zilog Z80";
	case ELF_EM_VISIUM:	return "VISIUMcore";
	case ELF_EM_FT32:	return "FTDI Chip FT32 RISC (32-bit)";
	case ELF_EM_MOXIE:	return "Moxie";
	case ELF_EM_AMDGPU:	return "AMD GPU";
	case ELF_EM_RISCV:	return "RISC-V";
	case ELF_EM_LOONGARCH:	return "LoongArch";
	default:	return null;
	}
}

const(char) *adbg_object_elf_sht_string(int section) {
	switch (section) {
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
	default:	return null;
	}
}