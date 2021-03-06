/**
 * Object definitions.
 *
 * License: BSD-3-Clause
 */
module adbg.obj.def;

public:
immutable:

//
// Machine names
//

// ELF

const(char) *OBJ_MACH_NONE	= "None";
const(char) *OBJ_MACH_M32	= "AT&T WE 32100";
const(char) *OBJ_MACH_SPARC	= "SPARC";
const(char) *OBJ_MACH_386	= "Intel x86";
const(char) *OBJ_MACH_68K	= "Motorola 68000";
const(char) *OBJ_MACH_88K	= "Motorola 88000";
const(char) *OBJ_MACH_MCU	= "Intel MCU";
const(char) *OBJ_MACH_860	= "Intel 80860";
const(char) *OBJ_MACH_MIPS	= "MIPS I (RS3000)";
const(char) *OBJ_MACH_S370	= "IBM System/370";
const(char) *OBJ_MACH_MIPS_RS3_LE	= "MIPS I (RS3000) Little-Endian";
const(char) *OBJ_MACH_PARISC	= "Hewlett-Packard PA-RISC";
const(char) *OBJ_MACH_VPP500	= "Fujitsu VPP500";
const(char) *OBJ_MACH_SPARC32PLUS	= "Enhanced SPARC";
const(char) *OBJ_MACH_960	= "Intel 80960";
const(char) *OBJ_MACH_PPC	= "PowerPC";
const(char) *OBJ_MACH_PPC64	= "PowerPC (64-bit)";
const(char) *OBJ_MACH_S390	= "IBM System/390";
const(char) *OBJ_MACH_SPU	= "IBM SPU/SPC";
const(char) *OBJ_MACH_V800	= "NEC V800";
const(char) *OBJ_MACH_FR20	= "Fujitsu FR20";
const(char) *OBJ_MACH_RH32	= "TRW (RH32)";
const(char) *OBJ_MACH_RCE	= "Motorola RCE";
const(char) *OBJ_MACH_ARM	= "ARM (32-bit)";
const(char) *OBJ_MACH_ALPHA	= "DEC Alpha";
const(char) *OBJ_MACH_SH	= "Hitachi SuperH";
const(char) *OBJ_MACH_SPARCV9	= "SPARC Version 9";
const(char) *OBJ_MACH_TRICORE	= "Siemens TriCore embedded";
const(char) *OBJ_MACH_ARC	= "Argonaut RISC Core";
const(char) *OBJ_MACH_H8_300	= "Hitachi H8/300";
const(char) *OBJ_MACH_H8_300H	= "Hitachi H8/300H";
const(char) *OBJ_MACH_H8S	= "Hitachi H8S";
const(char) *OBJ_MACH_H8_500	= "Hitachi H8/500";
const(char) *OBJ_MACH_IA64	= "Intel Itanium Architecture 64";
const(char) *OBJ_MACH_MIPS_X	= "Stanford MIPS-X";
const(char) *OBJ_MACH_COLDFIRE	= "Motorola ColdFire";
const(char) *OBJ_MACH_68HC12	= "Motorola M68HC12";
const(char) *OBJ_MACH_MMA	= "Fujitsu MMA Multimedia Accelerator";
const(char) *OBJ_MACH_PCP	= "Siemens PCP";
const(char) *OBJ_MACH_NCPU	= "Sony nCPU embedded RISC";
const(char) *OBJ_MACH_NDR1	= "Denso NDR1";
const(char) *OBJ_MACH_STARCODE	= "Motorola Star*Core";
const(char) *OBJ_MACH_ME16	= "Toyota ME16";
const(char) *OBJ_MACH_ST100	= "STMicroelectronics ST100";
const(char) *OBJ_MACH_TINYJ	= "Advanced Logic Corp. TinyJ";
const(char) *OBJ_MACH_X86_64	= "AMD x86-64";
const(char) *OBJ_MACH_PDSP	= "Sony DSP";
const(char) *OBJ_MACH_PDP10	= "DEC PDP-10";
const(char) *OBJ_MACH_PDP11	= "DEC PDP-11";
const(char) *OBJ_MACH_FX66	= "Siemens FX66";
const(char) *OBJ_MACH_ST9PLUS	= "STMicroelectronics ST9+ (8/16-bit)";
const(char) *OBJ_MACH_ST7	= "STMicroelectronics ST7 (8-bit)";
const(char) *OBJ_MACH_68HC16	= "Motorola 68HC16";
const(char) *OBJ_MACH_68HC11	= "Motorola 68HC11";
const(char) *OBJ_MACH_68HC08	= "Motorola 68HC08";
const(char) *OBJ_MACH_68HC05	= "Motorola 68HC05";
const(char) *OBJ_MACH_SVX	= "Silicon Graphics SVx";
const(char) *OBJ_MACH_ST19	= "STMicroelectronics ST19 (8-bit)";
const(char) *OBJ_MACH_VAX	= "DEC VAX";
const(char) *OBJ_MACH_CRIS	= "Axis Communications (32-bit)";
const(char) *OBJ_MACH_JAVELIN	= "Infineon Technologies (32-bit)";
const(char) *OBJ_MACH_FIREPATH	= "Element 14 DSP (64-bit)";
const(char) *OBJ_MACH_ZSP	= "LSI Logic DSP (16-bit)";
const(char) *OBJ_MACH_MMIX	= "Donald Knuth's educational processor (64-bit)";
const(char) *OBJ_MACH_HUANY	= "Harvard University machine-independent object";
const(char) *OBJ_MACH_PRISM	= "SiTera Prism";
const(char) *OBJ_MACH_AVR	= "Atmel AVR (8-bit)";
const(char) *OBJ_MACH_FR30	= "Fujitsu FR30";
const(char) *OBJ_MACH_D10V	= "Mitsubishi D10V";
const(char) *OBJ_MACH_D30V	= "Mitsubishi D30V";
const(char) *OBJ_MACH_V850	= "NEC V850";
const(char) *OBJ_MACH_M32R	= "Mitsubishi M32R";
const(char) *OBJ_MACH_MN10300	= "Mitsubishi MN10300 (AM33)";
const(char) *OBJ_MACH_MN10200	= "Mitsubishi MN10200";
const(char) *OBJ_MACH_PJ	= "picoJava";
const(char) *OBJ_MACH_OPENRISC	= "OpenRISC (32-bit)";
const(char) *OBJ_MACH_ARC_COMPACT	= "ARC International ARCompact";
const(char) *OBJ_MACH_XTENSA	= "Tensilica Xtensa Architecture";
const(char) *OBJ_MACH_VIDEOCORE	= "Alphamosaic VideoCore";
const(char) *OBJ_MACH_TMM_GPP	= "Thompson Multimedia General Purpose";
const(char) *OBJ_MACH_NS32K	= "National Semiconductor 32000";
const(char) *OBJ_MACH_TPC	= "Tenor Network TPC";
const(char) *OBJ_MACH_SNP1K	= "Trebia SNP 1000";
const(char) *OBJ_MACH_ST200	= "STMicroelectronics ST200";
const(char) *OBJ_MACH_IP2K	= "Ubicom IP2xxx";
const(char) *OBJ_MACH_MAX	= "MAX";
const(char) *OBJ_MACH_CR	= "National Semiconductor CompactRISC";
const(char) *OBJ_MACH_F2MC16	= "Fujitsu F2MC16";
const(char) *OBJ_MACH_MSP430	= "Texas Instruments MSP430";
const(char) *OBJ_MACH_BLACKFIN	= "Analog Devices Blackfin DSP";
const(char) *OBJ_MACH_SE_C33	= "Seiko Epson S1C33";
const(char) *OBJ_MACH_SEP	= "Sharp";
const(char) *OBJ_MACH_ARCA	= "Arca RISC";
const(char) *OBJ_MACH_UNICORE	= "PKU-Unity/Pekin Unicore";
const(char) *OBJ_MACH_EXCESS	= "eXcess (16/32/64-bit)";
const(char) *OBJ_MACH_DXP	= "Icera Semiconductor Inc. Deep Execution";
const(char) *OBJ_MACH_ALTERA_NIOS2	= "Altera Nios II soft-core";
const(char) *OBJ_MACH_CRX	= "national Semiconductor CompactRISC CRX";
const(char) *OBJ_MACH_XGATE	= "Motorola XGATE";
const(char) *OBJ_MACH_C116	= "Infineon C16x/XC16x";
const(char) *OBJ_MACH_M16C	= "Renesas M32C";
const(char) *OBJ_MACH_DSPIC30F	= "Microchip Technology DSPIC30F";
const(char) *OBJ_MACH_CE	= "Freescale Communication Engine RISC";
const(char) *OBJ_MACH_M32C	= "Renesas M32C";
const(char) *OBJ_MACH_TSK3000	= "Altium TSK3000";
const(char) *OBJ_MACH_RS08	= "Freescale RS08";
const(char) *OBJ_MACH_SHARC	= "SHARC (32-bit)";
const(char) *OBJ_MACH_ECOG2	= "Cyan Technology eCOG2";
const(char) *OBJ_MACH_SCORE7	= "Sunplus S+core7 RISC";
const(char) *OBJ_MACH_DSP24	= "New Japan Radio (NJR) DSP (24-bit)";
const(char) *OBJ_MACH_VIDEOCORE3	= "Broadcom VideoCore III";
const(char) *OBJ_MACH_LATTICEMICO32	= "Lattice FPGA";
const(char) *OBJ_MACH_SE_C17	= "Seiko Epson C17";
const(char) *OBJ_MACH_TI_C6000	= "Texas Instruments TMS320C6000";
const(char) *OBJ_MACH_TI_C2000	= "Texas Instruments TMS320C2000";
const(char) *OBJ_MACH_TI_C5500	= "Texas Instruments TMS320C55xx";
const(char) *OBJ_MACH_TI_ARP32	= "Texas Instruments Application Specific RISC (32-bit)";
const(char) *OBJ_MACH_TI_PRU	= "Texas Instruments Programmable Realtime Unit";
const(char) *OBJ_MACH_MMDSP_PLUS	= "STMicroelectronics VLIW DSP (64-bit)";
const(char) *OBJ_MACH_CYPRESS_M8C	= "Cypress M8C";
const(char) *OBJ_MACH_R32C	= "Renesas R32C";
const(char) *OBJ_MACH_TRIMEDIA	= "NXP Semiconductors TriMedia";
const(char) *OBJ_MACH_QDSP6	= "QUALCOMM DSP6";
const(char) *OBJ_MACH_8051	= "Intel 8051";
const(char) *OBJ_MACH_STXP7X	= "STMicroelectronics STxP7x";
const(char) *OBJ_MACH_NDS32	= "Andes Technology RISC";
const(char) *OBJ_MACH_ECOG1X	= "Cyan Technology eCOG1X";
const(char) *OBJ_MACH_MAXQ30	= "Dallas Semiconductor MAXQ30";
const(char) *OBJ_MACH_XIMO16	= "New Japan Radio (NJR) DSP (16-bit)";
const(char) *OBJ_MACH_MANIK	= "M2000 Reconfigurable RISC";
const(char) *OBJ_MACH_CRAYNV2	= "Cray Inc. NV2";
const(char) *OBJ_MACH_RX	= "Renesas RX";
const(char) *OBJ_MACH_METAG	= "Imagination Technologies META";
const(char) *OBJ_MACH_MCST_ELBRUS	= "MCST Elbrus general purpose hardware";
const(char) *OBJ_MACH_ECOG16	= "Cyan Technology eCOG16";
const(char) *OBJ_MACH_CR16	= "National Semiconductor CompactRISC CR16 (16-bit)";
const(char) *OBJ_MACH_ETPU	= "Freescale Extended Time Processing Unit";
const(char) *OBJ_MACH_SLE9X	= "Infineon Technologies SLE9X";
const(char) *OBJ_MACH_L10M	= "Intel L10M";
const(char) *OBJ_MACH_K10M	= "Intel K10M";
const(char) *OBJ_MACH_AARCH64	= "ARM (64-bit)";
const(char) *OBJ_MACH_AVR32	= "Atmel Corporation (32-bit)";
const(char) *OBJ_MACH_STM8	= "STMicroeletronics STM8 (8-bit)";
const(char) *OBJ_MACH_TILE64	= "Tilera TILE64";
const(char) *OBJ_MACH_TILEPRO	= "Tilera TILEPro";
const(char) *OBJ_MACH_MICROBLAZE	= "Xilinx MicroBlaze RISC soft core (32-bit)";
const(char) *OBJ_MACH_CUDA	= "NVIDIA CUDA";
const(char) *OBJ_MACH_TILEGX	= "Tilera TILE-Gx";
const(char) *OBJ_MACH_CLOUDSHIELD	= "CloudShield";
const(char) *OBJ_MACH_COREA_1ST	= "KIPO-KAIST Core-A 1st generation";
const(char) *OBJ_MACH_COREA_2ND	= "KIPO-KAIST Core-A 2nd generation";
const(char) *OBJ_MACH_ARC_COMPACT2	= "Synopsys ARCompact V2";
const(char) *OBJ_MACH_OPEN8	= "Open8 RISC soft core (8-bit)";
const(char) *OBJ_MACH_RL78	= "Renesas RL78";
const(char) *OBJ_MACH_VIDEOCORE5	= "Broadcom VideoCore V";
const(char) *OBJ_MACH_78KOR	= "Renesas 78KOR";
const(char) *OBJ_MACH_56800EX	= "Freescale 56800EX DSC";
const(char) *OBJ_MACH_BA1	= "Beyond BA1";
const(char) *OBJ_MACH_BA2	= "Beyond BA2";
const(char) *OBJ_MACH_XCORE	= "XMOS xCORE";
const(char) *OBJ_MACH_MCHP_PIC	= "Microchip PIC(r) (8-bit)";
const(char) *OBJ_MACH_INTEL205	= "Reserved by Intel (205)";
const(char) *OBJ_MACH_INTEL206	= "Reserved by Intel (206)";
const(char) *OBJ_MACH_INTEL207	= "Reserved by Intel (207)";
const(char) *OBJ_MACH_INTEL208	= "Reserved by Intel (208)";
const(char) *OBJ_MACH_INTEL209	= "Reserved by Intel (209)";
const(char) *OBJ_MACH_KM32	= "KM211 KM32 (32-bit)";
const(char) *OBJ_MACH_KMX32	= "KM211 KMX32 (32-bit)";
const(char) *OBJ_MACH_KMX16	= "KM211 KMX16 (16-bit)";
const(char) *OBJ_MACH_KMX8	= "KM211 KMX8 (8-bit)";
const(char) *OBJ_MACH_KVARC	= "KM211 KVARC";
const(char) *OBJ_MACH_CDP	= "Paneve CDP";
const(char) *OBJ_MACH_COGE	= "Cognitive Smart Memory";
const(char) *OBJ_MACH_COOL	= "Bluechip Systems";
const(char) *OBJ_MACH_NORC	= "Nanoradio Optimized RISC";
const(char) *OBJ_MACH_CSR_KALIMBA	= "CSR Kalimba";
const(char) *OBJ_MACH_Z80	= "Zilog Z80";
const(char) *OBJ_MACH_VISIUM	= "VISIUMcore";
const(char) *OBJ_MACH_FT32	= "FTDI Chip FT32 RISC (32-bit)";
const(char) *OBJ_MACH_MOXIE	= "Moxie";
const(char) *OBJ_MACH_AMDGPU	= "AMD GPU";
const(char) *OBJ_MACH_RISCV	= "RISC-V";

// +PE32

const(char) *OBJ_MACH_ALPHA64	= "DEC Alpha (64-bit)";
const(char) *OBJ_MACH_ARMNT	= "ARM Thumb-2 (32-bit)";
const(char) *OBJ_MACH_EBC	= "EFI Byte Code";
const(char) *OBJ_MACH_MIPS16	= "MIPS16";
const(char) *OBJ_MACH_MIPSFPU	= "MIPS I with FPU";
const(char) *OBJ_MACH_MIPSFPU16	= "MIPS16 with FPU";
const(char) *OBJ_MACH_PPCFPU	= "PowerPC with FPU";
const(char) *OBJ_MACH_MIPSIII	= "MIPS III";	// R4000
const(char) *OBJ_MACH_MIPSIV	= "MIPS IV";	// R10000
const(char) *OBJ_MACH_RISCV32	= "RISC-V (32-bit)";
const(char) *OBJ_MACH_RISCV64	= "RISC-V (64-bit)";
const(char) *OBJ_MACH_RISCV128	= "RISC-V (128-bit)";
const(char) *OBJ_MACH_SH3	= "Hitachi SuperH 3";
const(char) *OBJ_MACH_SH3DSP	= "Hitachi SuperH 3 DSP";
const(char) *OBJ_MACH_SH4	= "Hitachi SuperH 4";
const(char) *OBJ_MACH_SH5	= "Hitachi SuperH 5";
const(char) *OBJ_MACH_THUMB	= "ARM Thumb";
const(char) *OBJ_MACH_WCEMIPSV2	= "MIPS little-endian WCE v2";
const(char) *OBJ_MACH_CLR	= "Common Language Runtime";
