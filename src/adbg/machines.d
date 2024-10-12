/// Object name definitions.
///
/// This module handles various machine definitions as expressed as
/// baseline instruction set architectures.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.machines;

import core.stdc.string : strcmp;
import adbg.error;

// NOTE: Machine enum names are the same as their alias name.
//       This avoids (mostly) possible collisions.

// TODO: Replace alias1/alias2
//       with either static or immutable dynamic array

/// Object machine type.
enum AdbgMachine {
	/// Unknown.
	unknown,
	
	/// Intel x86 16-bit (8086)
	i8086,
	/// Intel x86 32-bit (i386)
	i386,
	/// AMD x86 64-bit (amd64)
	amd64,
	/// Intel MCU
	mcu,
	/// Intel i860
	i860,
	/// Intel i960
	i960,
	/// Intel 8051
	i8051,
	/// Intel L10M
	l10m,
	/// Intel K10M
	k10m,
	/// Intel Itanium (EPIC, IA-64)
	ia64,
	
	/// Thumb 16-bit T16
	thumb,
	/// Thumb 32-bit T32 (Thumb-2)
	thumb32,
	/// Arm AArch32/A32
	arm,
	/// Arm AArch64/A64
	aarch64,
	/// ARM64EC: Compiled-Hybrid Portable Executable, Microsoft extension
	arm64ec,
	arm64x = arm64ec, /// Alias for arm64ec
	
	/// IBM ROMP
	romp,
	/// PowerPC/PowerISA
	ppc,
	/// PowerPC/PowerISA Little-Endian
	ppcle,
	/// PowerPC with FPU
	ppcfpu,
	/// PowerPC64/PowerISA 64-bit
	ppc64,
	/// PowerPC64/PowerISA 64-bit Little-Endian
	ppc64le,
	/// IBM System/370
	s370,
	/// IBM System/390
	s390,
	/// IBM SPU/SPC
	spu,
	/// IBM RS/6000
	rs6000,
	/// z/Architecture
	systemz,
	
	/// SPARC
	sparc,
	/// Enhanced SPARC
	sparc8p,
	/// SPARC Version 9
	sparc64,
	/// Alias for sparc64
	sparc9 = sparc64,

	/// RISC-V RV32
	riscv32,
	/// RISC-V RV64
	riscv64,
	/// RISC-V RV128
	riscv128,
	
	// Could consider adding the following:
	// MIPS32 "mips32" is based on MIPS II with features from III, IV, and V
	// MIPS64 "mips64"
	// microMIPS "umips"
	
	/// Stanford MIPS-X
	mipsx,
	/// MIPS I (R2000)
	mips,
	/// MIPS I with FPU
	mipsfpu,
	/// MIPS I Little-Endian
	mipsle,
	/// MIPS16 (microMIPS related?)
	mips16,
	/// MIPS16 with FPU
	mips16fpu,
	/// MIPS II (R6000)
	mipsii,
	/// MIPS III (R4000), support for 64-bit
	mipsiii,
	/// MIPS IV (R8000)
	mipsiv,
	/// MIPS little-endian WCE v2
	mipswcele,
	
	/// DEC PDP-10
	pdp10,
	/// DEC PDP-11
	pdp11,
	/// DEC VAX
	vax,
	/// DEC Alpha
	alpha,
	/// DEC Alpha (64-bit)
	alpha64,
	
	/// Motorola 68000
	m68k,
	/// Motorola 88000
	m88k, // NOTE: MC98000 *is* PowerPC
	/// Motorola 68HC05
	m68hc05,
	/// Motorola 68HC08
	m68hc08,
	/// Motorola 68HC11
	m68hc11,
	/// Motorola M68HC12
	m68hc12,
	/// Motorola 68HC16
	m68hc16,
	/// Motorola RCE
	rce,
	/// Motorola ColdFire
	coldfire,
	/// Motorola Star*Core
	starcore,
	/// Motorola XGATE
	xgate,
	
	/// Atmel AVR
	avr,
	/// Atmel AVR32
	avr32,
	
	/// Hitachi H8/300
	h8300,
	/// Hitachi H8/300H
	h8300h,
	/// Hitachi H8S
	h8s,
	/// Hitachi H8/500
	h8500,
	/// Hitachi SuperH
	sh,
	/// Hitachi SuperH 3
	sh3,
	/// Hitachi SuperH 3 DSP
	sh3dsp,
	/// Hitachi SuperH 4
	sh4,
	/// Hitachi SuperH 5
	sh5,
	
	/// Mitsubishi D10V
	d10v,
	/// Mitsubishi D30V
	d30v,
	/// Mitsubishi M32R
	m32r,
	/// Mitsubishi MN10300 (AM33)
	am33,
	/// Mitsubishi MN10200
	mn10200,
	/// Mitsubishi MN10300
	mn10300,
	
	/// ARC
	arc,
	/// XTensa
	xtensa,
	
	/// Renesas M16C
	m16c,
	/// Renesas M32C
	m32c,
	/// Renesas R32C
	r32c,
	/// Renesas RX
	rx,
	/// Renesas RL78
	rl78,
	/// Renesas 78KOR
	r78kor,
	
	/// Texas Instruments MSP430
	msp430,
	/// Texas Instruments TMS320C2000
	tic2000,
	/// Texas Instruments TMS320C55xx
	tic55xx,
	/// Texas Instruments TMS320C6000
	tic6000,
	/// Texas Instruments Application Specific RISC (32-bit)
	asrisc,
	/// Texas Instruments Programmable Realtime Unit
	pru,
	
	/// STMicroelectronics ST7 (8-bit)
	st7,
	/// STMicroelectronics STM8 (8-bit)
	stm8,
	/// STMicroelectronics ST9+ (8/16-bit)
	st9,
	/// STMicroelectronics ST19 (8-bit)
	st19,
	/// STMicroelectronics ST100
	st100,
	/// STMicroelectronics ST200
	st200,
	/// STMicroelectronics VLIW DSP (64-bit)
	vdsp,
	/// STMicroelectronics STxP7x
	stxp7x,
	
	/// Fujitsu VPP500
	vpp500,
	/// Fujitsu FR20
	fr20,
	/// Fujitsu MMA Multimedia Accelerator
	mma,
	/// Fujitsu FR30
	fr30,
	/// Fujitsu F2MC16
	f2mc16,
	
	/// National Semiconductor 32000
	ns32k,
	/// National Semiconductor CompactRISC
	cr,
	/// National Semiconductor CompactRISC CRX
	crx,
	/// National Semiconductor CompactRISC CR16 (16-bit)
	cr16,
	
	/// Freescale Communication Engine RISC
	ce,
	/// Freescale RS08
	rs08,
	/// Freescale Extended Time Processing Unit
	etpu,
	/// Freescale 56800EX DSC
	dsc,
	
	/// Siemens TriCore embedded
	tricore,
	/// Siemens PCP
	pcp,
	/// Siemens FX66
	fx66,

	/// KM211 KMX8 (8-bit)
	kmx8,
	/// KM211 KMX16 (16-bit)
	kmx16,
	/// KM211 KM32 (32-bit)
	km32,
	/// KM211 KMX32 (32-bit)
	kmx32,
	/// KM211 KVARC
	kvarc,
	
	/// Elbrus
	elbrus,
	
	/// NEC V800
	v800,
	/// NEC V850
	v850,
	
	/// LoonArch32 (Loongson)
	loongarch32,
	/// LoonArch64 (Loongson)
	loongarch64,
	
	/// SHARC
	sharc,
	
	/// Moxie soft processor
	moxie,
	
	/// Donald Knuth's educational processor
	mmix,
	/// Harvard University machine-independent object
	harvard,
	
	/// AMD GPU
	amdgpu,
	/// NVIDIA CUDA
	cuda,
	
	/// EFI Byte Code
	ebc,
	/// Common Language Runtime
	clr,
	/// picoJava
	pj,
	
	/// AT&T WE 32100
	we32100,
	/// Hewlett-Packard PA-RISC / HP-PA / HPPA
	hppa,
	/// Alias to hppa
	parisc = hppa,
	/// TRW (RH32)
	rh32,
	/// Argonaut RISC Core
	arisc,
	/// Sony nCPU embedded RISC
	ncpu,
	/// Denso NDR1
	ndr1,
	/// Toyota ME16
	me16,
	/// Advanced Logic Corp. TinyJ
	tinyj,
	/// Sony DSP
	sonydsp,
	/// Silicon Graphics SVx
	svx,
	/// Axis Communications (32-bit)
	axis,
	/// Element Firepath 14 DSP (64-bit)
	firepath,
	/// LSI Logic ZSP DSP (16-bit)
	zsp,
	/// SiTera Prism
	prism,
	/// OpenRISC (32-bit) (so far, OpenRISC 1000, "or1k")
	openrisc,
	/// Alphamosaic VideoCore
	videocore,
	/// Thompson Multimedia General Purpose
	tmm,
	/// Tenor Network TPC
	tpc,
	/// Trebia SNP 1000
	snp1k,
	/// Ubicom IP2xxx
	ip2k,
	/// MAX
	max_, // "max" would override .max property
	/// Analog Devices Blackfin DSP
	blackfin,
	/// Sharp
	sep,
	/// Arca RISC
	arca,
	/// PKU-Unity/Pekin Unicore
	unicore,
	/// eXcess (16/32/64-bit)
	excess,
	/// Icera Semiconductor Inc. Deep Execution (DXP)
	dxp,
	/// Altera Nios II soft-core
	nios2,
	/// Microchip Technology DSPIC30F
	dspic30f,
	/// Altium TSK3000
	tsk3000,
	/// Sunplus S+core7 RISC
	score7,
	/// Broadcom VideoCore III
	videocore3,
	/// Broadcom VideoCore V
	videocore5,
	/// Lattice FPGA
	mico32,
	/// Seiko Epson S1C33
	s1c33,
	/// Seiko Epson C17
	c17,
	/// Cypress M8C
	m8c,
	/// NXP Semiconductors TriMedia
	trimedia,
	/// Qualcomm DSP6
	dsp6,
	/// Andes Technology RISC
	nds32,
	/// Dallas Semiconductor MAXQ30
	maxq30,
	/// New Japan Radio (NJR) DSP (16-bit)
	dsp16,
	/// New Japan Radio (NJR) DSP (24-bit)
	dsp24,
	/// M2000 Reconfigurable RISC
	m2000,
	/// Cray Inc. NV2
	nv2,
	/// Imagination Technologies META
	meta,
	/// Cyan Technology eCOG16
	ecog16,
	/// Cyan Technology eCOG1X
	ecog1x,
	/// Cyan Technology eCOG2
	ecog2,
	/// Infineon C16x/XC16x
	c166,
	/// Infineon Technologies SLE9X (32-bit)
	sle9x,
	/// Tilera TILE64
	tile64,
	/// Tilera TILEPro
	tilepro,
	/// Tilera TILE-Gx
	tilegx,
	/// Xilinx MicroBlaze RISC soft core (32-bit)
	microblaze,
	/// CloudShield
	cloudshield,
	/// KIPO-KAIST Core-A 1st generation
	corea1,
	/// KIPO-KAIST Core-A 2nd generation
	corea2,
	/// Synopsys ARCompact V2
	arcc2,
	/// Open8 RISC soft core (8-bit)
	open8,
	/// Beyond BA1
	ba1,
	/// Beyond BA2
	ba2,
	/// XMOS xCORE
	xcore,
	/// Microchip PIC(r) (8-bit)
	picr8,
	/// Paneve CDP
	cdp,
	/// Cognitive Smart Memory
	csm,
	/// Bluechip Systems
	bluechip,
	/// Nanoradio Optimized RISC
	nano,
	/// CSR Kalimba
	csr,
	/// Zilog Z80
	z80,
	/// VISIUMcore
	visium,
	/// FTDI Chip FT32 RISC (32-bit)
	ftdi,
	/// VEO
	veo,
}

/// Machine name.
struct adbg_machine_t {
	/// Machine type.
	AdbgMachine machine;
	/// Short name.
	/// Example: "i386"
	const(char) *alias1;
	/// Common alias.
	/// Example: "x86"
	const(char) *alias2;
	/// Full name.
	/// Example: "Intel x86"
	const(char) *name;
}

// NOTE: Full name consistency.
//     - Proper names (like an English name or title).
//     - Avoid parentheses when possible as they can be confused with another set.
/// List of known machines.
immutable adbg_machine_t[] machines = [
	// Intel
	{ AdbgMachine.i8086,  "8086",  null,     "Intel 8086" },
	{ AdbgMachine.i386,   "i386",  "x86",    "Intel x86" },
	{ AdbgMachine.amd64,  "amd64", "x86_64", "AMD x86-64" },
	{ AdbgMachine.mcu,    "mcu",  null, "Intel MCU" },
	{ AdbgMachine.i860,   "i860", null, "Intel i860" },
	{ AdbgMachine.i960,   "i960", null, "Intel i960" },
	{ AdbgMachine.i8051,  "8051", null, "Intel 8051" },
	{ AdbgMachine.l10m,   "l10m", null, "Intel L10M" },
	{ AdbgMachine.k10m,   "k10m", null, "Intel K10M" },
	{ AdbgMachine.ia64,   "ia64", null, "Intel Itanium Architecture 64" },
	
	// Arm
	{ AdbgMachine.thumb,   "thumb", "t16", "ARM Thumb" },
	{ AdbgMachine.thumb32, "thumb32", "t32", "ARM Thumb-2 32-bit" },
	{ AdbgMachine.arm,     "arm", "arm32", "ARM 32-bit" },
	{ AdbgMachine.aarch64, "aarch64", "arm64", "ARM 64-bit" },
	{ AdbgMachine.arm64x,  "arm64ec", "arm64x", "ARM64EC" },
	
	// IBM
	{ AdbgMachine.romp,   "romp", null, "IBM ROMP" },
	{ AdbgMachine.ppc,    "ppc", null, "IBM PowerPC" },
	{ AdbgMachine.ppcle,  "ppcle", null, "IBM PowerPC Little-Endian" },
	{ AdbgMachine.ppcfpu, "ppcfpu", null, "IBM PowerPC with FPU" },
	{ AdbgMachine.ppc64,  "ppc64", null, "IBM PowerPC 64-bit" },
	{ AdbgMachine.ppc64le,"ppc64le", null, "IBM PowerPC 64-bit Little-Endian" },
	{ AdbgMachine.s370,   "s370", null, "IBM System/370" },
	{ AdbgMachine.s390,   "s390", null, "IBM System/390" },
	{ AdbgMachine.spu,    "spu", null, "IBM SPU/SPC" },
	{ AdbgMachine.rs6000, "rs6000", null, "IBM RS/6000" },
	{ AdbgMachine.systemz,"systemz", "s390x", "IBM z/Architecture" },
	
	// Sun Microsystems
	{ AdbgMachine.sparc,   "sparc", null, "SPARC" },
	{ AdbgMachine.sparc8p, "sparc8p", null, "Enhanced SPARC Version 8+" },
	{ AdbgMachine.sparc9,  "sparc9", "sparc64", "SPARC Version 9" },
	
	// RISC-V
	{ AdbgMachine.riscv32,  "riscv32", null, "RISC-V 32-bit" },
	{ AdbgMachine.riscv64,  "riscv64", null, "RISC-V 64-bit" },
	{ AdbgMachine.riscv128, "riscv128", null, "RISC-V 128-bit" },
	
	// MIPS
	{ AdbgMachine.mipsx,     "mipsx", null, "Stanford MIPS-X" },
	{ AdbgMachine.mips,      "mips", "rs3000", "MIPS I RS3000" },
	{ AdbgMachine.mipsfpu,   "mipsfpu", null, "MIPS I RS3000 with FPU" },
	{ AdbgMachine.mipsle,    "mipsle", null, "MIPS I RS3000 Little-Endian" },
	{ AdbgMachine.mips16,    "mips16", null, "MIPS16" },
	{ AdbgMachine.mips16fpu, "mips16fpu", null, "MIPS16 with FPU" },
	{ AdbgMachine.mipsii,    "mipsii", "r3000", "MIPS II R3000" },
	{ AdbgMachine.mipsiii,   "mipsiii", "r4000", "MIPS III R4000" },
	{ AdbgMachine.mipsiv,    "mipsiv", "r10000", "MIPS IV R10000" },
	{ AdbgMachine.mipswcele, "mipswcele", "wcev2le", "MIPS WCE v2 Little-Endian" },
	
	// DEC
	{ AdbgMachine.pdp10,   "pdp10", null, "DEC PDP-10" },
	{ AdbgMachine.pdp11,   "pdp11", null, "DEC PDP-11" },
	{ AdbgMachine.vax,     "vax", null, "DEC VAX" },
	{ AdbgMachine.alpha,   "alpha", null, "DEC Alpha" },
	{ AdbgMachine.alpha64, "alpha64", null, "DEC Alpha 64-bit" },
	
	// Motorola
	{ AdbgMachine.m68k,     "m68k", "m68000", "Motorola 68000" },
	{ AdbgMachine.m88k,     "m88k", "m88000", "Motorola 88000" },
	{ AdbgMachine.m68hc05,  "m68hc05", null, "Motorola 68HC05" },
	{ AdbgMachine.m68hc08,  "m68hc08", null, "Motorola 68HC08" },
	{ AdbgMachine.m68hc11,  "m68hc11", null, "Motorola 68HC11" },
	{ AdbgMachine.m68hc12,  "m68hc12", null, "Motorola M68HC12" },
	{ AdbgMachine.m68hc16,  "m68hc16", null, "Motorola 68HC16" },
	{ AdbgMachine.rce,      "rce", null, "Motorola RCE" },
	{ AdbgMachine.coldfire, "coldfire", null, "Motorola ColdFire" },
	{ AdbgMachine.starcore, "starcore", null, "Motorola Star*Core" },
	{ AdbgMachine.xgate,    "xgate", null, "Motorola XGATE" },
	
	// Atmel
	{ AdbgMachine.avr,   "avr", null, "Atmel AVR 8-bit" },
	{ AdbgMachine.avr32, "avr32", null, "Atmel AVR 32-bit" },
	
	// Hitachi
	{ AdbgMachine.h8300,  "h8300", null, "Hitachi H8/300" },
	{ AdbgMachine.h8300h, "h8300h", null, "Hitachi H8/300H" },
	{ AdbgMachine.h8s,    "h8s", null, "Hitachi H8S" },
	{ AdbgMachine.h8500,  "h8500", null, "Hitachi H8/500" },
	{ AdbgMachine.sh,     "sh", null, "Hitachi SuperH" },
	{ AdbgMachine.sh3,    "sh3", null, "Hitachi SuperH 3" },
	{ AdbgMachine.sh3dsp, "sh3dsp", null, "Hitachi SuperH 3 DSP" },
	{ AdbgMachine.sh4,    "sh4", null, "Hitachi SuperH 4" },
	{ AdbgMachine.sh5,    "sh5", null, "Hitachi SuperH 5" },
	
	// Mitsubishi
	{ AdbgMachine.d10v,    "d10v", null, "Mitsubishi D10V" },
	{ AdbgMachine.d30v,    "d30v", null, "Mitsubishi D30V" },
	{ AdbgMachine.m32r,    "m32r", null, "Mitsubishi M32R" },
	{ AdbgMachine.am33,    "am33", null, "Mitsubishi AM33" }, // MN10300?
	{ AdbgMachine.mn10200, "mn10200", null, "Mitsubishi MN10200" },
	{ AdbgMachine.mn10300, "mn10300", null, "Mitsubishi MN10300" },
	
	// ARC
	{ AdbgMachine.arc, "arc", null, "ARC International ARCompact" },
	
	// XTENSA
	{ AdbgMachine.xtensa, "xtensa", null, "Tensilica Xtensa" },
	
	// Renesas
	{ AdbgMachine.m16c,   "m16c", null, "Renesas M16C" },
	{ AdbgMachine.m32c,   "m32c", null, "Renesas M32C" },
	{ AdbgMachine.r32c,   "r32c", null, "Renesas R32C" },
	{ AdbgMachine.rx,     "rx", null, "Renesas RX" },
	{ AdbgMachine.rl78,   "rl78", null, "Renesas RL78" },
	{ AdbgMachine.r78kor, "r78kor", null, "Renesas 78KOR" },
	
	// Texas Instruments
	{ AdbgMachine.msp430,  "msp430", null, "Texas Instruments MSP430" },
	{ AdbgMachine.tic2000, "tic2000", null, "Texas Instruments TMS320C2000" },
	{ AdbgMachine.tic55xx, "tic55xx", null, "Texas Instruments TMS320C55xx" },
	{ AdbgMachine.tic6000, "tic6000", null, "Texas Instruments TMS320C6000" },
	{ AdbgMachine.asrisc,  "asrisc", null, "Texas Instruments Application Specific RISC 32-bit" },
	{ AdbgMachine.pru,     "pru", null, "Texas Instruments Programmable Realtime Unit" },
	
	// STMicroelectronics
	{ AdbgMachine.st7,    "st7", null, "STMicroelectronics ST7 8-bit" },
	{ AdbgMachine.stm8,   "stm8", null, "STMicroelectronics STM8 8-bit" },
	{ AdbgMachine.st9,    "st9", null, "STMicroelectronics ST9+ 8/16-bit" },
	{ AdbgMachine.st19,   "st19", null, "STMicroelectronics ST19 8-bit" },
	{ AdbgMachine.st100,  "st100", null, "STMicroelectronics ST100" },
	{ AdbgMachine.st200,  "st200", null, "STMicroelectronics ST200" },
	{ AdbgMachine.vdsp,   "vdsp", null, "STMicroelectronics VLIW DSP 64-bit" },
	{ AdbgMachine.stxp7x, "stxp7x", null, "STMicroelectronics STxP7x" },
	
	// Fujistu
	{ AdbgMachine.vpp500, "vpp500", null, "Fujitsu VPP500" },
	{ AdbgMachine.fr20,   "fr20", null, "Fujitsu FR20" },
	{ AdbgMachine.mma,    "mma", null, "Fujitsu MMA Multimedia Accelerator" },
	{ AdbgMachine.fr30,   "fr30", null, "Fujitsu FR30" },
	{ AdbgMachine.f2mc16, "f2mc16", null, "Fujitsu F2MC16" },
	
	// National Semiconductor
	{ AdbgMachine.ns32k, "ns32k", null, "National Semiconductor 32000" },
	{ AdbgMachine.cr,    "cr", null, "National Semiconductor CompactRISC" },
	{ AdbgMachine.crx,   "crx", null, "National Semiconductor CompactRISC CRX" },
	{ AdbgMachine.cr16,  "cr16", null, "National Semiconductor CompactRISC CR16 16-bit" },
	
	// Freescale
	{ AdbgMachine.ce,   "ce", null, "Freescale Communication Engine RISC" },
	{ AdbgMachine.rs08, "rs08", null, "Freescale RS08" },
	{ AdbgMachine.etpu, "etpu", null, "Freescale Extended Time Processing Unit" },
	{ AdbgMachine.dsc,  "dsc", null, "Freescale 56800EX DSC" },
	
	// Siemens
	{ AdbgMachine.tricore, "tricore", null, "Siemens TriCore embedded" },
	{ AdbgMachine.pcp,     "pcp", null, "Siemens PCP" },
	{ AdbgMachine.fx66,    "fx66", null, "Siemens FX66" },
	
	// KM211
	{ AdbgMachine.kmx8,  "kmx8", null, "KM211 KMX8 8-bit" },
	{ AdbgMachine.kmx16, "kmx16", null, "KM211 KMX16 16-bit" },
	{ AdbgMachine.km32,  "km32", null, "KM211 KM32 32-bit" },
	{ AdbgMachine.kmx32, "kmx32", null, "KM211 KMX32 32-bit" },
	{ AdbgMachine.kvarc, "kvarc", null, "KM211 KVARC" },
	
	// MCST
	{ AdbgMachine.elbrus, "elbrus", null, "MCST Elbrus" },
	
	// NEC
	{ AdbgMachine.v800, "v800", null, "NEC V800" },
	{ AdbgMachine.v850, "v850", null, "NEC V850" },
	
	// Loongson
	{ AdbgMachine.loongarch32, "loongarch32", null, "LoongArch32" },
	{ AdbgMachine.loongarch64, "loongarch64", null, "LoongArch64" },
	
	// Analog Devices
	{ AdbgMachine.sharc, "sharc", null, "SHARC 32-bit" },
	
	// Soft processor group
	{ AdbgMachine.moxie, "moxie", null, "Moxie" },
	
	// Educational group
	{ AdbgMachine.mmix,    "mmix", null, "Donald Knuth's educational processor 64-bit" },
	{ AdbgMachine.harvard, "harvard", null, "Harvard University machine-independent object" },
	
	// GPU group
	{ AdbgMachine.amdgpu, "amdgpu", null, "AMD GPU" },
	{ AdbgMachine.cuda,   "cuda", null, "NVIDIA CUDA" },
	
	// Bytecode group
	{ AdbgMachine.ebc, "ebc", "efi", "EFI Byte Code" },
	{ AdbgMachine.clr, "clr", null, "Common Language Runtime" },
	{ AdbgMachine.pj,  "pj", "picojava", "picoJava" },
	
	// Etc.
	{ AdbgMachine.we32100,	"we32100", null, "AT&T WE 32100" },
	{ AdbgMachine.parisc,	"parisc", null, "Hewlett-Packard PA-RISC" },
	{ AdbgMachine.rh32,	"rh32", null, "TRW RH32" },
	{ AdbgMachine.arisc,	"arisc", null, "Argonaut RISC Core" },
	{ AdbgMachine.ncpu,	"ncpu", null, "Sony nCPU embedded RISC" },
	{ AdbgMachine.ndr1,	"ndr1", null, "Denso NDR1" },
	{ AdbgMachine.me16,	"me16", null, "Toyota ME16" },
	{ AdbgMachine.tinyj,	"tinyj", null, "Advanced Logic Corp. TinyJ" },
	{ AdbgMachine.sonydsp,	"sonydsp", null, "Sony DSP" },
	{ AdbgMachine.svx,	"svx", null, "Silicon Graphics SVx" },
	{ AdbgMachine.axis,	"axis", null, "Axis Communications 32-bit" },
	{ AdbgMachine.firepath,	"firepath", null, "Element Firepath 14 DSP 64-bit" },
	{ AdbgMachine.zsp,	"zsp", null, "LSI Logic ZSP DSP 16-bit" },
	{ AdbgMachine.prism,	"prism", null, "SiTera Prism" },
	{ AdbgMachine.openrisc,	"openrisc", null, "OpenRISC 32-bit" },
	{ AdbgMachine.videocore,	"videocore", null, "Alphamosaic VideoCore" },
	{ AdbgMachine.tmm,	"tmm", null, "Thompson Multimedia General Purpose" },
	{ AdbgMachine.tpc,	"tpc", null, "Tenor Network TPC" },
	{ AdbgMachine.snp1k,	"snp1k", null, "Trebia SNP 1000" },
	{ AdbgMachine.ip2k,	"ip2k", null, "Ubicom IP2xxx" },
	{ AdbgMachine.max_,	"max", null, "MAX" }, // overrides .max property...
	{ AdbgMachine.blackfin,	"blackfin", null, "Analog Devices Blackfin DSP" },
	{ AdbgMachine.sep,	"sep", null, "Sharp" },
	{ AdbgMachine.arca,	"arca", null, "Arca RISC" },
	{ AdbgMachine.unicore,	"unicore", null, "PKU-Unity/Pekin Unicore" },
	{ AdbgMachine.excess,	"excess", null, "eXcess 16/32/64-bit" },
	{ AdbgMachine.dxp,	"dxp", null, "Icera Semiconductor Inc. Deep Execution" },
	{ AdbgMachine.nios2,	"nios2", null, "Altera Nios II soft-core" },
	{ AdbgMachine.dspic30f,	"dspic30f", null, "Microchip Technology DSPIC30F" },
	{ AdbgMachine.tsk3000,	"tsk3000", null, "Altium TSK3000" },
	{ AdbgMachine.score7,	"score7", null, "Sunplus S+core7 RISC" },
	{ AdbgMachine.videocore3,	"videocore3", null, "Broadcom VideoCore III" },
	{ AdbgMachine.videocore5,	"videocore5", null, "Broadcom VideoCore V" },
	{ AdbgMachine.mico32,	"mico32", null, "Lattice FPGA" },
	{ AdbgMachine.s1c33,	"s1c33", null, "Seiko Epson S1C33" },
	{ AdbgMachine.c17,	"c17", null, "Seiko Epson C17" },
	{ AdbgMachine.m8c,	"m8c", null, "Cypress M8C" },
	{ AdbgMachine.trimedia,	"trimedia", null, "NXP Semiconductors TriMedia" },
	{ AdbgMachine.dsp6,	"dsp6", null, "Qualcomm DSP6" },
	{ AdbgMachine.nds32,	"nds32", null, "Andes Technology RISC" },
	{ AdbgMachine.maxq30,	"maxq30", null, "Dallas Semiconductor MAXQ30" },
	{ AdbgMachine.dsp16,	"dsp16", null, "New Japan Radio DSP 16-bit" },
	{ AdbgMachine.dsp24,	"dsp24", null, "New Japan Radio DSP 24-bit" },
	{ AdbgMachine.m2000,	"m2000", null, "M2000 Reconfigurable RISC" },
	{ AdbgMachine.nv2,	"nv2", null, "Cray Inc. NV2" },
	{ AdbgMachine.meta,	"meta", null, "Imagination Technologies META" },
	{ AdbgMachine.ecog16,	"ecog16", null, "Cyan Technology eCOG16" },
	{ AdbgMachine.ecog1x,	"ecog1x", null, "Cyan Technology eCOG1X" },
	{ AdbgMachine.ecog2,	"ecog2", null, "Cyan Technology eCOG2" },
	{ AdbgMachine.c166,	"c166", null, "Infineon C16x/XC16x" },
	{ AdbgMachine.sle9x,	"sle9x", null, "Infineon Technologies SLE9X 32-bit" },
	{ AdbgMachine.tile64,	"tile64", null, "Tilera TILE64" },
	{ AdbgMachine.tilepro,	"tilepro", null, "Tilera TILEPro" },
	{ AdbgMachine.tilegx,	"tilegx", null, "Tilera TILE-Gx" },
	{ AdbgMachine.microblaze,	"microblaze", null, "Xilinx MicroBlaze RISC soft core 32-bit" },
	{ AdbgMachine.cloudshield,	"cloudshield", null, "CloudShield" },
	{ AdbgMachine.corea1,	"corea1", null, "KIPO-KAIST Core-A 1st generation" },
	{ AdbgMachine.corea2,	"corea2", null, "KIPO-KAIST Core-A 2nd generation" },
	{ AdbgMachine.arcc2,	"arcc2", null, "Synopsys ARCompact V2" },
	{ AdbgMachine.open8,	"open8", null, "Open8 RISC soft core 8-bit" },
	{ AdbgMachine.ba1,	"ba1", null, "Beyond BA1" },
	{ AdbgMachine.ba2,	"ba2", null, "Beyond BA2" },
	{ AdbgMachine.xcore,	"xcore", null, "XMOS xCORE" },
	{ AdbgMachine.picr8,	"picr8", null, "Microchip PIC(r) 8-bit" },
	{ AdbgMachine.cdp,	"cdp", null, "Paneve CDP" },
	{ AdbgMachine.csm,	"csm", null, "Cognitive Smart Memory" },
	{ AdbgMachine.bluechip,	"bluechip", null, "Bluechip Systems" },
	{ AdbgMachine.nano,	"nano", null, "Nanoradio Optimized RISC" },
	{ AdbgMachine.csr,	"csr", null, "CSR Kalimba" },
	{ AdbgMachine.z80,	"z80", null, "Zilog Z80" },
	{ AdbgMachine.visium,	"visium", null, "VISIUMcore" },
	{ AdbgMachine.ftdi,	"ftdi", null, "FTDI Chip FT32 RISC 32-bit" },
	{ AdbgMachine.veo,	"veo", null, "VEO" },
];

static assert(cast(int)machines.length == AdbgMachine.max, "Count mistmatch");

// Target default machine
// These are expected targets that this project supports
version (X86)		private enum CURRENT_MACHINE = AdbgMachine.i386;
else version (X86_64)	private enum CURRENT_MACHINE = AdbgMachine.amd64;
else version (Arm)	private enum CURRENT_MACHINE = AdbgMachine.arm;
else version (AArch64)	private enum CURRENT_MACHINE = AdbgMachine.aarch64;
else version (PPC)	private enum CURRENT_MACHINE = AdbgMachine.ppc;
else version (PPC64)	private enum CURRENT_MACHINE = AdbgMachine.ppc64;
else version (SPARC)	private enum CURRENT_MACHINE = AdbgMachine.sparc;
else version (SPARC64)	private enum CURRENT_MACHINE = AdbgMachine.sparc64;
else version (S390)	private enum CURRENT_MACHINE = AdbgMachine.s390;
else version (SystemZ)	private enum CURRENT_MACHINE = AdbgMachine.systemz;
else version (RISCV32)	private enum CURRENT_MACHINE = AdbgMachine.riscv32;
else version (RISCV64)	private enum CURRENT_MACHINE = AdbgMachine.riscv64;
else static assert(false, "Add CURRENT_MACHINE for target");

/// Return the current machine target type.
///
/// For example, if this binary was compiled targetting AMD64 machines,
/// it will return amd64. If it targetted RISC-V 32-bit, then riscv32
/// will be returned
/// Returns: Machine value.
AdbgMachine adbg_machine_current() { return CURRENT_MACHINE; }

/// Get the number of registered machine platforms.
/// Returns: Count.
size_t adbg_machine_count() { return machines.length; }

/// Select a machine architecture from an machine enum value.
/// Params: mach = Machine enumeration value.
/// Returns: Machine pointer or null.
immutable(adbg_machine_t)* adbg_machine(AdbgMachine mach) {
	size_t i = cast(size_t)(mach - 1); // Skip "unknown"
	if (i >= machines.length) {
		adbg_oops(AdbgError.indexBounds);
		return null;
	}
	return &machines[i];
}
extern (D) unittest {
	assert(adbg_machine(cast(AdbgMachine)-1) == null);
	assert(adbg_machine(cast(AdbgMachine)0)  == null);
	assert(adbg_machine(AdbgMachine.i8086).machine  == AdbgMachine.i8086);
	assert(adbg_machine(AdbgMachine.am33).machine   == AdbgMachine.am33);
	for (size_t i = 1; i < machines.length; ++i) {
		immutable(adbg_machine_t)* m = adbg_machine(cast(AdbgMachine)i);
		assert(m);
		assert(m.machine == cast(AdbgMachine)i);
	}
}

/// Get machine alias from enumeration value.
/// Params: mach = Machine value.
/// Returns: Machine name, or null if invalid.
const(char)* adbg_machine_alias(AdbgMachine mach) {
	immutable(adbg_machine_t)* m = adbg_machine(mach);
	if (m == null) // Error already set.
		return null;
	return m.alias1;
}

/// Get machine name from enumeration value.
/// Params: mach = Machine value.
/// Returns: Machine name, or null if invalid.
const(char)* adbg_machine_name(AdbgMachine mach) {
	immutable(adbg_machine_t)* m = adbg_machine(mach);
	if (m == null) // Error already set.
		return null;
	return m.name;
}

/// Search a machine architecture by one of its alias name.
/// Params: alias_ = Alias string.
/// Returns: Machine pointer or null.
immutable(adbg_machine_t)* adbg_machine_select(const(char) *alias_) {
	if (alias_ == null) return null;
	
	for (size_t i; i < machines.length; ++i) {
		immutable(adbg_machine_t)* machine = &machines[i];
		
		assert(machine.alias1);
		if (strcmp(alias_, machine.alias1) == 0)
			return machine;
		
		if (machine.alias2 == null) continue;
		if (strcmp(alias_, machine.alias2) == 0)
			return machine;
	}
	
	adbg_oops(AdbgError.unfindable);
	return null;
}
extern (D) unittest {
	assert(adbg_machine_select(null) == null);
	assert(adbg_machine_select("I do not exist!") == null);
	assert(adbg_machine_select("8086").machine == AdbgMachine.i8086);
	assert(adbg_machine_select("i386").machine == AdbgMachine.i386);
	assert(adbg_machine_select("amd64").machine == AdbgMachine.amd64);
	assert(adbg_machine_select("mips").machine == AdbgMachine.mips);
	assert(adbg_machine_select("sparc64").machine == AdbgMachine.sparc9);
}