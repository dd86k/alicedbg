/// Object definitions and enumerations.
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

// TODO: AdbgMachineExtension? (Useful for disassembly options)
//       Bitflags, long

/// Word endian.
enum AdbgEndian { big, little }

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

/// Machine definition structure.
///
/// To access members of an instance of this structure,
/// it is highly recommended to use the appropriate get function.
struct adbg_machine_t {
	/// Machine identification number.
	AdbgMachine id;
	/// Full name.
	/// Example: "Intel x86"
	const(char) *name;
	/// List of aliases for this machine
	/// Example: "i386", "x86"
	const(char)*[] aliases;
	// TODO: Default endian?
}

private // Alias list, adds null terminator
template A(l...) { enum A = cast(immutable(char)*[])[l]~null; }

// NOTE: Full name consistency.
//     - Proper names (like an English name or title).
//     - Avoid parentheses when possible as they can be confused with another set.
/// List of known machines.
immutable adbg_machine_t[] machines = [
	// Intel
	{ AdbgMachine.i8086,  "Intel 8086",  A!("8086") },
	{ AdbgMachine.i386,   "Intel x86",   A!("i386", "x86") },
	{ AdbgMachine.amd64,  "AMD x86-64",  A!("amd64", "x86_64") },
	{ AdbgMachine.mcu,    "Intel MCU",   A!("mcu") },
	{ AdbgMachine.i860,   "Intel i860",  A!("i860") },
	{ AdbgMachine.i960,   "Intel i960",  A!("i960") },
	{ AdbgMachine.i8051,  "Intel 8051",  A!("8051") },
	{ AdbgMachine.l10m,   "Intel L10M",  A!("l10m") },
	{ AdbgMachine.k10m,   "Intel K10M",  A!("k10m") },
	{ AdbgMachine.ia64,   "Intel Itanium Architecture 64", A!("ia64") },
	
	// Arm
	{ AdbgMachine.thumb,   "ARM Thumb",  A!("thumb", "t16") },
	{ AdbgMachine.thumb32, "ARM Thumb-2 32-bit", A!("thumb32", "t32") },
	{ AdbgMachine.arm,     "ARM 32-bit", A!("arm", "arm32") },
	{ AdbgMachine.aarch64, "ARM 64-bit", A!("aarch64", "arm64") },
	{ AdbgMachine.arm64x,  "ARM64EC",    A!("arm64ec", "arm64x") },
	
	// IBM
	{ AdbgMachine.romp,    "IBM ROMP",       A!("romp") },
	{ AdbgMachine.ppc,     "IBM PowerPC",    A!("ppc") },
	{ AdbgMachine.ppcle,   "IBM PowerPC Little-Endian", A!("ppcle") },
	{ AdbgMachine.ppcfpu,  "IBM PowerPC with FPU", A!("ppcfpu") },
	{ AdbgMachine.ppc64,   "IBM PowerPC 64-bit",   A!("ppc64") },
	{ AdbgMachine.ppc64le, "IBM PowerPC 64-bit Little-Endian", A!("ppc64le") },
	{ AdbgMachine.s370,    "IBM System/370", A!("s370") },
	{ AdbgMachine.s390,    "IBM System/390", A!("s390") },
	{ AdbgMachine.spu,     "IBM SPU/SPC",    A!("spu")  },
	{ AdbgMachine.rs6000,  "IBM RS/6000",    A!("rs6000") },
	{ AdbgMachine.systemz, "IBM z/Architecture", A!("systemz", "s390x") },
	
	// Sun Microsystems
	{ AdbgMachine.sparc,   "SPARC", A!("sparc") },
	{ AdbgMachine.sparc8p, "Enhanced SPARC Version 8+", A!("sparc8p") },
	{ AdbgMachine.sparc9,  "SPARC Version 9", A!("sparc9", "sparc64") },
	
	// RISC-V
	{ AdbgMachine.riscv32,  "RISC-V 32-bit",  A!("riscv32") },
	{ AdbgMachine.riscv64,  "RISC-V 64-bit",  A!("riscv64") },
	{ AdbgMachine.riscv128, "RISC-V 128-bit", A!("riscv128") },
	
	// MIPS
	{ AdbgMachine.mipsx,     "Stanford MIPS-X", A!("mipsx") },
	{ AdbgMachine.mips,      "MIPS I RS3000",   A!("mips", "rs3000") },
	{ AdbgMachine.mipsfpu,   "MIPS I RS3000 with FPU", A!("mipsfpu") },
	{ AdbgMachine.mipsle,    "MIPS I RS3000 Little-Endian", A!("mipsle") },
	{ AdbgMachine.mips16,    "MIPS16",          A!("mips16") },
	{ AdbgMachine.mips16fpu, "MIPS16 with FPU", A!("mips16fpu") },
	{ AdbgMachine.mipsii,    "MIPS II R3000",   A!("mipsii", "r3000") },
	{ AdbgMachine.mipsiii,   "MIPS III R4000",  A!("mipsiii", "r4000") },
	{ AdbgMachine.mipsiv,    "MIPS IV R10000",  A!("mipsiv", "r10000") },
	{ AdbgMachine.mipswcele, "MIPS WCE v2 Little-Endian", A!("mipswcele", "wcev2le") },
	
	// DEC
	{ AdbgMachine.pdp10,   "DEC PDP-10",       A!("pdp10") },
	{ AdbgMachine.pdp11,   "DEC PDP-11",       A!("pdp11") },
	{ AdbgMachine.vax,     "DEC VAX",          A!("vax") },
	{ AdbgMachine.alpha,   "DEC Alpha",        A!("alpha") },
	{ AdbgMachine.alpha64, "DEC Alpha 64-bit", A!("alpha64") },
	
	// Motorola
	{ AdbgMachine.m68k,     "Motorola 68000",     A!("m68k", "m68000") },
	{ AdbgMachine.m88k,     "Motorola 88000",     A!("m88k", "m88000") },
	{ AdbgMachine.m68hc05,  "Motorola 68HC05",    A!("m68hc05") },
	{ AdbgMachine.m68hc08,  "Motorola 68HC08",    A!("m68hc08") },
	{ AdbgMachine.m68hc11,  "Motorola 68HC11",    A!("m68hc11") },
	{ AdbgMachine.m68hc12,  "Motorola M68HC12",   A!("m68hc12") },
	{ AdbgMachine.m68hc16,  "Motorola 68HC16",    A!("m68hc16") },
	{ AdbgMachine.rce,      "Motorola RCE",       A!("rce") },
	{ AdbgMachine.coldfire, "Motorola ColdFire",  A!("coldfire") },
	{ AdbgMachine.starcore, "Motorola Star*Core", A!("starcore") },
	{ AdbgMachine.xgate,    "Motorola XGATE",     A!("xgate") },
	
	// Atmel
	{ AdbgMachine.avr,   "Atmel AVR 8-bit",  A!("avr") },
	{ AdbgMachine.avr32, "Atmel AVR 32-bit", A!("avr32") },
	
	// Hitachi
	{ AdbgMachine.h8300,  "Hitachi H8/300",       A!("h8300") },
	{ AdbgMachine.h8300h, "Hitachi H8/300H",      A!("h8300h") },
	{ AdbgMachine.h8s,    "Hitachi H8S",          A!("h8s") },
	{ AdbgMachine.h8500,  "Hitachi H8/500",       A!("h8500") },
	{ AdbgMachine.sh,     "Hitachi SuperH",       A!("sh") },
	{ AdbgMachine.sh3,    "Hitachi SuperH 3",     A!("sh3") },
	{ AdbgMachine.sh3dsp, "Hitachi SuperH 3 DSP", A!("sh3dsp") },
	{ AdbgMachine.sh4,    "Hitachi SuperH 4",     A!("sh4") },
	{ AdbgMachine.sh5,    "Hitachi SuperH 5",     A!("sh5") },
	
	// Mitsubishi
	{ AdbgMachine.d10v,    "Mitsubishi D10V",    A!("d10v") },
	{ AdbgMachine.d30v,    "Mitsubishi D30V",    A!("d30v") },
	{ AdbgMachine.m32r,    "Mitsubishi M32R",    A!("m32r") },
	{ AdbgMachine.am33,    "Mitsubishi AM33",    A!("am33") }, // MN10300?
	{ AdbgMachine.mn10200, "Mitsubishi MN10200", A!("mn10200") },
	{ AdbgMachine.mn10300, "Mitsubishi MN10300", A!("mn10300") },
	
	// ARC
	{ AdbgMachine.arc, "ARC International ARCompact", A!("arc") },
	
	// Xtensa
	{ AdbgMachine.xtensa, "Tensilica Xtensa", A!("xtensa") },
	
	// Renesas
	{ AdbgMachine.m16c,   "Renesas M16C",  A!("m16c") },
	{ AdbgMachine.m32c,   "Renesas M32C",  A!("m32c") },
	{ AdbgMachine.r32c,   "Renesas R32C",  A!("r32c") },
	{ AdbgMachine.rx,     "Renesas RX",    A!("rx") },
	{ AdbgMachine.rl78,   "Renesas RL78",  A!("rl78") },
	{ AdbgMachine.r78kor, "Renesas 78KOR", A!("r78kor") },
	
	// Texas Instruments
	{ AdbgMachine.msp430,  "Texas Instruments MSP430",      A!("msp430") },
	{ AdbgMachine.tic2000, "Texas Instruments TMS320C2000", A!("tic2000") },
	{ AdbgMachine.tic55xx, "Texas Instruments TMS320C55xx", A!("tic55xx") },
	{ AdbgMachine.tic6000, "Texas Instruments TMS320C6000", A!("tic6000") },
	{ AdbgMachine.asrisc,  "Texas Instruments Application Specific RISC 32-bit", A!("asrisc") },
	{ AdbgMachine.pru,     "Texas Instruments Programmable Realtime Unit", A!("pru") },
	
	// STMicroelectronics
	{ AdbgMachine.st7,    "STMicroelectronics ST7 8-bit",     A!("st7") },
	{ AdbgMachine.stm8,   "STMicroelectronics STM8 8-bit",    A!("stm8") },
	{ AdbgMachine.st9,    "STMicroelectronics ST9+ 8/16-bit", A!("st9") },
	{ AdbgMachine.st19,   "STMicroelectronics ST19 8-bit",    A!("st19") },
	{ AdbgMachine.st100,  "STMicroelectronics ST100",         A!("st100") },
	{ AdbgMachine.st200,  "STMicroelectronics ST200",         A!("st200") },
	{ AdbgMachine.vdsp,   "STMicroelectronics VLIW DSP 64-bit", A!("vdsp") },
	{ AdbgMachine.stxp7x, "STMicroelectronics STxP7x",        A!("stxp7x") },
	
	// Fujistu
	{ AdbgMachine.vpp500, "Fujitsu VPP500", A!("vpp500") },
	{ AdbgMachine.fr20,   "Fujitsu FR20",   A!("fr20") },
	{ AdbgMachine.mma,    "Fujitsu MMA Multimedia Accelerator", A!("mma") },
	{ AdbgMachine.fr30,   "Fujitsu FR30",   A!("fr30") },
	{ AdbgMachine.f2mc16, "Fujitsu F2MC16", A!("f2mc16") },
	
	// National Semiconductor
	{ AdbgMachine.ns32k, "National Semiconductor 32000", A!("ns32k") },
	{ AdbgMachine.cr,    "National Semiconductor CompactRISC", A!("cr") },
	{ AdbgMachine.crx,   "National Semiconductor CompactRISC CRX", A!("crx") },
	{ AdbgMachine.cr16,  "National Semiconductor CompactRISC CR16 16-bit", A!("cr16") },
	
	// Freescale
	{ AdbgMachine.ce,   "Freescale Communication Engine RISC", A!("ce") },
	{ AdbgMachine.rs08, "Freescale RS08", A!("rs08") },
	{ AdbgMachine.etpu, "Freescale Extended Time Processing Unit", A!("etpu") },
	{ AdbgMachine.dsc,  "Freescale 56800EX DSC", A!("dsc") },
	
	// Siemens
	{ AdbgMachine.tricore, "Siemens TriCore embedded", A!("tricore")},
	{ AdbgMachine.pcp,     "Siemens PCP",  A!("pcp")},
	{ AdbgMachine.fx66,    "Siemens FX66", A!("fx66")},
	
	// KM211
	{ AdbgMachine.kmx8,  "KM211 KMX8 8-bit",   A!("kmx8") },
	{ AdbgMachine.kmx16, "KM211 KMX16 16-bit", A!("kmx16") },
	{ AdbgMachine.km32,  "KM211 KM32 32-bit",  A!("km32") },
	{ AdbgMachine.kmx32, "KM211 KMX32 32-bit", A!("kmx32") },
	{ AdbgMachine.kvarc, "KM211 KVARC",        A!("kvarc") },
	
	// MCST
	{ AdbgMachine.elbrus, "MCST Elbrus", A!"elbrus" },
	
	// NEC
	{ AdbgMachine.v800, "NEC V800", A!"v800" },
	{ AdbgMachine.v850, "NEC V850", A!"v850" },
	
	// Loongson
	{ AdbgMachine.loongarch32, "LoongArch32", A!("loongarch32") },
	{ AdbgMachine.loongarch64, "LoongArch64", A!("loongarch64") },
	
	// Analog Devices
	{ AdbgMachine.sharc, "SHARC 32-bit", A!"sharc" },
	
	// Soft processor group
	{ AdbgMachine.moxie, "Moxie", A!"moxie" },
	
	// Educational group
	{ AdbgMachine.mmix,    "Donald Knuth's educational processor 64-bit", A!"mmix" },
	{ AdbgMachine.harvard, "Harvard University machine-independent object", A!"harvard" },
	
	// GPU group
	{ AdbgMachine.amdgpu, "AMD GPU",     A!("amdgpu") },
	{ AdbgMachine.cuda,   "NVIDIA CUDA", A!("cuda") },
	
	// Bytecode group
	{ AdbgMachine.ebc, "EFI Byte Code",           A!("ebc", "efi") },
	{ AdbgMachine.clr, "Common Language Runtime", A!("clr") },
	{ AdbgMachine.pj,  "picoJava",                A!("pj", "picojava") },
	
	// Etc.
	{ AdbgMachine.we32100,     "AT&T WE 32100", A!("we32100") },
	{ AdbgMachine.parisc,      "Hewlett-Packard PA-RISC", A!("parisc") },
	{ AdbgMachine.rh32,        "TRW RH32", A!("rh32") },
	{ AdbgMachine.arisc,       "Argonaut RISC Core", A!("arisc") },
	{ AdbgMachine.ncpu,        "Sony nCPU embedded RISC", A!("ncpu") },
	{ AdbgMachine.ndr1,        "Denso NDR1", A!("ndr1") },
	{ AdbgMachine.me16,        "Toyota ME16", A!("me16") },
	{ AdbgMachine.tinyj,       "Advanced Logic Corp. TinyJ", A!("tinyj") },
	{ AdbgMachine.sonydsp,     "Sony DSP", A!("sonydsp") },
	{ AdbgMachine.svx,         "Silicon Graphics SVx", A!("svx") },
	{ AdbgMachine.axis,        "Axis Communications 32-bit", A!("axis") },
	{ AdbgMachine.firepath,    "Element Firepath 14 DSP 64-bit", A!("firepath") },
	{ AdbgMachine.zsp,         "LSI Logic ZSP DSP 16-bit", A!("zsp") },
	{ AdbgMachine.prism,       "SiTera Prism", A!("prism") },
	{ AdbgMachine.openrisc,    "OpenRISC 32-bit", A!("openrisc") },
	{ AdbgMachine.videocore,   "Alphamosaic VideoCore", A!("videocore") },
	{ AdbgMachine.tmm,         "Thompson Multimedia General Purpose", A!("tmm") },
	{ AdbgMachine.tpc,         "Tenor Network TPC", A!("tpc") },
	{ AdbgMachine.snp1k,       "Trebia SNP 1000", A!("snp1k") },
	{ AdbgMachine.ip2k,        "Ubicom IP2xxx", A!("ip2k") },
	{ AdbgMachine.max_,        "MAX", A!("max") },
	{ AdbgMachine.blackfin,    "Analog Devices Blackfin DSP", A!("blackfin") },
	{ AdbgMachine.sep,         "Sharp", A!("sep") },
	{ AdbgMachine.arca,        "Arca RISC", A!("arca") },
	{ AdbgMachine.unicore,     "PKU-Unity/Pekin Unicore", A!("unicore") },
	{ AdbgMachine.excess,      "eXcess 16/32/64-bit", A!("excess") },
	{ AdbgMachine.dxp,         "Icera Semiconductor Inc. Deep Execution", A!("dxp") },
	{ AdbgMachine.nios2,       "Altera Nios II soft-core", A!("nios2") },
	{ AdbgMachine.dspic30f,     "Microchip Technology DSPIC30F", A!("dspic30f") },
	{ AdbgMachine.tsk3000,     "Altium TSK3000", A!("tsk3000") },
	{ AdbgMachine.score7,      "Sunplus S+core7 RISC", A!("score7") },
	{ AdbgMachine.videocore3,  "Broadcom VideoCore III", A!("videocore3") },
	{ AdbgMachine.videocore5,  "Broadcom VideoCore V", A!("videocore5") },
	{ AdbgMachine.mico32,      "Lattice FPGA", A!("mico32") },
	{ AdbgMachine.s1c33,       "Seiko Epson S1C33", A!("s1c33") },
	{ AdbgMachine.c17,         "Seiko Epson C17", A!("c17") },
	{ AdbgMachine.m8c,         "Cypress M8C", A!("m8c") },
	{ AdbgMachine.trimedia,    "NXP Semiconductors TriMedia", A!("trimedia") },
	{ AdbgMachine.dsp6,        "Qualcomm DSP6", A!("dsp6") },
	{ AdbgMachine.nds32,       "Andes Technology RISC", A!("nds32") },
	{ AdbgMachine.maxq30,      "Dallas Semiconductor MAXQ30", A!("maxq30") },
	{ AdbgMachine.dsp16,       "New Japan Radio DSP 16-bit", A!("dsp16") },
	{ AdbgMachine.dsp24,       "New Japan Radio DSP 24-bit", A!("dsp24") },
	{ AdbgMachine.m2000,       "M2000 Reconfigurable RISC", A!("m2000") },
	{ AdbgMachine.nv2,         "Cray Inc. NV2", A!("nv2") },
	{ AdbgMachine.meta,        "Imagination Technologies META", A!("meta") },
	{ AdbgMachine.ecog16,      "Cyan Technology eCOG16", A!("ecog16") },
	{ AdbgMachine.ecog1x,      "Cyan Technology eCOG1X", A!("ecog1x") },
	{ AdbgMachine.ecog2,       "Cyan Technology eCOG2", A!("ecog2") },
	{ AdbgMachine.c166,        "Infineon C16x/XC16x", A!("c166") },
	{ AdbgMachine.sle9x,       "Infineon Technologies SLE9X 32-bit", A!("sle9x") },
	{ AdbgMachine.tile64,      "Tilera TILE64", A!("tile64") },
	{ AdbgMachine.tilepro,     "Tilera TILEPro", A!("tilepro") },
	{ AdbgMachine.tilegx,      "Tilera TILE-Gx", A!("tilegx") },
	{ AdbgMachine.microblaze,  "Xilinx MicroBlaze RISC soft core 32-bit", A!("microblaze") },
	{ AdbgMachine.cloudshield, "CloudShield", A!("cloudshield") },
	{ AdbgMachine.corea1,      "KIPO-KAIST Core-A 1st generation", A!("corea1") },
	{ AdbgMachine.corea2,      "KIPO-KAIST Core-A 2nd generation", A!("corea2") },
	{ AdbgMachine.arcc2,       "Synopsys ARCompact V2", A!("arcc2") },
	{ AdbgMachine.open8,       "Open8 RISC soft core 8-bit", A!("open8") },
	{ AdbgMachine.ba1,         "Beyond BA1", A!("ba1") },
	{ AdbgMachine.ba2,         "Beyond BA2", A!("ba2") },
	{ AdbgMachine.xcore,       "XMOS xCORE", A!("xcore") },
	{ AdbgMachine.picr8,       "Microchip PIC(r) 8-bit", A!("picr8") },
	{ AdbgMachine.cdp,         "Paneve CDP", A!("cdp") },
	{ AdbgMachine.csm,         "Cognitive Smart Memory", A!("csm") },
	{ AdbgMachine.bluechip,    "Bluechip Systems", A!("bluechip") },
	{ AdbgMachine.nano,        "Nanoradio Optimized RISC", A!("nano") },
	{ AdbgMachine.csr,         "CSR Kalimba", A!("csr") },
	{ AdbgMachine.z80,         "Zilog Z80", A!("z80") },
	{ AdbgMachine.visium,      "VISIUMcore", A!("visium") },
	{ AdbgMachine.ftdi,        "FTDI Chip FT32 RISC 32-bit", A!("ftdi") },
	{ AdbgMachine.veo,         "VEO", A!("veo") },
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
	assert(adbg_machine(AdbgMachine.i8086).id  == AdbgMachine.i8086);
	assert(adbg_machine(AdbgMachine.am33).id   == AdbgMachine.am33);
	for (size_t i = 1; i < machines.length; ++i) {
		immutable(adbg_machine_t)* m = adbg_machine(cast(AdbgMachine)i);
		assert(m);
		assert(m.id == cast(AdbgMachine)i);
	}
}

/// Get machine name.
/// Params: machine = Machine instance.
/// Returns: Machine name, or null if invalid.
const(char)* adbg_machine_fullname(immutable(adbg_machine_t) *machine) {
	if (machine == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	return machine.name;
}

/// Get the list of aliases linked to this machine definition.
/// Params: machine = Machine instance.
/// Returns: String list. The returned list is null-terminated.
const(char)** adbg_machine_aliases(immutable(adbg_machine_t) *machine) {
	if (machine == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	return cast(const(char)**)machine.aliases.ptr;
}

/// Search a machine architecture by one of its alias name.
/// Params: alias_ = Alias string.
/// Returns: Machine pointer or null.
immutable(adbg_machine_t)* adbg_machine_select(const(char) *alias_) {
	if (alias_ == null) {
		adbg_oops(AdbgError.invalidArgument);
		return null;
	}
	
	// For each machine definitions
	for (size_t i; i < machines.length; ++i) {
		immutable(adbg_machine_t)* machine = &machines[i];
		
		assert(machine.aliases[$-1] == null); // needs null terminator for now
		size_t len = machine.aliases.length - 1;
		// For each alias
		for (size_t a; a < len; ++a)
			if (strcmp(alias_, machine.aliases[a]) == 0)
				return machine;
	}
	
	adbg_oops(AdbgError.unfindable);
	return null;
}
extern (D) unittest {
	assert(adbg_machine_select(null) == null);
	assert(adbg_machine_select("I do not exist!") == null);
	assert(adbg_machine_select("8086").id    == AdbgMachine.i8086);
	assert(adbg_machine_select("i386").id    == AdbgMachine.i386);
	assert(adbg_machine_select("amd64").id   == AdbgMachine.amd64);
	assert(adbg_machine_select("mips").id    == AdbgMachine.mips);
	assert(adbg_machine_select("sparc64").id == AdbgMachine.sparc9);
}