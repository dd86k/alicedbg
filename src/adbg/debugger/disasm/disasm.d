/**
 * Disassembler core.
 *
 * License: BSD 3-Clause
 */
module adbg.debugger.disasm.disasm;

import adbg.debugger.disasm.arch;
import adbg.debugger.disasm.formatter;

extern (C):

/// Disassembler operating mode
enum DisasmMode : ubyte {
	Size,	/// Only calculate operation code sizes
	Data,	/// Opcode sizes with jump locations (e.g. JMP, CALL)
	File,	/// Machine code and instruction mnemonics formatting
	Full	/// (Not implemented) Add symbols and demangling
}

/// Disassembler error
enum DisasmError {
	None,	/// Nothing to report
	NullAddress,	/// Address given is null (0)
	NotSupported,	/// Selected ISA is not currently supported
	Illegal,	/// Illegal/invalid opcode
}

/// Disassembler ABI
enum DisasmISA : ubyte {
	Default,	/// Platform compiled target default
	Guess,	/// (Not implemented) Attempt to guess ISA
	x86_16,	/// 8086, 80186, 80286
	x86,	/// x86-32, 80386/i386
	x86_64,	/// AMD64, Intel64, x64 (Windows)
	arm_t32,	/// (Not implemented) ARM: Thumb 32-bit
	arm_a32,	/// (Not implemented) ARM: A32 (formally arm)
	arm_a64,	/// (Not implemented) ARM: A64 (formally aarch64)
	rv32,	/// RISC-V 32-bit
	rv64,	/// RISC-V 64-bit
}

/// Disassembler x86 styles
enum DisasmSyntax : ubyte {
	Default,	/// Platform compiled target default
	Intel,	/// Intel syntax
	Nasm,	/// (NASM) Netwide Assembler syntax
	Att,	/// AT&T syntax
//	Masm,	/// (Not implemented) (MASM) Microsoft/Macro Assembler
//	Ideal,	/// (Not implemented) Borland Ideal
//	Hyde,	/// (Not implemented) Randall Hyde High Level Assembly Language
}

/// Disassembler symbol demangling
enum DisasmDemangle : ushort {
	None,	/// (Not implemented) Leave symbol as-is
	C,	/// (Not implemented) C mangling
}

/// Character buffer size
///
/// Currently, 64 characters is enough to hold SIB memory references, AVX-512
/// instructions, or 15 bytes of machine code hexadecimal numbers. If that's
/// not enough, update it to 80 characters.
enum DISASM_BUF_SIZE = 64;

version (X86) {
	enum DISASM_DEFAULT_ISA = DisasmISA.x86;	/// Platform default ABI
	enum DISASM_DEFAULT_SYNTAX = DisasmSyntax.Intel;	/// Platform default syntax
} else
version (X86_64) {
	enum DISASM_DEFAULT_ISA = DisasmISA.x86_64;	/// Platform default ABI
	enum DISASM_DEFAULT_SYNTAX = DisasmSyntax.Intel;	/// Platform default syntax
} else
version (ARM) {
	enum DISASM_DEFAULT_ISA = DisasmISA.arm_a32;	/// Platform default ABI
	enum DISASM_DEFAULT_SYNTAX = DisasmSyntax.Att;	/// Platform default syntax
} else
version (AArch64) {
	enum DISASM_DEFAULT_ISA = DisasmISA.arm_a64;	/// Platform default ABI
	enum DISASM_DEFAULT_SYNTAX = DisasmSyntax.Att;	/// Platform default syntax
} else {
	enum DISASM_DEFAULT_ISA = DisasmISA.Default;	/// Platform default ABI
	enum DISASM_DEFAULT_SYNTAX = DisasmSyntax.Nasm;	/// Platform default syntax
}

//
// Option bits
//

///TODO: Diasm option: Use space instead of a tab between the mnemonic and operands
enum DISASM_O_SPACE	= 0x0001;
///TODO: Diasm option: Go backwards instead of forward. More expensive to calculate!
enum DISASM_O_BACKWARD	= 0x0002;
/// Diasm option: 
//enum DISASM_O_	= 0x0004;
/// Diasm option: 
//enum DISASM_O_	= 0x0008;
/// Disasm option: 
//enum DISASM_O_	= 0x0010;
///TODO: Disasm option: Do not group machine code integers
enum DISASM_O_MC_INT_SEP	= 0x0020;
/// Disasm option: Do not add an extra space
enum DISASM_O_MC_NOSPACE	= 0x0040;

/// Disassembler parameters structure
struct disasm_params_t { align(1):
	union {
		/// Memory address entry point. This value is modified to point
		/// to the current instruction address for the disassembler.
		/// Acts as instruction pointer/program counter.
		void   *addr;
		size_t addrv;	/// Non-pointer format for calculations
		ubyte  *addru8; 	/// Used internally
		ushort *addru16;	/// Used internally
		uint   *addru32;	/// Used internally
		ulong  *addru64;	/// Used internally
		byte   *addri8; 	/// Used internally
		short  *addri16;	/// Used internally
		int    *addri32;	/// Used internally
		long   *addri64;	/// Used internally
		float  *addrf32;	/// Used internally
		double *addrf64;	/// Used internally
	}
	/// This field is populated by adbg_dasm_line before calling the decoder.
	/// It serves the client for printing the address and the decoder
	/// the basis for jump/call address calculations.
	size_t lastaddr;
	/// Error code. See DisasmError enumeration for more details. Set by
	/// adbg_dasm_line or the the decoder.
	DisasmError error;
	/// Demangle option. See DisasmDemangle enum.
	DisasmDemangle demangle;
	/// Platform to disasm. See the DisasmABI enum for more details.
	DisasmISA isa;
	/// Assembler style. See DisasmStyle enums for more details.
	DisasmSyntax style;
	/// Operation mode.
	DisasmMode mode;
	/// Settings flags. See DISASM_O_* flags.
	uint options;
	union {
		void *internal;	/// Used internally
		x86_internals_t *x86;	/// Used internally
		x86_64_internals_t *x86_64;	/// Used internally
		rv32_internals_t *rv32;	/// Used internally
	}
	disasm_fmt_t *fmt;	/// Formatter structure pointer, used internally
	char [DISASM_BUF_SIZE]mcbuf;	/// Machine code buffer
	size_t mcbufi;	/// Machine code buffer index
	char [DISASM_BUF_SIZE]mnbuf;	/// Mnemonics buffer
	size_t mnbufi;	/// Mnemonics buffer index
}

/**
 * Disassemble instructions from a memory pointer given in disasm_params_t.
 * Caller must ensure memory pointer points to readable regions and givens
 * bounds are respected. The error field is always set.
 *
 * Disassembling modes go by the following: Size only traverses the instruction
 * stream. (Not implemented) Data fills the newloc field with the calculated
 * value from jumps, branches, and calls. File disassembles the instruction
 * stream and formats the output depending on the syntax/style. (Not
 * implemented) Full also adds labels, and source code (when available).
 *
 * Params:
 * 	p = Disassembler parameters
 * 	mode = Disassembling mode
 *
 * Returns: Error code; Non-zero indicating an error
 */
int adbg_dasm_line(disasm_params_t *p, DisasmMode mode) {
	if (p.addr == null) {
		adbg_dasm_err(p, DisasmError.NullAddress);
		p.mcbuf[0] = 0;
		return p.error;
	}

	int modefile = mode >= DisasmMode.File;

	p.mode = mode;
	p.error = DisasmError.None;
	p.lastaddr = p.addrv;

	if (modefile) {
		disasm_fmt_t fmt = void;
		p.fmt = &fmt;
		p.fmt.itemno = 0;
		p.fmt.settings = 0;
		with (p) mcbufi = mnbufi = 0;
	}

	if (p.isa == DisasmISA.Default)
		p.isa = DISASM_DEFAULT_ISA;

	with (DisasmISA)
	switch (p.isa) {
	case x86_16:	adbg_dasm_x86_16(p); break;
	case x86:	adbg_dasm_x86(p); break;
	case x86_64:	adbg_dasm_x86_64(p); break;
	case rv32:	adbg_dasm_rv32(p); break;
	default:
		adbg_dasm_err(p, DisasmError.NotSupported);
		p.mcbuf[0] = p.mnbuf[0] = 0;
		return p.error;
	}

	if (modefile) {
		if (p.style == DisasmSyntax.Default)
			p.style = DISASM_DEFAULT_SYNTAX;
		if (p.error == DisasmError.None)
			adbg_dasm_render(p);
		adbg_dasm_finalize(p); // leave machine code buffer intact
	}

	return p.error;
}

/// See if platform is big-endian (useful for cswap functions). Default values,
/// such as Default and Guess, return the value for the compiled target, so 0
/// if the target is in little-endian, and 1 if the target is big-endian.
/// Params: isa = DisasmISA value
/// Returns: Zero if little-endian, non-zero if big-endian
int adbg_dasm_msb(DisasmISA isa) {
	with (DisasmISA)
	switch (isa) {
	case x86_16, x86, x86_64, rv32, rv64: return 0;
	default:
		version (LittleEndian)
			return 0;
		else
			return 1;
	}
}

//TODO: ushort disasm_optstr(const(char)*) -- Interpret string value for disasm option
