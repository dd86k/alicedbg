/**
 * Disassembler core.
 *
 * License: BSD 3-Clause
 */
module adbg.debugger.disasm.disasm;

import adbg.debugger.disasm.arch;
import adbg.debugger.disasm.formatter;

extern (C):

/// Character buffer size
///
/// Currently, 64 characters is enough to hold SIB memory references, AVX-512
/// instructions, or 15 bytes of machine code hexadecimal numbers.
/// If that's not enough, update to 80 characters.
enum DISASM_BUF_SIZE = 64;

/// Disassembler operating mode
enum DisasmMode : ubyte {
	Size,	/// Only calculate operation code sizes
	Data,	/// Opcode sizes with jump locations (e.g. JMP, CALL)
	File,	/// Machine code and instruction mnemonics formatting
	Full	/// (Not implemented) Add comments
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
	platform,	/// (Default) Platform compiled target, see DISASM_DEFAULT_ISA
	guess,	/// (Not implemented) Attempt to guess ISA
	x86_16,	/// (WIP) 8086, 80186, 80286
	x86,	/// (WIP) x86-32, 80386/i386
	x86_64,	/// (WIP) AMD64, Intel64, x64 (Windows)
	arm_t32,	/// (Not implemented) ARM: Thumb 32-bit
	arm_a32,	/// (Not implemented) ARM: A32 (formally arm)
	arm_a64,	/// (Not implemented) ARM: A64 (formally aarch64)
	rv32,	/// (WIP) RISC-V 32-bit
	rv64,	/// (Not implemented) RISC-V 64-bit
}

/// Disassembler syntaxes
//TODO: Native syntax
//      A custom ISA-dependant format
enum DisasmSyntax : ubyte {
	Default,	/// Platform compiled target default
	Intel,	/// Intel syntax, closest to the Microsoft/Macro Assembler (MASM)
	Nasm,	/// (NASM) Netwide Assembler syntax
	Att,	/// AT&T syntax
//	Ideal,	/// (Not implemented) Borland Ideal
//	Hyde,	/// (Not implemented) Randall Hyde High Level Assembly Language
}

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
	static assert(0, "Platform has no default disassembler settings");
}

//
// Option bits
//

/// Disassembler: Use space instead of a tab between the mnemonic and operands
enum DISASM_O_SPACE	= 0x0001;
///TODO: Disassembler: Go backwards instead of forward. More expensive to calculate!
enum DISASM_O_BACKWARD	= 0x0002;
///TODO: Disassembler: When calculating target addresses, use the internal counter
//enum DISASM_O_BASEZERO	= 0x0004;
/// Disassembler: 
//enum DISASM_O_	= 0x0008;
/// Disassembler: 
//enum DISASM_O_	= 0x0010;
///TODO: Disassembler: Do not group machine code integers
enum DISASM_O_MC_INT_SEP	= 0x0020;
/// Disassembler: Do not add an extra space
enum DISASM_O_MC_NOSPACE	= 0x0040;

/// Disassembler parameters structure
struct disasm_params_t { align(1):
	union {
		/// Memory address entry point. This value is modified to point
		/// to the current instruction address for the disassembler.
		/// Acts as instruction pointer/program counter.
		void   *a;
		size_t av;	/// Non-pointer format for calculations
		ubyte  *ai8; 	/// Used internally
		ushort *ai16;	/// Used internally
		uint   *ai32;	/// Used internally
		ulong  *ai64;	/// Used internally
		float  *af32;	/// Used internally
		double *af64;	/// Used internally
	}
	/// Last Address.
	///
	/// This field is populated with the entry address, making it useful
	/// for printing purposes or calculating the address size.
	size_t la;
	/// Target Address.
	///
	/// This field is populated when the disassembler encounters an
	/// instruction capable of changing the control flow (jump and call
	/// instructions) and the disassembly mode is higher than File.
	size_t ta;
	/// Base Address;
	///
	/// Currently, this field is not used.
	///
	/// Used in calculating the target address.
	size_t ba;
	/// Error code.
	///
	/// If this field is non-zero, it indicates a decoding error. See the
	/// DisasmError enumeration for more details.
	DisasmError error;
	/// Disassembling Platform.
	///
	/// Instruction set architecture to disassemble. See the DisasmISA
	/// enumeration for more details.
	DisasmISA isa;
	/// Assembler syntax.
	///
	/// Assembler style when formatting instructions. See the DisasmSyntax
	/// enumeration for more details.
	DisasmSyntax syntax;
	/// Operation mode.
	///
	/// Disassembler operating mode. See the DisasmMode enumeration for
	/// more details.
	DisasmMode mode;
	/// Settings flags.
	///
	/// Bitwise flag. See DISASM_O_* flags.
	uint options;
	size_t mcbufi;	/// Machine code buffer index
	char [DISASM_BUF_SIZE]mcbuf;	/// Machine code buffer
	size_t mnbufi;	/// Mnemonics buffer index
	char [DISASM_BUF_SIZE]mnbuf;	/// Mnemonics buffer
	//
	// Internal fields
	//
	union {
		void *internal;	/// Used internally
		x86_internals_t *x86;	/// Used internally
		x86_64_internals_t *x86_64;	/// Used internally
		rv32_internals_t *rv32;	/// Used internally
	}
	disasm_fmt_t *fmt;	/// Formatter structure pointer, used internally
}

//TODO: adbg_dasm_setup
//      Should greatly help as a library function and speed up a few things.
//      Namely, with function pointers, and memory allocations (option?)

/**
 * Disassemble one instruction from a buffer pointer given in disasm_params_t.
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
	if (p.a == null) {
		adbg_dasm_err(p, DisasmError.NullAddress);
		p.mcbuf[0] = 0;
		return p.error;
	}

	bool modefile = mode >= DisasmMode.File;

	p.mode = mode;
	p.error = DisasmError.None;
	p.la = p.av;

	if (modefile) {
		disasm_fmt_t fmt = void;
		p.fmt = &fmt;
		p.fmt.itemno = 0;
		with (p) mcbufi = mnbufi = 0;
	}

	if (p.isa == DisasmISA.platform)
		p.isa = DISASM_DEFAULT_ISA;

	with (DisasmISA)
	switch (p.isa) {
	case x86_16:	adbg_dasm_x86_16(p); break;
	case x86:	adbg_dasm_x86(p); break;
	case x86_64:	adbg_dasm_x86_64(p); break;
	case rv32:	adbg_dasm_rv32(p); break;
	default:
		adbg_dasm_err(p, DisasmError.NotSupported);
		p.mcbuf[0] = 0;
		return p.error;
	}

	if (modefile) {
		if (p.syntax == DisasmSyntax.Default)
			p.syntax = DISASM_DEFAULT_SYNTAX;
		if (p.error == DisasmError.None)
			adbg_dasm_render(p);
	}

	return p.error;
}

/// See if platform is big-endian (useful for cswap functions). Default values,
/// such as Default and Guess, return the value for the compiled target, so 0
/// if the target is in little-endian, and 1 if the target is big-endian.
/// Params: isa = DisasmISA value
/// Returns: Zero if little-endian, non-zero if big-endian
int adbg_dasm_endian(DisasmISA isa) {
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

/// Get a short message for a DisasmError.
/// Params: e = DisasmError
/// Returns: String
const(char) *adbg_dasm_errmsg(DisasmError e) {
	with (DisasmError)
	final switch (e) {
	case None:	return "None";
	case NullAddress:	return "Received null address";
	case NotSupported:	return "Architecture not supported";
	case Illegal:	return "Illegal instruction";
	}
}
