/**
 * Disassembler core.
 *
 * License: BSD 3-clause
 */
module adbg.disasm.disasm;

import adbg.disasm.arch;
import adbg.disasm.formatter;
import adbg.utils.bit : fswap16, fswap32, fswap64;

extern (C):

/// Character buffer size
///
/// Currently, 64 characters is enough to hold SIB memory references, AVX-512
/// instructions, or 15 bytes of machine code hexadecimal numbers.
/// If that's not enough, update to 80 characters.
enum DISASM_CBUF_SIZE = 64;

/// Disassembler operating mode
enum DisasmMode : ubyte {
	Size,	/// Only calculate operation code sizes
	Data,	/// Opcode sizes with jump locations (e.g. JMP, CALL)
	File,	/// Machine code and instruction mnemonics formatting
	Full	/// (Not implemented) Add comments
}

/// Disassembler error
enum DisasmError : ubyte {
	None,	/// Nothing to report
	NullAddress,	/// Address given is null (0)
	NotSupported,	/// Selected ISA is not currently supported
	Illegal,	/// Illegal/invalid opcode
}

/// Disassembler ABI
enum DisasmISA : ubyte {
	platform,	/// (Default) Platform compiled target, see DISASM_DEFAULT_ISA
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
	static assert(0, "Missing default platform disassembler settings");
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
	/// Operation mode.
	///
	/// Disassembler operating mode. See the DisasmMode enumeration for
	/// more details.
	DisasmMode mode; // placed first for cache-related performance reasons
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
	/// Settings flags.
	///
	/// Bitwise flag. See DISASM_O_* flags.
	uint options;
	size_t mcbufi;	/// Machine code buffer index
	char [DISASM_CBUF_SIZE]mcbuf;	/// Machine code buffer
	size_t mnbufi;	/// Mnemonics buffer index
	char [DISASM_CBUF_SIZE]mnbuf;	/// Mnemonics buffer
	//
	// Internal fields
	//
	union {
		void *internal;	/// Used internally
		x86_internals_t *x86;	/// Used internally
		riscv_internals_t *rv;	/// Used internally
	}
	disasm_fmt_t *fmt;	/// Formatter structure pointer, used internally
	fswap16 si16;	/// Used internally
	fswap32 si32;	/// Used internally
	fswap64 si64;	/// Used internally
}

//TODO: int adbg_dasm_setup(disasm_params_t *p, int options, DisasmISA isa, DisasmSyntax syntax)
//      Initiate function pointers (isa and fswap)
//      Set value for .syntax field
//      + Setup options and functions once
//      + Formatter structure pointer can stay (in _line for decoder lifetime)

/**
 * Populate machine mnemonic and machine code buffers.
 *
 * Disassemble one instruction from a buffer pointer given in disasm_params_t.
 * Caller must ensure memory pointer points to readable regions and givens
 * bounds are respected. The error field is always set.
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
	case x86_16, x86, x86_64:
		adbg_dasm_x86(p);
		break;
	case rv32:
		adbg_dasm_riscv(p);
		break;
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

//TODO: DisasmISA adbg_dasm_guess(void *p, int size)
//      Returns Default if really nothing found or errors
//      Sets .isa
//      Score system (On min 50 instructions or before size is reached)

/// See if platform is big-endian (useful for fswap functions). The platform
/// value returns the compilation target's endianness.
/// Params: isa = DisasmISA value
/// Returns: Zero if little-endian, non-zero if big-endian
int adbg_dasm_endian(DisasmISA isa) {
	with (DisasmISA)
	switch (isa) {
	case x86_16, x86, x86_64, rv32, rv64: return 0;
	default:
		version (BigEndian) return 1;
		else return 0;
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

// Status: Waiting on _setup function
//TODO: byte  adbg_dasm_fi8(disasm_params_t*)
//TODO: short adbg_dasm_fi16(disasm_params_t*)
//TODO: int   adbg_dasm_fi32(disasm_params_t*)
//TODO: long  adbg_dasm_fi64(disasm_params_t*)
//      Add automatically to machine code buffer
//      Automatically increment pointer
//      Use structure fswap functions
//      + Removes the need to add _x8 in _modrm_rm functions
