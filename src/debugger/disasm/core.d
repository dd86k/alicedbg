module debugger.disasm.core;

import debugger.disasm.arch;
import debugger.disasm.formatter;

extern (C):

/// Disassembler operating mode
enum DisasmMode : ubyte {
	Size,	/// Only calculate operation code sizes
	Data,	/// Opcode sizes with jump locations (e.g. JMP, CALL)
	File,	/// Machine code and instruction mnemonics formatting
	Full	/// (Not implemented) Add symbols and demangling
}

/// Disassembler error
enum DisasmError : ushort {
	None,	/// Nothing to report
	NullAddress,	/// Address given in 
	NotSupported,	/// Selected ISA is not currently supported
	Illegal,	/// Illegal/invalid opcode
}

/// Disassembler ABI
enum DisasmABI : ubyte {
	Default,	/// Platform compiled target default
	Guess,	/// (Not implemented) Attempt to guess ISA
	x86_16,	/// 8086, 80186, 80286
	x86_32,	/// x86, 80386+, i386
	x86_64,	/// AMD64, Intel64, x64 (Windows)
	arm_t32,	/// (Not implemented) ARM: Thumb 32-bit
	arm_a32,	/// (Not implemented) ARM: A32 (formally arm)
	arm_a64,	/// (Not implemented) ARM: A64 (formally aarch64)
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
	enum DISASM_DEFAULT_ISA = DisasmABI.x86_32;	/// Platform default ABI
	enum DISASM_DEFAULT_SYNTAX = DisasmSyntax.Intel;	/// Platform default syntax
} else
version (X86_64) {
	enum DISASM_DEFAULT_ISA = DisasmABI.x86_64;	/// Platform default ABI
	enum DISASM_DEFAULT_SYNTAX = DisasmSyntax.Intel;	/// Platform default syntax
} else
version (ARM) {
	enum DISASM_DEFAULT_ISA = DisasmABI.arm_a32;	/// Platform default ABI
	enum DISASM_DEFAULT_SYNTAX = DisasmSyntax.Att;	/// Platform default syntax
} else
version (AArch64) {
	enum DISASM_DEFAULT_ISA = DisasmABI.arm_a64;	/// Platform default ABI
	enum DISASM_DEFAULT_SYNTAX = DisasmSyntax.Att;	/// Platform default syntax
} else {
	enum DISASM_DEFAULT_ISA = DisasmABI.Default;	/// Platform default ABI
}

//
// Option bits
//

/// Diasm option: 
//enum DISASM_O_	= 0x0001;
/// Diasm option: Go backwards instead of forward. More expensive to calculate!
enum DISASM_O_BACKWARD	= 0x0002;
/// Diasm option: 
//enum DISASM_O_	= 0x0004;
/// Diasm option: 
//enum DISASM_O_	= 0x0008;
/// Disasm option: 
//enum DISASM_O_	= 0x0010;
/// Disasm option: Do not group machine code integers
enum DISASM_O_MC_INT_SEP	= 0x0020;
/// Disasm option: Do not add an extra space
enum DISASM_O_MC_NOSPACE	= 0x0040;

/// Disassembler parameters structure
struct disasm_params_t { align(1):
	union {
		/// Memory address entry point. This value is modified to point
		/// to the next instruction address. Acts as instruction
		/// pointer/program counter.
		void *addr;
		/// Memory address entry point. This value is modified to point
		/// to the next instruction address. Acts as instruction
		/// pointer/program counter.
		size_t addrv;
		// Aliases
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
	/// Saved address position before the operation begins, good for
	/// printing purposes or calculating the delta after disassembling.
	/// This field is filled by disasm_line before disassembling.
	size_t lastaddr;
	/// Error code. See DisasmError enumeration for more details. Set by
	/// disasm_line or the the decoder.
	DisasmError error;
	/// Demangle option. See DisasmDemangle enum.
	DisasmDemangle demangle;
	/// Platform to disasm. See the DisasmABI enum for more details.
	DisasmABI abi;
	/// Assembler style. See DisasmStyle enums for more details.
	DisasmSyntax style;
	/// Operation mode.
	DisasmMode mode;
	/// Settings flags. See DISASM_O_* flags.
	uint options;
	union {
		void *internal;	/// Used internally
		x86_32_internals_t *x86_32;	/// Used internally
		x86_64_internals_t *x86_64;	/// Used internally
	}
	disasm_fmt_t *fmt;	/// Formatter structure pointer, used internally
	char [DISASM_BUF_SIZE]mcbuf;	/// Machine code buffer
	char [DISASM_BUF_SIZE]mnbuf;	/// Mnemonics buffer
	size_t mcbufi;	/// Machine code buffer index
	size_t mnbufi;	/// Mnemonics buffer index
}
pragma(msg, "* disasm_params_t.sizeof: ", disasm_params_t.sizeof);

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
int disasm_line(ref disasm_params_t p, DisasmMode mode) {
	if (p.addr == null) {
		disasm_err(p, DisasmError.NullAddress);
		p.mcbuf[0] = 0;
		return p.error;
	}

	p.mode = mode;
	p.error = DisasmError.None;
	p.lastaddr = p.addrv;

	if (p.mode >= DisasmMode.File) {
		disasm_fmt_t fmt = void;
		p.fmt = &fmt;
		p.fmt.settings = p.fmt.itemno = 0;
		with (p) mcbufi = mnbufi = 0;
	}

	if (p.abi == DisasmABI.Default)
		p.abi = DISASM_DEFAULT_ISA;

	with (DisasmABI)
	switch (p.abi) {
	case x86_16: disasm_x86_16(p); break;
	case x86_32: disasm_x86_32(p); break;
	case x86_64: disasm_x86_64(p); break;
	default:
		disasm_err(p, DisasmError.NotSupported);
		p.mcbuf[0] = 0;
		return p.error;
	}

	if (p.mode >= DisasmMode.File) {
		if (p.style == DisasmSyntax.Default)
			p.style = DISASM_DEFAULT_SYNTAX;
		disasm_render(p);
		with (p) {
			if (mcbuf[mcbufi - 1] == ' ') --mcbufi;
			mcbuf[mcbufi] = mnbuf[mnbufi] = 0;
		}
	}

	return p.error;
}

//TODO: ushort disasm_optstr(const(char)*) -- Interpret string value for disasm option
