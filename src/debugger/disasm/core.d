module debugger.disasm.core;

import debugger.arch;
import utils.str;
private import debugger.disasm.arch.x86 : x86_internals_t;
private import debugger.disasm.formatter;

extern (C):

/// Disassembler operating mode
enum DisasmMode {
	Size,	/// Only calculate operation code sizes
	Data,	/// Opcode sizes with jump locations (e.g. JMP, CALL)
	File,	/// Machine code and instruction mnemonics formatting
	Full	/// (Not implemented) Add symbols and demangling
}

/// Disassembler error
enum DisasmError {
	None,	/// Nothing to report
	NotSupported,	/// Selected ISA is not currently supported
	Illegal,	/// Illegal/invalid opcode
}

/// Disassembler ABI
enum DisasmABI : ubyte {
	Default,	/// Platform compiled target
	Guess,	/// (Not implemented) Attempt to guess ISA
	x86,	/// x86
	x86_64,	/// AMD64
	arm_t32,	/// (Not implemented) ARM: Thumb 32-bit
	arm_a32,	/// (Not implemented) ARM: A32 (formally arm)
	arm_a64,	/// (Not implemented) ARM: A64 (formally aarch64)
}

/// Disassembler x86 styles
enum DisasmSyntax : ubyte {
	Intel,	/// Intel syntax
	Nasm,	/// (NASM) Netwide Assembler syntax
	Att,	/// AT&T syntax
//	Masm,	/// (Not implemented) (MASM) Microsoft Assembler
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

version (X86)
	enum DISASM_DEFAULT_ISA = DisasmABI.x86;	/// Platform default ABI
else
version (X86_64)
	enum DISASM_DEFAULT_ISA = DisasmABI.x86_64;	/// Platform default ABI
else
version (ARM)
	enum DISASM_DEFAULT_ISA = DisasmABI.arm_a32;	/// Platform default ABI
else
version (AArch64)
	enum DISASM_DEFAULT_ISA = DisasmABI.arm_a64;	/// Platform default ABI
else
	enum DISASM_DEFAULT_ISA = DisasmABI.Default;	/// Platform default ABI

//
// Include bits
//

deprecated enum DISASM_I_MACHINECODE	= 0b0000_0001;	/// Include machine code
deprecated enum DISASM_I_MNEMONICS	= 0b0000_0010;	/// Include instruction mnemonics
deprecated enum DISASM_I_SYMBOLS	= 0b0000_0100;	/// (Not implemented) Include symbols
deprecated enum DISASM_I_SOURCE	= 0b0000_1000;	/// (Not implemented) Include source code
deprecated enum DISASM_I_COMMENTS	= 0b0001_0000;	/// (Not implemented) Include inlined comments
deprecated enum DISASM_I_EVERYTHING	= 0xFF;	/// Include everything

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
/// Disasm option: Do not group machine code bytes
enum DISASM_O_NOGROUP_MACHINECODE	= 0x0020;

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
		double *addrd32;	/// Used internally
	}
	/// Saved address position before the operation begins, good for
	/// printing purposes or calculating the delta after disassembling.
	size_t lastaddr;
	/// Error code. See DisasmError enumeration for more details.
	DisasmError error;
	/// Demangle option. See DisasmDemangle enum.
	DisasmDemangle demangle;
	/// Platform to disasm. See the DisasmABI enum for more details.
	DisasmABI abi;
	/// Assembler style. See DisasmStyle enums for more details.
	DisasmSyntax style;
	/// Operation mode. See DISASM_I_* flags. If unset, calculate
	/// and modify address pointer only.
	DisasmMode mode;
	/// Settings flags. See DISASM_O_* flags.
	uint options;
	union {
		void *internal;	/// Used internally
		x86_internals_t *x86;	/// Used internally
	}
	disasm_fmt_t fmt;	/// Used by debugger.disasm.formatter
	char [DISASM_BUF_SIZE]mcbuf;	/// Machine code buffer
	char [DISASM_BUF_SIZE]mnbuf;	/// Mnemonics buffer
	size_t mcbufi;	/// Machine code buffer index
	size_t mnbufi;	/// Mnemonics buffer index
}
pragma(msg, "* disasm_params_t.sizeof: ", disasm_params_t.sizeof);

/**
 * Disassemble from a memory pointer given in params. Caller must ensure
 * memory pointer points to readable regions and bounds are respected.
 * Params:
 * 	p = Disassembler parameters
 * Returns: Error code if non-zero
 */
int disasm_line(ref disasm_params_t p, DisasmMode mode) {
	p.mode = mode;
	p.error = DisasmError.None;
	p.lastaddr = p.addrv;
	p.fmt.settings = p.fmt.itemno = 0;

	if (p.mode >= DisasmMode.File)
		with (p) mcbufi = mnbufi = 0;

	if (p.abi == DisasmABI.Default)
		p.abi = DISASM_DEFAULT_ISA;

	with (DisasmABI)
	switch (p.abi) {
	case x86: disasm_x86(p); break;
	case x86_64: disasm_x86_64(p); break;
	default: return DisasmError.NotSupported;
	}

	if (p.mode >= DisasmMode.File) {
		disasm_render(p);
		with (p) mcbuf[mcbufi] = mnbuf[mnbufi] = 0;
	}

	return p.error;
}

//TODO: ushort disasm_optstr(const(char)*) -- Interpret string value for disasm option

//
// Disasm internals/utilities
//
// NOTE: The include checking is not done in these functions for performance
//       reasons (pushing 3+ values into stack just a bit to be checked is
//       silly).
//

deprecated:
package:
private import core.stdc.stdarg;

immutable const(char) *UNKNOWN_OP = "??";

void mnill(ref disasm_params_t p) {
	if (p.mode & DISASM_I_MACHINECODE)
		mnadd(p, UNKNOWN_OP);
	p.error = DisasmError.Illegal;
}

void mcaddx8(ref disasm_params_t p, ubyte v) {
	mcaddf(p, "%02X ", v);
}
void mcaddx16(ref disasm_params_t p, ushort v) {
	mcaddf(p, "%04X ", v);
}
void mcaddx32(ref disasm_params_t p, uint v) {
	mcaddf(p, "%08X ", v);
}

void mcadd(ref disasm_params_t p, const(char) *str) {
	with (p)
	mcbufi = stradd(cast(char*)mcbuf, DISASM_BUF_SIZE, mcbufi, str);
}

void mcaddf(ref disasm_params_t p, const(char) *f, ...) {
	va_list va;
	va_start(va, f);
	with (p)
	mcbufi = straddva(cast(char*)mcbuf, DISASM_BUF_SIZE, mcbufi, f, va);
}

void mnadd(ref disasm_params_t p, const(char) *str) {
	with (p)
	mnbufi = stradd(cast(char*)mnbuf, DISASM_BUF_SIZE, mnbufi, str);
}

void mnaddf(ref disasm_params_t p, const(char) *f, ...) {
	va_list va;
	va_start(va, f);
	with (p)
	mnbufi = straddva(cast(char*)mnbuf, DISASM_BUF_SIZE, mnbufi, f, va);
}