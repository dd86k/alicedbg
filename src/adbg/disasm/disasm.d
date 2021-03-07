/**
 * Disassembler core.
 *
 * License: BSD-3-Clause
 */
module adbg.disasm.disasm;

import adbg.error;
import adbg.disasm.arch;
import adbg.disasm.formatter;
import adbg.utils.bit : fswap16, fswap32, fswap64, BIT;

extern (C):

/// Character buffer size
///
/// Currently, 64 characters is enough to hold SIB memory references, AVX-512
/// instructions, or 15 bytes of machine code hexadecimal numbers. Used in
/// formatter module.
///
/// If that's not enough, update to 80 characters.
enum ADBG_DISASM_BUFFER_SIZE = 64;

/// Disassembler operating mode
enum AdbgDisasmMode : ubyte {
	size,	/// Only calculate operation code sizes
	data,	/// Opcode sizes with jump locations (e.g. JMP, CALL)
	file,	/// Machine code and instruction mnemonics formatting
	full	/// (Not implemented) Add comments (e.g., ; REX PUSH R8)
}

/// Disassembler ABI
enum AdbgDisasmPlatform : ubyte {
	native,	/// (Default) Platform compiled target, see DISASM_DEFAULT_PLATFORM
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
enum AdbgDisasmSyntax : ubyte {
	platform,	/// Platform compiled target default
	intel,	/// Intel syntax, close to Microsoft/Macro Assembler (MASM)
	nasm,	/// (NASM) Netwide Assembler syntax
	att,	/// AT&T syntax
//	ideal,	/// (Not implemented) Borland Ideal
//	hyde,	/// (Not implemented) Randall Hyde High Level Assembly Language
}

/// Disassembler option flag
enum AdbgDisasmOption : ushort {
	/// Use a space instead of a tab between the mnemonic and operands
	spaceSep	= BIT!(0),
	///TODO: Go backwards
	backward	= BIT!(1),
	///TODO: Do not group machine code integers
	noGroup	= BIT!(2),
	/// Do not insert spaces in-between machine code types (bytes, words, etc.)
	noSpace	= BIT!(3),
}

version (X86) {
	/// Platform default platform
	enum DISASM_DEFAULT_PLATFORM = AdbgDisasmPlatform.x86;
	/// Platform default syntax
	enum DISASM_DEFAULT_SYNTAX = AdbgDisasmSyntax.intel;
} else
version (X86_64) {
	/// Platform default platform
	enum DISASM_DEFAULT_PLATFORM = AdbgDisasmPlatform.x86_64;
	/// Platform default syntax
	enum DISASM_DEFAULT_SYNTAX = AdbgDisasmSyntax.intel;
} else
version (Thumb) {
	/// Platform default platform
	enum DISASM_DEFAULT_PLATFORM = AdbgDisasmPlatform.arm_t32;
	/// Platform default syntax
	enum DISASM_DEFAULT_SYNTAX = AdbgDisasmSyntax.att;
} else
version (ARM) {
	/// Platform default platform
	enum DISASM_DEFAULT_PLATFORM = AdbgDisasmPlatform.arm_a32;
	/// Platform default syntax
	enum DISASM_DEFAULT_SYNTAX = AdbgDisasmSyntax.att;
} else
version (AArch64) {
	/// Platform default platform
	enum DISASM_DEFAULT_PLATFORM = AdbgDisasmPlatform.arm_a64;
	/// Platform default syntax
	enum DISASM_DEFAULT_SYNTAX = AdbgDisasmSyntax.att;
} else {
	static assert(0, "DISASM_DEFAULT_PLATFORM/DISASM_DEFAULT_SYNTAX unset");
}

/// Disassembler parameters structure
struct adbg_disasm_t { align(1):
	union {
		/// Memory address entry point. This value is modified to point
		/// to the current instruction address for the disassembler.
		/// Acts as instruction pointer/program counter.
		void   *a;
		size_t av;	/// Non-pointer format for address calculation
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
	/// Disassembler operating mode. See the AdbgDisasmMode enumeration for
	/// more details.
	AdbgDisasmMode mode; // placed first for cache-related performance reasons
	/// Error code
	int error;
	/// Disassembling Platform.
	///
	/// Instruction set architecture platform to disassemble from. See the
	/// AdbgDisasmPlatform enumeration for more details.
	AdbgDisasmPlatform platform;
	/// Assembler syntax.
	///
	/// Assembler style when formatting instructions. See the AdbgDisasmSyntax
	/// enumeration for more details.
	AdbgDisasmSyntax syntax;
	/// Settings flags.
	///
	/// Bitwise flag. See DISASM_O_* flags.
	uint options;
	size_t mcbufi;	/// Machine code buffer index
	char [ADBG_DISASM_BUFFER_SIZE]mcbuf;	/// Machine code buffer
	size_t mnbufi;	/// Mnemonics buffer index
	char [ADBG_DISASM_BUFFER_SIZE]mnbuf;	/// Mnemonics buffer
	//
	// Internal fields
	//
	union {
		void *internal;	/// Used internally
		x86_internals_t *x86;	/// Used internally
		riscv_internals_t *rv;	/// Used internally
	}
	adg_disasmfmt_t *fmt;	/// Formatter structure pointer, used internally
	fswap16 swi16;	/// Used internally
	fswap32 swi32;	/// Used internally
	fswap64 swi64;	/// Used internally
}

//TODO: adbg_disasm_t* adbg_disasm_create();
//      + turns fmt struct into a normal one
//      - allocates buffers
//TODO: void adbg_disasm_destroy(adbg_disasm_t*);
//TODO: int adbg_disasm_config(adbg_disasm_t*, int, void*);
//      - formatter: sets function pointers (e.g., style, endian swappers)
//      - platform: function pointer to disasm function

/**
 * Populate machine mnemonic and machine code buffers.
 *
 * Disassemble one instruction from a buffer pointer given in adbg_disasm_t.
 * Caller must ensure memory pointer points to readable regions and givens
 * bounds are respected. The error field is always set.
 *
 * Params:
 * 	p = Disassembler parameters
 * 	mode = Disassembling mode
 *
 * Returns: Error code; Non-zero indicating an error
 */
//TODO: Address should be given here
int adbg_disasm(adbg_disasm_t *p, AdbgDisasmMode mode) {
	if (p == null) {
		p.mcbuf[0] = 0;
		return p.error = adbg_error(AdbgError.invalidArgument);
	}
	if (p.a == null) {
		p.mcbuf[0] = 0;
		return p.error = adbg_error(AdbgError.nullAddress);
	}

	bool modefile = mode >= AdbgDisasmMode.file;

	p.mode = mode;
	p.error = 0;
	p.la = p.av;

	if (modefile) {
		adg_disasmfmt_t fmt = void;
		p.fmt = &fmt;
		p.fmt.itemno = 0;
		with (p) mcbufi = mnbufi = 0;
	}

	if (p.platform == AdbgDisasmPlatform.native)
		p.platform = DISASM_DEFAULT_PLATFORM;

	with (AdbgDisasmPlatform)
	switch (p.platform) {
	case x86_16, x86, x86_64:
		adbg_disasm_x86(p);
		break;
	case rv32:
		adbg_disasm_riscv(p);
		break;
	default:
		p.mcbuf[0] = 0;
		return p.error = adbg_error(AdbgError.unsupportedPlatform);
	}

	if (modefile) {
		if (p.syntax == AdbgDisasmSyntax.platform)
			p.syntax = DISASM_DEFAULT_SYNTAX;
		if (p.error == AdbgError.none)
			adbg_disasm_render(p);
	}

	return p.error;
}

//TODO: AdbgDisasmPlatform adbg_disasm_guess(void *p, int size)
//      Returns Default if really nothing found or errors
//      Sets .isa
//      Score system (On min 50 instructions or before size is reached)

/// See if platform is big-endian (useful for swap functions) from an ISA enum
/// value. The default returns the compilation platform endianness value.
/// Params: isa = AdbgDisasmPlatform value
/// Returns: Zero if little-endian, non-zero if big-endian
int adbg_disasm_msb(AdbgDisasmPlatform isa) {
	with (AdbgDisasmPlatform)
	switch (isa) {
	case x86_16, x86, x86_64, rv32, rv64: return 0;
	default:
		version (BigEndian) return 1;
		else return 0;
	}
}

// Status: Waiting on _setup function
//TODO: byte  adbg_disasm_fi8(adbg_disasm_t*)
//TODO: short adbg_disasm_fi16(adbg_disasm_t*)
//TODO: int   adbg_disasm_fi32(adbg_disasm_t*)
//TODO: long  adbg_disasm_fi64(adbg_disasm_t*)
//      Add automatically to machine code buffer
//      Automatically increment pointer
//      Use structure fswap functions
//      + Removes the need to add _x8 in _modrm_rm functions
