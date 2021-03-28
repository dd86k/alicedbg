/**
 * Disassembler core.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: See LICENSE
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
package enum ADBG_DISASM_BUFFER_SIZE = 64;

/// Disassembler options
enum AdbgDisasmOpt {
	/// Set the operating mode.
	mode,
	/// Set new target platform.
	platform,
	/// Set the mnemonic syntax.
	syntax,
	/// Set the machine code format.
	machineFormat,
	///TODO: If set, go backward instead of forward in memory.
	backward,
	///TODO: Add commentary
	commentary,
	/// Memory source is a live debuggee process.
	debuggee,
	/// If true: Insert a hardware tab instead of a space between the
	/// mnemonic and operands.
	mnemonicTab,
//	x86AddrMode = 80,
//	x86DataMode = 81,
}

/// Disassembler operating mode
enum AdbgDisasmMode : ubyte {
	size,	/// Only calculate operation code sizes
	data,	/// Opcode sizes with jump locations (e.g. JMP, CALL)
	file,	/// Machine code and instruction mnemonics formatting
	full	/// (TODO) Analysis
}

/// Disassembler ABI
enum AdbgDisasmPlatform : ubyte {
	native,	/// (Default) Platform compiled target, see DISASM_DEFAULT_PLATFORM
	x86_16,	/// (WIP) 8086, 80186, 80286
	x86,	/// (WIP) x86-32, 80386/i386
	x86_64,	/// (WIP) AMD64, Intel64, x64 (Windows)
	arm_t32,	/// (TODO) ARM: Thumb 32-bit
	arm_a32,	/// (TODO) ARM: A32 (formally arm)
	arm_a64,	/// (TODO) ARM: A64 (formally aarch64)
	rv32,	/// (WIP) RISC-V 32-bit
	rv64,	/// (TODO) RISC-V 64-bit
}

/// Disassembler mnemonic syntaxes
enum AdbgDisasmSyntax : ubyte {
	platform,	/// Platform compiled target default
	intel,	/// Intel syntax, similar to Microsoft/Macro Assembler (MASM)
	nasm,	/// Netwide Assembler syntax (NASM)
	att,	/// AT&T syntax
//	ideal,	/// (TODO) Borland Ideal
//	hyde,	/// (TODO) Randall Hyde High Level Assembly Language
//	riscv,	/// 
}

/// Disassembler machine code formats
enum AdbgDisasmFormat : ubyte {
	/// Machine code platform-dependant. Operands are packed.
	// x86: Unpacked
	// ARM/RISC: Packed
	normal,
	/// Machine code is without spaces. Operands are spaced out.
	machinePackedOperandsUnpacked,
	/// 
	machineUnpackedOperandsPacked,
	/// All machine bytes, including operands, are separated with a space.
	allUnpacked,
	/// All machine bytes, including operands, are not separated with a space.
	allPacked,
}

/// Disassembler options
deprecated
enum AdbgDisasmOption {
	/// Use a space instead of a tab between the mnemonic and operands.
	spaceSep	= BIT!(0),
	///TODO: Go backwards.
	backward	= BIT!(1),
	///TODO: Do not group machine code integers.
	noGroup	= BIT!(2),
	/// Do not insert spaces in-between machine code types (bytes, words, etc.).
	noSpace	= BIT!(3),
}

/// Disassembler warnings
enum AdbgDisasmWarning {
	/// Far jump, call, or return
	farAddr	= BIT!(0),
	/// Loads a segment register
	segment	= BIT!(1),
	/// Privileged instruction
	privileged	= BIT!(2),
	/// I/O instruction
	io	= BIT!(3),
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
	static assert(0, "Set default disassembler variables");
}

/// Represents a disassembled instruction
struct adbg_disasm_opcode_t {
	int warnings;	/// Warning flags
	int size;	/// Instruction size
	const(char) *machcode;	/// Instruction machine code
	const(char) *mnemonic;	/// Instruction mnemonic
	const(char) *comment;	/// Instruction comment
	union { // Target address
		void   *targetaddr;	/// Used internally
		size_t  targetaddrv;	/// ditto
		ubyte  *targetaddri8;	/// ditto
		ushort *targetaddri16;	/// ditto
		uint   *targetaddri32;	/// ditto
		ulong  *targetaddri64;	/// ditto
		float  *targetaddrf32;	/// ditto
		double *targetaddrf64;	/// ditto
	}
}

/// Disassembler parameters structure. This structure is not meant to be
/// accessed directly.
struct adbg_disasm_t { align(1):
	//
	// Generic
	//
	
	union { // Current address
		/// Memory address entry point. This value is modified to point
		/// to the current instruction address for the disassembler.
		/// Acts as instruction pointer/program counter.
		deprecated void   *a;
		deprecated size_t av;	/// Non-pointer format for address calculation
		deprecated ubyte  *ai8; 	/// Used internally
		deprecated ushort *ai16;	/// Used internally
		deprecated uint   *ai32;	/// Used internally
		deprecated ulong  *ai64;	/// Used internally
		deprecated float  *af32;	/// Used internally
		deprecated double *af64;	/// Used internally
		void   *addr;	/// Used internally
		size_t  addrv;	/// ditto
		ubyte  *addru8;	/// ditto
		ushort *addru16;	/// ditto
		uint   *addru32;	/// ditto
		ulong  *addru64;	/// ditto
		float  *addrf32;	/// ditto
		double *addrf64;	/// ditto
	}
	union { // Base address
		/// Base Address;
		///
		/// Currently, this field is not used.
		///
		/// Used in calculating the target address.
		deprecated size_t ba;
		void   *baseaddr;	/// Used internally
		size_t  baseaddrv;	/// ditto
		ubyte  *baseaddri8;	/// ditto
		ushort *baseaddri16;	/// ditto
		uint   *baseaddri32;	/// ditto
		ulong  *baseaddri64;	/// ditto
		float  *baseaddrf32;	/// ditto
		double *baseaddrf64;	/// ditto
	}
	union { // Last address
		/// Last Address.
		///
		/// This field is populated with the entry address, making it useful
		/// for printing purposes or calculating the address size.
		deprecated size_t la;
		void   *lastaddr;	/// Used internally
		size_t  lastaddrv;	/// ditto
		ubyte  *lastaddri8;	/// ditto
		ushort *lastaddri16;	/// ditto
		uint   *lastaddri32;	/// ditto
		ulong  *lastaddri64;	/// ditto
		float  *lastaddrf32;	/// ditto
		double *lastaddrf64;	/// ditto
	}
	/// disasm implementation function
	int function(adbg_disasm_t*) func;
	union {
		x86_internals_t *x86;	/// 
		riscv_internals_t *rv;	/// 
	}
	
	//
	// Options
	//
	
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
	/// Machine code format.
	AdbgDisasmFormat format;
	/// Operation mode.
	///
	/// Disassembler operating mode. See the AdbgDisasmMode enumeration for
	/// more details.
	AdbgDisasmMode mode;
	/// User data length that can be processed. If disassembling a debuggee,
	/// this field is not taken into account.
	size_t left;
	/// If set, source is a debuggee. Uses Win32/ptrace to fetch memory.
	bool debuggee;
	/// If set, instead of a space, a hardware tab is inserted after the
	/// instruction mnemonic.
	bool mnemonicTab;
	/// Reserved
	bool reserved2;
	/// Reserved
	bool reserved3;
	
	//
	// Formatting
	//
	
	/// Format
	adbg_disasmfmt_t fmt;
	/// Machine code buffer index
	size_t mcbufi;
	/// Machine code buffer
	char[ADBG_DISASM_BUFFER_SIZE] mcbuf;
	/// Mnemonics buffer index
	size_t mnbufi;
	/// Mnemonics buffer
	char[ADBG_DISASM_BUFFER_SIZE] mnbuf;
}

adbg_disasm_t *adbg_disasm_open(AdbgDisasmPlatform m) {
	import core.stdc.stdlib : calloc;
	
	adbg_disasm_t *s = cast(adbg_disasm_t *)calloc(1, adbg_disasm_t.sizeof);
	if (s == null) {
		adbg_error(AdbgError.allocationFailed);
		return null;
	}
	
	if (adbg_disasm_reopen(s, m)) {
		free(s);
		return null;
	}
	
	return s;
}

int adbg_disasm_reopen(adbg_disasm_t *p, AdbgDisasmPlatform m) {
	p.syntax = DISASM_DEFAULT_SYNTAX;
	p.platform = m;
	with (AdbgDisasmPlatform)
	switch (m) {
	case native: goto case DISASM_DEFAULT_PLATFORM;
	case x86_16, x86, x86_64:
		p.func = &adbg_disasm_x86;
		return 0;
	case rv32:
		p.func = &adbg_disasm_riscv;
		return 0;
	default:
		return adbg_error(AdbgError.unsupportedPlatform);
	}
}

int adbg_disasm_start_file(adbg_disasm_t *p, void *buffer, size_t size, size_t base) {
	if (p == null)
		return adbg_error(AdbgError.nullArgument);
	
	p.debuggee = false;
	p.addr = buffer;
	p.left = size;
	p.baseaddrv = base;
	return 0;
}

int adbg_disasm_start_debuggee(adbg_disasm_t *p, size_t addr) {
	if (p == null)
		return adbg_error(AdbgError.nullArgument);
	
	p.debuggee = true;
	p.addrv = addr;
	return 0;
}

int adbg_disasm_opt(adbg_disasm_t *p, AdbgDisasmOpt opt, int val) {
	if (p == null)
		return adbg_error(AdbgError.nullArgument);
	
	with (AdbgDisasmOpt)
	switch (opt) {
	case mode:
		if (val >= AdbgDisasmMode.max)
			return adbg_error(AdbgError.invalidOptionValue);
		p.mode = cast(AdbgDisasmMode)val;
		break;
	case platform:
		if (val >= AdbgDisasmPlatform.max)
			return adbg_error(AdbgError.invalidOptionValue);
		p.platform = cast(AdbgDisasmPlatform)val;
		break;
	case syntax:
		if (val >= AdbgDisasmSyntax.max)
			return adbg_error(AdbgError.invalidOptionValue);
		p.syntax = cast(AdbgDisasmSyntax)val;
		break;
	case machineFormat:
		if (val >= AdbgDisasmFormat.max)
			return adbg_error(AdbgError.invalidOptionValue);
		p.format = cast(AdbgDisasmFormat)val;
		break;
	/*case backward:
		p.backwards = val != 0;
		break;*/
	/*case commentary:
		p.commentary = val != 0;
		break;*/
	case debuggee:
		p.debuggee = val != 0;
		break;
	default:
		return adbg_error(AdbgError.invalidOption);
	}
	return 0;
}

/// Populate machine mnemonic and machine code buffers.
///
/// Disassemble one instruction from a buffer pointer given in adbg_disasm_t.
/// Caller must ensure memory pointer points to readable regions and givens
/// bounds are respected. The error field is always set.
///
/// Params:
/// 	p = Disassembler parameters
/// 	mode = Disassembling mode
///
/// Returns: Error code; Non-zero indicating an error
int adbg_disasm(adbg_disasm_t *p, adbg_disasm_opcode_t *op, AdbgDisasmMode mode) {
	if (p == null)
		return adbg_error(AdbgError.invalidArgument);
	if (p.func == null)
		return adbg_error(AdbgError.unsupportedPlatform);
	
	if (mode >= AdbgDisasmMode.file) {
		p.mcbufi = p.mnbufi = 0;
		p.fmt.itemno = 0;
	}
	
	p.mode = mode;
	p.lastaddr = p.addr;
	
	int e = p.func(p);
	
	op.size = cast(int)(p.addrv - p.lastaddrv);
	
	if (mode >= AdbgDisasmMode.file && e == AdbgError.none)
		adbg_disasm_render(p);
	
	return e;
}

private import core.stdc.stdlib : free;
public  alias adbg_disasm_close = free;

/// (Internal) Fetch data from data source.
/// Params:
/// 	p = Disassembler structure pointer
/// 	u = Data pointer
/// Returns: Non-zero on error
int adbg_disasm_fetch(T)(adbg_disasm_t *p, T *u) {
	import adbg.dbg.debugger : adbg_mm_cread;
	int e = void;
	if (p.debuggee) {
		e = adbg_mm_cread(p.addrv, u, T.sizeof);
	} else {
		if (p.left < T.sizeof)
			return adbg_error(AdbgError.outOfData);
		*u = *cast(T*)p.addr;
		e = 0;
		p.left -= T.sizeof;
	}
	p.addrv += T.sizeof;
	return e;
}
