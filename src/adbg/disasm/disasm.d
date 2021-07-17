/**
 * Disassembler module.
 *
 * This module is responsable for disassembling and formatting machine code.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.disasm.disasm;

//NOTE: The _start functions avoid repetiveness in runtime.
//NOTE: The formatting can be done at the same time to avoid unnessary actions.
//      Like, specifying the mode to data calculates jump offsets, but does not
//      add items in the syntaxer buffers.

import adbg.error;
import adbg.utils.bit : swapfunc16, swapfunc32, swapfunc64, BIT;
import adbg.platform : adbg_address_t;
import adbg.disasm.arch;
import adbg.disasm.syntaxer;

extern (C):

/// Character buffer size
///
/// Currently, 64 characters is enough to hold SIB memory references, AVX-512
/// instructions, or 15 bytes of machine code hexadecimal numbers. Used in
/// formatter module.
///
/// If that's not enough, update to 80 characters.
package enum ADBG_DISASM_BUFFER_SIZE = 64;

/// Don't tell anyone.
// Acts as a "bool" to see if things are setup.
version (X86)
	private enum ADBG_COOKIE = 0xccccc0fe;
else version (X86_64)
	private enum ADBG_COOKIE = 0xccccc0fe;	/// Ditto

/// Disassembler ABI
enum AdbgPlatform : ubyte {
	native,	/// (Default) Platform compiled target, see DEFAULT_PLATFORM
	x86_16,	/// (WIP) 8086, 80186, 80286
	x86_32,	/// (WIP) 80386/i386, not to be confused with x32
	x86_64,	/// (WIP) AMD64, EM64T/Intel64, x64
	arm_t32,	/// (TODO) ARM T32 (thumb)
	arm_a32,	/// (TODO) ARM A32 (arm)
	arm_a64,	/// (TODO) ARM A64 (aarch64)
	riscv32,	/// (WIP) RISC-V 32-bit
	riscv64,	/// (TODO) RISC-V 64-bit
}

/// Disassembler options
enum AdbgDisasmOpt {
	/// Set the operating mode.
	mode,
	/// Set new target platform.
	platform,
	/// Set the mnemonic syntax.
	syntax,
	///TODO: If set, go backward instead of forward in memory.
	backward,
	///TODO: Add commentary
	commentary,
	/// Input mode. See $(SEE AdbgDisasmInput).
	input,
	/// Instead of a space, insert a tab between between the instruction
	/// mnemonic and operands.
	mnemonicTab
}

/// Disassembler operating mode
enum AdbgDisasmMode : ubyte {
	size,	/// Only calculate operation code sizes
	data,	/// Opcode sizes with jump locations (e.g. JMP, CALL)
	file,	/// Machine code and instruction mnemonics formatting
	full	/// (TODO) Analysis
}

/// Assembler syntax
enum AdbgSyntax : ubyte {
	/// Platform compiled default for target.
	platform,
	/// Intel syntax (introduced 1978)
	///
	/// Similar to the Microsoft/Macro Assembler (MASM) syntax.
	/// This is the reference syntax for the x86 instruction set.
	/// For more information, consult the Intel and AMD reference manuals.
	///
	/// Example:
	/// ---
	/// mov ecx, dword ptr ss:[ebp-14]
	/// ---
	intel,
	/// AT&T syntax (introduced 1975)
	///
	/// For more information, consult the IAS/RSX-11 MACRO-11 Reference
	/// Manual and the GNU Assembler documentation.
	///
	/// Example:
	/// ---
	/// mov ss:-14(%ebp), %ecx
	/// ---
	att,
	/// Netwide Assembler syntax (NASM, introduced 1996)
	///
	/// This is a popular alternative syntax for the x86 instruction set.
	/// For more information, consult The Netwide Assembler manual.
	///
	/// Example:
	/// ---
	/// mov ecx, dword ptr [ss:ebp-14]
	/// ---
	nasm,
	///TODO: Borland Turbo Assembler Ideal syntax (introduced 1989)
	///
	/// Also known as the TASM enhanced mode.
	/// For more information, consult the Borland Turbo Assembler Reference Guide.
	///
	/// Example:
	/// ---
	/// mov ecx, [dword ss:ebp-14]
	/// ---
//	ideal,
	/// TODO: Randall Hyde High Level Assembly Language syntax
	///
	/// Created by Randy Hyde, this syntax is based on the PL/360.
	/// For more information, consult the HLA Reference Manual.
	///
	/// Example:
	/// ---
	/// mov( [type dword ss:ebp-14], ecx )
	/// ---
//	hyde,
	///TODO: ARM native syntax.
	/// Example:
	/// ---
	/// ldr r0, [r1]
	/// ---
//	arm,
	///TODO: RISC-V native syntax.
	/// Example:
	/// ---
	/// lw x13, 0(x13)
	/// ---
//	riscv,
}

/// Disassembler warnings
//TODO: Only define warnings that are useful
enum AdbgDisasmWarning {
	/// Far jump, call, or return.
	farAddr	= BIT!(0),
	/// Loads a segment register.
	segment	= BIT!(1),
	/// Privileged instruction.
	privileged	= BIT!(2),
	/// I/O instruction.
	io	= BIT!(3),
}

/// Disassembler input
// NOTE: Uh, and why/how I'll do File/MmFile implementations?
//       There is no point to these two... Unless proven otherwise.
enum AdbgDisasmInput {
	raw,	/// Buffer
	debugger,	/// Debuggee
	file,	///TODO: File
	mmfile,	///TODO: MmFile
}

version (X86) {
	/// Platform default platform
	private enum DEFAULT_PLATFORM = AdbgPlatform.x86;
	/// Platform default syntax
	private enum DEFAULT_SYNTAX = AdbgSyntax.intel;
} else version (X86_64) {
	/// Platform default platform
	private enum DEFAULT_PLATFORM = AdbgPlatform.x86_64;
	/// Platform default syntax
	private enum DEFAULT_SYNTAX = AdbgSyntax.intel;
} else version (Thumb) {
	/// Platform default platform
	private enum DEFAULT_PLATFORM = AdbgPlatform.arm_t32;
	/// Platform default syntax
	private enum DEFAULT_SYNTAX = AdbgSyntax.att;	//TODO: ARM syntax
} else version (ARM) {
	/// Platform default platform
	private enum DEFAULT_PLATFORM = AdbgPlatform.arm_a32;
	/// Platform default syntax
	private enum DEFAULT_SYNTAX = AdbgSyntax.att;	//TODO: ARM syntax
} else version (AArch64) {
	/// Platform default platform
	private enum DEFAULT_PLATFORM = AdbgPlatform.arm_a64;
	/// Platform default syntax
	private enum DEFAULT_SYNTAX = AdbgSyntax.att;	//TODO: ARM syntax
} else version (RISCV32) {
	/// Platform default platform
	private enum DEFAULT_PLATFORM = AdbgPlatform.rv32;
	/// Platform default syntax
	private enum DEFAULT_SYNTAX = AdbgSyntax.att;	//TODO: RISC-V syntax
} else version (RISCV64) {
	/// Platform default platform
	private enum DEFAULT_PLATFORM = AdbgPlatform.rv64;
	/// Platform default syntax
	private enum DEFAULT_SYNTAX = AdbgSyntax.att;	//TODO: RISC-V syntax
} else {
	static assert(0, "Set default disassembler variables");
}

/// 
package
struct adbg_options_t {
	/// Input mode.
	AdbgDisasmInput input;
}

/// Represents a disassembled instruction
struct adbg_disasm_opcode_t {
	const(char) *machine;	/// Instruction machine code
	const(char) *mnemonic;	/// Instruction mnemonic
	const(char) *comment;	/// Instruction comment
	int warnings;	/// Warning flags
	int size;	/// Instruction size
	adbg_address_t target;	/// Target address
}

/// Disassembler parameters structure. This structure is not meant to be
/// accessed directly.
struct adbg_disasm_t { align(1):
	//
	// Generic
	//
	
	adbg_address_t current;	/// Current address, used as a program counter.
	adbg_address_t base;	/// Base address, used for target calculations.
	adbg_address_t last;	/// Last address, saved from input.
	
	/// Implementation function
	int function(adbg_disasm_t*) decode;
	union {
		void *internal;	/// Pointer for internal decoders
		x86_internals_t *x86;	/// Ditto
		riscv_internals_t *rv;	/// Ditto
	}
	/// Opcode information
	adbg_disasm_opcode_t *opcode;
	/// Internal cookie. Yummy!
	uint cookie;
	
	//
	// Options
	//
	
	/// Disassembling Platform.
	///
	/// Instruction set architecture platform to disassemble from. See the
	/// AdbgDisasmPlatform enumeration for more details.
	AdbgPlatform platform;
	/// Operation mode.
	///
	/// Disassembler operating mode. See the AdbgDisasmMode enumeration for
	/// more details.
	AdbgDisasmMode mode;
	/// User data length that can be processed. If disassembling a debuggee,
	/// this field is not taken into account.
	size_t left;
	/// 
	adbg_options_t option;
	/// Responsable for formatting decoded instructions.
	adbg_syntaxer_t syntaxer;
}

// alloc
adbg_disasm_t *adbg_disasm_new(AdbgPlatform m) {
	import core.stdc.stdlib : calloc;
	
	adbg_disasm_t *s = cast(adbg_disasm_t *)calloc(1, adbg_disasm_t.sizeof);
	if (s == null) {
		adbg_oops(AdbgError.allocationFailed);
		return null;
	}
	
	if (adbg_disasm_configure(s, m)) {
		free(s);
		return null;
	}
	
	return s;
}

// configure
int adbg_disasm_configure(adbg_disasm_t *p, AdbgPlatform m) {
	with (AdbgPlatform)
	switch (m) {
	case native: goto case DEFAULT_PLATFORM;
	case x86_16, x86_32, x86_64:
		p.decode = &adbg_disasm_x86;
		break;
	case riscv32:
		p.decode = &adbg_disasm_riscv;
		break;
	default:
		return adbg_oops(AdbgError.unsupportedPlatform);
	}
	p.platform = m;
	p.cookie = ADBG_COOKIE;
	adbg_syntax_init(p.syntaxer, DEFAULT_SYNTAX);
	return 0;
}

// start: raw buffer
int adbg_disasm_start_buffer(adbg_disasm_t *p, AdbgDisasmMode mode, void *buffer, size_t size, size_t base) {
	if (p == null)
		return adbg_oops(AdbgError.nullArgument);
	
	p.option.input = AdbgDisasmInput.raw;
	p.mode = mode;
	p.current.raw = buffer;
	p.left = size;
	p.base.sz = base;
	return 0;
}

// start: debuggee
//TODO: Consider adding base parameter
int adbg_disasm_start_debuggee(adbg_disasm_t *p, AdbgDisasmMode mode, size_t addr) {
	if (p == null)
		return adbg_oops(AdbgError.nullArgument);
	
	p.option.input = AdbgDisasmInput.debugger;
	p.mode = mode;
	p.current.sz = addr;
//	p.base.sz = base;
	return 0;
}

// set option
int adbg_disasm_opt(adbg_disasm_t *p, AdbgDisasmOpt opt, int val) {
	if (p == null)
		return adbg_oops(AdbgError.nullArgument);
	
	with (AdbgDisasmOpt)
	switch (opt) {
	case mode:
		if (val >= AdbgDisasmMode.max)
			return adbg_oops(AdbgError.invalidOptionValue);
		p.mode = cast(AdbgDisasmMode)val;
		break;
	case platform:
		if (val >= AdbgPlatform.max)
			return adbg_oops(AdbgError.invalidOptionValue);
		p.platform = cast(AdbgPlatform)val;
		break;
	case input:
		if (val >= AdbgDisasmInput.max)
			return adbg_oops(AdbgError.invalidOptionValue);
		p.option.input = cast(AdbgDisasmInput)val;
		break;
	case syntax:
		if (val >= AdbgSyntax.max)
			return adbg_oops(AdbgError.invalidOptionValue);
		p.syntaxer.syntax = cast(AdbgSyntax)val;
		break;
	case mnemonicTab:
		p.syntaxer.userOpts.mnemonicTab = val != 0;
		break;
	default:
		return adbg_oops(AdbgError.invalidOption);
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
/// 	op = Opcode structure
///
/// Returns: Error code; Non-zero indicating an error
int adbg_disasm(adbg_disasm_t *p, adbg_disasm_opcode_t *op) {
	if (p == null || op == null)
		return adbg_oops(AdbgError.nullArgument);
	if (p.cookie != ADBG_COOKIE)
		return adbg_oops(AdbgError.uninitiated);
	
	// Syntax prep
	if (p.mode >= AdbgDisasmMode.file) {
		adbg_syntax_reset(p.syntaxer);
	}
	
	// Decode prep
	p.last = p.current;
	p.opcode = op;
	
	// Decode
	int e = p.decode(p);
	
	if (e == 0) {
		// opcode size
		op.size = cast(int)(p.current.sz - p.last.sz);
		
		// formatting
		if (p.mode >= AdbgDisasmMode.file) {
			adbg_syntax_render(p.syntaxer);
			op.machine = p.syntaxer.machineBuffer.cstring;
			op.mnemonic = p.syntaxer.mnemonicBuffer.cstring;
		}
	}
	
	return e;
}

private import core.stdc.stdlib : free;
/// Frees a previously allocated disassembly structure.
/// Params: ptr = adbg_disasm_t structure
public  alias adbg_disasm_delete = free;

/// (Internal) Fetch data from data source.
/// Params:
/// 	p = Disassembler structure pointer
/// 	u = Data pointer
/// Returns: Non-zero on error
//TODO: Consider T... (type-safe template) variadic loop
package
int adbg_disasm_fetch(T)(adbg_disasm_t *p, T *u) {
	int e = void;
	with (AdbgDisasmInput)
	switch (p.option.input) {
	case debugger:
		import adbg.dbg.debugger : adbg_mm_cread;
		e = adbg_mm_cread(p.current.sz, u, T.sizeof);
		break;
	case raw:
		if (p.left < T.sizeof)
			return adbg_oops(AdbgError.outOfData);
		*u = *cast(T*)p.current;
		p.left -= T.sizeof;
		e = 0;
		break;
	default: assert(0);
	}
	p.current.sz += T.sizeof;
	adbg_syntax_add_machine(p.syntaxer, *u);
	return e;
}

// calculate near offset
package
void adbg_disasm_calc_offset(T)(adbg_disasm_t *p, T u) {
	//TODO: adbg_disasm_offset
}
