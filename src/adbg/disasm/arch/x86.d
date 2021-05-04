/**
 * 8086/x86/amd64 decoder.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.disasm.arch.x86;

//TODO: Operand handling fill target jump location
//TODO: Consider default segment per instruction

import adbg.error;
import adbg.disasm.disasm;
import adbg.disasm.formatter;

extern (C):
	
private import adbg.disasm.syntaxer;

private
struct prefixes_t { align(1):
	union {
		ulong all;
		struct {
			x86Segment segment;	/// segment override
			x86Prefix select;	/// SSE/VEX instruction selector
			bool lock;	/// LOCK prefix
			bool rep;	/// REP/REPE prefix
			bool repne;	/// REPNE prefix
		}
	}
}
private
struct vex_t { align(1):
	union {
		ulong all;
		struct {
			ubyte LL;	/// VEX.L vector length
					// 0=scalar/i128, 1=i256, 2=i512, 3=reserved (i1024)
			ubyte pp;	/// VEX.pp opcode extension (NONE, 66H, F2H, F3H)
			ubyte vvvv;	/// VEX.vvvv register, limited to 3 bits in x86-32
			bool W;	/// REX.W alias, 1=64-bit size, 0=CS.D (normal operation)
			ubyte RR;	/// VEX.R/REX.R alias, affects ModRM.REG
					// 0=REG:0111, 1=REG:1111, 2=, 3=
			bool X;	/// REX.X alias, affects SIB.INDEX
			bool B;	/// REX.B alias, affects ModRM.RM, SIB.BASE, or opcode
		}
	}
}
private
struct vex_data_t { align(1):
	/// VEX byte pos  [0]      [1]      [2]      [3]
	/// (C5H) VEX.2B: 11000101 RvvvvLpp
	/// (C4H) VEX.3B: 11000100 RXBmmmmm WvvvvLpp
	/// (8FH) XOP   : 10001111 RXBmmmmm WvvvvLpp
	/// (62H) EVEX  : 01100010 RXBR00mm Wvvvv1pp zLLbVaa
	//    EVEX Notes:             R'              L' V'
	union {
		uint     i32;	/// VEX data filler alias
		ubyte[4] i8;	/// VEX byte data
		ushort   i16;	/// VEX i16 shortcut
	}
}

/// x86 internal structure
struct x86_internals_t { align(1):
	union {
		ushort modepack;	/// hehe
		struct {
			AdbgSyntaxWidth addrmode;	/// Current address register width (
			AdbgSyntaxWidth datamode;	/// Current memory operation width
		}
	}
	prefixes_t prefix;	/// Prefix data
	vex_data_t vexraw;	/// VEX raw data
	vex_t vex;	/// VEX computed fields
}

/// (Internal)
int adbg_disasm_x86(adbg_disasm_t *p) {
	// This is a trick I call "I like being memory unsafe just to save
	// an instruction"
	version (LittleEndian) {
		enum MODEPACK64 = 
			AdbgSyntaxWidth.i64 |
			AdbgSyntaxWidth.i32 << 8;
	} else {
		enum MODEPACK64 = 
			AdbgSyntaxWidth.i64 << 8 |
			AdbgSyntaxWidth.i32;
	}
	enum MODEPACK32 = 
		AdbgSyntaxWidth.i32 |
		AdbgSyntaxWidth.i32 << 8;
	enum MODEPACK16 = 
		AdbgSyntaxWidth.i16 |
		AdbgSyntaxWidth.i16 << 8;
	
	x86_internals_t x86 = void;
	
	with (AdbgDisasmPlatform)
	switch (p.platform) {
	case x86_64: x86.modepack = MODEPACK64; break;
	case x86_32: x86.modepack = MODEPACK32; break;
	default:     x86.modepack = MODEPACK16; break; // x86-16/8086
	}
	x86.prefix.all = 0;
	x86.vex.all = 0;
	x86.vexraw.i32 = 0;
	p.x86 = &x86;
	
L_START:
	ubyte opcode = void;
	int e = void;
	if ((e = adbg_disasm_fetch!ubyte(p, &opcode)) != 0) return e;
	
	if (opcode == 0xD6) // yep
		return adbg_error(AdbgError.illegalInstruction);
	
	immutable(x86_legacy_opcode_t) *op = &opcodes_legacy[opcode];
	
	adbg_disasm_push_x8(p, opcode);
	
	with (x86OpType)
	switch (op.type) { // Classed by priority then occurence
	case custom:
		return op.custom(p);
	case operand:
		adbg_disasm_push_str(p, op.mnemonic);
		return op.operand(p);
	case none:
		adbg_disasm_push_str(p, op.mnemonic);
		return 0;
	case prefix:
		with (x86Prefix)
		switch (opcode) {
		case data: // 66H
			x86.prefix.select = x86Prefix.choice66H;
			x86.datamode = x86.datamode == AdbgSyntaxWidth.i32 ?
				AdbgSyntaxWidth.i16 : AdbgSyntaxWidth.i32;
			goto L_START;
		case addr: // 67H
			if (p.platform == AdbgDisasmPlatform.x86_64) {
				x86.addrmode = x86.addrmode == AdbgSyntaxWidth.i32 ?
					AdbgSyntaxWidth.i64 : AdbgSyntaxWidth.i32;
			} else { // 16-bit mode
				x86.addrmode = x86.addrmode == AdbgSyntaxWidth.i32 ?
					AdbgSyntaxWidth.i16 : AdbgSyntaxWidth.i32;
			}
			goto L_START;
		case lock: // F0H
			x86.prefix.lock = true;
			goto L_START;
		case repne: // F2H
			x86.prefix.select = x86Prefix.choiceF2H;
			x86.prefix.repne = true;
			goto L_START;
		case rep: // F3H
			x86.prefix.select = x86Prefix.choiceF3H;
			x86.prefix.rep = true;
			goto L_START;
		default: // none
			assert(0, "X86: INVALID PREFIX");
		}
	case segment:
		x86.prefix.segment = op.segment;
		goto L_START;
	default: assert(0, "X86: INVALID TYPE");
	}
}

private:

int adbg_disasm_x86_0f(adbg_disasm_t *p) {
	
	
	return 0;
}

/// Segment override
enum x86Segment : ubyte {
	none, es, cs, ss, ds, fs, gs
}
/// x86 prefixes
enum x86Prefix : ubyte { // Intel order
	// Prefix selector
	none,
	choice66H,
	choiceF3H,
	choiceF2H,
	// With actual values
	data	= 0x66, /// 0x66
	rep	= 0xF3, /// 0xF3
	repne	= 0xF2, /// 0xF2
	addr	= 0x67, /// 0x67
	lock	= 0xF0, /// 0xF0
}
enum x86OpType : ubyte {
	/// Instruction has no operands
	none,
	/// Instruction has operand handler
	operand,
	/// Instruction prefix
	prefix,
	/// Instruction segment override
	segment,
	/// Instruction maps or custom handling
	custom,
}

struct x86_opcode_t {
	const(char)* mnemonic;
	int function(adbg_disasm_t*) operand;
}
struct x86_legacy_opcode_t {
	align(2) x86OpType type;
	union {
		struct {
			const(char)* mnemonic;
			int function(adbg_disasm_t*) operand;
		}
		int function(adbg_disasm_t*) custom;
		x86Segment segment;
	}
}
struct x86_vex_opcode_t {
	align(2) x86OpType type;
	union { // NOTE: null meaning invalid
		struct {
			x86_opcode_t[4] vex; // none/66H/F3H/F2H
			x86_opcode_t[2] sse; // none/66H
		}
		int function(adbg_disasm_t*) custom;
	}
}

// Instruction names, in case the compiler doesn't support string pooling
// Legacy
immutable const(char) *M_ADD	= "add";
immutable const(char) *M_OR	= "or";
immutable const(char) *M_PUSH	= "push";
immutable const(char) *M_POP	= "pop";
immutable const(char) *M_ADC	= "adc";
immutable const(char) *M_SBB	= "sbb";
immutable const(char) *M_AND	= "and";
immutable const(char) *M_SUB	= "sub";
immutable const(char) *M_XOR	= "xor";
immutable const(char) *M_CMP	= "cmp";
immutable const(char) *M_DAA	= "daa";
immutable const(char) *M_DAS	= "das";
immutable const(char) *M_AAA	= "aaa"; // not the battery format
immutable const(char) *M_AAS	= "aas";
immutable const(char) *M_INC	= "inc";
immutable const(char) *M_DEC	= "dec";
immutable const(char) *M_PUSHA	= "pusha";
immutable const(char) *M_PUSHD	= "pushd";
immutable const(char) *M_BOUND	= "bound";
immutable const(char) *M_ARPL	= "arpl";
immutable const(char) *M_MOVSXD	= "movsxd";
immutable const(char) *M_IMUL	= "imul";
immutable const(char) *M_INSB	= "insb";
immutable const(char) *M_INSW	= "insw";
immutable const(char) *M_INSD	= "insd";
immutable const(char) *M_OUTSB	= "outsb";
immutable const(char) *M_OUTSW	= "outsw";
immutable const(char) *M_OUTSD	= "outsd";
immutable const(char) *M_JO	= "jo";
immutable const(char) *M_JNO	= "jno";
immutable const(char) *M_JB	= "jb";
immutable const(char) *M_JNB	= "jnb";
immutable const(char) *M_JZ	= "jz";
immutable const(char) *M_JNZ	= "jnz";
immutable const(char) *M_JBE	= "jbe";
immutable const(char) *M_JNBE	= "jnbe";
immutable const(char) *M_JS	= "js";
immutable const(char) *M_JNS	= "jns";
immutable const(char) *M_JP	= "jp";
immutable const(char) *M_JNP	= "jnp";
immutable const(char) *M_JL	= "jl";
immutable const(char) *M_JNL	= "jnl";
immutable const(char) *M_JLE	= "jle";
immutable const(char) *M_JNLE	= "jnle";
// SSE
// AVX

// Operand aliases, for readability
// Intel-compliant, unless the operand format is AMD-specific
// ModR/M
alias EbGb	= adbg_disasm_x86_op_EbGb;
alias EvGv	= adbg_disasm_x86_op_EvGv;
alias GbEb	= adbg_disasm_x86_op_GbEb;
alias GvEv	= adbg_disasm_x86_op_GvEv;
// ModR/M-Immediate
alias GvEvIz	= adbg_disasm_x86_op_GvEvIz;
alias GvEvIb	= adbg_disasm_x86_op_GvEvIb;
// Register-Immediate
alias ALIb	= adbg_disasm_x86_op_ALIb;
alias rAXIz	= adbg_disasm_x86_op_rAXIz;
// Register-Register
alias rAXr8	= adbg_disasm_x86_op_rAXr8;
alias rCXr9	= adbg_disasm_x86_op_rCXr9;
alias rDXr10	= adbg_disasm_x86_op_rDXr10;
alias rBXr11	= adbg_disasm_x86_op_rBXr11;
alias rSPr12	= adbg_disasm_x86_op_rSPr12;
alias rBPr13	= adbg_disasm_x86_op_rBPr13;
alias rSIr14	= adbg_disasm_x86_op_rSIr14;
alias rDIr15	= adbg_disasm_x86_op_rDIr15;
// Segment registers
alias ES	= adbg_disasm_x86_op_ES;
alias CS	= adbg_disasm_x86_op_CS;
alias SS	= adbg_disasm_x86_op_SS;
alias DS	= adbg_disasm_x86_op_DS;
// Immediate
alias Iz	= adbg_disasm_x86_op_Iz;
alias Ib	= adbg_disasm_x86_op_Ib;
// Special
alias YbDX	= adbg_disasm_x86_op_YbDX;
alias DXXb	= adbg_disasm_x86_op_DXXb;

// ANCHOR Instruction definitions

immutable x86_legacy_opcode_t[256] opcodes_legacy = [
	// 00H
	{ x86OpType.operand,	M_ADD,	&EbGb },
	{ x86OpType.operand,	M_ADD,	&EvGv },
	{ x86OpType.operand,	M_ADD,	&GbEb },
	{ x86OpType.operand,	M_ADD,	&GvEv },
	{ x86OpType.operand,	M_ADD,	&ALIb },
	{ x86OpType.operand,	M_ADD,	&rAXIz },
	{ x86OpType.operand,	M_PUSH,	&ES },
	{ x86OpType.operand,	M_POP,	&ES },
	// 08H
	{ x86OpType.operand,	M_OR,	&EbGb },
	{ x86OpType.operand,	M_OR,	&EvGv },
	{ x86OpType.operand,	M_OR,	&GbEb },
	{ x86OpType.operand,	M_OR,	&GvEv },
	{ x86OpType.operand,	M_OR,	&ALIb },
	{ x86OpType.operand,	M_OR,	&rAXIz },
	{ x86OpType.operand,	M_PUSH,	&CS },
	{ x86OpType.custom,	null },
	// 10H
	{ x86OpType.operand,	M_ADC,	&EbGb },
	{ x86OpType.operand,	M_ADC,	&EvGv },
	{ x86OpType.operand,	M_ADC,	&GbEb },
	{ x86OpType.operand,	M_ADC,	&GvEv },
	{ x86OpType.operand,	M_ADC,	&ALIb },
	{ x86OpType.operand,	M_ADC,	&rAXIz },
	{ x86OpType.operand,	M_PUSH,	&SS },
	{ x86OpType.operand,	M_POP,	&SS },
	// 18H
	{ x86OpType.operand,	M_SBB,	&EbGb },
	{ x86OpType.operand,	M_SBB,	&EvGv },
	{ x86OpType.operand,	M_SBB,	&GbEb },
	{ x86OpType.operand,	M_SBB,	&GvEv },
	{ x86OpType.operand,	M_SBB,	&ALIb },
	{ x86OpType.operand,	M_SBB,	&rAXIz },
	{ x86OpType.operand,	M_PUSH,	&DS },
	{ x86OpType.operand,	M_POP,	&DS },
	// 20H
	{ x86OpType.operand,	M_AND,	&EbGb },
	{ x86OpType.operand,	M_AND,	&EvGv },
	{ x86OpType.operand,	M_AND,	&GbEb },
	{ x86OpType.operand,	M_AND,	&GvEv },
	{ x86OpType.operand,	M_AND,	&ALIb },
	{ x86OpType.operand,	M_AND,	&rAXIz },
	{ x86OpType.segment,	segment: x86Segment.es },
	{ x86OpType.custom,	custom: null }, //TODO: DAA (except 64bit mode)
	// 28H
	{ x86OpType.operand,	M_SUB,	&EbGb },
	{ x86OpType.operand,	M_SUB,	&EvGv },
	{ x86OpType.operand,	M_SUB,	&GbEb },
	{ x86OpType.operand,	M_SUB,	&GvEv },
	{ x86OpType.operand,	M_SUB,	&ALIb },
	{ x86OpType.operand,	M_SUB,	&rAXIz },
	{ x86OpType.segment,	segment: x86Segment.cs },
	{ x86OpType.custom,	custom: null }, //TODO: DAS (except 64bit mode)
	// 30H
	{ x86OpType.operand,	M_XOR,	&EbGb },
	{ x86OpType.operand,	M_XOR,	&EvGv },
	{ x86OpType.operand,	M_XOR,	&GbEb },
	{ x86OpType.operand,	M_XOR,	&GvEv },
	{ x86OpType.operand,	M_XOR,	&ALIb },
	{ x86OpType.operand,	M_XOR,	&rAXIz },
	{ x86OpType.segment,	segment: x86Segment.ss },
	{ x86OpType.custom,	custom: null }, //TODO: AAA (except 64bit mode)
	// 38H
	{ x86OpType.operand,	M_CMP,	&EbGb },
	{ x86OpType.operand,	M_CMP,	&EvGv },
	{ x86OpType.operand,	M_CMP,	&GbEb },
	{ x86OpType.operand,	M_CMP,	&GvEv },
	{ x86OpType.operand,	M_CMP,	&ALIb },
	{ x86OpType.operand,	M_CMP,	&rAXIz },
	{ x86OpType.segment,	segment: x86Segment.ds },
	{ x86OpType.custom,	custom: null }, //TODO: AAS (except 64bit mode)
	// 40H
	{ x86OpType.custom,	custom: null }, //TODO: REX handlers
	{ x86OpType.custom,	custom: null },
	{ x86OpType.custom,	custom: null },
	{ x86OpType.custom,	custom: null },
	{ x86OpType.custom,	custom: null },
	{ x86OpType.custom,	custom: null },
	{ x86OpType.custom,	custom: null },
	{ x86OpType.custom,	custom: null },
	// 48H
	{ x86OpType.custom,	custom: null },
	{ x86OpType.custom,	custom: null },
	{ x86OpType.custom,	custom: null },
	{ x86OpType.custom,	custom: null },
	{ x86OpType.custom,	custom: null },
	{ x86OpType.custom,	custom: null },
	{ x86OpType.custom,	custom: null },
	{ x86OpType.custom,	custom: null },
	// 50H
	{ x86OpType.operand,	M_PUSH,	&rAXr8 },
	{ x86OpType.operand,	M_PUSH,	&rCXr9 },
	{ x86OpType.operand,	M_PUSH,	&rDXr10 },
	{ x86OpType.operand,	M_PUSH,	&rBXr11 },
	{ x86OpType.operand,	M_PUSH,	&rSPr12 },
	{ x86OpType.operand,	M_PUSH,	&rBPr13 },
	{ x86OpType.operand,	M_PUSH,	&rSIr14 },
	{ x86OpType.operand,	M_PUSH,	&rDIr15 },
	// 58H
	{ x86OpType.operand,	M_POP,	&rAXr8 },
	{ x86OpType.operand,	M_POP,	&rCXr9 },
	{ x86OpType.operand,	M_POP,	&rDXr10 },
	{ x86OpType.operand,	M_POP,	&rBXr11 },
	{ x86OpType.operand,	M_POP,	&rSPr12 },
	{ x86OpType.operand,	M_POP,	&rBPr13 },
	{ x86OpType.operand,	M_POP,	&rSIr14 },
	{ x86OpType.operand,	M_POP,	&rDIr15 },
	// 60H
	{ x86OpType.custom,	custom: null },	//TODO: PUSHa/d (invalid in 64-bit)
	{ x86OpType.custom,	custom: null },	//TODO: POPa/d (invalid in 64-bit)
	{ x86OpType.custom,	custom: null },	//TODO: BOUND (invalid in 64-bit)
	{ x86OpType.custom,	custom: null },	//TODO: ARPL3/MOVSXD4
	{ x86OpType.prefix },	// fs:
	{ x86OpType.prefix },	// gs:
	{ x86OpType.prefix },	// data
	{ x86OpType.prefix },	// address
	// 68H
	{ x86OpType.operand,	M_PUSH,	&Iz },
	{ x86OpType.operand,	M_IMUL,	&GvEvIz },
	{ x86OpType.operand,	M_PUSH,	&Ib },
	{ x86OpType.operand,	M_IMUL,	&GvEvIb },
	{ x86OpType.operand,	M_INSB,	&YbDX },
	{ x86OpType.custom,	null },	/// TODO: INSW/D
	{ x86OpType.operand,	M_OUTSB,	&DXXb },
	{ x86OpType.custom,	null },	/// TODO: OUTSW/D
];

enum x86Reg { // ModRM order
	// 16b
	ax,	cx,	dx,	bx,
	sp,	bp,	si,	di,
	r8w,	r9w,	r10w,	r11w,
	r12w,	r13w,	r14w,	r15w,
	// 8b
	al = ax,	cl = cx,	dl = dx,	bl = bx,
	ah = sp,	ch = bp,	dh = si,	bh = di,
	r8b = r8w,	r9b = r9w,	r10b = r10w,	r11b = r11w,
	r12b = r12w,	r13b = r13w,	r14b = r14w,	r15b = r15w,
	// 32b
	eax = ax,	ecx = cx,	edx = dx,	ebx = bx,
	esp = sp,	ebp = bp,	esi = si,	edi = di,
	r8d = r8w,	r9d = r9w,	r10d = r10w,	r11d = r11w,
	r12d = r12w,	r13d = r13w,	r14d = r14w,	r15d = r15w,
	// 64b
	rax	= ax,	rcx	= cx,	rdx	= dx,	rbx	= bx,
	rsp	= sp,	rbp	= bp,	rsi	= si,	rdi	= di,
	r8	= r8w,	r9	= r9w,	r10	= r10w,	r11	= r11w,
	r12	= r12w,	r13	= r13w,	r14	= r14w,	r15	= r15w,
	// 128b
	xmm0	= ax,	xmm1	= cx,	xmm2	= dx,	xmm3	= bx,
	xmm4	= sp,	xmm5	= bp,	xmm6	= si,	xmm7	= di,
	xmm8	= r8w,	xmm9	= r9w,	xmm10	= r10w,	xmm11	= r11w,
	xmm12	= r12w,	xmm13	= r13w,	xmm14	= r14w,	xmm15	= r15w,
	// 256b
	ymm0	= ax,	ymm1	= cx,	ymm2	= dx,	ymm3	= bx,
	ymm4	= sp,	ymm5	= bp,	ymm6	= si,	ymm7	= di,
	ymm8	= r8w,	ymm9	= r9w,	ymm10	= r10w,	ymm11	= r11w,
	ymm12	= r12w,	ymm13	= r13w,	ymm14	= r14w,	ymm15	= r15w,
	// 512b
	zmm0	= ax,	zmm1	= cx,	zmm2	= dx,	zmm3	= bx,
	zmm4	= sp,	zmm5	= bp,	zmm6	= si,	zmm7	= di,
	zmm8	= r8w,	zmm9	= r9w,	zmm10	= r10w,	zmm11	= r11w,
	zmm12	= r12w,	zmm13	= r13w,	zmm14	= r14w,	zmm15	= r15w,
	// x87
	mm0	= 0,	mm1	= 1,	mm2	= 2,	mm3	= 3,
	mm4	= 4,	mm5	= 5,	mm6	= 6,	mm7	= 7,
}
immutable const(char)*[][] regs = [
	[ // 8b
		"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh",
		"r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"
	], [ // 16b
		"ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
		"r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"
	], [ // 32b
		"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
		"r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"
	], [ // 64b
		"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
		"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
	], [ // 128b
		"xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
		"xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"
	], [ // 256b
		"ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7",
		"ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15",
	], [ // 512b
		"zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7",
		"zmm8", "zmm9", "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15",
	]
];
immutable const(char)*[] regs80 = [ // x87
	"mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7"
];
immutable const(char)*[2][] regs_addr16 = [ // modrm:rm16
	[ "bx", "si" ], [ "bx", "si" ], [ "bp", "si" ], [ "bp", "di" ],
	[ "si", null ], [ "di", null ], [ "bp", null ], [ "bp", null ],
];
/*immutable const(char)*[] regs_tmm = [
	"tmm0", "tmm1", "tmm2", "tmm3", "tmm4", "tmm5", "tmm6", "tmm7"
];*/

//
// SECTION  Operand implementation
//

int adbg_disasm_x86_op_EbGb(adbg_disasm_t *p) {
	p.x86.datamode = AdbgSyntaxWidth.i8;
	return adbg_disasm_x86_modrm_auto(p, false);
}
int adbg_disasm_x86_op_EvGv(adbg_disasm_t *p) {
	return adbg_disasm_x86_modrm_auto(p, false);
}
int adbg_disasm_x86_op_GbEb(adbg_disasm_t *p) {
	p.x86.datamode = AdbgSyntaxWidth.i8;
	return adbg_disasm_x86_modrm_auto(p, true);
}
int adbg_disasm_x86_op_GvEv(adbg_disasm_t *p) {
	return adbg_disasm_x86_modrm_auto(p, true);
}
int adbg_disasm_x86_op_GvEvIz(adbg_disasm_t *p) {
	return 0;
}
int adbg_disasm_x86_op_GvEvIb(adbg_disasm_t *p) {
	return 0;
}
int adbg_disasm_x86_op_YbDX(adbg_disasm_t *p) {
	return 0;
}
int adbg_disasm_x86_op_DXXb(adbg_disasm_t *p) {
	return 0;
}

// ANCHOR Register-Immediate operand mechanic

int adbg_disasm_x86_op_ALIb(adbg_disasm_t *p) {
	adbg_disasm_push_reg(p, regs[AdbgSyntaxWidth.i8][x86Reg.al]);
	return adbg_disasm_x86_op_Ib(p);
}
int adbg_disasm_x86_op_rAXIz(adbg_disasm_t *p) {
	
	
	return 0;
}

// ANCHOR Immediate mechanic

int adbg_disasm_x86_op_Iz(adbg_disasm_t *p) {
	return 0;
}
int adbg_disasm_x86_op_Ib(adbg_disasm_t *p) {
	ubyte imm = void;
	int e = adbg_disasm_fetch!ubyte(p, &imm);
	if (e) return e;
	adbg_disasm_push_imm(p, imm);
	return 0;
}

// ANCHOR Register operand mechanic

int adbg_disasm_x86_op_rAXr8(adbg_disasm_t *p) {
	
	
	return 0;
}
int adbg_disasm_x86_op_rCXr9(adbg_disasm_t *p) {
	
	
	return 0;
}
int adbg_disasm_x86_op_rDXr10(adbg_disasm_t *p) {
	
	
	return 0;
}
int adbg_disasm_x86_op_rBXr11(adbg_disasm_t *p) {
	
	
	return 0;
}
int adbg_disasm_x86_op_rSPr12(adbg_disasm_t *p) {
	
	
	return 0;
}
int adbg_disasm_x86_op_rBPr13(adbg_disasm_t *p) {
	
	
	return 0;
}
int adbg_disasm_x86_op_rSIr14(adbg_disasm_t *p) {
	
	
	return 0;
}
int adbg_disasm_x86_op_rDIr15(adbg_disasm_t *p) {
	
	
	return 0;
}

// ANCHOR Segment register operand mechanic

int adbg_disasm_x86_op_ES(adbg_disasm_t *p) {
	
	
	return 0;
}
int adbg_disasm_x86_op_CS(adbg_disasm_t *p) {
	
	
	return 0;
}
int adbg_disasm_x86_op_SS(adbg_disasm_t *p) {
	
	
	return 0;
}
int adbg_disasm_x86_op_DS(adbg_disasm_t *p) {
	
	
	return 0;
}

//
// Internal "mechanic" implementations
//

// ANCHOR ModR/M mechanic

int adbg_disasm_x86_modrm_auto(adbg_disasm_t *p, bool reg) {
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(p, &modrm);
	return e ? e : adbg_disasm_x86_modrm(p, modrm, reg);
}
int adbg_disasm_x86_modrm(adbg_disasm_t *p, ubyte modrm, bool regtarget) {
	/*if (flags & X86_FLAG_USE_OP) {
		if (p.x86.vex.W)
			wmem = wreg = MemWidth.i64;
		else
			wreg = wmem = p.x86.op & X86_FLAG_WIDE ? MemWidth.i32 : MemWidth.i8;
		dir = p.x86.op & X86_FLAG_DIR;
	} else {
		wreg = (flags & X86_FLAG_REGW) >> 8;
		wmem = (flags & X86_FLAG_MEMW) >> 12;
		dir = flags & X86_FLAG_DIR;
	}*/
	if (regtarget) {
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_push_reg(p, adbg_disasm_x86_modrm_reg(p, modrm));
		adbg_disasm_x86_modrm_rm(p, modrm);
	} else {
		adbg_disasm_x86_modrm_rm(p, modrm);
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_push_reg(p, adbg_disasm_x86_modrm_reg(p, modrm));
	}
	
	return 0;
}
int adbg_disasm_x86_modrm_rm(adbg_disasm_t *p, ubyte modrm) {
	
	
	return 0;
}
const(char) *adbg_disasm_x86_modrm_reg(adbg_disasm_t *p, ubyte modrm) {
	
	
	return null;
}
