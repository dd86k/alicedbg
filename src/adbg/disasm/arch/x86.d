/**
 * 8086/x86/amd64 decoder.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.disasm.arch.x86;

//TODO: Consider default segment per instruction
//TODO: Use signed numbers as much as possible

//TODO:

import adbg.error;
import adbg.disasm.disasm;

extern (C):
	
private import adbg.disasm.syntaxer;

private
struct prefixes_t { align(1):
	union {
		ulong all;
		ushort modes;
		struct {
			AdbgSyntaxWidth data;	/// Data mode (register only)
			AdbgSyntaxWidth addr;	/// Address mode (address register only)
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
	/// Byte pos      [0]      [1]      [2]      [3]
	/// (4xH) REX   : 0100WRXB
	/// (C5H) VEX.2B: 11000101 RvvvvLpp
	/// (C4H) VEX.3B: 11000100 RXBmmmmm WvvvvLpp
	/// (8FH) XOP   : 10001111 RXBmmmmm WvvvvLpp
	/// (62H) EVEX  : 01100010 RXBR00mm Wvvvv1pp zLLbVaa
	//    EVEX Notes:             R'              L' V'
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
	union {
		uint     i32;	/// VEX data filler alias
		ubyte[4] i8;	/// VEX byte data
		ushort   i16;	/// VEX i16 shortcut
	}
}

/// x86 internal structure
struct x86_internals_t { align(1):
	prefixes_t prefix;	/// Prefix data
	vex_data_t vexraw;	/// VEX raw data
	vex_t vex;	/// VEX computed fields
}

/// (Internal)
int adbg_disasm_x86(adbg_disasm_t *p) {
	// This is a trick I call "I like being memory unsafe just to save
	// an instruction"
	version (LittleEndian) {
		enum MODEPACK64 = AdbgSyntaxWidth.i64 | AdbgSyntaxWidth.i32 << 8;
	} else {
		enum MODEPACK64 = AdbgSyntaxWidth.i64 << 8 | AdbgSyntaxWidth.i32;
	}
	enum MODEPACK32 = AdbgSyntaxWidth.i32 | AdbgSyntaxWidth.i32 << 8;
	enum MODEPACK16 = AdbgSyntaxWidth.i16 | AdbgSyntaxWidth.i16 << 8;
	
	x86_internals_t x86 = void;
	
	with (AdbgDisasmPlatform)
	switch (p.platform) {
	case x86_64: x86.prefix.modes = MODEPACK64; break; // AMD64
	case x86_32: x86.prefix.modes = MODEPACK32; break; // i386
	default:     x86.prefix.modes = MODEPACK16; break; // 8086
	}
	x86.prefix.all = 0;
	x86.vex.all = 0;
	x86.vexraw.i32 = 0;
	p.x86 = &x86;
	
	ubyte opcode = void;
L_PREFIX:
	int e = adbg_disasm_fetch!ubyte(p, &opcode);
	if (e) return e;
	
	switch (opcode) {
	case 0x26:
		x86.prefix.segment = x86Segment.es;
		p.syntaxer.segment = segs[x86Segment.es];
		goto L_PREFIX;
	case 0x2e:
		x86.prefix.segment = x86Segment.cs;
		p.syntaxer.segment = segs[x86Segment.cs];
		goto L_PREFIX;
	case 0x36:
		x86.prefix.segment = x86Segment.ss;
		p.syntaxer.segment = segs[x86Segment.ss];
		goto L_PREFIX;
	case 0x3e:
		x86.prefix.segment = x86Segment.ds;
		p.syntaxer.segment = segs[x86Segment.ds];
		goto L_PREFIX;
	case 0x64:
		x86.prefix.segment = x86Segment.fs;
		p.syntaxer.segment = segs[x86Segment.fs];
		goto L_PREFIX;
	case 0x65:
		x86.prefix.segment = x86Segment.gs;
		p.syntaxer.segment = segs[x86Segment.gs];
		goto L_PREFIX;
	case 0x66: // Data, 64-bit = REX.W (48H)
		x86.prefix.addr =
			x86.prefix.addr == AdbgSyntaxWidth.i16 ?
			AdbgSyntaxWidth.i32 : AdbgSyntaxWidth.i16;
		goto L_PREFIX;
	case 0x67: // Address, 64-bit = REX.XB (42H,41H)
		x86.prefix.addr =
			x86.prefix.addr == AdbgSyntaxWidth.i16 ?
			AdbgSyntaxWidth.i32 : AdbgSyntaxWidth.i16;
		goto L_PREFIX;
	case 0xd6: // hehe
		return adbg_error(AdbgError.illegalInstruction);
	case 0xf0:
		x86.prefix.lock = true;
		if (p.mode >= AdbgDisasmMode.file)
			if (x86.prefix.lock == false) // avoid spam
				adbg_syntax_add_prefix(p.syntaxer, "lock");
		goto L_PREFIX;
	case 0xf2:
		x86.prefix.repne = true;
		if (p.mode >= AdbgDisasmMode.file)
			if (x86.prefix.repne == false) // avoid spam
				adbg_syntax_add_prefix(p.syntaxer, "repne");
		goto L_PREFIX;
	case 0xf3:
		x86.prefix.rep = true;
		if (p.mode >= AdbgDisasmMode.file)
			if (x86.prefix.rep == false) // avoid spam
				adbg_syntax_add_prefix(p.syntaxer, "rep");
		goto L_PREFIX;
	default:
	}
	
	// Opcode
L_OPCODE:
	if ((e = adbg_disasm_fetch!ubyte(p, &opcode)) != 0) return e;
	
	if (opcode < 0x40) {
		// 2-byte escape
		// Most intructions are multi-byte so this trick services as an
		// "already handled" case.
		if (opcode == 0x0f) return adbg_disasm_x86_0f(p);
		
		//          r   m
		//              DW
		// 0	00 000 000	modrm
		// 1	00 000 001	modrm
		// 2	00 000 010	modrm
		// 3	00 000 011	modrm
		// 4	00 000 100	al, imm8
		// 5	00 000 101	ax, imm16
		// 6	00 000 110	PUSH
		// 7	00 000 111	POP (or 2-byte)
		// 00h	00 000 000	add
		// 08h	00 001 000	or
		// ..
		// 38h	00 111 000	cmp
		ubyte m = opcode & 7;
		ubyte r = opcode >> 3; // no masking since MOD=00
		
		// push/pop
		if (m >= 0b110) {
			if (r < 4) {
				adbg_syntax_add_mnemonic(p.syntaxer, opcode & 1 ? M_POP : M_PUSH);
				adbg_syntax_add_register(p.syntaxer, segs[r]);
				return 0;
			}
			// Prefixes already taken care of
			if (p.platform == AdbgDisasmPlatform.x86_64)
				return adbg_error(AdbgError.illegalInstruction);
			// 27h	00 100 111	daa
			// 2fh	00 101 111	das
			// 37h	00 110 111	aaa
			// 3fh	00 111 111	aas
			if (p.mode >= AdbgDisasmMode.file)
				adbg_syntax_add_register(p.syntaxer, mnemonic_ascii[r & 3]);
			return 0;
		}
		
		if (p.mode >= AdbgDisasmMode.file) {
			const(char) *mnemonic = mnemonic_00[r];
			adbg_syntax_add_mnemonic(p.syntaxer, mnemonic);
		}
		
		// A, immediate
		if (m >= 0b100) {
			if (p.mode >= AdbgDisasmMode.file)
				adbg_syntax_add_register(p.syntaxer,
					regs[x86.prefix.data][x86Reg.eax]);
			if (opcode & 1)
				return adbg_disasm_x86_op_Iz(p);
			else
				return adbg_disasm_x86_op_Ib(p);
		}
		
		// modrm
		return adbg_disasm_x86_modrm_legacy_auto(p, opcode);
	}
	if (opcode < 0x50) { // >=40H, INC/DEC or REX
		if (p.platform == AdbgDisasmPlatform.x86_64) {
			x86.vex.W  = (opcode & 8) != 0;
			x86.vex.RR = (opcode & 4) != 0;
			x86.vex.X  = (opcode & 2) != 0;
			x86.vex.B  = (opcode & 1) != 0;
			goto L_OPCODE;
		}
		if (p.mode >= AdbgDisasmMode.file) {
			ubyte m = opcode & 7;
			adbg_syntax_add_mnemonic(p.syntaxer, opcode < 0x48 ? M_INC : M_DEC);
			adbg_syntax_add_register(p.syntaxer, regs[x86.prefix.data][m]);
		}
		return 0;
	}
	if (opcode < 0x60) { // >=50H, PUSH/POP
		if (p.mode >= AdbgDisasmMode.file) {
			ubyte m = opcode & 7;
			if (x86.vex.RR) m |= 0b1000;
			adbg_syntax_add_mnemonic(p.syntaxer, opcode < 0x58 ? M_PUSH : M_POP);
			adbg_syntax_add_register(p.syntaxer, regs[x86.prefix.data][m]);
		}
		return 0;
	}
	if (opcode < 0x70) { // >=60H, random crap
		
		return 0;
	}
	if (opcode < 0x80) { // >=70H, Jcc
		if (p.mode >= AdbgDisasmMode.file)
			adbg_syntax_add_mnemonic(p.syntaxer, mnemonic_Jcc[opcode & 15]);
		return adbg_disasm_x86_op_Jb(p);
	}
	
	return 0;
}

private:

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

immutable const(char)*[] mnemonic_00 = [
	M_ADD, M_OR, M_ADC, M_SBB, M_AND, M_SUB, M_XOR, M_CMP
];
immutable const(char)*[] mnemonic_ascii = [
	M_DAA, M_DAS, M_AAA, M_AAS
];
immutable const(char)*[] mnemonic_Jcc = [ // Both Intel and AMD
	"jo", "jno", "jb", "jnb", "jz", "jnz", "jbe", "jnbe",
	"js", "jns", "jp", "jnp", "jl", "jnl", "jle", "jnle",
];

/// 2-byte escape
int adbg_disasm_x86_0f(adbg_disasm_t *p) {
	
	
	return 0;
}

/// Segment register (override only, not for segs)
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
immutable const(char)*[] segs = [
	"es", "cs", "ss", "ds", "fs", "gs"
];
/*immutable const(char)*[] regs_tmm = [
	"tmm0", "tmm1", "tmm2", "tmm3", "tmm4", "tmm5", "tmm6", "tmm7"
];*/

// Operand

int adbg_disasm_x86_op_Ib(adbg_disasm_t *p) { // Immediate 8-bit
	ubyte i = void;
	int e = adbg_disasm_fetch!ubyte(p, &i);
	if (e == 0) {
		if (p.mode >= AdbgDisasmMode.file) {
			adbg_syntax_add_machine!ubyte(p.syntaxer, i);
			adbg_syntax_add_immediate!ubyte(p.syntaxer, i);
		}
	}
	return e;
}
int adbg_disasm_x86_op_Iz(adbg_disasm_t *p) { // Immediate 16/32-bit
	union u_t {
		uint i32;
		ushort i16;
	}
	u_t u = void;
	int e = void;
	
	if (p.x86.prefix.data != AdbgSyntaxWidth.i16) { // 64/32 modes
		e = adbg_disasm_fetch!uint(p, &u.i32);
		if (e == 0) {
			if (p.mode >= AdbgDisasmMode.file) {
				adbg_syntax_add_machine!uint(p.syntaxer, u.i32);
				adbg_syntax_add_immediate!uint(p.syntaxer, u.i32);
			}
		}
	} else {
		e = adbg_disasm_fetch!ushort(p, &u.i16);
		if (e == 0) {
			if (p.mode >= AdbgDisasmMode.file) {
				adbg_syntax_add_machine!uint(p.syntaxer, u.i16);
				adbg_syntax_add_immediate!uint(p.syntaxer, u.i16);
			}
		}
	}
	
	return e;
}
int adbg_disasm_x86_op_Jb(adbg_disasm_t *p) { // Immediate 8-bit
	ubyte i = void;
	int e = adbg_disasm_fetch!ubyte(p, &i);
	if (e == 0) {
		if (p.mode >= AdbgDisasmMode.data)
			p.opcode.targetaddri64 = p.baseaddri64 + i;
		if (p.mode >= AdbgDisasmMode.file) {
			adbg_syntax_add_machine!ubyte(p.syntaxer, i);
			adbg_syntax_add_immediate!ubyte(p.syntaxer, i);
		}
	}
	return e;
}


//
// ANCHOR ModR/M legacy mechanics
//

int adbg_disasm_x86_modrm_legacy_auto(adbg_disasm_t *p, ubyte opcode) {
	// Reminder: Address and Data modes are already handled prior to
	//           calling this. Unless, of course, instruction dictactes
	//           otherwise (e.g. per instruction, per map, etc.)
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(p, &modrm);
	if (e) return e;
	
	
	
	return adbg_disasm_x86_modrm_legacy_modrm(p, modrm);
}
int adbg_disasm_x86_modrm_legacy_modrm(adbg_disasm_t *p, ubyte modrm) {
	
	
	
	return 0;
}
int adbg_disasm_x86_modrm_legacy(adbg_disasm_t *p, int reg, int mem, AdbgSyntaxWidth wreg, AdbgSyntaxWidth wmem, bool direction) {
	
	
	
	return 0;
}

int adbg_disasm_x86_modrm_rm(adbg_disasm_t *p, ubyte rm) {
	
	
	return 0;
}
const(char) *adbg_disasm_x86_modrm_reg(adbg_disasm_t *p, ubyte reg) {
	
	
	return null;
}

//
// ANCHOR ModR/M AVX mechanics
//
