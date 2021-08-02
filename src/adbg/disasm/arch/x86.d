/**
 * Linear 8086/x86/amd64 decoder.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.disasm.arch.x86;

// NOTE: Instruction encoding for opcodes <40h follow ModR/M encoding

import adbg.error;
import adbg.disasm.disasm;

extern (C):

private
enum x86Attr : uint {
	modrm	= 0x0000_0001,	/// Has ModRM byte
	sib	= 0x0000_0002,	/// Has SIB byte
	rex	= 0x0000_0004,	/// Has REX prefix
	xop	= 0x0000_0008,	/// Has XOP prefix
	vex	= 0x0000_0010,	/// Has VEX prefix
	evex	= 0x0000_0020,	/// Has EVEX prefix
	mvex	= 0x0000_0040,	/// Has MVEX prefix
	relative	= 0x0000_0080,	/// Has at least one operand with position-relative offset
	privileged	= 0x0000_0100,	/// Instruction is privileged
}

private
struct prefixes_t { align(1):
	union {
		ushort modes;
		struct {
			AdbgDisasmType data;	/// Data mode (register only)
			AdbgDisasmType addr;	/// Address mode (address register only)
		}
	}
	x86Segment segment;	/// segment override
	x86Prefix lastpf;	/// SSE/VEX instruction selector
	bool lock;	/// LOCK prefix
	bool rep;	/// REP/REPE prefix
	bool repne;	/// REPNE prefix
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
	ubyte LL;	/// VEX.L vector length
			// 0=scalar/i128, 1=i256, 2=i512, 3=i1024 (reserved)
	ubyte pp;	/// VEX.pp opcode extension (NONE, 66H, F2H, F3H)
	ubyte vvvv;	/// VEX.vvvv register, limited to 3 bits in x86-32
	bool W;	/// REX.W alias, 1=64-bit size, 0=CS.D (normal operation)
	ubyte RR;	/// VEX.R/REX.R alias, affects ModRM.REG
			// 0=REG:0111, 1=REG:1111, 2=, 3=
	bool X;	/// REX.X alias, affects SIB.INDEX
	bool B;	/// REX.B alias, affects ModRM.RM, SIB.BASE, or opcode
	ubyte res;
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
	union {
		ulong[4] z;	/// 
		struct {
			prefixes_t prefix;	/// Prefix data
			vex_data_t vexraw;	/// VEX raw data
			vex_t vex;	/// VEX/REX computed fields
		}
	}
}

// ANCHOR legacy map
int adbg_disasm_x86(adbg_disasm_t *p) {
	x86_internals_t x86 = void;
	x86.z[3] = x86.z[2] = x86.z[1] = x86.z[0] = 0;
	
	with (AdbgPlatform)
	switch (p.platform) {
	case x86_64:
		x86.prefix.addr = AdbgDisasmType.i64;
		x86.prefix.data = AdbgDisasmType.i32;
		break;
	case x86_32:
		x86.prefix.addr = AdbgDisasmType.i32;
		x86.prefix.data = AdbgDisasmType.i32;
		break;
	default:
		x86.prefix.addr = AdbgDisasmType.i16;
		x86.prefix.data = AdbgDisasmType.i16;
		break;
	}
	p.x86 = &x86;
	
	const(char) *mnemonic = void;
	ubyte opcode = void;
	ubyte reg = void;	/// modrm:reg
	ubyte rm  = void;	/// modrm:rm
	bool  W   = void;	/// W bit
L_PREFIX:
	int e = adbg_disasm_fetch!ubyte(p, &opcode);
	if (e) return e;
	
	//TODO: Consider moving this to the normal decoding process.
	//      Should be part of the normal decoding process, or at least
	//      attempt reducing the number of cases.
	//      Already has to go through 12 cases.
	switch (opcode) {
	case 0x26:
		x86.prefix.segment = x86Segment.es;
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_segment(p, segs[x86Segment.es]);
		goto L_PREFIX;
	case 0x2e:
		x86.prefix.segment = x86Segment.cs;
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_segment(p, segs[x86Segment.cs]);
		goto L_PREFIX;
	case 0x36:
		x86.prefix.segment = x86Segment.ss;
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_segment(p, segs[x86Segment.ss]);
		goto L_PREFIX;
	case 0x3e:
		x86.prefix.segment = x86Segment.ds;
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_segment(p, segs[x86Segment.ds]);
		goto L_PREFIX;
	case 0xd6: // hehe
		return adbg_oops(AdbgError.illegalInstruction);
	case 0xf0:
		x86.prefix.lock = true;
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_prefix(p, "lock");
		goto L_PREFIX;
	case 0xf2:
		x86.prefix.repne = true;
		x86.prefix.lastpf = x86Prefix.repne;
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_prefix(p, "repne");
		goto L_PREFIX;
	case 0xf3:
		x86.prefix.rep = true;
		x86.prefix.lastpf = x86Prefix.rep;
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_prefix(p, "rep");
		goto L_PREFIX;
	default:
		goto L_DECODE;
	}
	
	// Opcode
L_FETCH:
	e = adbg_disasm_fetch!ubyte(p, &opcode);
	if (e) return e;

L_DECODE:
	// Going ascending to make second opcode map closer (branching)
	if (opcode < 0x40) {
		// Most used instructions these days are outside of this map.
		// So, the 2-byte escape is checked here.
		if (opcode == 0x0f) return adbg_disasm_x86_0f(p);
		
		rm  = opcode & 7;
		reg = opcode >> 3;	// no masking since OPCODE:MOD=00
		W   = opcode & 1;
		
		//TODO: Consider function to adjust reg data width
		if (p.x86.vex.W)
			p.x86.prefix.data = AdbgDisasmType.i64;
		else switch (p.platform) with (AdbgPlatform) {
		case x86_16:
			with (AdbgDisasmType)
			if (p.x86.prefix.data != i32) // 66H used
				p.x86.prefix.data = W ? i16 : i8;
			break;
		default:
			with (AdbgDisasmType)
			if (p.x86.prefix.data != i16) // 66H used
				p.x86.prefix.data = W ? i32 : i8;
			break;
		}
		
		// push/pop
		if (rm >= 0b110) {
			if (reg < 4) {
				adbg_disasm_add_mnemonic(p, W ? M_POP : M_PUSH);
				adbg_disasm_add_register(p, segs[reg]);
				return 0;
			}
			// Prefixes already taken care of
			if (p.platform == AdbgPlatform.x86_64)
				return adbg_oops(AdbgError.illegalInstruction);
			// 27h	00 100 111	daa
			// 2fh	00 101 111	das
			// 37h	00 110 111	aaa
			// 3fh	00 111 111	aas
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_register(p, mnemonic_ascii[reg & 3]);
			return 0;
		}
		
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_mnemonic(p, mnemonic_00[reg]);
		
		// immediate
		if (rm >= 0b100) {
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_register(p,
					regs[x86.prefix.data][x86Reg.eax]);
			return W ? adbg_disasm_x86_op_Iz(p) : adbg_disasm_x86_op_Ib(p);
		}
		
		// modrm
		return adbg_disasm_x86_modrm_legacy_op(p, (opcode & 2) != 0);
	}
	if (opcode < 0x50) { // >=40H, INC/DEC or REX
		if (p.platform == AdbgPlatform.x86_64) {
			x86.vex.W  = (opcode & 8) != 0;
			x86.vex.RR = (opcode & 4) != 0;
			x86.vex.X  = (opcode & 2) != 0;
			x86.vex.B  = (opcode & 1) != 0;
			goto L_FETCH;
		}
		if (p.mode >= AdbgDisasmMode.file) {
			ubyte r = opcode & 7;
			adbg_disasm_add_mnemonic(p, opcode >= 0x48 ? M_DEC : M_INC);
			adbg_disasm_add_register(p, regs[x86.prefix.data][r]);
		}
		return 0;
	}
	if (opcode < 0x60) { // >=50H, PUSH/POP
		if (p.mode >= AdbgDisasmMode.file) {
			ubyte m = opcode & 7;
			if (x86.vex.RR) m |= 0b1000;
			adbg_disasm_add_mnemonic(p, opcode < 0x58 ? M_PUSH : M_POP);
			adbg_disasm_add_register(p, regs[x86.prefix.data][m]);
		}
		return 0;
	}
	if (opcode < 0x70) { // >=60H, random crap
		switch (opcode) {
		case 0x60, 0x61:
			if (p.platform == AdbgPlatform.x86_64)
				return adbg_oops(AdbgError.illegalInstruction);
			
			if (p.mode < AdbgDisasmMode.file)
				return 0;
			
			W = opcode >= 0x60;
			if (p.x86.prefix.data == AdbgDisasmType.i16)
				mnemonic = W ? "popa" : "push";
			else
				mnemonic = W ? "popad" : "pushd";
			adbg_disasm_add_mnemonic(p, mnemonic);
			return 0;
		case 0x62:
			if (p.platform == AdbgPlatform.x86_64)
				return adbg_oops(AdbgError.illegalInstruction);
			
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(p, "bound");
			
			return adbg_disasm_x86_op_GvMa(p);
		case 0x63:
			if (p.platform == AdbgPlatform.x86_64) {
				if (p.mode >= AdbgDisasmMode.file)
					adbg_disasm_add_mnemonic(p, "movsxd");
				W = true;
			} else {
				if (p.mode >= AdbgDisasmMode.file)
					adbg_disasm_add_mnemonic(p, "arpl");
				p.x86.prefix.data = AdbgDisasmType.i16;
				W = false;
			}
			return adbg_disasm_x86_modrm_legacy_op(p, W);
		case 0x64:
			x86.prefix.segment = x86Segment.fs;
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_segment(p, segs[x86Segment.fs]);
			goto L_FETCH;
		case 0x65:
			x86.prefix.segment = x86Segment.gs;
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_segment(p, segs[x86Segment.gs]);
			goto L_FETCH;
		case 0x66: // Data, in 64-bit+AVX, controlled by REX.W (48H)
			x86.prefix.data = x86.prefix.data == AdbgDisasmType.i16 ?
				AdbgDisasmType.i32 : AdbgDisasmType.i16;
			x86.prefix.lastpf = x86Prefix.data;
			goto L_FETCH;
		case 0x67: // Address, in 64-bit+AVX, controlled by REX.XB (42H,41H)
			x86.prefix.addr = x86.prefix.addr == AdbgDisasmType.i16 ?
				AdbgDisasmType.i32 : AdbgDisasmType.i16;
			goto L_FETCH;
		case 0x68:
		
			break;
		case 0x69:
		
			break;
		case 0x6a:
		
			break;
		case 0x6b:
		
			break;
		case 0x6c:
		
			break;
		case 0x6d:
		
			break;
		case 0x6e:
		
			break;
		default:
		
			break;
		}
	}
	if (opcode < 0x80) { // >=70H, Jcc
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_mnemonic(p, mnemonic_Jcc[opcode & 15]);
		return adbg_disasm_x86_op_Jb(p);
	}
	
	//NOTE: Remainder opcode A0-A3 is real=16b,extended=32b,long=64b
	
	return adbg_oops(AdbgError.illegalInstruction);
}

private:

//
// Instruction names
// In case the compiler doesn't support string pooling
//

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

//
// Instruction tables
//

immutable const(char)*[] mnemonic_00 = [
	M_ADD, M_OR, M_ADC, M_SBB, M_AND, M_SUB, M_XOR, M_CMP
];
immutable const(char)*[] mnemonic_ascii = [
	M_DAA, M_DAS, M_AAA, M_AAS
];
immutable const(char)*[] mnemonic_Jcc = [ // Both Intel and AMD
	M_JO, M_JNO, M_JB, M_JNB, M_JZ, M_JNZ, M_JBE, M_JNBE,
	M_JS, M_JNS, M_JP, M_JNP, M_JL, M_JNL, M_JLE, M_JNLE,
];

// ANCHOR 0f: 2-byte escape
int adbg_disasm_x86_0f(adbg_disasm_t *p) {
	
	
	return 0;
}

// ANCHOR 0f 38: 3-byte escape
int adbg_disasm_x86_0f_38(adbg_disasm_t *p) {
	
	return 0;
}

// ANCHOR 0f 3a: 3-byte escape
int adbg_disasm_x86_0f_3a(adbg_disasm_t *p) {
	
	return 0;
}

//
// SECTION Definitions
//

/// Segment register (override only, not for segs)
enum x86Segment : ubyte {
	none, es, cs, ss, ds, fs, gs
}
/// x86 prefixes
enum x86Prefix : ubyte {
	data	= 0x66,	/// 0x66
	addr	= 0x67,	/// 0x67
	lock	= 0xf0,	/// 0xF0
	repne	= 0xf2,	/// 0xF2
	rep	= 0xf3,	/// 0xF3
	_66h	= data,	/// Data operand prefix
	_67h	= addr,	/// Address operand prefix
	_f2h	= repne,	/// REPNE
	_f3h	= rep,	/// REP/REPE
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
immutable const(char)*[] regs_x87_intel = [
	"st", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)"
];
immutable const(char)*[] regs_x87_nasm = [
	"st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7"
];
immutable const(char)*[] regs_x87_att = [
	"st(0)", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)"
];
immutable const(char)*[] regs_mmx = [ // mmx
	"mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7"
];
immutable const(char)*[2][] regs_addr16 = [ // modrm:rm16
	[ "bx", "si" ], [ "bx", "di" ], [ "bp", "si" ], [ "bp", "di" ],
	[ "si", null ], [ "di", null ], [ "bp", null ], [ "bx", null ],
];
immutable const(char)*[] segs = [
	null, "es", "cs", "ss", "ds", "fs", "gs"
];
/*immutable const(char)*[] regs_tmm = [
	"tmm0", "tmm1", "tmm2", "tmm3", "tmm4", "tmm5", "tmm6", "tmm7"
];*/

// !SECTION

//
// SECTION Operand handling
//

//
int adbg_disasm_x86_op_Ib(adbg_disasm_t *p) { // Immediate 8-bit
	ubyte i = void;
	int e = adbg_disasm_fetch!ubyte(p, &i);
	if (e == 0) {
		if (p.mode >= AdbgDisasmMode.file) {
//			adbg_disasm_add_machine!ubyte(p, i);
			adbg_disasm_add_immediate(p, AdbgDisasmType.i8, &i);
		}
	}
	return e;
}
//
int adbg_disasm_x86_op_Iz(adbg_disasm_t *p) { // Immediate 16/32-bit
	union u_t {
		uint i32;
		ushort i16;
	}
	u_t u = void;
	int e = void;
	
	if (p.x86.prefix.data != AdbgDisasmType.i16) { // 64/32 modes
		e = adbg_disasm_fetch!uint(p, &u.i32);
		if (e == 0) {
			if (p.mode >= AdbgDisasmMode.file) {
				adbg_disasm_add_immediate(p, AdbgDisasmType.i32, &u.i32);
			}
		}
	} else {
		e = adbg_disasm_fetch!ushort(p, &u.i16);
		if (e == 0) {
			if (p.mode >= AdbgDisasmMode.file) {
				adbg_disasm_add_immediate(p, AdbgDisasmType.i16, &u.i16);
			}
		}
	}
	
	return e;
}
// for BOUND
int adbg_disasm_x86_op_GvMa(adbg_disasm_t *p) {
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(p, &modrm);
	if (e) return e;
	
	if (modrm >= 0b11000000)
		return adbg_oops(AdbgError.illegalInstruction);
	
	const(char) *reg = void;
	const(char) *basereg;
	const(char) *indexreg;
	ubyte scale;
	adbg_disasm_number_t disp = void;
	disp.i32 = 0;
	bool scaled;
	
	adbg_disasm_x86_modrm_legacy_reg(p, &reg, modrm & 7);
	e = adbg_disasm_x86_modrm_legacy_rm(p, &basereg, &indexreg, &scale, &disp, &scaled,
		modrm >> 6, (modrm >> 3) & 7);
	if (e) return e;
	
	if (p.mode < AdbgDisasmMode.file)
		return 0;
	
	adbg_disasm_add_register(p, reg);
	adbg_disasm_add_memory(p, basereg, indexreg, &disp,
		cast(AdbgDisasmType)(p.x86.prefix.data + 1), scale, scaled);
	return 0;
}
//
int adbg_disasm_x86_op_Jb(adbg_disasm_t *p) { // Immediate 8-bit
	ubyte i = void;
	int e = adbg_disasm_fetch!ubyte(p, &i);
	if (e == 0) {
		if (p.mode >= AdbgDisasmMode.data)
			adbg_disasm_calc_offset!ubyte(p, i);
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_immediate(p, AdbgDisasmType.i8, &i);
	}
	return e;
}

// !SECTION

//
// SECTION ModR/M legacy mechanics
//

// Uses opcode to determine operation width/direction
// Mostly used by legacy opcodes <40H
int adbg_disasm_x86_modrm_legacy_op(adbg_disasm_t *p, bool dir) {
	// NOTE: Address and Data modes are already handled prior to
	//       calling this. Unless, of course, instruction dictactes
	//       otherwise (e.g. per instruction, per map, etc.)
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(p, &modrm);
	if (e) return e;
	
	return adbg_disasm_x86_modrm_legacy(p, modrm, dir);
}
int adbg_disasm_x86_modrm_legacy(adbg_disasm_t *p, ubyte modrm, bool dir) {
	ubyte mode = (modrm >> 6) & 3;
	ubyte reg = (modrm >> 3) & 7;
	ubyte rm = modrm & 7;
	
	//TODO: REX/VEX
	
	const(char) *register = void;
	//TODO: Use adbg_disasm_operand_mem_t directly at this point
	const(char) *basereg;
	const(char) *indexreg;
	ubyte scale;
	bool scaled;
	adbg_disasm_number_t disp = void;
	disp.i32 = 0;
	
	// Configure register/memory stuff
	int e = adbg_disasm_x86_modrm_legacy_rm(p, &basereg, &indexreg, &scale, &disp, &scaled, mode, rm);
	if (e) return e;
	adbg_disasm_x86_modrm_legacy_reg(p, &register, reg);
	
	if (dir) { // to registers
		adbg_disasm_add_register(p, register);
		adbg_disasm_add_memory(p, basereg, indexreg, &disp, p.x86.prefix.data, scale, scaled);
	} else {
		adbg_disasm_add_memory(p, basereg, indexreg, &disp, p.x86.prefix.data, scale, scaled);
		adbg_disasm_add_register(p, register);
	}
	
	return 0;
}
//TODO: Consider using adbg_disasm_operand_mem_t here
int adbg_disasm_x86_modrm_legacy_rm(adbg_disasm_t *p,
	const(char) **basereg, const(char) **indexreg, ubyte *scale, adbg_disasm_number_t *disp, bool *scaled,
	ubyte mode, ubyte rm) {
	
	if (p.platform != AdbgPlatform.x86_16 && rm == 0b100 && mode < 3)
		return adbg_disasm_x86_sib_legacy(p, basereg, indexreg, scale, disp, mode);
	
	//TODO: VEX.B
	if (p.x86.prefix.addr == AdbgDisasmType.i16) {
		*basereg  = regs_addr16[rm][0];
		*indexreg = regs_addr16[rm][1];
	} else {
		*basereg  = regs[p.x86.prefix.addr][rm];
	}
	
	switch (mode) {
	case 0: return 0; // no displacement
	case 1: // +u8 displacement
		disp.type = AdbgDisasmType.i8;
		return adbg_disasm_fetch!ubyte(p, &disp.u8);
	case 2: // +u16/u32 displacement
		switch (p.platform) with (AdbgPlatform) {
		case x86_16:
			disp.type = AdbgDisasmType.i16;
			return adbg_disasm_fetch!ushort(p, &disp.u16);
		default:
			disp.type = AdbgDisasmType.i32;
			return adbg_disasm_fetch!uint(p, &disp.u32);
		}
	default:
		adbg_disasm_x86_modrm_legacy_reg(p, basereg, rm);
		return 0;
	}
}
void adbg_disasm_x86_modrm_legacy_reg(adbg_disasm_t *p, const(char) **basereg, ubyte reg) {
	*basereg = regs[p.x86.prefix.data][reg];
}

int adbg_disasm_x86_sib_legacy(adbg_disasm_t *p,
	const(char) **basereg, const(char) **indexreg, ubyte *scale, adbg_disasm_number_t *disp,
	ubyte mode) {
	
	AdbgDisasmType w = p.platform == AdbgPlatform.x86_64 ?
		AdbgDisasmType.i64 : AdbgDisasmType.i32;
	
	ubyte sib = void;
	int e = adbg_disasm_fetch!ubyte(p, &sib);
	if (e) return e;
	ubyte index = (sib >> 3) & 7;
	ubyte base  = sib & 7;
	bool noscaling = index == 0b100;
	
	if (p.x86.vex.B) base  |= 0b1000;
	if (p.x86.vex.X) index |= 0b1000;
	// all cases except index=0b100
	if (noscaling == false) *scale = (sib >> 6) & 3;
	
	switch (mode) {
	case 0:
		if (base == 0b101) {
			if (noscaling == false) { // DISP32
			} else { // INDEX*SCALE+DISP32
				*indexreg = regs[w][index];
			}
			goto L_DISP32;
		} else { // 
			if (noscaling) { // BASE
				*basereg  = regs[w][base];
			} else { // BASE+INDEX*SCALE
				*basereg  = regs[w][base];
				*indexreg = regs[w][index];
			}
			return 0;
		}
	case 1:
		if (noscaling) { // BASE+DISP8
			*basereg  = regs[w][base];
		} else { // BASE+INDEX*SCALE+DISP8
			*basereg  = regs[w][base];
			*indexreg = regs[w][index];
		}
		goto L_DISP8;
	case 2:
		if (noscaling) { // BASE+DISP32
			*basereg  = regs[w][index];
		} else { // BASE+INDEX*SCALE+DISP32
			*basereg  = regs[w][base];
			*indexreg = regs[w][index];
		}
		goto L_DISP32;
	default: assert(0);
	}

L_DISP8:
	disp.type = AdbgDisasmType.i8;
	return adbg_disasm_fetch!ubyte(p, &disp.u8);
L_DISP32:
	disp.type = AdbgDisasmType.i32;
	return adbg_disasm_fetch!uint(p, &disp.u32);
}

// !SECTION

//
// SECTION ModR/M AVX mechanics
//


// !SECTION