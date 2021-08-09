/**
 * Linear 8086/x86/amd64 decoder.
 *
 * Supported extensions: MMX, Extended MMX, SSE, SSE
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.disasm.arch.x86;

import adbg.error;
import adbg.disasm.disasm;

extern (C):

// NOTE: x86-64 operation modes
//       LMA=0: Legal Mode, LMA=1: Long Mode, CS.L: long, CS.D: dword
//       modes | CS.L=0  CS.D=0  | CS.L=0  CS.D=1  | CS.L=1  CS.D=0  | CS.L=1  CS.D=1  |
//       LMA=0 | standard 16-bit | standard 32-bit | standard 16-bit | standard 32-bit |
//       LMA=1 | 16-bit compat.  | 32-bit compat.  | 64-bit          | reserved        |
// NOTE: bound/invlpga/enter/other opcodes with 2 immediates: no reversed order

//TODO: Additional processors: 8086, 80186, 80386
//      Critical for 0x0f: 8086=pop cs, 80186+=2-byte
//TODO: Check LOCK
//      ADC, ADD, AND, BTC, BTR, BTS, CMPXCHG, CMPXCHG8B, CMPXCHG16B,
//      DEC, INC, NEG, NOT, OR, SBB, SUB, XADD, XCHG, and XOR.
//TODO: Check REPE/REPZ and REPNE/REPNZ
//      CMPS, CMPSB, CMPSD, CMPSW, SCAS, SCASB, SCASD, and SCASW.
//TODO: Consider adbg_disasm_x86_add_mnemonic(adbg_disasm_t*,enum)
//      Could check prefix data with enum value

private
enum x86Group : ubyte {
	legacy,
	sse,
	vex,
	evex
}

private
struct prefixes_t { align(1):
	AdbgDisasmType data;	/// Data mode (register only)
	AdbgDisasmType addr;	/// Address mode (address register only)
	x86Segment segment;	/// segment override
	x86Prefix lastpf;	/// SSE/VEX instruction selector
	bool lock;	/// LOCK prefix
	bool rep;	/// REP/REPE prefix
	bool repne;	/// REPNE prefix
	ubyte res;
}
private
struct vex_t { align(1):
	/// Byte pos      [0]      [1]      [2]      [3]
	/// (4xH) REX   : 0100WRXB
	/// (C5H) VEX.2B: 11000101 RvvvvLpp
	/// (C4H) VEX.3B: 11000100 RXBmmmmm WvvvvLpp
	/// (8FH) XOP   : 10001111 RXBmmmmm WvvvvLpp
	/// (62H) EVEX  : 01100010 RXBR00mm Wvvvv1pp zLLbVaaa
	//    EVEX Notes:             R'              L' V'
	ubyte LL;	/// VEX.L/EVEX.LL vector length
			// 0=scalar/i128, 1=i256, 2=i512, 3=i1024 (reserved)
	ubyte pp;	/// VEX.pp opcode extension
			// 0=NONE, 1=66H, 2=F2H, 3=F3H
	ubyte vvvv;	/// VEX.vvvv register selector
			// NOTE: Limited to 3 bits in x86-32
	bool  W;	/// REX.W/VEX.W
			// Affects: Register width+size
			// 0=CS.D, 1=64-bit size
	ubyte RR;	/// REX.R/VEX.R/EVEX.RR ModRM.REG extension
			// Affects: ModRM.REG
			// 0=REG:+0, 1=REG:+0b1000, 2=, 3=
	bool  X;	/// REX.X/VEX.X
			// Affects: SIB.INDEX
	bool  B;	/// REX.B/VEX.B
			// Affects: ModRM.RM, SIB.BASE, opcode (how, again?)
	ubyte aaa;	/// EVEX.aaa
}

/// x86 internal structure
struct x86_internals_t { align(1):
	union {
		ulong[3] z;	/// 
		struct {
			prefixes_t prefix;	/// Prefix data
			vex_t vex;	/// VEX/REX computed fields
			bool hasRex;	/// Has REX prefix
			bool hasVex;	/// Has VEX prefix
			bool hasEvex;	/// Has EVEX prefix
			bool hasMvex;	/// Has MVEX prefix
		}
	}
}
static assert(x86_internals_t.sizeof == ulong.sizeof * 3);

// ANCHOR legacy map
int adbg_disasm_x86(adbg_disasm_t *p) {
	x86_internals_t x86 = void;
	x86.z[2] = x86.z[1] = x86.z[0] = 0;
	
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
	
	int pfCounter;
	const(char) *mnemonic = void;
	ubyte opcode = void;
	ubyte mode = void;	/// modrm:mode
	ubyte reg  = void;	/// modrm:reg
	ubyte rm   = void;	/// modrm:rm
	bool  W    = void;	/// W bit
	bool  D    = void;	/// D bit
	
L_PREFIX:
	if (pfCounter >= 4) // x<=4
		//TODO: Verify if illegal or skipped
		return adbg_oops(AdbgError.illegalInstruction);
	++pfCounter;
	
	int e = adbg_disasm_fetch!ubyte(p, &opcode);
	if (e) return e;
	
	// Legacy prefixes must be processed before REX/VEX/EVEX
	switch (opcode) {
	case 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65: // es:/cs:/ss:/ds:/fs:/gs:
		x86Segment seg = opcode < 0b01000000 ? // +1 since 0=none (override)
			cast(x86Segment)((opcode >> 3) - 3) :
			cast(x86Segment)(opcode - 0x63);
		x86.prefix.segment = seg;
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_segment(p, segs[seg]);
		goto L_PREFIX;
	case 0x66: // Data, in 64-bit+AVX, controlled by REX.W (48H)
		x86.prefix.data = x86.prefix.data == AdbgDisasmType.i16 ?
			AdbgDisasmType.i32 : AdbgDisasmType.i16;
		x86.prefix.lastpf = x86Prefix.data;
		goto L_PREFIX;
	case 0x67: // Address, in 64-bit+AVX, controlled by REX.XB (42H,41H)
		x86.prefix.addr = x86.prefix.addr == AdbgDisasmType.i16 ?
			AdbgDisasmType.i32 : AdbgDisasmType.i16;
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
	
L_FETCH:
	e = adbg_disasm_fetch!ubyte(p, &opcode); // fetch opcode
	if (e) return e;

	// Ascending opcodes to make second opcode map closer (branching)
L_DECODE:
	if (opcode < 0x40) { // 0H..3FH: Legacy
		// Most used instructions these days are outside of this map.
		// So, the 2-byte escape is checked here.
		if (opcode == 0x0f) return adbg_disasm_x86_0f(p);
		
		rm  = opcode & 7;
		reg = opcode >> 3;	// no masking since OPCODE:MOD=00
		W   = opcode & 1;
		
		// push/pop
		if (rm >= 0b110) {
			if (reg < 4) {
				adbg_disasm_add_mnemonic(p, W ? M_POP : M_PUSH);
				adbg_disasm_add_register(p, segs[reg]);
				return 0;
			}
			// Prefixes already taken care of, unless moved here
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
			adbg_disasm_add_mnemonic(p, mnemonic_grp1[reg]);
		
		// immediate
		if (rm >= 0b100) {
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_register(p,
					regs[x86.prefix.data][x86Reg.eax]);
			return W ? adbg_disasm_x86_op_Iz(p) : adbg_disasm_x86_op_Ib(p);
		}
		
		// modrm
		return adbg_disasm_x86_op_modrm(p, (opcode & 2) != 0, W);
	}
	if (opcode < 0x50) { // 40H..4FH: INC/DEC or REX
		if (p.platform == AdbgPlatform.x86_64) {
			//NOTE: REX cannot be used to extend VEX
			x86.vex.W  = (opcode & 8) != 0;
			x86.vex.RR = (opcode & 4) != 0;
			x86.vex.X  = (opcode & 2) != 0;
			x86.vex.B  = (opcode & 1) != 0;
			x86.hasRex = true;
			goto L_FETCH;
		}
		if (p.mode >= AdbgDisasmMode.file) {
			ubyte r = opcode & 7;
			adbg_disasm_add_mnemonic(p, opcode >= 0x48 ? M_DEC : M_INC);
			adbg_disasm_add_register(p, regs[x86.prefix.data][r]);
		}
		return 0;
	}
	if (opcode < 0x60) { // 50H..5FH: PUSH/POP
		if (p.mode >= AdbgDisasmMode.file) {
			ubyte m = opcode & 7;
			if (x86.vex.RR) m |= 0b1000;
			adbg_disasm_add_mnemonic(p, opcode < 0x58 ? M_PUSH : M_POP);
			adbg_disasm_add_register(p, regs[x86.prefix.data][m]);
		}
		return 0;
	}
	if (opcode < 0x70) { // 60H..6FH: random crap
		if (opcode < 0x62) {
			if (p.platform == AdbgPlatform.x86_64)
				return adbg_oops(AdbgError.illegalInstruction);
			
			if (p.mode < AdbgDisasmMode.file)
				return 0;
			
			bool data16 = p.x86.prefix.data == AdbgDisasmType.i16;
			if (opcode & 1)
				mnemonic = data16 ? "popa" : "popad";
			else
				mnemonic = data16 ? "pusha" : "pushad";
			adbg_disasm_add_mnemonic(p, mnemonic);
			return 0;
		}
		
		switch (opcode) {
		case 0x62:
			if (p.platform == AdbgPlatform.x86_64) //TODO: EVEX
				return adbg_oops(AdbgError.illegalInstruction);
			
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(p, "bound");
			
			return adbg_disasm_x86_op_GvMa(p);
		case 0x63:
			if (p.platform == AdbgPlatform.x86_64) {
				if (p.mode >= AdbgDisasmMode.file)
					adbg_disasm_add_mnemonic(p, "movsxd");
				D = true;
			} else {
				if (p.mode >= AdbgDisasmMode.file)
					adbg_disasm_add_mnemonic(p, "arpl");
				p.x86.prefix.data = AdbgDisasmType.i16;
				D = false;
			}
			return adbg_disasm_x86_op_modrm(p, D, false);
		case 0x6c, 0x6d, 0x6e, 0x6f:
			W = opcode & 1;
			D = (opcode & 2) != 0;
			
			if (p.mode < AdbgDisasmMode.file)
				return 0;
			
			AdbgDisasmType width = W == false ? // mem
				p.x86.prefix.data : AdbgDisasmType.i8;
			const(char) *regbase = regs[p.x86.prefix.data][x86Reg.di];
			const(char) *dx = regs[p.x86.prefix.data][x86Reg.dx];
			x86Segment seg = p.x86.prefix.segment;
			if (D) { // outs
				mnemonic = M_OUTS;
				if (seg) // default if unset
					seg = x86Segment.ds;
			} else {
				mnemonic = M_INS;
				seg = x86Segment.es;
			}
			
			adbg_disasm_add_segment(p, segs[seg]);
			adbg_disasm_add_mnemonic(p, mnemonic);
			if (D) {
				adbg_disasm_add_register(p, dx);
				adbg_disasm_add_memory(p, width, regbase, null, ADBG_TYPE_NONE, null, 0, false);
			} else {
				adbg_disasm_add_memory(p, width, regbase, null, ADBG_TYPE_NONE, null, 0, false);
				adbg_disasm_add_register(p, dx);
			}
			return 0;
		default:
			W = opcode & 1;
			D = (opcode & 2) != 0;
			
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(p, W ? M_IMUL : M_PUSH);
			
			if (W) { // imul
				e = adbg_disasm_x86_op_modrm(p, true, true);
				if (e) return e;
			}
			
			return D ^ W ? adbg_disasm_x86_op_Iz(p) : adbg_disasm_x86_op_Ib(p);
		}
	}
	if (opcode < 0x80) { // 70H..7FH: Jcc
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_mnemonic(p, mnemonic_Jcc[opcode & 15]);
		return adbg_disasm_x86_op_Jb(p);
	}
	if (opcode < 0x90) { // 80H..8FH: more random stuff
		if (opcode < 0x84) // ANCHOR Group 1
			return adbg_disasm_x86_grp1(p, opcode);
		if (opcode < 0x88) { // TEST/XCHG
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(p, opcode <= 0x86 ? M_TEST : M_XCHG);
			return adbg_disasm_x86_op_modrm(p, false, opcode & 1);
		}
		switch (opcode) {
		case 0x8c, 0x8e: // MOV Mw/Rv,Sw or MOV Sw,Ew
			e = adbg_disasm_fetch!ubyte(p, &opcode);
			if (e) return e;
			
			reg  = (opcode >> 3) & 7;
			if (reg > 5)
				return adbg_oops(AdbgError.illegalInstruction);
			
			D    = opcode == 0x8e;
			mode = opcode >> 6;
			rm   = opcode & 7;
			W    = mode == 3;
			
			adbg_disasm_operand_mem_t mem = void;
			e = adbg_disasm_x86_modrm_legacy_rm(p, &mem, mode, rm);
			if (e) return e;
			
			if (p.mode < AdbgDisasmMode.file)
				return 0;
			
			const(char) *seg = segs[reg + 1];
			adbg_disasm_add_mnemonic(p, M_MOV);
			if (D) {
				adbg_disasm_add_register(p, seg);
				if (W)
					adbg_disasm_add_register(p, mem.base);
				else with (AdbgDisasmType)
					adbg_disasm_add_memory_raw(p, i16, &mem);
			} else {
				if (W)
					adbg_disasm_add_register(p, mem.base);
				else with (AdbgDisasmType)
					adbg_disasm_add_memory_raw(p, i16, &mem);
				adbg_disasm_add_register(p, seg);
			}
			return 0;
		case 0x8d: // LEA Gv, M
			e = adbg_disasm_fetch!ubyte(p, &opcode);
			if (e) return e;
			if (opcode >= 0b11000000)
				return adbg_oops(AdbgError.illegalInstruction);
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(p, M_LEA);
			return adbg_disasm_x86_op_modrm2(p, opcode, true, true);
		case 0x8f: // ANCHOR Group 1a (includes XOP)
			return adbg_disasm_x86_grp1a(p);
		default: // 88H..8BH
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(p, M_MOV);
			return adbg_disasm_x86_op_modrm(p, (opcode & 2) != 0, opcode & 1);
		}
	}
	
	//NOTE: Remainder opcode A0-A3 is real=16b,extended=32b,long=64b
	//NOTE: F0/F2/F3/66 illegal with VEX/XOP
	
	return adbg_oops(AdbgError.notImplemented);
}

private:

//
// SECTION Opcode maps
//

// ANCHOR 0f: 2-byte escape
int adbg_disasm_x86_0f(adbg_disasm_t *p) {
	
	
	return adbg_oops(AdbgError.notImplemented);
}

// ANCHOR 0f 38: 3-byte escape
int adbg_disasm_x86_0f_38(adbg_disasm_t *p) {
	
	return adbg_oops(AdbgError.notImplemented);
}

// ANCHOR 0f 3a: 3-byte escape
int adbg_disasm_x86_0f_3a(adbg_disasm_t *p) {
	
	return adbg_oops(AdbgError.notImplemented);
}

// !SECTION

//
// SECTION Instruction names
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
immutable const(char) *M_INS	= "ins";
immutable const(char) *M_OUTS	= "outs";
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
immutable const(char) *M_TEST	= "test";
immutable const(char) *M_XCHG	= "xchg";
immutable const(char) *M_MOV	= "mov";
immutable const(char) *M_LEA	= "lea";
// SSE
// AVX

// ANCHOR Instruction tables

immutable const(char)*[] mnemonic_grp1 = [ // same for <40H
	M_ADD, M_OR, M_ADC, M_SBB, M_AND, M_SUB, M_XOR, M_CMP
];
immutable const(char)*[] mnemonic_ascii = [
	M_DAA, M_DAS, M_AAA, M_AAS
];
immutable const(char)*[] mnemonic_Jcc = [
	M_JO, M_JNO, M_JB, M_JNB, M_JZ, M_JNZ, M_JBE, M_JNBE,
	M_JS, M_JNS, M_JP, M_JNP, M_JL, M_JNL, M_JLE, M_JNLE,
];

// !SECTION

//
// SECTION Definitions
//

/// Segment register
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
//TODO: Waiting for syntax engine to support getting rid of these
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
/*immutable const(char)*[] regs_amx = [
	"tmm0", "tmm1", "tmm2", "tmm3", "tmm4", "tmm5", "tmm6", "tmm7"
];*/

// !SECTION

//
// SECTION Operand types
//

// EbGb/EvGv/GbEb/GvEv, auto modrm
// D: 0=mem, 1=reg
// W: 0=i8, 1=i16/i32 (i64 if REX.W)
int adbg_disasm_x86_op_modrm(adbg_disasm_t *p, bool D, bool W) {
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(p, &modrm);
	if (e) return e;
	
	return adbg_disasm_x86_op_modrm2(p, modrm, D, W);
}
// EbGb/EvGv/GbEb/GvEv
// D: 0=mem, 1=reg
// W: 0=i8, 1=i16/i32 (i64 if REX.W)
int adbg_disasm_x86_op_modrm2(adbg_disasm_t *p, ubyte modrm, bool D, bool W) {
	if (p.x86.vex.W)
		p.x86.prefix.data = AdbgDisasmType.i64;
	else if (W == false)
		p.x86.prefix.data = AdbgDisasmType.i8;
	
	return adbg_disasm_x86_modrm_legacy(p, modrm, D);
}
int adbg_disasm_x86_op_Ib(adbg_disasm_t *p) {	// Immediate 8-bit
	ubyte i = void;
	int e = adbg_disasm_fetch!ubyte(p, &i);
	if (e) return e;
	if (p.mode >= AdbgDisasmMode.file)
		adbg_disasm_add_immediate(p, AdbgDisasmType.i8, &i);
	return 0;
}
int adbg_disasm_x86_op_Iz(adbg_disasm_t *p) {	// Immediate 16/32-bit
	union u_t {
		uint i32;
		ushort i16;
	}
	u_t u = void;
	int e = void;
	
	if (p.x86.prefix.data != AdbgDisasmType.i16) { // 64/32 modes
		e = adbg_disasm_fetch!uint(p, &u.i32);
		if (e == 0) {
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_immediate(p, AdbgDisasmType.i32, &u.i32);
		}
	} else {
		e = adbg_disasm_fetch!ushort(p, &u.i16);
		if (e == 0) {
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_immediate(p, AdbgDisasmType.i16, &u.i16);
		}
	}
	
	return e;
}
int adbg_disasm_x86_op_GvMa(adbg_disasm_t *p) {	// BOUND
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(p, &modrm);
	if (e) return e;
	
	if (modrm >= 0b11000000)
		return adbg_oops(AdbgError.illegalInstruction);
	
	adbg_disasm_operand_mem_t mem = void;
	e = adbg_disasm_x86_modrm_legacy_rm(p, &mem, modrm >> 6, (modrm >> 3) & 7);
	if (e) return e;
	
	const(char) *reg = void;
	adbg_disasm_x86_modrm_legacy_reg(p, &reg, modrm & 7);
	
	if (p.mode < AdbgDisasmMode.file)
		return 0;
	
	adbg_disasm_add_register(p, reg);
	adbg_disasm_add_memory_raw(p, cast(AdbgDisasmType)(p.x86.prefix.data + 1), &mem);
	return 0;
}
int adbg_disasm_x86_op_Jb(adbg_disasm_t *p) {	// Immediate 8-bit
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
// SECTION Operand groups
//

int adbg_disasm_x86_grp1(adbg_disasm_t *p, ubyte opcode) {	// ANCHOR Group 1
	if (p.platform == AdbgPlatform.x86_64 && opcode == 0x82)
		return adbg_oops(AdbgError.illegalInstruction);
	
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(p, &modrm);
	if (e) return e;
	
	//TODO: Consider function to adjust reg data width
	bool W = opcode & 1;
	if (p.x86.vex.W)
		p.x86.prefix.data = AdbgDisasmType.i64;
	else if (W == false)
		p.x86.prefix.data = AdbgDisasmType.i8;
	
	ubyte mode = modrm >> 6;
	ubyte rm = modrm & 7;
	
	adbg_disasm_operand_mem_t m = void;
	e = adbg_disasm_x86_modrm_legacy_rm(p, &m, mode, rm);
	if (e) return e;
	
	if (p.mode >= AdbgDisasmMode.file) {
		adbg_disasm_add_mnemonic(p, mnemonic_grp1[(modrm >> 3) & 7]);
		if (mode == 3)
			adbg_disasm_add_register(p, m.base);
		else
			adbg_disasm_add_memory_raw(p, p.x86.prefix.data, &m);
	}
	
	return opcode != 0x81 ? adbg_disasm_x86_op_Ib(p) : adbg_disasm_x86_op_Iz(p);
}
int adbg_disasm_x86_grp1a(adbg_disasm_t *p) {	// ANCHOR Group 1a
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(p, &modrm);
	if (e) return e;
	
	ubyte reg  = (modrm >> 3) & 7;
	if (reg > 0) //TODO: MODRM:REG >=1 -> XOP
		return adbg_oops(AdbgError.notImplemented);
	
	ubyte mode = modrm >> 6;
	ubyte rm   = modrm & 7;
	
	adbg_disasm_operand_mem_t m = void;
	e = adbg_disasm_x86_modrm_legacy_rm(p, &m, mode, rm);
	if (e) return e;
	
	if (p.mode >= AdbgDisasmMode.file) {
		adbg_disasm_add_mnemonic(p, M_POP);
		if (mode == 3)
			adbg_disasm_add_register(p, m.base);
		else
			adbg_disasm_add_memory_raw(p, p.x86.prefix.data, &m);
	}
	return 0;
}
int adbg_disasm_x86_grp2(adbg_disasm_t *p, ubyte opcode) {	// ANCHOR Group 2
	
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_disasm_x86_grp3(adbg_disasm_t *p, ubyte opcode) {	// ANCHOR Group 3
	
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_disasm_x86_grp4(adbg_disasm_t *p) {	// ANCHOR Group 4
	
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_disasm_x86_grp5(adbg_disasm_t *p) {	// ANCHOR Group 5
	
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_disasm_x86_grp6(adbg_disasm_t *p) {	// ANCHOR Group 6
	
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_disasm_x86_grp7(adbg_disasm_t *p) {	// ANCHOR Group 7
	
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_disasm_x86_grp8(adbg_disasm_t *p) {	// ANCHOR Group 8
	
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_disasm_x86_grp9(adbg_disasm_t *p) {	// ANCHOR Group 9
	
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_disasm_x86_grp10(adbg_disasm_t *p) {	// ANCHOR Group 10
	
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_disasm_x86_grp11(adbg_disasm_t *p) {	// ANCHOR Group 11
	
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_disasm_x86_grp12(adbg_disasm_t *p) {	// ANCHOR Group 12
	
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_disasm_x86_grp13(adbg_disasm_t *p) {	// ANCHOR Group 13
	
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_disasm_x86_grp14(adbg_disasm_t *p) {	// ANCHOR Group 14
	
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_disasm_x86_grp15(adbg_disasm_t *p) {	// ANCHOR Group 15
	
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_disasm_x86_grp16(adbg_disasm_t *p) {	// ANCHOR Group 16
	
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_disasm_x86_grp17(adbg_disasm_t *p) {	// ANCHOR Group 17
	
	return adbg_oops(AdbgError.notImplemented);
}

// !SECTION

//
// SECTION ModR/M legacy mechanics
//

//TODO: modrm extract inline
//      either full
//        int adbg_disasm_x86_modrm_extract(adbg_disasm_t *p, ref ubyte mode, ref ubyte reg, ref ubyte rm)
//        void adbg_disasm_x86_modrm_extract(ref ubyte mode, ref ubyte reg, ref ubyte rm, ref ubyte modrm)
//      or partial
//        ubyte adbg_disasm_x86_modrm_mode(ubyte modrm)
//        ubyte adbg_disasm_x86_modrm_reg(ubyte modrm)
//        ubyte adbg_disasm_x86_modrm_rm(ubyte modrm)

int adbg_disasm_x86_modrm_legacy(adbg_disasm_t *p, ubyte modrm, bool dir) {
	ubyte mode = modrm >> 6;
	ubyte reg = (modrm >> 3) & 7;
	ubyte rm = modrm & 7;
	
	const(char) *register = void;
	adbg_disasm_operand_mem_t mem = void;
	
	// Configure register/memory stuff
	int e = adbg_disasm_x86_modrm_legacy_rm(p, &mem, mode, rm);
	if (e) return e;
	adbg_disasm_x86_modrm_legacy_reg(p, &register, reg);
	
	bool regmode = mode == 3;
	
	if (dir) { // to registers
		adbg_disasm_add_register(p, register);
		if (regmode)
			adbg_disasm_add_register(p, mem.base);
		else
			adbg_disasm_add_memory_raw(p, p.x86.prefix.data, &mem);
	} else {
		if (regmode)
			adbg_disasm_add_register(p, mem.base);
		else
			adbg_disasm_add_memory_raw(p, p.x86.prefix.data, &mem);
		adbg_disasm_add_register(p, register);
	}
	
	return 0;
}
void adbg_disasm_x86_modrm_legacy_reg(adbg_disasm_t *p, const(char) **basereg, ubyte reg) {
	version (Trace) trace("reg=%x", reg);
	immutable static const(char)*[] regs8rex = [ "spl", "bpl", "sil", "dil" ];
	if (p.x86.hasRex && p.x86.prefix.data == AdbgDisasmType.i8) {
		if (reg >= 4 && reg <= 7) {
			*basereg = regs8rex[reg - 4];
			return;
		}
	}
	*basereg = regs[p.x86.prefix.data][reg];
}
int adbg_disasm_x86_modrm_legacy_rm(adbg_disasm_t *p, adbg_disasm_operand_mem_t *mem, ubyte mode, ubyte rm) {
	version (Trace) trace("mode=%x rm=%x", mode, rm);
	
	if (p.platform != AdbgPlatform.x86_16 && rm == 0b100 && mode < 3)
		return adbg_disasm_x86_sib_legacy(p, mem, mode);
	
	mem.scaled = false;
	
	//TODO: VEX.B
	if (p.x86.prefix.addr == AdbgDisasmType.i16) {
		mem.base  = regs_addr16[rm][0];
		mem.index = regs_addr16[rm][1];
	} else {
		mem.base  = regs[p.x86.prefix.addr][rm];
		mem.index = null;
	}
	
	switch (mode) {
	case 0: // no displacement
		mem.hasOffset = false;
		return 0;
	case 1: // +u8 displacement
		mem.hasOffset = true;
		mem.offset.type = AdbgDisasmType.i8;
		return adbg_disasm_fetch!ubyte(p, &mem.offset.u8);
	case 2: // +u16/u32 displacement
		mem.hasOffset = true;
		switch (p.x86.prefix.data) with (AdbgDisasmType) {
		case i16:
			mem.offset.type = AdbgDisasmType.i16;
			return adbg_disasm_fetch!ushort(p, &mem.offset.u16);
		default:
			mem.offset.type = AdbgDisasmType.i32;
			return adbg_disasm_fetch!uint(p, &mem.offset.u32);
		}
	default:
		adbg_disasm_x86_modrm_legacy_reg(p, &mem.base, rm);
		return 0;
	}
}
int adbg_disasm_x86_sib_legacy(adbg_disasm_t *p, adbg_disasm_operand_mem_t *mem, ubyte mode) {
	ubyte sib = void;
	int e = adbg_disasm_fetch!ubyte(p, &sib);
	if (e) return e;
	
	mem.scaled = true;
	AdbgDisasmType w = AdbgDisasmType.i32;
	ubyte index = (sib >> 3) & 7;
	ubyte base  = sib & 7;
	
	bool hasScaling = index != 0b100; // + index*scale
	bool noBase     = base  == 0b101; // no base
	
	if (p.x86.vex.B) base  |= 0b1000;
	if (p.x86.vex.X) index |= 0b1000;
	
	if (hasScaling) {
		mem.scale = 1 << (sib >> 6);
		mem.index = regs[w][index];
		mem.base  = regs[w][base];
	} else {
		mem.scale = 0;
		mem.index = null;
		mem.base  = noBase ? null : regs[w][base];
	}
	
	switch (mode) {
	case 0:
		if (noBase == false) {
			mem.hasOffset = false;
			return 0;
		}
		goto case 2;
	case 1: 
		mem.hasOffset = true;
		mem.offset.type = AdbgDisasmType.i8;
		return adbg_disasm_fetch!ubyte(p, &mem.offset.u8);
	case 2:
		mem.hasOffset = true;
		mem.offset.type = AdbgDisasmType.i32;
		return adbg_disasm_fetch!uint(p, &mem.offset.u32);
	default: assert(0);
	}
}

// !SECTION

//
// SECTION ModR/M AVX mechanics
//


// !SECTION