/**
 * Linear 8086/x86/amd64 decoder.
 *
 * Supported extensions: MMX, Extended MMX, SSE, SSE
 *
 * Version: 4
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
//       https://ftp.gnu.org/old-gnu/Manuals/gas-2.9.1/html_chapter/as_16.html
// NOTE: F0/F2/F3/66 illegal with VEX/XOP

//TODO: Additional processors: 8086, 80186, 80386, Intel64, AMD64
//      Critical for 0x0f: 8086=pop cs, 80186+=2-byte
//      And something else with MOVXSD
//TODO: Check LOCK
//      ADC, ADD, AND, BTC, BTR, BTS, CMPXCHG, CMPXCHG8B, CMPXCHG16B,
//      DEC, INC, NEG, NOT, OR, SBB, SUB, XADD, XCHG, and XOR.
//      only check if hasLock
//TODO: Check REPE/REPZ and REPNE/REPNZ
//      CMPS, CMPSB, CMPSD, CMPSW, SCAS, SCASB, SCASD, and SCASW.
//      only check if hasRepe/hasRepne
//TODO: Consider adbg_disasm_x86_add_mnemonic(adbg_disasm_t*,enum)
//      Could check prefix data (rep/repne/repnz/lock/etc.) with enum value

private
enum x86Group : ubyte {
	legacy,
	sse,
	vex,
	evex
}

/// x86 internal structure
struct x86_internals_t { align(1):
	union {
		ulong[3] z;	/// 
		struct {
			AdbgDisasmType pfData;	/// Data mode (register only)
			AdbgDisasmType pfAddr;	/// Address mode (address register only)
			x86Seg pfSegment;	/// segment override
			x86Prefix pfSelect;	/// SSE/VEX instruction selector
			bool pfLock;	/// LOCK prefix
			bool pfRep;	/// REP/REPE prefix
			bool pfRepne;	/// REPNE prefix
			ubyte pfRes;	/// 
			/// Byte pos      [0]      [1]      [2]      [3]
			/// (4xH) REX   : 0100WRXB
			/// (C5H) VEX.2B: 11000101 RvvvvLpp
			/// (C4H) VEX.3B: 11000100 RXBmmmmm WvvvvLpp
			/// (8FH) XOP   : 10001111 RXBmmmmm WvvvvLpp
			/// (62H) EVEX  : 01100010 RXBR00mm Wvvvv1pp zLLbVaaa
			//    EVEX Notes:             R'              L' V'
			ubyte vexLL;	/// VEX.L/EVEX.LL vector length
					// 0=scalar/i128, 1=i256, 2=i512, 3=i1024 (reserved)
			ubyte vexpp;	/// VEX.pp opcode extension
					// 0=NONE, 1=66H, 2=F2H, 3=F3H
			ubyte vexvvvv;	/// VEX.vvvv register selector
					// NOTE: Limited to 3 bits in x86-32
			bool  vexW;	/// REX.W/VEX.W
					// Affects: Register width+size
					// 0=CS.D, 1=64-bit size
			ubyte vexRR;	/// REX.R/VEX.R/EVEX.RR ModRM.REG extension
					// Affects: ModRM.REG
					// 0=REG:+0, 1=REG:+0b1000, 2=, 3=
			bool  vexX;	/// REX.X/VEX.X
					// Affects: SIB.INDEX
			bool  vexB;	/// REX.B/VEX.B
					// Affects: ModRM.RM, SIB.BASE, opcode (how, again?)
			ubyte vexaaa;	/// EVEX.aaa
			bool hasRex;	/// Has REX prefix
			bool hasVex;	/// Has VEX prefix
			bool hasEvex;	/// Has EVEX prefix
			bool hasMvex;	/// Has MVEX prefix
			bool[4] res;	/// 
		}
	}
}
static assert(x86_internals_t.sizeof == ulong.sizeof * 3);

// ANCHOR legacy map
int adbg_disasm_x86(adbg_disasm_t *p) {
	x86_internals_t x86 = void;
	x86.z[2] = x86.z[1] = x86.z[0] = 0;
	
	switch (p.platform) with (AdbgPlatform) {
	case x86_64:
		x86.pfAddr = AdbgDisasmType.i64;
		x86.pfData = AdbgDisasmType.i32;
		break;
	case x86_32:
		x86.pfAddr = AdbgDisasmType.i32;
		x86.pfData = AdbgDisasmType.i32;
		break;
	default:
		x86.pfAddr = AdbgDisasmType.i16;
		x86.pfData = AdbgDisasmType.i16;
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
	if (pfCounter > 4) // x<=4
		//TODO: Verify if illegal or skipped
		return adbg_oops(AdbgError.illegalInstruction);
	
	int e = adbg_disasm_fetch!ubyte(p, &opcode, AdbgDisasmTag.prefix);
	if (e) return e;
	
	// Legacy prefixes must be processed before REX/VEX/EVEX
	switch (opcode) {
	// Group 2
	case 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65: // es/cs/ss/ds/fs/gs
		++pfCounter;
		x86Seg seg = opcode < 0b01000000 ? // +1 since 0=none (override)
			cast(x86Seg)((opcode >> 3) - 3) :
			cast(x86Seg)(opcode - 0x5f);
		x86.pfSegment = seg;
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_segment(p, segs[seg]);
		goto L_PREFIX;
	// Group 3
	case 0x66: // Data, in 64-bit+AVX, controlled by REX.W (48H)
		++pfCounter;
		x86.pfData = p.platform == AdbgPlatform.x86_16 ?
			AdbgDisasmType.i32 : AdbgDisasmType.i16;
		x86.pfSelect = x86Prefix.h66;
		goto L_PREFIX;
	// Group 4
	case 0x67: // Address, in 64-bit+AVX, controlled by REX.XB (42H,41H)
		++pfCounter;
		switch (p.platform) with (AdbgPlatform) {
		case x86_64: x86.pfAddr = AdbgDisasmType.i32; break;
		case x86_32: x86.pfAddr = AdbgDisasmType.i16; break;
		default:     x86.pfAddr = AdbgDisasmType.i32; break;
		}
		goto L_PREFIX;
	// Group 1
	case 0xf0:
		++pfCounter;
		x86.pfLock = true;
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_prefix(p, "lock");
		goto L_PREFIX;
	case 0xf2:
		++pfCounter;
		x86.pfRepne = true;
		x86.pfSelect = x86Prefix.repne;
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_prefix(p, "repne");
		goto L_PREFIX;
	case 0xf3:
		++pfCounter;
		x86.pfRep = true;
		x86.pfSelect = x86Prefix.rep;
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_prefix(p, "rep");
		goto L_PREFIX;
	default:
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_fetch_lasttag(p, AdbgDisasmTag.opcode);
	}
	
	// Ascending opcodes to make second opcode map closer (branching)
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
				adbg_disasm_add_register(p, M_ASCII[reg & 3]);
			return 0;
		}
		
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_mnemonic(p, M_GRP1[reg]);
		
		// immediate
		if (rm >= 0b100) {
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_register(p,
					regs[x86.pfData][x86Reg.eax]);
			return W ? adbg_disasm_x86_op_Iz(p) : adbg_disasm_x86_op_Ib(p);
		}
		
		// modrm
		return adbg_disasm_x86_op_modrm(p, (opcode & 2) != 0, W);
	}
	if (opcode < 0x50) { // 40H..4FH: INC/DEC or REX
		if (p.platform == AdbgPlatform.x86_64) {
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_fetch_lasttag(p, AdbgDisasmTag.rex);
			//NOTE: REX cannot be used to extend VEX
			x86.vexW   = (opcode & 8) != 0;
			x86.vexRR  = (opcode & 4) != 0;
			x86.vexX   = (opcode & 2) != 0;
			x86.vexB   = (opcode & 1) != 0;
			x86.hasRex = true;
			if (x86.vexW)
				x86.pfData = AdbgDisasmType.i64;
			goto L_PREFIX;
		}
		if (p.mode >= AdbgDisasmMode.file) {
			ubyte r = opcode & 7;
			adbg_disasm_add_mnemonic(p, opcode >= 0x48 ? M_DEC : M_INC);
			adbg_disasm_add_register(p, regs[x86.pfData][r]);
		}
		return 0;
	}
	if (opcode < 0x60) { // 50H..5FH: PUSH/POP
		if (p.mode >= AdbgDisasmMode.file) {
			ubyte m = opcode & 7;
			if (x86.vexRR) m |= 0b1000;
			adbg_disasm_add_mnemonic(p, opcode < 0x58 ? M_PUSH : M_POP);
			adbg_disasm_add_register(p, regs[x86.pfData][m]);
		}
		return 0;
	}
	if (opcode < 0x70) { // 60H..6FH: random crap
		if (opcode < 0x62) {
			if (p.platform == AdbgPlatform.x86_64)
				return adbg_oops(AdbgError.illegalInstruction);
			
			if (p.mode < AdbgDisasmMode.file)
				return 0;
			
			bool data16 = p.x86.pfData == AdbgDisasmType.i16;
			if (opcode & 1)
				mnemonic = data16 ? "popa" : "popad";
			else
				mnemonic = data16 ? "pusha" : "pushad";
			adbg_disasm_add_mnemonic(p, mnemonic);
			return 0;
		}
		if (opcode >= 0x6c) { // INS
			W = opcode & 1;
			D = (opcode & 2) != 0;
			
			if (p.mode < AdbgDisasmMode.file)
				return 0;
			
			AdbgDisasmType mw = W ? p.x86.pfData : AdbgDisasmType.i8;
			const(char) *regbase = regs[p.x86.pfAddr][x86Reg.di];
			const(char) *dx = regs[p.x86.pfData][x86Reg.dx];
			x86Seg seg = p.x86.pfSegment;
			if (D) { // outs
				mnemonic = M_OUTS;
				if (seg) // default if unset
					seg = x86Seg.ds;
			} else {
				mnemonic = M_INS;
				seg = x86Seg.es;
			}
			adbg_disasm_add_mnemonic(p, mnemonic);
			adbg_disasm_operand_mem_t mem = void;
			adbg_disasm_set_mem(&mem, segs[seg], regbase, null, AdbgDisasmType.none, null, 0, false);
			if (D) {
				adbg_disasm_add_register(p, dx);
				adbg_disasm_add_memory2(p, mw, &mem);
			} else {
				adbg_disasm_add_memory2(p, mw, &mem);
				adbg_disasm_add_register(p, dx);
			}
			return 0;
		}
		
		switch (opcode) {
		case 0x62:
			if (p.platform == AdbgPlatform.x86_64) //TODO: EVEX
				return adbg_oops(AdbgError.illegalInstruction);
			
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(p, "bound");
			
			return adbg_disasm_x86_op_GvMa(p);
		case 0x63: // ARPL/MOVSXD
			if (p.platform == AdbgPlatform.x86_64) {
				if (p.mode >= AdbgDisasmMode.file)
					adbg_disasm_add_mnemonic(p, "movsxd");
				D = true;
			} else {
				if (p.mode >= AdbgDisasmMode.file)
					adbg_disasm_add_mnemonic(p, "arpl");
				p.x86.pfData = AdbgDisasmType.i16;
				D = false;
			}
			return adbg_disasm_x86_op_modrm(p, D, false);
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
			adbg_disasm_add_mnemonic(p, M_Jcc[opcode & 15]);
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
			e = adbg_disasm_fetch!ubyte(p, &opcode, AdbgDisasmTag.modrm);
			if (e) return e;
			
			reg  = (opcode >> 3) & 7;
			if (reg > 5)
				return adbg_oops(AdbgError.illegalInstruction);
			
			D    = opcode == 0x8e;
			mode = opcode >> 6;
			rm   = opcode & 7;
			W    = mode == 3;
			
			adbg_disasm_operand_mem_t mem = void;
			e = adbg_disasm_x86_modrm_rm(p, &mem, mode, rm);
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
					adbg_disasm_add_memory2(p, i16, &mem);
			} else {
				if (W)
					adbg_disasm_add_register(p, mem.base);
				else with (AdbgDisasmType)
					adbg_disasm_add_memory2(p, i16, &mem);
				adbg_disasm_add_register(p, seg);
			}
			return 0;
		case 0x8d: // LEA Gv, M
			e = adbg_disasm_fetch!ubyte(p, &opcode, AdbgDisasmTag.modrm);
			if (e) return e;
			if (opcode >= 0b11000000)
				return adbg_oops(AdbgError.illegalInstruction);
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(p, M_LEA);
			return adbg_disasm_x86_op_modrm2(p, opcode, true, true);
		case 0x8f: // ANCHOR Group 1a (includes XOP)
			return adbg_disasm_x86_grp1a(p);
		default: // 88H..8BH: MOV EbGb/EvGv/GbEb/GvEv
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(p, M_MOV);
			return adbg_disasm_x86_op_modrm(p, (opcode & 2) != 0, opcode & 1);
		}
	}
	if (opcode < 0xa0) { // 90H..9FH: XCHG or random stuff
		if (opcode < 0x98) { // XCHG
			if (p.mode < AdbgDisasmMode.file)
				return 0;
			if (opcode == 0x90) {
				adbg_disasm_add_mnemonic(p, x86.pfRep ? M_PAUSE : M_NOP);
				return 0;
			}
			adbg_disasm_add_mnemonic(p, M_XCHG);
			adbg_disasm_add_register(p, regs[x86.pfData][opcode & 7]);
			adbg_disasm_add_register(p, regs[x86.pfData][x86Reg.al]);
			return 0;
		}
		switch (opcode) {
		case 0x98, 0x99:
			if (p.mode < AdbgDisasmMode.file)
				return 0;
			W = opcode == 0x99;
			switch (x86.pfData) with (AdbgDisasmType) {
			case i64: mnemonic = W ? M_CQO : M_CDQE; break;
			case i32: mnemonic = W ? M_CDQ : M_CWDE; break;
			default:  mnemonic = W ? M_CWD : M_CBW; break;
			}
			adbg_disasm_add_mnemonic(p, mnemonic);
			return 0;
		case 0x9a:
			if (p.platform == AdbgPlatform.x86_64)
				return adbg_oops(AdbgError.illegalInstruction);
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(p, M_CALL);
			return adbg_disasm_x86_op_Ap(p);
		case 0x9b:
			if (p.mode < AdbgDisasmMode.file)
				return 0;
			adbg_disasm_add_mnemonic(p, M_WAIT);
			return 0;
		case 0x9c, 0x9d: // PUSH/POP Fv
			if (p.mode < AdbgDisasmMode.file)
				return 0;
			W = opcode == 0x9d;
			switch (p.platform) with (AdbgPlatform) {
			case x86_64: mnemonic = W ? M_POPFQ : M_PUSHFQ; break;
			case x86_32: mnemonic = W ? M_POPFD : M_PUSHFD; break;
			default:     mnemonic = W ? M_POPF  : M_PUSHF; break;
			}
			adbg_disasm_add_mnemonic(p, mnemonic);
			return 0;
		default:
			if (p.mode < AdbgDisasmMode.file)
				return 0;
			adbg_disasm_add_mnemonic(p, opcode == 0x9f ? M_LAHF : M_SAHF);
			return 0;
		}
	}
	if (opcode < 0xb0) { // A0H..AFH: MOV/MOVS/CMPS/TEST/STOS/LODS/SCAS
		D = (opcode & 2) != 0;
		W = opcode & 1;
		AdbgDisasmType dwidth = W ? x86.pfData : AdbgDisasmType.i8;
		adbg_disasm_operand_mem_t X = void; // ES:DI
		adbg_disasm_operand_mem_t Y = void; // DS:SI
		
		if (opcode < 0xa4) { // A0..A3H: MOV
			union ut {
				ulong  u64;
				uint   u32;
				ushort u16;
			} ut u = void;
			
			switch (x86.pfAddr) with (AdbgDisasmType) {
			case i16:
				e = adbg_disasm_fetch!ushort(p, &u.u16, AdbgDisasmTag.disp);
				break;
			case i32:
				e = adbg_disasm_fetch!uint(p, &u.u32, AdbgDisasmTag.disp);
				break;
			default:
				e = adbg_disasm_fetch!ulong(p, &u.u64, AdbgDisasmTag.disp);
				break;
			}
			
			if (e) return e;
			
			if (p.mode < AdbgDisasmMode.file)
				return 0;
			
			if (x86.pfSegment == 0)
				x86.pfSegment = x86Seg.ds;
			
			mnemonic = regs[dwidth][x86Reg.al]; // al/ax/eax
			adbg_disasm_operand_mem_t O = void;
			adbg_disasm_set_mem(&O, segs[x86.pfSegment], null, null, x86.pfAddr, &u.u64, 0, false);
			
			adbg_disasm_add_mnemonic(p, M_MOV);
			if (D) {
				adbg_disasm_add_memory2(p, dwidth, &O);
				adbg_disasm_add_register(p, mnemonic);
			} else {
				adbg_disasm_add_register(p, mnemonic);
				adbg_disasm_add_memory2(p, dwidth, &O);
			}
			return 0;
		}
		if (opcode < 0xa8) { // A4H..A7H: MOVS/CMPS
			if (p.mode < AdbgDisasmMode.file)
				return 0;
			
			if (x86.pfSegment == 0)
				x86.pfSegment = x86Seg.ds;
			
			adbg_disasm_add_mnemonic(p, opcode < 0xa6 ? M_MOVS : M_CMPS);
			adbg_disasm_set_mem(&X, segs[x86Seg.es], regs[x86.pfAddr][x86Reg.di], null, AdbgDisasmType.none, null, 0, false);
			adbg_disasm_set_mem(&Y, segs[x86.pfSegment], regs[x86.pfAddr][x86Reg.si], null, AdbgDisasmType.none, null, 0, false);
			if (D) {
				adbg_disasm_add_memory2(p, dwidth, &Y);
				adbg_disasm_add_memory2(p, dwidth, &X);
			} else {
				adbg_disasm_add_memory2(p, dwidth, &X);
				adbg_disasm_add_memory2(p, dwidth, &Y);
			}
			return 0;
		}
		if (opcode < 0xaa) { // A8H..A9H: TEST
			if (p.mode >= AdbgDisasmMode.file) {
				adbg_disasm_add_mnemonic(p, M_TEST);
				adbg_disasm_add_register(p, regs[dwidth][x86Reg.al]);
			}
			if (W)
				adbg_disasm_x86_op_Iz(p);
			else
				adbg_disasm_x86_op_Ib(p);
			return 0;
		}
		// AAH..AFH: STOS/LODS/SCAS
		if (p.mode < AdbgDisasmMode.file)
			return 0;
		
		opcode = cast(ubyte)((opcode >> 1) - 0x55);
		adbg_disasm_add_mnemonic(p, M_STR1[opcode]);
		mnemonic = regs[dwidth][x86Reg.al];
		
		if (D) {
			adbg_disasm_set_mem(&Y, null, regs[x86.pfAddr][x86Reg.di], null, AdbgDisasmType.none, null, 0, false);
		} else {
			adbg_disasm_set_mem(&X, segs[x86.pfSegment], regs[x86.pfAddr][x86Reg.si], null, AdbgDisasmType.none, null, 0, false);
		}
		switch (opcode) {
		case 0:
			adbg_disasm_add_memory2(p, dwidth, &Y);
			adbg_disasm_add_register(p, mnemonic);
			return 0;
		case 1:
			adbg_disasm_add_register(p, mnemonic);
			adbg_disasm_add_memory2(p, dwidth, &X);
			return 0;
		default:
			adbg_disasm_add_register(p, mnemonic);
			adbg_disasm_add_memory2(p, dwidth, &Y);
			return 0;
		}
	}
	if (opcode < 0xc0) { // B0H..BFH: MOV reg, Ib/Iz
		W = opcode >= 0xb8;
		if (p.mode >= AdbgDisasmMode.file) {
			opcode &= 7;
			if (x86.vexB) opcode |= 0b1000;
			AdbgDisasmType dw = W ? x86.pfData : AdbgDisasmType.i8;
			adbg_disasm_add_mnemonic(p, M_MOV);
			adbg_disasm_add_register(p, regs[dw][opcode]);
		}
		return W ? adbg_disasm_x86_op_Iz(p) : adbg_disasm_x86_op_Ib(p);
	}
	if (opcode < 0xd0) { // C0H..CFH: GRP2/RET/LES/LDS/GRP11/ENTER/LEAVE/INT
		ushort Iw = void;
		switch (opcode) {
		case 0xc4: // LES / VEX 2B
			if (p.platform == AdbgPlatform.x86_64) {
				//return adbg_disasm_x86_0f(p);
				return adbg_oops(AdbgError.notImplemented);
			}
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(p, M_LES);
			return adbg_disasm_x86_op_GzMp(p);
		case 0xc5: // LDS / VEX 3B
			if (p.platform == AdbgPlatform.x86_64) {
				return adbg_oops(AdbgError.notImplemented);
			}
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(p, M_LDS);
			return adbg_disasm_x86_op_GzMp(p);
		case 0xc2: // RET imm16
			e = adbg_disasm_fetch!ushort(p, &Iw, AdbgDisasmTag.immediate);
			if (e) return e;
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_immediate(p, AdbgDisasmType.i16, &Iw);
			goto case;
		case 0xc3: // RET
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(p, M_RET);
			return 0;
		case 0xc8: // ENTER
			e = adbg_disasm_fetch!ushort(p, &Iw, AdbgDisasmTag.immediate);
			if (e) return e;
			e = adbg_disasm_fetch!ubyte(p, &opcode, AdbgDisasmTag.immediate);
			if (e) return e;
			if (p.mode >= AdbgDisasmMode.file) {
				p.decoderNoReverse = true;
				adbg_disasm_add_mnemonic(p, M_ENTER);
				adbg_disasm_add_immediate(p, AdbgDisasmType.i16, &Iw);
				adbg_disasm_add_immediate(p, AdbgDisasmType.i8, &opcode);
			}
			return 0;
		case 0xc9: // LEAVE
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(p, M_LEAVE);
			return 0;
		case 0xca: // far RET Iw
			e = adbg_disasm_fetch!ushort(p, &Iw, AdbgDisasmTag.immediate);
			if (e) return e;
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_immediate(p, AdbgDisasmType.i16, &Iw);
			goto case;
		case 0xcb: // far RET
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(p, M_RETF);
			return 0;
		case 0xcc: // int3
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(p, M_INT3);
			return 0;
		case 0xcd: // int imm8
			e = adbg_disasm_fetch!ubyte(p, &opcode, AdbgDisasmTag.immediate);
			if (e) return e;
			if (p.mode >= AdbgDisasmMode.file) {
				adbg_disasm_add_mnemonic(p, M_INT);
				adbg_disasm_add_immediate(p, AdbgDisasmType.i16, &opcode);
			}
			return 0;
		case 0xce: // into
			if (p.platform == AdbgPlatform.x86_64)
				return adbg_oops(AdbgError.illegalInstruction);
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(p, M_INTO);
			return 0;
		case 0xcf: // iret/d/q
			if (p.mode < AdbgDisasmMode.file)
				return 0;
			switch (x86.pfData) with (AdbgDisasmType) {
			case i64: mnemonic = M_IRETQ; break;
			case i32: mnemonic = M_IRETD; break;
			default:  mnemonic = M_IRET; break;
			}
			adbg_disasm_add_mnemonic(p, mnemonic);
			return 0;
		case 0xc0, 0xc1:
			return adbg_disasm_x86_grp2(p, opcode);
		default: // C6H..C7H
			return adbg_disasm_x86_grp11(p, opcode);
		}
	}
	if (opcode < 0xe0) { // D0H..DFH: GRP2/AAM/AAD/XLAT/ESCAPE
		if (opcode < 0xd4)
			return adbg_disasm_x86_grp2(p, opcode);
		switch (opcode) {
		case 0xd4, 0xd5:
			if (p.platform == AdbgPlatform.x86_64)
				return adbg_oops(AdbgError.illegalInstruction);
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(p, opcode == 0xd4 ? M_AAM : M_AAD);
			return adbg_disasm_x86_op_Ib(p);
		case 0xd6:
			return adbg_oops(AdbgError.illegalInstruction);
		case 0xd7:
			if (p.mode < AdbgDisasmMode.file)
				return 0;
			if (x86.pfSegment == 0)
				x86.pfSegment = x86Seg.ds;
			adbg_disasm_add_mnemonic(p, M_XLAT);
			adbg_disasm_add_memory(p, AdbgDisasmType.i8, segs[x86.pfSegment],
				regs[x86.pfAddr][x86Reg.bx], null, AdbgDisasmType.none, null, 0, false);
			return 0;
		default:
			return adbg_disasm_x86_escape(p, opcode);
		}
	}
	if (opcode < 0xf0) { // E0H..EFH: LOOP/IN/OUT/CALL/JrCXZ
		if (opcode < 0xe4) { // LOOP/JCXZ
			if (p.mode >= AdbgDisasmMode.file) {
				switch (opcode) {
				case 0xf0: mnemonic = M_LOOPNE; break;
				case 0xf1: mnemonic = M_LOOPE; break;
				case 0xf2: mnemonic = M_LOOP; break;
				default:
					switch (p.platform) with (AdbgPlatform) {
					case x86_16: mnemonic = M_JCXZ; break;
					case x86_32: mnemonic = M_JECXZ; break;
					default:     mnemonic = M_JRCXZ; break;
					}
				}
				adbg_disasm_add_mnemonic(p, mnemonic);
			}
			return adbg_disasm_x86_op_Jb(p);
		}
		bool S = opcode >= 0xec;
		if (opcode < 0xe8 || S) { // IN/OUT
			ubyte imm8 = void;
			if (S == false) {
				e = adbg_disasm_fetch!ubyte(p, &imm8, AdbgDisasmTag.immediate);
				if (e) return e;
			}
			
			W = opcode & 1;
			D = (opcode & 2) != 0;
			
			if (p.mode < AdbgDisasmMode.file)
				return 0;
			
			// Unaffected by REX
			if (p.x86.pfData == AdbgDisasmType.i64)
				p.x86.pfData = AdbgDisasmType.i32;
			mnemonic = W ? regs[p.x86.pfData][x86Reg.ax] :
				regs[AdbgDisasmType.i8][x86Reg.ax];
			
			adbg_disasm_add_mnemonic(p, D ? M_OUT : M_IN);
			if (S) {
				if (D) {
					adbg_disasm_add_register(p, regs[AdbgDisasmType.i16][x86Reg.dx]);
					adbg_disasm_add_register(p, mnemonic);
				} else {
					adbg_disasm_add_register(p, mnemonic);
					adbg_disasm_add_register(p, regs[AdbgDisasmType.i16][x86Reg.dx]);
				}
			} else {
				if (D) {
					adbg_disasm_add_immediate(p, AdbgDisasmType.i8, &imm8);
					adbg_disasm_add_register(p, mnemonic);
				} else {
					adbg_disasm_add_register(p, mnemonic);
					adbg_disasm_add_immediate(p, AdbgDisasmType.i8, &imm8);
				}
			}
			return 0;
		}
		// CALL/JMP
		switch (opcode) {
		case 0xe8:
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(p, M_CALL);
			return adbg_disasm_x86_op_Jz(p);
		case 0xe9:
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(p, M_JMP);
			return adbg_disasm_x86_op_Jz(p);
		case 0xea:
			if (p.platform == AdbgPlatform.x86_64)
				return adbg_oops(AdbgError.illegalInstruction);
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(p, M_JMP);
			return adbg_disasm_x86_op_Ap(p);
		default: // EBH
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(p, M_JMP);
			return adbg_disasm_x86_op_Jb(p);
		}
	}
	// F1H..FFH: 
	switch (opcode) {
	case 0xff: // grp5
		return adbg_disasm_x86_grp5(p);
	case 0xfe: // grp4
		return adbg_disasm_x86_grp4(p);
	case 0xf6,0xf7: // grp3
		return adbg_disasm_x86_grp3(p, opcode);
	default:
		if (p.mode < AdbgDisasmMode.file)
			return 0;
		if (opcode >= 0xf8)
			mnemonic = M_F8[opcode - 0xf8];
		else if (opcode >= 0xf4)
			mnemonic = opcode == 0xf4 ? M_HLT : M_CMC;
		else
			mnemonic = M_INT1;
		adbg_disasm_add_mnemonic(p, mnemonic);
		return 0;
	}
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
// SECTION Instruction mnemonics
// In case the compiler doesn't support string pooling
//

// ANCHOR Legacy
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
immutable const(char) *M_NOP	= "nop";
immutable const(char) *M_XCHG	= "xchg";
immutable const(char) *M_PAUSE	= "pause";
immutable const(char) *M_MOV	= "mov";
immutable const(char) *M_LEA	= "lea";
immutable const(char) *M_CQO	= "cqo";
immutable const(char) *M_CDQE	= "cdqe";
immutable const(char) *M_CDQ	= "cdq";
immutable const(char) *M_CWDE	= "cwde";
immutable const(char) *M_CWD	= "cwd";
immutable const(char) *M_CBW	= "cbw";
immutable const(char) *M_WAIT	= "wait";
immutable const(char) *M_CALL	= "call";
immutable const(char) *M_POPFQ	= "popfq";
immutable const(char) *M_PUSHFQ	= "pushfq";
immutable const(char) *M_POPFD	= "popfd";
immutable const(char) *M_PUSHFD	= "pushfd";
immutable const(char) *M_POPF	= "popf";
immutable const(char) *M_PUSHF	= "pushf";
immutable const(char) *M_SAHF	= "sahf";
immutable const(char) *M_LAHF	= "lahf";
immutable const(char) *M_MOVS	= "movs";
immutable const(char) *M_CMPS	= "cmps";
immutable const(char) *M_STOS	= "stos";
immutable const(char) *M_LODS	= "lods";
immutable const(char) *M_SCAS	= "scas";
immutable const(char) *M_ROL	= "rol";
immutable const(char) *M_ROR	= "ror";
immutable const(char) *M_RCL	= "rcl";
immutable const(char) *M_RCR	= "rcr";
immutable const(char) *M_SHL	= "shl";
immutable const(char) *M_SHR	= "shr";
immutable const(char) *M_SAR	= "sar";
immutable const(char) *M_LES	= "les";
immutable const(char) *M_LDS	= "lds";
immutable const(char) *M_RET	= "ret";
immutable const(char) *M_RETF	= "retf";
immutable const(char) *M_ENTER	= "enter";
immutable const(char) *M_LEAVE	= "leave";
immutable const(char) *M_INT	= "int";
immutable const(char) *M_INT3	= "int3";
immutable const(char) *M_INTO	= "into";
immutable const(char) *M_IRET	= "iret";
immutable const(char) *M_IRETD	= "iretd";
immutable const(char) *M_IRETQ	= "iretq";
immutable const(char) *M_XABORT	= "xabort";
immutable const(char) *M_XBEGIN	= "xbegin";
immutable const(char) *M_AAM	= "aam";
immutable const(char) *M_AAD	= "aad";
immutable const(char) *M_XLAT	= "xlat";
immutable const(char) *M_LOOPNE	= "loopne";
immutable const(char) *M_LOOPE	= "loope";
immutable const(char) *M_LOOP	= "loop";
immutable const(char) *M_JCXZ	= "jcxz";
immutable const(char) *M_JECXZ	= "jecxz";
immutable const(char) *M_JRCXZ	= "jrcxz";
immutable const(char) *M_IN	= "in";
immutable const(char) *M_OUT	= "out";
immutable const(char) *M_JMP	= "jmp";
immutable const(char) *M_INT1	= "int1";
immutable const(char) *M_HLT	= "hlt";
immutable const(char) *M_CMC	= "cmc";
immutable const(char) *M_CLC	= "clc";
immutable const(char) *M_STC	= "stc";
immutable const(char) *M_CLI	= "cli";
immutable const(char) *M_STI	= "sti";
immutable const(char) *M_CLD	= "cld";
immutable const(char) *M_STD	= "std";
immutable const(char) *M_NOT	= "not";
immutable const(char) *M_NEG	= "neg";
immutable const(char) *M_MUL	= "mul";
immutable const(char) *M_DIV	= "div";
immutable const(char) *M_IDIV	= "idiv";
// ANCHOR ESCAPE D8H
immutable const(char) *M_FADD	= "fadd";
immutable const(char) *M_FMUL	= "fmul";
immutable const(char) *M_FCOM	= "fcom";
immutable const(char) *M_FCOMP	= "fcomp";
immutable const(char) *M_FSUB	= "fsub";
immutable const(char) *M_FSUBR	= "fsubr";
immutable const(char) *M_FDIV	= "fdiv";
immutable const(char) *M_FDIVR	= "fdivr";
// ANCHOR ESCAPE D9H
immutable const(char) *M_FLD	= "fld";
immutable const(char) *M_FST	= "fst";
immutable const(char) *M_FSTP	= "fstp";
immutable const(char) *M_FLDENV	= "fldenv";
immutable const(char) *M_FLDCW	= "fldcw";
immutable const(char) *M_FSTENV	= "fstenv";
immutable const(char) *M_FSTCW	= "fstcw";
immutable const(char) *M_FXCH	= "fxch";
immutable const(char) *M_FNOP	= "fnop";	// D0H
immutable const(char) *M_FCHS	= "fchs";	// E0H
immutable const(char) *M_FABS	= "fabs";	// E1H
immutable const(char) *M_FTST	= "ftst";	// E4H
immutable const(char) *M_FXAM	= "fxam";	// E5H
immutable const(char) *M_FLD1	= "fld1";	// E8H
immutable const(char) *M_FLDL2T	= "fldl2t";	// E9H
immutable const(char) *M_FLDL2E	= "fldl2e";	// EAH
immutable const(char) *M_FLDPI	= "fldpi";	// EBH
immutable const(char) *M_FLDLG2	= "fldlg2";	// ECH
immutable const(char) *M_FLDLN2	= "fldln2";	// EDH
immutable const(char) *M_FLDZ	= "fldz";	// EEH
// ANCHOR ESCAPE DAH
immutable const(char) *M_FIADD	= "fiadd";
immutable const(char) *M_FIMUL	= "fimul";
immutable const(char) *M_FICOM	= "ficom";
immutable const(char) *M_FICOMP	= "ficomp";
immutable const(char) *M_FISUB	= "fisub";
immutable const(char) *M_FISUBR	= "fisubr";
immutable const(char) *M_FIDIV	= "fidiv";
immutable const(char) *M_FIDIVR	= "fidivr";
immutable const(char) *M_FCMOVB	= "fcmovb";	// C0H..C7H
immutable const(char) *M_FCMOVE	= "fcmove";	// C8H..CFH
immutable const(char) *M_FCMOVBE	= "fcmovbe";	// D0H..D7H
immutable const(char) *M_FCMOVU	= "fcmovu";	// D8H..DFH
immutable const(char) *M_FUCOMPP	= "fucompp";	// E9H
// ANCHOR ESCAPE DBH
immutable const(char) *M_FILD	= "fild";
immutable const(char) *M_FISTTP	= "fisttp";
immutable const(char) *M_FIST	= "fist";
immutable const(char) *M_FISTP	= "fistp";
immutable const(char) *M_FCMOVNB	= "fcmovnb";	// reg=0
immutable const(char) *M_FCMOVNE	= "fcmovne";	// reg=1
immutable const(char) *M_FCMOVNBE	= "fcmovnbe";	// reg=2
immutable const(char) *M_FCMOVNU	= "fcmovnu";	// reg=3
immutable const(char) *M_FUCOMI	= "fucomi";	// reg=5
immutable const(char) *M_FCOMI	= "fcomi";	// reg=6
immutable const(char) *M_FCLEX	= "fclex";	// reg=4 rm=2
immutable const(char) *M_FINIT	= "finit";	// reg=4 rm=3
// ANCHOR ESCAPE DDH
immutable const(char) *M_FRSTOR	= "frstor";
immutable const(char) *M_FSAVE	= "fsave";
immutable const(char) *M_FSTSW	= "fstsw";
immutable const(char) *M_FFREE	= "ffree";	// reg=0
immutable const(char) *M_FUCOM	= "fucom";	// reg=4
immutable const(char) *M_FUCOMP	= "fucomp";	// reg=5
// ANCHOR ESCAPE DEH
immutable const(char) *M_FADDP	= "faddp";
immutable const(char) *M_MULP	= "mulp";
immutable const(char) *M_SUBRP	= "subrp";
immutable const(char) *M_SUBP	= "subp";
immutable const(char) *M_DIVRP	= "divrp";
immutable const(char) *M_DIVP	= "divp";
immutable const(char) *M_FCOMPP	= "fcompp";
// ANCHOR ESCAPE DFH
immutable const(char) *M_FBLD	= "fbld";
immutable const(char) *M_FBSTP	= "fbstp";
immutable const(char) *M_FUCOMIP	= "fucomip";
immutable const(char) *M_FCOMIP	= "fcomip";
// ANCHOR MAP 0F
// ANCHOR MAP 0F 38
// ANCHOR MAP 0F 3A

// ANCHOR Instruction tables

immutable const(char)*[8] M_GRP1 = [ // same for <40H
	M_ADD, M_OR, M_ADC, M_SBB, M_AND, M_SUB, M_XOR, M_CMP
];
immutable const(char)*[8] M_GRP2 = [
	M_ROL, M_ROR, M_RCL, M_RCR, M_SHL, M_SHR, null, M_SAR
];
immutable const(char)*[4] M_ASCII = [
	M_DAA, M_DAS, M_AAA, M_AAS
];
immutable const(char)*[16] M_Jcc = [
	M_JO, M_JNO, M_JB, M_JNB, M_JZ, M_JNZ, M_JBE, M_JNBE,
	M_JS, M_JNS, M_JP, M_JNP, M_JL, M_JNL, M_JLE, M_JNLE,
];
immutable const(char)*[3] M_STR1 = [
	M_STOS, M_LODS, M_SCAS
];
immutable const(char)*[6] M_F8 = [
	M_CLC, M_STC, M_CLI, M_STI, M_CLD, M_STD
];
immutable const(char)*[8] M_X87_D8 = [
	M_FADD, M_FMUL, M_FCOM, M_FCOMP, M_FSUB, M_FSUBR, M_FDIV, M_FDIVR
];
immutable const(char)*[8] M_X87_D9 = [
	M_FLD, null, M_FST, M_FSTP, M_FLDENV, M_FLDCW, M_FSTENV, M_FSTCW
];
immutable const(char)*[8] M_X87_DA = [
	M_FIADD, M_FIMUL, M_FICOM, M_FICOMP, M_FISUB, M_FISUBR, M_FIDIV, M_FIDIVR
];
immutable const(char)*[8] M_X87_DB = [
	M_FILD, M_FISTTP, M_FIST, M_FISTP, null, M_FLD, null, M_FSTP
];
// DCH same as D8H
immutable const(char)*[8] M_X87_DD = [
	M_FLD, M_FISTTP, M_FST, M_FSTP, M_FRSTOR, null, M_FSAVE, M_FSTSW
];
immutable const(char)*[8] M_X87_DF = [
	M_FILD, M_FISTTP, M_FIST, M_FISTP, M_FBLD, M_FILD, M_FBSTP, M_FISTP
];

// !SECTION

//
// SECTION Definitions
//

/// x86 prefixes
enum x86Prefix : ubyte {
	data	= 0x66,	/// 0x66
	addr	= 0x67,	/// 0x67
	lock	= 0xf0,	/// 0xF0
	repne	= 0xf2,	/// 0xF2
	rep	= 0xf3,	/// 0xF3
	// SSE:
	h66	= data,	/// Data operand prefix
	hf2	= repne,	/// REPNE
	hf3	= rep,	/// REP/REPE
}

/// Segment register overrides
enum x86Seg : ubyte {
	none, es, cs, ss, ds, fs, gs
}
/// Segment strings
immutable const(char)*[7] segs = [
	null, "es", "cs", "ss", "ds", "fs", "gs"
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
	// amx
	tmm0	= 0,	tmm1	= 1,	tmm2	= 2,	tmm3	= 3,
	tmm4	= 4,	tmm5	= 5,	tmm6	= 6,	tmm7	= 7,
}
immutable const(char)*[16][16] regs = [
	//TODO: const(char) *adbg_disasm_x86_reg(width, i)
	[], [], [], [], [], [], [], [], // self-imposed garbage
	[ // 8b, excluding REX special cases
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
immutable const(char)*[2][8] regs_addr16 = [ // modrm:rm16
	[ "bx", "si" ], [ "bx", "di" ], [ "bp", "si" ], [ "bp", "di" ],
	[ "si", null ], [ "di", null ], [ "bp", null ], [ "bx", null ],
];
immutable const(char)*[8] regs_mmx = [
	"mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7"
];
/*immutable const(char)*[] regs_amx = [
	"tmm0", "tmm1", "tmm2", "tmm3", "tmm4", "tmm5", "tmm6", "tmm7"
];*/

// !SECTION

//
// SECTION Operand types
//

/// EbGb/EvGv/GbEb/GvEv, auto modrm
// D: 0=mem, 1=reg
// W: 0=i8, 1=i16/i32 (i64 if REX.W)
int adbg_disasm_x86_op_modrm(adbg_disasm_t *p, bool D, bool W) {
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(p, &modrm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	return adbg_disasm_x86_op_modrm2(p, modrm, D, W);
}
/// EbGb/EvGv/GbEb/GvEv, manual modrm
// D: 0=mem, 1=reg
// W: 0=i8, 1=i16/i32 (i64 if REX.W)
int adbg_disasm_x86_op_modrm2(adbg_disasm_t *p, ubyte modrm, bool D, bool W) {
	if (W == false)
		p.x86.pfData = AdbgDisasmType.i8;
	
	return adbg_disasm_x86_modrm(p, modrm, D);
}
int adbg_disasm_x86_op_Ib(adbg_disasm_t *p) {	// Immediate 8-bit
	ubyte i = void;
	int e = adbg_disasm_fetch!ubyte(p, &i, AdbgDisasmTag.immediate);
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
	
	if (p.x86.pfData != AdbgDisasmType.i16) { // 64/32 modes
		e = adbg_disasm_fetch!uint(p, &u.i32, AdbgDisasmTag.immediate);
		if (e == 0) {
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_immediate(p, AdbgDisasmType.i32, &u.i32);
		}
	} else {
		e = adbg_disasm_fetch!ushort(p, &u.i16, AdbgDisasmTag.immediate);
		if (e == 0) {
			if (p.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_immediate(p, AdbgDisasmType.i16, &u.i16);
		}
	}
	
	return e;
}
int adbg_disasm_x86_op_GvMa(adbg_disasm_t *p) {	// BOUND
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(p, &modrm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	if (modrm >= 0b11000000)
		return adbg_oops(AdbgError.illegalInstruction);
	
	adbg_disasm_operand_mem_t mem = void;
	e = adbg_disasm_x86_modrm_rm(p, &mem, modrm >> 6, (modrm >> 3) & 7);
	if (e) return e;
	
	const(char) *reg = void;
	adbg_disasm_x86_modrm_reg(p, &reg, modrm & 7);
	
	if (p.mode < AdbgDisasmMode.file)
		return 0;
	
	adbg_disasm_add_register(p, reg);
	adbg_disasm_add_memory2(p, cast(AdbgDisasmType)(p.x86.pfData + 1), &mem);
	return 0;
}
int adbg_disasm_x86_op_GzMp(adbg_disasm_t *p) { // LDS/LES
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(p, &modrm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	ubyte mode = modrm >> 6;
	if (mode == 0b11)
		return adbg_oops(AdbgError.illegalInstruction);
	
	ubyte rm = modrm & 7;
	adbg_disasm_operand_mem_t mem = void;
	e = adbg_disasm_x86_modrm_rm(p, &mem, mode, rm);
	if (e) return e;
	
	if (p.mode < AdbgDisasmMode.file)
		return 0;
	
	ubyte reg = (modrm >> 3) & 7;
	const(char) *register = void;
	adbg_disasm_x86_modrm_reg(p, &register, reg);
	
	adbg_disasm_add_register(p, register);
	adbg_disasm_add_memory2(p, AdbgDisasmType.far, &mem);
	return 0;
}
int adbg_disasm_x86_op_Jb(adbg_disasm_t *p) {	// Target immediate 8-bit
	ubyte i = void;
	int e = adbg_disasm_fetch!ubyte(p, &i, AdbgDisasmTag.immediate);
	if (e == 0) {
		if (p.mode >= AdbgDisasmMode.data)
			adbg_disasm_calc_offset!ubyte(p, i);
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_immediate(p, AdbgDisasmType.i8, &i);
	}
	return e;
}
int adbg_disasm_x86_op_Jz(adbg_disasm_t *p) {	// Target immediate
	int e = void;
	switch (p.x86.pfData) with (AdbgDisasmType) {
	case i16:
		ushort u16 = void;
		e = adbg_disasm_fetch!ushort(p, &u16, AdbgDisasmTag.immediate);
		if (e) return e;
		if (p.mode >= AdbgDisasmMode.data)
			adbg_disasm_calc_offset!ushort(p, u16);
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_immediate(p, i16, &u16);
		return 0;
	default:
		uint u32 = void;
		e = adbg_disasm_fetch!uint(p, &u32, AdbgDisasmTag.immediate);
		if (e) return e;
		if (p.mode >= AdbgDisasmMode.data)
			adbg_disasm_calc_offset!uint(p, u32);
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_immediate(p, i32, &u32);
		return 0;
	}
}
int adbg_disasm_x86_op_Ap(adbg_disasm_t *p) {	// immediate+segment (in that order)
	int e = void;
	ushort segment = void;
	void *b = void;
	if (p.x86.pfData == AdbgDisasmType.i16) {
		ushort a = void;
		e = adbg_disasm_fetch!ushort(p, &a, AdbgDisasmTag.immediate);
		if (e) return e;
		b = &a;
	} else {
		uint a = void;
		e = adbg_disasm_fetch!uint(p, &a, AdbgDisasmTag.immediate);
		if (e) return e;
		b = &a;
	}
	e = adbg_disasm_fetch!ushort(p, &segment, AdbgDisasmTag.segment);
	if (e) return e;
	adbg_disasm_add_immediate(p, p.x86.pfData, b, segment);
	p.decoderFar = true;
	return 0;
}

// !SECTION

//
// SECTION Operand groups
//

int adbg_disasm_x86_escape(adbg_disasm_t *p, ubyte opcode) {	// ANCHOR x87 escape
	immutable static const(char) *st = "st";
	version (Trace) trace("opcode=%x", opcode);
	
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(p, &modrm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	p.decoderNoReverse = true;
	const(char) *mnemonic = void;
	AdbgDisasmType width = void;
	ubyte mode = modrm >> 6;
	ubyte reg  = (modrm >> 3) & 7; /// instruction selector
	ubyte rm   = modrm & 7; /// mem
	bool regmode = mode == 0b11;
	
	// check invalid and no-operand first with reg/rm
	switch (opcode) {
	case 0xd8:
		width = AdbgDisasmType.i32;
		mnemonic = M_X87_D8[reg];
		if (regmode) goto L_REG0RM; else goto L_MEM;
	case 0xd9:
		if (regmode) {
			switch (reg) {
			case 0b000: mnemonic = M_FLD; goto L_REG0RM;
			case 0b001: mnemonic = M_FXCH; goto L_REG0RM;
			default:
				switch (modrm) {
				case 0xd0: mnemonic = M_FNOP; break;
				case 0xe1: mnemonic = M_FCHS; break;
				case 0xe2: mnemonic = M_FABS; break;
				case 0xe4: mnemonic = M_FTST; break;
				case 0xe5: mnemonic = M_FXAM; break;
				case 0xe8: mnemonic = M_FLD1; break;
				case 0xe0: mnemonic = M_FLDL2T; break;
				case 0xea: mnemonic = M_FLDL2E; break;
				case 0xeb: mnemonic = M_FLDPI; break;
				case 0xec: mnemonic = M_FLDLG2; break;
				case 0xed: mnemonic = M_FLDLN2; break;
				case 0xee: mnemonic = M_FLDZ; break;
				default: goto L_ILLEGAL;
				}
				goto L_NOOP;
			}
		}
		switch (reg) {
		case 0,2,3: width = AdbgDisasmType.i32; break;
		case 4,6:   width = AdbgDisasmType.none; break;
		case 5,7:   width = AdbgDisasmType.i16; break;
		default:    goto L_ILLEGAL;
		}
		if (reg == 1)
			goto L_ILLEGAL;
		mnemonic = M_X87_D9[reg];
		goto L_MEM;
	case 0xda:
		if (regmode) {
			switch (reg) {
			case 0: mnemonic = M_FCMOVB; goto L_REG0RM;
			case 1: mnemonic = M_FCMOVE; goto L_REG0RM;
			case 2: mnemonic = M_FCMOVBE; goto L_REG0RM;
			case 3: mnemonic = M_FCMOVU; goto L_REG0RM;
			default:
			}
			if (modrm != 0xe9)
				goto L_ILLEGAL;
			mnemonic = M_FUCOMPP;
			goto L_NOOP;
		}
		width = AdbgDisasmType.i32;
		mnemonic = M_X87_DA[reg];
		goto L_MEM;
	case 0xdb:
		if (regmode) {
			switch (reg) {
			case 0: mnemonic = M_FCMOVNB; break;
			case 1: mnemonic = M_FCMOVNE; break;
			case 2: mnemonic = M_FCMOVNBE; break;
			case 3: mnemonic = M_FCMOVNU; break;
			case 5: mnemonic = M_FUCOMI; break;
			case 6: mnemonic = M_FCOMI; break;
			case 4:
				switch (rm) {
				case 2: mnemonic = M_FCLEX; break;
				case 3: mnemonic = M_FINIT; break;
				default: goto L_ILLEGAL;
				}
				goto L_NOOP;
			default: goto L_ILLEGAL;
			}
			goto L_REG0RM;
		}
		if (reg < 4)
			width = AdbgDisasmType.i32;
		else if (reg == 5 || reg == 7)
			width = AdbgDisasmType.f80;
		else
			goto L_ILLEGAL;
		mnemonic = M_X87_DB[reg];
		goto L_MEM;
	case 0xdc:
		mnemonic = M_X87_D8[reg];
		if (regmode) {
			switch (reg) {
			case 2, 3: goto L_ILLEGAL;
			default: goto L_REGRM0;
			}
		}
		width = AdbgDisasmType.i64;
		goto L_MEM;
	case 0xdd: // me
		if (regmode) {
			switch (reg) {
			case 0: mnemonic = M_FFREE; goto L_REGRM;
			case 2: mnemonic = M_FST; goto L_REGRM;
			case 3: mnemonic = M_FSTP; goto L_REGRM;
			case 4: mnemonic = M_FUCOM; goto L_REGRM0;
			case 5: mnemonic = M_FUCOMP; goto L_REGRM;
			default: goto L_ILLEGAL;
			}
		}
		switch (reg) {
		case 0b101: return adbg_oops(AdbgError.illegalInstruction);
		case 0b100, 0b110: width = AdbgDisasmType.none; break;
		case 0b111: width = AdbgDisasmType.i16; break;
		default: width = AdbgDisasmType.i64;
		}
		mnemonic = M_X87_D8[reg];
		goto L_MEM;
	case 0xde:
		if (regmode) {
			switch (reg) {
			case 0: mnemonic = M_FADDP; goto L_REGRM0;
			case 1: mnemonic = M_MULP; goto L_REGRM0;
			case 4: mnemonic = M_SUBRP; goto L_REGRM0;
			case 5: mnemonic = M_SUBP; goto L_REGRM0;
			case 6: mnemonic = M_DIVRP; goto L_REGRM0;
			case 7: mnemonic = M_DIVP; goto L_REGRM0;
			default:
			}
			if (modrm != 0xd9)
				goto L_ILLEGAL;
			mnemonic = M_FCOMPP;
			goto L_NOOP;
		}
		width = AdbgDisasmType.i16;
		mnemonic = M_X87_DA[reg];
		goto L_MEM;
	default: // DFH
		if (regmode) {
			switch (reg) {
			case 4:
				if (modrm != 0xe0)
					goto L_ILLEGAL;
				mnemonic = M_FSTSW;
				goto L_REGAX;
			case 5: mnemonic = M_FUCOMIP; goto L_REG0RM;
			case 6: mnemonic = M_FCOMIP; goto L_REG0RM;
			default: goto L_ILLEGAL;
			}
		}
		switch (reg) {
		case 0b100, 0b110: width = AdbgDisasmType.f80; break;
		case 0b101, 0b111: width = AdbgDisasmType.i64; break;
		default: width = AdbgDisasmType.i16;
		}
		mnemonic = M_X87_DF[reg];
		goto L_MEM;
	}
	
L_NOOP: // no operands
	if (p.mode < AdbgDisasmMode.file)
		return 0;
	goto L_MNEMONIC;
	
L_REGAX:
	if (p.mode < AdbgDisasmMode.file)
		return 0;
	adbg_disasm_add_register(p, regs[AdbgDisasmType.i16][x86Reg.ax]);
	goto L_MNEMONIC;
	
L_REGRM: // st(rm)
	if (p.mode < AdbgDisasmMode.file)
		return 0;
	adbg_disasm_add_register(p, st, rm, true);
	goto L_MNEMONIC;
	
L_REG0RM: // st(0),st(rm)
	if (p.mode < AdbgDisasmMode.file)
		return 0;
	adbg_disasm_add_register(p, st, 0, true);
	adbg_disasm_add_register(p, st, rm, true);
	goto L_MNEMONIC;
	
L_REGRM0: // st(rm),st(0)
	if (p.mode < AdbgDisasmMode.file)
		return 0;
	adbg_disasm_add_register(p, st, 0, true);
	adbg_disasm_add_register(p, st, rm, true);
	goto L_MNEMONIC;

L_MEM: // memory operand
	if (p.mode < AdbgDisasmMode.file)
		return 0;
	if (p.x86.pfSegment == 0)
		p.x86.pfSegment = x86Seg.ds;
	adbg_disasm_add_memory(p, width, segs[p.x86.pfSegment],
		regs[p.x86.pfAddr][rm], null, AdbgDisasmType.none, null, 0, false);
	
L_MNEMONIC:
	adbg_disasm_add_mnemonic(p, mnemonic);
	return 0;
	
L_ILLEGAL:
	return adbg_oops(AdbgError.illegalInstruction);
}
int adbg_disasm_x86_grp1(adbg_disasm_t *p, ubyte opcode) {	// ANCHOR Group 1
	if (p.platform == AdbgPlatform.x86_64 && opcode == 0x82)
		return adbg_oops(AdbgError.illegalInstruction);
	
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(p, &modrm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	//TODO: Consider function to adjust reg data width
	bool W = opcode & 1;
	if (W == false)
		p.x86.pfData = AdbgDisasmType.i8;
	
	ubyte mode = modrm >> 6;
	ubyte rm = modrm & 7;
	
	adbg_disasm_operand_mem_t m = void;
	e = adbg_disasm_x86_modrm_rm(p, &m, mode, rm);
	if (e) return e;
	
	if (p.mode >= AdbgDisasmMode.file) {
		adbg_disasm_add_mnemonic(p, M_GRP1[(modrm >> 3) & 7]);
		if (mode == 3)
			adbg_disasm_add_register(p, m.base);
		else
			adbg_disasm_add_memory2(p, p.x86.pfData, &m);
	}
	
	return opcode != 0x81 ? adbg_disasm_x86_op_Ib(p) : adbg_disasm_x86_op_Iz(p);
}
int adbg_disasm_x86_grp1a(adbg_disasm_t *p) {	// ANCHOR Group 1a
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(p, &modrm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	ubyte reg  = (modrm >> 3) & 7;
	if (reg > 0) //TODO: XOP
		return adbg_oops(AdbgError.notImplemented);
	
	ubyte mode = modrm >> 6;
	ubyte rm   = modrm & 7;
	
	adbg_disasm_operand_mem_t m = void;
	e = adbg_disasm_x86_modrm_rm(p, &m, mode, rm);
	if (e) return e;
	
	if (p.mode >= AdbgDisasmMode.file) {
		adbg_disasm_add_mnemonic(p, M_POP);
		if (mode == 3)
			adbg_disasm_add_register(p, m.base);
		else
			adbg_disasm_add_memory2(p, p.x86.pfData, &m);
	}
	return 0;
}
int adbg_disasm_x86_grp2(adbg_disasm_t *p, ubyte opcode) {	// ANCHOR Group 2
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(p, &modrm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	ubyte mode = modrm >> 6;
	ubyte reg  = (modrm >> 3) & 7;
	ubyte rm   = modrm & 7;
	
	if (reg == 0b110)
		return adbg_oops(AdbgError.illegalInstruction);
	
	bool W = opcode & 1;
	p.x86.pfData = W ? p.x86.pfData : AdbgDisasmType.i8;
	adbg_disasm_operand_mem_t mem = void;
	e = adbg_disasm_x86_modrm_rm(p, &mem, mode, rm);
	if (e) return e;
	
	if (p.mode >= AdbgDisasmMode.file) {
		adbg_disasm_add_mnemonic(p, M_GRP2[reg]);
		if (mode == 0b11)
			adbg_disasm_add_register(p, mem.base);
		else
			adbg_disasm_add_memory2(p, p.x86.pfData, &mem);
	}
	
	ubyte i8 = void;
	switch (opcode) {
	case 0xc0, 0xc1: // imm8
		e = adbg_disasm_fetch!ubyte(p, &i8, AdbgDisasmTag.immediate);
		if (e) return e;
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_immediate(p, AdbgDisasmType.i8, &i8);
		return 0;
	case 0xd0, 0xd1: // 1
		if (p.mode >= AdbgDisasmMode.file) {
			i8 = 1;
			adbg_disasm_add_immediate(p, AdbgDisasmType.i8, &i8);
		}
		return 0;
	default: // cl
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_register(p, regs[AdbgDisasmType.i8][x86Reg.cl]);
		return 0;
	}
}
int adbg_disasm_x86_grp3(adbg_disasm_t *p, ubyte opcode) {	// ANCHOR Group 3
	immutable static const(char)*[8] M_GRP3 =
		[ M_TEST, M_TEST, M_NOT, M_NEG, M_MUL, M_IMUL, M_DIV, M_IDIV ];
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(p, &modrm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	ubyte reg = (modrm >> 3) & 7;
		
	// NOTE: libopcode says this is illegal
	//       Zydis and Capstone allow it as per the AMD reference
	if (reg == 1)
		return adbg_oops(AdbgError.illegalInstruction);

	ubyte rm = modrm & 7;
	ubyte mode = modrm & 7;
	adbg_disasm_operand_mem_t mem = void;
	e = adbg_disasm_x86_modrm_rm(p, &mem, mode, rm);
	if (e) return e;
	
	bool W = opcode & 1;
	
	if (p.mode >= AdbgDisasmMode.file) {
		adbg_disasm_add_mnemonic(p, M_GRP3[reg]);
		AdbgDisasmType width = W ? p.x86.pfData : AdbgDisasmType.i8;
		adbg_disasm_add_memory2(p, width, &mem);
	}

	if (reg < 2) {
		return W ? adbg_disasm_x86_op_Iz(p) : adbg_disasm_x86_op_Ib(p);
	}
	return 0;
}
int adbg_disasm_x86_grp4(adbg_disasm_t *p) {	// ANCHOR Group 4
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(p, &modrm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	
	
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_disasm_x86_grp5(adbg_disasm_t *p) {	// ANCHOR Group 5
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(p, &modrm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	
	
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
int adbg_disasm_x86_grp11(adbg_disasm_t *p, ubyte opcode) {	// ANCHOR Group 11
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(p, &modrm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	ubyte reg  = (modrm >> 3) & 7;
	ubyte mode = modrm >> 6;
	bool c6 = opcode == 0xc6;
	
	switch (reg) {
	case 0:
		ubyte rm = modrm & 7;
		adbg_disasm_operand_mem_t mem = void;
		e = adbg_disasm_x86_modrm_rm(p, &mem, mode, rm);
		if (p.mode >= AdbgDisasmMode.file) {
			adbg_disasm_add_mnemonic(p, M_MOV);
			if (mode == 0b11)
				adbg_disasm_add_register(p, mem.base);
			else
				adbg_disasm_add_memory2(p, p.x86.pfData, &mem);
		}
		break;
	case 7:
		if (mode < 0b11)
			return adbg_oops(AdbgError.illegalInstruction);
		if (p.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_mnemonic(p, c6 ? M_XABORT : M_XBEGIN);
		break;
	default: return adbg_oops(AdbgError.illegalInstruction);
	}
	return c6 ? adbg_disasm_x86_op_Ib(p) : adbg_disasm_x86_op_Iz(p);
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
//      just extract
//        void adbg_disasm_x86_modrm_extract(ref ubyte mode, ref ubyte reg, ref ubyte rm, ref ubyte modrm)
//      or partial
//        ubyte adbg_disasm_x86_modrm_mode(ubyte modrm)
//        ubyte adbg_disasm_x86_modrm_reg(ubyte modrm)
//        ubyte adbg_disasm_x86_modrm_rm(ubyte modrm)

int adbg_disasm_x86_modrm(adbg_disasm_t *p, ubyte modrm, bool dir) {
	ubyte mode = modrm >> 6;
	ubyte reg = (modrm >> 3) & 7;
	ubyte rm = modrm & 7;
	
	const(char) *register = void;
	adbg_disasm_operand_mem_t mem = void;
	
	// Configure register/memory stuff
	int e = adbg_disasm_x86_modrm_rm(p, &mem, mode, rm);
	if (e) return e;
	adbg_disasm_x86_modrm_reg(p, &register, reg);
	
	bool regmode = mode == 3;
	
	if (dir) { // to registers
		adbg_disasm_add_register(p, register);
		if (regmode)
			adbg_disasm_add_register(p, mem.base);
		else
			adbg_disasm_add_memory2(p, p.x86.pfData, &mem);
	} else {
		if (regmode)
			adbg_disasm_add_register(p, mem.base);
		else
			adbg_disasm_add_memory2(p, p.x86.pfData, &mem);
		adbg_disasm_add_register(p, register);
	}
	
	return 0;
}
void adbg_disasm_x86_modrm_reg(adbg_disasm_t *p, const(char) **basereg, ubyte reg) {
	version (Trace) trace("reg=%x", reg);
	immutable static const(char)*[] regs8rex = [ "spl", "bpl", "sil", "dil" ];
	if (p.x86.hasRex && p.x86.pfData == AdbgDisasmType.i8) {
		if (reg >= 4 && reg <= 7) {
			*basereg = regs8rex[reg - 4];
			return;
		}
	}
	*basereg = regs[p.x86.pfData][reg];
}
int adbg_disasm_x86_modrm_rm(adbg_disasm_t *p, adbg_disasm_operand_mem_t *mem, ubyte mode, ubyte rm) {
	version (Trace) trace("mode=%x rm=%x", mode, rm);
	
	if (p.platform != AdbgPlatform.x86_16 && rm == 0b100 && mode < 3)
		return adbg_disasm_x86_sib(p, mem, mode);
	
	mem.scaled = false;
	mem.scale  = 0;
	mem.segment = segs[p.x86.pfSegment];
	
	//TODO: VEX.B
	if (p.x86.pfAddr == AdbgDisasmType.i16) {
		mem.base  = regs_addr16[rm][0];
		mem.index = regs_addr16[rm][1];
	} else {
		mem.base  = regs[p.x86.pfAddr][rm];
		mem.index = null;
	}
	
	switch (mode) {
	case 0: // no displacement
		mem.hasOffset = false;
		return 0;
	case 1: // +u8 displacement
		mem.hasOffset = true;
		mem.offset.type = AdbgDisasmType.i8;
		return adbg_disasm_fetch!ubyte(p, &mem.offset.u8, AdbgDisasmTag.disp);
	case 2: // +u16/u32 displacement
		mem.hasOffset = true;
		switch (p.x86.pfData) with (AdbgDisasmType) {
		case i16:
			mem.offset.type = AdbgDisasmType.i16;
			return adbg_disasm_fetch!ushort(p, &mem.offset.u16, AdbgDisasmTag.disp);
		default:
			mem.offset.type = AdbgDisasmType.i32;
			return adbg_disasm_fetch!uint(p, &mem.offset.u32, AdbgDisasmTag.disp);
		}
	default:
		adbg_disasm_x86_modrm_reg(p, &mem.base, rm);
		return 0;
	}
}
int adbg_disasm_x86_sib(adbg_disasm_t *p, adbg_disasm_operand_mem_t *mem, ubyte mode) {
	ubyte sib = void;
	int e = adbg_disasm_fetch!ubyte(p, &sib, AdbgDisasmTag.sib);
	if (e) return e;
	
	mem.scaled = true;
	AdbgDisasmType w = AdbgDisasmType.i32;
	ubyte index = (sib >> 3) & 7;
	ubyte base  = sib & 7;
	
	bool hasScaling = index != 0b100; // + index*scale
	bool noBase     = base  == 0b101; // no base
	
	if (p.x86.vexB) base  |= 0b1000;
	if (p.x86.vexX) index |= 0b1000;
	
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
		return adbg_disasm_fetch!ubyte(p, &mem.offset.u8, AdbgDisasmTag.disp);
	case 2:
		mem.hasOffset = true;
		mem.offset.type = AdbgDisasmType.i32;
		return adbg_disasm_fetch!uint(p, &mem.offset.u32, AdbgDisasmTag.disp);
	default: assert(0);
	}
}

// !SECTION

//
// SECTION AVX mechanics
//

enum x86VexMode {
	MemReg,
	RegMem,
	RegRegMem
}

int adbg_disasm_x86_avx_modrm(adbg_disasm_t *p, ubyte modrm, x86VexMode mode) {
	return adbg_oops(AdbgError.notImplemented);
}

// !SECTION