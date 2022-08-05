/**
 * Linear x86 decoder.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2022 dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module adbg.disasm.decoder.x86;

// The decoder is quite messy.
// You have been warned.

import adbg.error;
import adbg.disassembler;
private import adbg.utils.bit : BIT;

extern (C):

// NOTE: x86-64 operation modes
//       LMA=0: Legal Mode, LMA=1: Long Mode, CS.L: long, CS.D: dword
//             | CS.L=0  CS.D=0  | CS.L=0  CS.D=1  | CS.L=1  CS.D=0  | CS.L=1  CS.D=1  |
//       LMA=0 | standard 16-bit | standard 32-bit | standard 16-bit | standard 32-bit |
//       LMA=1 | 16-bit compat.  | 32-bit compat.  | 64-bit          | reserved        |
// NOTE: AT&T: bound/invlpga/enter/other opcodes with 2 immediates: no reversed order
//       https://ftdisasm.gnu.org/old-gnu/Manuals/gas-2.9.1/html_chapter/as_16.html
// NOTE: If-ranges saves a few instructions over switch (opcode >> 4)
// NOTE: Struct .init without a ctor is much better (when fields are aligned)

//TODO: Control-flow analysis
//TODO: Additional processors: 8086, 80186, 80386, Intel64, AMD64
//      Critical for 0x0f: 8086=pop cs, 80186+=2-byte
//      And something else with MOVXSD
//TODO: Check LOCK
//      ADC, ADD, AND, BTC, BTR, BTS, CMPXCHG, CMPXCHG8B, CMPXCHG16B,
//      DEC, INC, NEG, NOT, OR, SBB, SUB, XADD, XCHG, and XOR.
//      only check if hasLock
//TODO: Check REPE/REPZ and REPNE/REPNZ
//      Low priority because Intel defines on for others being undefined (not strict).
//      CMPS, CMPSB, CMPSD, CMPSW, SCAS, SCASB, SCASD, and SCASW.
//      only check if hasRepe/hasRepne
//TODO: Maybe flag table to check LOCK/REP support?
//TODO: Add "preliminary" prefix system (stack then commit)

/// Internal entry point for the x86 decoder.
/// Params: p = adbg_disasm_t pointer.
/// Returns: Error code.
int adbg_disasm_x86(adbg_disasm_t *disasm) {
	x86_state_t state;
	state.disasm = disasm;
	
	switch (disasm.platform) with (AdbgPlatform) {
	case x86_64:
		state.pf.addr = AdbgDisasmType.i64;
		state.pf.data = AdbgDisasmType.i32;
		break;
	case x86_32:
		state.pf.addr = AdbgDisasmType.i32;
		state.pf.data = AdbgDisasmType.i32;
		break;
	default:
		state.pf.addr = AdbgDisasmType.i16;
		state.pf.data = AdbgDisasmType.i16;
		break;
	}
	
	int pfCounter;
	int e = void;
	const(char) *mnemonic = void;
	ubyte opcode = void;
	ubyte mode   = void;	/// modrm:mode
	ubyte reg    = void;	/// modrm:reg
	ubyte rm     = void;	/// modrm:rm
	bool  W      = void;	/// W bit
	bool  D      = void;	/// D bit
	
L_PREFIX:
	if (pfCounter > 4) // x<=4
		//TODO: Verify if illegal or skipped
		//return adbg_oops(AdbgError.illegalInstruction);
		goto L_OPCODE;
	
	e = adbg_disasm_fetch!ubyte(&opcode, disasm, AdbgDisasmTag.prefix);
	if (e) return e;
	
	version (Trace) trace("opcode=%x", opcode);
	
	// Legacy prefixes must be processed before REX/VEX/EVEX
	switch (opcode) {
	// Group 2
	case 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65: // es/cs/ss/ds/fs/gs
		++pfCounter;
		x86Seg seg = opcode < 0b01000000 ? // +1 since 0=none (override)
			cast(x86Seg)((opcode >> 3) - 3) :
			cast(x86Seg)(opcode - 0x5f);
		state.pf.segment = seg;
		if (disasm.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_segment(disasm, x86segs[seg]);
		goto L_PREFIX;
	// Group 3
	case 0x66: // Data
		++pfCounter;
		state.has |= x86Has.data;
		state.pf.data = disasm.platform == AdbgPlatform.x86_16 ?
			AdbgDisasmType.i32 : AdbgDisasmType.i16;
		state.pf.select = x86Select.data;
		goto L_PREFIX;
	// Group 4
	case 0x67: // Address
		++pfCounter;
		state.has |= x86Has.addr;
		switch (disasm.platform) with (AdbgPlatform) {
		case x86_64: state.pf.addr = AdbgDisasmType.i32; break;
		case x86_32: state.pf.addr = AdbgDisasmType.i16; break;
		default:     state.pf.addr = AdbgDisasmType.i32; break;
		}
		goto L_PREFIX;
	// Group 1
	case 0xf0: // LOCK
		++pfCounter;
		state.has |= x86Has.lock;
		if (disasm.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_prefix(disasm, "lock");
		goto L_PREFIX;
	case 0xf2: // REPNE
		++pfCounter;
		state.has = x86Has.repne;
		state.pf.select = x86Select.repne;
		if (disasm.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_prefix(disasm, "repne");
		goto L_PREFIX;
	case 0xf3: // REP
		++pfCounter;
		state.has = x86Has.rep;
		state.pf.select = x86Select.rep;
		if (disasm.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_prefix(disasm, "rep");
		goto L_PREFIX;
	default:
		if (disasm.mode >= AdbgDisasmMode.file)
			adbg_disasm_fetch_lasttag(disasm, AdbgDisasmTag.opcode);
	}
	
L_OPCODE:
	// Ascending opcodes to make second opcode map closer (branching)
	if (opcode < 0x40) { // 0H..3FH: Legacy
		// Most used instructions these days are outside of this madisasm.
		// So, the 2-byte escape is checked here.
		if (opcode == 0x0f) return adbg_disasm_x86_0f(state);
		
		rm  = opcode & 7;
		reg = opcode >> 3;	// no masking since OPCODE:MOD=00
		W   = opcode & 1;
		
		// push/pop
		if (rm >= 0b110) {
			if (reg < 4) {
				adbg_disasm_add_mnemonic(disasm, W ? X86_POP : X86_PUSH);
				adbg_disasm_add_register(disasm, x86segs[reg + 1]);
				return 0;
			}
			// Prefixes already taken care of, unless moved here
			if (disasm.platform == AdbgPlatform.x86_64)
				return adbg_oops(AdbgError.illegalInstruction);
			// 27h	00 100 111	daa
			// 2fh	00 101 111	das
			// 37h	00 110 111	aaa
			// 3fh	00 111 111	aas
			if (disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_register(disasm, X86_ASCII[reg & 3]);
			return 0;
		}
		
		if (disasm.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_mnemonic(disasm, X86_GRP1[reg]);
		
		// immediate
		if (rm >= 0b100) {
			if (disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_register(disasm,
					x86regs[state.pf.data][x86Reg.eax]);
			return W ?
				adbg_disasm_x86_op_Iz(state) :
				adbg_disasm_x86_op_Ib(state);
		}
		
		// modrm
		return adbg_disasm_x86_op_modrm(state, (opcode & 2) != 0, W);
	}
	if (opcode < 0x50) { // 40H..4FH: INC/DEC or REX
		if (disasm.platform == AdbgPlatform.x86_64) {
			adbg_disasm_fetch_lasttag(disasm, AdbgDisasmTag.rex);
			//NOTE: REX cannot be used to extend VEX
			state.vex.W   = (opcode & 8) != 0;
			state.vex.RR  = (opcode & 4) != 0;
			state.vex.X   = (opcode & 2) != 0;
			state.vex.B   = (opcode & 1) != 0;
			state.has    |= x86Has.anyRex;
			if (state.vex.W)
				state.pf.data = AdbgDisasmType.i64;
			goto L_PREFIX;
		}
		if (disasm.mode >= AdbgDisasmMode.file) {
			ubyte r = opcode & 7;
			adbg_disasm_add_mnemonic(disasm, opcode >= 0x48 ? X86_DEC : X86_INC);
			adbg_disasm_add_register(disasm, x86regs[state.pf.data][r]);
		}
		return 0;
	}
	if (opcode < 0x60) { // 50H..5FH: PUSH/POP
		if (disasm.mode >= AdbgDisasmMode.file) {
			ubyte m = opcode & 7;
			if (state.vex.RR) m |= 0b1000;
			adbg_disasm_add_mnemonic(disasm, opcode < 0x58 ? X86_PUSH : X86_POP);
			adbg_disasm_add_register(disasm, x86regs[state.pf.data][m]);
		}
		return 0;
	}
	if (opcode < 0x70) { // 60H..6FH: random crap
		if (opcode < 0x62) {
			if (disasm.platform == AdbgPlatform.x86_64)
				return adbg_oops(AdbgError.illegalInstruction);
			
			if (disasm.mode < AdbgDisasmMode.file)
				return 0;
			
			bool data16 = state.pf.data == AdbgDisasmType.i16;
			if (opcode & 1)
				mnemonic = data16 ? "popa" : "popad";
			else
				mnemonic = data16 ? "pusha" : "pushad";
			adbg_disasm_add_mnemonic(disasm, mnemonic);
			return 0;
		}
		if (opcode >= 0x6c) { // INS
			W = opcode & 1;
			D = (opcode & 2) != 0;
			
			if (disasm.mode < AdbgDisasmMode.file)
				return 0;
			
			AdbgDisasmType mw = W ? state.pf.data : AdbgDisasmType.i8;
			const(char) *regbase = x86regs[state.pf.addr][x86Reg.di];
			const(char) *dx = x86regs[state.pf.data][x86Reg.dx];
			x86Seg seg = state.pf.segment;
			if (D) { // outs
				mnemonic = X86_OUTS;
				if (seg) // default if unset
					seg = x86Seg.ds;
			} else {
				mnemonic = X86_INS;
				seg = x86Seg.es;
			}
			adbg_disasm_add_mnemonic(disasm, mnemonic);
			adbg_disasm_operand_mem_t mem = void;
			adbg_disasm_set_memory(&mem, x86segs[seg], regbase, null, AdbgDisasmType.none, null, 0, false, false);
			if (D) {
				adbg_disasm_add_register(disasm, dx);
				adbg_disasm_add_memory2(disasm, mw, &mem);
			} else {
				adbg_disasm_add_memory2(disasm, mw, &mem);
				adbg_disasm_add_register(disasm, dx);
			}
			return 0;
		}
		
		switch (opcode) {
		case 0x62:
			if (disasm.platform == AdbgPlatform.x86_64) { // ANCHOR: MVEX/EVEX
				if (state.has & X86_ILLEGAL_PF_VEX)
					return adbg_oops(AdbgError.illegalInstruction);
					
				adbg_disasm_fetch_lasttag(state.disasm, AdbgDisasmTag.evex);
				
				ubyte P0 = void, P1 = void, P2 = void;
				
				e = adbg_disasm_fetch!ubyte(&P0, state.disasm, AdbgDisasmTag.evex);
				if (e) return e;
				e = adbg_disasm_fetch!ubyte(&P1, state.disasm, AdbgDisasmTag.evex);
				if (e) return e;
				e = adbg_disasm_fetch!ubyte(&P2, state.disasm, AdbgDisasmTag.evex);
				if (e) return e;
				
				if (P1 & BIT!2) { //TODO: MVEX
					ubyte mm = P0 & 15;
					
					if (mm > 2)
						return adbg_oops(AdbgError.illegalInstruction);
					
					//TODO: EVEX.b
					state.vex.LL    = ((P2 & BIT!6) == 0) | ((P2 & BIT!5) != 0);
					if (state.vex.LL == 3) // 1024-bit vector
						return adbg_oops(AdbgError.illegalInstruction);
					state.vex.RR    = (P0 < 0x80) | (((P0 & BIT!4) == 0) << 1);
					state.vex.X     = (P0 & BIT!6) == 0;
					state.vex.B     = (P0 & BIT!5) == 0;
					state.vex.W     = (P1 >= 0x80);
					state.vex.vvvv  = (P1 >> 3) & 15;
					state.vex.pp    = (P1 & 3);
					state.vex.zaaa  = P2 & 0x80; // EVEX.z
					state.vex.vvvv |= ((P2 & BIT!3) == 0) << 1; // EVEX.V'
					state.vex.zaaa |= (P2 & 7); // EVEX.aaa
					state.pf.data   = cast(AdbgDisasmType)(state.vex.LL + 7);
					state.has      |= x86Has.evex;
					
					version (Trace)
						trace("[evex] RR=%u X=%u B=%u W=%u Vvvvv=%u "~
						"mm=%u pp=%u zaaa=0x%x LL=%u",
						state.vex.RR, state.vex.X, state.vex.B, state.vex.W, state.vex.vvvv,
						mm, state.vex.pp, state.vex.zaaa, state.vex.LL);
					
					switch (mm) { // EVEX.mm
					case 1: return adbg_disasm_x86_0f(state);
					case 2: return adbg_disasm_x86_0f38(state);
					case 3: return adbg_disasm_x86_0f3a(state);
					default: return adbg_oops(AdbgError.illegalInstruction);
					}
				} else { // EVEX
					return adbg_oops(AdbgError.notImplemented);
				}
			}
			
			if (disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(disasm, "bound");
			
			return adbg_disasm_x86_op_GvMa(state);
		case 0x63: // ARPL/MOVSXD
			if (disasm.platform == AdbgPlatform.x86_64) {
				if (disasm.mode >= AdbgDisasmMode.file)
					adbg_disasm_add_mnemonic(disasm, "movsxd");
				D = true;
			} else {
				if (disasm.mode >= AdbgDisasmMode.file)
					adbg_disasm_add_mnemonic(disasm, "arpl");
				state.pf.data = AdbgDisasmType.i16;
				D = false;
			}
			return adbg_disasm_x86_op_modrm(state, D, false);
		default:
			W = opcode & 1;
			D = (opcode & 2) != 0;
			
			if (disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(disasm, W ? X86_IMUL : X86_PUSH);
			
			if (W) { // imul
				e = adbg_disasm_x86_op_modrm(state, true, true);
				if (e) return e;
			}
			
			return D ^ W ?
				adbg_disasm_x86_op_Iz(state) :
				adbg_disasm_x86_op_Ib(state);
		}
	}
	if (opcode < 0x80) { // 70H..7FH: Jcc
		if (disasm.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_mnemonic(disasm, X86_Jcc[opcode & 15]);
		return adbg_disasm_x86_op_Jb(state);
	}
	if (opcode < 0x90) { // 80H..8FH: more random stuff
		if (opcode < 0x84) // ANCHOR Group 1
			return adbg_disasm_x86_group1(state, opcode);
		if (opcode < 0x88) { // TEST/XCHG
			if (disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(disasm, opcode <= 0x86 ? X86_TEST : X86_XCHG);
			return adbg_disasm_x86_op_modrm(state, false, opcode & 1);
		}
		switch (opcode) {
		case 0x8c, 0x8e: // MOV Mw/Rv,Sw or MOV Sw,Ew
			e = adbg_disasm_fetch!ubyte(&opcode, disasm, AdbgDisasmTag.modrm);
			if (e) return e;
			
			reg  = (opcode >> 3) & 7;
			if (reg > 5)
				return adbg_oops(AdbgError.illegalInstruction);
			
			D    = opcode == 0x8e;
			mode = opcode >> 6;
			rm   = opcode & 7;
			W    = mode == 3;
			
			adbg_disasm_operand_mem_t mem = void;
			e = adbg_disasm_x86_modrm_rm(state, &mem, mode, rm);
			if (e) return e;
			
			if (disasm.mode < AdbgDisasmMode.file)
				return 0;
			
			const(char) *seg = x86segs[reg + 1];
			adbg_disasm_add_mnemonic(disasm, X86_MOV);
			if (D) {
				adbg_disasm_add_register(disasm, seg);
				if (W)
					adbg_disasm_add_register(disasm, mem.base);
				else with (AdbgDisasmType)
					adbg_disasm_add_memory2(disasm, i16, &mem);
			} else {
				if (W)
					adbg_disasm_add_register(disasm, mem.base);
				else with (AdbgDisasmType)
					adbg_disasm_add_memory2(disasm, i16, &mem);
				adbg_disasm_add_register(disasm, seg);
			}
			return 0;
		case 0x8d: // LEA Gv, M
			e = adbg_disasm_fetch!ubyte(&opcode, disasm, AdbgDisasmTag.modrm);
			if (e) return e;
			if (opcode >= 0b11000000)
				return adbg_oops(AdbgError.illegalInstruction);
			if (disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(disasm, X86_LEA);
			return adbg_disasm_x86_op_modrm2(state, opcode, true, true);
		case 0x8f: // ANCHOR Group 1a (disasmncludes XOP)
			return adbg_disasm_x86_group1a(state);
		default: // 88H..8BH: MOV EbGb/EvGv/GbEb/GvEv
			if (disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(disasm, X86_MOV);
			return adbg_disasm_x86_op_modrm(state, (opcode & 2) != 0, opcode & 1);
		}
	}
	if (opcode < 0xa0) { // 90H..9FH: XCHG or random stuff
		if (opcode < 0x98) { // XCHG
			if (disasm.mode < AdbgDisasmMode.file)
				return 0;
			if (opcode == 0x90) {
				adbg_disasm_add_mnemonic(disasm,
					state.has & x86Has.rep ? X86_PAUSE : X86_NOP);
				return 0;
			}
			adbg_disasm_add_mnemonic(disasm, X86_XCHG);
			adbg_disasm_add_register(disasm, x86regs[state.pf.data][opcode & 7]);
			adbg_disasm_add_register(disasm, x86regs[state.pf.data][x86Reg.al]);
			return 0;
		}
		switch (opcode) {
		case 0x98, 0x99:
			if (disasm.mode < AdbgDisasmMode.file)
				return 0;
			W = opcode == 0x99;
			switch (state.pf.data) with (AdbgDisasmType) {
			case i64: mnemonic = W ? X86_CQO : X86_CDQE; break;
			case i32: mnemonic = W ? X86_CDQ : X86_CWDE; break;
			default:  mnemonic = W ? X86_CWD : X86_CBW; break;
			}
			adbg_disasm_add_mnemonic(disasm, mnemonic);
			return 0;
		case 0x9a:
			if (disasm.platform == AdbgPlatform.x86_64)
				return adbg_oops(AdbgError.illegalInstruction);
			if (disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(disasm, X86_CALL);
			return adbg_disasm_x86_op_Ap(state);
		case 0x9b:
			if (disasm.mode < AdbgDisasmMode.file)
				return 0;
			adbg_disasm_add_mnemonic(disasm, X86_WAIT);
			return 0;
		case 0x9c, 0x9d: // PUSH/POP Fv
			if (disasm.mode < AdbgDisasmMode.file)
				return 0;
			W = opcode == 0x9d;
			switch (disasm.platform) with (AdbgPlatform) {
			case x86_64: mnemonic = W ? X86_POPFQ : X86_PUSHFQ; break;
			case x86_32: mnemonic = W ? X86_POPFD : X86_PUSHFD; break;
			default:     mnemonic = W ? X86_POPF  : X86_PUSHF; break;
			}
			adbg_disasm_add_mnemonic(disasm, mnemonic);
			return 0;
		default:
			if (disasm.mode < AdbgDisasmMode.file)
				return 0;
			adbg_disasm_add_mnemonic(disasm, opcode == 0x9f ? X86_LAHF : X86_SAHF);
			return 0;
		}
	}
	if (opcode < 0xb0) { // A0H..AFH: MOV/MOVS/CMPS/TEST/STOS/LODS/SCAS
		D = (opcode & 2) != 0;
		W = opcode & 1;
		AdbgDisasmType dwidth = W ? state.pf.data : AdbgDisasmType.i8;
		adbg_disasm_operand_mem_t X = void; // ES:DI
		adbg_disasm_operand_mem_t Y = void; // DS:SI
		
		if (opcode < 0xa4) { // A0..A3H: MOV
			//TODO: Dedicated function to fetch any type
			//      With this type of union
			//      Automatically added to operand list?
			union ut {
				ulong  u64;
				uint   u32;
				ushort u16;
			} ut u = void;
			
			switch (state.pf.addr) with (AdbgDisasmType) {
			case i16:
				e = adbg_disasm_fetch!ushort(&u.u16, disasm, AdbgDisasmTag.disp);
				break;
			case i32:
				e = adbg_disasm_fetch!uint(&u.u32, disasm, AdbgDisasmTag.disp);
				break;
			default:
				e = adbg_disasm_fetch!ulong(&u.u64, disasm, AdbgDisasmTag.disp);
				break;
			}
			
			if (e) return e;
			
			if (disasm.mode < AdbgDisasmMode.file)
				return 0;
			
			if (state.pf.segment == 0)
				state.pf.segment = x86Seg.ds;
			
			mnemonic = x86regs[dwidth][x86Reg.al]; // al/ax/eax
			adbg_disasm_operand_mem_t O = void;
			adbg_disasm_set_memory(&O, x86segs[state.pf.segment], null, null, state.pf.addr, &u.u64, 0, false, false);
			
			adbg_disasm_add_mnemonic(disasm, X86_MOV);
			if (D) {
				adbg_disasm_add_memory2(disasm, dwidth, &O);
				adbg_disasm_add_register(disasm, mnemonic);
			} else {
				adbg_disasm_add_register(disasm, mnemonic);
				adbg_disasm_add_memory2(disasm, dwidth, &O);
			}
			return 0;
		}
		if (opcode < 0xa8) { // A4H..A7H: MOVS/CMPS
			if (disasm.mode < AdbgDisasmMode.file)
				return 0;
			
			if (state.pf.segment == 0)
				state.pf.segment = x86Seg.ds;
			
			adbg_disasm_add_mnemonic(disasm, opcode < 0xa6 ? X86_MOVS : X86_CMPS);
			adbg_disasm_set_memory(&X, x86segs[x86Seg.es], x86regs[state.pf.addr][x86Reg.di], null, AdbgDisasmType.none, null, 0, false, false);
			adbg_disasm_set_memory(&Y, x86segs[state.pf.segment], x86regs[state.pf.addr][x86Reg.si], null, AdbgDisasmType.none, null, 0, false, false);
			if (D) {
				adbg_disasm_add_memory2(disasm, dwidth, &Y);
				adbg_disasm_add_memory2(disasm, dwidth, &X);
			} else {
				adbg_disasm_add_memory2(disasm, dwidth, &X);
				adbg_disasm_add_memory2(disasm, dwidth, &Y);
			}
			return 0;
		}
		if (opcode < 0xaa) { // A8H..A9H: TEST
			if (disasm.mode >= AdbgDisasmMode.file) {
				adbg_disasm_add_mnemonic(disasm, X86_TEST);
				adbg_disasm_add_register(disasm, x86regs[dwidth][x86Reg.al]);
			}
			return W ?
				adbg_disasm_x86_op_Iz(state) :
				adbg_disasm_x86_op_Ib(state);
		}
		// AAH..AFH: STOS/LODS/SCAS
		if (disasm.mode < AdbgDisasmMode.file)
			return 0;
		
		opcode = cast(ubyte)((opcode >> 1) - 0x55);
		adbg_disasm_add_mnemonic(disasm, X86_STR1[opcode]);
		mnemonic = x86regs[dwidth][x86Reg.al];
		
		if (D) {
			adbg_disasm_set_memory(&Y, null, x86regs[state.pf.addr][x86Reg.di], null, AdbgDisasmType.none, null, 0, false, false);
		} else {
			adbg_disasm_set_memory(&X, x86segs[state.pf.segment], x86regs[state.pf.addr][x86Reg.si], null, AdbgDisasmType.none, null, 0, false, false);
		}
		switch (opcode) {
		case 0:
			adbg_disasm_add_memory2(disasm, dwidth, &Y);
			adbg_disasm_add_register(disasm, mnemonic);
			return 0;
		case 1:
			adbg_disasm_add_register(disasm, mnemonic);
			adbg_disasm_add_memory2(disasm, dwidth, &X);
			return 0;
		default:
			adbg_disasm_add_register(disasm, mnemonic);
			adbg_disasm_add_memory2(disasm, dwidth, &Y);
			return 0;
		}
	}
	if (opcode < 0xc0) { // B0H..BFH: MOV reg, Ib/Iz
		W = opcode >= 0xb8;
		if (disasm.mode >= AdbgDisasmMode.file) {
			opcode &= 7;
			if (state.vex.B) opcode |= 0b1000;
			AdbgDisasmType dw = W ? state.pf.data : AdbgDisasmType.i8;
			adbg_disasm_add_mnemonic(disasm, X86_MOV);
			adbg_disasm_add_register(disasm, x86regs[dw][opcode]);
		}
		return W ?
			adbg_disasm_x86_op_Iz(state) :
			adbg_disasm_x86_op_Ib(state);
	}
	if (opcode < 0xd0) { // C0H..CFH: GRP2/RET/LES/LDS/GRP11/ENTER/LEAVE/INT
		ushort Iw = void;
		switch (opcode) {
		case 0xc4: // ANCHOR: VEX.3B / LES
			if (disasm.platform == AdbgPlatform.x86_64) {
				// NOTE: F0/F2/F3/66 illegal with VEX/XOP
				//       I think 67H is still premitted
				if (state.has & X86_ILLEGAL_PF_VEX)
					return adbg_oops(AdbgError.illegalInstruction);
				
				// NOTE: Could fetch by ushort but breaks the purpose of tagging
				//       Compared to what, Zydis?
				e = adbg_disasm_fetch!ubyte(&opcode, state.disasm, AdbgDisasmTag.vex);
				if (e) return e;
				e = adbg_disasm_fetch!ubyte(&rm, state.disasm, AdbgDisasmTag.vex);
				if (e) return e;
				
				// (C4H) VEX.3B: 11000100 RXBmmmmm WvvvvLpp
				state.vex.RR    = opcode < 0x80;
				state.vex.X	    = (opcode >> 6) & 1;
				state.vex.B	    = (opcode >> 5) & 1;
				state.vex.W     = rm >= 0x80;
				state.vex.vvvv  = (~cast(uint)rm >> 3) & 15;
				state.vex.LL    = (rm >> 2) & 1;
				state.vex.pp    = rm & 3;
				state.has      |= x86Has.vex;
				state.pf.select = cast(x86Select)state.vex.pp;
				with (AdbgDisasmType) state.pf.data = state.vex.LL ? i256 : i128;
				
				version (Trace)
					trace("[vex.3b] R=%u X=%u B=%u W=%u"~
					"vvvv=%u L=%u pp=%u ",
					state.vex.RR, state.vex.X, state.vex.B, state.vex.W,
					state.vex.vvvv, state.vex.LL, state.vex.pp);
				
				switch (opcode & 31) {
				case 0:  return adbg_disasm_x86_0f(state);
				case 1:  return adbg_disasm_x86_0f38(state);
				case 2:  return adbg_disasm_x86_0f3a(state);
				default: return adbg_oops(AdbgError.illegalInstruction);
				}
			}
			if (disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(disasm, X86_LES);
			return adbg_disasm_x86_op_GzMp(state);
		case 0xc5: // ANCHOR: VEX.2B / LDS
			if (disasm.platform == AdbgPlatform.x86_64) {
				if (state.has & X86_ILLEGAL_PF_VEX)
					return adbg_oops(AdbgError.illegalInstruction);
				
				e = adbg_disasm_fetch!ubyte(&opcode, state.disasm, AdbgDisasmTag.vex);
				if (e) return e;
				
				// (C5H) VEX.2B: 11000101 RvvvvLpp
				state.vex.RR    = opcode < 0x80;
				state.vex.vvvv  = (~cast(uint)opcode >> 3) & 15;
				state.vex.LL    = (opcode >> 2) & 1;
				state.vex.pp    = opcode & 3;
				state.has      |= x86Has.vex;
				state.pf.select = cast(x86Select)state.vex.pp;
				with (AdbgDisasmType) state.pf.data = state.vex.LL ? i256 : i128;
				
				version (Trace)
					trace("[vex.2b] R=%u vvvv=%u L=%u pp=%u",
					state.vex.RR, state.vex.vvvv, state.vex.LL, state.vex.pp
					);
				
				return adbg_disasm_x86_0f(state);
			}
			if (disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(disasm, X86_LDS);
			return adbg_disasm_x86_op_GzMp(state);
		case 0xc2: // RET imm16
			e = adbg_disasm_fetch!ushort(&Iw, disasm, AdbgDisasmTag.immediate);
			if (e) return e;
			if (disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_immediate(disasm, AdbgDisasmType.i16, &Iw);
			goto case;
		case 0xc3: // RET
			if (disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(disasm, X86_RET);
			return 0;
		case 0xc8: // ENTER
			e = adbg_disasm_fetch!ushort(&Iw, disasm, AdbgDisasmTag.immediate);
			if (e) return e;
			e = adbg_disasm_fetch!ubyte(&opcode, disasm, AdbgDisasmTag.immediate);
			if (e) return e;
			if (disasm.mode >= AdbgDisasmMode.file) {
				disasm.decoderNoReverse = true;
				adbg_disasm_add_mnemonic(disasm, X86_ENTER);
				adbg_disasm_add_immediate(disasm, AdbgDisasmType.i16, &Iw);
				adbg_disasm_add_immediate(disasm, AdbgDisasmType.i8, &opcode);
			}
			return 0;
		case 0xc9: // LEAVE
			if (disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(disasm, X86_LEAVE);
			return 0;
		case 0xca: // far RET Iw
			e = adbg_disasm_fetch!ushort(&Iw, disasm, AdbgDisasmTag.immediate);
			if (e) return e;
			if (disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_immediate(disasm, AdbgDisasmType.i16, &Iw);
			goto case;
		case 0xcb: // far RET
			if (disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(disasm, X86_RETF);
			return 0;
		case 0xcc: // int3
			if (disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(disasm, X86_INT3);
			return 0;
		case 0xcd: // int imm8
			e = adbg_disasm_fetch!ubyte(&opcode, disasm, AdbgDisasmTag.immediate);
			if (e) return e;
			if (disasm.mode >= AdbgDisasmMode.file) {
				adbg_disasm_add_mnemonic(disasm, X86_INT);
				adbg_disasm_add_immediate(disasm, AdbgDisasmType.i16, &opcode);
			}
			return 0;
		case 0xce: // into
			if (disasm.platform == AdbgPlatform.x86_64)
				return adbg_oops(AdbgError.illegalInstruction);
			if (disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(disasm, X86_INTO);
			return 0;
		case 0xcf: // iret/d/q
			if (disasm.mode < AdbgDisasmMode.file)
				return 0;
			switch (state.pf.data) with (AdbgDisasmType) {
			case i64: mnemonic = X86_IRETQ; break;
			case i32: mnemonic = X86_IRETD; break;
			default:  mnemonic = X86_IRET; break;
			}
			adbg_disasm_add_mnemonic(disasm, mnemonic);
			return 0;
		case 0xc0, 0xc1:
			return adbg_disasm_x86_group2(state, opcode);
		default: // C6H..C7H
			return adbg_disasm_x86_group11(state, opcode);
		}
	}
	if (opcode < 0xe0) { // D0H..DFH: GRP2/AAM/AAD/XLAT/ESCAPE
		if (opcode < 0xd4)
			return adbg_disasm_x86_group2(state, opcode);
		switch (opcode) {
		case 0xd4, 0xd5:
			if (disasm.platform == AdbgPlatform.x86_64)
				return adbg_oops(AdbgError.illegalInstruction);
			if (disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(disasm, opcode == 0xd4 ? X86_AAM : X86_AAD);
			return adbg_disasm_x86_op_Ib(state);
		case 0xd6:
			return adbg_oops(AdbgError.illegalInstruction);
		case 0xd7:
			if (disasm.mode < AdbgDisasmMode.file)
				return 0;
			if (state.pf.segment == 0)
				state.pf.segment = x86Seg.ds;
			adbg_disasm_add_mnemonic(disasm, X86_XLAT);
			adbg_disasm_add_memory(disasm, AdbgDisasmType.i8, x86segs[state.pf.segment],
				x86regs[state.pf.addr][x86Reg.bx], null, AdbgDisasmType.none, null, 0, false, false);
			return 0;
		default:
			return adbg_disasm_x86_escape(state, opcode);
		}
	}
	if (opcode < 0xf0) { // E0H..EFH: LOOP/IN/OUT/CALL/JrCXZ
		if (opcode < 0xe4) { // LOOP/JCXZ
			if (disasm.mode >= AdbgDisasmMode.file) {
				switch (opcode) {
				case 0xf0: mnemonic = X86_LOOPNE; break;
				case 0xf1: mnemonic = X86_LOOPE; break;
				case 0xf2: mnemonic = X86_LOOP; break;
				default:
					switch (disasm.platform) with (AdbgPlatform) {
					case x86_16: mnemonic = X86_JCXZ; break;
					case x86_32: mnemonic = X86_JECXZ; break;
					default:     mnemonic = X86_JRCXZ; break;
					}
				}
				adbg_disasm_add_mnemonic(disasm, mnemonic);
			}
			return adbg_disasm_x86_op_Jb(state);
		}
		bool S = opcode >= 0xec;
		if (opcode < 0xe8 || S) { // IN/OUT
			ubyte imm8 = void;
			if (S == false) {
				e = adbg_disasm_fetch!ubyte(&imm8, disasm, AdbgDisasmTag.immediate);
				if (e) return e;
			}
			
			W = opcode & 1;
			D = (opcode & 2) != 0;
			
			if (disasm.mode < AdbgDisasmMode.file)
				return 0;
			
			// Unaffected by REX
			if (state.pf.data == AdbgDisasmType.i64)
				state.pf.data = AdbgDisasmType.i32;
			mnemonic = W ? x86regs[state.pf.data][x86Reg.ax] :
				x86regs[AdbgDisasmType.i8][x86Reg.ax];
			
			adbg_disasm_add_mnemonic(disasm, D ? X86_OUT : X86_IN);
			if (S) {
				if (D) {
					adbg_disasm_add_register(disasm, x86regs[AdbgDisasmType.i16][x86Reg.dx]);
					adbg_disasm_add_register(disasm, mnemonic);
				} else {
					adbg_disasm_add_register(disasm, mnemonic);
					adbg_disasm_add_register(disasm, x86regs[AdbgDisasmType.i16][x86Reg.dx]);
				}
			} else {
				if (D) {
					adbg_disasm_add_immediate(disasm, AdbgDisasmType.i8, &imm8);
					adbg_disasm_add_register(disasm, mnemonic);
				} else {
					adbg_disasm_add_register(disasm, mnemonic);
					adbg_disasm_add_immediate(disasm, AdbgDisasmType.i8, &imm8);
				}
			}
			return 0;
		}
		// CALL/JMP
		switch (opcode) {
		case 0xe8:
			if (disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(disasm, X86_CALL);
			return adbg_disasm_x86_op_Jz(state);
		case 0xe9:
			if (disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(disasm, X86_JMP);
			return adbg_disasm_x86_op_Jz(state);
		case 0xea:
			if (disasm.platform == AdbgPlatform.x86_64)
				return adbg_oops(AdbgError.illegalInstruction);
			if (disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(disasm, X86_JMP);
			return adbg_disasm_x86_op_Ap(state);
		default: // EBH
			if (disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(disasm, X86_JMP);
			return adbg_disasm_x86_op_Jb(state);
		}
	}
	// F1H..FFH: 
	switch (opcode) {
	case 0xff: // grp5
		return adbg_disasm_x86_group5(state);
	case 0xfe: // grp4
		return adbg_disasm_x86_group4(state);
	case 0xf6,0xf7: // grp3
		return adbg_disasm_x86_group3(state, opcode);
	default:
		if (disasm.mode < AdbgDisasmMode.file)
			return 0;
		if (opcode >= 0xf8)
			mnemonic = X86_F8[opcode - 0xf8];
		else if (opcode >= 0xf4)
			mnemonic = opcode == 0xf4 ? X86_HLT : X86_CMC;
		else
			mnemonic = X86_INT1;
		adbg_disasm_add_mnemonic(disasm, mnemonic);
		return 0;
	}
}

private:

// NOTE: Prefixes
//       Byte pos      [0]      [1]      [2]      [3]
//       (4xH) REX   : 0100WRXB
//       (C5H) VEX.2B: 11000101 RvvvvLpp
//       (C4H) VEX.3B: 11000100 RXBmmmmm WvvvvLpp
//       (8FH) XOP   : 10001111 RXBmmmmm WvvvvLpp
//       (62H) EVEX  : 01100010 RXBR00mm Wvvvv1pp zLLbVaaa
//              Notes:             '      ''''     '  '
//       (62H) MVEX  : 01100010 RXBRmmmm Wvvvv0pp ESSSVkkk
//              Notes:             '      ''''        '

/// x86 internal structure
struct x86_state_t { align(1):
	adbg_disasm_t *disasm;	/// Disassembler
	uint has;	/// Has a certain prefix
	struct Prefix { align(1):
		AdbgDisasmType data;	/// Data register mode width
		AdbgDisasmType addr;	/// Address register mode width
		x86Seg segment;	/// Segment override
		x86Select select;	/// SSE/VEX instruction selector
	} Prefix pf;	/// Prefix data
	struct VEX { align(1):
		ubyte LL;	/// VEX.L/EVEX.LL vector length
				// VEX:  0=scalar/i128, 1=i256
				// EVEX: 2=i512, 3=i1024 (reserved)
		ubyte pp;	/// VEX.pp opcode extension (disasmf.select should be updated)
				// 0=NONE, 1=66H, 2=F2H, 3=F3H
		ubyte vvvv;	/// VEX.vvvv register selector
				// NOTE: Limited to 3 bits in 32/16-bit modes
		bool  W;	/// REX.W/VEX.W
				// Affects: Register width+size
				// 0=CS.D, 1=64-bit size
		ubyte RR;	/// REX.R/VEX.R/EVEX.RR ModRM.REG extension
				// VEX:  0=+0, 1=+0b1000
				// EVEX: 2=+0b1_0000, 3=Reserved
		bool  X;	/// REX.X/VEX.X
				// Affects: SIB.INDEX
		bool  B;	/// REX.B/VEX.B
				// Affects: ModRM.RM, SIB.BASE, opcode (non-CS.D?)
		ubyte zaaa;	/// EVEX.z | EVEX.aaa
	} VEX vex;	/// REX and AVX VEX/EVEX data
	bool vsib;
	private bool[3] res;
}

//
// SECTION Opcode maps
//

// ANCHOR 0f: 2-byte escape
int adbg_disasm_x86_0f(ref x86_state_t state) {
	const(char) *m = void;
	adbg_disasm_operand_mem_t mem = void;
	ubyte modrm = void;
	
	ubyte opcode = void;
	int e = adbg_disasm_fetch!ubyte(&opcode, state.disasm, AdbgDisasmTag.opcode);
	if (e) return e;
	
	if (opcode < 0x10) {
		if (state.has & x86Has.anyVex)
			return adbg_oops(AdbgError.illegalInstruction);
		
		switch (opcode) {
		case 0: return adbg_disasm_x86_group6(state);
		case 1: return adbg_disasm_x86_group7(state);
		case 2:
			if (state.disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(state.disasm, X86_LAR);
			return adbg_disasm_x86_op_modrm3(state, AdbgDisasmType.i16, true);
		case 3:
			if (state.disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(state.disasm, X86_LSL);
			return adbg_disasm_x86_op_modrm3(state, AdbgDisasmType.i16, true);
		case 5:
			if (state.disasm.platform != AdbgPlatform.x86_64)
				return adbg_oops(AdbgError.illegalInstruction);
			if (state.disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(state.disasm, X86_SYSCALL);
			return 0;
		case 6:
			if (state.disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(state.disasm, X86_CLTS);
			return 0;
		case 7:
			if (state.disasm.platform != AdbgPlatform.x86_64)
				return adbg_oops(AdbgError.illegalInstruction);
			if (state.disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(state.disasm, X86_SYSRET);
			return 0;
		case 8:
			if (state.disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(state.disasm, X86_INVD);
			return 0;
		case 9:
			if (state.disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(state.disasm,
					state.has & x86Has.rep ? X86_WBNOINVD : X86_WBINVD);
			return 0;
		case 0xb: // UD2
			if (state.disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(state.disasm, X86_UD2);
			return 0;
		case 0xd: // PREFETCH
			return adbg_disasm_x86_group_prefetch(state);
		case 0xe: // FEMMS
			if (state.disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_mnemonic(state.disasm, X86_FEMMS);
			return 0;
		case 0xf: // 3DNow!
			return adbg_disasm_x86_3dnow(state);
		default: return adbg_oops(AdbgError.illegalInstruction);
		}
	}
	if (opcode < 0x20) { // 10H..1FH:
		e = adbg_disasm_fetch!ubyte(&modrm, state.disasm, AdbgDisasmTag.modrm);
		if (e) return e;
		
		ubyte mode = modrm >> 6;
		ubyte reg  = (modrm >> 3) & 7;
		ubyte rm   = modrm & 7;
		
		if (opcode >= 0x18) {
			e = adbg_disasm_x86_modrm_rm(state, &mem, mode, rm);
			if (e) return e;
			
			switch (opcode) {
			case 0x18: return adbg_disasm_x86_group16(state, mem, reg);
			case 0x1e: // AMD
				if (mode != 3 || reg != 1 || (state.has & x86Has.rep) == 0)
					break;
				if (state.disasm.mode < AdbgDisasmMode.file)
					return 0;
				adbg_disasm_x86_modrm_reg(state, &m, reg);
				adbg_disasm_add_mnemonic(state.disasm, state.vex.W ? "rdsspq" : "rdsspd");
				adbg_disasm_add_register(state.disasm, m);
				return 0;
			default:
			}
			if (state.disasm.mode < AdbgDisasmMode.file)
				return 0;
			adbg_disasm_x86_modrm_reg(state, &m, reg);
			adbg_disasm_add_mnemonic(state.disasm, X86_NOP);
			adbg_disasm_add_memory2(state.disasm, state.pf.data, &mem);
			adbg_disasm_add_register(state.disasm, m);
			return 0;
		}
		
		static immutable const(char)* X86_M_VMOVUPS = "vmovups";
		static immutable const(char)* X86_M_VMOVUPD = "vmovupd";
		static immutable const(char)* X86_M_VMOVUSS = "vmovss";
		static immutable const(char)* X86_M_VMOVUSD = "vmovsd";
		
		switch (opcode) {
		case 0x10:
			switch (state.pf.select) with (x86Select) {
			default:
				m = X86_M_VMOVUPS;
				// Vps, Wps
				break;
			case x86Select.rep:
				m = X86_M_VMOVUPD;
				// Vpd, Wpd
				break;
			case x86Select.repne:
				m = X86_M_VMOVUSS;
				// Vx, Hx, Wss
				break;
			case x86Select.data:
				m = X86_M_VMOVUSD;
				// Vx, Hx, Wsd
				break;
			}
			break;
		case 0x11:
		case 0x12:
		case 0x13:
		case 0x14:
		case 0x15:
		case 0x16:
		default:
		}
		
		if (state.disasm.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_mnemonic(state.disasm,
				m + !(state.has & x86Has.anyVex));
		
		return adbg_oops(AdbgError.notImplemented);
	}
	if (opcode < 0x30) { // 20H..2FH:
		return adbg_oops(AdbgError.notImplemented);
	}
	if (opcode < 0x40) { // 30H..3FH:
		return adbg_oops(AdbgError.notImplemented);
	}
	if (opcode < 0x50) { // 40H..4FH: CMOVcc Gv, Ev
		if (state.has & x86Has.anyVex)
			return adbg_oops(AdbgError.illegalInstruction);
		
		static immutable const(char)*[16] x86_M_CMOVcc = [
			"cmovo", "cmovno", "cmovb", "cmovae",
			"cmove", "cmovne", "cmovbe", "cmova",
			"cmovs", "cmovns", "cmovp", "cmovnp",
			"cmovl", "cmovnl", "cmovle", "cmovnle",
		];
		
		if (state.disasm.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_mnemonic(state.disasm, x86_M_CMOVcc[opcode & 15]);
		
		return adbg_disasm_x86_op_modrm(state, true, true);
	}
	
	return adbg_oops(AdbgError.notImplemented);
}

// ANCHOR 0f 38: 3-byte escape
int adbg_disasm_x86_0f38(ref x86_state_t state) {
	
	return adbg_oops(AdbgError.notImplemented);
}

// ANCHOR 0f 3a: 3-byte escape
int adbg_disasm_x86_0f3a(ref x86_state_t state) {
	
	return adbg_oops(AdbgError.notImplemented);
}

// ANCHOR 0f 0f: 3DNow!
// 0Fh 0Fh [ModRM] [SIB] [displacement] imm8_opcode
int adbg_disasm_x86_3dnow(ref x86_state_t state) {
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(&modrm, state.disasm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	adbg_disasm_operand_mem_t mem = void;
	e = adbg_disasm_x86_modrm_rm(state, &mem, modrm >> 6, modrm & 7);
	if (e) return e;
	
	ubyte opcode = void;
	e = adbg_disasm_fetch!ubyte(&opcode, state.disasm, AdbgDisasmTag.opcode);
	if (e) return e;
	
	const(char) *m = void;
	switch (opcode) { //TODO: Find pattern for 3DNow?
	case 0xc:  m = "pi2fw"; break;
	case 0xd:  m = "pi2fd"; break;
	case 0x1c: m = "pf2iw"; break;
	case 0x1d: m = "pf2id"; break;
	case 0x8a: m = "pfnacc"; break;
	case 0x8e: m = "pfpnacc"; break;
	case 0x90: m = "pfcmpge"; break;
	case 0x94: m = "pfmin"; break;
	case 0x96: m = "pfrcp"; break;
	case 0x97: m = "pfrsqrt"; break;
	case 0x9a: m = "pfsub"; break;
	case 0x9e: m = "pfadd"; break;
	case 0xa0: m = "pfcmpgt"; break;
	case 0xa4: m = "pfmax"; break;
	case 0xa6: m = "pfrcpit1"; break;
	case 0xa7: m = "pfrsqit1"; break;
	case 0xaa: m = "pfsubr"; break;
	case 0xae: m = "pfacc"; break;
	case 0xb0: m = "pfcmpeq"; break;
	case 0xb4: m = "pfmul"; break;
	case 0xb6: m = "pfrcpit2"; break;
	case 0xb7: m = "pmulhrw"; break;
	case 0xbb: m = "pswapd"; break;
	case 0xbf: m = "pavgusb"; break;
	default: return adbg_oops(AdbgError.illegalInstruction);
	}
	
	if (state.disasm.mode < AdbgDisasmMode.file)
		return 0;
	
	adbg_disasm_add_mnemonic(state.disasm, m);
	adbg_disasm_add_register(state.disasm, x86mmx[(modrm >> 3) & 7]);
	adbg_disasm_add_memory2(state.disasm, AdbgDisasmType.i64, &mem);
	return 0;
}

// !SECTION

//
// SECTION Instruction mnemonics
// In case the compiler doesn't support string pooling
//

//TODO: Consider avoiding defining multiple symbols where possible.
//      + An array (or multiple) would reduce the number of symbols generated.
//      + Could add metadata to array (bitflags but I don't know)

// ANCHOR Legacy
immutable const(char) *X86_ADD	= "add";
immutable const(char) *X86_OR	= "or";
immutable const(char) *X86_PUSH	= "push";
immutable const(char) *X86_POP	= "pop";
immutable const(char) *X86_ADC	= "adc";
immutable const(char) *X86_SBB	= "sbb";
immutable const(char) *X86_AND	= "and";
immutable const(char) *X86_SUB	= "sub";
immutable const(char) *X86_XOR	= "xor";
immutable const(char) *X86_CMP	= "cmp";
immutable const(char) *X86_DAA	= "daa";
immutable const(char) *X86_DAS	= "das";
immutable const(char) *X86_AAA	= "aaa"; // not the battery format
immutable const(char) *X86_AAS	= "aas";
immutable const(char) *X86_INC	= "inc";
immutable const(char) *X86_DEC	= "dec";
immutable const(char) *X86_PUSHA	= "pusha";
immutable const(char) *X86_PUSHD	= "pushd";
immutable const(char) *X86_BOUND	= "bound";
immutable const(char) *X86_ARPL	= "arpl";
immutable const(char) *X86_MOVSXD	= "movsxd";
immutable const(char) *X86_IMUL	= "imul";
immutable const(char) *X86_INS	= "ins";
immutable const(char) *X86_OUTS	= "outs";
immutable const(char) *X86_JO	= "jo";
immutable const(char) *X86_JNO	= "jno";
immutable const(char) *X86_JB	= "jb";
immutable const(char) *X86_JNB	= "jnb";
immutable const(char) *X86_JZ	= "jz";
immutable const(char) *X86_JNZ	= "jnz";
immutable const(char) *X86_JBE	= "jbe";
immutable const(char) *X86_JNBE	= "jnbe";
immutable const(char) *X86_JS	= "js";
immutable const(char) *X86_JNS	= "jns";
immutable const(char) *X86_JP	= "jp";
immutable const(char) *X86_JNP	= "jnp";
immutable const(char) *X86_JL	= "jl";
immutable const(char) *X86_JNL	= "jnl";
immutable const(char) *X86_JLE	= "jle";
immutable const(char) *X86_JNLE	= "jnle";
immutable const(char) *X86_TEST	= "test";
immutable const(char) *X86_NOP	= "nop";
immutable const(char) *X86_XCHG	= "xchg";
immutable const(char) *X86_PAUSE	= "pause";
immutable const(char) *X86_MOV	= "mov";
immutable const(char) *X86_LEA	= "lea";
immutable const(char) *X86_CQO	= "cqo";
immutable const(char) *X86_CDQE	= "cdqe";
immutable const(char) *X86_CDQ	= "cdq";
immutable const(char) *X86_CWDE	= "cwde";
immutable const(char) *X86_CWD	= "cwd";
immutable const(char) *X86_CBW	= "cbw";
immutable const(char) *X86_WAIT	= "wait";
immutable const(char) *X86_CALL	= "call";
immutable const(char) *X86_POPFQ	= "popfq";
immutable const(char) *X86_PUSHFQ	= "pushfq";
immutable const(char) *X86_POPFD	= "popfd";
immutable const(char) *X86_PUSHFD	= "pushfd";
immutable const(char) *X86_POPF	= "popf";
immutable const(char) *X86_PUSHF	= "pushf";
immutable const(char) *X86_SAHF	= "sahf";
immutable const(char) *X86_LAHF	= "lahf";
immutable const(char) *X86_MOVS	= "movs";
immutable const(char) *X86_CMPS	= "cmps";
immutable const(char) *X86_STOS	= "stos";
immutable const(char) *X86_LODS	= "lods";
immutable const(char) *X86_SCAS	= "scas";
immutable const(char) *X86_ROL	= "rol";
immutable const(char) *X86_ROR	= "ror";
immutable const(char) *X86_RCL	= "rcl";
immutable const(char) *X86_RCR	= "rcr";
immutable const(char) *X86_SHL	= "shl";
immutable const(char) *X86_SHR	= "shr";
immutable const(char) *X86_SAR	= "sar";
immutable const(char) *X86_LES	= "les";
immutable const(char) *X86_LDS	= "lds";
immutable const(char) *X86_RET	= "ret";
immutable const(char) *X86_RETF	= "retf";
immutable const(char) *X86_ENTER	= "enter";
immutable const(char) *X86_LEAVE	= "leave";
immutable const(char) *X86_INT	= "int";
immutable const(char) *X86_INT3	= "int3";
immutable const(char) *X86_INTO	= "into";
immutable const(char) *X86_IRET	= "iret";
immutable const(char) *X86_IRETD	= "iretd";
immutable const(char) *X86_IRETQ	= "iretq";
immutable const(char) *X86_XABORT	= "xabort";
immutable const(char) *X86_XBEGIN	= "xbegin";
immutable const(char) *X86_AAM	= "aam";
immutable const(char) *X86_AAD	= "aad";
immutable const(char) *X86_XLAT	= "xlat";
immutable const(char) *X86_LOOPNE	= "loopne";
immutable const(char) *X86_LOOPE	= "loope";
immutable const(char) *X86_LOOP	= "loop";
immutable const(char) *X86_JCXZ	= "jcxz";
immutable const(char) *X86_JECXZ	= "jecxz";
immutable const(char) *X86_JRCXZ	= "jrcxz";
immutable const(char) *X86_IN	= "in";
immutable const(char) *X86_OUT	= "out";
immutable const(char) *X86_JMP	= "jmp";
immutable const(char) *X86_INT1	= "int1";
immutable const(char) *X86_HLT	= "hlt";
immutable const(char) *X86_CMC	= "cmc";
immutable const(char) *X86_CLC	= "clc";
immutable const(char) *X86_STC	= "stc";
immutable const(char) *X86_CLI	= "cli";
immutable const(char) *X86_STI	= "sti";
immutable const(char) *X86_CLD	= "cld";
immutable const(char) *X86_STD	= "std";
immutable const(char) *X86_NOT	= "not";
immutable const(char) *X86_NEG	= "neg";
immutable const(char) *X86_MUL	= "mul";
immutable const(char) *X86_DIV	= "div";
immutable const(char) *X86_IDIV	= "idiv";
// ANCHOR ESCAPE D8H
immutable const(char) *X86_FADD	= "fadd";
immutable const(char) *X86_FMUL	= "fmul";
immutable const(char) *X86_FCOM	= "fcom";
immutable const(char) *X86_FCOMP	= "fcomp";
immutable const(char) *X86_FSUB	= "fsub";
immutable const(char) *X86_FSUBR	= "fsubr";
immutable const(char) *X86_FDIV	= "fdiv";
immutable const(char) *X86_FDIVR	= "fdivr";
// ANCHOR ESCAPE D9H
immutable const(char) *X86_FLD	= "fld";
immutable const(char) *X86_FST	= "fst";
immutable const(char) *X86_FSTP	= "fstp";
immutable const(char) *X86_FLDENV	= "fldenv";
immutable const(char) *X86_FLDCW	= "fldcw";
immutable const(char) *X86_FSTENV	= "fstenv";
immutable const(char) *X86_FSTCW	= "fstcw";
immutable const(char) *X86_FXCH	= "fxch";
immutable const(char) *X86_FNOP	= "fnop";	// D0H
immutable const(char) *X86_FCHS	= "fchs";	// E0H
immutable const(char) *X86_FABS	= "fabs";	// E1H
immutable const(char) *X86_FTST	= "ftst";	// E4H
immutable const(char) *X86_FXAM	= "fxam";	// E5H
immutable const(char) *X86_FLD1	= "fld1";	// E8H
immutable const(char) *X86_FLDL2T	= "fldl2t";	// E9H
immutable const(char) *X86_FLDL2E	= "fldl2e";	// EAH
immutable const(char) *X86_FLDPI	= "fldpi";	// EBH
immutable const(char) *X86_FLDLG2	= "fldlg2";	// ECH
immutable const(char) *X86_FLDLN2	= "fldln2";	// EDH
immutable const(char) *X86_FLDZ	= "fldz";	// EEH
// ANCHOR ESCAPE DAH
immutable const(char) *X86_FIADD	= "fiadd";
immutable const(char) *X86_FIMUL	= "fimul";
immutable const(char) *X86_FICOM	= "ficom";
immutable const(char) *X86_FICOMP	= "ficomp";
immutable const(char) *X86_FISUB	= "fisub";
immutable const(char) *X86_FISUBR	= "fisubr";
immutable const(char) *X86_FIDIV	= "fidiv";
immutable const(char) *X86_FIDIVR	= "fidivr";
immutable const(char) *X86_FCMOVB	= "fcmovb";	// C0H..C7H
immutable const(char) *X86_FCMOVE	= "fcmove";	// C8H..CFH
immutable const(char) *X86_FCMOVBE	= "fcmovbe";	// D0H..D7H
immutable const(char) *X86_FCMOVU	= "fcmovu";	// D8H..DFH
immutable const(char) *X86_FUCOMPP	= "fucompp";	// E9H
// ANCHOR ESCAPE DBH
immutable const(char) *X86_FILD	= "fild";
immutable const(char) *X86_FISTTP	= "fisttp";
immutable const(char) *X86_FIST	= "fist";
immutable const(char) *X86_FISTP	= "fistp";
immutable const(char) *X86_FCMOVNB	= "fcmovnb";	// reg=0
immutable const(char) *X86_FCMOVNE	= "fcmovne";	// reg=1
immutable const(char) *X86_FCMOVNBE	= "fcmovnbe";	// reg=2
immutable const(char) *X86_FCMOVNU	= "fcmovnu";	// reg=3
immutable const(char) *X86_FUCOMI	= "fucomi";	// reg=5
immutable const(char) *X86_FCOMI	= "fcomi";	// reg=6
immutable const(char) *X86_FCLEX	= "fclex";	// reg=4 rm=2
immutable const(char) *X86_FINIT	= "finit";	// reg=4 rm=3
// ANCHOR ESCAPE DDH
immutable const(char) *X86_FRSTOR	= "frstor";
immutable const(char) *X86_FSAVE	= "fsave";
immutable const(char) *X86_FSTSW	= "fstsw";
immutable const(char) *X86_FFREE	= "ffree";	// reg=0
immutable const(char) *X86_FUCOM	= "fucom";	// reg=4
immutable const(char) *X86_FUCOMP	= "fucomp";	// reg=5
// ANCHOR ESCAPE DEH
immutable const(char) *X86_FADDP	= "faddp";
immutable const(char) *X86_MULP	= "mulp";
immutable const(char) *X86_SUBRP	= "subrp";
immutable const(char) *X86_SUBP	= "subp";
immutable const(char) *X86_DIVRP	= "divrp";
immutable const(char) *X86_DIVP	= "divp";
immutable const(char) *X86_FCOMPP	= "fcompp";
// ANCHOR ESCAPE DFH
immutable const(char) *X86_FBLD	= "fbld";
immutable const(char) *X86_FBSTP	= "fbstp";
immutable const(char) *X86_FUCOMIP	= "fucomip";
immutable const(char) *X86_FCOMIP	= "fcomip";
// ANCHOR MAP 0F
immutable const(char) *X86_SLDT	= "sldt";
immutable const(char) *X86_STR	= "str";
immutable const(char) *X86_LLDT	= "lldt";
immutable const(char) *X86_LTR	= "ltr";
immutable const(char) *X86_VERR	= "verr";
immutable const(char) *X86_VERW	= "verw";
immutable const(char) *X86_SGDT	= "sgdt";
immutable const(char) *X86_SIDT	= "sidt";
immutable const(char) *X86_LGDT	= "lgdt";
immutable const(char) *X86_LIDT	= "lidt";
immutable const(char) *X86_SMSW	= "smsw";
immutable const(char) *X86_LMSW	= "lmsw";
immutable const(char) *X86_INVLPG	= "invlpg";
immutable const(char) *X86_VMCALL	= "vmcall";
immutable const(char) *X86_VMLAUNCH	= "vmlaunch";
immutable const(char) *X86_VMRESUME	= "vmresume";
immutable const(char) *X86_VMXOFF	= "vmxoff";
immutable const(char) *X86_MONITOR	= "monitor";
immutable const(char) *X86_MWAIT	= "mwait";
immutable const(char) *X86_CLAC	= "clac";
immutable const(char) *X86_STAC	= "stac";
immutable const(char) *X86_ENCLS	= "encls";
immutable const(char) *X86_XGETBV	= "xgetbv";
immutable const(char) *X86_XSETBV	= "xsetbv";
immutable const(char) *X86_VMFUNC	= "vmfunc";
immutable const(char) *X86_XEND	= "xend";
immutable const(char) *X86_XTEST	= "xtest";
immutable const(char) *X86_ENCLU	= "enclu";
immutable const(char) *X86_SWAPGS	= "swapgs";
immutable const(char) *X86_RDTSCP	= "rdtscp";
immutable const(char) *X86_LAR	= "lar";
immutable const(char) *X86_LSL	= "lsl";
immutable const(char) *X86_SYSCALL	= "syscall";
immutable const(char) *X86_CLTS	= "clts";
immutable const(char) *X86_SYSRET	= "sysret";
immutable const(char) *X86_INVD	= "invd";
immutable const(char) *X86_WBNOINVD	= "wbnoinvd";
immutable const(char) *X86_WBINVD	= "wbinvd";
immutable const(char) *X86_UD2	= "ud2";
immutable const(char) *X86_FEMMS	= "femms";
// ANCHOR MAP 0F 38
// ANCHOR MAP 0F 3A

// ANCHOR Instruction tables

immutable const(char)*[8] X86_GRP1 = [ // same for <40H
	X86_ADD, X86_OR, X86_ADC, X86_SBB, X86_AND, X86_SUB, X86_XOR, X86_CMP
];
immutable const(char)*[8] X86_GRP2 = [
	X86_ROL, X86_ROR, X86_RCL, X86_RCR, X86_SHL, X86_SHR, null, X86_SAR
];
immutable const(char)*[4] X86_ASCII = [
	X86_DAA, X86_DAS, X86_AAA, X86_AAS
];
immutable const(char)*[16] X86_Jcc = [
	X86_JO, X86_JNO, X86_JB, X86_JNB, X86_JZ, X86_JNZ, X86_JBE, X86_JNBE,
	X86_JS, X86_JNS, X86_JP, X86_JNP, X86_JL, X86_JNL, X86_JLE, X86_JNLE,
];
immutable const(char)*[3] X86_STR1 = [
	X86_STOS, X86_LODS, X86_SCAS
];
immutable const(char)*[6] X86_F8 = [
	X86_CLC, X86_STC, X86_CLI, X86_STI, X86_CLD, X86_STD
];
immutable const(char)*[8] X86_X87_D8 = [
	X86_FADD, X86_FMUL, X86_FCOM, X86_FCOMP, X86_FSUB, X86_FSUBR, X86_FDIV, X86_FDIVR
];
immutable const(char)*[8] X86_X87_D9 = [
	X86_FLD, null, X86_FST, X86_FSTP, X86_FLDENV, X86_FLDCW, X86_FSTENV, X86_FSTCW
];
immutable const(char)*[8] X86_X87_DA = [
	X86_FIADD, X86_FIMUL, X86_FICOM, X86_FICOMP, X86_FISUB, X86_FISUBR, X86_FIDIV, X86_FIDIVR
];
immutable const(char)*[8] X86_X87_DB = [
	X86_FILD, X86_FISTTP, X86_FIST, X86_FISTP, null, X86_FLD, null, X86_FSTP
];
// DCH same as D8H
immutable const(char)*[8] X86_X87_DD = [
	X86_FLD, X86_FISTTP, X86_FST, X86_FSTP, X86_FRSTOR, null, X86_FSAVE, X86_FSTSW
];
immutable const(char)*[8] X86_X87_DF = [
	X86_FILD, X86_FISTTP, X86_FIST, X86_FISTP, X86_FBLD, X86_FILD, X86_FBSTP, X86_FISTP
];

// !SECTION

//
// SECTION Definitions
//

/// 
enum x86Has : uint {
	// legacy[7:0]
	data	= 1,	/// Bit_0: 66H
	addr	= 1 << 1,	/// Bit_1: 67H
	lock	= 1 << 2,	/// Bit_2: F0H
	repne	= 1 << 3,	/// Bit_3: F2H
	rep	= 1 << 4,	/// Bit_4: F3H
	anyLegacy	= 0xff,	/// Any legacy prefixes except segment overrides
	// rex[15:8]
	// NOTE: Reserved for REX.RXBW if we really need it
	//       The internal VEX fields already serve as an alias anyway.
/*	rex   = 1 << 8,	/// Bit_8: REX
	rexR	= 1 << 8,	/// Bit_8: REX.R (ModRM.reg +16)
	rexX	= 1 << 9,	/// Bit_9: REX.X (SIB.index +16)
	rexB	= 1 << 10,	/// Bit_10: REX.B (ModRM.rm|SIB.base|opcode.reg +16)
	rexW	= 1 << 11,	/// Bit_11: REX.W (64-bit register promotion)*/
	anyRex	= 0xff00,	/// Any REX bits/presence
	// vex[24:16]
	vex	= 1 << 16,	/// C4H/VEX.3B and C5H/VEX.2B prefixes
	xop	= 1 << 17,	/// 8FH/XOP prefix
	mvex	= 1 << 18,	/// 62H/MVEX prefix
	evex	= 1 << 19,	/// 62H/EVEX prefix
	anyVex	= 0xff_0000,	/// Any VEX/XOP/MVEX/EVEX prefix
	// reserved[32:25]
}

/// Illegal prefixes for VEX.2B/VEX.3B/MVEX/EVEX and possibly XOP
enum X86_ILLEGAL_PF_VEX =
	x86Has.lock | x86Has.repne | x86Has.rep | x86Has.data | x86Has.anyRex;

immutable uint[256] x86_disallow_legacy = [
/* 00 */ 0,
/* 01 */ 0,
/* 02 */ 0,
/* 03 */ 0,
/* 04 */ 0,
/* 05 */ 0,
/* 06 */ 0,
/* 07 */ 0,
/* 08 */ 0,
/* 09 */ 0,
/* 0a */ 0,
/* 0b */ 0,
/* 0c */ 0,
/* 0d */ 0,
/* 0e */ 0,
/* 0f */ 0,
/* 10 */ 0,
/* 11 */ 0,
/* 12 */ 0,
/* 13 */ 0,
/* 14 */ 0,
/* 15 */ 0,
/* 16 */ 0,
/* 17 */ 0,
/* 18 */ 0,
/* 19 */ 0,
/* 1a */ 0,
/* 1b */ 0,
/* 1c */ 0,
/* 1d */ 0,
/* 1e */ 0,
/* 1f */ 0,
/* 20 */ 0,
/* 21 */ 0,
/* 22 */ 0,
/* 23 */ 0,
/* 24 */ 0,
/* 25 */ 0,
/* 26 */ 0,
/* 27 */ 0,
/* 28 */ 0,
/* 29 */ 0,
/* 2a */ 0,
/* 2b */ 0,
/* 2c */ 0,
/* 2d */ 0,
/* 2e */ 0,
/* 2f */ 0,
/* 30 */ 0,
/* 31 */ 0,
/* 32 */ 0,
/* 33 */ 0,
/* 34 */ 0,
/* 35 */ 0,
/* 36 */ 0,
/* 37 */ 0,
/* 38 */ 0,
/* 39 */ 0,
/* 3a */ 0,
/* 3b */ 0,
/* 3c */ 0,
/* 3d */ 0,
/* 3e */ 0,
/* 3f */ 0,
/* 40 */ 0,
/* 41 */ 0,
/* 42 */ 0,
/* 43 */ 0,
/* 44 */ 0,
/* 45 */ 0,
/* 46 */ 0,
/* 47 */ 0,
/* 48 */ 0,
/* 49 */ 0,
/* 4a */ 0,
/* 4b */ 0,
/* 4c */ 0,
/* 4d */ 0,
/* 4e */ 0,
/* 4f */ 0,
/* 50 */ 0,
/* 51 */ 0,
/* 52 */ 0,
/* 53 */ 0,
/* 54 */ 0,
/* 55 */ 0,
/* 56 */ 0,
/* 57 */ 0,
/* 58 */ 0,
/* 59 */ 0,
/* 5a */ 0,
/* 5b */ 0,
/* 5c */ 0,
/* 5d */ 0,
/* 5e */ 0,
/* 5f */ 0,
/* 60 */ 0,
/* 61 */ 0,
/* 62 */ 0,
/* 63 */ 0,
/* 64 */ 0,
/* 65 */ 0,
/* 66 */ 0,
/* 67 */ 0,
/* 68 */ 0,
/* 69 */ 0,
/* 6a */ 0,
/* 6b */ 0,
/* 6c */ 0,
/* 6d */ 0,
/* 6e */ 0,
/* 6f */ 0,
/* 70 */ 0,
/* 71 */ 0,
/* 72 */ 0,
/* 73 */ 0,
/* 74 */ 0,
/* 75 */ 0,
/* 76 */ 0,
/* 77 */ 0,
/* 78 */ 0,
/* 79 */ 0,
/* 7a */ 0,
/* 7b */ 0,
/* 7c */ 0,
/* 7d */ 0,
/* 7e */ 0,
/* 7f */ 0,
/* 80 */ 0,
/* 81 */ 0,
/* 82 */ 0,
/* 83 */ 0,
/* 84 */ 0,
/* 85 */ 0,
/* 86 */ 0,
/* 87 */ 0,
/* 88 */ 0,
/* 89 */ 0,
/* 8a */ 0,
/* 8b */ 0,
/* 8c */ 0,
/* 8d */ 0,
/* 8e */ 0,
/* 8f */ 0,
/* 90 */ 0,
/* 91 */ 0,
/* 92 */ 0,
/* 93 */ 0,
/* 94 */ 0,
/* 95 */ 0,
/* 96 */ 0,
/* 97 */ 0,
/* 98 */ 0,
/* 99 */ 0,
/* 9a */ 0,
/* 9b */ 0,
/* 9c */ 0,
/* 9d */ 0,
/* 9e */ 0,
/* 9f */ 0,
/* a0 */ 0,
/* a1 */ 0,
/* a2 */ 0,
/* a3 */ 0,
/* a4 */ 0,
/* a5 */ 0,
/* a6 */ 0,
/* a7 */ 0,
/* a8 */ 0,
/* a9 */ 0,
/* aa */ 0,
/* ab */ 0,
/* ac */ 0,
/* ad */ 0,
/* ae */ 0,
/* af */ 0,
/* b0 */ 0,
/* b1 */ 0,
/* b2 */ 0,
/* b3 */ 0,
/* b4 */ 0,
/* b5 */ 0,
/* b6 */ 0,
/* b7 */ 0,
/* b8 */ 0,
/* b9 */ 0,
/* ba */ 0,
/* bb */ 0,
/* bc */ 0,
/* bd */ 0,
/* be */ 0,
/* bf */ 0,
/* c0 */ 0,
/* c1 */ 0,
/* c2 */ 0,
/* c3 */ 0,
/* c4 */ 0,
/* c5 */ 0,
/* c6 */ 0,
/* c7 */ 0,
/* c8 */ 0,
/* c9 */ 0,
/* ca */ 0,
/* cb */ 0,
/* cc */ 0,
/* cd */ 0,
/* ce */ 0,
/* cf */ 0,
/* d0 */ 0,
/* d1 */ 0,
/* d2 */ 0,
/* d3 */ 0,
/* d4 */ 0,
/* d5 */ 0,
/* d6 */ 0,
/* d7 */ 0,
/* d8 */ 0,
/* d9 */ 0,
/* da */ 0,
/* db */ 0,
/* dc */ 0,
/* dd */ 0,
/* de */ 0,
/* df */ 0,
/* e0 */ 0,
/* e1 */ 0,
/* e2 */ 0,
/* e3 */ 0,
/* e4 */ 0,
/* e5 */ 0,
/* e6 */ 0,
/* e7 */ 0,
/* e8 */ 0,
/* e9 */ 0,
/* ea */ 0,
/* eb */ 0,
/* ec */ 0,
/* ed */ 0,
/* ee */ 0,
/* ef */ 0,
/* f0 */ 0,
/* f1 */ 0,
/* f2 */ 0,
/* f3 */ 0,
/* f4 */ 0,
/* f5 */ 0,
/* f6 */ 0,
/* f7 */ 0,
/* f8 */ 0,
/* f9 */ 0,
/* fa */ 0,
/* fb */ 0,
/* fc */ 0,
/* fd */ 0,
/* fe */ 0,
/* ff */ 0,
];
immutable uint[256] x86_disallow_0f = [
/* 00 */ 0,
/* 01 */ 0,
/* 02 */ 0,
/* 03 */ 0,
/* 04 */ 0,
/* 05 */ 0,
/* 06 */ 0,
/* 07 */ 0,
/* 08 */ 0,
/* 09 */ 0,
/* 0a */ 0,
/* 0b */ 0,
/* 0c */ 0,
/* 0d */ 0,
/* 0e */ 0,
/* 0f */ 0,
/* 10 */ 0,
/* 11 */ 0,
/* 12 */ 0,
/* 13 */ 0,
/* 14 */ 0,
/* 15 */ 0,
/* 16 */ 0,
/* 17 */ 0,
/* 18 */ 0,
/* 19 */ 0,
/* 1a */ 0,
/* 1b */ 0,
/* 1c */ 0,
/* 1d */ 0,
/* 1e */ 0,
/* 1f */ 0,
/* 20 */ 0,
/* 21 */ 0,
/* 22 */ 0,
/* 23 */ 0,
/* 24 */ 0,
/* 25 */ 0,
/* 26 */ 0,
/* 27 */ 0,
/* 28 */ 0,
/* 29 */ 0,
/* 2a */ 0,
/* 2b */ 0,
/* 2c */ 0,
/* 2d */ 0,
/* 2e */ 0,
/* 2f */ 0,
/* 30 */ 0,
/* 31 */ 0,
/* 32 */ 0,
/* 33 */ 0,
/* 34 */ 0,
/* 35 */ 0,
/* 36 */ 0,
/* 37 */ 0,
/* 38 */ 0,
/* 39 */ 0,
/* 3a */ 0,
/* 3b */ 0,
/* 3c */ 0,
/* 3d */ 0,
/* 3e */ 0,
/* 3f */ 0,
/* 40 */ 0,
/* 41 */ 0,
/* 42 */ 0,
/* 43 */ 0,
/* 44 */ 0,
/* 45 */ 0,
/* 46 */ 0,
/* 47 */ 0,
/* 48 */ 0,
/* 49 */ 0,
/* 4a */ 0,
/* 4b */ 0,
/* 4c */ 0,
/* 4d */ 0,
/* 4e */ 0,
/* 4f */ 0,
/* 50 */ 0,
/* 51 */ 0,
/* 52 */ 0,
/* 53 */ 0,
/* 54 */ 0,
/* 55 */ 0,
/* 56 */ 0,
/* 57 */ 0,
/* 58 */ 0,
/* 59 */ 0,
/* 5a */ 0,
/* 5b */ 0,
/* 5c */ 0,
/* 5d */ 0,
/* 5e */ 0,
/* 5f */ 0,
/* 60 */ 0,
/* 61 */ 0,
/* 62 */ 0,
/* 63 */ 0,
/* 64 */ 0,
/* 65 */ 0,
/* 66 */ 0,
/* 67 */ 0,
/* 68 */ 0,
/* 69 */ 0,
/* 6a */ 0,
/* 6b */ 0,
/* 6c */ 0,
/* 6d */ 0,
/* 6e */ 0,
/* 6f */ 0,
/* 70 */ 0,
/* 71 */ 0,
/* 72 */ 0,
/* 73 */ 0,
/* 74 */ 0,
/* 75 */ 0,
/* 76 */ 0,
/* 77 */ 0,
/* 78 */ 0,
/* 79 */ 0,
/* 7a */ 0,
/* 7b */ 0,
/* 7c */ 0,
/* 7d */ 0,
/* 7e */ 0,
/* 7f */ 0,
/* 80 */ 0,
/* 81 */ 0,
/* 82 */ 0,
/* 83 */ 0,
/* 84 */ 0,
/* 85 */ 0,
/* 86 */ 0,
/* 87 */ 0,
/* 88 */ 0,
/* 89 */ 0,
/* 8a */ 0,
/* 8b */ 0,
/* 8c */ 0,
/* 8d */ 0,
/* 8e */ 0,
/* 8f */ 0,
/* 90 */ 0,
/* 91 */ 0,
/* 92 */ 0,
/* 93 */ 0,
/* 94 */ 0,
/* 95 */ 0,
/* 96 */ 0,
/* 97 */ 0,
/* 98 */ 0,
/* 99 */ 0,
/* 9a */ 0,
/* 9b */ 0,
/* 9c */ 0,
/* 9d */ 0,
/* 9e */ 0,
/* 9f */ 0,
/* a0 */ 0,
/* a1 */ 0,
/* a2 */ 0,
/* a3 */ 0,
/* a4 */ 0,
/* a5 */ 0,
/* a6 */ 0,
/* a7 */ 0,
/* a8 */ 0,
/* a9 */ 0,
/* aa */ 0,
/* ab */ 0,
/* ac */ 0,
/* ad */ 0,
/* ae */ 0,
/* af */ 0,
/* b0 */ 0,
/* b1 */ 0,
/* b2 */ 0,
/* b3 */ 0,
/* b4 */ 0,
/* b5 */ 0,
/* b6 */ 0,
/* b7 */ 0,
/* b8 */ 0,
/* b9 */ 0,
/* ba */ 0,
/* bb */ 0,
/* bc */ 0,
/* bd */ 0,
/* be */ 0,
/* bf */ 0,
/* c0 */ 0,
/* c1 */ 0,
/* c2 */ 0,
/* c3 */ 0,
/* c4 */ 0,
/* c5 */ 0,
/* c6 */ 0,
/* c7 */ 0,
/* c8 */ 0,
/* c9 */ 0,
/* ca */ 0,
/* cb */ 0,
/* cc */ 0,
/* cd */ 0,
/* ce */ 0,
/* cf */ 0,
/* d0 */ 0,
/* d1 */ 0,
/* d2 */ 0,
/* d3 */ 0,
/* d4 */ 0,
/* d5 */ 0,
/* d6 */ 0,
/* d7 */ 0,
/* d8 */ 0,
/* d9 */ 0,
/* da */ 0,
/* db */ 0,
/* dc */ 0,
/* dd */ 0,
/* de */ 0,
/* df */ 0,
/* e0 */ 0,
/* e1 */ 0,
/* e2 */ 0,
/* e3 */ 0,
/* e4 */ 0,
/* e5 */ 0,
/* e6 */ 0,
/* e7 */ 0,
/* e8 */ 0,
/* e9 */ 0,
/* ea */ 0,
/* eb */ 0,
/* ec */ 0,
/* ed */ 0,
/* ee */ 0,
/* ef */ 0,
/* f0 */ 0,
/* f1 */ 0,
/* f2 */ 0,
/* f3 */ 0,
/* f4 */ 0,
/* f5 */ 0,
/* f6 */ 0,
/* f7 */ 0,
/* f8 */ 0,
/* f9 */ 0,
/* fa */ 0,
/* fb */ 0,
/* fc */ 0,
/* fd */ 0,
/* fe */ 0,
/* ff */ 0,
];
immutable uint[256] x86_disallow_0f38 = [
/* 00 */ 0,
/* 01 */ 0,
/* 02 */ 0,
/* 03 */ 0,
/* 04 */ 0,
/* 05 */ 0,
/* 06 */ 0,
/* 07 */ 0,
/* 08 */ 0,
/* 09 */ 0,
/* 0a */ 0,
/* 0b */ 0,
/* 0c */ 0,
/* 0d */ 0,
/* 0e */ 0,
/* 0f */ 0,
/* 10 */ 0,
/* 11 */ 0,
/* 12 */ 0,
/* 13 */ 0,
/* 14 */ 0,
/* 15 */ 0,
/* 16 */ 0,
/* 17 */ 0,
/* 18 */ 0,
/* 19 */ 0,
/* 1a */ 0,
/* 1b */ 0,
/* 1c */ 0,
/* 1d */ 0,
/* 1e */ 0,
/* 1f */ 0,
/* 20 */ 0,
/* 21 */ 0,
/* 22 */ 0,
/* 23 */ 0,
/* 24 */ 0,
/* 25 */ 0,
/* 26 */ 0,
/* 27 */ 0,
/* 28 */ 0,
/* 29 */ 0,
/* 2a */ 0,
/* 2b */ 0,
/* 2c */ 0,
/* 2d */ 0,
/* 2e */ 0,
/* 2f */ 0,
/* 30 */ 0,
/* 31 */ 0,
/* 32 */ 0,
/* 33 */ 0,
/* 34 */ 0,
/* 35 */ 0,
/* 36 */ 0,
/* 37 */ 0,
/* 38 */ 0,
/* 39 */ 0,
/* 3a */ 0,
/* 3b */ 0,
/* 3c */ 0,
/* 3d */ 0,
/* 3e */ 0,
/* 3f */ 0,
/* 40 */ 0,
/* 41 */ 0,
/* 42 */ 0,
/* 43 */ 0,
/* 44 */ 0,
/* 45 */ 0,
/* 46 */ 0,
/* 47 */ 0,
/* 48 */ 0,
/* 49 */ 0,
/* 4a */ 0,
/* 4b */ 0,
/* 4c */ 0,
/* 4d */ 0,
/* 4e */ 0,
/* 4f */ 0,
/* 50 */ 0,
/* 51 */ 0,
/* 52 */ 0,
/* 53 */ 0,
/* 54 */ 0,
/* 55 */ 0,
/* 56 */ 0,
/* 57 */ 0,
/* 58 */ 0,
/* 59 */ 0,
/* 5a */ 0,
/* 5b */ 0,
/* 5c */ 0,
/* 5d */ 0,
/* 5e */ 0,
/* 5f */ 0,
/* 60 */ 0,
/* 61 */ 0,
/* 62 */ 0,
/* 63 */ 0,
/* 64 */ 0,
/* 65 */ 0,
/* 66 */ 0,
/* 67 */ 0,
/* 68 */ 0,
/* 69 */ 0,
/* 6a */ 0,
/* 6b */ 0,
/* 6c */ 0,
/* 6d */ 0,
/* 6e */ 0,
/* 6f */ 0,
/* 70 */ 0,
/* 71 */ 0,
/* 72 */ 0,
/* 73 */ 0,
/* 74 */ 0,
/* 75 */ 0,
/* 76 */ 0,
/* 77 */ 0,
/* 78 */ 0,
/* 79 */ 0,
/* 7a */ 0,
/* 7b */ 0,
/* 7c */ 0,
/* 7d */ 0,
/* 7e */ 0,
/* 7f */ 0,
/* 80 */ 0,
/* 81 */ 0,
/* 82 */ 0,
/* 83 */ 0,
/* 84 */ 0,
/* 85 */ 0,
/* 86 */ 0,
/* 87 */ 0,
/* 88 */ 0,
/* 89 */ 0,
/* 8a */ 0,
/* 8b */ 0,
/* 8c */ 0,
/* 8d */ 0,
/* 8e */ 0,
/* 8f */ 0,
/* 90 */ 0,
/* 91 */ 0,
/* 92 */ 0,
/* 93 */ 0,
/* 94 */ 0,
/* 95 */ 0,
/* 96 */ 0,
/* 97 */ 0,
/* 98 */ 0,
/* 99 */ 0,
/* 9a */ 0,
/* 9b */ 0,
/* 9c */ 0,
/* 9d */ 0,
/* 9e */ 0,
/* 9f */ 0,
/* a0 */ 0,
/* a1 */ 0,
/* a2 */ 0,
/* a3 */ 0,
/* a4 */ 0,
/* a5 */ 0,
/* a6 */ 0,
/* a7 */ 0,
/* a8 */ 0,
/* a9 */ 0,
/* aa */ 0,
/* ab */ 0,
/* ac */ 0,
/* ad */ 0,
/* ae */ 0,
/* af */ 0,
/* b0 */ 0,
/* b1 */ 0,
/* b2 */ 0,
/* b3 */ 0,
/* b4 */ 0,
/* b5 */ 0,
/* b6 */ 0,
/* b7 */ 0,
/* b8 */ 0,
/* b9 */ 0,
/* ba */ 0,
/* bb */ 0,
/* bc */ 0,
/* bd */ 0,
/* be */ 0,
/* bf */ 0,
/* c0 */ 0,
/* c1 */ 0,
/* c2 */ 0,
/* c3 */ 0,
/* c4 */ 0,
/* c5 */ 0,
/* c6 */ 0,
/* c7 */ 0,
/* c8 */ 0,
/* c9 */ 0,
/* ca */ 0,
/* cb */ 0,
/* cc */ 0,
/* cd */ 0,
/* ce */ 0,
/* cf */ 0,
/* d0 */ 0,
/* d1 */ 0,
/* d2 */ 0,
/* d3 */ 0,
/* d4 */ 0,
/* d5 */ 0,
/* d6 */ 0,
/* d7 */ 0,
/* d8 */ 0,
/* d9 */ 0,
/* da */ 0,
/* db */ 0,
/* dc */ 0,
/* dd */ 0,
/* de */ 0,
/* df */ 0,
/* e0 */ 0,
/* e1 */ 0,
/* e2 */ 0,
/* e3 */ 0,
/* e4 */ 0,
/* e5 */ 0,
/* e6 */ 0,
/* e7 */ 0,
/* e8 */ 0,
/* e9 */ 0,
/* ea */ 0,
/* eb */ 0,
/* ec */ 0,
/* ed */ 0,
/* ee */ 0,
/* ef */ 0,
/* f0 */ 0,
/* f1 */ 0,
/* f2 */ 0,
/* f3 */ 0,
/* f4 */ 0,
/* f5 */ 0,
/* f6 */ 0,
/* f7 */ 0,
/* f8 */ 0,
/* f9 */ 0,
/* fa */ 0,
/* fb */ 0,
/* fc */ 0,
/* fd */ 0,
/* fe */ 0,
/* ff */ 0,
];
immutable uint[256] x86_disallow_0f3a = [
/* 00 */ 0,
/* 01 */ 0,
/* 02 */ 0,
/* 03 */ 0,
/* 04 */ 0,
/* 05 */ 0,
/* 06 */ 0,
/* 07 */ 0,
/* 08 */ 0,
/* 09 */ 0,
/* 0a */ 0,
/* 0b */ 0,
/* 0c */ 0,
/* 0d */ 0,
/* 0e */ 0,
/* 0f */ 0,
/* 10 */ 0,
/* 11 */ 0,
/* 12 */ 0,
/* 13 */ 0,
/* 14 */ 0,
/* 15 */ 0,
/* 16 */ 0,
/* 17 */ 0,
/* 18 */ 0,
/* 19 */ 0,
/* 1a */ 0,
/* 1b */ 0,
/* 1c */ 0,
/* 1d */ 0,
/* 1e */ 0,
/* 1f */ 0,
/* 20 */ 0,
/* 21 */ 0,
/* 22 */ 0,
/* 23 */ 0,
/* 24 */ 0,
/* 25 */ 0,
/* 26 */ 0,
/* 27 */ 0,
/* 28 */ 0,
/* 29 */ 0,
/* 2a */ 0,
/* 2b */ 0,
/* 2c */ 0,
/* 2d */ 0,
/* 2e */ 0,
/* 2f */ 0,
/* 30 */ 0,
/* 31 */ 0,
/* 32 */ 0,
/* 33 */ 0,
/* 34 */ 0,
/* 35 */ 0,
/* 36 */ 0,
/* 37 */ 0,
/* 38 */ 0,
/* 39 */ 0,
/* 3a */ 0,
/* 3b */ 0,
/* 3c */ 0,
/* 3d */ 0,
/* 3e */ 0,
/* 3f */ 0,
/* 40 */ 0,
/* 41 */ 0,
/* 42 */ 0,
/* 43 */ 0,
/* 44 */ 0,
/* 45 */ 0,
/* 46 */ 0,
/* 47 */ 0,
/* 48 */ 0,
/* 49 */ 0,
/* 4a */ 0,
/* 4b */ 0,
/* 4c */ 0,
/* 4d */ 0,
/* 4e */ 0,
/* 4f */ 0,
/* 50 */ 0,
/* 51 */ 0,
/* 52 */ 0,
/* 53 */ 0,
/* 54 */ 0,
/* 55 */ 0,
/* 56 */ 0,
/* 57 */ 0,
/* 58 */ 0,
/* 59 */ 0,
/* 5a */ 0,
/* 5b */ 0,
/* 5c */ 0,
/* 5d */ 0,
/* 5e */ 0,
/* 5f */ 0,
/* 60 */ 0,
/* 61 */ 0,
/* 62 */ 0,
/* 63 */ 0,
/* 64 */ 0,
/* 65 */ 0,
/* 66 */ 0,
/* 67 */ 0,
/* 68 */ 0,
/* 69 */ 0,
/* 6a */ 0,
/* 6b */ 0,
/* 6c */ 0,
/* 6d */ 0,
/* 6e */ 0,
/* 6f */ 0,
/* 70 */ 0,
/* 71 */ 0,
/* 72 */ 0,
/* 73 */ 0,
/* 74 */ 0,
/* 75 */ 0,
/* 76 */ 0,
/* 77 */ 0,
/* 78 */ 0,
/* 79 */ 0,
/* 7a */ 0,
/* 7b */ 0,
/* 7c */ 0,
/* 7d */ 0,
/* 7e */ 0,
/* 7f */ 0,
/* 80 */ 0,
/* 81 */ 0,
/* 82 */ 0,
/* 83 */ 0,
/* 84 */ 0,
/* 85 */ 0,
/* 86 */ 0,
/* 87 */ 0,
/* 88 */ 0,
/* 89 */ 0,
/* 8a */ 0,
/* 8b */ 0,
/* 8c */ 0,
/* 8d */ 0,
/* 8e */ 0,
/* 8f */ 0,
/* 90 */ 0,
/* 91 */ 0,
/* 92 */ 0,
/* 93 */ 0,
/* 94 */ 0,
/* 95 */ 0,
/* 96 */ 0,
/* 97 */ 0,
/* 98 */ 0,
/* 99 */ 0,
/* 9a */ 0,
/* 9b */ 0,
/* 9c */ 0,
/* 9d */ 0,
/* 9e */ 0,
/* 9f */ 0,
/* a0 */ 0,
/* a1 */ 0,
/* a2 */ 0,
/* a3 */ 0,
/* a4 */ 0,
/* a5 */ 0,
/* a6 */ 0,
/* a7 */ 0,
/* a8 */ 0,
/* a9 */ 0,
/* aa */ 0,
/* ab */ 0,
/* ac */ 0,
/* ad */ 0,
/* ae */ 0,
/* af */ 0,
/* b0 */ 0,
/* b1 */ 0,
/* b2 */ 0,
/* b3 */ 0,
/* b4 */ 0,
/* b5 */ 0,
/* b6 */ 0,
/* b7 */ 0,
/* b8 */ 0,
/* b9 */ 0,
/* ba */ 0,
/* bb */ 0,
/* bc */ 0,
/* bd */ 0,
/* be */ 0,
/* bf */ 0,
/* c0 */ 0,
/* c1 */ 0,
/* c2 */ 0,
/* c3 */ 0,
/* c4 */ 0,
/* c5 */ 0,
/* c6 */ 0,
/* c7 */ 0,
/* c8 */ 0,
/* c9 */ 0,
/* ca */ 0,
/* cb */ 0,
/* cc */ 0,
/* cd */ 0,
/* ce */ 0,
/* cf */ 0,
/* d0 */ 0,
/* d1 */ 0,
/* d2 */ 0,
/* d3 */ 0,
/* d4 */ 0,
/* d5 */ 0,
/* d6 */ 0,
/* d7 */ 0,
/* d8 */ 0,
/* d9 */ 0,
/* da */ 0,
/* db */ 0,
/* dc */ 0,
/* dd */ 0,
/* de */ 0,
/* df */ 0,
/* e0 */ 0,
/* e1 */ 0,
/* e2 */ 0,
/* e3 */ 0,
/* e4 */ 0,
/* e5 */ 0,
/* e6 */ 0,
/* e7 */ 0,
/* e8 */ 0,
/* e9 */ 0,
/* ea */ 0,
/* eb */ 0,
/* ec */ 0,
/* ed */ 0,
/* ee */ 0,
/* ef */ 0,
/* f0 */ 0,
/* f1 */ 0,
/* f2 */ 0,
/* f3 */ 0,
/* f4 */ 0,
/* f5 */ 0,
/* f6 */ 0,
/* f7 */ 0,
/* f8 */ 0,
/* f9 */ 0,
/* fa */ 0,
/* fb */ 0,
/* fc */ 0,
/* fd */ 0,
/* fe */ 0,
/* ff */ 0,
];

/// x86 prefixes
enum x86Prefix : ubyte {
	data	= 0x66,	/// 0x66
	addr	= 0x67,	/// 0x67
	lock	= 0xf0,	/// 0xF0
	repne	= 0xf2,	/// 0xF2
	rep	= 0xf3,	/// 0xF3
	x66	= data,	/// Data operand prefix
	xf2	= repne,	/// REPNE
	xf3	= rep,	/// REP/REPE
}
/// Instruction prefix selection, Intel sequence, 0-based for optimization
enum x86Select : ubyte {
	none,
	x66,
	xf3,
	xf2,
	data  = x66,
	repne = xf2,
	rep   = xf3
}

/// Segment register overrides
enum x86Seg : ubyte {
	none, es, cs, ss, ds, fs, gs
}
/// Segment strings
immutable const(char)*[7] x86segs = [
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
//TODO: Consider splitting vector/GP registers to stop wasting space
//TODO: Consider const(char) *adbg_disasm_x86_reg(width, i)
immutable const(char)*[32][9] x86regs = [
	[], // no types
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
		"xmm0",  "xmm1",  "xmm2",  "xmm3",  "xmm4",  "xmm5",  "xmm6",  "xmm7",
		"xmm8",  "xmm9",  "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
		"xmm16", "xmm17", "xmm18", "xmm19", "xmm20", "xmm21", "xmm22", "xmm23",
		"xmm24", "xmm25", "xmm26", "xmm27", "xmm28", "xmm29", "xmm30", "xmm31"
	], [ // 256b
		"ymm0",  "ymm1",  "ymm2",  "ymm3",  "ymm4",  "ymm5",  "ymm6",  "ymm7",
		"ymm8",  "ymm9",  "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15",
		"ymm16", "ymm17", "ymm18", "ymm19", "ymm20", "ymm21", "ymm22", "ymm23",
		"ymm24", "ymm25", "ymm26", "ymm27", "ymm28", "ymm29", "ymm30", "ymm31"
	], [ // 512b
		"zmm0",  "zmm1",  "zmm2",  "zmm3",  "zmm4",  "zmm5",  "zmm6",  "zmm7",
		"zmm8",  "zmm9",  "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15",
		"zmm16", "zmm17", "zmm18", "zmm19", "zmm20", "zmm21", "zmm22", "zmm23",
		"zmm24", "zmm25", "zmm26", "zmm27", "zmm28", "zmm29", "zmm30", "zmm31"
	]
];
immutable const(char)*[2][8] x86regs16 = [ // modrm:rm16
	[ "bx", "si" ], [ "bx", "di" ], [ "bp", "si" ], [ "bp", "di" ],
	[ "si", null ], [ "di", null ], [ "bp", null ], [ "bx", null ],
];
immutable const(char)*[8] x86mmx = [ // 64b
	"mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7"
];
/*immutable const(char)*[8] x86amx = [ // Not to be confused with AVX-1024
	"tmm0", "tmm1", "tmm2", "tmm3", "tmm4", "tmm5", "tmm6", "tmm7"
];*/

// !SECTION

//
// SECTION Operand types
//

/// EbGb/EvGv/GbEb/GvEv, auto modrm
// D: 0=mem, 1=reg
// W: 0=i8, 1=i16/i32 (disasm64 if REX.W)
int adbg_disasm_x86_op_modrm(ref x86_state_t state, bool D, bool W) {
	version (Trace) trace("D=%d W=%d", D, W);
	
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(&modrm, state.disasm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	if (W == false)
		state.pf.data = AdbgDisasmType.i8;
	
	return adbg_disasm_x86_modrm(state, modrm, state.pf.data, D);
}
/// EbGb/EvGv/GbEb/GvEv, manual modrm
// D: (direction bit) 0=mem, 1=reg
// W: (wide bit) 0=i8, 1=i16/i32 (disasm64 if REX.W)
int adbg_disasm_x86_op_modrm2(ref x86_state_t state, ubyte modrm, bool D, bool W) {
	version (Trace) trace("modrm=%x D=%d W=%d", modrm, D, W);
	
	if (W == false)
		state.pf.data = AdbgDisasmType.i8;
	
	return adbg_disasm_x86_modrm(state, modrm, state.pf.data, D);
}
/// EbGb/EvGv/GbEb/GvEv, auto modrm with width
// D: 0=mem, 1=reg
int adbg_disasm_x86_op_modrm3(ref x86_state_t state, AdbgDisasmType width, bool D) {
	version (Trace) trace("width=%u D=%u", width, D);
	
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(&modrm, state.disasm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	return adbg_disasm_x86_modrm(state, modrm, width, D);
}
int adbg_disasm_x86_op_Ib(ref x86_state_t state) {	// Immediate 8-bit
	ubyte v = void;
	int e = adbg_disasm_fetch!ubyte(&v, state.disasm, AdbgDisasmTag.immediate);
	if (e) return e;
	if (state.disasm.mode >= AdbgDisasmMode.file)
		adbg_disasm_add_immediate(state.disasm, AdbgDisasmType.i8, &v);
	return 0;
}
int adbg_disasm_x86_op_Iz(ref x86_state_t state) {	// Immediate 16/32-bit
	union u_t {
		uint i32;
		ushort i16;
	}
	u_t u = void;
	int e = void;
	
	if (state.pf.data != AdbgDisasmType.i16) { // 64/32 modes
		e = adbg_disasm_fetch!uint(&u.i32, state.disasm, AdbgDisasmTag.immediate);
		if (e == 0) {
			if (state.disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_immediate(state.disasm, AdbgDisasmType.i32, &u.i32);
		}
	} else {
		e = adbg_disasm_fetch!ushort(&u.i16, state.disasm, AdbgDisasmTag.immediate);
		if (e == 0) {
			if (state.disasm.mode >= AdbgDisasmMode.file)
				adbg_disasm_add_immediate(state.disasm, AdbgDisasmType.i16, &u.i16);
		}
	}
	
	return e;
}
int adbg_disasm_x86_op_GvMa(ref x86_state_t state) {	// BOUND
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(&modrm, state.disasm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	if (modrm >= 0b11000000)
		return adbg_oops(AdbgError.illegalInstruction);
	
	adbg_disasm_operand_mem_t mem = void;
	e = adbg_disasm_x86_modrm_rm(state, &mem, modrm >> 6, (modrm >> 3) & 7);
	if (e) return e;
	
	const(char) *reg = void;
	adbg_disasm_x86_modrm_reg(state, &reg, modrm & 7);
	
	if (state.disasm.mode < AdbgDisasmMode.file)
		return 0;
	
	adbg_disasm_add_register(state.disasm, reg);
	adbg_disasm_add_memory2(state.disasm, cast(AdbgDisasmType)(state.pf.data + 1), &mem);
	return 0;
}
int adbg_disasm_x86_op_GzMp(ref x86_state_t state) { // LDS/LES
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(&modrm, state.disasm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	ubyte mode = modrm >> 6;
	if (mode == 0b11)
		return adbg_oops(AdbgError.illegalInstruction);
	
	ubyte rm = modrm & 7;
	adbg_disasm_operand_mem_t mem = void;
	e = adbg_disasm_x86_modrm_rm(state, &mem, mode, rm);
	if (e) return e;
	
	if (state.disasm.mode < AdbgDisasmMode.file)
		return 0;
	
	ubyte reg = (modrm >> 3) & 7;
	const(char) *register = void;
	adbg_disasm_x86_modrm_reg(state, &register, reg);
	adbg_disasm_add_register(state.disasm, register);
	adbg_disasm_add_memory2(state.disasm, AdbgDisasmType.far, &mem);
	return 0;
}
int adbg_disasm_x86_op_Jb(ref x86_state_t state) {	// Target immediate 8-bit
	ubyte v = void;
	int e = adbg_disasm_fetch!ubyte(&v, state.disasm, AdbgDisasmTag.immediate);
	if (e == 0) {
		if (state.disasm.mode >= AdbgDisasmMode.data)
			adbg_disasm_calc_offset!ubyte(state.disasm, v);
		if (state.disasm.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_immediate(state.disasm, AdbgDisasmType.i8, &v);
	}
	return e;
}
int adbg_disasm_x86_op_Jz(ref x86_state_t state) {	// Target immediate
	int e = void;
	switch (state.pf.data) with (AdbgDisasmType) {
	case i16:
		ushort u16 = void;
		e = adbg_disasm_fetch!ushort(&u16, state.disasm, AdbgDisasmTag.immediate);
		if (e) return e;
		if (state.disasm.mode >= AdbgDisasmMode.data)
			adbg_disasm_calc_offset!ushort(state.disasm, u16);
		if (state.disasm.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_immediate(state.disasm, i16, &u16);
		return 0;
	default:
		uint u32 = void;
		e = adbg_disasm_fetch!uint(&u32, state.disasm, AdbgDisasmTag.immediate);
		if (e) return e;
		if (state.disasm.mode >= AdbgDisasmMode.data)
			adbg_disasm_calc_offset!uint(state.disasm, u32);
		if (state.disasm.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_immediate(state.disasm, i32, &u32);
		return 0;
	}
}
int adbg_disasm_x86_op_Ap(ref x86_state_t state) {	// immediate+segment (disasmn that order)
	int e = void;
	ushort segment = void;
	void *b = void;
	if (state.pf.data == AdbgDisasmType.i16) {
		ushort a = void;
		e = adbg_disasm_fetch!ushort(&a, state.disasm, AdbgDisasmTag.immediate);
		if (e) return e;
		b = &a;
	} else {
		uint a = void;
		e = adbg_disasm_fetch!uint(&a, state.disasm, AdbgDisasmTag.immediate);
		if (e) return e;
		b = &a;
	}
	e = adbg_disasm_fetch!ushort(&segment, state.disasm, AdbgDisasmTag.segment);
	if (e) return e;
	adbg_disasm_add_immediate(state.disasm, state.pf.data, b, segment, true);
	state.disasm.decoderFar = true;
	return 0;
}

// !SECTION

//
// SECTION Operand groups
//

int adbg_disasm_x86_escape(ref x86_state_t state, ubyte opcode) {	// ANCHOR x87 escape
	immutable static const(char) *st = "st";
	version (Trace) trace("opcode=%x", opcode);
	
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(&modrm, state.disasm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	//TODO: Consider following decoding by Intel's Volume 2 Appendix B.17 format
	
	state.disasm.decoderNoReverse = true;
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
		mnemonic = X86_X87_D8[reg];
		if (regmode) goto L_REG0RM; else goto L_MEM;
	case 0xd9:
		if (regmode) {
			switch (reg) {
			case 0b000: mnemonic = X86_FLD; goto L_REG0RM;
			case 0b001: mnemonic = X86_FXCH; goto L_REG0RM;
			default:
				switch (modrm) {
				case 0xd0: mnemonic = X86_FNOP; break;
				case 0xe1: mnemonic = X86_FCHS; break;
				case 0xe2: mnemonic = X86_FABS; break;
				case 0xe4: mnemonic = X86_FTST; break;
				case 0xe5: mnemonic = X86_FXAM; break;
				case 0xe8: mnemonic = X86_FLD1; break;
				case 0xe0: mnemonic = X86_FLDL2T; break;
				case 0xea: mnemonic = X86_FLDL2E; break;
				case 0xeb: mnemonic = X86_FLDPI; break;
				case 0xec: mnemonic = X86_FLDLG2; break;
				case 0xed: mnemonic = X86_FLDLN2; break;
				case 0xee: mnemonic = X86_FLDZ; break;
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
		mnemonic = X86_X87_D9[reg];
		goto L_MEM;
	case 0xda:
		if (regmode) {
			switch (reg) {
			case 0: mnemonic = X86_FCMOVB; goto L_REG0RM;
			case 1: mnemonic = X86_FCMOVE; goto L_REG0RM;
			case 2: mnemonic = X86_FCMOVBE; goto L_REG0RM;
			case 3: mnemonic = X86_FCMOVU; goto L_REG0RM;
			default:
			}
			if (modrm != 0xe9)
				goto L_ILLEGAL;
			mnemonic = X86_FUCOMPP;
			goto L_NOOP;
		}
		width = AdbgDisasmType.i32;
		mnemonic = X86_X87_DA[reg];
		goto L_MEM;
	case 0xdb:
		if (regmode) {
			switch (reg) {
			case 0: mnemonic = X86_FCMOVNB; break;
			case 1: mnemonic = X86_FCMOVNE; break;
			case 2: mnemonic = X86_FCMOVNBE; break;
			case 3: mnemonic = X86_FCMOVNU; break;
			case 5: mnemonic = X86_FUCOMI; break;
			case 6: mnemonic = X86_FCOMI; break;
			case 4:
				switch (rm) {
				case 2: mnemonic = X86_FCLEX; break;
				case 3: mnemonic = X86_FINIT; break;
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
		mnemonic = X86_X87_DB[reg];
		goto L_MEM;
	case 0xdc:
		mnemonic = X86_X87_D8[reg];
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
			case 0: mnemonic = X86_FFREE; goto L_REGRM;
			case 2: mnemonic = X86_FST; goto L_REGRM;
			case 3: mnemonic = X86_FSTP; goto L_REGRM;
			case 4: mnemonic = X86_FUCOM; goto L_REGRM0;
			case 5: mnemonic = X86_FUCOMP; goto L_REGRM;
			default: goto L_ILLEGAL;
			}
		}
		switch (reg) {
		case 0b101: return adbg_oops(AdbgError.illegalInstruction);
		case 0b100, 0b110: width = AdbgDisasmType.none; break;
		case 0b111: width = AdbgDisasmType.i16; break;
		default: width = AdbgDisasmType.i64;
		}
		mnemonic = X86_X87_D8[reg];
		goto L_MEM;
	case 0xde:
		if (regmode) {
			switch (reg) {
			case 0: mnemonic = X86_FADDP; goto L_REGRM0;
			case 1: mnemonic = X86_MULP; goto L_REGRM0;
			case 4: mnemonic = X86_SUBRP; goto L_REGRM0;
			case 5: mnemonic = X86_SUBP; goto L_REGRM0;
			case 6: mnemonic = X86_DIVRP; goto L_REGRM0;
			case 7: mnemonic = X86_DIVP; goto L_REGRM0;
			default:
			}
			if (modrm != 0xd9)
				goto L_ILLEGAL;
			mnemonic = X86_FCOMPP;
			goto L_NOOP;
		}
		width = AdbgDisasmType.i16;
		mnemonic = X86_X87_DA[reg];
		goto L_MEM;
	default: // DFH
		if (regmode) {
			switch (reg) {
			case 4:
				if (modrm != 0xe0)
					goto L_ILLEGAL;
				mnemonic = X86_FSTSW;
				goto L_REGAX;
			case 5: mnemonic = X86_FUCOMIP; goto L_REG0RM;
			case 6: mnemonic = X86_FCOMIP; goto L_REG0RM;
			default: goto L_ILLEGAL;
			}
		}
		switch (reg) {
		case 0b100, 0b110: width = AdbgDisasmType.f80; break;
		case 0b101, 0b111: width = AdbgDisasmType.i64; break;
		default: width = AdbgDisasmType.i16;
		}
		mnemonic = X86_X87_DF[reg];
		goto L_MEM;
	}
	
L_NOOP: // no operands
	if (state.disasm.mode < AdbgDisasmMode.file)
		return 0;
	goto L_MNEMONIC;
	
L_REGAX: // AX register
	if (state.disasm.mode < AdbgDisasmMode.file)
		return 0;
	adbg_disasm_add_register(state.disasm, x86regs[AdbgDisasmType.i16][x86Reg.ax]);
	goto L_MNEMONIC;
	
L_REGRM: // st(rm)
	if (state.disasm.mode < AdbgDisasmMode.file)
		return 0;
	adbg_disasm_add_register(state.disasm, null, null, st, rm, true);
	goto L_MNEMONIC;
	
L_REG0RM: // st(0),st(rm)
	if (state.disasm.mode < AdbgDisasmMode.file)
		return 0;
	adbg_disasm_add_register(state.disasm, null, null, st, 0, true);
	adbg_disasm_add_register(state.disasm, null, null, st, rm, true);
	goto L_MNEMONIC;
	
L_REGRM0: // st(rm),st(0)
	if (state.disasm.mode < AdbgDisasmMode.file)
		return 0;
	adbg_disasm_add_register(state.disasm, null, null, st, 0, true);
	adbg_disasm_add_register(state.disasm, null, null, st, rm, true);
	goto L_MNEMONIC;

L_MEM: // memory operand
	if (state.disasm.mode < AdbgDisasmMode.file)
		return 0;
	if (state.pf.segment == 0)
		state.pf.segment = x86Seg.ds;
	adbg_disasm_add_memory(state.disasm, width, x86segs[state.pf.segment],
		x86regs[state.pf.addr][rm], null, AdbgDisasmType.none, null, 0, false, false);
	
L_MNEMONIC:
	adbg_disasm_add_mnemonic(state.disasm, mnemonic);
	return 0;
	
L_ILLEGAL:
	return adbg_oops(AdbgError.illegalInstruction);
}
int adbg_disasm_x86_group1(ref x86_state_t state, ubyte opcode) {	// ANCHOR Group 1
	if (state.disasm.platform == AdbgPlatform.x86_64 && opcode == 0x82)
		return adbg_oops(AdbgError.illegalInstruction);
	
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(&modrm, state.disasm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	//TODO: Consider function to adjust reg data width
	bool W = opcode & 1;
	if (W == false)
		state.pf.data = AdbgDisasmType.i8;
	
	ubyte mode = modrm >> 6;
	ubyte rm = modrm & 7;
	
	adbg_disasm_operand_mem_t m = void;
	e = adbg_disasm_x86_modrm_rm(state, &m, mode, rm);
	if (e) return e;
	
	if (state.disasm.mode >= AdbgDisasmMode.file) {
		adbg_disasm_add_mnemonic(state.disasm, X86_GRP1[(modrm >> 3) & 7]);
		if (mode == 3)
			adbg_disasm_add_register(state.disasm, m.base);
		else
			adbg_disasm_add_memory2(state.disasm, state.pf.data, &m);
	}
	
	return opcode != 0x81 ?
		adbg_disasm_x86_op_Ib(state) :
		adbg_disasm_x86_op_Iz(state);
}
int adbg_disasm_x86_group1a(ref x86_state_t state) {	// ANCHOR Group 1a
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(&modrm, state.disasm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	ubyte reg  = (modrm >> 3) & 7;
	if (reg) //TODO: XOP
		return adbg_oops(AdbgError.notImplemented);
	
	ubyte mode = modrm >> 6;
	ubyte rm   = modrm & 7;
	
	adbg_disasm_operand_mem_t m = void;
	e = adbg_disasm_x86_modrm_rm(state, &m, mode, rm);
	if (e) return e;
	
	if (state.disasm.mode >= AdbgDisasmMode.file) {
		adbg_disasm_add_mnemonic(state.disasm, X86_POP);
		if (mode == 3)
			adbg_disasm_add_register(state.disasm, m.base);
		else
			adbg_disasm_add_memory2(state.disasm, state.pf.data, &m);
	}
	return 0;
}
int adbg_disasm_x86_group2(ref x86_state_t state, ubyte opcode) {	// ANCHOR Group 2
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(&modrm, state.disasm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	ubyte mode = modrm >> 6;
	ubyte reg  = (modrm >> 3) & 7;
	ubyte rm   = modrm & 7;
	
	if (reg == 0b110)
		return adbg_oops(AdbgError.illegalInstruction);
	
	bool W = opcode & 1;
	if (W == false)
		state.pf.data = AdbgDisasmType.i8;
	adbg_disasm_operand_mem_t mem = void;
	e = adbg_disasm_x86_modrm_rm(state, &mem, mode, rm);
	if (e) return e;
	
	if (state.disasm.mode >= AdbgDisasmMode.file) {
		adbg_disasm_add_mnemonic(state.disasm, X86_GRP2[reg]);
		if (mode == 0b11)
			adbg_disasm_add_register(state.disasm, mem.base);
		else
			adbg_disasm_add_memory2(state.disasm, state.pf.data, &mem);
	}
	
	ubyte i8 = void;
	switch (opcode) {
	case 0xc0, 0xc1: // imm8
		e = adbg_disasm_fetch!ubyte(&i8, state.disasm, AdbgDisasmTag.immediate);
		if (e) return e;
		if (state.disasm.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_immediate(state.disasm, AdbgDisasmType.i8, &i8);
		return 0;
	case 0xd0, 0xd1: // 1
		if (state.disasm.mode >= AdbgDisasmMode.file) {
			i8 = 1;
			adbg_disasm_add_immediate(state.disasm, AdbgDisasmType.i8, &i8);
		}
		return 0;
	default: // cl
		if (state.disasm.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_register(state.disasm, x86regs[AdbgDisasmType.i8][x86Reg.cl]);
		return 0;
	}
}
int adbg_disasm_x86_group3(ref x86_state_t state, ubyte opcode) {	// ANCHOR Group 3
	immutable static const(char)*[8] X86_GRP3 =
		[ X86_TEST, X86_TEST, X86_NOT, X86_NEG, X86_MUL, X86_IMUL, X86_DIV, X86_IDIV ];
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(&modrm, state.disasm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	ubyte reg = (modrm >> 3) & 7;
	
	// NOTE: Group 3 reg=001
	//       libopcode says this is illegal
	//       Zydis and Capstone allow it as per the AMD reference
	
	ubyte rm = modrm & 7;
	ubyte mode = modrm >> 6;
	adbg_disasm_operand_mem_t mem = void;
	e = adbg_disasm_x86_modrm_rm(state, &mem, mode, rm);
	if (e) return e;
	
	bool W = opcode & 1;
	
	if (state.disasm.mode >= AdbgDisasmMode.file) {
		adbg_disasm_add_mnemonic(state.disasm, X86_GRP3[reg]);
		AdbgDisasmType width = W ? state.pf.data : AdbgDisasmType.i8;
		if (mode == 0b11)
			adbg_disasm_add_register(state.disasm, mem.base);
		else
			adbg_disasm_add_memory2(state.disasm, width, &mem);
	}
	
	if (reg < 2) {
		return W ?
			adbg_disasm_x86_op_Iz(state) :
			adbg_disasm_x86_op_Ib(state);
	}
	return 0;
}
int adbg_disasm_x86_group4(ref x86_state_t state) {	// ANCHOR Group 4
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(&modrm, state.disasm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	ubyte reg = (modrm >> 3) & 7;
	const(char) *mnemonic = void;
	switch (reg) {
	case 0: mnemonic = X86_INC; break;
	case 1: mnemonic = X86_DEC; break;
	default: return adbg_oops(AdbgError.illegalInstruction);
	}
	
	ubyte mode = modrm >> 6;
	ubyte rm   = modrm & 7;
	adbg_disasm_operand_mem_t mem = void;
	e = adbg_disasm_x86_modrm_rm(state, &mem, mode, rm);
	if (e) return e;

	if (state.disasm.mode < AdbgDisasmMode.file)
		return 0;

	adbg_disasm_add_mnemonic(state.disasm, mnemonic);
	if (mode == 3)
		adbg_disasm_add_register(state.disasm, mem.base);
	else
		adbg_disasm_add_memory2(state.disasm, AdbgDisasmType.i8, &mem);
	return 0;
}
int adbg_disasm_x86_group5(ref x86_state_t state) {	// ANCHOR Group 5
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(&modrm, state.disasm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	version (Trace) trace("modrm=%x", modrm);
	
	ubyte reg = (modrm >> 3) & 7;
	const(char) *mnemonic = void;
	bool far;
	switch (reg) {
	case 0: mnemonic = X86_INC; break;
	case 1: mnemonic = X86_DEC; break;
	case 2: mnemonic = X86_CALL;
		if (state.disasm.platform == AdbgPlatform.x86_64)
			state.pf.data = AdbgDisasmType.i64;
		break;
	case 3:
		mnemonic = X86_CALL;
		far = true;
		break;
	case 4:
		mnemonic = X86_JMP;
		if (state.disasm.platform == AdbgPlatform.x86_64)
			state.pf.data = AdbgDisasmType.i64;
		break;
	case 5:
		mnemonic = X86_JMP;
		far = true;
		break;
	case 6:
		mnemonic = X86_PUSH;
		if (state.disasm.platform == AdbgPlatform.x86_64)
			state.pf.data = AdbgDisasmType.i64;
		break;
	default: return adbg_oops(AdbgError.illegalInstruction);
	}
	
	ubyte mode = modrm >> 6;
	ubyte rm   = modrm & 7;
	adbg_disasm_operand_mem_t mem = void;
	e = adbg_disasm_x86_modrm_rm(state, &mem, mode, rm);
	if (e) return e;
	
	if (state.disasm.mode < AdbgDisasmMode.file)
		return 0;
	
	state.disasm.decoderFar = far;
	adbg_disasm_add_mnemonic(state.disasm, mnemonic);
	if (mode == 3)
		adbg_disasm_add_register(state.disasm, mem.base);
	else
		adbg_disasm_add_memory2(state.disasm, far ? AdbgDisasmType.far : state.pf.data, &mem);
	return 0;
}
int adbg_disasm_x86_group6(ref x86_state_t state) {	// ANCHOR Group 6
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(&modrm, state.disasm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	ubyte mode = modrm >> 6;
	ubyte rm   = modrm & 7;
	ubyte reg = (modrm >> 3) & 7;
	bool modeReg = mode == 3;
	
	const(char) *m = void;
	switch (reg) {
	case 0:
		with (AdbgDisasmType) state.pf.data = modeReg ? i32 : i16;
		m = X86_SLDT;
		break;
	case 1:
		with (AdbgDisasmType) state.pf.data = modeReg ? i32 : i16;
		m = X86_STR;
		break;
	case 2:
		state.pf.data = AdbgDisasmType.i16;
		m = X86_LLDT;
		break;
	case 3:
		state.pf.data = AdbgDisasmType.i16;
		m = X86_LTR;
		break;
	case 4:
		state.pf.data = AdbgDisasmType.i16;
		m = X86_VERR;
		break;
	case 5:
		state.pf.data = AdbgDisasmType.i16;
		m = X86_VERW;
		break;
	default: return adbg_oops(AdbgError.illegalInstruction);
	}
	
	adbg_disasm_operand_mem_t mem = void;
	e = adbg_disasm_x86_modrm_rm(state, &mem, mode, rm);
	if (e) return e;
	
	if (state.disasm.mode < AdbgDisasmMode.file)
		return 0;
	
	adbg_disasm_add_mnemonic(state.disasm, m);
	if (modeReg)
		adbg_disasm_add_register(state.disasm, mem.base);
	else
		adbg_disasm_add_memory2(state.disasm, state.pf.data, &mem);
	return 0;
}
int adbg_disasm_x86_group7(ref x86_state_t state) {	// ANCHOR Group 7
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(&modrm, state.disasm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	bool modeFile = state.disasm.mode >= AdbgDisasmMode.file;
	
	ubyte mode   = modrm >> 6;
	ubyte reg    = (modrm >> 3) & 7;
	ubyte rm     = modrm & 7;
	bool modeReg = mode == 3;
	
	adbg_disasm_operand_mem_t mem = void;
	
	const(char) *m = void;
	switch (reg) {
	case 0:
		if (modeReg) {
			switch (rm) {
			case 0b001: m = X86_VMCALL; break;
			case 0b010: m = X86_VMLAUNCH; break;
			case 0b011: m = X86_VMRESUME; break;
			case 0b100: m = X86_VMXOFF; break;
			default: goto L_ILLEGAL;
			}
			goto L_NONE;
		} else {
			m = X86_SGDT;
			state.pf.data = AdbgDisasmType.none;
			goto L_MEM;
		}
	case 1:
		if (modeReg) {
			switch (rm) {
			case 0b000: m = X86_MONITOR; break;
			case 0b001: m = X86_MWAIT; break;
			case 0b010: m = X86_CLAC; break;
			case 0b011: m = X86_STAC; break;
			case 0b111: m = X86_ENCLS; break;
			default: goto L_ILLEGAL;
			}
			goto L_NONE;
		} else {
			m = X86_SIDT;
			state.pf.data = AdbgDisasmType.none;
			goto L_MEM;
		}
	case 2:
		if (modeReg) {
			switch (rm) {
			case 0b000: m = X86_XGETBV; break;
			case 0b001: m = X86_XSETBV; break;
			case 0b100: m = X86_VMFUNC; break;
			case 0b101: m = X86_XEND; break;
			case 0b110: m = X86_XTEST; break;
			case 0b111: m = X86_ENCLU; break;
			default: goto L_ILLEGAL;
			}
			goto L_NONE;
		} else {
			m = X86_LGDT;
			state.pf.data = AdbgDisasmType.none;
			goto L_MEM;
		}
	case 3:
		if (modeReg) {
			goto L_ILLEGAL;
		} else {
			m = X86_LIDT;
			state.pf.data = AdbgDisasmType.none;
			goto L_MEM;
		}
	case 4:
		m = X86_SMSW;
		if (modeReg == false)
			state.pf.data = AdbgDisasmType.none;
		goto L_MEM;
	case 6:
		m = X86_LMSW;
		if (modeReg == false)
			state.pf.data = AdbgDisasmType.none;
		goto L_MEM;
	case 7:
		if (modeReg) {
			switch (rm) {
			case 0:
				if (state.disasm.platform != AdbgPlatform.x86_64)
					return adbg_oops(AdbgError.illegalInstruction);
				m = X86_INVLPG;
				break;
			case 1: m = X86_RDTSCP; break;
			default: return adbg_oops(AdbgError.illegalInstruction);
			}
			goto L_NONE;
		} else {
			m = X86_LMSW;
		}
		goto L_MEM;
	default: goto L_ILLEGAL;
	}

L_MEM:
	e = adbg_disasm_x86_modrm_rm(state, &mem, mode, rm);
	if (e) return e;
	
	if (modeFile) {
		if (modeReg)
			adbg_disasm_add_register(state.disasm, mem.base);
		else
			adbg_disasm_add_memory2(state.disasm, state.pf.data, &mem);
	}
	
L_NONE:
	if (modeFile)
		adbg_disasm_add_mnemonic(state.disasm, m);
	return 0;
	
L_ILLEGAL:
	return adbg_oops(AdbgError.illegalInstruction);
}
int adbg_disasm_x86_group8(ref x86_state_t state) {	// ANCHOR Group 8
	
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_disasm_x86_group9(ref x86_state_t state) {	// ANCHOR Group 9
	
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_disasm_x86_group10(ref x86_state_t state) {	// ANCHOR Group 10
	
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_disasm_x86_group11(ref x86_state_t state, ubyte opcode) {	// ANCHOR Group 11
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(&modrm, state.disasm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	ubyte reg  = (modrm >> 3) & 7;
	ubyte mode = modrm >> 6;
	bool c6 = opcode == 0xc6;
	
	switch (reg) {
	case 0:
		ubyte rm = modrm & 7;
		adbg_disasm_operand_mem_t mem = void;
		e = adbg_disasm_x86_modrm_rm(state, &mem, mode, rm);
		if (state.disasm.mode >= AdbgDisasmMode.file) {
			adbg_disasm_add_mnemonic(state.disasm, X86_MOV);
			if (mode == 0b11)
				adbg_disasm_add_register(state.disasm, mem.base);
			else
				adbg_disasm_add_memory2(state.disasm, state.pf.data, &mem);
		}
		break;
	case 7:
		if (mode < 0b11)
			return adbg_oops(AdbgError.illegalInstruction);
		if (state.disasm.mode >= AdbgDisasmMode.file)
			adbg_disasm_add_mnemonic(state.disasm, c6 ? X86_XABORT : X86_XBEGIN);
		break;
	default: return adbg_oops(AdbgError.illegalInstruction);
	}
	return c6 ?
		adbg_disasm_x86_op_Ib(state) :
		adbg_disasm_x86_op_Iz(state);
}
int adbg_disasm_x86_group12(ref x86_state_t state) {	// ANCHOR Group 12
	
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_disasm_x86_group13(ref x86_state_t state) {	// ANCHOR Group 13
	
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_disasm_x86_group14(ref x86_state_t state) {	// ANCHOR Group 14
	
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_disasm_x86_group15(ref x86_state_t state) {	// ANCHOR Group 15
	
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_disasm_x86_group16(ref x86_state_t state, ref adbg_disasm_operand_mem_t mem, ubyte reg) {	// ANCHOR Group 16 (disasmrefetch)
	if (state.disasm.mode < AdbgDisasmMode.file)
		return 0;
	
	const(char) *m = void;
	switch (reg) {
	case 0:  m = "prefetchnta"; break;
	case 1:  m = "prefetcht0"; break;
	case 2:  m = "prefetcht1"; break;
	case 3:  m = "prefetcht2"; break;
	default: m = "nop";
	}
	
	if (state.pf.segment == 0)
		mem.segment = x86segs[x86Seg.ds];
	
	adbg_disasm_add_mnemonic(state.disasm, m);
	adbg_disasm_add_memory2(state.disasm, AdbgDisasmType.i8, &mem);
	return 0;
}
int adbg_disasm_x86_group17(ref x86_state_t state) {	// ANCHOR Group 17
	
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_disasm_x86_group_prefetch(ref x86_state_t state) {	// ANCHOR Group PREFETCH
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(&modrm, state.disasm, AdbgDisasmTag.modrm);
	if (e) return e;
	
	ubyte mode = modrm >> 6;
	ubyte rm   = modrm & 7;
	
	adbg_disasm_operand_mem_t mem = void;
	e = adbg_disasm_x86_modrm_rm(state, &mem, mode, rm);
	if (e) return e;
	
	if (state.disasm.mode < AdbgDisasmMode.file)
		return 0;
	
	ubyte reg  = (modrm >> 3) & 7;
	
	const(char) *m = void;
	switch (reg) {
	case 1:  m = "prefetchw"; break;
	case 2:  m = "prefetchwt1"; break;
	default: m = "prefetch";
	}
	
	if (state.pf.segment == 0)
		mem.segment = x86segs[x86Seg.ds];
	
	adbg_disasm_add_mnemonic(state.disasm, m);
	adbg_disasm_add_memory2(state.disasm, AdbgDisasmType.i8, &mem);
	return 0;
}

// !SECTION

//
// SECTION ModR/M legacy mechanics
//

//TODO: modrm extraction
//      either full
//        int adbg_disasm_x86_modrm_extract(ref x86_state_t state, ref ubyte mode, ref ubyte reg, ref ubyte rm)
//      just extract
//        void adbg_disasm_x86_modrm_extract(ref ubyte mode, ref ubyte reg, ref ubyte rm, ref ubyte modrm)
//      or partial
//        ubyte adbg_disasm_x86_modrm_mode(ubyte modrm)
//        ubyte adbg_disasm_x86_modrm_reg(ubyte modrm)
//        ubyte adbg_disasm_x86_modrm_rm(ubyte modrm)
//      OR do an "extractor" with mem/reg structs

/// Processes ModR/M
/// Params:
/// 	p = Disassembler pointer.
/// 	modrm = ModR/M byte.
/// 	width = Memory operation width, different from data and address widths.
/// 	dir = If set, the register is the destination, otherwise register/memory.
/// Returns: Error code
int adbg_disasm_x86_modrm(ref x86_state_t state, ubyte modrm, AdbgDisasmType width, bool dir) {
	version (Trace) trace("modrm=%x width=%u dir=%u", modrm, width, dir);
	ubyte mode = modrm >> 6;
	ubyte reg = (modrm >> 3) & 7;
	ubyte rm = modrm & 7;
	
	// Configure register/memory stuff
	adbg_disasm_operand_mem_t mem = void;
	int e = adbg_disasm_x86_modrm_rm(state, &mem, mode, rm);
	if (e) return e;
	
	const(char) *register = void;
	adbg_disasm_x86_modrm_reg(state, &register, reg);
	
	bool regmode = mode == 3;
	
	if (dir) { // to registers
		adbg_disasm_add_register(state.disasm, register);
		if (regmode)
			adbg_disasm_add_register(state.disasm, mem.base);
		else
			adbg_disasm_add_memory2(state.disasm, width, &mem);
	} else {
		if (regmode)
			adbg_disasm_add_register(state.disasm, mem.base);
		else
			adbg_disasm_add_memory2(state.disasm, width, &mem);
		adbg_disasm_add_register(state.disasm, register);
	}
	
	return 0;
}
void adbg_disasm_x86_modrm_reg(ref x86_state_t state, const(char) **basereg, ubyte reg) {
	version (Trace) trace("reg=%x", reg);
	static immutable const(char)*[] x86regs8rex = [ "spl", "bpl", "sil", "dil" ];
	if (state.has & x86Has.anyRex && state.pf.data == AdbgDisasmType.i8) {
		if (reg >= 4 && reg <= 7) {
			*basereg = x86regs8rex[reg - 4];
			return;
		}
	}
	*basereg = x86regs[state.pf.data][reg];
}
int adbg_disasm_x86_modrm_rm(ref x86_state_t state, adbg_disasm_operand_mem_t *mem, ubyte mode, ubyte rm) {
	version (Trace) trace("mem=%p mode=%x rm=%x", mem, mode, rm);
	
	mem.segment = x86segs[state.pf.segment];
	
	// SIB mode
	if (state.disasm.platform != AdbgPlatform.x86_16 && rm == 4 && mode < 3)
		return adbg_disasm_x86_sib(state, mem, mode);
	
	mem.scale    = 0;
	mem.scaled   = false;
	mem.absolute = false;
	
	//TODO: VEX.B
	if (state.pf.addr == AdbgDisasmType.i16) {
		mem.base  = x86regs16[rm][0];
		mem.index = x86regs16[rm][1];
	} else {
		mem.base  = x86regs[state.pf.addr][rm];
		mem.index = null;
	}
	
	switch (mode) {
	case 0: // no displacement
		if (state.disasm.platform == AdbgPlatform.x86_16 && rm == 0b110) {
			mem.base = mem.index = null;
			goto case 2;
		}
		mem.hasOffset = false;
		return 0;
	case 1: // +u8 displacement
		mem.hasOffset = true;
		mem.offset.type = AdbgDisasmType.i8;
		return adbg_disasm_fetch!ubyte(&mem.offset.u8, state.disasm, AdbgDisasmTag.disp);
	case 2: // +u16/u32 displacement
		mem.hasOffset = true;
		switch (state.pf.addr) with (AdbgDisasmType) {
		case i16:
			mem.offset.type = AdbgDisasmType.i16;
			return adbg_disasm_fetch!ushort(&mem.offset.u16, state.disasm, AdbgDisasmTag.disp);
		default:
			mem.offset.type = AdbgDisasmType.i32;
			return adbg_disasm_fetch!uint(&mem.offset.u32, state.disasm, AdbgDisasmTag.disp);
		}
	default:
		adbg_disasm_x86_modrm_reg(state, &mem.base, rm);
		return 0;
	}
}
int adbg_disasm_x86_sib(ref x86_state_t state, adbg_disasm_operand_mem_t *mem, ubyte mode) {
	ubyte sib = void;
	int e = adbg_disasm_fetch!ubyte(&sib, state.disasm, AdbgDisasmTag.sib);
	if (e) return e;
	
	mem.scaled = true;
	ubyte index = (sib >> 3) & 7;
	ubyte base  = sib & 7;
	
	bool hasScaling = index != 0b100; // + index*scale
	bool noBase     = base  == 0b101; // no base
	
	if (state.vex.B) base  |= 0b1000;
	if (state.vex.X) index |= 0b1000;
	
	if (hasScaling) {
		mem.scale = 1 << (sib >> 6);
		mem.index = x86regs[state.pf.addr][index];
		mem.base  = x86regs[state.pf.addr][base];
	} else {
		mem.scale = 0;
		mem.index = null;
		mem.base  = noBase ? null : x86regs[state.pf.addr][base];
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
		return adbg_disasm_fetch!ubyte(&mem.offset.u8, state.disasm, AdbgDisasmTag.disp);
	case 2:
		mem.hasOffset = true;
		if (state.pf.addr == AdbgDisasmType.i16) {
			mem.offset.type = AdbgDisasmType.i16;
			return adbg_disasm_fetch!ushort(&mem.offset.u16, state.disasm, AdbgDisasmTag.disp);
		} else {
			mem.offset.type = AdbgDisasmType.i32;
			return adbg_disasm_fetch!uint(&mem.offset.u32, state.disasm, AdbgDisasmTag.disp);
		}
	default: assert(0);
	}
}

// !SECTION

//
// SECTION SSE/AVX mechanics
//

// Tied to instruction:
// - AVX class exceptions
// Tied to operand:
// VSIB, AVX class exceptions

immutable const(char)*[8] x86AVX512masks = [
	null, "k1", "k2", "k3", "k4", "k5", "k6", "k7",
];
immutable const(char) *x86AVX512zmask = "z";

enum x86ModrmMode : ubyte {
	/// Destination or source is register (ModRM.reg).
	reg,
	/// Destination or source is either register or memory (ModRM.rm)
	/// depending on ModRM.mode.
	rm,
	/// Destination or source is memory-only (Modrm.mode != 3).
	rmMemOnly,
	/// Destination or source is register-only.
	rmRegOnly,
}
enum x86AvxMode : ubyte {
	G,	/// Generial-purpose register (e.g., EAX)
	P,	/// MMX Register
	Q,	/// modrm: MMX Register or memory
	U,	/// modrm: AVX Register from ModRM.rm
	V,	/// modrm: AVX Register from ModRM.reg
	W,	/// modrm: AVX Register or memory
	I,	/// Immediate
	H,	/// Non-desctructive register from VEX.vvvv (unset=#UB)
	L,	/// imm8[7:4] is AVX register
}
enum x86AvxWidth : ubyte { // Used to override MMX/SSE/AVX widths
	s,	/// i32 - Single-precision
	ss,	/// i32
	ps,	/// i32
	d,	/// i64
	sd,	/// i64
	pd,	/// i64
}

enum x86AVXOpFlag : ushort { // Added to internal state
	vsib	= BIT!0,
	/*addIb	= BIT!8,
	addH	= BIT!9,
	addLx	= BIT!10,*/
}

struct x86Operand {
	alias full this;
	union {
		int full;
		struct {
			x86AvxWidth width;
			x86AvxMode mode;
		}
	}
}

template AVXOP(x86AvxMode mode, x86AvxWidth width) {
	enum uint AVXOP = mode << 8 | width;
}

enum {
	Vss	= AVXOP!(x86AvxMode.V, x86AvxWidth.ss),
}

/// AVX Exception Classes
// NOTE: Embedded broadcast is not supported with the ".nb" suffix
enum x86AVXEx : ubyte { // Fault suppression depends on Mem operand
	none,	/// 
	E1,	/// Type 1, Vector Moves/Load/Stores, with fault suppression
	E1NF,	/// Type 1, Vector Non-temporal Stores, No Fault suppression
	E2,	/// Type 2, FP Vector Load+op, supports fault suppression
	E2NF,	/// Type 2, FP Vector Load+op, No Fault suppression
	E3,	/// Type 3, FP Scalar/Partial Vector, Load+Op, supports fault suppression
	E3NF,	/// Type 3, FP Scalar/Partial Vector, Load+Op, No Fault suppression
	E4,	/// Type 4, Integer Vector Load+op, supports fault suppression
	E4nb,	/// Type 4, Integer Vector Load+op, supports fault suppression + .nb prefix
	E4NF,	/// Type 4, Integer Vector Load+op, No Fault suppression
	E4NFnb,	/// Type 4, Integer Vector Load+op, No Fault suppression + .nb prefix
	E5,	/// Type 5, Legacy-like Promotion, supports fault suppression
	E5NF,	/// Type 5, Legacy-like Promotion, No Fault suppression
	E6,	/// Type 6, supports fault suppression
	E6NF,	/// Type 6, No Fault suppression
	E7NM128,	/// Type 7, No Memory
	E8NM,	/// Type 8, No Memory
	E9,	/// Type 9, supports fault suppression
	E9NF,	/// Type 9, No Fault suppression
	E10,	/// Type 10,
	E10NF,	/// Type 10,
	E11,	/// Type 11,
	E12,	/// Type 12,
}

int adbg_disasm_x86_op_Lx(ref x86_state_t state) {
	ubyte reg = void;
	int e = adbg_disasm_fetch!ubyte(&reg, state.disasm, AdbgDisasmTag.immediate);
	if (e) return e;
	
	if (state.disasm.mode < AdbgDisasmMode.file)
		return 0;
	
	adbg_disasm_add_register(state.disasm, x86regs[state.pf.data][reg >> 4]);
	return 0;
}

// Check state with AVX exception class
int adbg_disasm_x86_avx_check(ref x86_state_t state, x86AVXEx exception) {
	
	return adbg_oops(AdbgError.notImplemented);
}

// Process SSE/AVX operands
//TODO: Consider variadic function that builds struct with int len + int[4]?
int adbg_disasm_x86_ops_avx(ref x86_state_t state, immutable(int)[] operands) {
	bool lx; // Lx
	bool h;  // Hx
	
	/+const(char) *regstr = void;
	int e = void;
	
	// NOTE: Per mode indicate mode dependong on SSE/AVX (?)
	foreach (int operand; operands) {
		x86Operand op = void;
		op.full = operand;
		
		switch (op.mode) with (x86AvxMode) {
		case V:
			adbg_disasm_x86_modrm_reg(state, &regstr, reg);
			if (modeFile)
				adbg_disasm_add_register(state.disasm,
					regstr,
					x86masks[state.vex.zaaa & 7],
					state.vex.zaaa >= 0x80 ? x86zmask : null);
			break;
		case W:
			e = adbg_disasm_x86_modrm_rm(state, &amem, mod, rm);
			if (e) return e;
			if (modeFile) {
				if (mod == 3)
					adbg_disasm_add_register(state.disasm, amem.base);
				else
					adbg_disasm_add_memory2(state.disasm, state.pf.data, &amem);
			}
			break;
		case L:
			return adbg_disasm_x86_op_Lx(state);
		default: return adbg_oops(AdbgError.fault);
		}
	}+/
	
	return adbg_oops(AdbgError.notImplemented);
}

int adbg_disasm_x86_op_avx(ref x86_state_t state, ushort oprnd) {
	ubyte modrm = void; // used when op is modrm
	
	/*immutable(x86AvxMeta)* op = &x86AVXOps[index - 1];
	
	switch (op.mode) with (x86VexMode) {
	case V:
		adbg_disasm_x86_modrm_reg(disasm, &areg, reg);
		if (modeFile)
			adbg_disasm_add_register(state.disasm,
				areg,
				x86masks[state.vex.zaaa & 7],
				state.vex.zaaa >= 0x80 ? x86zmask : null);
		break;
	case W:
		e = adbg_disasm_x86_modrm_rm(disasm, &amem, mod, rm);
		if (e) return e;
		if (modeFile) {
			if (mod == 3)
				adbg_disasm_add_register(state.disasm, amem.base);
			else
				adbg_disasm_add_memory2(state.disasm, state.pf.data, &amem);
		}
		break;
	default: return adbg_oops(AdbgError.softAssert);
	}*/
	
	
	return adbg_oops(AdbgError.notImplemented);
}

int adbg_disasm_x86_op_avx_modrm(ref x86_state_t state, ubyte modrm) {
	ubyte mod  = modrm >> 6;
	ubyte reg  = (modrm >> 3) & 7;
	ubyte rm   = modrm & 7;
	
	
	
	return adbg_oops(AdbgError.notImplemented);
}
int adbg_disasm_x86_op_avx_sib(ref x86_state_t state, ubyte sib) {
	// VSIB: Using XMM/YMM as base
	// - Any VEX prefix is used
	// - 32-bit: illegal if address override to 16-bit
	// - 16-bit: permitted if address override to 32-bit
	
	return adbg_oops(AdbgError.notImplemented);
}

/*deprecated
int adbg_disasm_x86_op_vex_modrm(ref x86_state_t state, uint ops) {
	ubyte modrm = void;
	int e = adbg_disasm_fetch!ubyte(state.disasm, &modrm, AdbgDisasmTag.modrm);
	return e ? e : adbg_disasm_x86_op_vex_modrm2(disasm, ops, modrm);
}
deprecated
int adbg_disasm_x86_op_vex_modrm2(ref x86_state_t state, uint ops, ubyte modrm) {
	version (Trace) trace("ops=0x%x modrm=%x", ops, modrm);
	
	adbg_disasm_operand_mem_t amem = void;
	const(char) *areg = void;
	
	int e = void;
	ubyte dstMode = (ops >> 12) & 15;
	ubyte dstType = (ops >> 8) & 15;
	ubyte srcMode = (ops >> 4) & 15;
	ubyte srcType = ops & 15;
	ubyte mod  = modrm >> 6;
	ubyte reg  = (modrm >> 3) & 7;
	ubyte rm   = modrm & 7;
	bool modeFile   = state.disasm.mode >= AdbgDisasmMode.file;
	bool dstReg = (ops & x86VexFlag.dir) != 0;
	bool modeVex = (state.has & x86Has.anyVex) != 0;
	
	if (modeVex == false) {
		state.pf.data = AdbgDisasmType.i128;
	}
	
	//TODO: VSIB
	//      reg,vvvv,rm -> reg,rm(vvvv)
	
	// destination
	switch (dstMode) with (x86VexMode) {
	case V:
		adbg_disasm_x86_modrm_reg(disasm, &areg, reg);
		if (modeFile)
			adbg_disasm_add_register(state.disasm,
				areg,
				x86masks[state.vex.zaaa & 7],
				state.vex.zaaa >= 0x80 ? x86zmask : null);
		break;
	case W:
		e = adbg_disasm_x86_modrm_rm(disasm, &amem, mod, rm);
		if (e) return e;
		if (modeFile) {
			if (mod == 3)
				adbg_disasm_add_register(state.disasm, amem.base);
			else
				adbg_disasm_add_memory2(state.disasm, state.pf.data, &amem);
		}
		break;
	default: return adbg_oops(AdbgError.softAssert);
	}
	
	// non-destructive source
	ubyte midType = (ops >> 16) & 15;
	if (modeVex && midType) {
		adbg_disasm_x86_modrm_reg(disasm, &areg, state.vex.vvvv);
		if (modeFile)
			adbg_disasm_add_register(state.disasm, areg);
	}
	
	// source
	switch (srcMode) with (x86VexMode) {
	case V:
		adbg_disasm_x86_modrm_reg(disasm, &areg, reg);
		if (modeFile)
			adbg_disasm_add_register(state.disasm, areg);
		break;
	case W:
		e = adbg_disasm_x86_modrm_rm(disasm, &amem, mod, rm);
		if (e) return e;
		if (modeFile) {
			if (mod == 3)
				adbg_disasm_add_register(state.disasm, amem.base);
			else
				adbg_disasm_add_memory2(state.disasm, state.pf.data, &amem);
		}
		break;
	default: return adbg_oops(AdbgError.softAssert);
	}
	
	// extras
	if (ops & x86VexFlag.Lx) {
		e = adbg_disasm_x86_op_Lx(disasm);
		if (e) return e;
	}
	
	if (ops & x86VexFlag.Ib)
		return adbg_disasm_x86_op_Ib(disasm);
	
	return 0;
}*/

// !SECTION