/**
 * x86-32 disassembler.
 *
 * License: BSD 3-Clause
 */
module adbg.debugger.disasm.arch.x86;

import adbg.debugger.disasm.disasm;
import adbg.debugger.disasm.formatter;
import adbg.utils.str;

extern (C):

struct x86_internals_t {
	align(2) ubyte op;	/// Last significant opcode
	ushort lock;	/// LOCK Prefix
	ushort last_prefix;	/// Last effective prefix for 0f (F2H/F3H)
	ushort segreg;	/// Last selected segment register
	ushort pf_operand; /// 66H Operand prefix
	ushort pf_address; /// 67H Address prefix
	/// VEX prefix    [0]      [1]      [2]      [3]
	/// (C5H) VEX.2B: 11000101 RvvvvLpp
	/// (C4H) VEX.3B: 11000100 RXBmmmmm WvvvvLpp
	/// (8FH) XOP   : 10001111 RXBmmmmm WvvvvLpp
	/// (62H) EVEX  : 01100010 RXBR00mm Wvvvv1pp zLLbVaa
	//          Note:             R'              L' V'
	union {
		uint vex32;
		ubyte[4] vex;
	}
	// VEX pre-calculated values
	// NOTE: REX/VEX.{WRXB} fields are ignored
	ushort vex_L;	/// VEX vector length (128b/scalar, 256b)
	ushort vex_pp;	/// VEX opcode extension (NONE, 66H, F2H, F3H)
	ushort vex_vvvv;	/// VEX register
}

//TODO: Condense vex maps into legacy maps
//      + Binary size reduction
//      - One more tiny check
//TODO: Adjust float memory widths
//TODO: Consider making templates to inline certain oprations
//TODO: Opcode function table (see version ADBG_DASM_X86_NEW)

//version = ADBG_DASM_X86_NEW;

version (ADBG_DASM_X86_NEW) {
__gshared void function(disasm_params_t*)[64] x86_table = [
	// 00H-3FH
	&adbg_dasm_x86_grp1, &adbg_dasm_x86_grp2, &adbg_dasm_x86_grp1, &adbg_dasm_x86_grp2,
	&adbg_dasm_x86_grp1, &adbg_dasm_x86_grp2, &adbg_dasm_x86_grp1, &adbg_dasm_x86_grp2,
	&adbg_dasm_x86_grp1, &adbg_dasm_x86_grp2, &adbg_dasm_x86_grp1, &adbg_dasm_x86_grp2,
	&adbg_dasm_x86_grp1, &adbg_dasm_x86_grp2, &adbg_dasm_x86_grp1, &adbg_dasm_x86_grp2,
	// 40H-5FH
	&adbg_dasm_x86_grp3, &adbg_dasm_x86_grp3, &adbg_dasm_x86_grp3, &adbg_dasm_x86_grp3,
	&adbg_dasm_x86_grp3, &adbg_dasm_x86_grp3, &adbg_dasm_x86_grp3, &adbg_dasm_x86_grp3,
	// 60H-6FH
	
	// 70H-7FH (Jcc)
	&adbg_dasm_x86_grp7, &adbg_dasm_x86_grp7, &adbg_dasm_x86_grp7, &adbg_dasm_x86_grp7,
	// 80H-
];

void adbg_dasm_x86(disasm_params_t *p, bool init = true) {
	if (init) {
		x86_internals_t i;
		p.x86 = &i;
	}

L_CONTINUE:
	p.x86.op = *p.ai8;
	++p.ai8;

	if (p.mode >= DisasmMode.File)
		adbg_dasm_push_x8(p, p.x86.op);

	x86_table[p.x86.op >> 2](p);
}

private:

void adbg_dasm_x86_grp1(disasm_params_t *p) {
	if (p.mode >= DisasmMode.File)
		adbg_dasm_push_str(p, x86_T_grp1[p.x86.op >> 3]);
	adbg_dasm_x86_modrm(p, X86_FLAG_USE_OP);
}

void adbg_dasm_x86_grp2(disasm_params_t *p) {
	int opr = (p.x86.op & MODRM_REG) >> 3;

	if (p.x86.op & X86_FLAG_DIR) {
		if (opr == 0b001) {
			adbg_dasm_x86_0f(p);
			return;
		}
		if (p.mode >= DisasmMode.File) {
			adbg_dasm_push_str(p, p.x86.op & X86_FLAG_WIDE ? "pop" : "push");
			adbg_dasm_push_reg(p, x86_T_segs[opr]);
		}
	} else {
		if (p.mode >= DisasmMode.File) {
			adbg_dasm_push_str(p, x86_T_grp1[opr]);
			adbg_dasm_push_reg(p, adbg_dasm_x86_eax(p, p.x86.op));
		}
		if (p.x86.op & X86_FLAG_WIDE)
			adbg_dasm_x86_u32imm(p);
		else
			adbg_dasm_x86_u8imm(p);
	}
}

void adbg_dasm_x86_grp3(disasm_params_t *p) {
	if (p.mode >= DisasmMode.File) {
		adbg_dasm_push_str(p, x86_T_40h[(p.x86.op >> 4) & 3]);
		adbg_dasm_push_reg(p,
			adbg_dasm_x86_modrm_reg(p, p.x86.op, MemWidth.i32));
	}
}


void adbg_dasm_x86_grp7(disasm_params_t *p) {
	if (p.mode >= DisasmMode.File)
		adbg_dasm_push_str(p, x86_T_Jcc[p.x86.op & 15]);
	adbg_dasm_x86_u8imm(p);
}

} else
/**
 * x86 disassembler.
 * Params:
 * 	p = Disassembler parameters
 * 	init = Initiate structure (x86_16 sets this to false and preps its own)
 */
void adbg_dasm_x86(disasm_params_t *p, bool init = true) {
	if (init) {
		x86_internals_t i;
		p.x86 = &i;
	}

L_CONTINUE:
	p.x86.op = *p.ai8;
	++p.ai8;

	if (p.mode >= DisasmMode.File)
		adbg_dasm_push_x8(p, p.x86.op);

	switch (p.x86.op & 252) { // 1111_1100
	// 00H-03H, 08H-0BH, 10H-13H, 18-1BH, 20H-23H, 28H-2BH, 30H-33H, 38H-3BH
	case 0, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38:
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, x86_T_grp1[p.x86.op >> 3]);
		adbg_dasm_x86_modrm(p, X86_FLAG_USE_OP);
		return;
	case 0x04: // 04H-07H
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.mode >= DisasmMode.File) {
				adbg_dasm_push_str(p, p.x86.op & X86_FLAG_WIDE ? "pop" : "push");
				adbg_dasm_push_reg(p, "es");
			}
		} else {
			if (p.mode >= DisasmMode.File) {
				adbg_dasm_push_str(p, "add");
				adbg_dasm_push_reg(p, adbg_dasm_x86_eax(p, p.x86.op));
			}
			if (p.x86.op & X86_FLAG_WIDE)
				adbg_dasm_x86_u32imm(p);
			else
				adbg_dasm_x86_u8imm(p);
		}
		return;
	case 0x0C: // 0CH-0FH
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				adbg_dasm_x86_0f(p);
			} else {
				if (p.mode >= DisasmMode.File) {
					adbg_dasm_push_str(p, "push");
					adbg_dasm_push_reg(p, "cs");
				}
			}
		} else {
			if (p.mode >= DisasmMode.File) {
				adbg_dasm_push_str(p, "or");
				adbg_dasm_push_reg(p, adbg_dasm_x86_eax(p, p.x86.op));
			}
			if (p.x86.op & X86_FLAG_WIDE)
				adbg_dasm_x86_u32imm(p);
			else
				adbg_dasm_x86_u8imm(p);
		}
		return;
	case 0x14: // 14H-17H
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.mode >= DisasmMode.File) {
				adbg_dasm_push_str(p, p.x86.op & X86_FLAG_WIDE ? "pop" : "push");
				adbg_dasm_push_reg(p, "ss");
			}
		} else {
			if (p.mode >= DisasmMode.File) {
				adbg_dasm_push_str(p, "adc");
				adbg_dasm_push_reg(p, adbg_dasm_x86_eax(p, p.x86.op));
			}
			if (p.x86.op & X86_FLAG_WIDE)
				adbg_dasm_x86_u32imm(p);
			else
				adbg_dasm_x86_u8imm(p);
		}
		return;
	case 0x1C: // 1CH-1FH
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.mode >= DisasmMode.File) {
				adbg_dasm_push_str(p, p.x86.op & X86_FLAG_WIDE ? "pop" : "push");
				adbg_dasm_push_reg(p, "ds");
			}
		} else {
			if (p.mode >= DisasmMode.File) {
				adbg_dasm_push_str(p, "sbb");
				adbg_dasm_push_reg(p, adbg_dasm_x86_eax(p, p.x86.op));
			}
			if (p.x86.op & X86_FLAG_WIDE)
				adbg_dasm_x86_u32imm(p);
			else
				adbg_dasm_x86_u8imm(p);
		}
		return;
	case 0x24: // 24H-27H
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "daa");
			} else {
				p.x86.segreg = x86SegReg.ES;
				goto L_CONTINUE;
			}
		} else {
			if (p.mode >= DisasmMode.File) {
				adbg_dasm_push_str(p, "and");
				adbg_dasm_push_reg(p, adbg_dasm_x86_eax(p, p.x86.op));
			}
			if (p.x86.op & X86_FLAG_WIDE)
				adbg_dasm_x86_u32imm(p);
			else
				adbg_dasm_x86_u8imm(p);
		}
		return;
	case 0x2C: // 2CH-2FH
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "das");
				
			} else {
				p.x86.segreg = x86SegReg.CS;
				goto L_CONTINUE;
			}
		} else {
			if (p.mode >= DisasmMode.File) {
				adbg_dasm_push_str(p, "sub");
				adbg_dasm_push_reg(p, adbg_dasm_x86_eax(p, p.x86.op));
			}
			if (p.x86.op & X86_FLAG_WIDE)
				adbg_dasm_x86_u32imm(p);
			else
				adbg_dasm_x86_u8imm(p);
		}
		return;
	case 0x34: // 34H-37H
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "aaa");
			} else {
				p.x86.segreg = x86SegReg.SS;
				goto L_CONTINUE;
			}
		} else {
			if (p.mode >= DisasmMode.File) {
				adbg_dasm_push_str(p, "xor");
				adbg_dasm_push_reg(p, adbg_dasm_x86_eax(p, p.x86.op));
			}
			if (p.x86.op & X86_FLAG_WIDE)
				adbg_dasm_x86_u32imm(p);
			else
				adbg_dasm_x86_u8imm(p);
		}
		return;
	case 0x3C: // 3CH-3FH
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "aas");
			} else {
				p.x86.segreg = x86SegReg.DS;
				goto L_CONTINUE;
			}
		} else {
			if (p.mode >= DisasmMode.File) {
				adbg_dasm_push_str(p, "cmp");
				adbg_dasm_push_reg(p, adbg_dasm_x86_eax(p, p.x86.op));
			}
			if (p.x86.op & X86_FLAG_WIDE)
				adbg_dasm_x86_u32imm(p);
			else
				adbg_dasm_x86_u8imm(p);
		}
		return;
	case 0x40, 0x44, 0x48, 0x4C, 0x50, 0x54, 0x58, 0x5C: // 40H-5CH
		if (p.mode >= DisasmMode.File) {
			adbg_dasm_push_str(p, x86_T_40h[(p.x86.op >> 4) & 3]);
			adbg_dasm_push_reg(p,
				adbg_dasm_x86_modrm_reg(p, p.x86.op, MemWidth.i32));
		}
		return;
	case 0x60: // 60H-63H
		if (p.x86.op & X86_FLAG_DIR) {
			const(char) *m = void;
			int f = X86_FLAG_DIR;
			if (p.x86.op & X86_FLAG_WIDE) {
				m = "arpl";
				f |= X86_FLAG_MODW_8B;
			} else {
				// ANCHOR EVEX
				//TODO: EVEX
				if ((*p.ai8 & MODRM_MOD) == MODRM_MOD_11) {
					adbg_dasm_err(p);
					return;
				}
				m = "bound";
				f |= X86_FLAG_MODW_32B;
			}
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, m);
			adbg_dasm_x86_modrm(p, f);
		} else {
			if (p.mode >= DisasmMode.File) {
				const(char) *m = void;
				if (p.x86.op & X86_FLAG_WIDE)
					m = p.x86.pf_operand ? "popa" : "popad";
				else
					m = p.x86.pf_operand ? "pusha" : "pushad";
				adbg_dasm_push_str(p, m);
			}
		}
		return;
	case 0x64: // 64H-67H
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE)
				p.x86.pf_address = !p.x86.pf_address;
			else
				p.x86.pf_operand = !p.x86.pf_operand;
		} else {
			with (x86SegReg)
			p.x86.segreg = p.x86.op & X86_FLAG_WIDE ? GS : FS;
		}
		goto L_CONTINUE;
	case 0x68: // 68H-6BH
		if (p.x86.op & X86_FLAG_WIDE) {
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, "imul");
			adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_32B);
		} else {
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, "push");
		}
		if (p.x86.op & X86_FLAG_DIR)
			adbg_dasm_x86_u8imm(p);
		else
			adbg_dasm_x86_u32imm(p);
		return;
	case 0x6C: // 6CH-6FH
		if (p.mode >= DisasmMode.File) {
			MemWidth w = p.x86.op & X86_FLAG_WIDE ? MemWidth.i32 : MemWidth.i8;
			if (p.x86.op & X86_FLAG_DIR) {
				adbg_dasm_push_str(p, "outs");
				adbg_dasm_push_reg(p, "dx");
				adbg_dasm_push_memsegreg(p, "ds:", p.x86.pf_address ? "si" : "esi", w);
			} else {
				adbg_dasm_push_str(p, "ins");
				adbg_dasm_push_memsegreg(p, "es:", p.x86.pf_address ? "di" : "edi", w);
				adbg_dasm_push_reg(p, "dx");
			}
		}
		return;
	case 0x70, 0x74, 0x78, 0x7C: // 70H-7FH
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, x86_T_Jcc[p.x86.op & 15]);
		adbg_dasm_x86_u8imm(p);
		return;
	case 0x80: // 80H-83H
		ubyte modrm = *p.ai8;
		++p.ai8;
		if (p.mode >= DisasmMode.File) {
			adbg_dasm_push_x8(p, modrm);
			adbg_dasm_push_str(p, x86_T_grp1[(modrm >> 3) & 7]);
		}
		int w = p.x86.op & X86_FLAG_WIDE;
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_reg(p, adbg_dasm_x86_modrm_reg(p, modrm, w));
		if (p.x86.op & X86_FLAG_DIR && w == 0)
			adbg_dasm_x86_u8imm(p);
		else
			adbg_dasm_x86_u32imm(p);
		return;
	case 0x84: // 84H-87H
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, p.x86.op & X86_FLAG_DIR ? "xchg" : "test");
		adbg_dasm_x86_modrm(p, X86_FLAG_USE_OP);
		return;
	case 0x88: // 88H-8BH
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, "mov");
		adbg_dasm_x86_modrm(p, X86_FLAG_USE_OP);
		return;
	case 0x8C: // 8CH-8FH
		if (p.x86.op & X86_FLAG_WIDE) {
			if (p.x86.op & X86_FLAG_DIR) { // GRP1A POP REG32
				ubyte modrm = *p.ai8;
				++p.ai8;
				int xop_map = modrm & X86_VEX_MAP;
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_x8(p, modrm);
				if (xop_map < 8) {
					if (modrm & MODRM_REG) {
						adbg_dasm_err(p);
						return;
					}
					if (p.mode >= DisasmMode.File) {
						adbg_dasm_push_str(p, "pop");
						adbg_dasm_push_reg(p,
							adbg_dasm_x86_modrm_reg(p, modrm, MemWidth.i32));
					}
					return;
				}
				// ANCHOR: XOP prefix
				switch (xop_map) {
				case X86_XOP_MAP8:  adbg_dasm_x86_xop_8(p);  return;
				case X86_XOP_MAP9:  adbg_dasm_x86_xop_9(p);  return;
				case X86_XOP_MAP10: adbg_dasm_x86_xop_10(p); return;
				default: adbg_dasm_err(p); return;
				}
			} else { // LEA REG32, MEM32
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "lea");
				adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_32B);
			}
		} else {
			ubyte modrm = *p.ai8;
			++p.ai8;
			int sr = (modrm >> 3) & 7;
			if (sr > 5) {
				adbg_dasm_err(p);
				return;
			}
			if (p.mode >= DisasmMode.File) {
				adbg_dasm_push_x8(p, modrm);
				adbg_dasm_push_str(p, "mov");
				const(char) *seg = x86_T_segs[sr];
				const(char) *reg = adbg_dasm_x86_modrm_reg(p, modrm, MemWidth.i16);
				if (p.x86.op & X86_FLAG_DIR) {
					adbg_dasm_push_reg(p, seg);
					adbg_dasm_push_reg(p, reg);
				} else {
					adbg_dasm_push_reg(p, reg);
					adbg_dasm_push_reg(p, seg);
				}
			}
		}
		return;
	case 0x90, 0x94: // 90H-97H
		if (p.mode >= DisasmMode.File) {
			if (p.x86.op == 0x90) {
				adbg_dasm_push_str(p, "nop");
			} else {
				adbg_dasm_push_str(p, "xchg");
				adbg_dasm_push_reg(p, adbg_dasm_x86_modrm_reg(p, p.x86.op, MemWidth.i32));
				adbg_dasm_push_reg(p, p.x86.pf_operand ? "ax" : "eax");
			}
		}
		return;
	case 0x98: // 98H-9BH
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) { // WAIT/FWAIT
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "fwait");
			} else { // CALL (FAR)
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "call");
				adbg_dasm_x86_immfar(p);
			}
		} else {
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, p.x86.op & X86_FLAG_WIDE ? "cbd" : "cbw");
		}
		return;
	case 0x9C: // 9CH-9FH
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, x86_T_9Ch[p.x86.op & 3]);
		return;
	case 0xA0: // A0H-A3H
		const(char) *s = void, a = void;
		if (p.mode >= DisasmMode.File) {
			if (p.x86.segreg == x86SegReg.None)
				p.x86.segreg = x86SegReg.DS;
			adbg_dasm_push_str(p, "mov");
			s = adbg_dasm_x86_T_segstr(p.x86.segreg);
			a = adbg_dasm_x86_eax(p, p.x86.op);
		}
		if (p.x86.op & X86_FLAG_DIR) {
			adbg_dasm_x86_segimm(p, s);
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_reg(p, a);
		} else {
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_reg(p, a);
			adbg_dasm_x86_segimm(p, s);
		}
		return;
	case 0xA4: // A4H-A7H
		if (p.mode < DisasmMode.File)
			return;
		const(char) *m = void,
			seg1 = void, seg2 = void,
			reg1 = void, reg2 = void;
		if (p.x86.op & X86_FLAG_DIR) {
			m = "cmps";
			seg1 = "ds:"; seg2 = "es:";
			if (p.x86.pf_address) {
				reg1 = "si"; reg2 = "di";
			} else {
				reg1 = "esi"; reg2 = "edi";
			}
		} else {
			m = "movs";
			seg1 = "es:"; seg2 = "ds:";
			if (p.x86.pf_address) {
				reg1 = "di"; reg2 = "si";
			} else {
				reg1 = "edi"; reg2 = "esi";
			}
		}
		MemWidth w = adbg_dasm_x86_modrm_width(p, p.x86.op);
		adbg_dasm_push_str(p, m);
		adbg_dasm_push_memsegreg(p, seg1, reg1, w);
		adbg_dasm_push_memsegreg(p, seg2, reg2, w);
		return;
	case 0xA8: // A8H-ABH
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.mode < DisasmMode.File)
				return;
			const(char) *areg = p.x86.pf_address ? "di" : "edi";
			adbg_dasm_push_str(p, "stos");
			adbg_dasm_push_memsegreg(p, "es:", areg, adbg_dasm_x86_modrm_width(p, p.x86.op));
			adbg_dasm_push_reg(p, adbg_dasm_x86_eax(p, p.x86.op));
		} else {
			if (p.mode >= DisasmMode.File) {
				adbg_dasm_push_str(p, "test");
				adbg_dasm_push_reg(p, adbg_dasm_x86_eax(p, p.x86.op));
			}
			if (p.x86.op & X86_FLAG_WIDE)
				adbg_dasm_x86_u32imm(p);
			else
				adbg_dasm_x86_u8imm(p);
		}
		return;
	case 0xAC: // ACH-AFH
		if (p.mode >= DisasmMode.File) {
			const(char) *seg = void, reg = void, m = void;
			if (p.x86.op & X86_FLAG_DIR) {
				m = "scas";
				seg = "es:";
				reg = p.x86.pf_operand ? "di" : "edi";
			} else {
				m = "lods";
				seg = "ds:";
				reg = p.x86.pf_operand ? "si" : "esi";
			}
			adbg_dasm_push_str(p, m);
			adbg_dasm_push_reg(p, adbg_dasm_x86_eax(p, p.x86.op));
			adbg_dasm_push_segreg(p, seg, reg);
		}
		return;
	case 0xB0, 0xB4, 0xB8, 0xBC: // B0H-B7H
		int w = p.x86.op & 0b00_001_000;
		if (p.mode >= DisasmMode.File) {
			adbg_dasm_push_str(p, "mov");
			adbg_dasm_push_reg(p, adbg_dasm_x86_modrm_reg(p, p.x86.op,
				w ? MemWidth.i32 : MemWidth.i8));
		}
		if (w)	adbg_dasm_x86_u32imm(p);
		else	adbg_dasm_x86_u8imm(p);
		return;
	case 0xC0: // C0H-C3H
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, "ret");
			if (p.x86.op & X86_FLAG_WIDE) // RET IMM16
				return;
			if (p.mode >= DisasmMode.File) {
				adbg_dasm_push_x16(p, *p.ai16);
				adbg_dasm_push_imm(p, *p.ai16);
			}
			++p.ai16;
		} else { // GRP2 R/M, IMM8
			ubyte modrm = *p.ai8;
			++p.ai8;
			const(char) *r = x86_T_grp2[(modrm >> 3) & 7];
			if (r == null) {
				adbg_dasm_err(p);
				return;
			}
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, r);
			int w = p.x86.op & X86_FLAG_WIDE;
			adbg_dasm_x86_modrm_rm(p, modrm, w, w);
			adbg_dasm_x86_u8imm(p);
		}
		return;
	case 0xC4: // C4H-C7H
		ubyte modrm = *p.ai8;
		if (p.x86.op & X86_FLAG_DIR) { // GRP11
			++p.ai8;
			if (modrm & MODRM_REG) {
				adbg_dasm_err(p);
				return;
			}
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, "mov");
			int w = p.x86.op & X86_FLAG_WIDE;
			adbg_dasm_x86_modrm_rm(p, modrm, w, w);
			if (p.x86.op & X86_FLAG_WIDE)
				adbg_dasm_x86_u32imm(p);
			else
				adbg_dasm_x86_u8imm(p);
		} else { // MOD=11 checking is only in x86-32
			if ((modrm & MODRM_MOD) == MODRM_MOD_11) {
				// ANCHOR: VEX 2-byte/3-byte prefix
				p.x86.vex[0] = p.x86.op;
				p.x86.vex[1] = modrm;
				if (p.x86.op & X86_FLAG_WIDE) { // C5H, VEX 2-byte prefix
					if (p.mode >= DisasmMode.File)
						adbg_dasm_push_x8(p, modrm);
					p.x86.vex_vvvv = (~cast(uint)modrm & 56) >> 3; // 3 bits under 32-bit
					p.x86.vex_L    = modrm & 4;
					p.x86.vex_pp   = modrm & 3;
					++p.ai8;
					adbg_dasm_x86_vex_0f(p);
				} else { // C4H, VEX 3-byte prefix
					ubyte u8 = p.x86.vex[2] = *(p.ai8 + 1);
					if (p.mode >= DisasmMode.File) {
						adbg_dasm_push_x8(p, modrm);
						adbg_dasm_push_x8(p, p.x86.vex[2]);
					}
					p.x86.vex_vvvv = (~cast(uint)u8 & 56) >> 3; // 3 bits under 32-bit
					p.x86.vex_L    = u8 & 4;
					p.x86.vex_pp   = u8 & 3;
					++p.ai16;
					switch (p.x86.vex[1] & X86_VEX_MAP) {
					case X86_VEX_MAP_0F: adbg_dasm_x86_vex_0f(p); return;
					case X86_VEX_MAP_0F38: adbg_dasm_x86_vex_0f38(p); return;
					case X86_VEX_MAP_0F3A: adbg_dasm_x86_vex_0f3a(p); return;
					default: adbg_dasm_err(p); return;
					}
				}
				return;
			}
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, p.x86.op & X86_FLAG_WIDE ? "lds" : "les");
			adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_32B);
		}
		return;
	case 0xC8: // C8H-CBH
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, "ret");
			if (p.x86.op & X86_FLAG_WIDE)
				return;
			if (p.mode >= DisasmMode.File) {
				adbg_dasm_push_x16(p, *p.ai16);
				adbg_dasm_push_imm(p, *p.ai16);
			}
			++p.ai16;
		} else {
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, p.x86.op & X86_FLAG_WIDE ? "leave" : "enter");
			if ((p.x86.op & X86_FLAG_WIDE) == 0) {
				if (p.mode >= DisasmMode.File) {
					ushort v1 = *p.ai16;
					ubyte v2 = *(p.ai8 + 2);
					adbg_dasm_push_x16(p, v1);
					adbg_dasm_push_x8(p, v2);
					adbg_dasm_push_imm(p, v1);
					adbg_dasm_push_imm(p, v2);
				}
				p.av += 3;
			}
		}
		return;
	case 0xCC: // CCH-CFH
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, p.x86.op & X86_FLAG_WIDE ? "iret" : "into");
		} else {
			if (p.x86.op & X86_FLAG_WIDE) { // INT IMM8
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "int");
				adbg_dasm_x86_u8imm(p);
			} else { // INT3
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "int3");
			}
		}
		return;
	case 0xD0: // D0H-D3H
		ubyte modrm = *p.ai8;
		++p.ai8;
		const(char) *m = x86_T_grp2[(modrm >> 3) & 7];
		if (m == null) {
			adbg_dasm_err(p);
			return;
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		int w = p.x86.op & X86_FLAG_WIDE;
		adbg_dasm_x86_modrm_rm(p, modrm, w, w);
		if (p.mode >= DisasmMode.File) {
			if (p.x86.op & X86_FLAG_DIR)
				adbg_dasm_push_reg(p, "cl");
			else
				adbg_dasm_push_imm(p, 1);
		}
		return;
	case 0xD4: // D4H-D7H
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "xlat");
			} else adbg_dasm_err(p);
		} else {
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, p.x86.op & X86_FLAG_WIDE ? "aad" : "amm");
			adbg_dasm_x86_u8imm(p);
		}
		return;
	case 0xD8, 0xDC: // D8H-DBH ESCAPE
		ubyte modrm = *p.ai8;
		++p.ai8;
		const(char) *m = void;
		switch (p.x86.op & 7) {
		case 0:	// D8H
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, x86_T_FLT1[(modrm >> 3) & 7]);
			if (modrm > 0xBF) { // operand is FP
				if (p.mode < DisasmMode.File)
					return;
				adbg_dasm_push_x8(p, modrm);
				adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, 0));
				adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, modrm & 7));
			} else { // operand is memory pointer
				adbg_dasm_x86_modrm_rm(p, modrm, MemWidth.i32, MemWidth.i32);
			}
			return;
		case 1:	// D9H
			if (modrm > 0xBF) { // operand is FP
				ubyte sti = modrm & 0xF;
				switch (modrm & 0xF0) {
				case 0xC0: // FLD/FXCH
					if (p.mode < DisasmMode.File)
						return;
					if (sti < 0x8) { // FLD
						m = "fld";
					} else { // FXCH
						sti -= 8;
						m = "fxch";
					}
					adbg_dasm_push_x8(p, modrm);
					adbg_dasm_push_str(p, m);
					adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, 0));
					adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, sti));
					return;
				case 0xD0: // FNOP/Reserved
					if (sti == 0) {
						if (p.mode >= DisasmMode.File) {
							adbg_dasm_push_x8(p, modrm);
							adbg_dasm_push_str(p, "fnop");
						}
					} else
						adbg_dasm_err(p);
					return;
				case 0xE0:
					m = x86_T_FLT5[sti];
					if (m == null) {
						adbg_dasm_err(p);
						return;
					}
					if (p.mode >= DisasmMode.File) {
						adbg_dasm_push_x8(p, modrm);
						adbg_dasm_push_str(p, m);
					}
					return;
				default: // F0
					if (p.mode < DisasmMode.File)
						return;
					adbg_dasm_push_x8(p, modrm);
					adbg_dasm_push_str(p, x86_T_FLT4[sti]);
					return;
				}
			} else { // operand is memory pointer
				m = x86_T_FLT6[(modrm >> 3) & 7];
				if (m == null) {
					adbg_dasm_err(p);
					return;
				}
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, m);
				adbg_dasm_x86_modrm_rm(p, modrm, MemWidth.i32, MemWidth.i32);
			}
			return;
		case 2:	// DAH
			if (modrm > 0xBF) { // operand is FP
				ubyte sti = modrm & 0xF;
				switch (modrm & 0xF0) {
				case 0xC0: // FCMOVB/FCMOVE
					if (p.mode < DisasmMode.File)
						return;
					if (sti < 0x8) { // FCMOVB
						m = "fcmovb";
					} else { // FCMOVE
						sti -= 8;
						m = "fcmove";
					}
					adbg_dasm_push_x8(p, modrm);
					adbg_dasm_push_str(p, m);
					adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, 0));
					adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, sti));
					return;
				case 0xD0: // FCMOVBE/FCMOVU
					if (p.mode < DisasmMode.File)
						return;
					if (sti < 0x8) { // FCMOVBE
						m = "fcmovbe";
					} else { // FCMOVU
						sti -= 8;
						m = "fcmovu";
					}
					adbg_dasm_push_x8(p, modrm);
					adbg_dasm_push_str(p, m);
					adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, 0));
					adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, sti));
					return;
				case 0xE0:
					if (sti == 9) {
						if (p.mode >= DisasmMode.File) {
							adbg_dasm_push_x8(p, modrm);
							adbg_dasm_push_str(p, "fucompp");
						}
						return;
					}
					goto default;
				default: // 0xF0:
					adbg_dasm_err(p);
				}
			} else { // operand is memory pointer
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, x86_T_FLT2[(modrm >> 3) & 7]);
				adbg_dasm_x86_modrm_rm(p, modrm, MemWidth.i32, MemWidth.i32);
			}
			return;
		case 3:	// DBH
			if (modrm > 0xBF) { // operand is FP
				ubyte sti = modrm & 0xF;
				switch (modrm & 0xF0) {
				case 0xC0: // FCMOVNB/FCMOVNE
					if (p.mode < DisasmMode.File)
						return;
					if (sti < 0x8) { // FCMOVNB
						m = "fcmovnb";
					} else { // FCMOVNE
						sti -= 8;
						m = "fcmovne";
					}
					adbg_dasm_push_x8(p, modrm);
					adbg_dasm_push_str(p, m);
					adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, 0));
					adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, sti));
					break;
				case 0xD0: // FCMOVNBE/FCMOVNU
					if (p.mode < DisasmMode.File)
						return;
					if (sti < 0x8) { // FCMOVNBE
						m = "fcmovnbe";
					} else { // FCMOVNU
						sti -= 8;
						m = "fcmovnu";
					}
					adbg_dasm_push_x8(p, modrm);
					adbg_dasm_push_str(p, m);
					adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, 0));
					adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, sti));
					break;
				case 0xE0: // */FUCOMI
					if (sti < 0x8) { // FCMOVNBE
						switch (sti) {
						case 1: m = "fclex"; break;
						case 2: m = "finit"; break;
						default: adbg_dasm_err(p); return;
						}
						if (p.mode >= DisasmMode.File)
							adbg_dasm_push_str(p, m);
					} else { // FUCOMI
						if (p.mode >= DisasmMode.File) {
							sti -= 8;
							adbg_dasm_push_x8(p, modrm);
							adbg_dasm_push_str(p, "fucomi");
							adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, 0));
							adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, sti));
						}
					}
					return;
				default: // (F0) FCOMI/Reserved
					if (sti < 0x8) { // FCOMI
						adbg_dasm_push_x8(p, modrm);
						adbg_dasm_push_str(p, "fcomi");
						adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, 0));
						adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, sti));
					} else { // Reserved
						adbg_dasm_err(p);
					}
					return;
				}
			} else { // operand is memory pointer
				m = x86_T_FLT7[(modrm >> 3) & 7];
				if (m == null) {
					adbg_dasm_err(p);
					return;
				}
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, m);
				adbg_dasm_x86_modrm_rm(p, modrm, MemWidth.i32, MemWidth.i32);
			}
			return;
		case 4:	// DCH
			if (modrm > 0xBF) { // operand is FP
				int reg = modrm & MODRM_REG;
				if (reg == MODRM_REG_010 || reg == MODRM_REG_011) {
					adbg_dasm_err(p);
					return;
				}
				if (p.mode >= DisasmMode.File) {
					adbg_dasm_push_x8(p, modrm);
					adbg_dasm_push_str(p, x86_T_FLT1[reg >> 3]);
					adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, modrm & 7));
					adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, 0));
				}
			} else { // operand is memory pointer
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, x86_T_FLT1[(modrm >> 3) & 7]);
				adbg_dasm_x86_modrm_rm(p, modrm, MemWidth.i32, MemWidth.i64);
			}
			return;
		case 5:	// DDH
			if (modrm > 0xBF) { // operand is FP
				ubyte sti = modrm & 0xF;
				switch (modrm & 0xF0) {
				case 0xC0: // FFREE/Reserved
					if (sti < 0x8) { // FFREE
						if (p.mode >= DisasmMode.File) {
							adbg_dasm_push_x8(p, modrm);
							adbg_dasm_push_str(p, "ffree");
							adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, sti));
						}
					} else { // Reserved
						adbg_dasm_err(p);
					}
					return;
				case 0xD0: // FST/FSTP
					if (p.mode < DisasmMode.File)
						return;
					if (sti < 0x8) { // FST
						m = "fst";
					} else { // FSTP
						sti -= 8;
						m = "fstp";
					}
					adbg_dasm_push_x8(p, modrm);
					adbg_dasm_push_str(p, m);
					adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, sti));
					return;
				case 0xE0: // FUCOM/FUCOMP
					if (p.mode < DisasmMode.File)
						return;
					adbg_dasm_push_x8(p, modrm);
					if (sti < 0x8) { // FUCOM
						adbg_dasm_push_str(p, "fucom");
						adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, sti));
						adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, 0));
					} else { // FUCOMP
						sti -= 8;
						adbg_dasm_push_str(p, "fucomp");
						adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, sti));
					}
					return;
				default: // 0xF0
					adbg_dasm_err(p);
					return;
				}
			} else { // operand is memory pointer
				m = x86_T_FLT8[(modrm >> 3) & 7];
				if (m == null) {
					adbg_dasm_err(p);
					return;
				}
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, m);
				adbg_dasm_x86_modrm_rm(p, modrm, MemWidth.i32, MemWidth.i64);
				return;
			}
		case 6:	// DEH
			if (modrm > 0xBF) { // operand is FP
				ubyte sti = modrm & 0xF;
				switch (modrm & 0xF0) {
				case 0xC0: // FADDP/FMULP
					if (sti < 0x8) { // FADDP
						m = "faddp";
					} else { // FMULP
						sti -= 8;
						m = "fmulp";
					}
					break;
				case 0xD0: // Reserved/FCOMPP*
					if (sti == 9) {
						if (p.mode >= DisasmMode.File) {
							adbg_dasm_push_x8(p, modrm);
							adbg_dasm_push_str(p, "fcompp");
						}
					} else
						adbg_dasm_err(p);
					return;
				case 0xE0: // FSUBRP/FSUBP
					if (sti < 0x8) { // FSUBP
						m = "fsubrp";
					} else { // FSUBP
						sti -= 8;
						m = "fucomp";
					}
					break;
				default: // (F0) FDIVRP/FDIVP
					if (sti < 0x8) { // FDIVRP
						m = "fdivrp";
					} else { // FDIVP
						sti -= 8;
						m = "fdivp";
					}
					break;
				}
				if (p.mode >= DisasmMode.File) {
					adbg_dasm_push_x8(p, modrm);
					adbg_dasm_push_str(p, m);
					adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, sti));
					adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, 0));
				}
			} else { // operand is memory pointer
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, x86_T_FLT2[(modrm >> 3) & 7]);
				adbg_dasm_x86_modrm_rm(p, modrm, MemWidth.i32, MemWidth.i16);
			}
			return;
		default:	// DFH
			if (modrm > 0xBF) { // operand is FP
				ubyte sti = modrm & 0xF;
				switch (modrm & 0xF0) {
				case 0xC0:
					if (sti < 8) { // (Undocumented)
						adbg_dasm_push_x8(p, modrm);
						adbg_dasm_push_str(p, "ffreep");
						adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, sti));
					} else {
						adbg_dasm_err(p);
					}
					return;
				case 0xE0: // FSTSW*/FUCOMIP
					if (sti < 0x8) { // FSUBP
						if (sti == 0) {
							if (p.mode >= DisasmMode.File) {
								adbg_dasm_push_x8(p, modrm);
								adbg_dasm_push_str(p, "fstsw");
								adbg_dasm_push_reg(p, "ax");
							}
						} else
							adbg_dasm_err(p);
					} else { // FUCOMIP
						if (p.mode < DisasmMode.File)
							return;
						sti -= 8;
						adbg_dasm_push_x8(p, modrm);
						adbg_dasm_push_str(p, "fstsw");
						adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, 0));
						adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, sti));
					}
					return;
				case 0xF0: // FCOMIP/Reserved
					if (sti < 0x8) { // FCOMIP
						if (p.mode < DisasmMode.File)
							return;
						adbg_dasm_push_x8(p, modrm);
						adbg_dasm_push_str(p, "fcomip");
						adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, 0));
						adbg_dasm_push_str(p, adbg_dasm_x87_ststr(p, sti));
					} // else Reserved
					goto default;
				default:
					adbg_dasm_err(p);
				}
			} else { // operand is memory pointer
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, x86_T_FLT3[(modrm >> 3) & 7]);
				adbg_dasm_x86_modrm_rm(p, modrm, MemWidth.i32, MemWidth.i64);
			}
			return;
		}
	case 0xE0: // E0H-E3H
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, x86_T_E0h[p.x86.op & 3]);
		adbg_dasm_x86_u8imm(p);
		return;
	case 0xE4: // E4H-E7H
		const(char) *a = void;
		if (p.mode >= DisasmMode.File)
			a = adbg_dasm_x86_eax(p, p.x86.op);
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, "out");
			adbg_dasm_x86_u8imm(p);
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_reg(p, a);
		} else {
			if (p.mode >= DisasmMode.File) {
				adbg_dasm_push_str(p, "in");
				adbg_dasm_push_reg(p, a);
			}
			adbg_dasm_x86_u8imm(p);
		}
		return;
	case 0xE8: // E8H-EBH
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, "jmp");
			if (p.x86.op & X86_FLAG_WIDE) {
				adbg_dasm_x86_u8imm(p);
			} else {
				if (p.mode >= DisasmMode.File) {
					adbg_dasm_push_x16(p, *p.ai16);
					adbg_dasm_push_imm(p, *p.ai16);
				}
				++p.ai16;
				adbg_dasm_x86_u32imm(p);
			}
		} else {
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, p.x86.op & X86_FLAG_WIDE ? "jmp" : "call");
			adbg_dasm_x86_u32imm(p);
		}
		return;
	case 0xEC: // ECH-EFH
		if (p.mode < DisasmMode.File)
			return;
		const(char) *m = adbg_dasm_x86_eax(p, p.x86.op);
		if (p.x86.op & X86_FLAG_DIR) {
			adbg_dasm_push_str(p, "out");
			adbg_dasm_push_reg(p, "dx");
			adbg_dasm_push_reg(p, m);
		} else {
			adbg_dasm_push_str(p, "in");
			adbg_dasm_push_reg(p, m);
			adbg_dasm_push_reg(p, "dx");
		}
		return;
	case 0xF0: // F0H-F3H
		//TODO: Something about showing prefixes
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) { // REPZ/REPE/REPE
				p.x86.last_prefix = 0xF3;
//				if (p.mode >= DisasmMode.File)
//					disasm_push_prefix(p, "repz");
				goto L_CONTINUE;
			} else { // REPNZ/REPNE
				p.x86.last_prefix = 0xF2;
//				if (p.mode >= DisasmMode.File)
//					disasm_push_prefix(p, "repnz");
				goto L_CONTINUE;
			}
		} else {
			if (p.x86.op & X86_FLAG_WIDE) {
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "int1");
			} else {
				p.x86.lock = 0xF0;
//				if (p.mode >= DisasmMode.File)
//					disasm_push_prefix(p, "lock");
				goto L_CONTINUE;
			}
		}
		return;
	case 0xF4: // F4H-F7H
		int w = p.x86.op & X86_FLAG_WIDE;
		if (p.x86.op & X86_FLAG_DIR) { // GRP3
			ubyte modrm = *p.ai8;
			++p.ai8;
			int mreg = modrm & MODRM_REG;
			if (mreg == MODRM_REG_001) {
				adbg_dasm_err(p);
				return;
			}
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, x86_T_F4h[mreg >> 3]);
			adbg_dasm_x86_modrm_rm(p, modrm, w, w);
			if (mreg >= MODRM_REG_100) {
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_reg(p, adbg_dasm_x86_eax(p, p.x86.op));
			} else if (mreg == MODRM_REG_000) { // TEST RM, IMM8
				adbg_dasm_x86_u8imm(p);
			}
		} else {
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, w ? "cmc" : "hlt");
		}
		return;
	case 0xF8: // F8H-FBH
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, x86_T_F8h[p.x86.op & 3]);
		return;
	default: // FCH-FFH
		MemWidth w = adbg_dasm_x86_modrm_width(p, p.x86.op);
		if (p.x86.op & X86_FLAG_DIR) {
			ubyte modrm = *p.ai8;
			++p.ai8;
			const(char) *m = void; // @suppress(dscanner.suspicious.label_var_same_name)
			if (w) { // GRP5
				switch (modrm & MODRM_REG) {
				case MODRM_REG_000: m = "inc"; break;
				case MODRM_REG_001: m = "dec"; break;
				case MODRM_REG_010: m = "call"; break;
				case MODRM_REG_011: w = MemWidth.far; m = "call"; break;
				case MODRM_REG_100: m = "jmp"; break;
				case MODRM_REG_101: w = MemWidth.far; m = "jmp"; break;
				case MODRM_REG_110: m = "push"; break;
				default: adbg_dasm_err(p); return;
				}
			} else { // GRP4
				switch (modrm & MODRM_REG) {
				case MODRM_REG_000: m = "inc"; break;
				case MODRM_REG_001: m = "dec"; break;
				default: adbg_dasm_err(p); return;
				}
			}
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, m);
			adbg_dasm_x86_modrm_rm(p, modrm, w, 0);
		} else {
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, w ? "std" : "cld");
		}
		return;
	}
}

package:

void adbg_dasm_x86_0f(disasm_params_t *p) {
	p.x86.op = *p.ai8;
	++p.ai8;

	if (p.mode >= DisasmMode.File)
		adbg_dasm_push_x8(p, p.x86.op);

	switch (p.x86.op & 252) { // 1111_1100
	case 0:
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, p.x86.op & X86_FLAG_WIDE ? "lsl" : "lar");
			adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_32B);
			return;
		}
		ubyte modrm = *p.ai8;
		++p.ai8;
		if (p.x86.op & X86_FLAG_WIDE) {
			ubyte mod11 = (modrm & MODRM_MOD) == MODRM_MOD_11;
			const(char) *m = void;
			switch (modrm & MODRM_REG) {
			case MODRM_REG_000:
				if (mod11) { // VM*
					if (p.mode < DisasmMode.File)
						break;
					switch (modrm & MODRM_RM) {
					case MODRM_RM_001: m = "vmcall"; break;
					case MODRM_RM_010: m = "vmlaunch"; break;
					case MODRM_RM_011: m = "vmresume"; break;
					case MODRM_RM_100: m = "vmxoff"; break;
					default: adbg_dasm_err(p); return;
					}
					adbg_dasm_push_x8(p, modrm);
					adbg_dasm_push_str(p, m);
				} else { // SGDT
					if (p.mode >= DisasmMode.File)
						adbg_dasm_push_str(p, "sgdt");
					adbg_dasm_x86_modrm_rm(p, modrm, MemWidth.i32, MemWidth.i32);
				}
				return;
			case MODRM_REG_001:
				if (mod11) { // MONITOR*
					if (p.mode < DisasmMode.File)
						break;
					switch (modrm & MODRM_RM) {
					case MODRM_RM_000: m = "monitor"; break;
					case MODRM_RM_001: m = "mwait"; break;
					case MODRM_RM_010: m = "clac"; break;
					case MODRM_RM_011: m = "stac"; break;
					case MODRM_RM_111: m = "encls"; break;
					default: adbg_dasm_err(p); return;
					}
					adbg_dasm_push_x8(p, modrm);
					adbg_dasm_push_str(p, m);
				} else { // SIDT
					if (p.mode >= DisasmMode.File)
						adbg_dasm_push_str(p, "sidt");
					adbg_dasm_x86_modrm_rm(p, modrm, MemWidth.i32, MemWidth.i32);
				}
				return;
			case MODRM_REG_010:
				if (mod11) { // X*
					if (p.mode < DisasmMode.File)
						break;
					switch (modrm & MODRM_RM) {
					case MODRM_RM_000: m = "xgetbv"; break;
					case MODRM_RM_001: m = "xsetbv"; break;
					case MODRM_RM_100: m = "vmfunc"; break;
					case MODRM_RM_101: m = "xend"; break;
					case MODRM_RM_110: m = "xtest"; break;
					case MODRM_RM_111: m = "enclu"; break;
					default: adbg_dasm_err(p); return;
					}
					adbg_dasm_push_x8(p, modrm);
					adbg_dasm_push_str(p, m);
				} else { // LGDT
					if (p.mode >= DisasmMode.File)
						adbg_dasm_push_str(p, "lgdt");
					adbg_dasm_x86_modrm_rm(p, modrm, MemWidth.i32, MemWidth.i32);
				}
				return;
			case MODRM_REG_011:
				if (mod11) { // (AMD) SVM
					if (p.mode < DisasmMode.File)
						break;
					switch (modrm & MODRM_RM) {
					case MODRM_RM_000: m = "vmrun"; break;
					case MODRM_RM_001: m = "vmmcall"; break;
					case MODRM_RM_010: m = "vmload"; break;
					case MODRM_RM_011: m = "vmsave"; break;
					case MODRM_RM_100: m = "stgi"; break;
					case MODRM_RM_101: m = "clgi"; break;
					case MODRM_RM_110: m = "skinit"; break;
					default:           m = "invlpga"; break;
					}
					adbg_dasm_push_x8(p, modrm);
					adbg_dasm_push_str(p, m);
				} else { // LIDT
					if (p.mode >= DisasmMode.File)
						adbg_dasm_push_str(p, "lgdt");
					adbg_dasm_x86_modrm_rm(p, modrm, MemWidth.i32, MemWidth.i32);
				}
				return;
			case MODRM_REG_100: // SMSW
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "smsw");
				adbg_dasm_x86_modrm_rm(p, modrm, MemWidth.i32, MemWidth.i32);
				return;
			case MODRM_REG_110: // LMSW
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "lmsw");
				adbg_dasm_x86_modrm_rm(p, modrm, MemWidth.i32, MemWidth.i32);
				return;
			case MODRM_REG_111:
				if (mod11) { // *
					if ((modrm & MODRM_RM) == MODRM_RM_001) {
						if (p.mode >= DisasmMode.File) {
							adbg_dasm_push_x8(p, modrm);
							adbg_dasm_push_str(p, "rdtscp");
						}
					} else
						adbg_dasm_err(p);
				} else { // INVLPG
					if (p.mode >= DisasmMode.File)
						adbg_dasm_push_str(p, "invlpg");
					adbg_dasm_x86_modrm_rm(p, modrm, MemWidth.i32, MemWidth.i32);
				}
				return;
			default: adbg_dasm_err(p);
			}
		} else {
			const(char) *m = void;
			switch (modrm & MODRM_REG) {
			case MODRM_REG_000: m = "sldt"; break;
			case MODRM_REG_001: m = "str"; break;
			case MODRM_REG_010: m = "lldt"; break;
			case MODRM_REG_011: m = "ltr"; break;
			case MODRM_REG_100: m = "verr"; break;
			case MODRM_REG_101: m = "verw"; break;
			default: adbg_dasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, m);
			adbg_dasm_x86_modrm_rm(p, modrm, MemWidth.i32, MemWidth.i32);
		}
		return;
	case 0x04: // 04H-07H
		if (p.x86.op & X86_FLAG_DIR && (p.x86.op & X86_FLAG_WIDE) == 0) { // 06H
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, "clts");
		} else {
			adbg_dasm_err(p);
		}
		return;
	case 0x08: // 08H-0BH
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "ud2");
			} else {
				adbg_dasm_err(p);
			}
		} else {
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, p.x86.op & X86_FLAG_WIDE ? "wbinvd" : "invd");
		}
		return;
	case 0x0C: // 0CH-0FH
		if ((p.x86.op & X86_FLAG_DIR) == 0 && p.x86.op & X86_FLAG_WIDE) { // 0DH: PREFETCHW /1
			ubyte modrm = *p.ai8;
			++p.ai8;
			if ((modrm & MODRM_REG) != MODRM_REG_001) {
				adbg_dasm_err(p);
				return;
			}
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, "prefetchw");
			adbg_dasm_x86_modrm_rm(p, modrm, MemWidth.i32, MemWidth.i32);
		} else {
			adbg_dasm_err(p);
		}
		return;
	case 0x10: // 10H-13H
		int f = X86_FLAG_MODW_128B;
		if (p.x86.op & X86_FLAG_DIR) {
			const(char) *m = void;
			if (p.x86.op & X86_FLAG_WIDE) { // MOVLPS/MOVLPD
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE: m = "movlps"; break;
				case X86_0F_66H: m = "movlpd"; break;
				default: adbg_dasm_err(p); return;
				}
			} else { // (MOVLPS|MOVHLPS)/MOVSLDUP/MOVLPD/MOVDDUP
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE:
					m = (*p.ai8 & MODRM_MOD) == MODRM_MOD_11 ?
						"movhlps" : "movlps";
					break;
				case X86_0F_66H: m = "movlpd"; break;
				case X86_0F_F2H: m = "movddup"; break;
				case X86_0F_F3H: m = "movsldup"; break;
				default: adbg_dasm_err(p); return;
				}
				f |= X86_FLAG_DIR;
			}
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, m);
			adbg_dasm_x86_modrm(p, f);
			
		} else {
			const(char) *m = void;
			switch (adbg_dasm_x86_0f_select(p)) {
			case X86_0F_NONE: m = "movups"; break;
			case X86_0F_66H: m = "movupd"; break;
			case X86_0F_F2H: m = "movsd"; break;
			case X86_0F_F3H: m = "movss"; break;
			default: adbg_dasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, m);
			if (p.x86.op & X86_FLAG_WIDE) f |= X86_FLAG_DIR;
			adbg_dasm_x86_modrm(p, f);
		}
		return;
	case 0x14: // 14H-17H
		const(char) *m = void;
		int f = void;
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE: m = "movhps"; break;
				case X86_0F_66H: m = "movhpd"; break;
				default: adbg_dasm_err(p); return;
				}
				f = X86_FLAG_MODW_128B;
			} else {
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE:
					m = (*p.ai8 & MODRM_MOD) == MODRM_MOD_11 ?
						"movlhps" : "movhps";
					break;
				case X86_0F_66H: m = "movhpd"; break;
				case X86_0F_F3H: m = "movshdup"; break;
				default: adbg_dasm_err(p); return;
				}
				f = X86_FLAG_DIR | X86_FLAG_MODW_128B;
			}
		} else {
			switch (adbg_dasm_x86_0f_select(p)) {
			case X86_0F_NONE: m = p.x86.op & X86_FLAG_WIDE ? "unpckhps" : "unpcklpd"; break;
			case X86_0F_66H: m = p.x86.op & X86_FLAG_WIDE ? "unpckhpd" : "unpcklpd"; break;
			default: adbg_dasm_err(p); return;
			}
			f = X86_FLAG_DIR | X86_FLAG_MODW_128B;
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, f);
		return;
	case 0x18: // 18H-1BH
		ubyte modrm = *p.ai8;
		++p.ai8;
		const(char) *m = void, sr = void;
		if (p.x86.op & X86_FLAG_DIR) {
			switch (modrm & MODRM_REG) {
			case MODRM_REG_000: sr = "bnd0"; break;
			case MODRM_REG_001: sr = "bnd1"; break;
			case MODRM_REG_010: sr = "bnd2"; break;
			case MODRM_REG_011: sr = "bnd3"; break;
			default: adbg_dasm_err(p); return;
			}
			int mi = adbg_dasm_x86_0f_select(p);
			if (mi >= X86_0F_F266H) {
				adbg_dasm_err(p);
				return;
			}
			int w = p.x86.op & X86_FLAG_WIDE;
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, x86_T_0F_18h[w][mi]);
			if (w) {
				adbg_dasm_x86_modrm_rm(p, modrm, MemWidth.i32, MemWidth.i32);
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_reg(p, sr);
			} else {
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_reg(p, sr);
				adbg_dasm_x86_modrm_rm(p, modrm, MemWidth.i32, MemWidth.i32);
			}
		} else {
			if (p.x86.op & X86_FLAG_WIDE) {
				adbg_dasm_err(p);
				return;
			} // GRP 16
			if ((modrm & MODRM_MOD) == MODRM_MOD_11) {
				adbg_dasm_err(p);
				return;
			}
			switch (modrm & MODRM_REG) {
			case MODRM_REG_000: m = "prefetchnta"; break;
			case MODRM_REG_001: m = "prefetcht0"; break;
			case MODRM_REG_010: m = "prefetcht1"; break;
			case MODRM_REG_011: m = "prefetcht2"; break;
			default: adbg_dasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, m);
			adbg_dasm_x86_modrm_rm(p, modrm, MemWidth.i32, MemWidth.i32);
		}
		return;
	case 0x1C: // 1CH-1FH
		if (p.x86.op & X86_FLAG_DIR && p.x86.op & X86_FLAG_WIDE) {
			ubyte modrm = *p.ai8;
			++p.ai8;
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, "nop");
			adbg_dasm_x86_modrm_rm(p, modrm, MemWidth.i32, MemWidth.i32);
		} else {
			adbg_dasm_err(p);
		}
		return;
	case 0x20: // 20H-23H
		ubyte modrm = *p.ai8;
		++p.ai8;
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_x8(p, modrm);
		if ((modrm & MODRM_MOD) != MODRM_MOD_11) {
			adbg_dasm_err(p);
			return;
		}
		if (p.mode < DisasmMode.File)
			return;
		adbg_dasm_push_str(p, "mov");
		int r = (modrm & MODRM_REG) >> 3;
		const(char) *sr = void; // special reg
		if (p.x86.op & X86_FLAG_WIDE) {
			sr = x86_T_DR[r];
		} else {
			if (p.x86.lock) r |= 0b1000;
			sr = x86_T_CR[r];
		}
		const(char) *reg = adbg_dasm_x86_modrm_reg(p, modrm, MemWidth.i32);
		if (p.x86.op & X86_FLAG_DIR) {
			adbg_dasm_push_reg(p, sr);
			adbg_dasm_push_reg(p, reg);
		} else {
			adbg_dasm_push_reg(p, reg);
			adbg_dasm_push_reg(p, sr);
		}
		return;
	case 0x28: // 28H-2BH
		const(char) *m = void;
		int f = X86_FLAG_MODW_128B;
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE: m = "movntps"; break;
				case X86_0F_66H: m = "movntpd"; break;
				case X86_0F_F2H: m = "movntsd"; break; // SSE4a
				case X86_0F_F3H: m = "movntsd"; break; // SSE4a
				default: adbg_dasm_err(p); return;
				}
			} else {
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE: m = "cvtpi2ps"; break;
				case X86_0F_66H: m = "cvtpi2pd"; break;
				case X86_0F_F2H: m = "cvtsi2sd"; break;
				case X86_0F_F3H: m = "cvtsi2ss"; break;
				default: adbg_dasm_err(p); return;
				}
				f |= X86_FLAG_DIR;
			}
		} else {
			switch (adbg_dasm_x86_0f_select(p)) {
			case X86_0F_NONE: m = "movaps"; break;
			case X86_0F_66H: m = "movapd"; break;
			default: adbg_dasm_err(p); return;
			}
			if ((p.x86.op & X86_FLAG_WIDE) == 0)
				f |= X86_FLAG_DIR;
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, f);
		return;
	case 0x2C: // 2CH-2FH
		if (p.x86.op & X86_FLAG_DIR) {
			const(char) *m = void;
			switch (adbg_dasm_x86_0f_select(p)) {
			case X86_0F_NONE: m = p.x86.op & X86_FLAG_WIDE ? "comiss" : "ucomiss"; break;
			case X86_0F_66H: m = p.x86.op & X86_FLAG_WIDE ? "comisd" : "ucomisd"; break;
			default: adbg_dasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, m);
			adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
		} else {
			ubyte modrm = *p.ai8;
			++p.a;
			const(char) *m = void;
			int w = void;
			switch (adbg_dasm_x86_0f_select(p)) {
			case X86_0F_NONE:
				m = p.x86.op & X86_FLAG_WIDE ? "cvtps2pi" : "cvttps2pi";
				w = MemWidth.i64;
				break;
			case X86_0F_66H:
				m = p.x86.op & X86_FLAG_WIDE ? "cvtpd2pi" : "cvttpd2pi";
				w = MemWidth.i64;
				break;
			case X86_0F_F2H:
				m = p.x86.op & X86_FLAG_WIDE ? "cvtsd2si" : "cvttsd2si";
				w = MemWidth.i32;
				break;
			case X86_0F_F3H:
				m = p.x86.op & X86_FLAG_WIDE ? "cvtss2si" : "cvttss2si";
				w = MemWidth.i32;
				break;
			default: adbg_dasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File) {
				adbg_dasm_push_str(p, m);
				adbg_dasm_push_reg(p, adbg_dasm_x86_modrm_reg(p, modrm, w));
			}
			adbg_dasm_x86_modrm_rm(p, modrm, MemWidth.i32, MemWidth.i128);
		}
		return;
	case 0x30: // 30H-33H
		if (p.mode < DisasmMode.File)
			return;
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR)
			m = p.x86.op & X86_FLAG_WIDE ? "rdpmc" : "rdmsr";
		else
			m = p.x86.op & X86_FLAG_WIDE ? "rdtsc" : "wrmsr";
		adbg_dasm_push_str(p, m);
		return;
	case 0x34: // 34H-37H
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR)
			if (p.x86.op & X86_FLAG_WIDE) {
				m = "getsec";
			} else {
				adbg_dasm_err(p);
				return;
			}
		else
			m = p.x86.op & X86_FLAG_WIDE ? "sysexit" : "sysenter";
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		return;
	case 0x38: // 38H-3BH
		if (p.x86.op & X86_FLAG_WIDE) {
			adbg_dasm_err(p);
			return;
		}
		if (p.x86.op & X86_FLAG_DIR)
			adbg_dasm_x86_0f3a(p);
		else
			adbg_dasm_x86_0f38(p);
		return;
	case 0x40, 0x44, 0x48, 0x4C: // 40H-4FH
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, x86_T_CMOVcc[p.x86.op & 15]);
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_32B);
		return;
	case 0x50: // 50H-53H
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR) {
			switch (adbg_dasm_x86_0f_select(p)) {
			case X86_0F_NONE: m = p.x86.op & X86_FLAG_WIDE ? "rcpps" : "rsqrtps"; break;
			case X86_0F_F3H: m = p.x86.op & X86_FLAG_WIDE ? "rcpss" : "rsqrtss"; break;
			default: adbg_dasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, m);
			adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
		} else {
			if (p.x86.op & X86_FLAG_WIDE) {
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE: m = "sqrtps"; break;
				case X86_0F_66H: m = "sqrtpd"; break;
				case X86_0F_F2H: m = "sqrtsd"; break;
				case X86_0F_F3H: m = "sqrtss"; break;
				default: adbg_dasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, m);
				adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
			} else {
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE: m = "movmskps"; break;
				case X86_0F_66H: m = "movmskpd"; break;
				default: adbg_dasm_err(p); return;
				}
				ubyte modrm = *p.ai8;
				++p.ai8;
				if ((modrm & MODRM_MOD) != MODRM_MOD_11) {
					adbg_dasm_err(p);
					return;
				}
				if (p.mode >= DisasmMode.File) {
					adbg_dasm_push_x8(p, modrm);
					adbg_dasm_push_str(p, m);
					adbg_dasm_push_reg(p,
						adbg_dasm_x86_modrm_reg(p, modrm >> 3, MemWidth.i32));
					adbg_dasm_push_reg(p,
						adbg_dasm_x86_modrm_reg(p, modrm, MemWidth.i128));
				}
			}
		}
		return;
	case 0x54: // 54H-57H
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR) {
			switch (adbg_dasm_x86_0f_select(p)) {
			case X86_0F_NONE: m = p.x86.op & X86_FLAG_WIDE ? "xorps" : "orps"; break;
			case X86_0F_66H: m = p.x86.op & X86_FLAG_WIDE ? "xorpd" : "orpd"; break;
			default: adbg_dasm_err(p); return;
			}
		} else {
			switch (adbg_dasm_x86_0f_select(p)) {
			case X86_0F_NONE: m = p.x86.op & X86_FLAG_WIDE ? "andnps" : "andps"; break;
			case X86_0F_66H: m = p.x86.op & X86_FLAG_WIDE ? "andnpd" : "andpd"; break;
			default: adbg_dasm_err(p); return;
			}
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
		return;
	case 0x58: // 58H-5BH
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE: m = "cvtdq2ps"; break;
				case X86_0F_66H: m = "cvtps2dq"; break;
				case X86_0F_F3H: m = "cvttps2dq"; break;
				default: adbg_dasm_err(p); return;
				}
			} else {
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE: m = "cvtps2pd"; break;
				case X86_0F_66H: m = "cvtpd2ps"; break;
				case X86_0F_F2H: m = "cvtsd2ss"; break;
				case X86_0F_F3H: m = "cvtss2sd"; break;
				default: adbg_dasm_err(p); return;
				}
			}
		} else {
			switch (adbg_dasm_x86_0f_select(p)) {
			case X86_0F_NONE: m = p.x86.op & X86_FLAG_WIDE ? "mulps" : "addps"; break;
			case X86_0F_66H: m = p.x86.op & X86_FLAG_WIDE ? "mulpd" : "addpd"; break;
			case X86_0F_F2H: m = p.x86.op & X86_FLAG_WIDE ? "mulsd" : "addsd"; break;
			case X86_0F_F3H: m = p.x86.op & X86_FLAG_WIDE ? "mulss" : "addss"; break;
			default: adbg_dasm_err(p); return;
			}
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
		return;
	case 0x5C: // 5CH-5FH
		int s = adbg_dasm_x86_0f_select(p);
		if (s == X86_0F_F266H) {
			adbg_dasm_err(p);
			return;
		}
		if (p.mode >= DisasmMode.File) {
			s |= (p.x86.op & 3) << 2;
			adbg_dasm_push_str(p, x86_T_0F_5Ch[s]);
		}
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
		return;
	case 0x60: // 60H-63H
		int w = void;
		switch (adbg_dasm_x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_FLAG_MODW_64B | X86_FLAG_DIR; break;
		case X86_0F_66H: w = X86_FLAG_MODW_128B | X86_FLAG_DIR; break;
		default: adbg_dasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			if (p.x86.op & X86_FLAG_DIR)
				m = p.x86.op & X86_FLAG_WIDE ? "packsswb" : "punpckldq";
			else
				m = p.x86.op & X86_FLAG_WIDE ? "punpcklwd" : "punpcklbw";
			adbg_dasm_push_str(p, m);
		}
		adbg_dasm_x86_modrm(p, w);
		return;
	case 0x64: // 64H-67H
		int w = void;
		switch (adbg_dasm_x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_FLAG_MODW_64B | X86_FLAG_DIR; break;
		case X86_0F_66H: w = X86_FLAG_MODW_128B | X86_FLAG_DIR; break;
		default: adbg_dasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			if (p.x86.op & X86_FLAG_DIR)
				m = p.x86.op & X86_FLAG_WIDE ? "packuswb" : "pcmpgtd";
			else
				m = p.x86.op & X86_FLAG_WIDE ? "pcmpgtw" : "pcmpgtb";
			adbg_dasm_push_str(p, m);
		}
		adbg_dasm_x86_modrm(p, w);
		return;
	case 0x68: // 68H-6BH
		int w = void;
		switch (adbg_dasm_x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_FLAG_MODW_64B | X86_FLAG_DIR; break;
		case X86_0F_66H: w = X86_FLAG_MODW_128B | X86_FLAG_DIR; break;
		default: adbg_dasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			if (p.x86.op & X86_FLAG_DIR)
				m = p.x86.op & X86_FLAG_WIDE ? "packssdw" : "punpckhdq";
			else
				m = p.x86.op & X86_FLAG_WIDE ? "punpckhwd" : "punpckhbw";
			adbg_dasm_push_str(p, m);
		}
		adbg_dasm_x86_modrm(p, w);
		return;
	case 0x6C: // 6CH-6FH
		const(char) *m = void;
		int w = void;
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE:
					m = "movq";
					w = X86_FLAG_MODW_64B;
					break;
				case X86_0F_66H:
					m = "movdqa";
					w = X86_FLAG_MODW_128B;
					break;
				case X86_0F_F3H:
					m = "movdqu";
					w = X86_FLAG_MODW_128B;
					break;
				default: adbg_dasm_err(p); return;
				}
			} else {
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE: w = X86_FLAG_MODW_64B; break;
				case X86_0F_66H: w = X86_FLAG_MODW_128B; break;
				default: adbg_dasm_err(p); return;
				}
				m = "movd";
			}
		} else {
			switch (adbg_dasm_x86_0f_select(p)) {
			case X86_0F_66H: break;
			default: adbg_dasm_err(p); return;
			}
			w = X86_FLAG_MODW_128B;
			m = p.x86.op & X86_FLAG_WIDE ? "punpckhqdq" : "punpcklqdq";
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | w);
		break;
	case 0x70: // 70H-73H
		ubyte modrm = *p.ai8;
		++p.ai8;
		if ((modrm & MODRM_MOD) != MODRM_MOD_11) {
			adbg_dasm_err(p);
			break;
		}
		const(char) *m = void;
		int w = void;
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) { // GRP14
				switch (modrm & MODRM_REG) {
				case MODRM_REG_010:
					switch (adbg_dasm_x86_0f_select(p)) {
					case X86_0F_NONE: w = X86_FLAG_MODW_64B; break;
					case X86_0F_66H: w = X86_FLAG_MODW_128B; break;
					default: adbg_dasm_err(p); return;
					}
					m = "psrlq";
					break;
				case MODRM_REG_011:
					switch (adbg_dasm_x86_0f_select(p)) {
					case X86_0F_66H: w = X86_FLAG_MODW_128B; break;
					default: adbg_dasm_err(p); return;
					}
					m = "psrldq";
					break;
				case MODRM_REG_110:
					switch (adbg_dasm_x86_0f_select(p)) {
					case X86_0F_NONE: w = X86_FLAG_MODW_64B; break;
					case X86_0F_66H: w = X86_FLAG_MODW_128B; break;
					default: adbg_dasm_err(p); return;
					}
					m = "psllq";
					break;
				case MODRM_REG_111:
					switch (adbg_dasm_x86_0f_select(p)) {
					case X86_0F_66H: w = X86_FLAG_MODW_128B; break;
					default: adbg_dasm_err(p); return;
					}
					m = "pslldq";
					break;
				default: adbg_dasm_err(p); return;
				}
			} else { // GRP13
				switch (modrm & MODRM_REG) {
				case MODRM_REG_010:
					switch (adbg_dasm_x86_0f_select(p)) {
					case X86_0F_NONE: w = X86_FLAG_MODW_64B; break;
					case X86_0F_66H: w = X86_FLAG_MODW_128B; break;
					default: adbg_dasm_err(p); return;
					}
					m = "psrld";
					break;
				case MODRM_REG_100:
					switch (adbg_dasm_x86_0f_select(p)) {
					case X86_0F_NONE: w = X86_FLAG_MODW_64B; break;
					case X86_0F_66H: w = X86_FLAG_MODW_128B; break;
					default: adbg_dasm_err(p); return;
					}
					m = "psrad";
					break;
				case MODRM_REG_110:
					switch (adbg_dasm_x86_0f_select(p)) {
					case X86_0F_NONE: w = X86_FLAG_MODW_64B; break;
					case X86_0F_66H: w = X86_FLAG_MODW_128B; break;
					default: adbg_dasm_err(p); return;
					}
					m = "pslld";
					break;
				default: adbg_dasm_err(p); return;
				}
			}
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, m);
			adbg_dasm_x86_modrm(p, X86_FLAG_DIR | w);
		} else {
			if (p.x86.op & X86_FLAG_WIDE) { // GRP12
				switch (modrm & MODRM_REG) {
				case MODRM_REG_010:
					m = "psrlw";
					switch (adbg_dasm_x86_0f_select(p)) {
					case X86_0F_NONE: w = X86_FLAG_MODW_64B; break;
					case X86_0F_66H: w = X86_FLAG_MODW_128B; break;
					default: adbg_dasm_err(p); return;
					}
					break;
				case MODRM_REG_100:
					m = "psraw";
					switch (adbg_dasm_x86_0f_select(p)) {
					case X86_0F_NONE: w = X86_FLAG_MODW_64B; break;
					case X86_0F_66H: w = X86_FLAG_MODW_128B; break;
					default: adbg_dasm_err(p); return;
					}
					break;
				case MODRM_REG_110:
					m = "psllw";
					switch (adbg_dasm_x86_0f_select(p)) {
					case X86_0F_NONE: w = X86_FLAG_MODW_64B; break;
					case X86_0F_66H: w = X86_FLAG_MODW_128B; break;
					default: adbg_dasm_err(p); return;
					}
					break;
				default: adbg_dasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, m);
				adbg_dasm_x86_modrm(p, X86_FLAG_DIR | w);
			} else {
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE:
					m = "pshufw";
					w = MemWidth.i64;
					break;
				case X86_0F_66H:
					m = "pshufd";
					w = MemWidth.i128;
					break;
				case X86_0F_F2H:
					m = "pshuflw";
					w = MemWidth.i128;
					break;
				case X86_0F_F3H:
					m = "pshufhw";
					w = MemWidth.i128;
					break;
				default: adbg_dasm_err(p); return;
				}
				ubyte imm = *p.ai8;
				++p.ai8;
				if (p.mode >= DisasmMode.File) {
					adbg_dasm_push_x8(p, modrm);
					adbg_dasm_push_x8(p, imm);
					adbg_dasm_push_str(p, m);
					adbg_dasm_push_reg(p,
						adbg_dasm_x86_modrm_reg(p, modrm >> 3, w));
					adbg_dasm_push_reg(p,
						adbg_dasm_x86_modrm_reg(p, modrm, w));
					adbg_dasm_push_imm(p, imm);
				}
			}
		}
		return;
	case 0x74: // 74H-77H
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "emms");
			} else {
				int w = void;
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE: w = X86_FLAG_MODW_64B | X86_FLAG_DIR; break;
				case X86_0F_66H: w = X86_FLAG_MODW_128B | X86_FLAG_DIR; break;
				default: adbg_dasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "pcmpeqd");
				adbg_dasm_x86_modrm(p, w);
			}
		} else {
			int w = void;
			switch (adbg_dasm_x86_0f_select(p)) {
			case X86_0F_NONE: w = X86_FLAG_MODW_64B | X86_FLAG_DIR; break;
			case X86_0F_66H: w = X86_FLAG_MODW_128B | X86_FLAG_DIR; break;
			default: adbg_dasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, p.x86.op & X86_FLAG_WIDE ? "pcmpeqw" : "pcmpeqb");
			adbg_dasm_x86_modrm(p, w);
		}
		return;
	case 0x78: // 78H-7BH
		if (p.x86.op & X86_FLAG_DIR) {
			adbg_dasm_err(p);
			return;
		}
		int f;
		switch (adbg_dasm_x86_0f_select(p)) {
		case X86_0F_NONE: // (Intel) VMX
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, p.x86.op & X86_FLAG_WIDE ? "vmwrite" : "vmread");
			if (p.x86.op & X86_FLAG_WIDE)
				f |= X86_FLAG_DIR;
			adbg_dasm_x86_modrm(p, f | X86_FLAG_MODW_32B);
			return;
		case X86_0F_66H: // (AMD) SSE4a
			ubyte modrm = *p.ai8; // Reg only
			++p.ai8;
			if (p.x86.op & X86_FLAG_WIDE) {
				if ((modrm & MODRM_MOD) != MODRM_MOD_11) {
					adbg_dasm_err(p);
					return;
				}
				if (p.mode >= DisasmMode.File) {
					adbg_dasm_push_x8(p, modrm);
					adbg_dasm_push_str(p, "extrq");
					adbg_dasm_push_reg(p,
						adbg_dasm_x86_modrm_reg(p, modrm >> 3, MemWidth.i128));
					adbg_dasm_push_reg(p,
						adbg_dasm_x86_modrm_reg(p, modrm, MemWidth.i128));
				}
			} else { // Group 17
				if (modrm & MODRM_REG || (modrm & MODRM_MOD) != MODRM_MOD_11) {
					adbg_dasm_err(p);
					return;
				}
				if (p.mode >= DisasmMode.File) {
					adbg_dasm_push_x8(p, modrm);
					adbg_dasm_push_str(p, "extrq");
					adbg_dasm_push_reg(p,
						adbg_dasm_x86_modrm_reg(p, modrm, MemWidth.i128));
				}
				adbg_dasm_x86_u8imm(p);
				adbg_dasm_x86_u8imm(p);
			}
			return;
		case X86_0F_F2H: // SSE4a
			ubyte modrm = *p.ai8; // Reg only
			++p.ai8;
			if (p.x86.op & X86_FLAG_WIDE) {
				if ((modrm & MODRM_MOD) != MODRM_MOD_11) {
					adbg_dasm_err(p);
					return;
				}
				if (p.mode >= DisasmMode.File) {
					adbg_dasm_push_x8(p, modrm);
					adbg_dasm_push_str(p, "insertq");
					adbg_dasm_push_reg(p,
						adbg_dasm_x86_modrm_reg(p, modrm >> 3, MemWidth.i128));
					adbg_dasm_push_reg(p,
						adbg_dasm_x86_modrm_reg(p, modrm, MemWidth.i128));
				}
			} else { // Group 17/GRP17
				if ((modrm & MODRM_MOD) != MODRM_MOD_11) {
					adbg_dasm_err(p);
					return;
				}
				if (p.mode >= DisasmMode.File) {
					adbg_dasm_push_x8(p, modrm);
					adbg_dasm_push_str(p, "insertq");
					adbg_dasm_push_reg(p,
						adbg_dasm_x86_modrm_reg(p, modrm >> 3, MemWidth.i128));
					adbg_dasm_push_reg(p,
						adbg_dasm_x86_modrm_reg(p, modrm, MemWidth.i128));
				}
				adbg_dasm_x86_u8imm(p);
				adbg_dasm_x86_u8imm(p);
			}
			return;
		default: adbg_dasm_err(p); return;
		}
	case 0x7C: // 7CH-7FH
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR) {
			int f = void;
			if (p.x86.op & X86_FLAG_WIDE) {
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE:
					m = "movq";
					f = X86_FLAG_MODW_64B;
					break;
				case X86_0F_66H:
					m = "movdqa";
					f = X86_FLAG_MODW_128B;
					break;
				case X86_0F_F3H:
					m = "movdqu";
					f = X86_FLAG_MODW_128B;
					break;
				default: adbg_dasm_err(p); return;
				}
			} else {
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE:
					m = "movd";
					f = X86_FLAG_MODW_64B;
					break;
				case X86_0F_66H:
					m = "movd";
					f = X86_FLAG_MODW_128B;
					break;
				case X86_0F_F3H:
					m = "movq";
					f = X86_FLAG_MODW_128B | X86_FLAG_DIR;
					break;
				default: adbg_dasm_err(p); return;
				}
			}
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, m);
			adbg_dasm_x86_modrm(p, f);
		} else {
			switch (adbg_dasm_x86_0f_select(p)) {
			case X86_0F_66H: m = p.x86.op & X86_FLAG_WIDE ? "hsubpd" : "haddpd"; break;
			case X86_0F_F2H: m = p.x86.op & X86_FLAG_WIDE ? "hsubps" : "haddps"; break;
			default: adbg_dasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, m);
			adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
		}
		return;
	case 0x80, 0x84, 0x88, 0x8C: // 80H-83H
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, x86_T_Jcc[p.x86.op & 15]);
		adbg_dasm_x86_u32imm(p);
		return;
	case 0x90, 0x94, 0x98, 0x9C: // 90H-93H
		ubyte modrm = *p.ai8;
		++p.ai8;
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, x86_T_SETcc[p.x86.op & 15]);
		adbg_dasm_x86_modrm_rm(p, modrm, MemWidth.i8, MemWidth.i8);
		return;
	case 0xA0: // A0H-A3H
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "bt");
				adbg_dasm_x86_modrm(p, X86_FLAG_MODW_32B);
			} else {
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "cpuid");
			}
		} else {
			if (p.mode >= DisasmMode.File) {
				adbg_dasm_push_str(p, p.x86.op & X86_FLAG_WIDE ? "pop" : "push");
				adbg_dasm_push_reg(p, "fs");
			}
		}
		return;
	case 0xA4: // A4H-A7H
		if (p.x86.op & X86_FLAG_DIR) {
			adbg_dasm_err(p);
			return;
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, "shld");
		adbg_dasm_x86_modrm(p, X86_FLAG_MODW_32B);
		if (p.x86.op & X86_FLAG_WIDE) {
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_reg(p, "cl");
		} else {
			adbg_dasm_x86_u8imm(p);
		}
		return;
	case 0xA8: // A8H-ABH
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "bts");
				adbg_dasm_x86_modrm(p, X86_FLAG_MODW_32B);
			} else {
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "rsm");
			}
		} else {
			if (p.mode >= DisasmMode.File) {
				adbg_dasm_push_str(p, p.x86.op & X86_FLAG_WIDE ? "pop" : "push");
				adbg_dasm_push_reg(p, "gs");
			}
		}
		return;
	case 0xAC: // ACH-AFH
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "imul");
				adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_32B);
			} else { // GRP15
				ubyte modrm = *p.ai8;
				++p.ai8;
				const(char) *m = void;
				if ((modrm & MODRM_MOD) == MODRM_MOD_11) {
					switch (adbg_dasm_x86_0f_select(p)) {
					case X86_0F_NONE:
						switch (modrm & MODRM_REG) {
						case MODRM_REG_101: m = "lfence"; break;
						case MODRM_REG_110: m = "mfence"; break;
						case MODRM_REG_111: m = "sfence"; break;
						default: adbg_dasm_err(p); return;
						}
						if (p.mode >= DisasmMode.File) {
							adbg_dasm_push_x8(p, modrm);
							adbg_dasm_push_str(p, m);
						}
						return;
					case X86_0F_66H, X86_0F_F2H: // waitpkg
						switch (modrm & MODRM_REG) {
						case MODRM_REG_110: // Same REG field (/6)
							m = p.x86.pf_operand ? "tpause" : "umwait";
							break;
						default: adbg_dasm_err(p); return;
						}
						if (p.mode >= DisasmMode.File) {
							p.x86.pf_operand = 0;
							adbg_dasm_push_x8(p, modrm);
							adbg_dasm_push_str(p, m);
							adbg_dasm_push_reg(p,
								adbg_dasm_x86_modrm_reg(p, modrm, MemWidth.i32));
							adbg_dasm_push_reg(p, "edx");
							adbg_dasm_push_reg(p, "eax");
						}
						return;
					case X86_0F_F3H:
						switch (modrm & MODRM_REG) {
						case MODRM_REG_000: m = "rdfsbase"; break;
						case MODRM_REG_001: m = "rdgsbase"; break;
						case MODRM_REG_010: m = "wrfsbase"; break;
						case MODRM_REG_011: m = "wrgsbase"; break;
						case MODRM_REG_110: m = "umonitor"; break;
						default: adbg_dasm_err(p); return;
						}
						if (p.mode >= DisasmMode.File) {
							adbg_dasm_push_x8(p, modrm);
							adbg_dasm_push_str(p, m);
							adbg_dasm_push_reg(p,
								adbg_dasm_x86_modrm_reg(p, modrm, MemWidth.i32));
						}
						return;
					default: adbg_dasm_err(p); return;
					}
				} else { // mem
					switch (modrm & MODRM_REG) {
					case MODRM_REG_000: m = "fxsave"; break;
					case MODRM_REG_001: m = "fxrstor"; break;
					case MODRM_REG_010: m = "ldmxcsr"; break;
					case MODRM_REG_011: m = "stmxcsr"; break;
					case MODRM_REG_100: m = "xsave"; break;
					case MODRM_REG_101: m = "xrstor"; break;
					case MODRM_REG_110: m = "xsaveopt"; break;
					default:            m = "clflush"; break;
					}
					if (p.mode >= DisasmMode.File)
						adbg_dasm_push_str(p, m);
					adbg_dasm_x86_modrm_rm(p, modrm, MemWidth.i32, MemWidth.i32);
				}
			}
		} else {
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, "shld");
			adbg_dasm_x86_modrm(p, X86_FLAG_MODW_32B);
			if (p.x86.op & X86_FLAG_WIDE) {
				adbg_dasm_x86_u8imm(p);
			} else {
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_reg(p, "cl");
			}
		}
		return;
	case 0xB0: // B0H-B3H
		int f = void;
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR) {
			m = p.x86.op & X86_FLAG_WIDE ? "btr" : "lss";
			f = X86_FLAG_MODW_32B;
			if (p.x86.op & X86_FLAG_WIDE)
				f |= X86_FLAG_DIR;
		} else {
			m = "cmpxchg";
			if (p.x86.op & X86_FLAG_WIDE) {
				f = X86_FLAG_DIR | X86_FLAG_MODW_32B;
			} else {
				f = X86_FLAG_DIR | X86_FLAG_MODW_8B;
			}
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, "cmpxchg");
		adbg_dasm_x86_modrm(p, f);
		return;
	case 0xB4: // B4H-B7H
		const(char) *m = void;
		int f = void;
		if (p.x86.op & X86_FLAG_DIR) {
			m = "movzx";
			f = p.x86.op & X86_FLAG_WIDE ?
				X86_FLAG_DIR | X86_FLAG_MODW_16B :
				X86_FLAG_DIR | X86_FLAG_MODW_8B;
		} else {
			m = p.x86.op & X86_FLAG_WIDE ? "lgs" : "lfs";
			f = X86_FLAG_DIR | X86_FLAG_MODW_32B;
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, f);
		return;
	case 0xB8: // B8H-BBH
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				ubyte modrm = *p.ai8;
				++p.ai8;
				if ((modrm & MODRM_MOD) != MODRM_MOD_11) {
					adbg_dasm_err(p);
					return;
				}
				const(char) *m = void;
				switch (modrm & MODRM_REG) {
				case MODRM_REG_100: m = "bt"; break;
				case MODRM_REG_101: m = "bts"; break;
				case MODRM_REG_110: m = "btr"; break;
				case MODRM_REG_111: m = "btc"; break;
				default: adbg_dasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File) {
					adbg_dasm_push_x8(p, modrm);
					adbg_dasm_push_str(p, m);
					adbg_dasm_push_reg(p,
						adbg_dasm_x86_modrm_reg(p, modrm, MemWidth.i32));
				}
				adbg_dasm_x86_u8imm(p);
			} else {
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "btc");
				adbg_dasm_x86_modrm(p, X86_FLAG_MODW_32B);
			}
		} else {
			if (p.x86.op & X86_FLAG_WIDE) {
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "ud1");
			} else {
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_F3H:
					if (p.mode >= DisasmMode.File)
						adbg_dasm_push_str(p, "popcnt");
					adbg_dasm_x86_modrm(p, X86_FLAG_MODW_32B);
					return;
				default: adbg_dasm_err(p);
				}
			}
		}
		return;
	case 0xBC: // BCH-BFH
		const(char) *m = void;
		int f = void;
		if (p.x86.op & X86_FLAG_DIR) {
			m = "movsx";
			f = p.x86.op & X86_FLAG_WIDE ?
				X86_FLAG_DIR | X86_FLAG_MODW_16B :
				X86_FLAG_DIR | X86_FLAG_MODW_8B;
		} else {
			switch (adbg_dasm_x86_0f_select(p)) {
			case X86_0F_NONE: m = p.x86.op & X86_FLAG_WIDE ? "bsr" : "bsf"; break;
			case X86_0F_F3H: m = p.x86.op & X86_FLAG_WIDE ? "lzcnt" : "tzcnt"; break;
			default: adbg_dasm_err(p); return;
			}
			f = X86_FLAG_DIR | X86_FLAG_MODW_32B;
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, f);
		return;
	case 0xC0: // C0H-C3H
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "movnti");
				adbg_dasm_x86_modrm(p, X86_FLAG_MODW_32B);
			} else {
				const(char) *m = void;
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE: m = "cmpps"; break;
				case X86_0F_66H:  m = "cmppd"; break;
				case X86_0F_F2H:  m = "cmpsd"; break;
				case X86_0F_F3H:  m = "cmpss"; break;
				default: adbg_dasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, m);
				adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
				adbg_dasm_x86_u8imm(p);
			}
		} else {
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, "xadd");
			adbg_dasm_x86_modrm(p, X86_FLAG_MODW_32B);
		}
		return;
	case 0xC4: // C4H-C7H
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) { // GRP9
				ubyte modrm = *p.ai8;
				++p.ai8;
				int modrm_reg = modrm & MODRM_REG;
				if ((modrm & MODRM_MOD) == MODRM_MOD_11) {
					const(char) *m = void;
					switch (modrm_reg) {
					case MODRM_REG_110: m = "rdrand"; break;
					case MODRM_REG_111:
						switch (adbg_dasm_x86_0f_select(p)) {
						case X86_0F_NONE: m = "rdseed"; break;
						case X86_0F_66H: m = "rdpid"; break;
						default: adbg_dasm_err(p); return;
						}
						break;
					default: adbg_dasm_err(p); return;
					}
					if (p.mode >= DisasmMode.File) {
						adbg_dasm_push_x8(p, modrm);
						adbg_dasm_push_str(p, m);
						adbg_dasm_push_reg(p,
							adbg_dasm_x86_modrm_reg(p, modrm, MemWidth.i32));
					}
				} else {
					const(char) *m = void;
					switch (modrm_reg) {
					// cmpxchg16b is only in x86-64
					// in x86-64, cmpxchg16b can be selected with REX 48H
					case MODRM_REG_001: m = "cmpxchg8b"; break;
					case MODRM_REG_110:
						switch (adbg_dasm_x86_0f_select(p)) {
						case X86_0F_NONE: m = "vmptrld"; break;
						case X86_0F_66H: m = "vmclear"; break;
						case X86_0F_F3H: m = "vmxon"; break;
						default: adbg_dasm_err(p); return;
						}
						break;
					case MODRM_REG_111: m = "vmptrst"; break;
					default: adbg_dasm_err(p); return;
					}
					if (p.mode >= DisasmMode.File)
						adbg_dasm_push_str(p, m);
					adbg_dasm_x86_modrm_rm(p, modrm, MemWidth.i32, MemWidth.i32);
				}
			} else {
				ubyte modrm = *p.ai8;
				++p.ai8;
				if ((modrm & MODRM_MOD) != MODRM_MOD_11) {
					adbg_dasm_err(p);
					return;
				}
				const(char) *m = void;
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE: m = "shufps"; break;
				case X86_0F_66H: m = "shufpd"; break;
				default: adbg_dasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File) {
					adbg_dasm_push_x8(p, modrm);
					adbg_dasm_push_str(p, m);
					adbg_dasm_push_reg(p,
						adbg_dasm_x86_modrm_reg(p, modrm >> 3, MemWidth.i128));
					adbg_dasm_push_reg(p,
						adbg_dasm_x86_modrm_reg(p, modrm, MemWidth.i128));
				}
				adbg_dasm_x86_u8imm(p);
			}
		} else {
			if (p.x86.op & X86_FLAG_WIDE) {
				ubyte modrm = *p.ai8;
				++p.ai8;
				if ((modrm & MODRM_MOD) != MODRM_MOD_11) {
					adbg_dasm_err(p);
					return;
				}
				int w = void;
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE: w = MemWidth.i64; break;
				case X86_0F_66H: w = MemWidth.i128; break;
				default: adbg_dasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File) {
					adbg_dasm_push_x8(p, modrm);
					adbg_dasm_push_str(p, "pextrw");
					adbg_dasm_push_reg(p, adbg_dasm_x86_modrm_reg(p, modrm >> 3, MemWidth.i32));
					adbg_dasm_push_reg(p, adbg_dasm_x86_modrm_reg(p, modrm, w));
				}
				adbg_dasm_x86_u8imm(p);
			} else {
				int w = void;
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE: w = X86_FLAG_MODW_64B | X86_FLAG_DIR; break;
				case X86_0F_66H: w = X86_FLAG_MODW_128B | X86_FLAG_DIR; break;
				default: adbg_dasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "pinsrw");
				adbg_dasm_x86_modrm(p, w);
				adbg_dasm_x86_u8imm(p);
			}
		}
		return;
	case 0xC8, 0xCC: // C8H-CFH
		if (p.mode < DisasmMode.File)
			return;
		adbg_dasm_push_str(p, "bswap");
		adbg_dasm_push_reg(p, adbg_dasm_x86_modrm_reg(p, p.x86.op, X86_FLAG_MODW_32B));
		return;
	case 0xD0: // D0H-D3H
		if (p.x86.op & X86_FLAG_DIR) {
			int w = void;
			switch (adbg_dasm_x86_0f_select(p)) {
			case X86_0F_NONE: w = X86_FLAG_MODW_64B | X86_FLAG_DIR; break;
			case X86_0F_66H: w = X86_FLAG_MODW_128B | X86_FLAG_DIR; break;
			default: adbg_dasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, p.x86.op & X86_FLAG_WIDE ? "psrlq" : "psrld");
			adbg_dasm_x86_modrm(p, w);
		} else {
			if (p.x86.op & X86_FLAG_WIDE) {
				int w = void;
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE: w = X86_FLAG_MODW_64B | X86_FLAG_DIR; break;
				case X86_0F_66H: w = X86_FLAG_MODW_128B | X86_FLAG_DIR; break;
				default: adbg_dasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "psrlw");
				adbg_dasm_x86_modrm(p, w);
			} else {
				const(char) *m = void;
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_66H: m = "addsubpd"; break;
				case X86_0F_F2H: m = "addsubps"; break;
				default: adbg_dasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, m);
				adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
			}
		}
		return;
	case 0xD4: // D4H-D7H
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				ubyte modrm = *p.ai8;
				++p.ai8;
				if ((modrm & MODRM_MOD) != MODRM_MOD_11) {
					adbg_dasm_err(p);
					return;
				}
				int w = void;
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE: w = MemWidth.i64; break;
				case X86_0F_66H: w = MemWidth.i128; break;
				default: adbg_dasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File) {
					adbg_dasm_push_x8(p, modrm);
					adbg_dasm_push_str(p, "pmovmskb");
					adbg_dasm_push_reg(p,
						adbg_dasm_x86_modrm_reg(p, modrm >> 3, MemWidth.i32));
					adbg_dasm_push_reg(p,
						adbg_dasm_x86_modrm_reg(p, modrm, w));
				}
			} else {
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_66H:
					if (p.mode >= DisasmMode.File)
						adbg_dasm_push_str(p, "movq");
					adbg_dasm_x86_modrm(p, X86_FLAG_MODW_128B);
					return;
				case X86_0F_F2H:
					ubyte modrm = *p.ai8;
					++p.ai8;
					if ((modrm & MODRM_MOD) != MODRM_MOD_11) {
						adbg_dasm_err(p);
						return;
					}
					if (p.mode >= DisasmMode.File) {
						adbg_dasm_push_x8(p, modrm);
						adbg_dasm_push_str(p, "movdq2q");
						adbg_dasm_push_reg(p,
							adbg_dasm_x86_modrm_reg(p, modrm >> 3, MemWidth.i64));
						adbg_dasm_push_reg(p,
							adbg_dasm_x86_modrm_reg(p, modrm, MemWidth.i128));
					}
					return;
				case X86_0F_F3H:
					ubyte modrm = *p.ai8;
					++p.ai8;
					if ((modrm & MODRM_MOD) != MODRM_MOD_11) {
						adbg_dasm_err(p);
						return;
					}
					if (p.mode >= DisasmMode.File) {
						adbg_dasm_push_x8(p, modrm);
						adbg_dasm_push_str(p, "movq2dq");
						adbg_dasm_push_reg(p,
							adbg_dasm_x86_modrm_reg(p, modrm >> 3, MemWidth.i128));
						adbg_dasm_push_reg(p,
							adbg_dasm_x86_modrm_reg(p, modrm, MemWidth.i64));
					}
					return;
				default: adbg_dasm_err(p); return;
				}
			}
		} else {
			int w = void;
			switch (adbg_dasm_x86_0f_select(p)) {
			case X86_0F_NONE: w = X86_FLAG_MODW_64B | X86_FLAG_DIR; break;
			case X86_0F_66H: w = X86_FLAG_MODW_128B | X86_FLAG_DIR; break;
			default: adbg_dasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, p.x86.op & X86_FLAG_WIDE ? "pmullw" : "paddq");
			adbg_dasm_x86_modrm(p, w);
		}
		return;
	case 0xD8: // D8H-DBH
		int w = void;
		switch (adbg_dasm_x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_FLAG_MODW_64B | X86_FLAG_DIR; break;
		case X86_0F_66H: w = X86_FLAG_MODW_128B | X86_FLAG_DIR; break;
		default: adbg_dasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (p.x86.op & 3) {
			case 0:  m = "psubusb"; break;
			case 1:  m = "psubusw"; break;
			case 2:  m = "pminub"; break;
			default: m = "pand"; break;
			}
			adbg_dasm_push_str(p, m);
		}
		adbg_dasm_x86_modrm(p, w);
		return;
	case 0xDC: // DCH-DFH
		int w = void;
		switch (adbg_dasm_x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_FLAG_MODW_64B | X86_FLAG_DIR; break;
		case X86_0F_66H: w = X86_FLAG_MODW_128B | X86_FLAG_DIR; break;
		default: adbg_dasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (p.x86.op & 3) {
			case 0:  m = "paddusb"; break;
			case 1:  m = "paddusw"; break;
			case 2:  m = "pmaxub"; break;
			default: m = "pandn"; break;
			}
			adbg_dasm_push_str(p, m);
		}
		adbg_dasm_x86_modrm(p, w);
		return;
	case 0xE0: // E0H-E3H
		int w = void;
		switch (adbg_dasm_x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_FLAG_MODW_64B | X86_FLAG_DIR; break;
		case X86_0F_66H: w = X86_FLAG_MODW_128B | X86_FLAG_DIR; break;
		default: adbg_dasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (p.x86.op & 3) {
			case 0:  m = "pavgb"; break;
			case 1:  m = "psraw"; break;
			case 2:  m = "psrad"; break;
			default: m = "pavgw"; break;
			}
			adbg_dasm_push_str(p, m);
		}
		adbg_dasm_x86_modrm(p, w);
		return;
	case 0xE4: // E4H-E7H
		const(char) *m = void;
		int w = void;
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE:
					m = "movntq";
					w = X86_FLAG_MODW_64B;
					break;
				case X86_0F_66H:
					m = "movntdq";
					w = X86_FLAG_MODW_128B;
					break;
				default: adbg_dasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, m);
				adbg_dasm_x86_modrm(p, w);
			} else {
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_66H: m = "cvttpd2dq"; break;
				case X86_0F_F2H: m = "cvtpd2dq"; break;
				case X86_0F_F3H: m = "cvtdq2pd"; break;
				default: adbg_dasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, m);
				adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
			}
		} else {
			switch (adbg_dasm_x86_0f_select(p)) {
			case X86_0F_NONE: w = X86_FLAG_MODW_64B | X86_FLAG_DIR; break;
			case X86_0F_66H: w = X86_FLAG_MODW_128B | X86_FLAG_DIR; break;
			default: adbg_dasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, p.x86.op & X86_FLAG_WIDE ? "pmulhw" : "pmulhuw");
			adbg_dasm_x86_modrm(p, w);
		}
		return;
	case 0xE8: // E8H-EBH
		int w = void;
		switch (adbg_dasm_x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_FLAG_MODW_64B | X86_FLAG_DIR; break;
		case X86_0F_66H: w = X86_FLAG_MODW_128B | X86_FLAG_DIR; break;
		default: adbg_dasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (p.x86.op & 3) {
			case 0:  m = "psubsb"; break;
			case 1:  m = "psubsw"; break;
			case 2:  m = "pminsw"; break;
			default: m = "por"; break;
			}
			adbg_dasm_push_str(p, m);
		}
		adbg_dasm_x86_modrm(p, w);
		return;
	case 0xEC: // ECH-EFH
		int w = void;
		switch (adbg_dasm_x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_FLAG_MODW_64B | X86_FLAG_DIR; break;
		case X86_0F_66H: w = X86_FLAG_MODW_128B | X86_FLAG_DIR; break;
		default: adbg_dasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (p.x86.op & 3) {
			case 0:  m = "paddsb"; break;
			case 1:  m = "paddsw"; break;
			case 2:  m = "pmaxsw"; break;
			default: m = "pxor"; break;
			}
			adbg_dasm_push_str(p, m);
		}
		adbg_dasm_x86_modrm(p, w);
		return;
	case 0xF0: // F0H-F3H
		int w = void;
		if (p.x86.op & X86_FLAG_DIR) {
			switch (adbg_dasm_x86_0f_select(p)) {
			case X86_0F_NONE: w = X86_FLAG_MODW_64B; break;
			case X86_0F_66H: w = X86_FLAG_MODW_128B; break;
			default: adbg_dasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, p.x86.op & X86_FLAG_WIDE ? "psllq" : "psllq");
			adbg_dasm_x86_modrm(p, X86_FLAG_DIR | w);
		} else {
			const(char) *m = void;
			if (p.x86.op & X86_FLAG_WIDE) {
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE: w = X86_FLAG_MODW_64B; break;
				case X86_0F_66H: w = X86_FLAG_MODW_128B; break;
				default: adbg_dasm_err(p); return;
				}
				m = "psllw";
			} else {
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_F2H: w = X86_FLAG_MODW_128B; break;
				default: adbg_dasm_err(p); return;
				}
				m = "lldqu";
			}
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, m);
			adbg_dasm_x86_modrm(p, X86_FLAG_DIR | w);
		}
		return;
	case 0xF4: // F4H-F7H
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				ubyte modrm = *p.ai8;
				++p.ai8;
				if ((modrm & MODRM_MOD) != MODRM_MOD_11) {
					adbg_dasm_err(p);
					return;
				}
				int w = void;
				const(char) *m = void;
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE:
					m = "maskmovq";
					w = X86_FLAG_MODW_64B;
					break;
				case X86_0F_66H:
					m = "maskmovdqu";
					w = X86_FLAG_MODW_128B;
					break;
				default: adbg_dasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, m);
				adbg_dasm_x86_modrm(p, X86_FLAG_DIR | w);
			} else {
				int w = void;
				switch (adbg_dasm_x86_0f_select(p)) {
				case X86_0F_NONE: w = X86_FLAG_MODW_64B; break;
				case X86_0F_66H: w = X86_FLAG_MODW_128B; break;
				default: adbg_dasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, "psadbw");
				adbg_dasm_x86_modrm(p, X86_FLAG_DIR | w);
			}
		} else {
			int w = void;
			switch (adbg_dasm_x86_0f_select(p)) {
			case X86_0F_NONE: w = X86_FLAG_MODW_64B; break;
			case X86_0F_66H: w = X86_FLAG_MODW_128B; break;
			default: adbg_dasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, p.x86.op & X86_FLAG_WIDE ? "pmaddwd" : "pmuludq");
			adbg_dasm_x86_modrm(p, X86_FLAG_DIR | w);
		}
		return;
	case 0xF8: // F8H-FBH
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (p.x86.op & 3) {
			case 0:  m = "psubb"; break;
			case 1:  m = "psubw"; break;
			case 2:  m = "psubd"; break;
			default: m = "psubq"; break;
			}
			adbg_dasm_push_str(p, m);
		}
		int w = void;
		switch (adbg_dasm_x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_FLAG_MODW_64B; break;
		case X86_0F_66H: w = X86_FLAG_MODW_128B; break;
		default: adbg_dasm_err(p); return;
		}
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | w);
		return;
	case 0b1111_1100: // FCH-FFH
		// UD0 NOTE: Some older processors decode without ModR/M.
		// Instead, an opcode exception is thrown (instead of a fault).
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (p.x86.op & 3) {
			case 0:  m = "paddb"; break;
			case 1:  m = "paddw"; break;
			case 2:  m = "paddd"; break;
			default:
				adbg_dasm_push_str(p, "ud0");
				return;
			}
			adbg_dasm_push_str(p, m);
		}
		int w = void;
		switch (adbg_dasm_x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_FLAG_MODW_64B | X86_FLAG_DIR; break;
		case X86_0F_66H: w = X86_FLAG_MODW_128B | X86_FLAG_DIR; break;
		default: adbg_dasm_err(p); return;
		}
		adbg_dasm_x86_modrm(p, w);
		return;
	default: adbg_dasm_err(p); return;
	}
}

void adbg_dasm_x86_0f38(disasm_params_t *p) {
	p.x86.op = *p.ai8;
	++p.ai8;

	if (p.mode >= DisasmMode.File)
		adbg_dasm_push_x8(p, p.x86.op);

	switch (p.x86.op & 252) { // 1111_1100
	case 0: // 00H-03H
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR)
			m = p.x86.op & X86_FLAG_WIDE ? "phaddsw" : "phaddd";
		else
			m = p.x86.op & X86_FLAG_WIDE ? "phaddw" : "pshufb";
		int w = p.x86.pf_operand ? X86_FLAG_MODW_128B : X86_FLAG_MODW_64B;
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | w);
		return;
	case 0x04: // 04H-07H
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR)
			m = p.x86.op & X86_FLAG_WIDE ? "phsubsw" : "phsubd";
		else
			m = p.x86.op & X86_FLAG_WIDE ? "phsubw" : "pmaddubsw";
		int w = p.x86.pf_operand ? X86_FLAG_MODW_128B : X86_FLAG_MODW_64B;
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | w);
		return;
	case 0x08: // 08H-0BH
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR) {
			m = p.x86.op & X86_FLAG_WIDE ? "pmulhrsw" : "psignd";
		} else {
			m = p.x86.op & X86_FLAG_WIDE ? "psignw" : "psignb";
		}
		int w = p.x86.pf_operand ? X86_FLAG_MODW_128B : X86_FLAG_MODW_64B;
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | w);
		return;
	case 0x10: // 10H-13H
		if (p.x86.op & X86_FLAG_DIR || p.x86.op & X86_FLAG_WIDE || p.x86.pf_operand == 0) {
			adbg_dasm_err(p);
			return;
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, "pblendvb");
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
		return;
	case 0x14: // 14H-17H
		if (p.x86.pf_operand == 0) {
			adbg_dasm_err(p);
			return;
		}
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				m = "ptest";
			} else {
				adbg_dasm_err(p);
				return;
			}
		} else {
			m = p.x86.op & X86_FLAG_WIDE ? "blendvpd" : "blendvps";
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
		return;
	case 0x1C: // 1CH-1FH
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				adbg_dasm_err(p);
				return;
			} else {
				m = "pabsd";
			}
		} else {
			m = p.x86.op & X86_FLAG_WIDE ? "pabsb" : "pabsw";
		}
		int w = p.x86.pf_operand ? X86_FLAG_MODW_128B : X86_FLAG_MODW_64B;
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | w);
		return;
	case 0x20: // 20H-23H
		if (p.x86.pf_operand == 0) {
			adbg_dasm_err(p);
			return;
		}
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR)
			m = p.x86.op & X86_FLAG_WIDE ? "pmovsxwd" : "pmovsxbq";
		else
			m = p.x86.op & X86_FLAG_WIDE ? "pmovsxbd" : "pmovsxbw";
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
		return;
	case 0x24: // 24H-27H
		if (p.x86.pf_operand == 0) {
			adbg_dasm_err(p);
			return;
		}
		if (p.x86.op & X86_FLAG_DIR) {
			adbg_dasm_err(p);
			return;
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, p.x86.op & X86_FLAG_WIDE ? "pmovsxbd" : "pmovsxbw");
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
		return;
	case 0x28: // 28H-2BH
		if (p.x86.pf_operand == 0) {
			adbg_dasm_err(p);
			return;
		}
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR) {
			m = p.x86.op & X86_FLAG_WIDE ? "packusdw" : "movntdqa";
		} else {
			m = p.x86.op & X86_FLAG_WIDE ? "pcmpeqq" : "pmuldq";
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
		return;
	case 0x30: // 30H-33H
		if (p.x86.pf_operand == 0) {
			adbg_dasm_err(p);
			return;
		}
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR) {
			m = p.x86.op & X86_FLAG_WIDE ? "pmovzxwd" : "pmovzxbq";
		} else {
			m = p.x86.op & X86_FLAG_WIDE ? "pmovzxbd" : "pmovzxbw";
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
		return;
	case 0x34: // 34H-37H
		if (p.x86.pf_operand == 0) {
			adbg_dasm_err(p);
			return;
		}
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				m = "pcmpgtq";
			} else {
				adbg_dasm_err(p);
				return;
			}
		} else {
			m = p.x86.op & X86_FLAG_WIDE ? "pmovzxdq" : "pmovzxwq";
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
		return;
	case 0x38: // 38H-3BH
		if (p.x86.pf_operand == 0) {
			adbg_dasm_err(p);
			return;
		}
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR) {
			m = p.x86.op & X86_FLAG_WIDE ? "pminud" : "pminuw";
		} else {
			m = p.x86.op & X86_FLAG_WIDE ? "pminsd" : "pminsb";
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
		return;
	case 0x3C: // 3CH-3FH
		if (p.x86.pf_operand == 0) {
			adbg_dasm_err(p);
			return;
		}
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR) {
			m = p.x86.op & X86_FLAG_WIDE ? "pmaxud" : "pmaxuw";
		} else {
			m = p.x86.op & X86_FLAG_WIDE ? "pmaxsd" : "pmaxsb";
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
		return;
	case 0x40: // 40H-43H
		if (p.x86.op & X86_FLAG_DIR || p.x86.pf_operand == 0) {
			adbg_dasm_err(p);
			return;
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, p.x86.op & X86_FLAG_WIDE ? "phminposuw" : "pmulld");
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
		return;
	case 0x80: // 80H-83H
		if ((p.x86.op & X86_FLAG_WIDE && p.x86.op & X86_FLAG_DIR) || p.x86.pf_operand == 0) {
			adbg_dasm_err(p);
			return;
		}
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR)
			m = "invpcid";
		else
			m = p.x86.op & X86_FLAG_WIDE ? "invvpid" : "invept";
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, p.x86.op & X86_FLAG_WIDE ? "phminposuw" : "pmulld");
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_32B);
		return;
	case 0xC8: // C8H-CBH
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR)
			m = p.x86.op & X86_FLAG_WIDE ? "sha256rnds2" : "sha1msg2";
		else
			m = p.x86.op & X86_FLAG_WIDE ? "sha1msg1" : "sha1nexte";
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
		return;
	case 0xCC: // CCH-CFH
		if (p.x86.op & X86_FLAG_DIR) {
			adbg_dasm_err(p);
			return;
		}
		const(char) *m = p.x86.op & X86_FLAG_WIDE ? "sha256msg2" : "sha256msg1";
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
		return;
	case 0xD8: // D8H-DBH
		if (p.x86.op & X86_FLAG_DIR && p.x86.op & X86_FLAG_WIDE && p.x86.pf_operand) {
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, "aesimc");
			adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
		} else {
			adbg_dasm_err(p);
		}
		return;
	case 0xDC: // DBH-DFH
		if (p.x86.pf_operand == 0) {
			adbg_dasm_err(p);
			return;
		}
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR)
			m = p.x86.op & X86_FLAG_WIDE ? "aesdeclast" : "aesdec";
		else
			m = p.x86.op & X86_FLAG_WIDE ? "aesenclast" : "aesenc";
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
		return;
	case 0xF0: // F0H-F3H
		if (p.x86.op & X86_FLAG_DIR) { // Yep, GRP17 is all VEX stuff
			adbg_dasm_err(p);
			return;
		}
		const(char) *m = void;
		int f = void;
		switch (adbg_dasm_x86_0f_select(p)) {
		case X86_0F_NONE, X86_0F_66H:
			if ((*p.ai8 & MODRM_MOD) == MODRM_MOD_11) {
				adbg_dasm_err(p);
				return;
			}
			m = "movbe";
			f = X86_FLAG_MODW_32B;
			break;
		case X86_0F_F2H, X86_0F_F266H:
			m = "crc32";
			if (p.x86.op & X86_FLAG_WIDE) {
				f = X86_FLAG_MODW_32B;
			} else {
				f = X86_FLAG_REGW_32B | X86_FLAG_MEMW_8B;
			}
			break;
		default: adbg_dasm_err(p); return;
		}
		if (p.x86.op & X86_FLAG_DIR)
			f |= X86_FLAG_DIR;
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, f);
		return;
	case 0xF4: // F4H-F7H
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				adbg_dasm_err(p);
				return;
			}
			const(char) *m = void;
			switch (adbg_dasm_x86_0f_select(p)) {
			case X86_0F_66H: m = "adcx"; break;
			case X86_0F_F3H: m = "adox"; break;
			default: adbg_dasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				adbg_dasm_push_str(p, m);
			adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_32B);
		} else {
			adbg_dasm_err(p);
		}
		return;
	default: adbg_dasm_err(p); return;
	}
}

void adbg_dasm_x86_0f3a(disasm_params_t *p) {
	p.x86.op = *p.ai8;
	++p.ai8;

	if (p.mode >= DisasmMode.File)
		adbg_dasm_push_x8(p, p.x86.op);

	switch (p.x86.op & 252) { // 1111_1100
	case 0x08: // 08H-0BH
		if (p.x86.pf_operand == 0) {
			adbg_dasm_err(p);
			return;
		}
		p.x86.pf_operand = 0;
		const(char) *m = void;
		int f = void;
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				m = "roundsd";
				f = X86_FLAG_MEMW_64B | X86_FLAG_REGW_128B | X86_FLAG_DIR;
			} else {
				m = "roundss";
				f = X86_FLAG_MEMW_32B | X86_FLAG_REGW_128B | X86_FLAG_DIR;
			}
		} else {
			f = X86_FLAG_MODW_128B | X86_FLAG_DIR;
			m = p.x86.op & X86_FLAG_WIDE ? "roundpd" : "roundps";
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, f);
		adbg_dasm_x86_u8imm(p);
		return;
	case 0x0C: // 0CH-0FH
		const(char) *m = void;
		int w = void;
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				m = "palignr";
				w =  p.x86.pf_operand ? X86_FLAG_MODW_128B : X86_FLAG_MODW_64B;
			} else {
				if (p.x86.pf_operand == 0) {
					adbg_dasm_err(p);
					return;
				}
				m = "pblendw";
				w = X86_FLAG_MODW_128B;
			}
		} else {
			if (p.x86.pf_operand == 0) {
				adbg_dasm_err(p);
				return;
			}
			w = X86_FLAG_MODW_128B;
			m = p.x86.op & X86_FLAG_WIDE ? "blendpd" : "blendps";
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | w);
		adbg_dasm_x86_u8imm(p);
		return;
	case 0x14: // 14H-17H
		if (p.x86.pf_operand == 0) {
			adbg_dasm_err(p);
			return;
		}
		p.x86.pf_operand = 0;
		const(char) *m = void;
		int wmem = void;
		if (p.x86.op & X86_FLAG_DIR) {
			m = p.x86.op & X86_FLAG_WIDE ? "extractps" : "pextrd";
			wmem = X86_FLAG_MODW_32B;
		} else {
			if (p.x86.op & X86_FLAG_WIDE) {
				m = "pextrw";
				wmem = X86_FLAG_MODW_16B;
			} else {
				m = "pextrb";
				wmem = X86_FLAG_MODW_8B;
			}
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, wmem | X86_FLAG_MODW_128B);
		adbg_dasm_x86_u8imm(p);
		return;
	case 0x20: // 20H-23H
		if ((p.x86.op & X86_FLAG_DIR && p.x86.op & X86_FLAG_WIDE) || p.x86.pf_operand == 0) {
			adbg_dasm_err(p);
			return;
		}
		p.x86.pf_operand = 0;
		const(char) *m = void;
		int wmem = void;
		if (p.x86.op & X86_FLAG_DIR) {
			m = "pinsrd";
			wmem = X86_FLAG_MODW_32B;
		} else {
			if (p.x86.op & X86_FLAG_WIDE) {
				m = "insertps";
				wmem = X86_FLAG_MODW_32B;
			} else {
				m = "pinsrb";
				wmem = X86_FLAG_MODW_8B;
			}
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | wmem | X86_FLAG_MEMW_128B);
		adbg_dasm_x86_u8imm(p);
		return;
	case 0x40: // 40H-43H
		if ((p.x86.op & X86_FLAG_DIR && p.x86.op & X86_FLAG_WIDE) || p.x86.pf_operand == 0) {
			adbg_dasm_err(p);
			return;
		}
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR) {
			m = "mpsadbw";
		} else {
			m = p.x86.op & X86_FLAG_WIDE ? "dppd" : "dpps";
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
		adbg_dasm_x86_u8imm(p);
		return;
	case 0x44: // 44H-47H
		if (p.x86.op & (X86_FLAG_WIDE | X86_FLAG_DIR) || p.x86.pf_operand == 0) {
			adbg_dasm_err(p);
			return;
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, "pclmulqdq");
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
		adbg_dasm_x86_u8imm(p);
		return;
	case 0x60: // 60H-63H
		if (p.x86.pf_operand == 0) {
			adbg_dasm_err(p);
			return;
		}
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR) {
			m = p.x86.op & X86_FLAG_WIDE ? "pcmpistri" : "pcmpistrm";
		} else {
			m = p.x86.op & X86_FLAG_WIDE ? "pcmpestri" : "pcmpestrm";
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
		adbg_dasm_x86_u8imm(p);
		return;
	case 0xCC: // CCH-CFH
		if (p.x86.op & (X86_FLAG_WIDE | X86_FLAG_DIR) || p.x86.pf_operand) {
			adbg_dasm_err(p);
			return;
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, "sha1rnds4");
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
		adbg_dasm_x86_u8imm(p);
		return;
	case 0xDC: // DCH-DFH
		if ((p.x86.op & X86_FLAG_WIDE) == 0 || (p.x86.op & X86_FLAG_DIR) == 0 || p.x86.pf_operand == 0) {
			adbg_dasm_err(p);
			return;
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, "aeskeygenassist");
		adbg_dasm_x86_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B);
		adbg_dasm_x86_u8imm(p);
		return;
	default: adbg_dasm_err(p); return;
	}
}

//
// ANCHOR: VEX/XOP maps
//

void adbg_dasm_x86_vex_0f(disasm_params_t *p) {
	p.x86.op = *p.ai8;
	++p.ai8;

	if (p.mode >= DisasmMode.File)
		adbg_dasm_push_x8(p, p.x86.op);

	switch (p.x86.op & 252) {
	case 0x10: // 10H-13H
		const(char) *m = void;
		int f = X86_FLAG_REGW_128B;
		if ((p.x86.op & X86_FLAG_WIDE) == 0) f |= X86_FLAG_DIR;
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				switch (p.x86.vex_pp) {
				case X86_VEX_PP_NONE:
					m = "vmovlps";
					f |= X86_FLAG_MEMW_64B;
					break;
				case X86_VEX_PP_66H:
					m = "vmovlpd";
					f |= X86_FLAG_MEMW_64B;
					break;
				default: adbg_dasm_err(p); return;
				}
			} else {
				switch (p.x86.vex_pp) {
				case X86_VEX_PP_NONE:
					if ((*p.ai8 & MODRM_MOD) == MODRM_MOD_11) {
						m = "vmovhlps";
						f |= X86_FLAG_MEMW_128B | X86_FLAG_3OPRND;
					} else {
						m = "vmovlps";
						f |= X86_FLAG_MEMW_64B | X86_FLAG_3OPRND;
					}
					break;
				case X86_VEX_PP_66H:
					m = "vmovlpd";
					f |= X86_FLAG_MEMW_64B | X86_FLAG_3OPRND;
					break;
				case X86_VEX_PP_F3H:
					m = "vmovsldup";
					f |= X86_FLAG_MEMW_128B;
					break;
				default:
					m = "vmovddup";
					f |= X86_FLAG_MEMW_64B;
					break;
				}
			}
		} else {
			switch (p.x86.vex_pp) {
			case X86_VEX_PP_NONE:
				m = "vmovups";
				f |= X86_FLAG_MEMW_128B;
				break;
			case X86_VEX_PP_66H:
				m = "vmovupd";
				f |= X86_FLAG_MEMW_128B;
				break;
			case X86_VEX_PP_F3H:
				m = "vmovss";
				if ((*p.ai8 & MODRM_MOD) == MODRM_MOD_11) {
					f |= X86_FLAG_MEMW_128B | X86_FLAG_3OPRND;
				} else {
					f |= X86_FLAG_MEMW_32B;
				}
				break;
			default:
				m = "vmovsd";
				if ((*p.ai8 & MODRM_MOD) == MODRM_MOD_11) {
					f |= X86_FLAG_MEMW_128B | X86_FLAG_3OPRND;
				} else {
					f |= X86_FLAG_MEMW_32B;
				}
				break;
			}
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_vex_modrm(p, f);
		return;
	case 0x14: // 14H-17H
		const(char) *i = void;
		int f = X86_FLAG_REGW_128B;
		if (p.x86.op & X86_FLAG_DIR) {
			f |= X86_FLAG_MEMW_64B;
			if ((p.x86.op & X86_FLAG_WIDE) == 0)
				f |= X86_FLAG_3OPRND | X86_FLAG_DIR;
			switch (p.x86.vex_pp) {
			case X86_VEX_PP_NONE:
				f |= X86_FLAG_VEX_NO_L;
				if ((*p.ai8 & MODRM_MOD) == MODRM_MOD_11)
					i = "vmovlhps";
				else
					i = "vmovhps";
				break;
			case X86_VEX_PP_66H:
				f |= X86_FLAG_VEX_NO_L;
				i = "vmovhpd";
				break;
			case X86_VEX_PP_F3H:
				if (p.x86.op & X86_FLAG_WIDE) {
					adbg_dasm_err(p);
					return;
				}
				i = "vmovshdup";
				break;
			default: adbg_dasm_err(p); return;
			}
		} else {
			int w = p.x86.op & X86_FLAG_WIDE;
			f |= X86_FLAG_3OPRND | X86_FLAG_MEMW_128B | X86_FLAG_DIR;
			switch (p.x86.vex_pp) {
			case X86_VEX_PP_NONE: i = w ? "vunpckhps" : "vunpcklps"; break;
			case X86_VEX_PP_66H:  i = w ? "vunpckhpd" : "vunpcklpd"; break;
			default: adbg_dasm_err(p); return;
			}
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, i);
		adbg_dasm_x86_vex_modrm(p, f);
		return;
	case 0x50: // 50H-53H
		const(char) *i = void;
		int f = X86_FLAG_DIR;
		if (p.x86.op & X86_FLAG_DIR) {
			f = X86_FLAG_DIR | X86_FLAG_REGW_128B;
			if (p.x86.op & X86_FLAG_WIDE) {
				switch (p.x86.vex_pp) {
				case X86_VEX_PP_NONE: i = "vrcpps"; break;
				case X86_VEX_PP_F3H:
					i = "vrcpss";
					f |= X86_FLAG_3OPRND;
					break;
				default: adbg_dasm_err(p); return;
				}
			} else {
				switch (p.x86.vex_pp) {
				case X86_VEX_PP_NONE: i = "vrsqrtps"; break;
				case X86_VEX_PP_F3H:
					i = "vrsqrtss";
					f |= X86_FLAG_3OPRND | X86_FLAG_MEMW_32B;
					break;
				default: adbg_dasm_err(p); return;
				}
			}
		} else {
			if (p.x86.op & X86_FLAG_WIDE) {
				f |= X86_FLAG_REGW_128B;
				switch (p.x86.vex_pp) {
				case X86_VEX_PP_NONE: i = "vsqrtps"; break;
				case X86_VEX_PP_66H:  i = "vsqrtpd"; break;
				case X86_VEX_PP_F3H:
					i = "vsqrtss";
					f |= X86_FLAG_MEMW_32B | X86_FLAG_3OPRND;
					break;
				default:
					i = "vsqrtsd";
					f |= X86_FLAG_MEMW_64B | X86_FLAG_3OPRND;
					break;
				}
			} else {
				if ((*p.ai8 & MODRM_MOD) != MODRM_MOD_11) {
					adbg_dasm_err(p);
					return;
				}
				switch (p.x86.vex_pp) {
				case X86_VEX_PP_NONE: i = "vmovmskps"; break;
				case X86_VEX_PP_66H:  i = "vmovmskpd"; break;
				default: adbg_dasm_err(p); return;
				}
				f |= X86_FLAG_REGW_32B | X86_FLAG_MEMW_32B;
			}
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, i);
		adbg_dasm_x86_vex_modrm(p, f);
		return;
	case 0x54: // 54H-57H
		const(char) *i = void;
		switch (p.x86.vex_pp) {
		case X86_VEX_PP_NONE:
			if (p.x86.op & X86_FLAG_DIR) {
				i = p.x86.op & X86_FLAG_WIDE ? "vxorps" : "vorps";
			} else {
				i = p.x86.op & X86_FLAG_WIDE ? "vandnps" : "vandps";
			}
			break;
		case X86_VEX_PP_66H:
			if (p.x86.op & X86_FLAG_DIR) {
				i = p.x86.op & X86_FLAG_WIDE ? "vxorpd" : "vorpd";
			} else {
				i = p.x86.op & X86_FLAG_WIDE ? "vandnpd" : "vandpd";
			}
			break;
		default: adbg_dasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, i);
		adbg_dasm_x86_vex_modrm(p, X86_FLAG_3OPRND | X86_FLAG_REGW_128B | X86_FLAG_DIR);
		return;
	case 0x58: // 58H-5BH
		int f = X86_FLAG_REGW_128B | X86_FLAG_DIR;
		const(char) *i = void;
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				switch (p.x86.vex_pp) {
				case X86_VEX_PP_NONE: i = "vaddps"; break;
				case X86_VEX_PP_66H:  i = "vaddpd"; break;
				case X86_VEX_PP_F3H:  i = "vaddss"; break;
				default: adbg_dasm_err(p); return;
				}
			} else {
				switch (p.x86.vex_pp) {
				case X86_VEX_PP_NONE: i = "vcvtps2pd"; break;
				case X86_VEX_PP_66H:
					if ((*p.ai8 & MODRM_MOD) != MODRM_MOD_11) {
						adbg_dasm_err(p);
						return;
					}
					i = "vcvtpd2ps";
					break;
				case X86_VEX_PP_F3H:
					i = "vcvtss2sd";
					f |= X86_FLAG_3OPRND;
					break;
				default:
					i = "vcvtsd2ss";
					f |= X86_FLAG_3OPRND;
					break;
				}
			}
		} else {
			f |= X86_FLAG_3OPRND;
			if (p.x86.op & X86_FLAG_WIDE) {
				switch (p.x86.vex_pp) {
				case X86_VEX_PP_NONE: i = "vmulps"; break;
				case X86_VEX_PP_66H:  i = "vmulpd"; break;
				case X86_VEX_PP_F3H:  i = "vmulss"; break;
				default:              i = "vmulsd"; break;
				}
			} else {
				switch (p.x86.vex_pp) {
				case X86_VEX_PP_NONE: i = "vaddps"; break;
				case X86_VEX_PP_66H:  i = "vaddpd"; break;
				case X86_VEX_PP_F3H:  i = "vaddss"; break;
				default:              i = "vaddsd"; break;
				}
			}
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, i);
		adbg_dasm_x86_vex_modrm(p, f);
		return;
	case 0x5C: // 5CH-5FH
		const(char) *i = void;
		int f = void;
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				switch (p.x86.vex_pp) {
				case X86_VEX_PP_NONE:
					i = "vmaxps";
					f = X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND;
					break;
				case X86_VEX_PP_66H:
					i = "vmaxpd";
					f = X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND;
					break;
				case X86_VEX_PP_F3H:
					i = "vmaxss";
					f = X86_FLAG_DIR | X86_FLAG_REGW_128B | X86_FLAG_3OPRND | X86_FLAG_MEMW_32B;
					break;
				default:
					i = "vmaxsd";
					f = X86_FLAG_DIR | X86_FLAG_REGW_128B | X86_FLAG_3OPRND | X86_FLAG_MEMW_64B;
					break;
				}
			} else {
				switch (p.x86.vex_pp) {
				case X86_VEX_PP_NONE:
					i = "vdivps";
					f = X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND;
					break;
				case X86_VEX_PP_66H:
					i = "vdivpd";
					f = X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND;
					break;
				case X86_VEX_PP_F3H:
					i = "vdivss";
					f = X86_FLAG_DIR | X86_FLAG_REGW_128B | X86_FLAG_3OPRND | X86_FLAG_MEMW_32B;
					break;
				default:
					i = "vdivsd";
					f = X86_FLAG_DIR | X86_FLAG_REGW_128B | X86_FLAG_3OPRND | X86_FLAG_MEMW_64B;
					break;
				}
			}
		} else {
			if (p.x86.op & X86_FLAG_WIDE) {
				switch (p.x86.vex_pp) {
				case X86_VEX_PP_NONE:
					i = "vminps";
					f = X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND;
					break;
				case X86_VEX_PP_66H:
					i = "vminpd";
					f = X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND;
					break;
				case X86_VEX_PP_F3H:
					i = "vminss";
					f = X86_FLAG_DIR | X86_FLAG_REGW_128B | X86_FLAG_3OPRND | X86_FLAG_MEMW_32B;
					break;
				default:
					i = "vminsd";
					f = X86_FLAG_DIR | X86_FLAG_REGW_128B | X86_FLAG_3OPRND | X86_FLAG_MEMW_64B;
					break;
				}
			} else {
				switch (p.x86.vex_pp) {
				case X86_VEX_PP_NONE:
					i = "vsubps";
					f = X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND;
					break;
				case X86_VEX_PP_66H:
					i = "vsubpd";
					f = X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND;
					break;
				case X86_VEX_PP_F3H:
					i = "vsubss";
					f = X86_FLAG_DIR | X86_FLAG_REGW_128B | X86_FLAG_3OPRND | X86_FLAG_MEMW_32B;
					break;
				default:
					i = "vsubsd";
					f = X86_FLAG_DIR | X86_FLAG_REGW_128B | X86_FLAG_3OPRND | X86_FLAG_MEMW_64B;
					break;
				}
			}
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, i);
		adbg_dasm_x86_vex_modrm(p, f);
		return;
	case 0x60: // 60H-63H
		if (p.x86.vex_pp != X86_VEX_PP_66H) {
			adbg_dasm_err(p);
			return;
		}
		const(char) *i = void;
		if (p.x86.op & X86_FLAG_DIR)
			i = p.x86.op & X86_FLAG_WIDE ? "vpacksswb" : "vpunpckldq";
		else
			i = p.x86.op & X86_FLAG_WIDE ? "vpunpcklwd" : "vpunpcklbw";
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, i);
		adbg_dasm_x86_vex_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND);
		return;
	case 0x64: // 64H-67H
		if (p.x86.vex_pp != X86_VEX_PP_66H) {
			adbg_dasm_err(p);
			return;
		}
		const(char) *i = void;
		if (p.x86.op & X86_FLAG_DIR)
			i = p.x86.op & X86_FLAG_WIDE ? "vpackuswb" : "vpcmpgtd";
		else
			i = p.x86.op & X86_FLAG_WIDE ? "vpcmpgtw" : "vpcmpgtb";
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, i);
		adbg_dasm_x86_vex_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND);
		return;
	case 0x68: // 68H-6BH
		if (p.x86.vex_pp != X86_VEX_PP_66H) {
			adbg_dasm_err(p);
			return;
		}
		const(char) *i = void;
		if (p.x86.op & X86_FLAG_DIR)
			i = p.x86.op & X86_FLAG_WIDE ? "vpackssdw" : "vpunpckhdq";
		else
			i = p.x86.op & X86_FLAG_WIDE ? "vpunpckhwd" : "vpunpckhbw";
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, i);
		adbg_dasm_x86_vex_modrm(p,
			X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND);
		return;
	case 0x6C: // 6CH-6FH
		const(char) *i = void;
		int f = void;
		if (p.x86.op & X86_FLAG_DIR) {
			switch (p.x86.vex_pp) {
			case X86_VEX_PP_66H:
				if (p.x86.op & X86_FLAG_WIDE) {
					i = "vmovdqa";
					f = X86_FLAG_DIR | X86_FLAG_MODW_128B;
				} else {
					if ((*p.ai8 & MODRM_MOD) == MODRM_MOD_11) {
						adbg_dasm_err(p);
						return;
					}
					i = "vmovd";
					//TODO: objdump ignores VEX.L completely...
					f = X86_FLAG_DIR | X86_FLAG_REGW_128B | X86_FLAG_MEMW_32B | X86_FLAG_VEX_NO_L;
				}
				break;
			case X86_VEX_PP_F3H:
				if ((p.x86.op & X86_FLAG_WIDE) == 0) {
					adbg_dasm_err(p);
					return;
				}
				i = "vmovdqu";
				f = X86_FLAG_DIR | X86_FLAG_MODW_128B;
				break;
			default:
				adbg_dasm_err(p);
				return;
			}
		} else {
			if (p.x86.vex_pp != X86_VEX_PP_66H) {
				adbg_dasm_err(p);
				return;
			}
			i = p.x86.op & X86_FLAG_WIDE ? "vpunpcklqdq" : "vpunpckhqdq";
			f = X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND;
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, i);
		adbg_dasm_x86_vex_modrm(p, f);
		return;
	case 0x70: // 70H-73H
		const(char) *m = void;
		int f = void;
		ubyte modrm = void;
		if (p.x86.op & X86_FLAG_DIR) {
			modrm = *p.ai8;
			if (p.x86.vex_pp != X86_VEX_PP_66H ||
				(modrm & MODRM_MOD) != MODRM_MOD_11) {
				adbg_dasm_err(p);
				return;
			}
			if (p.x86.op & X86_FLAG_WIDE) {
				switch (modrm & MODRM_REG) {
				case MODRM_REG_010: m = "vpsrlq"; break;
				case MODRM_REG_011: m = "vpsrldq"; break;
				case MODRM_REG_110: m = "vpsllq"; break;
				case MODRM_REG_111: m = "vpslldq"; break;
				default: adbg_dasm_err(p); return;
				}
			} else {
				switch (modrm & MODRM_REG) {
				case MODRM_REG_010: m = "vpsrld"; break;
				case MODRM_REG_100: m = "vpsrad"; break;
				case MODRM_REG_110: m = "vpslld"; break;
				default: adbg_dasm_err(p); return;
				}
			}
			f = X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_VEX_USEvvvv;
		} else {
			if (p.x86.op & X86_FLAG_WIDE) {
				modrm = *p.ai8;
				if (p.x86.vex_pp != X86_VEX_PP_66H ||
					(modrm & MODRM_MOD) != MODRM_MOD_11) {
					adbg_dasm_err(p);
					return;
				}
				switch (modrm & MODRM_REG) {
				case MODRM_REG_010: m = "vpsrlw"; break;
				case MODRM_REG_100: m = "vpsraw"; break;
				case MODRM_REG_110: m = "vpsllw"; break;
				default: adbg_dasm_err(p); return;
				}
				f = X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_VEX_USEvvvv;
			} else {
				switch (p.x86.vex_pp) {
				case X86_VEX_PP_66H: m = "vpshufd"; break;
				case X86_VEX_PP_F3H: m = "vpshufhw"; break;
				case X86_VEX_PP_F2H: m = "vpshuflw"; break;
				default: adbg_dasm_err(p); return;
				}
				f = X86_FLAG_DIR | X86_FLAG_MODW_128B;
			}
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_vex_modrm(p, f);
		adbg_dasm_x86_u8imm(p);
		return;
	case 0x74: // 74H-77H
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				if (p.mode >= DisasmMode.File)
					adbg_dasm_push_str(p, p.x86.vex_L ? "vzeroall" : "vzeroupper");
				return;
			} else {
				if (p.x86.vex_pp != X86_VEX_PP_66H) {
					adbg_dasm_err(p);
					return;
				}
				m = "vpcmpeqd";
			}
		} else {
			if (p.x86.vex_pp != X86_VEX_PP_66H) {
				adbg_dasm_err(p);
				return;
			}
			m = p.x86.op & X86_FLAG_WIDE ? "vpcmpeqw" : "vpcmpeqb";
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_vex_modrm(p, X86_FLAG_DIR | X86_FLAG_3OPRND | X86_FLAG_MODW_128B);
		return;
	case 0x7C: // 7CH-7FH
		const(char) *m = void;
		int f = void;
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				switch (p.x86.vex_pp) {
				case X86_VEX_PP_66H: m = "vmovdqa"; break;
				case X86_VEX_PP_F3H: m = "vmovdqu"; break;
				default: adbg_dasm_err(p); return;
				}
				f = X86_FLAG_MODW_128B;
			} else {
				switch (p.x86.vex_pp) {
				case X86_VEX_PP_66H:
					if ((*p.ai8 & MODRM_MOD) != MODRM_MOD_11) {
						adbg_dasm_err(p);
						return;
					}
					m = "vmovd";
					f = X86_FLAG_REGW_32B | X86_FLAG_MEMW_128B | X86_FLAG_DIR | X86_FLAG_VEX_NO_L;
					break;
				case X86_VEX_PP_F3H:
					m = "vmovq";
					f = X86_FLAG_MODW_128B | X86_FLAG_DIR | X86_FLAG_VEX_NO_L;
					break;
				default: adbg_dasm_err(p); return;
				}
			}
		} else {
			switch (p.x86.vex_pp) {
			case X86_VEX_PP_66H:
				m = p.x86.op & X86_FLAG_WIDE ? "vhaddpd" : "vhsubpd";
				break;
			case X86_VEX_PP_F2H:
				m = p.x86.op & X86_FLAG_WIDE ? "vhsubps" : "vhaddps";
				break;
			default: adbg_dasm_err(p); return;
			}
			f = X86_FLAG_DIR | X86_FLAG_3OPRND | X86_FLAG_MODW_128B;
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_vex_modrm(p, f);
		return;
	case 0xC0: // C0H-C3H
		if ((p.x86.op & 0b11) != 0b10) {
			adbg_dasm_err(p);
			return;
		}
		const(char) *m = void;
		int f = void;
		switch (p.x86.vex_pp) {
		case X86_VEX_PP_NONE:
			m = "vcmpps";
			f = X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND;
			break;
		case X86_VEX_PP_66H:
			m = "vcmppd";
			f = X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND;
			break;
		case X86_VEX_PP_F3H:
			m = "vcmpss";
			f = X86_FLAG_DIR | X86_FLAG_REGW_128B | X86_FLAG_3OPRND | X86_FLAG_MEMW_32B;
			break;
		default:
			m = "vcmpsd";
			f = X86_FLAG_DIR | X86_FLAG_REGW_128B | X86_FLAG_3OPRND | X86_FLAG_MEMW_64B;
			break;
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_vex_modrm(p, f);
		adbg_dasm_x86_u8imm(p);
		return;
	case 0xC4: // C4H-C7H
		const(char) *m = void;
		int f = void;
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				adbg_dasm_err(p);
				return;
			} else {
				switch (p.x86.vex_pp) {
				case X86_VEX_PP_NONE: m = "vshufps"; break;
				case X86_VEX_PP_66H:  m = "vshufpd"; break;
				default: adbg_dasm_err(p); return;
				}
			}
			f = X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND;
		} else {
			if (p.x86.vex_pp != X86_VEX_PP_66H) {
				adbg_dasm_err(p);
				return;
			}
			ubyte modrm = *p.ai8 & MODRM_MOD;
			if (p.x86.op & X86_FLAG_WIDE) {
				if (modrm != MODRM_MOD_11) {
					adbg_dasm_err(p);
					return;
				}
				m = "vpextrw";
				f = X86_FLAG_DIR | X86_FLAG_REGW_32B | X86_FLAG_MEMW_128B |
					X86_FLAG_VEX_NO_L;
			} else {
				m = "vpinsrw";
				if (modrm == MODRM_MOD_11)
					f = X86_FLAG_MEMW_32B | X86_FLAG_REGW_32B
						| X86_FLAG_VEX_NO_L | X86_FLAG_3OPRND;
				else
					f = X86_FLAG_MEMW_16B | X86_FLAG_REGW_128B
						| X86_FLAG_DIR | X86_FLAG_VEX_NO_L | X86_FLAG_3OPRND;
			}
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_vex_modrm(p, f);
		adbg_dasm_x86_u8imm(p);
		return;
	case 0xD0: // D0H-D3H
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.vex_pp != X86_VEX_PP_66H) {
				adbg_dasm_err(p);
				return;
			}
			m = p.x86.op & X86_FLAG_WIDE ? "vpsrlq" : "vpsrld";
		} else {
			if (p.x86.op & X86_FLAG_WIDE) {
				if (p.x86.vex_pp != X86_VEX_PP_66H) {
					adbg_dasm_err(p);
					return;
				}
				m = "vpsrlw";
			} else {
				switch (p.x86.vex_pp) {
				case X86_VEX_PP_66H: m = "vaddsubpd"; break;
				case X86_VEX_PP_F2H: m = "vaddsubps"; break;
				default: adbg_dasm_err(p); return;
				}
			}
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_vex_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND);
		return;
	case 0xD4: // D4H-D7H
		if (p.x86.vex_pp != X86_VEX_PP_66H) {
			adbg_dasm_err(p);
			return;
		}
		const(char) *m = void;
		int f = void;
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.op & X86_FLAG_WIDE) {
				if ((*p.ai8 & MODRM_MOD) != MODRM_MOD_11) {
					adbg_dasm_err(p);
					return;
				}
				f = X86_FLAG_REGW_32B | X86_FLAG_MEMW_128B | X86_FLAG_DIR;
				m = "vpmovmskb";
			} else {
				f = X86_FLAG_MODW_128B;
				m = "vmovq";
			}
		} else {
			f = X86_FLAG_3OPRND | X86_FLAG_MODW_128B | X86_FLAG_DIR;
			m = p.x86.op & X86_FLAG_WIDE ? "vpmullw" : "vpaddq";
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_vex_modrm(p, f);
		return;
	case 0xD8: // D8H-DBH
		if (p.x86.vex_pp != X86_VEX_PP_66H) {
			adbg_dasm_err(p);
			return;
		}
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR) {
			m = p.x86.op & X86_FLAG_WIDE ? "vpand" : "vpminub";
		} else {
			m = p.x86.op & X86_FLAG_WIDE ? "vpsubusw" : "vpsubusb";
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_vex_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND);
		return;
	case 0xDC: // DCH-DFH
		if (p.x86.vex_pp != X86_VEX_PP_66H) {
			adbg_dasm_err(p);
			return;
		}
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR)
			m = p.x86.op & X86_FLAG_WIDE ? "vpandn" : "vpmaxub";
		else
			m = p.x86.op & X86_FLAG_WIDE ? "vpaddusw" : "vpaddusb";
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_vex_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND);
		return;
	case 0xE0: // E0H-E3H
		if (p.x86.vex_pp != X86_VEX_PP_66H) {
			adbg_dasm_err(p);
			return;
		}
		const(char) *m = void;
		if (p.x86.op & X86_FLAG_DIR)
			m = p.x86.op & X86_FLAG_WIDE ? "vpavgw" : "vpsrad";
		else
			m = p.x86.op & X86_FLAG_WIDE ? "vpsraw" : "vpavgb";
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_vex_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND);
		return;
	case 0xE4: // E4H-E7H
		const(char) *m = void;
		int f = void;
		if (p.x86.op & X86_FLAG_DIR)
			if (p.x86.op & X86_FLAG_WIDE) {
				if (p.x86.vex_pp != X86_VEX_PP_66H) {
					adbg_dasm_err(p);
					return;
				}
				m = "vmovntdq";
				f = X86_FLAG_MODW_128B;
			} else {
				if ((*p.ai8 & MODRM_MOD) != MODRM_MOD_11) {
					adbg_dasm_err(p);
					return;
				}
				switch (p.x86.vex_pp) {
				case X86_VEX_PP_66H: m = "vcvttpd2dq"; break;
				case X86_VEX_PP_F3H: m = "vcvtdq2pd"; break;
				case X86_VEX_PP_F2H: m = "vcvtpd2dq"; break;
				default:
					adbg_dasm_err(p);
					return;
				}
				f = X86_FLAG_DIR | X86_FLAG_MODW_128B;
			}
		else {
			if (p.x86.vex_pp != X86_VEX_PP_66H) {
				adbg_dasm_err(p);
				return;
			}
			m = p.x86.op & X86_FLAG_WIDE ? "vpmulhw" : "vpmulhuw";
			f = X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND;
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_vex_modrm(p, f);
		return;
	case 0xE8, 0xEC: // E8H-EFH
		if (p.x86.vex_pp != X86_VEX_PP_66H) {
			adbg_dasm_err(p);
			return;
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, x86_T_VEX_0F_E8h[p.x86.op & 7]);
		adbg_dasm_x86_vex_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND);
		return;
	case 0xF0:
		const(char) *m = void;
		int f = void;
		if (p.x86.op & X86_FLAG_DIR) {
			if (p.x86.vex_pp != X86_VEX_PP_66H) {
				adbg_dasm_err(p);
				return;
			}
			m = p.x86.op & X86_FLAG_WIDE ? "vpsllq" : "vpslld";
			f = X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND;
		} else {
			if (p.x86.op & X86_FLAG_WIDE) {
				if (p.x86.vex_pp != X86_VEX_PP_66H) {
					adbg_dasm_err(p);
					return;
				}
				m = "vpsllw";
				f = X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND;
			} else {
				if (p.x86.vex_pp != X86_VEX_PP_F2H) {
					adbg_dasm_err(p);
					return;
				}
				m = "vlddqu";
				f = X86_FLAG_DIR | X86_FLAG_MODW_128B;
			}
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, x86_T_VEX_0F_E8h[p.x86.op & 7]);
		adbg_dasm_x86_vex_modrm(p, f);
		return;
	case 0xF4, 0xF8:
		if (p.x86.vex_pp != X86_VEX_PP_66H) {
			adbg_dasm_err(p);
			return;
		}
		int i = p.x86.op & 7;
		int f = void;
		if (i == 0b111) {
			if ((*p.ai8 & MODRM_MOD) != MODRM_MOD_11) {
				adbg_dasm_err(p);
				return;
			}
			f = X86_FLAG_DIR | X86_FLAG_MODW_128B;
		} else f = X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND;
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, x86_T_VEX_0F_F4h[i]);
		adbg_dasm_x86_vex_modrm(p, f);
		return;
	case 0xFB:
		int i = p.x86.op & 3;
		const(char) *m = void;
		switch (i) {
		case 0: m = "vpaddb"; break;
		case 1: m = "vpaddw"; break;
		case 2: m = "vpaddd"; break;
		default: adbg_dasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, m);
		adbg_dasm_x86_vex_modrm(p, X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND);
		return;
	default: adbg_dasm_err(p); return;
	}
}

void adbg_dasm_x86_vex_0f38(disasm_params_t *p) {
	p.x86.op = *p.ai8;
	++p.ai8;

	if (p.mode >= DisasmMode.File)
		adbg_dasm_push_x8(p, p.x86.op);

	switch (p.x86.op & 252) {
	case 0, 0x04, 0x08, 0x0C:
		int f = p.x86.op >= 0x0E ?
			X86_FLAG_DIR | X86_FLAG_MODW_128B :
			X86_FLAG_DIR | X86_FLAG_MODW_128B | X86_FLAG_3OPRND;
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, x86_T_VEX_0F38_00h[p.x86.op & 15]);
		adbg_dasm_x86_vex_modrm(p, f);
		return;
	default: adbg_dasm_err(p); return;
	}
}

void adbg_dasm_x86_vex_0f3a(disasm_params_t *p) {
	p.x86.op = *p.ai8;
	++p.ai8;

	if (p.mode >= DisasmMode.File)
		adbg_dasm_push_x8(p, p.x86.op);
	
}

void adbg_dasm_x86_xop_8(disasm_params_t *p) {
	p.x86.op = *p.ai8;
	++p.ai8;

	if (p.mode >= DisasmMode.File)
		adbg_dasm_push_x8(p, p.x86.op);
	
}

void adbg_dasm_x86_xop_9(disasm_params_t *p) {
	p.x86.op = *p.ai8;
	++p.ai8;

	if (p.mode >= DisasmMode.File)
		adbg_dasm_push_x8(p, p.x86.op);
	
}

void adbg_dasm_x86_xop_10(disasm_params_t *p) {
	p.x86.op = *p.ai8;
	++p.ai8;

	if (p.mode >= DisasmMode.File)
		adbg_dasm_push_x8(p, p.x86.op);
	
}

//
// ANCHOR: Shared instruction tables
//

__gshared const(char) *[]x86_T_segs = [
	"es:", "cs:", "ss:", "ds:", "fs:", "gs:"
];
__gshared const(char) *[]x86_T_grp1 = [
	"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"
];
__gshared const(char) *[]x86_T_grp2 = [
	"ror", "rcl", "rcr", "shl", "shr", "ror", null, "sar"
];
__gshared const(char) *[]x86_T_bcd = [
	"daa", "das", "aaa", "aas"
];
__gshared const(char) *[]x86_T_6Ch = [
	"insb", "insd", "outsb", "outsd"
];
__gshared const(char) *[]x86_T_40h = [
	"inc", "dec", "push", "pop"
];
__gshared const(char) *[]x86_T_9Ch = [
	"pushf", "popf", "sahf", "lahf"
];
__gshared const(char) *[]x86_T_E0h = [
	"loopne", "loope", "loop", "jecxz"
];
__gshared const(char) *[]x86_T_F4h = [
	"test", null, "not", "neg", "mul", "imul", "div", "idiv"
];
__gshared const(char) *[]x86_T_F8h = [
	"clc", "stc", "cli", "sti"
];
__gshared const(char) *[][]x86_T_0F_18h = [
	[ "bndldx", "bndmov", "bndcu", "bndcl" ],
	[ "bndstx", "bndmov", "bndcn", "bndmk" ]
];
__gshared const(char) *[]x86_T_0F_5Ch = [
	"subps", "subpd", "subsd", "subss", // D=0 W=0
	"minps", "minpd", "minsd", "minss", // D=0 W=1
	"divps", "divpd", "divsd", "divss", // D=1 W=0
	"maxps", "maxpd", "maxsd", "maxss"  // D=1 W=1
];
__gshared const(char) *[]x86_T_VEX_0F_E8h = [
	"vpsubsb", "vpsubsw", "vpminsw", "vpor",
	"vpaddsb", "vpaddsw", "vpmaxsw", "vpxor"
];
__gshared const(char) *[]x86_T_VEX_0F_F4h = [
	"vpsubb", "vpsubw", "vpsubd", "vpsubq",          // F8H-FBH
	"vpmuludq", "vpmaddwd", "vpsadbw", "vmaskmovdqu" // F4H-F7H
];
__gshared const(char) *[]x86_T_VEX_0F38_00h = [
	"vpshufb", "vphaddw", "vphaddd", "vphaddsw",
	"vpmaddubsw", "vphsubw", "vphsubd", "vphsubsw",
	"vpsignb", "vpsignw", "vpsignd", "vpmulhrsw",
	"vpermilps", "vpermilpd", "vtestps", "vtestpd"
];
__gshared const(char) *[]x86_T_Jcc = [
	"jo", "jno", "jb", "jnb",
	"jz", "jnz", "jbe", "jnbe",
	"js", "jns", "jp", "jnp",
	"jl", "jnl", "jle", "jnle",
];
__gshared const(char) *[]x86_T_CMOVcc = [
	"cmovo", "cmovno", "cmovb", "cmovae",
	"cmove", "cmovne", "cmovbe", "cmova",
	"cmovs", "cmovns", "cmovp", "cmovnp",
	"cmovl", "cmovnl", "cmovle", "cmovnle"
];
__gshared const(char) *[]x86_T_SETcc = [
	"seto", "setno", "setb", "setae",
	"sete", "setne", "setbe", "seta",
	"sets", "setns", "setp", "setnp",
	"setl", "setnl", "setle", "setnle"
];
__gshared const(char) *[]x86_T_FLT1 = [
	"fadd", "fmul", "fcom", "fcomp", "fsub", "fsubr", "fdiv", "fdivr"
];
__gshared const(char) *[]x86_T_FLT2 = [
	"fiadd", "fimul", "ficom", "ficomp", "fisub", "fisubr", "fidiv", "fidivr"
];
__gshared const(char) *[]x86_T_FLT3 = [
	"fild", "fisttp", "fist", "fistp", "fbld", "fild", "fbstp", "fistp"
];
__gshared const(char) *[]x86_T_FLT4 = [
	"f2xm1", "fyl2x", "fptan", "fpatan", "fxtract", "fprem1", "fdecstp", "fincstp",
	"fprem", "fyl2xp1", "fsqrt", "fsincos", "frndint", "fscale", "fsin", "fcos"
];
__gshared const(char) *[]x86_T_FLT5 = [
	"fchs", "fabs", null, null, "ftst", "fxam", null, null,
	"fld1", "fldl2t", "fldl2e", "fldpi", "fldlg2", "fldln2", "fldz", null
];
__gshared const(char) *[]x86_T_FLT6 = [
	"fld", null, "fst", "fstp", "fldenv", "fldcw", "fstenv", "fstcw"
];
__gshared const(char) *[]x86_T_FLT7 = [
	"fild", "fisttp", "fist", "fistp", null, "fld", null, "fstp"
];
__gshared const(char) *[]x86_T_FLT8 = [
	"fild", "fisttp", "fst", "fstp", "frstor", null, "fsave", "fstsw"
];
__gshared const(char) *[]x86_T_DR = [
	"dr0", "dr1", "dr2", "dr3", "dr4", "dr5", "dr6", "dr7"
];
__gshared const(char) *[]x86_T_CR = [
	"cr0", "cr1", "cr2", "cr3", "cr4", "cr5", "cr6", "cr7",
	"cr8", "cr9", "cr10", "cr11", "cr12", "cr13", "cr14", "cr15"
];

//
// ANCHOR: Internal functions
//

enum : ubyte {
	MODRM_MOD_00 =   0,	/// MOD 00, Memory Mode, no displacement
	MODRM_MOD_01 =  64,	/// MOD 01, Memory Mode, 8-bit displacement
	MODRM_MOD_10 = 128,	/// MOD 10, Memory Mode, 16-bit displacement
	MODRM_MOD_11 = 192,	/// MOD 11, Register Mode
	MODRM_MOD    = MODRM_MOD_11,	/// Used for masking the MOD bits (11 000 000)

	MODRM_REG_000 =  0,	/// AL/AX
	MODRM_REG_001 =  8,	/// CL/CX
	MODRM_REG_010 = 16,	/// DL/DX
	MODRM_REG_011 = 24,	/// BL/BX
	MODRM_REG_100 = 32,	/// AH/SP
	MODRM_REG_101 = 40,	/// CH/BP
	MODRM_REG_110 = 48,	/// DH/SI
	MODRM_REG_111 = 56,	/// BH/DI
	MODRM_REG     = MODRM_REG_111,	/// Used for masking the REG bits (00 111 000)

	MODRM_RM_000 = 0,	/// R/M 000 bits
	MODRM_RM_001 = 1,	/// R/M 001 bits
	MODRM_RM_010 = 2,	/// R/M 010 bits
	MODRM_RM_011 = 3,	/// R/M 011 bits
	MODRM_RM_100 = 4,	/// R/M 100 bits
	MODRM_RM_101 = 5,	/// R/M 101 bits
	MODRM_RM_110 = 6,	/// R/M 110 bits
	MODRM_RM_111 = 7,	/// R/M 111 bits
	MODRM_RM     = MODRM_RM_111,	/// Used for masking the R/M bits (00 000 111)

	SIB_SCALE_00 = MODRM_MOD_00,	/// SCALE 00, *1
	SIB_SCALE_01 = MODRM_MOD_01,	/// SCALE 01, *2
	SIB_SCALE_10 = MODRM_MOD_10,	/// SCALE 10, *4
	SIB_SCALE_11 = MODRM_MOD_11,	/// SCALE 11, *8
	SIB_SCALE    = SIB_SCALE_11,	/// Scale filter

	SIB_INDEX_000 = MODRM_REG_000 >> 3,	/// INDEX 000, EAX
	SIB_INDEX_001 = MODRM_REG_001 >> 3,	/// INDEX 001, ECX
	SIB_INDEX_010 = MODRM_REG_010 >> 3,	/// INDEX 010, EDX
	SIB_INDEX_011 = MODRM_REG_011 >> 3,	/// INDEX 011, EBX
	SIB_INDEX_100 = MODRM_REG_100 >> 3,	/// INDEX 100, (special override)
	SIB_INDEX_101 = MODRM_REG_101 >> 3,	/// INDEX 101, EBP
	SIB_INDEX_110 = MODRM_REG_110 >> 3,	/// INDEX 110, ESI
	SIB_INDEX_111 = MODRM_REG_111 >> 3,	/// INDEX 111, EDI
	SIB_INDEX     = MODRM_REG >> 3,	/// Index filter

	SIB_BASE_000 = MODRM_RM_000,	/// BASE 000, EAX
	SIB_BASE_001 = MODRM_RM_001,	/// BASE 001, ECX
	SIB_BASE_010 = MODRM_RM_010,	/// BASE 010, EDX
	SIB_BASE_011 = MODRM_RM_011,	/// BASE 011, EBX
	SIB_BASE_100 = MODRM_RM_100,	/// BASE 100, ESP
	SIB_BASE_101 = MODRM_RM_101,	/// BASE 101, (special override)
	SIB_BASE_110 = MODRM_RM_110,	/// BASE 110, ESI
	SIB_BASE_111 = MODRM_RM_111,	/// BASE 111, EDI
	SIB_BASE     = MODRM_RM,	/// Base filter
}

// ANCHOR modrm function flags
// 00 00 00 00
// || |  || ++- 0000 0000  (bits)
// || |  ||            |+- WIDE bit, instruction is wider (8b/32b)
// || |  ||            +-- DIR bit, ModRM.REG is destination
// || |  |+--------------- Register width
// || |  +---------------- Memory pointer width
// || +------------------- (VEX) Number of operands
// ++---------- 0000 0000  (bits)
//               |||    +- Use WIDE flag for width
//               ||+------ (VEX) If VEX.L is set, trip
//               |+------- (VEX) Ignore VEX.L, proceed as unset
//               +-------- (VEX) Use VEX.vvvv as ModRM.REG (2OPRND only)
enum {	// Flags for ModRM functions
	// Bit that maps to the opcode if X86_FLAG_USE_OP is set
	X86_FLAG_WIDE	= 1,	/// Set: Instruction is wide (32b instead of 8b)
	X86_FLAG_DIR	= 2,	/// Set: ModRM.REG is destination
	// Register width
	X86_FLAG_REGW_8B	= MemWidth.i8	<< 8,
	X86_FLAG_REGW_16B	= MemWidth.i16	<< 8,
	X86_FLAG_REGW_32B	= MemWidth.i32	<< 8,
	X86_FLAG_REGW_64B	= MemWidth.i64	<< 8,
	X86_FLAG_REGW_128B	= MemWidth.i128	<< 8,
	X86_FLAG_REGW_256B	= MemWidth.i256	<< 8,
	X86_FLAG_REGW_512B	= MemWidth.i512	<< 8,
	X86_FLAG_REGW	= 0x0F00,
	// Memory pointer width
	X86_FLAG_MEMW_8B	= MemWidth.i8	<< 12,
	X86_FLAG_MEMW_16B	= MemWidth.i16	<< 12,
	X86_FLAG_MEMW_32B	= MemWidth.i32	<< 12,
	X86_FLAG_MEMW_64B	= MemWidth.i64	<< 12,
	X86_FLAG_MEMW_128B	= MemWidth.i128	<< 12,
	X86_FLAG_MEMW_256B	= MemWidth.i256	<< 12,
	X86_FLAG_MEMW_512B	= MemWidth.i512	<< 12,
	X86_FLAG_MEMW_1024B	= MemWidth.i1024	<< 12,
	X86_FLAG_MEMW_MEM	= MemWidth.far	<< 12,
	X86_FLAG_MEMW_FLOAT	= MemWidth.f80	<< 12,
	X86_FLAG_MEMW	= 0xF000,
	// Combined widths for easier writing
	X86_FLAG_MODW_8B	= X86_FLAG_REGW_8B   | X86_FLAG_MEMW_8B,
	X86_FLAG_MODW_16B	= X86_FLAG_REGW_16B  | X86_FLAG_MEMW_16B,
	X86_FLAG_MODW_32B	= X86_FLAG_REGW_32B  | X86_FLAG_MEMW_32B,
	X86_FLAG_MODW_64B	= X86_FLAG_REGW_64B  | X86_FLAG_MEMW_64B,
	X86_FLAG_MODW_128B	= X86_FLAG_REGW_128B | X86_FLAG_MEMW_128B,
	X86_FLAG_MODW_256B	= X86_FLAG_REGW_256B | X86_FLAG_MEMW_256B,
	X86_FLAG_MODW_512B	= X86_FLAG_REGW_512B | X86_FLAG_MEMW_512B,
	// (VEX) n operands
	// NOTE: Currently excludes 8-bit immediate
	X86_FLAG_2OPRND	= 0,
	X86_FLAG_3OPRND	= 0x10_0000,
	X86_FLAG_4OPRND	= 0x20_0000,
	X86_FLAG_OPRNDM	= 0xF0_0000, /// n operand mask
	// MODRM flags
	X86_FLAG_USE_OP	= 0x0100_0000,	/// Use the opcode for width (8/32), ignores direction bit
	//TODO: Flag to disallow MOD=00|01|10
	//      Will be useful to remove some reduntant code.
//	X86_FLAG_REGONLY	= 0x0200_0000,
//	X86_FLAG_	= 0x0400_0000,
//	X86_FLAG_	= 0x0800_0000,
	// (VEX) VEX flags
	X86_FLAG_VEX_NO_L	= 0x1000_0000,	/// Trip on VEX.L if set
	X86_FLAG_VEX_IGNORE_L	= 0x2000_0000,	/// Force VEX.L as unset
	X86_FLAG_VEX_USEvvvv	= 0x4000_0000,	/// Use VEX.vvvv instead of ModRM.REG
//	X86_FLAG_VEX_	= 0x8000_0000
}

// Prefix combos for 0F
enum {
	X86_0F_NONE,
	X86_0F_66H,
	X86_0F_F2H,
	X86_0F_F3H,
	X86_0F_F266H,
}

/// Quick register A 
/// Params:
/// 	p = disasm_params_t 
/// 	w = If non-zero, imitate W bit
/// Returns: Register A
const(char) *adbg_dasm_x86_eax(disasm_params_t *p, int w) {
	const(char) *a = void;
	if (w & 1)
		a = p.x86.pf_operand ? "ax" : "eax";
	else
		a = "al";
	return a;
}

// Also serves as "default widths"
MemWidth adbg_dasm_x86_modrm_width(disasm_params_t *p, int op) {
	if (op & 1)
		return p.x86.pf_operand ? MemWidth.i16 : MemWidth.i32;
	else
		return MemWidth.i8;
}

void adbg_dasm_x86_u8imm(disasm_params_t *p) {
	if (p.mode >= DisasmMode.File) {
		adbg_dasm_push_x8(p, *p.ai8);
		adbg_dasm_push_imm(p, *p.ai8);
	}
	++p.ai8;
}

/// (Internal) Fetch variable 32-bit immediate, affected by operand prefix.
/// Then if it's the case, fetch and push a 16-bit immediate instead.
/// Modifies memory pointer.
/// Params: p = disassembler structure
void adbg_dasm_x86_u32imm(disasm_params_t *p) {
	if (p.x86.pf_operand) { // 16-bit
		if (p.mode >= DisasmMode.File) {
			adbg_dasm_push_x16(p, *p.ai16);
			adbg_dasm_push_imm(p, *p.ai16);
		}
		++p.ai16;
	} else { // Normal mode 32-bit
		if (p.mode >= DisasmMode.File) {
			adbg_dasm_push_x32(p, *p.ai32);
			adbg_dasm_push_imm(p, *p.ai32);
		}
		++p.ai32;
	}
}

/// (Internal) Fetch variable 16+16/32-bit as immediate, affected by address
/// prefix. Handles machine code and mnemonics, including the segment register.
/// Modifies memory pointer.
/// Params:
/// 	p = disassembler structure
/// 	seg = Segment register string
void adbg_dasm_x86_segimm(disasm_params_t *p, const(char) *seg) {
	if (p.x86.pf_address) { // 16-bit
		if (p.mode >= DisasmMode.File) {
			adbg_dasm_push_x16(p, *p.ai16);
			adbg_dasm_push_immseg(p, *p.ai16, seg);
		}
		++p.ai16;
	} else { // Normal mode 32-bit
		if (p.mode >= DisasmMode.File) {
			adbg_dasm_push_x32(p, *p.ai32);
			adbg_dasm_push_immseg(p, *p.ai32, seg);
		}
		++p.ai32;
	}
}

/// (Internal) Fetch variable 16+16/32-bit as immediate far, affected by address
/// prefix. Handles machine code and mnemonics, including the segment register.
/// Modifies memory pointer.
/// Params: p = disassembler structure
void adbg_dasm_x86_immfar(disasm_params_t *p) {
	ushort sv = *p.ai16;
	++p.ai16;
	uint v = void;
	if (p.x86.pf_address) {
		v = *p.ai16;
		++p.ai16;
	} else {
		v = *p.ai32;
		++p.ai32;
	}
	if (p.mode >= DisasmMode.File) {
		adbg_dasm_push_x16(p, sv);
		if (p.x86.pf_address)
			adbg_dasm_push_x16(p, cast(ushort)v);
		else
			adbg_dasm_push_x32(p, v);
		adbg_dasm_push_immfar(p, v, sv);
	}
}

/// (Internal) Returns a number depending on the set prefixes for the 2-byte
/// instructions (0FH). Useful for a switch per-instruction. Does not check
/// for errors. Unconfirmed with the official order it's supposed to have.
///
/// Enumeration mapping:
/// - X86_0F_NONE  (0): No prefixes
/// - X86_0F_66H   (1): 66H
/// - X86_0F_F2H   (2): F2H
/// - X86_0F_F3H   (3): F3H
/// - X86_0F_F266H (4): 66H+F2H
///
/// Params: p = Disassembler parameters
///
/// Returns: Selection number (see Enumeration mapping)
int adbg_dasm_x86_0f_select(disasm_params_t *p) {
	switch (p.x86.last_prefix) {
	case 0xF2: return p.x86.pf_operand ? X86_0F_F266H : X86_0F_F2H;
	case 0xF3: return X86_0F_F3H;
	default:   return p.x86.pf_operand ? X86_0F_66H : X86_0F_NONE;
	}
}

enum x86SegReg { // By official arrangement
	None, ES, CS, SS, DS, FS, GS
}

/// (Internal) Return a segment register depending on its opcode.
/// Returns an empty string if unset.
/// Params: segreg = Byte opcode
/// Returns: Segment register string
const(char) *adbg_dasm_x86_T_segstr(int segreg) {
	return segreg ? x86_T_segs[segreg] : "";
}

/// While it is the formatter's job to format registers, the long legacy of
/// the syntax wars lead to this
const(char) *adbg_dasm_x87_ststr(disasm_params_t *p, int index) {
	__gshared const(char) *[]att = [
		"%st", "%st(1)", "%st(2)", "%st(3)", "%st(4)", "%st(5)", "%st(6)", "%st(7)"
	];
	__gshared const(char) *[]intel = [
		"st", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)"
	];
	__gshared const(char) *[]nasm = [
		"st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7"
	];
	with (DisasmSyntax)
	switch (p.syntax) {
	case Att:	return att[index];
	case Nasm:	return nasm[index];
	default:	return intel[index];
	}
}

/// (Internal) Process a ModR/M byte automatically.
///
/// This function calls adbg_dasm_x86_modrm_rm and adbg_dasm_push_reg depending on the
/// direction flag. If non-zero (X86_FLAG_DIR), the reg field is processed
/// first; Otherwise vice versa (0).
///
/// Params:
/// 	p = Disassembler parameters
/// 	f = Flags
void adbg_dasm_x86_modrm(disasm_params_t *p, int f) {
	ubyte modrm = *p.ai8;
	++p.ai8;

	int dir = void;
	int wreg = void;
	int wmem = void;
	if (f & X86_FLAG_USE_OP) {
		wreg = wmem = p.x86.op & X86_FLAG_WIDE ? MemWidth.i32 : MemWidth.i8;
		dir = p.x86_64.op & X86_FLAG_DIR;
	} else {
		wreg = (f & X86_FLAG_REGW) >> 8;
		wmem = (f & X86_FLAG_MEMW) >> 12;
		dir = f & X86_FLAG_DIR;
	}
	if (dir) goto L_REG;
L_RM:
	adbg_dasm_x86_modrm_rm(p, modrm, wmem, wreg);
	if (dir) return;

L_REG:
	if (p.mode >= DisasmMode.File) {
		adbg_dasm_push_reg(p, adbg_dasm_x86_modrm_reg(p, modrm >> 3, wreg));
	}
	if (dir) goto L_RM;
}

/// (Internal) Retrieve a register name from a ModR/M byte (REG field) and a
/// specified width. This function conditionally honors the operand prefix
/// (66H) when the width is X86_FLAG_MODW_32B.
/// Params:
/// 	p = Disassembler parameters
/// 	reg = Register selector
/// 	width = Register width (byte, wide, mm, xmm, etc.)
/// Returns: Register string or null if out of bound
const(char) *adbg_dasm_x86_modrm_reg(disasm_params_t *p, int reg, int width) {
	// This is asking for trouble, hopefully more checks will be added later
	// The array has this order for X86_OP_WIDE, non-vex register
	// NOTE: ModRM/VEX extension is x86-64 only!
	__gshared const(char) *[][]x86_regs = [
		[ "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh" ],	// BYTE
		[ "ax", "cx", "dx", "cx", "sp", "bp", "si", "di" ],	// WIDE
		[ "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" ],	// EXT
		[ "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7" ],	// MM
		[ "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7" ],	// XMM
		[ "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7" ],	// YMM
		[ "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7" ],	// ZMM
	];

	if (p.x86.pf_operand) {
		switch (width) {
		case MemWidth.i16: width = MemWidth.i32; break;
		case MemWidth.i32: width = MemWidth.i16; break;
		default:
		}
	}

	return x86_regs[width][reg & 7];
}

/// (Internal) Retrieve a register name from a ModR/M byte (RM field) and
/// conditionally returns the 16-bit addressing 
/// Params:
/// 	rm = Disassembler parameters
/// 	addrpf = If the address prefix is applied
/// Returns: Register string
const(char) *adbg_dasm_x86_modrm_rm_reg(int rm, int addrpf) {
	// This is asking for trouble, hopefully more checks will be added later
	__gshared const(char) *[][]x86_regs = [
		[ "bx+si", "bx+di", "bp+si", "bi+di", "si", "di", "bp", "bx" ],
		[ "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" ],
	];
	return x86_regs[!addrpf][rm & 7];
}

/// (Internal) Process the R/M field automatically
///
/// Params:
/// 	p = Disasm params
/// 	modrm = Modrm byte
/// 	wmem = Memory pointer width
/// 	wreg = Register width
void adbg_dasm_x86_modrm_rm(disasm_params_t *p, ubyte modrm, int wmem, int wreg) {
	bool filemode = p.mode >= DisasmMode.File;

	const(char) *seg = void;
	const(char) *reg = void;

	if (filemode) {
		adbg_dasm_push_x8(p, modrm);
		seg = adbg_dasm_x86_T_segstr(p.x86.segreg);
	}

	int mode = modrm & MODRM_MOD;
	int rm   = modrm & MODRM_RM;

	if (mode != MODRM_MOD_11) {
		if (p.x86.pf_operand) {
			switch (wmem) {
			case MemWidth.i16: wmem = MemWidth.i32; break;
			case MemWidth.i32: wmem = MemWidth.i16; break;
			default:
			}
		}
	}

	switch (mode) {
	case MODRM_MOD_00:	// Memory Mode, no displacement
		if (p.x86.pf_address) {
			if (rm == MODRM_RM_110) {
				ushort m = *p.ai16;
				++p.ai16;
				if (filemode)
					adbg_dasm_push_memregimm(p, seg, m, wmem);
			} else {
				if (filemode) {
					reg = adbg_dasm_x86_modrm_rm_reg(rm, p.x86.pf_address);
					adbg_dasm_push_memsegreg(p, seg, reg, wmem);
				}
			}
		} else {
			if (rm == MODRM_RM_100) {
				adbg_dasm_x86_sib(p, modrm, wmem);
				return;
			}
			reg = adbg_dasm_x86_modrm_rm_reg(rm, p.x86.pf_address);
			if (rm == MODRM_RM_101) {
				uint m = *p.ai32;
				++p.ai32;
				if (filemode) {
					adbg_dasm_push_x32(p, m);
					adbg_dasm_push_memregimm(p, reg, m, wmem);
				}
			} else {
				if (filemode)
					adbg_dasm_push_memsegreg(p, seg, reg, wmem);
			}
		}
		break;
	case MODRM_MOD_01:	// Memory Mode, 8-bit displacement
		if (rm == MODRM_RM_100) {
			adbg_dasm_x86_sib(p, modrm, wmem);
			return;
		}
		if (filemode) {
			adbg_dasm_push_x8(p, *p.ai8);
			reg = adbg_dasm_x86_modrm_rm_reg(rm, p.x86.pf_address);
			adbg_dasm_push_memsegregimm(p, seg, reg, *p.ai8, wmem);
		}
		++p.ai8;
		break;
	case MODRM_MOD_10:	// Memory Mode, 32-bit displacement
		uint m = void;
		if (p.x86.pf_address) {
			m = *p.ai16;
			++p.ai16;
			if (filemode)
				adbg_dasm_push_x16(p, cast(ushort)m);
		} else {
			if (rm == MODRM_RM_100) {
				adbg_dasm_x86_sib(p, modrm, wmem);
				return;
			}
			m = *p.ai32;
			++p.ai32;
			if (filemode)
				adbg_dasm_push_x32(p, m);
		}
		if (filemode) {
			reg = adbg_dasm_x86_modrm_rm_reg(rm, p.x86.pf_address);
			adbg_dasm_push_memsegregimm(p, seg, reg, m, wmem);
		}
		++p.ai32;
		break;
	default:
		if (filemode)
			adbg_dasm_push_reg(p, adbg_dasm_x86_modrm_reg(p, modrm, wreg));
		break;
	}
}

// Process SIB, trips on address prefix
void adbg_dasm_x86_sib(disasm_params_t *p, ubyte modrm, int wmem) {
	if (p.x86.pf_address) {
		adbg_dasm_err(p);
		return;
	}
	// 11 111 111
	// || ||| +++- BASE
	// || +++----- INDEX
	// ++--------- SCALE
	ubyte sib = *p.ai8;
	++p.ai8;
	int scale = 1 << (sib >> 6); // 2 ^ (0b11_000_000 >> 6)
	int index = (sib & SIB_INDEX) >> 3;
	int base  = sib & SIB_BASE;

	const(char)* rbase = void, rindex = void, seg = void;

	if (p.mode >= DisasmMode.File) {
		adbg_dasm_push_x8(p, sib);
		seg = adbg_dasm_x86_T_segstr(p.x86.segreg);
	}

	switch (modrm & MODRM_MOD) { // Mode
	case MODRM_MOD_00:
		if (base == SIB_BASE_101) { // INDEX * SCALE + D32
			if (p.mode >= DisasmMode.File) {
				adbg_dasm_push_x32(p, *p.ai32);
				if (index == SIB_INDEX_100)
					adbg_dasm_push_x86_sib_m00_i100_b101(p,
						seg, *p.ai32, wmem);
				else
					adbg_dasm_push_x86_sib_m00_b101(p, seg,
						adbg_dasm_x86_modrm_rm_reg(base, false),
						scale, *p.ai32, wmem);
			}
			++p.ai32;
		} else { // BASE32 + INDEX * SCALE
			if (p.mode < DisasmMode.File) return;
			rbase = adbg_dasm_x86_modrm_rm_reg(sib, false);
			if (index == SIB_INDEX_100)
				adbg_dasm_push_x86_sib_m00_i100(p, seg, rbase, wmem);
			else
				adbg_dasm_push_x86_sib_mod00(p, seg, rbase,
					adbg_dasm_x86_modrm_rm_reg(base, false),
					scale, wmem);
		}
		return;
	case MODRM_MOD_01:
		if (index == SIB_INDEX_100) { // BASE32 + DISP8
			if (p.mode >= DisasmMode.File) {
				adbg_dasm_push_x8(p, *p.ai8);
				adbg_dasm_push_x86_sib_m01_i100(p,
					seg,
					adbg_dasm_x86_modrm_rm_reg(sib, false),
					*p.ai8, wmem);
			}
		} else { // BASE8 + INDEX * SCALE + DISP8
			if (p.mode >= DisasmMode.File) {
				adbg_dasm_push_x8(p, *p.ai8);
				rbase = adbg_dasm_x86_modrm_rm_reg(base, false);
				rindex = adbg_dasm_x86_modrm_rm_reg(index, false);
				adbg_dasm_push_x86_sib_m01(p,
					seg, rbase, rindex, scale, *p.ai8, wmem);
			}
		}
		++p.ai8;
		break;
	default: // MOD=11, last case
		if (p.mode >= DisasmMode.File) {
			adbg_dasm_push_x32(p, *p.ai32);
			rbase = adbg_dasm_x86_modrm_rm_reg(base, false);
			if (index == SIB_INDEX_100) { // BASE32 + DISP32
				adbg_dasm_push_x86_sib_m01_i100(p,
				seg, rbase, *p.ai32, wmem);
			} else { // BASE32 + INDEX * SCALE + DISP32
				rindex = adbg_dasm_x86_modrm_rm_reg(index, false);
				adbg_dasm_push_x86_sib_m01(p,
					seg, rbase, rindex, scale, *p.ai32, wmem);
			}
		}
		++p.ai32;
		break;
	}
}

//
// ANCHOR: VEX internals
//

// VEX byte "type"
enum : ubyte {
	X86_VEX_TYPE_2BYTE	= 0xC5,
	X86_VEX_TYPE_3BYTE	= 0xC4,
	X86_VEX_TYPE_XOP	= 0x8F,
	X86_VEX_TYPE_EVEX	= 0x62,
	X86_VEX_PP_NONE	= 0,
	X86_VEX_PP_66H	= 1,
	X86_VEX_PP_F3H	= 2,
	X86_VEX_PP_F2H	= 3,
}

// VEX/XOP 3-byte m-mmmm field, 2-byte VEX implies the 0F map (Map 1)
enum X86_VEX_MAP	= 0b1_1111;	/// Map filter
enum X86_VEX_MAP_0F	= 0b0_0001;	/// Map 1
enum X86_VEX_MAP_0F38	= 0b0_0010;	/// Map 2
enum X86_VEX_MAP_0F3A	= 0b0_0011;	/// Map 3
enum X86_XOP_MAP8	= 0b0_1000;	/// Map 8
enum X86_XOP_MAP9	= 0b0_1001;	/// Map 9
enum X86_XOP_MAP10	= 0b0_1010;	/// Map 10

/**
 * (Internal) Automatically process a ModR/M byte under a VEX map.
 * Params:
 * 	p = Disassembler parameters
 * 	flags = Direction, Memory/Register widths, Scalar
 */
void adbg_dasm_x86_vex_modrm(disasm_params_t *p, int flags) {
	// NOTE: VEX ModRM decoding notes
	// vsqrtss xmm0, xmm0, [eax]
	//         ||||  ||||  +++++-- ModRM.RM stays as-is, (MOD=11) forced to VEX.L
	//         ||||  ++++--------- VEX.vvvv (affected by VEX.L), source, by instruction
	//         ++++--------------- ModRM.REG, affected by VEX.L if XMM/YMM
	ubyte modrm = *p.ai8;
	++p.ai8;

	if (flags & X86_FLAG_VEX_NO_L && p.x86.vex_L) {
		adbg_dasm_err(p);
		return;
	}

	int dir = flags & X86_FLAG_DIR;
	int wreg = (flags & X86_FLAG_REGW) >> 8;
	int wmem = (flags & X86_FLAG_MEMW) >> 12;
	int sw = p.x86.vex_L ? MemWidth.i256 : MemWidth.i128; // RM and vvvv

	if (wreg == MemWidth.i128 && p.x86.vex_L)
		wreg = wmem = MemWidth.i256;

	// Barbaric, but works
	final switch (flags & X86_FLAG_OPRNDM) {
	case 0: // 0, most cases
		if (dir) goto L_2REG;
L_2RM:
		adbg_dasm_x86_modrm_rm(p, modrm, wmem, sw);
		if (dir) return;
L_2REG:
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			if (flags & X86_FLAG_VEX_USEvvvv) {
				m = adbg_dasm_x86_modrm_reg(p, p.x86.vex_vvvv, sw);
			} else {
				m = adbg_dasm_x86_modrm_reg(p, modrm >> 3, wreg);
			}
			adbg_dasm_push_reg(p, m);
		}
		if (dir) goto L_2RM;
		return;
	case X86_FLAG_3OPRND:
		if (dir) goto L_3REG;
L_3RM:
		adbg_dasm_x86_modrm_rm(p, modrm, wmem, sw);
		if (dir) return;
L_3REG:
		if (p.mode >= DisasmMode.File) {
			const(char)* r1 = adbg_dasm_x86_modrm_reg(p, modrm, wreg);
			const(char)* r2 = adbg_dasm_x86_modrm_reg(p, p.x86.vex_vvvv, sw);
			if (dir) {
				adbg_dasm_push_reg(p, r1);
				adbg_dasm_push_reg(p, r2);
			} else {
				adbg_dasm_push_reg(p, r2);
				adbg_dasm_push_reg(p, r1);
			}
		}
		if (dir) goto L_3RM;
		return;
	case X86_FLAG_4OPRND:
		if (p.mode >= DisasmMode.File)
			adbg_dasm_push_str(p, "todo");
		return;
	}
}
