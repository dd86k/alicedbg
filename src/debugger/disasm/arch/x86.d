/**
 * x86-32 disassembler.
 *
 * License: BSD 3-Clause
 */
module debugger.disasm.arch.x86;

import debugger.disasm.core;
import debugger.disasm.formatter;
import utils.str;

extern (C):

struct x86_internals_t { align(1):
	int lock;	/// LOCK Prefix
	int repz;	/// (F3H) REP/REPE/REPZ
	int repnz;	/// (F2H) REPNE/REPNZ/BND
	int last_prefix;	/// Last effective prefix for 0f (F2H/F3H)
	int segreg;	/// Last selected segment register
	int pf_operand; /// 66H Operand prefix
	int pf_address; /// 67H Address prefix
	/// VEX prefix
	/// First byte indicates 2-byte VEX (C5H), 3-byte VEX (C4H),
	/// 3-byte XOP (8FH), or 4-byte EVEX (62H)
	union {
		uint vex32;
		ubyte[4] vex;
	}
}

//TODO: Consider group instructions per operand (e.g. all REG8, IMM8)
//      + Possible binary reduction
//      - Possible lookup time increase (e.g. case 4,8: + another switch for string)
//TODO: Repass all instructions to adjust their reg/mem operation width

/**
 * x86 disassembler.
 * Params:
 * 	p = Disassembler parameters
 * 	init = Initiate structure (x86_16 sets this to false)
 */
void disasm_x86(disasm_params_t *p, bool init = true) {
	if (init) {
		x86_internals_t i;
		p.x86 = &i;
	}

L_CONTINUE:
	ubyte b = *p.addru8;
	++p.addrv;

	if (p.mode >= DisasmMode.File)
		disasm_push_x8(p, b);

	int dbit = b & 2; /// Direction bit
	int wbit = b & 1; /// Wide bit
	switch (b & 252) { // 1111_1100
	case 0: // 00H-03H
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "add");
		x86_modrm(p, dbit, wbit, wbit);
		return;
	case 0b0000_0100: // 04H-07H
		if (dbit) {
			if (p.mode >= DisasmMode.File) {
				disasm_push_str(p, wbit ? "pop" : "push");
				disasm_push_reg(p, "es");
			}
		} else {
			if (wbit) {
				if (p.mode >= DisasmMode.File) {
					disasm_push_str(p, "add");
					disasm_push_reg(p, p.x86.pf_operand ? "ax" : "eax");
				}
				x86_u32imm(p);
			} else {
				if (p.mode >= DisasmMode.File) {
					disasm_push_str(p, "add");
					disasm_push_reg(p, "al");
				}
				x86_u8imm(p);
			}
		}
		return;
	case 0b0000_1000: // 08H-0BH
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "or");
		x86_modrm(p, dbit, wbit, wbit);
		return;
	case 0b0000_1100: // 0CH-0FH
		if (dbit) {
			if (wbit) {
				x86_0f(p);
			} else {
				if (p.mode >= DisasmMode.File) {
					disasm_push_str(p, "push");
					disasm_push_reg(p, "cs");
				}
			}
		} else {
			if (wbit) {
				if (p.mode >= DisasmMode.File) {
					disasm_push_str(p, "or");
					disasm_push_reg(p, p.x86.pf_operand ? "ax" : "eax");
				}
				x86_u32imm(p);
			} else {
				if (p.mode >= DisasmMode.File) {
					disasm_push_str(p, "or");
					disasm_push_reg(p, "al");
				}
				x86_u8imm(p);
			}
		}
		return;
	case 0b0001_0000: // 10H-13H
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "adc");
		x86_modrm(p, dbit, wbit, wbit);
		return;
	case 0b0001_0100: // 14H-17H
		if (dbit) {
			if (p.mode >= DisasmMode.File) {
				disasm_push_str(p, wbit ? "pop" : "push");
				disasm_push_reg(p, "ss");
			}
		} else {
			if (wbit) {
				if (p.mode >= DisasmMode.File) {
					disasm_push_str(p, "adc");
					disasm_push_reg(p, p.x86.pf_operand ? "ax" : "eax");
				}
				x86_u32imm(p);
			} else {
				if (p.mode >= DisasmMode.File) {
					disasm_push_str(p, "adc");
					disasm_push_reg(p, "al");
				}
				x86_u8imm(p);
			}
		}
		return;
	case 0b0001_1000: // 18H-1BH
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "sbb");
		x86_modrm(p, dbit, wbit, wbit);
		return;
	case 0b0001_1100: // 1CH-1FH
		if (dbit) {
			if (p.mode >= DisasmMode.File) {
				disasm_push_str(p, wbit ? "pop" : "push");
				disasm_push_reg(p, "ds");
			}
		} else {
			if (wbit) {
				if (p.mode >= DisasmMode.File) {
					disasm_push_str(p, "sbb");
					disasm_push_reg(p, p.x86.pf_operand ? "ax" : "eax");
				}
				x86_u32imm(p);
			} else {
				if (p.mode >= DisasmMode.File) {
					disasm_push_str(p, "sbb");
					disasm_push_reg(p, "al");
				}
				x86_u8imm(p);
			}
		}
		return;
	case 0b0010_0000: // 20H-23H
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "and");
		x86_modrm(p, dbit, wbit, wbit);
		return;
	case 0b0010_0100: // 24H-27H
		if (dbit) {
			if (wbit) {
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "daa");
			} else {
				p.x86.segreg = x86SegReg.ES;
				goto L_CONTINUE;
			}
		} else {
			if (wbit) {
				if (p.mode >= DisasmMode.File) {
					disasm_push_str(p, "and");
					disasm_push_reg(p, p.x86.pf_operand ? "ax" : "eax");
				}
				x86_u32imm(p);
			} else {
				if (p.mode >= DisasmMode.File) {
					disasm_push_str(p, "and");
					disasm_push_reg(p, "al");
				}
				x86_u8imm(p);
			}
		}
		return;
	case 0b0010_1000: // 28H-2BH
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "sub");
		x86_modrm(p, dbit, wbit, wbit);
		return;
	case 0b0010_1100: // 2CH-2FH
		if (dbit) {
			if (wbit) {
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "das");
				
			} else {
				p.x86.segreg = x86SegReg.CS;
				goto L_CONTINUE;
			}
		} else {
			if (wbit) {
				if (p.mode >= DisasmMode.File) {
					disasm_push_str(p, "sub");
					disasm_push_reg(p, p.x86.pf_operand ? "ax" : "eax");
				}
				x86_u32imm(p);
			} else {
				if (p.mode >= DisasmMode.File) {
					disasm_push_str(p, "sub");
					disasm_push_reg(p, "al");
				}
				x86_u8imm(p);
			}
		}
		return;
	case 0b0011_0000: // 30H-33H
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "xor");
		x86_modrm(p, dbit, wbit, wbit);
		return;
	case 0b0011_0100: // 34H-37H
		if (dbit) {
			if (wbit) {
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "aaa");
			} else {
				p.x86.segreg = x86SegReg.SS;
				goto L_CONTINUE;
			}
		} else {
			if (wbit) {
				if (p.mode >= DisasmMode.File) {
					disasm_push_str(p, "xor");
					disasm_push_reg(p, p.x86.pf_operand ? "ax" : "eax");
				}
				x86_u32imm(p);
			} else {
				if (p.mode >= DisasmMode.File) {
					disasm_push_str(p, "xor");
					disasm_push_reg(p, "al");
				}
				x86_u8imm(p);
			}
		}
		return;
	case 0b0011_1000: // 38H-3BH
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "cmp");
		x86_modrm(p, dbit, wbit, wbit);
		return;
	case 0b0011_1100: // 3CH-3FH
		if (dbit) {
			if (wbit) {
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "aas");
			} else {
				p.x86.segreg = x86SegReg.DS;
				goto L_CONTINUE;
			}
		} else {
			if (wbit) {
				if (p.mode >= DisasmMode.File) {
					disasm_push_str(p, "cmp");
					disasm_push_reg(p, p.x86.pf_operand ? "ax" : "eax");
				}
				x86_u32imm(p);
			} else {
				if (p.mode >= DisasmMode.File) {
					disasm_push_str(p, "cmp");
					disasm_push_reg(p, "al");
				}
				x86_u8imm(p);
			}
		}
		return;
	case 0b0100_0000: // 40H-43H
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = p.x86.pf_operand ? "ax" : "eax"; break;
			case 1:  m = p.x86.pf_operand ? "cx" : "ecx"; break;
			case 2:  m = p.x86.pf_operand ? "dx" : "edx"; break;
			default: m = p.x86.pf_operand ? "bx" : "ebx"; break;
			}
			disasm_push_str(p, "inc");
			disasm_push_reg(p, m);
		}
		return;
	case 0b0100_0100: // 44H-47H
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = p.x86.pf_operand ? "sp" : "esp"; break;
			case 1:  m = p.x86.pf_operand ? "bp" : "ebp"; break;
			case 2:  m = p.x86.pf_operand ? "si" : "esi"; break;
			default: m = p.x86.pf_operand ? "di" : "edi"; break;
			}
			disasm_push_str(p, "inc");
			disasm_push_reg(p, m);
		}
		return;
	case 0b0100_1000: // 48H-4BH
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = p.x86.pf_operand ? "ax" : "eax"; break;
			case 1:  m = p.x86.pf_operand ? "cx" : "ecx"; break;
			case 2:  m = p.x86.pf_operand ? "dx" : "edx"; break;
			default: m = p.x86.pf_operand ? "bx" : "ebx"; break;
			}
			disasm_push_str(p, "dec");
			disasm_push_reg(p, m);
		}
		return;
	case 0b0100_1100: // 4CH-4FH
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = p.x86.pf_operand ? "sp" : "esp"; break;
			case 1:  m = p.x86.pf_operand ? "bp" : "ebp"; break;
			case 2:  m = p.x86.pf_operand ? "si" : "esi"; break;
			default: m = p.x86.pf_operand ? "di" : "edi"; break;
			}
			disasm_push_str(p, "dec");
			disasm_push_reg(p, m);
		}
		return;
	case 0b0101_0000: // 50H-53H
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = p.x86.pf_operand ? "ax" : "eax"; break;
			case 1:  m = p.x86.pf_operand ? "cx" : "ecx"; break;
			case 2:  m = p.x86.pf_operand ? "dx" : "edx"; break;
			default: m = p.x86.pf_operand ? "bx" : "ebx"; break;
			}
			disasm_push_str(p, "push");
			disasm_push_reg(p, m);
		}
		return;
	case 0b0101_0100: // 54H-57H
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = p.x86.pf_operand ? "sp" : "esp"; break;
			case 1:  m = p.x86.pf_operand ? "bp" : "ebp"; break;
			case 2:  m = p.x86.pf_operand ? "si" : "esi"; break;
			default: m = p.x86.pf_operand ? "di" : "edi"; break;
			}
			disasm_push_str(p, "push");
			disasm_push_reg(p, m);
		}
		return;
	case 0b0101_1000: // 58H-5BH
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = p.x86.pf_operand ? "ax" : "eax"; break;
			case 1:  m = p.x86.pf_operand ? "cx" : "ecx"; break;
			case 2:  m = p.x86.pf_operand ? "dx" : "edx"; break;
			default: m = p.x86.pf_operand ? "bx" : "ebx"; break;
			}
			disasm_push_str(p, "pop");
			disasm_push_reg(p, m);
		}
		return;
	case 0b0101_1100: // 5CH-5FH
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = p.x86.pf_operand ? "sp" : "esp"; break;
			case 1:  m = p.x86.pf_operand ? "bp" : "ebp"; break;
			case 2:  m = p.x86.pf_operand ? "si" : "esi"; break;
			default: m = p.x86.pf_operand ? "di" : "edi"; break;
			}
			disasm_push_str(p, "pop");
			disasm_push_reg(p, m);
		}
		return;
	case 0b0110_0000: // 60H-63H
		if (dbit) {
			if (wbit) {
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "arpl");
				x86_modrm(p, X86_DIR_REG, X86_WIDTH_BYTE, X86_WIDTH_BYTE);
			} else {
				if ((*p.addru8 & RM_MOD) == RM_MOD_11) {
					disasm_err(p);
					return;
				}
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "bound");
				x86_modrm(p, X86_DIR_REG, X86_WIDTH_EXT, X86_WIDTH_EXT);
			}
		} else {
			if (p.mode >= DisasmMode.File) {
				const(char) *m = void;
				if (wbit)
					m = p.x86.pf_operand ? "popa" : "popad";
				else
					m = p.x86.pf_operand ? "pusha" : "pushad";
				disasm_push_str(p, m);
			}
		}
		return;
	case 0b0110_0100: // 64H-67H
		if (dbit) {
			if (wbit)
				p.x86.pf_address = 0x67;
			else
				p.x86.pf_operand = 0x66;
		} else {
			with (x86SegReg)
			p.x86.segreg = wbit ? GS : FS;
		}
		goto L_CONTINUE;
	case 0b0110_1000: // 68H-6BH
		if (dbit) {
			if (wbit) { // IMUL REG32, R/M32, IMM8
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "imul");
				x86_modrm(p, X86_DIR_REG, X86_WIDTH_EXT, X86_WIDTH_EXT);
			} else { // PUSH IMM8
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "push");
			}
			if (p.mode >= DisasmMode.File) {
				disasm_push_x8(p, *p.addru8);
				disasm_push_imm(p, *p.addru8);
			}
			++p.addrv;
		} else {
			if (wbit) { // IMUL REG32, R/M32, IMM32
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "imul");
				x86_modrm(p, X86_DIR_REG, X86_WIDTH_EXT, X86_WIDTH_EXT);
			} else { // PUSH IMM32
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "push");
			}
			if (p.mode >= DisasmMode.File) {
				disasm_push_x32(p, *p.addru32);
				disasm_push_imm(p, *p.addru32);
			}
			p.addrv += 4;
		}
		return;
	case 0b0110_1100: // 6CH-6FH
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "insb"; break;
			case 1:  m = "insd"; break;
			case 2:  m = "outsb"; break;
			default: m = "outsd"; break;
			}
			disasm_push_str(p, m);
		}
		return;
	case 0b0111_0000: // 70H-73H
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "jo"; break;
			case 1:  m = "jno"; break;
			case 2:  m = "jb"; break;
			default: m = "jnb"; break;
			}
			disasm_push_str(p, m);
		}
		x86_u8imm(p);
		return;
	case 0b0111_0100: // 74H-77H
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "jz"; break;
			case 1:  m = "jnz"; break;
			case 2:  m = "jbe"; break;
			default: m = "jnbe"; break;
			}
			disasm_push_str(p, m);
		}
		x86_u8imm(p);
		return;
	case 0b0111_1000: // 78H-7BH
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "js"; break;
			case 1:  m = "jns"; break;
			case 2:  m = "jp"; break;
			default: m = "jnp"; break;
			}
			disasm_push_str(p, m);
		}
		x86_u8imm(p);
		return;
	case 0b0111_1100: // 7CH-7FH
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "jl"; break;
			case 1:  m = "jnl"; break;
			case 2:  m = "jle"; break;
			default: m = "jnle"; break;
			}
			disasm_push_str(p, m);
		}
		x86_u8imm(p);
		return;
	case 0b1000_0000: // 80H-83H
		ubyte modrm = *p.addru8;
		int modrm_reg = modrm << 3;
		++p.addrv;
		if (p.mode >= DisasmMode.File) {
			const(char) *f = void;
			switch (modrm & RM_REG) {
			case RM_REG_000: f = "add"; break;
			case RM_REG_001: f = "or";  break;
			case RM_REG_010: f = "adc"; break;
			case RM_REG_011: f = "sbb"; break;
			case RM_REG_100: f = "and"; break;
			case RM_REG_101: f = "sub"; break;
			case RM_REG_110: f = "xor"; break;
			case RM_REG_111: f = "cmp"; break;
			default: // impossible
			}
			disasm_push_x8(p, modrm);
			disasm_push_str(p, f);
		}
		if (dbit) { // GRP1 REG8/32, IMM8
			if (p.mode >= DisasmMode.File)
				disasm_push_reg(p,
					x86_modrm_reg(p, modrm_reg, wbit));
			x86_u8imm(p);
		} else {
			if (wbit) { // GRP1 REG32, IMM32
				if (p.mode >= DisasmMode.File)
					disasm_push_reg(p,
						x86_modrm_reg(p, modrm_reg, X86_WIDTH_EXT));
				x86_u32imm(p);
			} else { // GRP1 REG8, IMM8
				if (p.mode >= DisasmMode.File)
					disasm_push_reg(p,
						x86_modrm_reg(p, modrm_reg, X86_WIDTH_BYTE));
				x86_u8imm(p);
			}
		}
		return;
	case 0b1000_0100: // 84H-87H XCHG RM8/32, REG8/32 / TEST RM8/32, REG8/32
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, dbit ? "xchg" : "test");
		x86_modrm(p, X86_DIR_MEM, wbit, wbit);
		return;
	case 0b1000_1000: // 88H-8BH
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "mov");
		x86_modrm(p, dbit, wbit, wbit);
		return;
	case 0b1000_1100: // 8CH-8FH
		if (wbit) {
			if (dbit) { // GRP1A POP REG32
				ubyte modrm = *p.addru8;
				++p.addrv;
				if (modrm & RM_RM) { // Invalid
					disasm_err(p);
					return;
				}
				if (p.mode >= DisasmMode.File) {
					disasm_push_x8(p, modrm);
					disasm_push_str(p, "pop");
					disasm_push_reg(p,
						x86_modrm_reg(p, modrm, X86_WIDTH_EXT));
				}
			} else { // LEA REG32, MEM32
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "lea");
				x86_modrm(p, X86_DIR_REG, X86_WIDTH_EXT, X86_WIDTH_EXT);
			}
		} else {
			ubyte modrm = *p.addru8;
			++p.addrv;
			const(char) *seg = void;
			switch (modrm & RM_REG) {
			case RM_REG_000: seg = "es"; break;
			case RM_REG_001: seg = "cs"; break;
			case RM_REG_010: seg = "ss"; break;
			case RM_REG_011: seg = "ds"; break;
			case RM_REG_100: seg = "fs"; break;
			case RM_REG_101: seg = "gs"; break;
			default: disasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File) {
				p.x86.pf_operand = 1;
				disasm_push_x8(p, modrm);
				disasm_push_str(p, "mov");
				const(char) *reg = x86_modrm_reg(p, modrm, X86_WIDTH_EXT);
				if (dbit) {
					disasm_push_reg(p, seg);
					disasm_push_reg(p, reg);
				} else {
					disasm_push_reg(p, reg);
					disasm_push_reg(p, seg);
				}
			}
		}
		return;
	case 0b1001_0000: // 90H-93H
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  disasm_push_str(p, "nop"); return;
			case 1:  m = p.x86.pf_operand ? "cx" : "ecx"; break;
			case 2:  m = p.x86.pf_operand ? "dx" : "edx"; break;
			default: m = p.x86.pf_operand ? "bx" : "ebx"; break;
			}
			disasm_push_str(p, "xchg");
			disasm_push_reg(p, m);
			disasm_push_reg(p, p.x86.pf_operand ? "ax" : "eax");
		}
		return;
	case 0b1001_0100: // 94H-97H
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = p.x86.pf_operand ? "sp" : "esp"; break;
			case 1:  m = p.x86.pf_operand ? "bp" : "ebp"; break;
			case 2:  m = p.x86.pf_operand ? "si" : "esi"; break;
			default: m = p.x86.pf_operand ? "di" : "edi"; break;
			}
			disasm_push_str(p, "xchg");
			disasm_push_reg(p, m);
			disasm_push_reg(p, p.x86.pf_operand ? "ax" : "eax");
		}
		return;
	case 0b1001_1000: // 98H-9BH
		if (dbit) {
			if (wbit) { // WAIT/FWAIT
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "fwait");
			} else { // CALL (FAR)
				ushort m = *p.addru16;
				p.addrv += 2;
				if (p.mode >= DisasmMode.File) {
					disasm_push_x16(p, m);
					disasm_push_str(p, "call");
					disasm_push_imm(p, m);
				}
				x86_u32imm(p);
			}
		} else {
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, wbit ? "cbd" : "cbw");
		}
		return;
	case 0b1001_1100: // 9CH-9FH
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "pushf"; break;
			case 1:  m = "popf"; break;
			case 2:  m = "sahf"; break;
			default: m = "lahf"; break;
			}
			disasm_push_str(p, m);
		}
		return;
	case 0b1010_0000: // A0H-A3H
		if (p.mode >= DisasmMode.File) {
			if (p.x86.segreg == x86SegReg.None)
				p.x86.segreg = x86SegReg.DS;
			disasm_push_str(p, "mov");
		}
		if (dbit) {
			x86_immmem(p);
			if (p.mode >= DisasmMode.File)
				disasm_push_reg(p, wbit ? "eax" : "al");
		} else {
			if (p.mode >= DisasmMode.File)
				disasm_push_reg(p, wbit ? "eax" : "al");
			x86_immmem(p);
		}
		return;
	case 0b1010_0100: // A4H-A7H
		if (p.mode >= DisasmMode.File) {
			disasm_push_str(p, wbit ? "movsd" : "movsb");
			if (dbit) {
				disasm_push_segreg(p, "ds:", "esi");
				disasm_push_segreg(p, "es:", "edi");
			} else {
				disasm_push_segreg(p, "es:", "edi");
				disasm_push_segreg(p, "ds:", "esi");
			}
		}
		return;
	case 0b1010_1000: // A8H-ABH
		if (dbit) {
			if (p.mode >= DisasmMode.File) {
				disasm_push_str(p, wbit ? "stosd" : "stosb");
				disasm_push_segreg(p, "es:", "edi");
				disasm_push_reg(p, wbit ? "eax" : "al");
			}
		} else {
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, "test");
			if (wbit) {
				if (p.mode >= DisasmMode.File)
					disasm_push_reg(p, "eax");
				x86_u32imm(p);
			} else {
				if (p.mode >= DisasmMode.File)
					disasm_push_reg(p, "al");
				x86_u8imm(p);
			}
		}
		return;
	case 0b1010_1100: // ACH-AFH
		if (dbit) {
			if (p.mode >= DisasmMode.File) {
				disasm_push_str(p, wbit ? "scasd" : "scasb");
				disasm_push_reg(p, wbit ? "eax" : "al");
				disasm_push_segreg(p, "es:", "edi");
			}
		} else {
			if (p.mode >= DisasmMode.File) {
				disasm_push_str(p, wbit ? "lodsd" : "lodsb");
				disasm_push_reg(p, wbit ? "eax" : "al");
				disasm_push_segreg(p, "es:", "esi");
			}
		}
		return;
	case 0b1011_0000: // B0H-B3H
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "al"; break;
			case 1:  m = "cl"; break;
			case 2:  m = "dl"; break;
			default: m = "bl"; break;
			}
			disasm_push_str(p, "mov");
			disasm_push_reg(p, m);
		}
		x86_u8imm(p);
		return;
	case 0b1011_0100: // B4H-B7H
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "ah"; break;
			case 1:  m = "ch"; break;
			case 2:  m = "dh"; break;
			default: m = "bh"; break;
			}
			disasm_push_str(p, "mov");
			disasm_push_reg(p, m);
		}
		x86_u8imm(p);
		return;
	case 0b1011_1000: // B8H-BBH
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = p.x86.pf_operand ? "ax" : "eax"; break;
			case 1:  m = p.x86.pf_operand ? "cx" : "ecx"; break;
			case 2:  m = p.x86.pf_operand ? "dx" : "edx"; break;
			default: m = p.x86.pf_operand ? "bx" : "ebx"; break;
			}
			disasm_push_str(p, "mov");
			disasm_push_reg(p, m);
		}
		x86_u32imm(p);
		return;
	case 0b1011_1100: // BCH-BFH
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = p.x86.pf_operand ? "sp" : "esp"; break;
			case 1:  m = p.x86.pf_operand ? "bp" : "ebp"; break;
			case 2:  m = p.x86.pf_operand ? "si" : "esi"; break;
			default: m = p.x86.pf_operand ? "di" : "edi"; break;
			}
			disasm_push_str(p, "mov");
			disasm_push_reg(p, m);
		}
		x86_u32imm(p);
		return;
	case 0b1100_0000: // C0H-C3H
		if (dbit) {
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, "ret");
			if (wbit) // RET IMM16
				return;
			if (p.mode >= DisasmMode.File) {
				disasm_push_x16(p, *p.addru16);
				disasm_push_imm(p, *p.addri16);
			}
			p.addrv += 2;
		} else { // GRP2
			ubyte modrm = *p.addru8;
			++p.addrv;
			const(char) *r = void;
			switch (modrm & RM_REG) {
			case RM_REG_000: r = "ror"; break;
			case RM_REG_001: r = "rcl"; break;
			case RM_REG_010: r = "rcr"; break;
			case RM_REG_011: r = "shl"; break;
			case RM_REG_100: r = "shr"; break;
			case RM_REG_101: r = "ror"; break;
			case RM_REG_111: r = "sar"; break;
			default: disasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				disasm_push_reg(p, r);
			x86_modrm_rm(p, modrm, wbit);
			x86_u8imm(p);
		}
		return;
	case 0b1100_0100: // C4H-C7H
		if (dbit) { // GRP11
			ubyte modrm = *p.addru8;
			++p.addrv;
			if (modrm & RM_REG) {
				disasm_err(p);
				return;
			}
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, "mov");
			x86_modrm_rm(p, modrm, wbit ? X86_WIDTH_EXT : X86_WIDTH_BYTE);
			if (wbit)
				x86_u32imm(p);
			else
				x86_u8imm(p);
		} else { // MOD=11 checking is only in x86-32
			ubyte modrm = *p.addru8;
			if ((modrm & RM_MOD) == RM_MOD_11) {
				p.x86.vex[0] = b;
				if (wbit) { // C5H, VEX 2-byte prefix
					p.x86.vex[1] = modrm;
					++p.addrv;
				} else { // C4H, VEX 3-byte prefix
					p.x86.vex[1] = modrm;
					p.x86.vex[2] = *(p.addru8 + 1);
					p.addrv += 2;
				}
				return;
			}
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, wbit ? "lds" : "les");
			x86_modrm(p, X86_DIR_REG, X86_WIDTH_EXT, X86_WIDTH_EXT);
		}
		return;
	case 0b1100_1000: // C8H-CBH
		if (dbit) {
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, "ret");
			if (wbit)
				return;
			if (p.mode >= DisasmMode.File) {
				disasm_push_x16(p, *p.addru16);
				disasm_push_imm(p, *p.addri16);
			}
			p.addrv += 2;
		} else {
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, wbit ? "leave" : "enter");
			if (wbit)
				return;
			if (p.mode >= DisasmMode.File) {
				ushort v1 = *p.addru16;
				ubyte v2 = *(p.addru8 + 2);
				disasm_push_x16(p, v1);
				disasm_push_x8(p, v2);
				disasm_push_imm(p, v1);
				disasm_push_imm(p, v2);
			}
			p.addrv += 3;
		}
		return;
	case 0b1100_1100: // CCH-CFH
		if (dbit) {
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, wbit ? "iret" : "into");
		} else {
			if (wbit) { // INT IMM8
				if (p.mode >= DisasmMode.File) {
					disasm_push_x8(p, *p.addru8);
					disasm_push_str(p, "int");
					disasm_push_imm(p, *p.addru8);
				}
				++p.addrv;
			} else { // INT3
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "int3");
			}
		}
		return;
	case 0b1101_0000: // D0H-D3H
		ubyte modrm = *p.addru8;
		++p.addrv;
		const(char) *m = void;
		switch (modrm & RM_REG) {
		case RM_REG_000: m = "rol"; break;
		case RM_REG_001: m = "ror"; break;
		case RM_REG_010: m = "rcl"; break;
		case RM_REG_011: m = "rcr"; break;
		case RM_REG_100: m = "shl"; break;
		case RM_REG_101: m = "shr"; break;
		case RM_REG_111: m = "rol"; break;
		default: disasm_err(p); return;
		}

		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);

		x86_modrm_rm(p, modrm, wbit);

		if (p.mode >= DisasmMode.File) {
			if (dbit)
				disasm_push_reg(p, "cl");
			else
				disasm_push_imm(p, 1);
		}
		return;
	case 0b1101_0100: // D4H-D7H
		if (dbit) {
			if (wbit) {
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "xlat");
			} else disasm_err(p);
		} else {
			if (p.mode >= DisasmMode.File) {
				disasm_push_x8(p, *p.addru8);
				disasm_push_str(p, wbit ? "aad" : "amm");
				disasm_push_imm(p, *p.addru8);
			}
			++p.addrv;
		}
		return;
	case 0b1101_1000: // D8H-DBH ESCAPE
		ubyte modrm = *p.addru8;
		++p.addrv;
		const(char) *m = void;
		switch (b & 3) {
		case 0:
			if (modrm > 0xBF) { // operand is FP
				if (p.mode < DisasmMode.File)
					return;
				ubyte sti = modrm & 0xF; // ST index
				switch (modrm & 0xF0) {
				case 0xC0: // FADD/FMUL
					if (sti < 0x8) { // FADD
						m = "fadd";
					} else { // FMUL
						sti -= 8;
						m = "fmul";
					}
					break;
				case 0xD0: // FCOM/FCOMP
					if (sti < 0x8) { // FCOM
						m = "fcom";
					} else { // FCOMP
						sti -= 8;
						m = "fcomp";
					}
					break;
				case 0xE0: // FSUB/FSUBR
					if (sti < 0x8) { // FSUB
						m = "fsub";
					} else { // FSUBR
						sti -= 8;
						m = "fsubr";
					}
					break;
				case 0xF0: // FDIV/FDIVR
					if (sti < 0x8) { // FDIV
						m = "fdiv";
					} else { // FDIVR
						sti -= 8;
						m = "fdivr";
					}
					break;
				default:
				}
				disasm_push_x8(p, modrm);
				disasm_push_str(p, m);
				disasm_push_str(p, x87_ststr(p, 0));
				disasm_push_str(p, x87_ststr(p, sti));
			} else { // operand is memory pointer
				if (p.mode >= DisasmMode.File) {
					switch (modrm & RM_REG) {
					case RM_REG_000: m = "fadd"; break;
					case RM_REG_001: m = "fmul"; break;
					case RM_REG_010: m = "fcom"; break;
					case RM_REG_011: m = "fcomp"; break;
					case RM_REG_100: m = "fsub"; break;
					case RM_REG_101: m = "fsubr"; break;
					case RM_REG_110: m = "fdiv"; break;
					case RM_REG_111: m = "fdivr"; break;
					default: // never
					}
					disasm_push_str(p, m);
				}
				x86_modrm_rm(p, modrm, X86_WIDTH_EXT);
			}
			return;
		case 1:
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
					disasm_push_x8(p, modrm);
					disasm_push_str(p, m);
					disasm_push_str(p, x87_ststr(p, 0));
					disasm_push_str(p, x87_ststr(p, sti));
					return;
				case 0xD0: // FNOP/Reserved
					if (sti == 0) {
						if (p.mode >= DisasmMode.File) {
							disasm_push_x8(p, modrm);
							disasm_push_str(p, "fnop");
						}
					} else
						disasm_err(p);
					return;
				case 0xE0:
					switch (sti) {
					case 0: m = "fchs"; break;
					case 1: m = "fabs"; break;
					case 4: m = "ftst"; break;
					case 5: m = "fxam"; break;
					case 8: m = "fld1"; break;
					case 9: m = "fldl2t"; break;
					case 0xA: m = "fldl2e"; break;
					case 0xB: m = "fldpi"; break;
					case 0xC: m = "fldlg2"; break;
					case 0xD: m = "fldln2"; break;
					case 0xE: m = "fldz"; break;
					default: disasm_err(p); return;
					}
					if (p.mode >= DisasmMode.File) {
						disasm_push_x8(p, modrm);
						disasm_push_str(p, m);
					}
					return;
				case 0xF0:
					if (p.mode < DisasmMode.File)
						return;
					switch (sti) {
					case 0: m = "f2xm1"; break;
					case 1: m = "fyl2x"; break;
					case 2: m = "fptan"; break;
					case 3: m = "fpatan"; break;
					case 4: m = "fxtract"; break;
					case 5: m = "fprem1"; break;
					case 6: m = "fdecstp"; break;
					case 7: m = "fincstp"; break;
					case 8: m = "fprem"; break;
					case 9: m = "fyl2xp1"; break;
					case 0xA: m = "fsqrt"; break;
					case 0xB: m = "fsincos"; break;
					case 0xC: m = "frndint"; break;
					case 0xD: m = "fscale"; break;
					case 0xE: m = "fsin"; break;
					case 0xF: m = "fcos"; break;
					default: // never
					}
					disasm_push_x8(p, modrm);
					disasm_push_str(p, m);
					return;
				default:
				}
			} else { // operand is memory pointer
				switch (modrm & RM_REG) {
				case RM_REG_000: m = "fld"; break;
				case RM_REG_010: m = "fst"; break;
				case RM_REG_011: m = "fstp"; break;
				case RM_REG_100: m = "fldenv"; break;
				case RM_REG_101: m = "fldcw"; break;
				case RM_REG_110: m = "fstenv"; break;
				case RM_REG_111: m = "fstcw"; break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, m);
				x86_modrm_rm(p, modrm, X86_WIDTH_EXT);
			}
			return;
		case 2:
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
					disasm_push_x8(p, modrm);
					disasm_push_str(p, m);
					disasm_push_str(p, x87_ststr(p, 0));
					disasm_push_str(p, x87_ststr(p, sti));
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
					disasm_push_x8(p, modrm);
					disasm_push_str(p, m);
					disasm_push_str(p, x87_ststr(p, 0));
					disasm_push_str(p, x87_ststr(p, sti));
					return;
				case 0xE0:
					if (sti == 9) {
						if (p.mode >= DisasmMode.File) {
							disasm_push_x8(p, modrm);
							disasm_push_str(p, "fucompp");
						}
						return;
					}
					goto default;
				default: // 0xF0:
					disasm_err(p);
				}
			} else { // operand is memory pointer
				if (p.mode >= DisasmMode.File) {
					switch (modrm & RM_REG) {
					case RM_REG_000: m = "fiadd"; break;
					case RM_REG_001: m = "fimul"; break;
					case RM_REG_010: m = "ficom"; break;
					case RM_REG_011: m = "ficomp"; break;
					case RM_REG_100: m = "fisub"; break;
					case RM_REG_101: m = "fisubr"; break;
					case RM_REG_110: m = "fidiv"; break;
					case RM_REG_111: m = "fidivr"; break;
					default: // never
					}
					disasm_push_str(p, m);
				}
				x86_modrm_rm(p, modrm, X86_WIDTH_EXT);
			}
			return;
		default:
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
					disasm_push_x8(p, modrm);
					disasm_push_str(p, m);
					disasm_push_str(p, x87_ststr(p, 0));
					disasm_push_str(p, x87_ststr(p, sti));
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
					disasm_push_x8(p, modrm);
					disasm_push_str(p, m);
					disasm_push_str(p, x87_ststr(p, 0));
					disasm_push_str(p, x87_ststr(p, sti));
					break;
				case 0xE0: // */FUCOMI
					if (sti < 0x8) { // FCMOVNBE
						switch (sti) {
						case 1: m = "fclex"; break;
						case 2: m = "finit"; break;
						default: disasm_err(p); return;
						}
						if (p.mode >= DisasmMode.File)
							disasm_push_str(p, m);
					} else { // FUCOMI
						if (p.mode >= DisasmMode.File) {
							sti -= 8;
							disasm_push_x8(p, modrm);
							disasm_push_str(p, "fucomi");
							disasm_push_str(p, x87_ststr(p, 0));
							disasm_push_str(p, x87_ststr(p, sti));
						}
					}
					return;
				case 0xF0: // FCOMI/Reserved
					if (sti < 0x8) { // FCOMI
						disasm_push_x8(p, modrm);
						disasm_push_str(p, "fcomi");
						disasm_push_str(p, x87_ststr(p, 0));
						disasm_push_str(p, x87_ststr(p, sti));
					} else { // Reserved
						disasm_err(p);
					}
					return;
				default: // Never
				}
			} else { // operand is memory pointer
				switch (modrm & RM_REG) {
				case RM_REG_000: m = "fild"; break;
				case RM_REG_001: m = "fisttp"; break;
				case RM_REG_010: m = "fist"; break;
				case RM_REG_011: m = "fistp"; break;
				case RM_REG_101: m = "fld"; break;
				case RM_REG_111: m = "fstp"; break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, m);
				x86_modrm_rm(p, modrm, X86_WIDTH_EXT);
			}
			return;
		}
	case 0b1101_1100: // DCH-DFH ESCAPE
		ubyte modrm = *p.addru8;
		++p.addrv;
		const(char) *m = void;
		switch (b & 3) {
		case 0:
			if (modrm > 0xBF) { // operand is FP
				ubyte sti = modrm & 0xF;
				switch (modrm & 0xF0) {
				case 0xC0: // FADD/FMUL
					if (sti < 0x8) { // FADD
						m = "fadd";
					} else { // FMUL
						sti -= 8;
						m = "fmul";
					}
					break;
				case 0xE0: // FSUBR/FSUB
					if (sti < 0x8) { // FSUBR
						m = "fsubr";
					} else { // FSUB
						sti -= 8;
						m = "fsub";
					}
					break;
				case 0xF0: // FDIVR/FDIV
					if (sti < 0x8) { // FDIVR
						m = "fdivr";
					} else { // FDIV
						sti -= 8;
						m = "fdiv";
					}
					break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File) {
					disasm_push_x8(p, modrm);
					disasm_push_str(p, m);
					disasm_push_str(p, x87_ststr(p, sti));
					disasm_push_str(p, x87_ststr(p, 0));
				}
			} else { // operand is memory pointer
				if (p.mode >= DisasmMode.File) {
					switch (modrm & RM_REG) {
					case RM_REG_000: m = "fadd"; break;
					case RM_REG_001: m = "fmul"; break;
					case RM_REG_010: m = "fcom"; break;
					case RM_REG_011: m = "fcomp"; break;
					case RM_REG_100: m = "fsub"; break;
					case RM_REG_101: m = "fsubr"; break;
					case RM_REG_110: m = "fdiv"; break;
					case RM_REG_111: m = "fdivr"; break;
					default: // never
					}
					disasm_push_str(p, m);
				}
				x86_modrm_rm(p, modrm, X86_WIDTH_MM);
			}
			return;
		case 1:
			if (modrm > 0xBF) { // operand is FP
				ubyte sti = modrm & 0xF;
				switch (modrm & 0xF0) {
				case 0xC0: // FFREE/Reserved
					if (sti < 0x8) { // FFREE
						if (p.mode >= DisasmMode.File) {
							disasm_push_x8(p, modrm);
							disasm_push_str(p, "ffree");
							disasm_push_str(p, x87_ststr(p, sti));
						}
					} else { // Reserved
						disasm_err(p);
					}
					break;
				case 0xD0: // FST/FSTP
					if (p.mode < DisasmMode.File)
						return;
					if (sti < 0x8) { // FST
						m = "fst";
					} else { // FSTP
						sti -= 8;
						m = "fstp";
					}
					disasm_push_x8(p, modrm);
					disasm_push_str(p, m);
					disasm_push_str(p, x87_ststr(p, sti));
					break;
				case 0xE0: // FUCOM/FUCOMP
					if (p.mode < DisasmMode.File)
						return;
					disasm_push_x8(p, modrm);
					if (sti < 0x8) { // FUCOM
						disasm_push_str(p, "fucom");
						disasm_push_str(p, x87_ststr(p, sti));
						disasm_push_str(p, x87_ststr(p, 0));
					} else { // FUCOMP
						sti -= 8;
						disasm_push_str(p, "fucomp");
						disasm_push_str(p, x87_ststr(p, sti));
					}
					break;
				default: // 0xF0
					disasm_err(p);
				}
			} else { // operand is memory pointer
				switch (modrm & RM_REG) {
				case RM_REG_000: m = "fld"; break;
				case RM_REG_001: m = "fisttp"; break;
				case RM_REG_010: m = "fst"; break;
				case RM_REG_011: m = "fstp"; break;
				case RM_REG_100: m = "frstor"; break;
				case RM_REG_110: m = "fsave"; break;
				case RM_REG_111: m = "fstsw"; break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, m);
				x86_modrm_rm(p, modrm, X86_WIDTH_MM);
			}
			return;
		case 2:
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
							disasm_push_x8(p, modrm);
							disasm_push_str(p, "fcompp");
						}
					} else
						disasm_err(p);
					return;
				case 0xE0: // FSUBRP/FSUBP
					if (sti < 0x8) { // FSUBP
						m = "fsubrp";
					} else { // FSUBP
						sti -= 8;
						m = "fucomp";
					}
					break;
				case 0xF0: // FDIVRP/FDIVP
					if (sti < 0x8) { // FDIVRP
						m = "fdivrp";
					} else { // FDIVP
						sti -= 8;
						m = "fdivp";
					}
					break;
				default:
				}
				if (p.mode >= DisasmMode.File) {
					disasm_push_x8(p, modrm);
					disasm_push_str(p, m);
					disasm_push_str(p, x87_ststr(p, sti));
					disasm_push_str(p, x87_ststr(p, 0));
				}
			} else { // operand is memory pointer
				if (p.mode >= DisasmMode.File) {
					switch (modrm & RM_REG) {
					case RM_REG_000: m = "fiadd"; break;
					case RM_REG_001: m = "fimul"; break;
					case RM_REG_010: m = "ficom"; break;
					case RM_REG_011: m = "ficomp"; break;
					case RM_REG_100: m = "fisub"; break;
					case RM_REG_101: m = "fisubr"; break;
					case RM_REG_110: m = "fidiv"; break;
					case RM_REG_111: m = "fidivr"; break;
					default: // never
					}
					disasm_push_str(p, m);
				}
				x86_modrm_rm(p, modrm, X86_WIDTH_WIDE);
			}
			return;
		default:
			if (modrm > 0xBF) { // operand is FP
				ubyte sti = modrm & 0xF;
				switch (modrm & 0xF0) {
				case 0xE0: // FSTSW*/FUCOMIP
					if (sti < 0x8) { // FSUBP
						if (sti == 0) {
							if (p.mode >= DisasmMode.File) {
								disasm_push_x8(p, modrm);
								disasm_push_str(p, "fstsw");
								disasm_push_reg(p, "ax");
							}
						} else
							disasm_err(p);
					} else { // FUCOMIP
						if (p.mode < DisasmMode.File)
							return;
						sti -= 8;
						disasm_push_x8(p, modrm);
						disasm_push_str(p, "fstsw");
						disasm_push_str(p, x87_ststr(p, 0));
						disasm_push_str(p, x87_ststr(p, sti));
					}
					return;
				case 0xF0: // FCOMIP/Reserved
					if (sti < 0x8) { // FCOMIP
						if (p.mode < DisasmMode.File)
							return;
						disasm_push_x8(p, modrm);
						disasm_push_str(p, "fcomip");
						disasm_push_str(p, x87_ststr(p, 0));
						disasm_push_str(p, x87_ststr(p, sti));
					} // else Reserved
					goto default;
				default:
					disasm_err(p);
				}
			} else { // operand is memory pointer
				if (p.mode >= DisasmMode.File) {
					switch (modrm & RM_REG) {
					case RM_REG_000: m = "fild"; break;
					case RM_REG_001: m = "fisttp"; break;
					case RM_REG_010: m = "fist"; break;
					case RM_REG_011: m = "fistp"; break;
					case RM_REG_100: m = "fbld"; break;
					case RM_REG_101: m = "fild"; break;
					case RM_REG_110: m = "fbstp"; break;
					case RM_REG_111: m = "fistp"; break;
					default: // never
					}
					disasm_push_str(p, m);
				}
				x86_modrm_rm(p, modrm, X86_WIDTH_MM);
			}
			return;
		}
	case 0b1110_0000: // E0H-E3H
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "loopne"; break;
			case 1:  m = "loope"; break;
			case 2:  m = "loop"; break;
			default: m = "jecxz"; break;
			}
			disasm_push_str(p, m);
		}
		x86_u8imm(p);
		return;
	case 0b1110_0100: // E4H-E7H
		if (dbit) {
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, "out");
			x86_u8imm(p);
			if (p.mode >= DisasmMode.File)
				disasm_push_reg(p, wbit ? "eax" : "al");
		} else {
			if (p.mode >= DisasmMode.File) {
				disasm_push_str(p, "in");
				disasm_push_reg(p, wbit ? "eax" : "al");
			}
			x86_u8imm(p);
		}
		return;
	case 0b1110_1000: // E8H-EBH
		if (dbit) {
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, "jmp");
			if (wbit) { 
				if (p.mode >= DisasmMode.File) {
					disasm_push_x16(p, *p.addru16);
					disasm_push_imm(p, *p.addru16);
				}
				p.addrv += 2;
				x86_u32imm(p);
			} else {
				x86_u8imm(p);
			}
		} else {
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, wbit ? "jmp" : "call");
			x86_u32imm(p);
		}
		return;
	case 0b1110_1100: // ECH-EFH
		if (p.mode < DisasmMode.File)
			return;
		if (dbit) {
			disasm_push_str(p, "out");
			disasm_push_reg(p, "dx");
			disasm_push_reg(p, wbit ? "eax" : "al");
		} else {
			disasm_push_str(p, "in");
			disasm_push_reg(p, wbit ? "eax" : "al");
			disasm_push_reg(p, "dx");
		}
		return;
	case 0b1111_0000: // F0H-F3H
		if (dbit) {
			if (wbit) { // REPZ/REPE/REPE
				p.x86.repz = p.x86.last_prefix = 0xF3;
//				if (p.mode >= DisasmMode.File)
//					disasm_push_prefix(p, "repz");
				goto L_CONTINUE;
			} else { // REPNZ/REPNE
				p.x86.repnz = p.x86.last_prefix = 0xF2;
//				if (p.mode >= DisasmMode.File)
//					disasm_push_prefix(p, "repnz");
				goto L_CONTINUE;
			}
		} else {
			if (wbit) {
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "int1");
			} else {
				p.x86.lock = 0xF0;
//				if (p.mode >= DisasmMode.File)
//					disasm_push_prefix(p, "lock");
				goto L_CONTINUE;
			}
		}
		return;
	case 0b1111_0100: // F4H-F7H
		if (dbit) { // GRP3
			ubyte modrm = *p.addru8;
			++p.addrv;
			switch (modrm & RM_REG) {
			case RM_REG_000: // TEST R/M*, IMM8
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "test");
				x86_modrm_rm(p, modrm, wbit);
				x86_u8imm(p);
				return;
			case RM_REG_010: // NOT R/M*
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "not");
				x86_modrm_rm(p, modrm, wbit);
				return;
			case RM_REG_011: // NEG R/M*
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "neg");
				x86_modrm_rm(p, modrm, wbit);
				return;
			case RM_REG_100: // MUL R/M*, reg-a
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "mul");
				x86_modrm_rm(p, modrm, wbit);
				if (p.mode >= DisasmMode.File)
					disasm_push_reg(p, wbit ? "eax" : "al");
				return;
			case RM_REG_101: // IMUL R/M*, reg-a
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "imul");
				x86_modrm_rm(p, modrm, wbit);
				if (p.mode >= DisasmMode.File)
					disasm_push_reg(p, wbit ? "eax" : "al");
				return;
			case RM_REG_110:
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "div");
				x86_modrm_rm(p, modrm, wbit);
				if (p.mode >= DisasmMode.File)
					disasm_push_reg(p, wbit ? "eax" : "al");
				return;
			case RM_REG_111:
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "idiv");
				x86_modrm_rm(p, modrm, wbit);
				if (p.mode >= DisasmMode.File)
					disasm_push_reg(p, wbit ? "eax" : "al");
				return;
			default:
				disasm_err(p);
			}
		} else {
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, wbit ? "cmc" : "hlt");
		}
		return;
	case 0b1111_1000: // F8H-FBH
		if (p.mode < DisasmMode.File)
			return;
		const(char) *m = void;
		switch (b & 3) {
		case 0:  m = "clc"; break;
		case 1:  m = "stc"; break;
		case 2:  m = "cli"; break;
		default: m = "sti"; break;
		}
		disasm_push_str(p, m);
		return;
	default: // FCH-FFH ANCHOR Last case
		if (dbit) {
			ubyte modrm = *p.addru8;
			++p.addrv;
			const(char) *m = void; // @suppress(dscanner.suspicious.label_var_same_name)
			if (wbit) { // GRP5
				switch (modrm & RM_REG) {
				case RM_REG_000: m = "inc"; break;
				case RM_REG_001: m = "dec"; break;
				case RM_REG_010:
				case RM_REG_011: m = "call"; break; // fword
				case RM_REG_100:
				case RM_REG_101: m = "jmp"; break; // fword
				case RM_REG_110: m = "push"; break;
				default: disasm_err(p); return;
				}
			} else { // GRP4
				switch (modrm & RM_REG) {
				case RM_REG_000: m = "inc"; break;
				case RM_REG_001: m = "dec"; break;
				default: disasm_err(p); return;
				}
			}
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, m);
			x86_modrm_rm(p, modrm,
				wbit ? X86_WIDTH_EXT : X86_WIDTH_BYTE);
		} else {
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, wbit ? "std" : "cld");
		}
		return;
	}
}

private:

void x86_0f(disasm_params_t *p) {
	ubyte b = *p.addru8;
	++p.addrv;

	if (p.mode >= DisasmMode.File)
		disasm_push_x8(p, b);

	int wbit = b & 1;
	int dbit = b & 2;
	switch (b & 252) { // 1111_1100
	case 0:
		if (dbit) {
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, wbit ? "lsl" : "lar");
			x86_modrm(p, X86_DIR_REG, X86_WIDTH_EXT, X86_WIDTH_EXT);
		} else {
			ubyte modrm = *p.addru8;
			++p.addrv;
			if (wbit) {
				ubyte mod11 = (modrm & RM_MOD) == RM_MOD_11;

				const(char) *m = void;
				switch (modrm & RM_REG) {
				case RM_REG_000:
					if (mod11) { // VM*
						if (p.mode < DisasmMode.File)
							break;
						switch (modrm & RM_RM) {
						case RM_RM_001: m = "vmcall"; break;
						case RM_RM_010: m = "vmlaunch"; break;
						case RM_RM_011: m = "vmresume"; break;
						case RM_RM_100: m = "vmxoff"; break;
						default: disasm_err(p); return;
						}
						disasm_push_x8(p, modrm);
						disasm_push_str(p, m);
					} else { // SGDT
						if (p.mode >= DisasmMode.File)
							disasm_push_str(p, "sgdt");
						x86_modrm_rm(p, modrm, X86_WIDTH_EXT);
					}
					return;
				case RM_REG_001:
					if (mod11) { // MONITOR*
						if (p.mode < DisasmMode.File)
							break;
						switch (modrm & RM_RM) {
						case RM_RM_000: m = "monitor"; break;
						case RM_RM_001: m = "mwait"; break;
						case RM_RM_010: m = "clac"; break;
						case RM_RM_011: m = "stac"; break;
						case RM_RM_111: m = "encls"; break;
						default: disasm_err(p); return;
						}
						disasm_push_x8(p, modrm);
						disasm_push_str(p, m);
					} else { // SIDT
						if (p.mode >= DisasmMode.File)
							disasm_push_str(p, "sidt");
						x86_modrm_rm(p, modrm, X86_WIDTH_EXT);
					}
					return;
				case RM_REG_010:
					if (mod11) { // X*
						if (p.mode < DisasmMode.File)
							break;
						switch (modrm & RM_RM) {
						case RM_RM_000: m = "xgetbv"; break;
						case RM_RM_001: m = "xsetbv"; break;
						case RM_RM_100: m = "vmfunc"; break;
						case RM_RM_101: m = "xend"; break;
						case RM_RM_110: m = "xtest"; break;
						case RM_RM_111: m = "enclu"; break;
						default: disasm_err(p); return;
						}
						disasm_push_x8(p, modrm);
						disasm_push_str(p, m);
					} else { // LGDT
						if (p.mode >= DisasmMode.File)
							disasm_push_str(p, "lgdt");
						x86_modrm_rm(p, modrm, X86_WIDTH_EXT);
					}
					return;
				case RM_REG_011:
					if (mod11) { // (AMD) SVM
						if (p.mode < DisasmMode.File)
							break;
						switch (modrm & RM_RM) {
						case RM_RM_000: m = "vmrun"; break;
						case RM_RM_001: m = "vmmcall"; break;
						case RM_RM_010: m = "vmload"; break;
						case RM_RM_011: m = "vmsave"; break;
						case RM_RM_100: m = "stgi"; break;
						case RM_RM_101: m = "clgi"; break;
						case RM_RM_110: m = "skinit"; break;
						case RM_RM_111: m = "invlpga"; break;
						default: // never
						}
						disasm_push_x8(p, modrm);
						disasm_push_str(p, m);
					} else { // LIDT
						if (p.mode >= DisasmMode.File)
							disasm_push_str(p, "lgdt");
						x86_modrm_rm(p, modrm, X86_WIDTH_EXT);
					}
					return;
				case RM_REG_100: // SMSW
					if (p.mode >= DisasmMode.File)
						disasm_push_str(p, "smsw");
					x86_modrm_rm(p, modrm, X86_WIDTH_EXT);
					return;
				case RM_REG_110: // LMSW
					if (p.mode >= DisasmMode.File)
						disasm_push_str(p, "lmsw");
					x86_modrm_rm(p, modrm, X86_WIDTH_EXT);
					return;
				case RM_REG_111:
					if (mod11) { // *
						if ((modrm & RM_RM) == RM_RM_001) {
							if (p.mode >= DisasmMode.File) {
								disasm_push_x8(p, modrm);
								disasm_push_str(p, "rdtscp");
							}
						} else
							disasm_err(p);
					} else { // INVLPG
						if (p.mode >= DisasmMode.File)
							disasm_push_str(p, "invlpg");
						x86_modrm_rm(p, modrm, X86_WIDTH_EXT);
					}
					return;
				default: disasm_err(p);
				}
			} else {
				const(char) *m = void;
				switch (modrm & RM_REG) {
				case RM_REG_000: m = "sldt"; break;
				case RM_REG_001: m = "str"; break;
				case RM_REG_010: m = "lldt"; break;
				case RM_REG_011: m = "ltr"; break;
				case RM_REG_100: m = "verr"; break;
				case RM_REG_101: m = "verw"; break;
				default: disasm_err(p); return;
				}

				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, m);
				x86_modrm_rm(p, modrm, X86_WIDTH_EXT);
			}
		}
		return;
	case 0b0000_0100: // 04H-07H
		if (dbit && wbit == 0) { // 06H
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, "clts");
		} else {
			disasm_err(p);
		}
		return;
	case 0b0000_1000: // 08H-0BH
		if (dbit) {
			if (wbit) {
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "ud2");
			} else {
				disasm_err(p);
			}
		} else {
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, wbit ? "wbinvd" : "invd");
		}
		return;
	case 0b0000_1100: // 0CH-0FH
		if (dbit == 0 && wbit) { // 0DH: PREFETCHW /1
			ubyte modrm = *p.addru8;
			++p.addrv;
			if ((modrm & RM_REG) != RM_REG_001) {
				disasm_err(p);
				return;
			}
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, "prefetchw");
			x86_modrm_rm(p, modrm, X86_WIDTH_EXT);
		} else {
			disasm_err(p);
		}
		return;
	case 0b0001_0000: // 10H-13H
		if (dbit) {
			const(char) *m = void;
			if (wbit) { // MOVLPS/MOVLPD
				switch (x86_0f_select(p)) {
				case X86_0F_NONE: m = "movlps"; break;
				case X86_0F_66H: m = "movlpd"; break;
				default: disasm_err(p); return;
				}
			} else { // (MOVLPS|MOVHLPS)/MOVSLDUP/MOVLPD/MOVDDUP
				switch (x86_0f_select(p)) {
				case X86_0F_NONE:
					m = (*p.addru8 & RM_MOD) == RM_MOD_11 ?
						"movhlps" : "movlps";
					break;
				case X86_0F_66H: m = "movlpd"; break;
				case X86_0F_F2H: m = "movddup"; break;
				case X86_0F_F3H: m = "movsldup"; break;
				default: disasm_err(p); return;
				}
			}
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, m);
			x86_modrm(p, !wbit, X86_WIDTH_XMM, X86_WIDTH_XMM);
			
		} else {
			const(char) *m = void;
			switch (x86_0f_select(p)) {
			case X86_0F_NONE: m = "movups"; break;
			case X86_0F_66H: m = "movupd"; break;
			case X86_0F_F2H: m = "movsd"; break;
			case X86_0F_F3H: m = "movss"; break;
			default: disasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, m);
			x86_modrm(p, wbit, X86_WIDTH_XMM, X86_WIDTH_XMM);
		}
		return;
	case 0b0001_0100: // 14H-17H
		if (dbit) {
			const(char) *m = void;
			if (wbit) {
				switch (x86_0f_select(p)) {
				case X86_0F_NONE: m = "movhps"; break;
				case X86_0F_66H: m = "movhpd"; break;
				default: disasm_err(p); return;
				}
			} else {
				switch (x86_0f_select(p)) {
				case X86_0F_NONE:
					m = (*p.addru8 & RM_MOD) == RM_MOD_11 ?
						"movlhps" : "movhps";
					break;
				case X86_0F_66H: m = "movhpd"; break;
				case X86_0F_F3H: m = "movshdup"; break;
				default: disasm_err(p); return;
				}
			}
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, m);
			x86_modrm(p, !wbit, X86_WIDTH_XMM, X86_WIDTH_XMM);
		} else {
			const(char) *m = void;
			switch (x86_0f_select(p)) {
			case X86_0F_NONE: m = wbit ? "unpckhps" : "unpcklpd"; break;
			case X86_0F_66H: m = wbit ? "unpckhpd" : "unpcklpd"; break;
			default: disasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, m);
			x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
		}
		return;
	case 0b0001_1000: // 18H-1BH
		ubyte modrm = *p.addru8;
		++p.addrv;
		const(char) *m = void, sr = void;
		if (dbit) {
			switch (modrm & RM_REG) {
			case RM_REG_000: sr = "bnd0"; break;
			case RM_REG_001: sr = "bnd1"; break;
			case RM_REG_010: sr = "bnd2"; break;
			case RM_REG_011: sr = "bnd3"; break;
			default: disasm_err(p); return;
			}
			if (wbit) {
				switch (x86_0f_select(p)) {
				case X86_0F_NONE: m = "bndstx"; break;
				case X86_0F_66H: m = "bndmov"; break;
				case X86_0F_F2H: m = "bndcn"; break;
				case X86_0F_F3H: m = "bndmk"; break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, m);
				x86_modrm_rm(p, modrm, X86_WIDTH_EXT);
				if (p.mode >= DisasmMode.File)
					disasm_push_reg(p, sr);
			} else {
				switch (x86_0f_select(p)) {
				case X86_0F_NONE: m = "bndldx"; break;
				case X86_0F_66H: m = "bndmov"; break;
				case X86_0F_F2H: m = "bndcu"; break;
				case X86_0F_F3H: m = "bndcl"; break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File) {
					disasm_push_str(p, m);
					disasm_push_reg(p, sr);
				}
				x86_modrm_rm(p, modrm, X86_WIDTH_EXT);
			}
		} else {
			if (wbit) {
				disasm_err(p);
			} else { // GRP 16
				if ((modrm & RM_MOD) == RM_MOD_11) {
					disasm_err(p);
					return;
				}

				switch (modrm & RM_REG) {
				case RM_REG_000: m = "prefetchnta"; break;
				case RM_REG_001: m = "prefetcht0"; break;
				case RM_REG_010: m = "prefetcht1"; break;
				case RM_REG_011: m = "prefetcht2"; break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, m);
				x86_modrm_rm(p, modrm, X86_WIDTH_EXT);
			}
		}
		return;
	case 0b0001_1100: // 1CH-1FH
		if (dbit && wbit) {
			ubyte modrm = *p.addru8;
			++p.addrv;
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, "nop");
			x86_modrm_rm(p, modrm, X86_WIDTH_EXT);
		} else {
			disasm_err(p);
		}
		return;
	case 0b0010_0000: // 20H-23H
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File)
			disasm_push_x8(p, modrm);
		if ((modrm & RM_MOD) != RM_MOD_11) {
			disasm_err(p);
			return;
		}
		if (p.mode < DisasmMode.File)
			return;
		const(char) *reg = x86_modrm_reg(p, modrm << 3, X86_WIDTH_EXT);
		const(char) *sr = void; // special reg
		if (wbit) {
			switch (modrm & RM_REG) {
			case RM_REG_000: sr = "dr0"; break;
			case RM_REG_001: sr = "dr1"; break;
			case RM_REG_010: sr = "dr2"; break;
			case RM_REG_011: sr = "dr3"; break;
			case RM_REG_100: sr = "dr4"; break;
			case RM_REG_101: sr = "dr5"; break;
			case RM_REG_110: sr = "dr6"; break;
			case RM_REG_111: sr = "dr7"; break;
			default: // never
			}
			disasm_push_str(p, "mov");
			if (dbit) {
				disasm_push_reg(p, sr);
				disasm_push_reg(p, reg);
			} else {
				disasm_push_reg(p, reg);
				disasm_push_reg(p, sr);
			}
		} else {
			if (p.x86.lock)
				switch (modrm & RM_REG) {
				case RM_REG_000: sr = "cr8"; break;
				case RM_REG_001: sr = "cr9"; break;
				case RM_REG_010: sr = "cr10"; break;
				case RM_REG_011: sr = "cr11"; break;
				case RM_REG_100: sr = "cr12"; break;
				case RM_REG_101: sr = "cr13"; break;
				case RM_REG_110: sr = "cr14"; break;
				case RM_REG_111: sr = "cr15"; break;
				default: // never
				}
			else
				switch (modrm & RM_REG) {
				case RM_REG_000: sr = "cr0"; break;
				case RM_REG_001: sr = "cr1"; break;
				case RM_REG_010: sr = "cr2"; break;
				case RM_REG_011: sr = "cr3"; break;
				case RM_REG_100: sr = "cr4"; break;
				case RM_REG_101: sr = "cr5"; break;
				case RM_REG_110: sr = "cr6"; break;
				case RM_REG_111: sr = "cr7"; break;
				default: // never
				}
			disasm_push_str(p, "mov");
			if (dbit) {
				disasm_push_reg(p, sr);
				disasm_push_reg(p, reg);
			} else {
				disasm_push_reg(p, reg);
				disasm_push_reg(p, sr);
			}
		}
		return;
	case 0b0010_1000: // 28H-2BH
		if (dbit) {
			const(char) *m = void;
			if (wbit) {
				switch (x86_0f_select(p)) {
				case X86_0F_NONE: m = "movntps"; break;
				case X86_0F_66H: m = "movntpd"; break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, m);
				x86_modrm(p, X86_DIR_MEM, X86_WIDTH_XMM, X86_WIDTH_XMM);
			} else {
				switch (x86_0f_select(p)) {
				case X86_0F_NONE: m = "cvtpi2ps"; break;
				case X86_0F_66H: m = "cvtpi2pd"; break;
				case X86_0F_F2H: m = "cvtsi2sd"; break;
				case X86_0F_F3H: m = "cvtsi2ss"; break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, m);
				x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
			}
		} else {
			const(char) *m = void;
			switch (x86_0f_select(p)) {
			case X86_0F_NONE: m = "movaps"; break;
			case X86_0F_66H: m = "movapd"; break;
			default: disasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, m);
			x86_modrm(p, !wbit, X86_WIDTH_XMM, X86_WIDTH_XMM);
		}
		return;
	case 0b0010_1100: // 2CH-2FH
		if (dbit) {
			const(char) *m = void;
			switch (x86_0f_select(p)) {
			case X86_0F_NONE: m = wbit ? "comiss" : "ucomiss"; break;
			case X86_0F_66H: m = wbit ? "comisd" : "ucomisd"; break;
			default: disasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, m);
			x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
		} else {
			ubyte modrm = *p.addru8;
			++p.addr;
			const(char) *m = void;
			int w = void;
			switch (x86_0f_select(p)) {
			case X86_0F_NONE:
				m = wbit ? "cvtps2pi" : "cvttps2pi";
				w = X86_WIDTH_MM;
				break;
			case X86_0F_66H:
				m = wbit ? "cvtpd2pi" : "cvttpd2pi";
				w = X86_WIDTH_MM;
				break;
			case X86_0F_F2H:
				m = wbit ? "cvtsd2si" : "cvttsd2si";
				w = X86_WIDTH_EXT;
				break;
			case X86_0F_F3H:
				m = wbit ? "cvtss2si" : "cvttss2si";
				w = X86_WIDTH_EXT;
				break;
			default: disasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File) {
				disasm_push_str(p, m);
				disasm_push_reg(p, x86_modrm_reg(p, modrm, w));
			}
			x86_modrm_rm(p, modrm, X86_WIDTH_XMM);
		}
		return;
	case 0b0011_0000: // 30H-33H
		if (p.mode < DisasmMode.File)
			return;
		const(char) *m = void;
		if (dbit)
			m = wbit ? "rdpmc" : "rdmsr";
		else
			m = wbit ? "rdtsc" : "wrmsr";
		disasm_push_str(p, m);
		return;
	case 0b0011_0100: // 34H-37H
		const(char) *m = void;
		if (dbit)
			if (wbit) {
				m = "getsec";
			} else {
				disasm_err(p);
				return;
			}
		else
			m = wbit ? "sysexit" : "sysenter";
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		return;
	case 0b0011_1000: // 38H-3BH
		if (wbit) {
			disasm_err(p);
			return;
		}
		if (dbit)
			x86_0f3a(p);
		else
			x86_0f38(p);
		return;
	case 0b0100_0000: // 40H-43H
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "cmovo"; break;
			case 1:  m = "cmovno"; break;
			case 2:  m = "cmovb"; break;
			default: m = "cmovae"; break;
			}
		}
		x86_modrm(p, X86_DIR_REG, X86_WIDTH_EXT, X86_WIDTH_EXT);
		return;
	case 0b0100_0100: // 44H-47H
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "cmove"; break;
			case 1:  m = "cmovne"; break;
			case 2:  m = "cmovbe"; break;
			default: m = "cmova"; break;
			}
		}
		x86_modrm(p, X86_DIR_REG, X86_WIDTH_EXT, X86_WIDTH_EXT);
		return;
	case 0b0100_1000: // 48H-4BH
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "cmovs"; break;
			case 1:  m = "cmovns"; break;
			case 2:  m = "cmovp"; break;
			default: m = "cmovnp"; break;
			}
		}
		x86_modrm(p, X86_DIR_REG, X86_WIDTH_EXT, X86_WIDTH_EXT);
		return;
	case 0b0100_1100: // 4CH-4FH
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "cmovl"; break;
			case 1:  m = "cmovnl"; break;
			case 2:  m = "cmovle"; break;
			default: m = "cmovnle"; break;
			}
		}
		x86_modrm(p, X86_DIR_REG, X86_WIDTH_EXT, X86_WIDTH_EXT);
		return;
	case 0b0101_0000: // 50H-53H
		const(char) *m = void;
		if (dbit) {
			switch (x86_0f_select(p)) {
			case X86_0F_NONE: m = wbit ? "rcpps" : "rsqrtps"; break;
			case X86_0F_F3H: m = wbit ? "rcpss" : "rsqrtss"; break;
			default: disasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, m);
			x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
		} else {
			if (wbit) {
				switch (x86_0f_select(p)) {
				case X86_0F_NONE: m = "sqrtps"; break;
				case X86_0F_66H: m = "sqrtpd"; break;
				case X86_0F_F2H: m = "sqrtsd"; break;
				case X86_0F_F3H: m = "sqrtss"; break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, m);
				x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
			} else {
				switch (x86_0f_select(p)) {
				case X86_0F_NONE: m = "movmskps"; break;
				case X86_0F_66H: m = "movmskpd"; break;
				default: disasm_err(p); return;
				}
				ubyte modrm = *p.addru8;
				++p.addrv;
				if ((modrm & RM_MOD) != RM_MOD_11) {
					disasm_err(p);
					return;
				}
				if (p.mode >= DisasmMode.File) {
					disasm_push_x8(p, modrm);
					disasm_push_str(p, m);
					disasm_push_reg(p,
						x86_modrm_reg(p, modrm, X86_WIDTH_EXT));
					disasm_push_reg(p,
						x86_modrm_reg(p, modrm << 3, X86_WIDTH_XMM));
				}
			}
		}
		return;
	case 0b0101_0100: // 54H-57H
		const(char) *m = void;
		if (dbit) {
			switch (x86_0f_select(p)) {
			case X86_0F_NONE: m = wbit ? "xorps" : "orps"; break;
			case X86_0F_66H: m = wbit ? "xorpd" : "orpd"; break;
			default: disasm_err(p); return;
			}
		} else {
			switch (x86_0f_select(p)) {
			case X86_0F_NONE: m = wbit ? "andnps" : "andps"; break;
			case X86_0F_66H: m = wbit ? "andnpd" : "andpd"; break;
			default: disasm_err(p); return;
			}
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
		return;
	case 0b0101_1000: // 58H-5BH
		const(char) *m = void;
		if (dbit) {
			if (wbit) {
				switch (x86_0f_select(p)) {
				case X86_0F_NONE: m = "cvtdq2ps"; break;
				case X86_0F_66H: m = "cvtps2dq"; break;
				case X86_0F_F3H: m = "cvttps2dq"; break;
				default: disasm_err(p); return;
				}
			} else {
				switch (x86_0f_select(p)) {
				case X86_0F_NONE: m = "cvtps2pd"; break;
				case X86_0F_66H: m = "cvtpd2ps"; break;
				case X86_0F_F2H: m = "cvtsd2ss"; break;
				case X86_0F_F3H: m = "cvtss2sd"; break;
				default: disasm_err(p); return;
				}
			}
		} else {
			switch (x86_0f_select(p)) {
			case X86_0F_NONE: m = wbit ? "mulps" : "addps"; break;
			case X86_0F_66H: m = wbit ? "mulpd" : "addpd"; break;
			case X86_0F_F2H: m = wbit ? "mulsd" : "addsd"; break;
			case X86_0F_F3H: m = wbit ? "mulss" : "addss"; break;
			default: disasm_err(p); return;
			}
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
		return;
	case 0b0101_1100: // 5CH-5FH
		const(char) *m = void;
		if (dbit) {
			switch (x86_0f_select(p)) {
			case X86_0F_NONE: m = wbit ? "maxps" : "divps"; break;
			case X86_0F_66H: m = wbit ? "maxpd" : "divpd"; break;
			case X86_0F_F2H: m = wbit ? "maxss" : "divsd"; break;
			case X86_0F_F3H: m = wbit ? "maxsd" : "divss"; break;
			default: disasm_err(p); return;
			}
		} else {
			switch (x86_0f_select(p)) {
			case X86_0F_NONE: m = wbit ? "minps" : "subps"; break;
			case X86_0F_66H: m = wbit ? "minpd" : "subpd"; break;
			case X86_0F_F2H: m = wbit ? "minsd" : "subsd"; break;
			case X86_0F_F3H: m = wbit ? "minss" : "subss"; break;
			default: disasm_err(p); return;
			}
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
		return;
	case 0b0110_0000: // 60H-63H
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			if (dbit)
				m = wbit ? "packsswb" : "punpckldq";
			else
				m = wbit ? "punpcklwd" : "punpcklbw";
			disasm_push_str(p, m);
		}
		x86_modrm(p, X86_DIR_REG, w, w);
		return;
	case 0b0110_0100: // 64H-67H
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			if (dbit)
				m = wbit ? "packuswb" : "pcmpgtd";
			else
				m = wbit ? "pcmpgtw" : "pcmpgtb";
			disasm_push_str(p, m);
		}
		x86_modrm(p, X86_DIR_REG, w, w);
		return;
	case 0b0110_1000: // 68H-6BH
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			if (dbit)
				m = wbit ? "packssdw" : "punpckhdq";
			else
				m = wbit ? "punpckhwd" : "punpckhbw";
			disasm_push_str(p, m);
		}
		x86_modrm(p, X86_DIR_REG, w, w);
		return;
	case 0b0110_1100: // 6CH-6FH
		const(char) *m = void;
		int w = void;
		if (dbit) {
			if (wbit) {
				switch (x86_0f_select(p)) {
				case X86_0F_NONE:
					m = "movq";
					w = X86_WIDTH_MM;
					break;
				case X86_0F_66H:
					m = "movdqa";
					w = X86_WIDTH_XMM;
					break;
				case X86_0F_F3H:
					m = "movdqu";
					w = X86_WIDTH_XMM;
					break;
				default: disasm_err(p); return;
				}
			} else {
				switch (x86_0f_select(p)) {
				case X86_0F_NONE: w = X86_WIDTH_MM; break;
				case X86_0F_66H: w = X86_WIDTH_XMM; break;
				default: disasm_err(p); return;
				}
				m = "movd";
			}
		} else {
			switch (x86_0f_select(p)) {
			case X86_0F_66H: break;
			default: disasm_err(p); return;
			}
			w = X86_WIDTH_XMM;
			m = wbit ? "punpckhqdq" : "punpcklqdq";
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_DIR_REG, w, w);
		break;
	case 0b0111_0000: // 70H-73H
		ubyte modrm = *p.addru8;
		++p.addrv;
		if ((modrm & RM_MOD) != RM_MOD_11) {
			disasm_err(p);
			break;
		}
		const(char) *m = void;
		int w = void;
		if (dbit) {
			if (wbit) { // GRP14
				switch (modrm & RM_REG) {
				case RM_REG_010:
					switch (x86_0f_select(p)) {
					case X86_0F_NONE: w = X86_WIDTH_MM; break;
					case X86_0F_66H: w = X86_WIDTH_XMM; break;
					default: disasm_err(p); return;
					}
					m = "psrlq";
					break;
				case RM_REG_011:
					switch (x86_0f_select(p)) {
					case X86_0F_66H: w = X86_WIDTH_XMM; break;
					default: disasm_err(p); return;
					}
					m = "psrldq";
					break;
				case RM_REG_110:
					switch (x86_0f_select(p)) {
					case X86_0F_NONE: w = X86_WIDTH_MM; break;
					case X86_0F_66H: w = X86_WIDTH_XMM; break;
					default: disasm_err(p); return;
					}
					m = "psllq";
					break;
				case RM_REG_111:
					switch (x86_0f_select(p)) {
					case X86_0F_66H: w = X86_WIDTH_XMM; break;
					default: disasm_err(p); return;
					}
					m = "pslldq";
					break;
				default: disasm_err(p); return;
				}
			} else { // GRP13
				switch (modrm & RM_REG) {
				case RM_REG_010:
					switch (x86_0f_select(p)) {
					case X86_0F_NONE: w = X86_WIDTH_MM; break;
					case X86_0F_66H: w = X86_WIDTH_XMM; break;
					default: disasm_err(p); return;
					}
					m = "psrld";
					break;
				case RM_REG_100:
					switch (x86_0f_select(p)) {
					case X86_0F_NONE: w = X86_WIDTH_MM; break;
					case X86_0F_66H: w = X86_WIDTH_XMM; break;
					default: disasm_err(p); return;
					}
					m = "psrad";
					break;
				case RM_REG_110:
					switch (x86_0f_select(p)) {
					case X86_0F_NONE: w = X86_WIDTH_MM; break;
					case X86_0F_66H: w = X86_WIDTH_XMM; break;
					default: disasm_err(p); return;
					}
					m = "pslld";
					break;
				default: disasm_err(p); return;
				}
			}
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, m);
			x86_modrm(p, X86_DIR_REG, w, w);
		} else {
			if (wbit) { // GRP12
				switch (modrm & RM_REG) {
				case RM_REG_010:
					m = "psrlw";
					switch (x86_0f_select(p)) {
					case X86_0F_NONE: w = X86_WIDTH_MM; break;
					case X86_0F_66H: w = X86_WIDTH_XMM; break;
					default: disasm_err(p); return;
					}
					break;
				case RM_REG_100:
					m = "psraw";
					switch (x86_0f_select(p)) {
					case X86_0F_NONE: w = X86_WIDTH_MM; break;
					case X86_0F_66H: w = X86_WIDTH_XMM; break;
					default: disasm_err(p); return;
					}
					break;
				case RM_REG_110:
					m = "psllw";
					switch (x86_0f_select(p)) {
					case X86_0F_NONE: w = X86_WIDTH_MM; break;
					case X86_0F_66H: w = X86_WIDTH_XMM; break;
					default: disasm_err(p); return;
					}
					break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, m);
				x86_modrm(p, X86_DIR_REG, w, w);
			} else {
				switch (x86_0f_select(p)) {
				case X86_0F_NONE:
					m = "pshufw";
					w = X86_WIDTH_MM;
					break;
				case X86_0F_66H:
					m = "pshufd";
					w = X86_WIDTH_XMM;
					break;
				case X86_0F_F2H:
					m = "pshuflw";
					w = X86_WIDTH_XMM;
					break;
				case X86_0F_F3H:
					m = "pshufhw";
					w = X86_WIDTH_XMM;
					break;
				default: disasm_err(p); return;
				}
				ubyte imm = *p.addru8;
				++p.addrv;
				if (p.mode >= DisasmMode.File) {
					disasm_push_x8(p, modrm);
					disasm_push_x8(p, imm);
					disasm_push_str(p, m);
					disasm_push_reg(p,
						x86_modrm_reg(p, modrm, w));
					disasm_push_reg(p,
						x86_modrm_reg(p, modrm << 3, w));
					disasm_push_imm(p, imm);
				}
			}
		}
		return;
	case 0b0111_0100: // 74H-77H
		if (dbit) {
			if (wbit) {
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "emms");
			} else {
				int w = void;
				switch (x86_0f_select(p)) {
				case X86_0F_NONE: w = X86_WIDTH_MM; break;
				case X86_0F_66H: w = X86_WIDTH_XMM; break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "pcmpeqd");
				x86_modrm(p, X86_DIR_REG, w, w);
			}
		} else {
			int w = void;
			switch (x86_0f_select(p)) {
			case X86_0F_NONE: w = X86_WIDTH_MM; break;
			case X86_0F_66H: w = X86_WIDTH_XMM; break;
			default: disasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, wbit ? "pcmpeqw" : "pcmpeqb");
			x86_modrm(p, X86_DIR_REG, w, w);
		}
		return;
	case 0b0111_1000: // 78H-7BH
		if (dbit) {
			disasm_err(p);
			return;
		}
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, wbit ? "vmwrite" : "vmread");
		x86_modrm(p, wbit, X86_WIDTH_EXT, X86_WIDTH_EXT);
		return;
	case 0b0111_1100: // 7CH-7FH
		const(char) *m = void;
		if (dbit) {
			if (wbit) {
				int w = void;
				switch (x86_0f_select(p)) {
				case X86_0F_NONE:
					m = "movq";
					w = X86_WIDTH_MM;
					break;
				case X86_0F_66H:
					m = "movdqa";
					w = X86_WIDTH_XMM;
					break;
				case X86_0F_F3H:
					m = "movdqu";
					w = X86_WIDTH_XMM;
					break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, m);
				x86_modrm(p, X86_DIR_MEM, w, w);
			} else {
				int d = void, w = void;
				switch (x86_0f_select(p)) {
				case X86_0F_NONE:
					m = "movd";
					w = X86_WIDTH_MM;
					d = X86_DIR_MEM;
					break;
				case X86_0F_66H:
					m = "movd";
					w = X86_WIDTH_XMM;
					d = X86_DIR_MEM;
					break;
				case X86_0F_F3H:
					m = "movq";
					w = X86_WIDTH_XMM;
					d = X86_DIR_REG;
					break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, m);
				x86_modrm(p, d, w, w);
			}
		} else {
			switch (x86_0f_select(p)) {
			case X86_0F_66H: m = wbit ? "hsubpd" : "haddpd"; break;
			case X86_0F_F2H: m = wbit ? "hsubps" : "haddps"; break;
			default: disasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, m);
			x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
		}
		return;
	case 0b1000_0000: // 80H-83H
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "jo"; break;
			case 1:  m = "jno"; break;
			case 2:  m = "jb"; break;
			default: m = "jae"; break;
			}
			disasm_push_str(p, m);
		}
		x86_u32imm(p);
		return;
	case 0b1000_0100: // 84H-87H
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "je"; break;
			case 1:  m = "jne"; break;
			case 2:  m = "jbe"; break;
			default: m = "ja"; break;
			}
			disasm_push_str(p, m);
		}
		x86_u32imm(p);
		return;
	case 0b1000_1000: // 88H-8BH
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "js"; break;
			case 1:  m = "jns"; break;
			case 2:  m = "jp"; break;
			default: m = "jnp"; break;
			}
			disasm_push_str(p, m);
		}
		x86_u32imm(p);
		return;
	case 0b1000_1100: // 8CH-8FH
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "jl"; break;
			case 1:  m = "jnl"; break;
			case 2:  m = "jle"; break;
			default: m = "jnle"; break;
			}
			disasm_push_str(p, m);
		}
		x86_u32imm(p);
		return;
	case 0b1001_0000: // 90H-93H
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "seto"; break;
			case 1:  m = "setno"; break;
			case 2:  m = "setb"; break;
			default: m = "setae"; break;
			}
			disasm_push_str(p, m);
		}
		x86_modrm_rm(p, modrm, X86_WIDTH_BYTE);
		return;
	case 0b1001_0100: // 94H-97H
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "sete"; break;
			case 1:  m = "setne"; break;
			case 2:  m = "setbe"; break;
			default: m = "seta"; break;
			}
			disasm_push_str(p, m);
		}
		x86_modrm_rm(p, modrm, X86_WIDTH_BYTE);
		return;
	case 0b1001_1000: // 98H-9BH
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "sets"; break;
			case 1:  m = "setns"; break;
			case 2:  m = "setp"; break;
			default: m = "setnp"; break;
			}
			disasm_push_str(p, m);
		}
		x86_modrm_rm(p, modrm, X86_WIDTH_BYTE);
		return;
	case 0b1001_1100: // 9CH-9FH
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "setl"; break;
			case 1:  m = "setnl"; break;
			case 2:  m = "setle"; break;
			default: m = "setnle"; break;
			}
			disasm_push_str(p, m);
		}
		x86_modrm_rm(p, modrm, X86_WIDTH_BYTE);
		return;
	case 0b1010_0000: // A0H-A3H
		if (dbit) {
			if (wbit) {
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "bt");
				x86_modrm(p, X86_DIR_MEM, X86_WIDTH_EXT, X86_WIDTH_EXT);
			} else {
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "cpuid");
			}
		} else {
			if (p.mode >= DisasmMode.File) {
				disasm_push_str(p, wbit ? "pop" : "push");
				disasm_push_reg(p, "fs");
			}
		}
		return;
	case 0b1010_0100: // A4H-A7H
		if (dbit) {
			disasm_err(p);
			return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "shld");
		x86_modrm(p, X86_DIR_MEM, X86_WIDTH_EXT, X86_WIDTH_EXT);
		if (wbit) {
			if (p.mode >= DisasmMode.File)
				disasm_push_reg(p, "cl");
		} else {
			x86_u8imm(p);
		}
		return;
	case 0b1010_1000: // A8H-ABH
		if (dbit) {
			if (wbit) {
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "bts");
				x86_modrm(p, X86_DIR_MEM, X86_WIDTH_EXT, X86_WIDTH_EXT);
			} else {
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "rsm");
			}
		} else {
			if (p.mode >= DisasmMode.File) {
				disasm_push_str(p, wbit ? "pop" : "push");
				disasm_push_reg(p, "gs");
			}
		}
		return;
	case 0b1010_1100: // ACH-AFH
		if (dbit) {
			if (wbit) {
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "imul");
				x86_modrm(p, X86_DIR_REG, X86_WIDTH_EXT, X86_WIDTH_EXT);
			} else { // GRP15
				ubyte modrm = *p.addru8;
				++p.addrv;
				if ((modrm & RM_MOD) == RM_MOD_11) {
					switch (x86_0f_select(p)) {
					case X86_0F_NONE:
						const(char) *m = void;
						switch (modrm & RM_REG) {
						case RM_REG_101: m = "lfence"; break;
						case RM_REG_110: m = "mfence"; break;
						case RM_REG_111: m = "sfence"; break;
						default: disasm_err(p); return;
						}
						if (p.mode >= DisasmMode.File) {
							disasm_push_x8(p, modrm);
							disasm_push_str(p, m);
						}
						return;
					case X86_0F_F3H:
						const(char) *m = void;
						switch (modrm & RM_REG) {
						case RM_REG_000: m = "rdfsbase"; break;
						case RM_REG_001: m = "rdgsbase"; break;
						case RM_REG_010: m = "wrfsbase"; break;
						case RM_REG_011: m = "wrgsbase"; break;
						default: disasm_err(p); return;
						}
						if (p.mode >= DisasmMode.File) {
							disasm_push_x8(p, modrm);
							disasm_push_str(p, m);
							disasm_push_reg(p,
								x86_modrm_reg(p, modrm, X86_WIDTH_EXT));
						}
						return;
					default: disasm_err(p); return;
					}
				} else { // mem
					const(char) *m = void;
					switch (modrm & RM_REG) {
					case RM_REG_000: m = "fxsave"; break;
					case RM_REG_001: m = "fxrstor"; break;
					case RM_REG_010: m = "ldmxcsr"; break;
					case RM_REG_011: m = "stmxcsr"; break;
					case RM_REG_100: m = "xsave"; break;
					case RM_REG_101: m = "xrstor"; break;
					case RM_REG_110: m = "xsaveopt"; break;
					case RM_REG_111: m = "clflush"; break;
					default: // Never
					}
					if (p.mode >= DisasmMode.File)
						disasm_push_str(p, m);
					x86_modrm_rm(p, modrm, X86_WIDTH_EXT);
				}
			}
		} else {
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, "shld");
			x86_modrm(p, X86_DIR_MEM, X86_WIDTH_EXT, X86_WIDTH_EXT);
			if (wbit) {
				x86_u8imm(p);
			} else {
				if (p.mode >= DisasmMode.File)
					disasm_push_reg(p, "cl");
			}
		}
		return;
	case 0b1011_0000: // B0H-B3H
		if (dbit) {
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, wbit ? "btr" : "lss");
			x86_modrm(p, !wbit, X86_WIDTH_EXT, X86_WIDTH_EXT);
		} else {
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, "cmpxchg");
			x86_modrm(p, X86_DIR_MEM, wbit, wbit);
		}
		return;
	case 0b1011_0100: // B4H-B7H
		if (dbit) {
			// wbit 0: RM8, 1: RM16
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, "movzx");
			x86_modrm(p, X86_DIR_REG, X86_WIDTH_EXT, X86_WIDTH_EXT);
		} else {
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, wbit ? "lgs" : "lfs");
			x86_modrm(p, X86_DIR_REG, X86_WIDTH_EXT, X86_WIDTH_EXT);
		}
		return;
	case 0b1011_1000: // B8H-BBH
		if (dbit) {
			if (wbit) {
				ubyte modrm = *p.addru8;
				++p.addrv;
				if ((modrm & RM_MOD) != RM_MOD_11) {
					disasm_err(p);
					return;
				}
				const(char) *m = void;
				switch (modrm & RM_REG) {
				case RM_REG_100: m = "bt"; break;
				case RM_REG_101: m = "bts"; break;
				case RM_REG_110: m = "btr"; break;
				case RM_REG_111: m = "btc"; break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File) {
					disasm_push_x8(p, modrm);
					disasm_push_str(p, m);
					disasm_push_reg(p,
						x86_modrm_reg(p, modrm << 3, X86_WIDTH_EXT));
				}
				x86_u8imm(p);
			} else {
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "btc");
				x86_modrm(p, X86_DIR_MEM, X86_WIDTH_EXT, X86_WIDTH_EXT);
			}
		} else {
			if (wbit) {
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "ud1");
			} else {
				switch (x86_0f_select(p)) {
				case X86_0F_F3H:
					if (p.mode >= DisasmMode.File)
						disasm_push_str(p, "popcnt");
					x86_modrm(p, X86_DIR_MEM, X86_WIDTH_EXT, X86_WIDTH_EXT);
					return;
				default: disasm_err(p);
				}
			}
		}
		return;
	case 0b1011_1100: // BCH-BFH
		if (dbit) {
			// wbit 0: RM8, 1: RM16
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, "movsx");
			x86_modrm(p, X86_DIR_REG, X86_WIDTH_EXT, X86_WIDTH_EXT);
		} else {
			const(char) *m = void;
			switch (x86_0f_select(p)) {
			case X86_0F_NONE: m = wbit ? "bsr" : "bsf"; break;
			case X86_0F_F3H: m = wbit ? "lzcnt" : "tzcnt"; break;
			default: disasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, m);
			x86_modrm(p, X86_DIR_REG, X86_WIDTH_EXT, X86_WIDTH_EXT);
		}
		return;
	case 0b1100_0000: // C0H-C3H
		if (dbit) {
			if (wbit) {
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "movnti");
				x86_modrm(p, X86_DIR_MEM, X86_WIDTH_EXT, X86_WIDTH_EXT);
			} else {
				const(char) *m = void;
				switch (x86_0f_select(p)) {
				case X86_0F_NONE: m = "cmpps"; break;
				case X86_0F_66H: m = "cmppd"; break;
				case X86_0F_F2H: m = "cmpsd"; break;
				case X86_0F_F3H: m = "cmpss"; break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, m);
				x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
				x86_u8imm(p);
			}
		} else {
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, "xadd");
			int w = wbit ? X86_WIDTH_EXT : X86_WIDTH_BYTE;
			x86_modrm(p, X86_DIR_MEM, w, w);
		}
		return;
	case 0b1100_0100: // C4H-C7H
		if (dbit) {
			if (wbit) { // GRP9
				ubyte modrm = *p.addru8;
				++p.addrv;
				int modrm_reg = modrm & RM_REG;
				if ((modrm & RM_MOD) == RM_MOD_11) {
					const(char) *m = void;
					switch (modrm_reg) {
					case RM_REG_110: m = "rdrand"; break;
					case RM_REG_111:
						switch (x86_0f_select(p)) {
						case X86_0F_NONE: m = "rdseed"; break;
						case X86_0F_66H: m = "rdpid"; break;
						default: disasm_err(p); return;
						}
						break;
					default: disasm_err(p); return;
					}
					if (p.mode >= DisasmMode.File) {
						disasm_push_x8(p, modrm);
						disasm_push_str(p, m);
						disasm_push_reg(p,
							x86_modrm_reg(p, modrm >> 3, X86_WIDTH_EXT));
					}
				} else {
					const(char) *m = void;
					switch (modrm_reg) {
					// cmpxchg16b is only in x86-64
					// in x86-64, cmpxchg16b can be selected with REX 48H
					case RM_REG_001: m = "cmpxchg8b"; break;
					case RM_REG_110:
						switch (x86_0f_select(p)) {
						case X86_0F_NONE: m = "vmptrld"; break;
						case X86_0F_66H: m = "vmclear"; break;
						case X86_0F_F3H: m = "vmxon"; break;
						default: disasm_err(p); return;
						}
						break;
					case RM_REG_111: m = "vmptrst"; break;
					default: disasm_err(p); return;
					}
					if (p.mode >= DisasmMode.File)
						disasm_push_str(p, m);
					x86_modrm_rm(p, modrm, X86_WIDTH_EXT);
				}
			} else {
				ubyte modrm = *p.addru8;
				++p.addrv;
				if ((modrm & RM_MOD) != RM_MOD_11) {
					disasm_err(p);
					return;
				}
				const(char) *m = void;
				switch (x86_0f_select(p)) {
				case X86_0F_NONE: m = "shufps"; break;
				case X86_0F_66H: m = "shufpd"; break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File) {
					disasm_push_x8(p, modrm);
					disasm_push_str(p, m);
					disasm_push_reg(p,
						x86_modrm_reg(p, modrm, X86_WIDTH_XMM));
					disasm_push_reg(p,
						x86_modrm_reg(p, modrm << 3, X86_WIDTH_XMM));
				}
				x86_u8imm(p);
			}
		} else {
			if (wbit) {
				ubyte modrm = *p.addru8;
				++p.addrv;
				if ((modrm & RM_MOD) != RM_MOD_11) {
					disasm_err(p);
					return;
				}
				int w = void;
				switch (x86_0f_select(p)) {
				case X86_0F_NONE: w = X86_WIDTH_MM; break;
				case X86_0F_66H: w = X86_WIDTH_XMM; break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File) {
					disasm_push_x8(p, modrm);
					disasm_push_str(p, "pextrw");
					disasm_push_reg(p, x86_modrm_reg(p, modrm, X86_WIDTH_EXT));
					disasm_push_reg(p, x86_modrm_reg(p, modrm << 3, w));
				}
				x86_u8imm(p);
			} else {
				int w = void;
				switch (x86_0f_select(p)) {
				case X86_0F_NONE: w = X86_WIDTH_MM; break;
				case X86_0F_66H: w = X86_WIDTH_XMM; break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "pinsrw");
				x86_modrm(p, X86_DIR_REG, w, w);
				ubyte imm = *p.addru8;
				++p.addrv;
				if (p.mode >= DisasmMode.File) {
					disasm_push_x8(p, imm);
					disasm_push_imm(p, imm);
				}
			}
		}
		return;
	case 0b1100_1000: // C8H-CBH
		if (p.mode < DisasmMode.File)
			return;
		const(char) *m = void;
		switch (b & 3) {
		case 0:  m = p.x86.pf_operand ? "ax" : "eax"; break;
		case 1:  m = p.x86.pf_operand ? "cx" : "ecx"; break;
		case 2:  m = p.x86.pf_operand ? "dx" : "edx"; break;
		default: m = p.x86.pf_operand ? "bx" : "ebx"; break;
		}
		disasm_push_str(p, "bswap");
		disasm_push_reg(p, m);
		return;
	case 0b1100_1100: // CCH-CFH
		if (p.mode < DisasmMode.File)
			return;
		const(char) *m = void;
		switch (b & 3) {
		case 0:  m = p.x86.pf_operand ? "sp" : "esp"; break;
		case 1:  m = p.x86.pf_operand ? "bp" : "ebp"; break;
		case 2:  m = p.x86.pf_operand ? "si" : "esi"; break;
		default: m = p.x86.pf_operand ? "di" : "edi"; break;
		}
		disasm_push_str(p, "bswap");
		disasm_push_reg(p, m);
		return;
	case 0b1101_0000: // D0H-D3H
		if (dbit) {
			int w = void;
			switch (x86_0f_select(p)) {
			case X86_0F_NONE: w = X86_WIDTH_MM; break;
			case X86_0F_66H: w = X86_WIDTH_XMM; break;
			default: disasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, wbit ? "psrlq" : "psrld");
			x86_modrm(p, X86_DIR_REG, w, w);
		} else {
			if (wbit) {
				int w = void;
				switch (x86_0f_select(p)) {
				case X86_0F_NONE: w = X86_WIDTH_MM; break;
				case X86_0F_66H: w = X86_WIDTH_XMM; break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "psrlw");
				x86_modrm(p, X86_DIR_REG, w, w);
			} else {
				const(char) *m = void;
				switch (x86_0f_select(p)) {
				case X86_0F_66H: m = "addsubpd"; break;
				case X86_0F_F2H: m = "addsubps"; break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, m);
				x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
			}
		}
		return;
	case 0b1101_0100: // D4H-D7H
		if (dbit) {
			if (wbit) {
				ubyte modrm = *p.addru8;
				++p.addrv;
				if ((modrm & RM_MOD) != RM_MOD_11) {
					disasm_err(p);
					return;
				}
				int w = void;
				switch (x86_0f_select(p)) {
				case X86_0F_NONE: w = X86_WIDTH_MM; break;
				case X86_0F_66H: w = X86_WIDTH_XMM; break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File) {
					disasm_push_x8(p, modrm);
					disasm_push_str(p, "pmovmskb");
					disasm_push_reg(p,
						x86_modrm_reg(p, modrm, X86_WIDTH_EXT));
					disasm_push_reg(p,
						x86_modrm_reg(p, modrm << 3, w));
				}
			} else {
				switch (x86_0f_select(p)) {
				case X86_0F_66H:
					if (p.mode >= DisasmMode.File)
						disasm_push_str(p, "movq");
					x86_modrm(p, X86_DIR_MEM, X86_WIDTH_XMM, X86_WIDTH_XMM);
					return;
				case X86_0F_F2H:
					ubyte modrm = *p.addru8;
					++p.addrv;
					if ((modrm & RM_MOD) != RM_MOD_11) {
						disasm_err(p);
						return;
					}
					if (p.mode >= DisasmMode.File) {
						disasm_push_x8(p, modrm);
						disasm_push_str(p, "movdq2q");
						disasm_push_reg(p,
							x86_modrm_reg(p, modrm, X86_WIDTH_MM));
						disasm_push_reg(p,
							x86_modrm_reg(p, modrm << 3, X86_WIDTH_XMM));
					}
					return;
				case X86_0F_F3H:
					ubyte modrm = *p.addru8;
					++p.addrv;
					if ((modrm & RM_MOD) != RM_MOD_11) {
						disasm_err(p);
						return;
					}
					if (p.mode >= DisasmMode.File) {
						disasm_push_x8(p, modrm);
						disasm_push_str(p, "movq2dq");
						disasm_push_reg(p,
							x86_modrm_reg(p, modrm, X86_WIDTH_XMM));
						disasm_push_reg(p,
							x86_modrm_reg(p, modrm << 3, X86_WIDTH_MM));
					}
					return;
				default: disasm_err(p); return;
				}
			}
		} else {
			int w = void;
			switch (x86_0f_select(p)) {
			case X86_0F_NONE: w = X86_WIDTH_MM; break;
			case X86_0F_66H: w = X86_WIDTH_XMM; break;
			default: disasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, wbit ? "pmullw" : "paddq");
			x86_modrm(p, X86_DIR_REG, w, w);
		}
		return;
	case 0b1101_1000: // D8H-DBH
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "psubusb"; break;
			case 1:  m = "psubusw"; break;
			case 2:  m = "pminub"; break;
			default: m = "pand"; break;
			}
			disasm_push_str(p, m);
		}
		x86_modrm(p, X86_DIR_REG, w, w);
		return;
	case 0b1101_1100: // DCH-DFH
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "paddusb"; break;
			case 1:  m = "paddusw"; break;
			case 2:  m = "pmaxub"; break;
			default: m = "pandn"; break;
			}
			disasm_push_str(p, m);
		}
		x86_modrm(p, X86_DIR_REG, w, w);
		return;
	case 0b1110_0000: // E0H-E3H
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "pavgb"; break;
			case 1:  m = "psraw"; break;
			case 2:  m = "psrad"; break;
			default: m = "pavgw"; break;
			}
			disasm_push_str(p, m);
		}
		x86_modrm(p, X86_DIR_REG, w, w);
		return;
	case 0b1110_0100: // E4H-E7H
		const(char) *m = void;
		int w = void;
		if (dbit) {
			if (wbit) {
				switch (x86_0f_select(p)) {
				case X86_0F_NONE:
					m = "movntq";
					w = X86_WIDTH_MM;
					break;
				case X86_0F_66H:
					m = "movntdq";
					w = X86_WIDTH_XMM;
					break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, m);
				x86_modrm(p, X86_DIR_MEM, w, w);
			} else {
				switch (x86_0f_select(p)) {
				case X86_0F_66H: m = "cvttpd2dq"; break;
				case X86_0F_F2H: m = "cvtpd2dq"; break;
				case X86_0F_F3H: m = "cvtdq2pd"; break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, m);
				x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
			}
		} else {
			switch (x86_0f_select(p)) {
			case X86_0F_NONE: w = X86_WIDTH_MM; break;
			case X86_0F_66H: w = X86_WIDTH_XMM; break;
			default: disasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, wbit ? "pmulhw" : "pmulhuw");
			x86_modrm(p, X86_DIR_REG, w, w);
		}
		return;
	case 0b1110_1000: // E8H-EBH
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "psubsb"; break;
			case 1:  m = "psubsw"; break;
			case 2:  m = "pminsw"; break;
			default: m = "por"; break;
			}
			disasm_push_str(p, m);
		}
		x86_modrm(p, X86_DIR_REG, w, w);
		return;
	case 0b1110_1100: // ECH-EFH
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "paddsb"; break;
			case 1:  m = "paddsw"; break;
			case 2:  m = "pmaxsw"; break;
			default: m = "pxor"; break;
			}
			disasm_push_str(p, m);
		}
		x86_modrm(p, X86_DIR_REG, w, w);
		return;
	case 0b1111_0000: // F0H-F3H
		int w = void;
		if (dbit) {
			switch (x86_0f_select(p)) {
			case X86_0F_NONE: w = X86_WIDTH_MM; break;
			case X86_0F_66H: w = X86_WIDTH_XMM; break;
			default: disasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, wbit ? "psllq" : "psllq");
			x86_modrm(p, X86_DIR_REG, w, w);
		} else {
			const(char) *m = void;
			if (wbit) {
				switch (x86_0f_select(p)) {
				case X86_0F_NONE: w = X86_WIDTH_MM; break;
				case X86_0F_66H: w = X86_WIDTH_XMM; break;
				default: disasm_err(p); return;
				}
				m = "psllw";
			} else {
				switch (x86_0f_select(p)) {
				case X86_0F_F2H: w = X86_WIDTH_XMM; break;
				default: disasm_err(p); return;
				}
				m = "lldqu";
			}
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, m);
			x86_modrm(p, X86_DIR_REG, w, w);
		}
		return;
	case 0b1111_0100: // F4H-F7H
		if (dbit) {
			if (wbit) {
				ubyte modrm = *p.addru8;
				++p.addrv;
				if ((modrm & RM_MOD) != RM_MOD_11) {
					disasm_err(p);
					return;
				}
				int w = void;
				const(char) *m = void;
				switch (x86_0f_select(p)) {
				case X86_0F_NONE:
					m = "maskmovq";
					w = X86_WIDTH_MM;
					break;
				case X86_0F_66H:
					m = "maskmovdqu";
					w = X86_WIDTH_XMM;
					break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, m);
				x86_modrm(p, X86_DIR_REG, w, w);
			} else {
				int w = void;
				switch (x86_0f_select(p)) {
				case X86_0F_NONE: w = X86_WIDTH_MM; break;
				case X86_0F_66H: w = X86_WIDTH_XMM; break;
				default: disasm_err(p); return;
				}
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "psadbw");
				x86_modrm(p, X86_DIR_REG, w, w);
			}
		} else {
			int w = void;
			switch (x86_0f_select(p)) {
			case X86_0F_NONE: w = X86_WIDTH_MM; break;
			case X86_0F_66H: w = X86_WIDTH_XMM; break;
			default: disasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, wbit ? "pmaddwd" : "pmuludq");
			x86_modrm(p, X86_DIR_REG, w, w);
		}
		return;
	case 0b1111_1000: // F8H-FBH
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "psubb"; break;
			case 1:  m = "psubw"; break;
			case 2:  m = "psubd"; break;
			default: m = "psubq"; break;
			}
			disasm_push_str(p, m);
		}
		x86_modrm(p, X86_DIR_REG, w, w);
		return;
	case 0b1111_1100: // FCH-FFH
		// UD0 NOTE: Some older processors decode without ModR/M.
		// Instead, an opcode exception is thrown (instead of a fault).
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File) {
			const(char) *m = void;
			switch (b & 3) {
			case 0:  m = "paddb"; break;
			case 1:  m = "paddw"; break;
			case 2:  m = "paddd"; break;
			default:
				disasm_push_str(p, "ud0");
				return;
			}
			disasm_push_str(p, m);
		}
		x86_modrm(p, X86_DIR_REG, w, w);
		return;
	default: // ANCHOR End of instructions
		disasm_err(p);
	}
}

void x86_0f38(disasm_params_t *p) {
	ubyte b = *p.addru8;
	++p.addrv;

	if (p.mode >= DisasmMode.File)
		disasm_push_x8(p, b);

	int wbit = b & 1;
	int dbit = b & 2;
	switch (b & 252) { // 1111_1100
	case 0: // 00H-03H
		const(char) *m = void;
		if (dbit) {
			m = wbit ? "phaddsw" : "phaddd";
		} else {
			m = wbit ? "phaddw" : "pshufb";
		}
		int w = p.x86.pf_operand ? X86_WIDTH_XMM : X86_WIDTH_MM;
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_DIR_REG, w, w);
		return;
	case 0b0000_0100: // 04H-07H
		const(char) *m = void;
		if (dbit) {
			m = wbit ? "phsubsw" : "phsubd";
		} else {
			m = wbit ? "phsubw" : "pmaddubsw";
		}
		int w = p.x86.pf_operand ? X86_WIDTH_XMM : X86_WIDTH_MM;
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_DIR_REG, w, w);
		return;
	case 0b0000_1000: // 08H-0BH
		const(char) *m = void;
		if (dbit) {
			m = wbit ? "pmulhrsw" : "psignd";
		} else {
			m = wbit ? "psignw" : "psignb";
		}
		int w = p.x86.pf_operand ? X86_WIDTH_XMM : X86_WIDTH_MM;
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_DIR_REG, w, w);
		return;
	case 0b0001_0000: // 10H-13H
		if (dbit || wbit || p.x86.pf_operand == 0) {
			disasm_err(p);
			return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "pblendvb");
		x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
		return;
	case 0b0001_0100: // 14H-17H
		if (p.x86.pf_operand == 0) {
			disasm_err(p);
			return;
		}
		const(char) *m = void;
		if (dbit) {
			if (wbit) {
				m = "ptest";
			} else {
				disasm_err(p);
				return;
			}
		} else {
			m = wbit ? "blendvpd" : "blendvps";
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
		return;
	case 0b0001_1100: // 1CH-1FH
		const(char) *m = void;
		if (dbit) {
			if (wbit) {
				disasm_err(p);
				return;
			} else {
				m = "pabsd";
			}
		} else {
			m = wbit ? "pabsb" : "pabsw";
		}
		int w = p.x86.pf_operand ? X86_WIDTH_XMM : X86_WIDTH_MM;
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_DIR_REG, w, w);
		return;
	case 0b0010_0000: // 20H-23H
		if (p.x86.pf_operand == 0) {
			disasm_err(p);
			return;
		}
		const(char) *m = void;
		if (dbit) {
			m = wbit ? "pmovsxwd" : "pmovsxbq";
		} else {
			m = wbit ? "pmovsxbd" : "pmovsxbw";
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
		return;
	case 0b0010_0100: // 24H-27H
		if (p.x86.pf_operand == 0) {
			disasm_err(p);
			return;
		}
		if (dbit) {
			disasm_err(p);
			return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, wbit ? "pmovsxbd" : "pmovsxbw");
		x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
		return;
	case 0b0010_1000: // 28H-2BH
		if (p.x86.pf_operand == 0) {
			disasm_err(p);
			return;
		}
		const(char) *m = void;
		if (dbit) {
			m = wbit ? "packusdw" : "movntdqa";
		} else {
			m = wbit ? "pcmpeqq" : "pmuldq";
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
		return;
	case 0b0011_0000: // 30H-33H
		if (p.x86.pf_operand == 0) {
			disasm_err(p);
			return;
		}
		const(char) *m = void;
		if (dbit) {
			m = wbit ? "pmovzxwd" : "pmovzxbq";
		} else {
			m = wbit ? "pmovzxbd" : "pmovzxbw";
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
		return;
	case 0b0011_0100: // 34H-37H
		if (p.x86.pf_operand == 0) {
			disasm_err(p);
			return;
		}
		const(char) *m = void;
		if (dbit) {
			if (wbit) {
				m = "pcmpgtq";
			} else {
				disasm_err(p);
				return;
			}
		} else {
			m = wbit ? "pmovzxdq" : "pmovzxwq";
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
		return;
	case 0b0011_1000: // 38H-3BH
		if (p.x86.pf_operand == 0) {
			disasm_err(p);
			return;
		}
		const(char) *m = void;
		if (dbit) {
			m = wbit ? "pminud" : "pminuw";
		} else {
			m = wbit ? "pminsd" : "pminsb";
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
		return;
	case 0b0011_1100: // 3CH-3FH
		if (p.x86.pf_operand == 0) {
			disasm_err(p);
			return;
		}
		const(char) *m = void;
		if (dbit) {
			m = wbit ? "pmaxud" : "pmaxuw";
		} else {
			m = wbit ? "pmaxsd" : "pmaxsb";
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
		return;
	case 0b0100_0000: // 40H-43H
		if (dbit || p.x86.pf_operand == 0) {
			disasm_err(p);
			return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, wbit ? "phminposuw" : "pmulld");
		x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
		return;
	case 0b1000_0000: // 80H-83H
		if ((wbit && dbit) || p.x86.pf_operand == 0) {
			disasm_err(p);
			return;
		}
		const(char) *m = void;
		if (dbit) {
			m = "invpcid";
		} else {
			m = wbit ? "invvpid" : "invept";
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, wbit ? "phminposuw" : "pmulld");
		x86_modrm(p, X86_DIR_REG, X86_WIDTH_EXT, X86_WIDTH_EXT);
		return;
	case 0b1100_1000: // C8H-CBH
		const(char) *m = void;
		if (dbit) {
			m = wbit ? "sha256rnds2" : "sha1msg2";
		} else {
			m = wbit ? "sha1msg1" : "sha1nexte";
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
		return;
	case 0b1100_1100: // CCH-CFH
		if (dbit) {
			disasm_err(p);
			return;
		}
		const(char) *m = wbit ? "sha256msg2" : "sha256msg1";
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
		return;
	case 0b1101_1000: // D8H-DBH
		if (dbit && wbit && p.x86.pf_operand) {
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, "aesimc");
			x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
		} else {
			disasm_err(p);
		}
		return;
	case 0b1101_1100: // DBH-DFH
		if (p.x86.pf_operand == 0) {
			disasm_err(p);
			return;
		}
		const(char) *m = void;
		if (dbit) {
			m = wbit ? "aesdeclast" : "aesdec";
		} else {
			m = wbit ? "aesenclast" : "aesenc";
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_DIR_REG, X86_WIDTH_XMM, X86_WIDTH_XMM);
		return;
	case 0b1111_0000: // F0H-F3H
		if (dbit) { // Yep, GRP17 is all VEX stuff
			disasm_err(p);
			return;
		}
		const(char) *m = void;
		int wr = void, wm = void;
		int s = x86_0f_select(p);
		switch (s) {
		case X86_0F_NONE, X86_0F_66H:
			if ((*p.addru8 & RM_MOD) == RM_MOD_11) {
				disasm_err(p);
				return;
			}
			m = "movbe";
			dbit = !wbit;
			wr = wm = s == X86_0F_66H ?
				X86_WIDTH_WIDE : X86_WIDTH_EXT;
			break;
		case X86_0F_F2H, X86_0F_F266H:
			m = "crc32";
			dbit = X86_DIR_REG;
			wr = X86_WIDTH_EXT;
			if (wbit) {
				wm = s == X86_0F_66H ?
					X86_WIDTH_WIDE : X86_WIDTH_EXT;
			} else {
				wm = X86_WIDTH_BYTE;
			}
			break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, dbit, wm, wr);
		return;
	case 0b1111_0100: // F4H-F7H
		if (dbit) {
			if (wbit) {
				disasm_err(p);
				return;
			}
			const(char) *m = void;
			switch (x86_0f_select(p)) {
			case X86_0F_66H: m = "adcx"; break;
			case X86_0F_F3H: m = "adox"; break;
			default: disasm_err(p); return;
			}
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, m);
			x86_modrm(p, X86_DIR_REG, X86_WIDTH_EXT, X86_WIDTH_EXT);
		} else {
			disasm_err(p);
		}
		return;
	default: disasm_err(p); // ANCHOR End of 0f38
	}
}

void x86_0f3a(disasm_params_t *p) {
	ubyte b = *p.addru8;
	++p.addrv;

	if (p.mode >= DisasmMode.File)
		disasm_push_x8(p, b);

	int wbit = b & 1;
	int dbit = b & 2;
	switch (b & 252) { // 1111_1100
	case 0b0000_1000: // 08H-0BH
		if (p.x86.pf_operand == 0) {
			disasm_err(p);
			return;
		}
		p.x86.pf_operand = 0;
		const(char) *m = void;
		int wmem = void;
		if (dbit) {
			if (wbit) {
				m = "roundsd";
				wmem = X86_WIDTH_MM;
			} else {
				m = "roundss";
				wmem = X86_WIDTH_EXT;
			}
		} else {
			wmem = X86_WIDTH_XMM;
			m = wbit ? "roundpd" : "roundps";
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_DIR_REG, wmem, X86_WIDTH_XMM);
		x86_u8imm(p);
		return;
	case 0b0000_1100: // 0CH-0FH
		const(char) *m = void;
		int w = void;
		if (dbit) {
			if (wbit) {
				m = "palignr";
				w =  p.x86.pf_operand ? X86_WIDTH_XMM : X86_WIDTH_MM;
			} else {
				if (p.x86.pf_operand == 0) {
					disasm_err(p);
					return;
				}
				m = "pblendw";
				w = X86_WIDTH_XMM;
			}
		} else {
			if (p.x86.pf_operand == 0) {
				disasm_err(p);
				return;
			}
			w = X86_WIDTH_XMM;
			m = wbit ? "blendpd" : "blendps";
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_DIR_REG, w, w);
		x86_u8imm(p);
		return;
	case 0b0001_0100: // 14H-17H
		if (p.x86.pf_operand == 0) {
			disasm_err(p);
			return;
		}
		p.x86.pf_operand = 0;
		const(char) *m = void;
		int wmem = void;
		if (dbit) {
			m = wbit ? "extractps" : "pextrd";
			wmem = X86_WIDTH_EXT;
		} else {
			if (wbit) {
				m = "pextrw";
				wmem = X86_WIDTH_WIDE;
			} else {
				m = "pextrb";
				wmem = X86_WIDTH_BYTE;
			}
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_DIR_MEM, wmem, X86_WIDTH_XMM);
		x86_u8imm(p);
		return;
	case 0b0010_0000: // 20H-23H
		if ((dbit && wbit) || p.x86.pf_operand == 0) {
			disasm_err(p);
			return;
		}
		p.x86.pf_operand = 0;
		const(char) *m = void;
		int wmem = void;
		if (dbit) {
			m = "pinsrd";
			wmem = X86_WIDTH_EXT;
		} else {
			if (wbit) {
				m = "insertps";
				wmem = X86_WIDTH_EXT;
			} else {
				m = "pinsrb";
				wmem = X86_WIDTH_BYTE;
			}
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_DIR_REG, wmem, X86_WIDTH_XMM);
		x86_u8imm(p);
		return;
	default: disasm_err(p); // ANCHOR End of 0f3a
	}
}

enum x86SegReg {
	None, CS, DS, ES, FS, GS, SS
}

enum : ubyte {
	RM_MOD_00 =   0,	/// MOD 00, Memory Mode, no displacement
	RM_MOD_01 =  64,	/// MOD 01, Memory Mode, 8-bit displacement
	RM_MOD_10 = 128,	/// MOD 10, Memory Mode, 16-bit displacement
	RM_MOD_11 = 192,	/// MOD 11, Register Mode
	RM_MOD = RM_MOD_11,	/// Used for masking the MOD bits (11 000 000)

	RM_REG_000 =  0,	/// AL/AX
	RM_REG_001 =  8,	/// CL/CX
	RM_REG_010 = 16,	/// DL/DX
	RM_REG_011 = 24,	/// BL/BX
	RM_REG_100 = 32,	/// AH/SP
	RM_REG_101 = 40,	/// CH/BP
	RM_REG_110 = 48,	/// DH/SI
	RM_REG_111 = 56,	/// BH/DI
	RM_REG = RM_REG_111,	/// Used for masking the REG bits (00 111 000)

	RM_RM_000 = 0,	/// R/M 000 bits
	RM_RM_001 = 1,	/// R/M 001 bits
	RM_RM_010 = 2,	/// R/M 010 bits
	RM_RM_011 = 3,	/// R/M 011 bits
	RM_RM_100 = 4,	/// R/M 100 bits
	RM_RM_101 = 5,	/// R/M 101 bits
	RM_RM_110 = 6,	/// R/M 110 bits
	RM_RM_111 = 7,	/// R/M 111 bits
	RM_RM = RM_RM_111,	/// Used for masking the R/M bits (00 000 111)

	SIB_SCALE_00 = RM_MOD_00,	/// SCALE 00, *1
	SIB_SCALE_01 = RM_MOD_01,	/// SCALE 01, *2
	SIB_SCALE_10 = RM_MOD_10,	/// SCALE 10, *4
	SIB_SCALE_11 = RM_MOD_11,	/// SCALE 11, *8
	SIB_SCALE = SIB_SCALE_11,	/// Scale filter

	SIB_INDEX_000 = RM_REG_000,	/// INDEX 000, EAX
	SIB_INDEX_001 = RM_REG_001,	/// INDEX 001, ECX
	SIB_INDEX_010 = RM_REG_010,	/// INDEX 010, EDX
	SIB_INDEX_011 = RM_REG_011,	/// INDEX 011, EBX
	SIB_INDEX_100 = RM_REG_100,	/// INDEX 100, (special override)
	SIB_INDEX_101 = RM_REG_101,	/// INDEX 101, EBP
	SIB_INDEX_110 = RM_REG_110,	/// INDEX 110, ESI
	SIB_INDEX_111 = RM_REG_111,	/// INDEX 111, EDI
	SIB_INDEX = RM_REG,	/// Index filter

	SIB_BASE_000 = RM_RM_000,	/// BASE 000, EAX
	SIB_BASE_001 = RM_RM_001,	/// BASE 001, ECX
	SIB_BASE_010 = RM_RM_010,	/// BASE 010, EDX
	SIB_BASE_011 = RM_RM_011,	/// BASE 011, EBX
	SIB_BASE_100 = RM_RM_100,	/// BASE 100, ESP
	SIB_BASE_101 = RM_RM_101,	/// BASE 101, (special override)
	SIB_BASE_110 = RM_RM_110,	/// BASE 110, ESI
	SIB_BASE_111 = RM_RM_111,	/// BASE 111, EDI
	SIB_BASE = RM_RM,	/// Base filter
}

// Prefix combos for 0F
package enum {
	X86_0F_NONE,
	X86_0F_66H,
	X86_0F_F2H,
	X86_0F_F3H,
	X86_0F_F266H,
}

// ModR/M register width
package enum {
	X86_WIDTH_BYTE,	/// 8-bit registers (8086), BYTE PTR
	X86_WIDTH_EXT,	/// 32/64-bit extended registers (i386/amd64), DWORD PTR
	X86_WIDTH_WIDE,	/// 16-bit registers (8086), WORD PTR
	X86_WIDTH_MM,	/// 64-bit MM registers (MMX), QWORD PTR
	X86_WIDTH_XMM,	/// 128-bit XMM registers (SSE), OWORD PTR
	X86_WIDTH_YMM,	/// 256-bit YMM registers (AVX), YWORD PTR
	X86_WIDTH_ZMM,	/// 512-bit ZMM registers (AVX-512), ZWORD PTR
}
// ModR/M Direction
package enum {
	X86_DIR_MEM,	/// Destination: Memory, Source: REG
	X86_DIR_REG	/// Destination: REG, Source: Memory
}

/// (Internal) Function to determine if opcode has WIDE bit set
/// Params: op = Opcode
int X86_OP_WIDE(int op) { return op & 1; }
/// (Internal) Function to determine if opcode has DIRECTION bit set
/// Params: op = Opcode
int X86_OP_DIR(int op)  { return op & 2; }

void x86_u8imm(disasm_params_t *p) {
	if (p.mode >= DisasmMode.File) {
		disasm_push_x8(p, *p.addru8);
		disasm_push_imm(p, *p.addru8);
	}
	++p.addrv;
}

/// (Internal) Fetch variable 32-bit immediate, affected by operand prefix.
/// Then if it's the case, fetch and push a 16-bit immediate instead.
/// Modifies memory pointer.
/// Params: p = disassembler structure
void x86_u32imm(disasm_params_t *p) {
	if (p.x86.pf_operand) { // 16-bit
		if (p.mode >= DisasmMode.File) {
			disasm_push_x16(p, *p.addru16);
			disasm_push_imm(p, *p.addru16);
		}
		p.addrv += 2;
	} else { // Normal mode 32-bit
		if (p.mode >= DisasmMode.File) {
			disasm_push_x32(p, *p.addru32);
			disasm_push_imm(p, *p.addru32);
		}
		p.addrv += 4;
	}
}

/// (Internal) Fetch variable 16+16/32-bit as immediate, affected by address
/// prefix. Handles machine code and mnemonics, including the segment register.
/// Modifies memory pointer.
/// Params: p = disassembler structure
void x86_immmem(disasm_params_t *p) {
	const(char) *seg = x86_segstr(p.x86.segreg);
	if (p.x86.pf_address) { // 16-bit
		if (p.mode >= DisasmMode.File) {
			disasm_push_x16(p, *p.addru16);
			disasm_push_memregimm(p, seg, *p.addru16);
		}
		p.addrv += 2;
	} else { // Normal mode 32-bit
		if (p.mode >= DisasmMode.File) {
			disasm_push_x32(p, *p.addru32);
			disasm_push_memregimm(p, seg, *p.addru32);
		}
		p.addrv += 4;
	}
}

/// (Internal) Returns a number depending on the set prefixes for the 2-byte
/// instructions (0FH). Useful for a switch per-instruction. Does not check
/// for errors. Unconfirmed with the official order it's supposed to have.
///
/// Enumeration mapping
/// X86_0F_NONE  (0): No prefixes
/// X86_0F_66H   (1): 66H
/// X86_0F_F2H   (2): F2H
/// X86_0F_F3H   (3): F3H
/// X86_0F_F266H (4): 66H+F2H
///
/// Params: p = Disassembler parameters
///
/// Returns: Selection number (see Enumeration mapping)
package
int x86_0f_select(disasm_params_t *p) {
	switch (p.x86.last_prefix) {
	case 0xF2: return p.x86.pf_operand ? X86_0F_F266H : X86_0F_F2H;
	case 0xF3: return X86_0F_F3H;
	default:   return p.x86.pf_operand ? X86_0F_66H : X86_0F_NONE;
	}
}

/// (Internal) Return a segment register depending on its opcode.
/// Returns an empty string if unset.
/// Params: segreg = Byte opcode
/// Returns: Segment register string
const(char) *x86_segstr(int segreg) {
	const(char) *s = void;
	with (x86SegReg)
	switch (segreg) {
	case CS: s = "cs:"; break;
	case DS: s = "ds:"; break;
	case ES: s = "es:"; break;
	case FS: s = "fs:"; break;
	case GS: s = "gs:"; break;
	case SS: s = "ss:"; break;
	default: s = ""; break;
	}
	return s;
}

const(char) *x87_ststr(disasm_params_t *p, int index) {
	const(char) *st = void;
	with (DisasmSyntax)
	switch (p.style) {
	case Att:
		switch (index) {
		case 0: st = "%st"; break;
		case 1: st = "%st(1)"; break;
		case 2: st = "%st(2)"; break;
		case 3: st = "%st(3)"; break;
		case 4: st = "%st(4)"; break;
		case 5: st = "%st(5)"; break;
		case 6: st = "%st(6)"; break;
		case 7: st = "%st(7)"; break;
		default: st = "%st(?)";
		}
		break;
	case Nasm:
		switch (index) {
		case 0: st = "st0"; break;
		case 1: st = "st1"; break;
		case 2: st = "st2"; break;
		case 3: st = "st3"; break;
		case 4: st = "st4"; break;
		case 5: st = "st5"; break;
		case 6: st = "st6"; break;
		case 7: st = "st7"; break;
		default: st = "st?";
		}
		break;
	default:
		switch (index) {
		case 0: st = "st"; break;
		case 1: st = "st(1)"; break;
		case 2: st = "st(2)"; break;
		case 3: st = "st(3)"; break;
		case 4: st = "st(4)"; break;
		case 5: st = "st(5)"; break;
		case 6: st = "st(6)"; break;
		case 7: st = "st(7)"; break;
		default: st = "st(?)";
		}
	}
	return st;
}

/// (Internal) Process a ModR/M byte automatically.
///
/// This function calls x86_modrm_rm and disasm_push_reg depending on the
/// direction flag. If non-zero (X86_DIR_REG), the reg field is processed
/// first; Otherwise vice versa (X86_DIR_MEM).
///
/// Params:
/// 	p = Disassembler parameters
/// 	direction = If set, the registers are the target
/// 	wmem = Memory operation width, see X86_WIDTH_* enumerations
/// 	wreg = Register width, see X86_WIDTH_* enumerations
void x86_modrm(disasm_params_t *p, int direction, int wmem, int wreg) {
	// 11 111 111
	// || ||| +++- RM
	// || +++----- REG
	// ++--------- MODE
	ubyte modrm = *p.addru8;
	++p.addrv;

	if (direction) goto L_REG;

L_RM:
	// Memory regs are only general registers
	x86_modrm_rm(p, modrm, wmem);
	if (direction) return;

L_REG:
	if (p.mode >= DisasmMode.File)
		disasm_push_reg(p, x86_modrm_reg(p, modrm, wreg));
	if (direction) goto L_RM;
}

/// (Internal) Retrieve a register name from a ModR/M byte (REG field) and a
/// specified width. This function conditionally honors the operand prefix
/// (66H) when the width is X86_WIDTH_EXT.
/// Params:
/// 	p = Disassembler parameters
/// 	modrm = ModR/M byte
/// 	width = Register width (byte, wide, mm, xmm, etc.)
/// Returns: Register string or null if out of bound
const(char) *x86_modrm_reg(disasm_params_t *p, int modrm, int width) {
	// This is asking for trouble, hopefully more checks will be added later
	// The array has this order for X86_OP_WIDE
	// NOTE: ModR/M extension is x86-64 only! (REX)
	__gshared const(char) *[][]x86_regs = [
		[ "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh" ],	// BYTE
		[ "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" ],	// EXT
		[ "ax", "cx", "dx", "cx", "sp", "bp", "si", "di" ],	// WIDE
		[ "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7" ],	// MM
		[ "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7" ],	// XMM
		[ "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7" ],	// YMM
		[ "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7" ],	// ZMM
	];
	if (width > 6) return null;
	size_t i = (modrm & RM_REG) >> 3;
	if (i > 7) return null;

	if (width == X86_WIDTH_EXT && p.x86.pf_operand)
		width = X86_WIDTH_WIDE;

	return x86_regs[width][i];
}

/// (Internal) Retrieve a register name from a ModR/M byte (RM field) and
/// conditionally returns the 16-bit addressing 
/// Params:
/// 	p = Disassembler parameters
/// 	modrm = ModR/M byte
/// Returns: Register string
const(char) *x86_modrm_rm_reg(int modrm, int addrpf) {
	// This is asking for trouble, hopefully more checks will be added later
	__gshared const(char) *[][]x86_regs = [
		[ "bx+si", "bx+di", "bp+si", "bi+di", "si", "di", "bp", "bx" ],
		[ "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" ],
	];
	size_t i = modrm & RM_RM;
	if (i > 7) return null;
	size_t pf = !addrpf;
	return x86_regs[pf][i];
}

/// (Internal) Process the R/M field automatically
///
/// Params:
/// 	p = Disasm params
/// 	modrm = Modrm byte
/// 	width = Register width
void x86_modrm_rm(disasm_params_t *p, ubyte modrm, int width) {
	if (p.mode >= DisasmMode.File)
		disasm_push_x8(p, modrm);

	int mode = modrm & RM_MOD;
	int rm   = modrm & RM_RM;

	//
	// ModR/M Mode
	//

	const(char) *seg = x86_segstr(p.x86.segreg);
	const(char) *reg = void;

	switch (mode) {
	case RM_MOD_00:	// Memory Mode, no displacement
		if (p.x86.pf_address) {
			if (rm == RM_RM_110) {
				ushort m = *p.addru16;
				p.addrv += 2;
				if (p.mode >= DisasmMode.File)
					disasm_push_memregimm(p, seg, m);
			} else {
				if (p.mode >= DisasmMode.File) {
					reg = x86_modrm_rm_reg(modrm, p.x86.pf_address);
					disasm_push_memsegreg(p, seg, reg);
				}
			}
		} else {
			if (rm == RM_RM_100) {
				x86_sib(p, modrm);
				return;
			}
			reg = x86_modrm_rm_reg(modrm, p.x86.pf_address);
			if (rm == RM_RM_101) {
				uint m = *p.addru32;
				p.addrv += 4;
				if (p.mode >= DisasmMode.File)
					disasm_push_memregimm(p, reg, m);
			} else {
				if (p.mode >= DisasmMode.File)
					disasm_push_memsegreg(p, seg, reg);
			}
		}
		break;
	case RM_MOD_01:	// Memory Mode, 8-bit displacement
		if (rm == RM_RM_100) {
			x86_sib(p, modrm);
			return;
		}
		if (p.mode >= DisasmMode.File) {
			disasm_push_x8(p, *p.addru8);
			reg = x86_modrm_rm_reg(modrm, p.x86.pf_address);
			disasm_push_memsegregimm(p, seg, reg, *p.addru8);
		}
		++p.addrv;
		break;
	case RM_MOD_10:	// Memory Mode, 32-bit displacement
		uint m = void;
		if (p.x86.pf_address) {
			m = *p.addru16;
			p.addrv += 2;
			disasm_push_x16(p, cast(ushort)m);
		} else {
			if (rm == RM_RM_100) {
				x86_sib(p, modrm);
				return;
			}
			m = *p.addru32;
			p.addrv += 4;
			disasm_push_x32(p, m);
		}
		if (p.mode >= DisasmMode.File) {
			reg = x86_modrm_rm_reg(modrm, p.x86.pf_address);
			disasm_push_memsegregimm(p, seg, reg, m);
		}
		p.addrv += 4;
		break;
	default:
		if (p.mode >= DisasmMode.File)
			disasm_push_reg(p, x86_modrm_reg(p, modrm << 3, width));
		break;
	}
}

// Process SIB, ignores address prefix
void x86_sib(disasm_params_t *p, ubyte modrm) {
	// 11 111 111
	// || ||| +++- BASE
	// || +++----- INDEX
	// ++--------- SCALE
	ubyte sib = *p.addru8;
	++p.addrv;
	int scale = 1 << (sib >> 6); // 2 ^ (0b11_000_000 >> 6)
	int index = sib & SIB_INDEX;
	int base  = sib & SIB_BASE;

	const(char)* rbase = void, rindex = void, seg = void;

	if (p.mode >= DisasmMode.File) {
		disasm_push_x8(p, sib);
		seg = x86_segstr(p.x86.segreg);
	}

	switch (modrm & RM_MOD) { // Mode
	case RM_MOD_00:
		if (base == SIB_BASE_101) { // INDEX * SCALE + D32
			if (p.mode >= DisasmMode.File) {
				disasm_push_x32(p, *p.addru32);
				if (index == SIB_INDEX_100)
					disasm_push_x86_sib_mod00_index100_base101(p,
						seg, *p.addru32);
				else
					disasm_push_x86_sib_mod00_base101(p, seg,
						x86_modrm_rm_reg(sib, false),
						scale, *p.addru32);
			}
			p.addrv += 4;
		} else { // BASE32 + INDEX * SCALE
			if (p.mode < DisasmMode.File) return;
			rbase = x86_modrm_rm_reg(sib, false);
			if (index == SIB_INDEX_100)
				disasm_push_x86_sib_mod00_index100(p, seg, rbase);
			else
				disasm_push_x86_sib_mod00(p, seg, rbase,
					x86_modrm_rm_reg(sib, false),
					scale);
		}
		return;
	case RM_MOD_01:
		if (index == SIB_INDEX_100) { // B32 + D8
			if (p.mode >= DisasmMode.File) {
				disasm_push_x8(p, *p.addru8);
				disasm_push_x86_sib_mod01_index100(p,
					seg,
					x86_modrm_rm_reg(sib, false),
					*p.addru8);
			}
			++p.addrv;
		} else { // BASE8 + INDEX * SCALE + DISP32
			if (p.mode >= DisasmMode.File) {
				disasm_push_x32(p, *p.addru32);
				rbase = x86_modrm_rm_reg(sib, false);
				rindex = x86_modrm_rm_reg(sib >> 3, false);
				disasm_push_x86_sib_mod01(p,
					seg, rbase, rindex, scale, *p.addru32);
			}
			p.addrv += 4;
		}
		break;
	default:
		if (p.mode >= DisasmMode.File) {
			disasm_push_x32(p, *p.addru32);
			rbase = x86_modrm_rm_reg(sib, false);
			if ((sib & SIB_INDEX) == SIB_INDEX_100) { // BASE32 + DISP32
				disasm_push_x86_sib_mod01_index100(p,
				seg, rbase, *p.addru32);
			} else { // BASE32 + INDEX * SCALE + DISP32
				rindex = x86_modrm_rm_reg(sib >> 3, false);
				disasm_push_x86_sib_mod01(p,
					seg, rbase, rindex, scale, *p.addru32);
			}
		}
		p.addrv += 4;
		break;
	}
}
