/**
 * x86 disassembler.
 *
 * License: BSD 3-Clause
 */
module debugger.disasm.arch.x86;

import debugger.disasm.core;
import debugger.disasm.formatter;
import utils.str;

extern (C):

package
struct x86_internals_t {
	int lock;
	int repz;	// (F3h) REP/REPE/REPZ
	int repnz;	// (F2h) REPNE/REPNZ/BND
	int last_prefix;	// Last effective prefix for 0f (f2/f3)
	int segreg;
	int pf_operand; /// 66H Operand prefix
	int pf_address; /// 67H Address prefix
	/// VEX prefix
	int vex; //TODO: x86-32 VEX
}

/**
 * x86 disassembler.
 * Params:
 * 	p = Disassembler parameters
 * 	init = Initiate structure (x86_16 sets this to false)
 */
void disasm_x86(ref disasm_params_t p, bool init = true) {
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
	case 0:
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "add");
		x86_modrm(p, wbit, dbit);
		return;
	case 0b0000_0100:
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
	case 0b0000_1000:
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "or");
		x86_modrm(p, wbit, dbit);
		return;
	case 0b0000_1100:
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
	case 0b0001_0000:
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "adc");
		x86_modrm(p, wbit, dbit);
		return;
	case 0b0001_0100:
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
	case 0b0001_1000:
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "sbb");
		x86_modrm(p, wbit, dbit);
		return;
	case 0b0001_1100:
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
	case 0b0010_0000:
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "and");
		x86_modrm(p, wbit, dbit);
		return;
	case 0b0010_0100:
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
	case 0b0010_1000:
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "sub");
		x86_modrm(p, X86_OP_WIDE(b), X86_OP_DIR(b));
		return;
	case 0b0010_1100:
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
	case 0b0011_0000:
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "xor");
		x86_modrm(p, X86_OP_WIDE(b), X86_OP_DIR(b));
		return;
	case 0b0011_0100:
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
	case 0b0011_1000:
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "cmp");
		x86_modrm(p, X86_OP_WIDE(b), X86_OP_DIR(b));
		return;
	case 0b0011_1100:
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
	case 0b0100_0000:
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
	case 0b0100_0100:
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
	case 0b0100_1000:
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
	case 0b0100_1100:
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
	case 0b0101_0000:
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
	case 0b0101_0100:
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
	case 0b0101_1000:
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
	case 0b0101_1100:
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
	case 0b0110_0000:
		if (dbit) {
			if (wbit) {
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "arpl");
				x86_modrm(p, X86_WIDTH_BYTE, X86_DIR_REG);
			} else {
				if ((*p.addru8 & RM_MOD) == RM_MOD_11) {
					disasm_err(p);
					return;
				}
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "bound");
				x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
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
	case 0b0110_0100:
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
	case 0b0110_1000:
		if (dbit) {
			if (wbit) { // IMUL REG32, R/M32, IMM8
				if (p.mode >= DisasmMode.File)
					disasm_push_str(p, "imul");
				x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
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
				x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
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
	case 0b0110_1100:
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
	case 0b0111_0000:
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
	case 0b0111_0100:
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
	case 0b0111_1000:
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
	case 0b0111_1100:
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
	case 0b1000_0000:
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
	case 0b1000_0100: // XCHG RM8/32, REG8/32 / TEST RM8/32, REG8/32
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, dbit ? "xchg" : "test");
		x86_modrm(p, wbit, X86_DIR_MEM);
		return;
	case 0b1000_1000:
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "mov");
		x86_modrm(p, wbit, dbit);
		return;
	case 0b1000_1100:
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
				x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
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
	case 0b1001_0000:
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
	case 0b1001_0100:
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
	case 0b1001_1000:
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
	case 0b1001_1100:
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
	case 0b1010_0000:
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
	case 0b1010_0100:
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
	case 0b1010_1000:
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
	case 0b1010_1100:
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
	case 0b1011_0000:
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
	case 0b1011_0100:
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
	case 0b1011_1000:
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
	case 0b1011_1100:
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
	case 0b1100_0000:
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
	case 0b1100_0100:
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
		} else {
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, wbit ? "lds" : "les");
			x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		}
		return;
	case 0b1100_1000:
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
	case 0b1100_1100:
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
	case 0b1101_0000:
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
	case 0b1101_0100:
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
	case 0b1101_1000: // ESCAPE D8-DB
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
	case 0b1101_1100: // ESCAPE DC-DF
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
	case 0b1110_0000:
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
	case 0b1110_0100:
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
	case 0b1110_1000:
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
	case 0b1110_1100:
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
	case 0b1111_0000:
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
	case 0b1111_0100:
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
	case 0b1111_1000:
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
	default: // ANCHOR Last case
		if (dbit) {
			ubyte modrm = *p.addru8;
			++p.addrv;
			const(char) *m = void;
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

void x86_0f(ref disasm_params_t p) {
	ubyte b = *p.addru8;
	++p.addrv;

	if (p.mode >= DisasmMode.File)
		disasm_push_x8(p, b);

	switch (b) {
	case 0x00: // GRP6
		ubyte modrm = *p.addru8;
		++p.addrv;

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
		return;
	case 0x01: // GRP7
		ubyte modrm = *p.addru8;
		ubyte mod11 = (modrm & RM_MOD) == RM_MOD_11;
		++p.addrv;

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
		default:
			disasm_err(p);
		}
		return;
	case 0x02: // LAR REG32, R/M16
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "lar");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0x03: // LSL REG32, R/M16
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "lsl");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0x06: // CLTS
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "clts");
		return;
	case 0x08: // INVD
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "invd");
		return;
	case 0x09: // WBINVD
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "wbinvd");
		return;
	case 0x0B: // UD2
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "ud2");
		return;
	case 0x0D: // PREFETCHW /1
		ubyte modrm = *p.addru8;
		++p.addrv;
		if ((modrm & RM_REG) == RM_REG_001) {
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, "prefetchw");
			x86_modrm_rm(p, modrm, X86_WIDTH_EXT);
		} else
			disasm_err(p);
		return;
	case 0x10, 0x11: // MOVUPS/MOVUPD/MOVSS/MOVSD
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
		x86_modrm(p, X86_WIDTH_XMM, X86_OP_DIR(b));
		return;
	case 0x12: // (MOVLPS|MOVHLPS)/MOVSLDUP/MOVLPD/MOVDDUP
		const(char) *m = void;
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
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0x13: // MOVLPS/MOVLPD
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "movlps"; break;
		case X86_0F_66H: m = "movlpd"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_MEM);
		return;
	case 0x14: // UNPCKLPS/UNPCKLPD
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "unpcklpd"; break;
		case X86_0F_66H: m = "unpcklpd"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0x15: // UNPCKHPS/UNPCKHPD
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "unpckhps"; break;
		case X86_0F_66H: m = "unpckhpd"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0x16: // (MOVHPS|MOVLHPS)/MOVHPD/MOVSHDUP
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE:
			m = (*p.addru8 & RM_MOD) == RM_MOD_11 ?
				"movlhps" : "movhps";
			break;
		case X86_0F_66H: m = "movhpd"; break;
		case X86_0F_F3H: m = "movshdup"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0x17: // MOVHPS/MOVHPD
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "movhps"; break;
		case X86_0F_66H: m = "movhpd"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_MEM);
		return;
	case 0x18: // GRP 16
		ubyte modrm = *p.addru8;
		++p.addrv;

		if ((modrm & RM_MOD) == RM_MOD_11) {
			disasm_err(p);
			return;
		}

		const(char) *m = void;
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
		return;
	case 0x1A: // BNDLDX/BNDMOV/BNDCU/BNDCL
		const(char) *m = void; // instruction
		const(char) *r = void; // bound keyword (bnd0..bnd3)
		ubyte modrm = *p.addru8;
		++p.addrv;
		switch (modrm & RM_REG) {
		case RM_REG_000: r = "bnd0"; break;
		case RM_REG_001: r = "bnd1"; break;
		case RM_REG_010: r = "bnd2"; break;
		case RM_REG_011: r = "bnd3"; break;
		default: disasm_err(p); return;
		}
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "bndldx"; break;
		case X86_0F_66H: m = "bndmov"; break;
		case X86_0F_F2H: m = "bndcu"; break;
		case X86_0F_F3H: m = "bndcl"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File) {
			disasm_push_str(p, m);
			disasm_push_reg(p, r);
		}
		x86_modrm_rm(p, modrm, X86_WIDTH_EXT);
		return;
	case 0x1B: // BNDSTX/BNDMOV/BNDCN/BNDMK
		const(char) *m = void; // instruction
		const(char) *r = void; // bound keyword (bnd0..bnd3)
		ubyte modrm = *p.addru8;
		++p.addrv;
		switch (modrm & RM_REG) {
		case RM_REG_000: r = "bnd0"; break;
		case RM_REG_001: r = "bnd1"; break;
		case RM_REG_010: r = "bnd2"; break;
		case RM_REG_011: r = "bnd3"; break;
		default: disasm_err(p); return;
		}
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
			disasm_push_reg(p, r);
		return;
	case 0x1F: // Multi-byte NOP
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "nop");
		x86_modrm_rm(p, modrm, X86_WIDTH_EXT);
		return;
	case 0x20: // MOV REG, CR
	case 0x22: // MOV CR, REG
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File)
			disasm_push_x8(p, modrm);
		if ((modrm & RM_MOD) != RM_MOD_11) {
			disasm_err(p);
			return;
		}
		if (p.mode >= DisasmMode.File) {
			const(char) *reg = x86_modrm_reg(p, modrm << 3, X86_WIDTH_EXT);
			const(char) *cr = void;
			if (p.x86.lock)
				switch (modrm & RM_REG) {
				case RM_REG_000: cr = "cr8"; break;
				case RM_REG_001: cr = "cr9"; break;
				case RM_REG_010: cr = "cr10"; break;
				case RM_REG_011: cr = "cr11"; break;
				case RM_REG_100: cr = "cr12"; break;
				case RM_REG_101: cr = "cr13"; break;
				case RM_REG_110: cr = "cr14"; break;
				case RM_REG_111: cr = "cr15"; break;
				default: // never
				}
			else
				switch (modrm & RM_REG) {
				case RM_REG_000: cr = "cr0"; break;
				case RM_REG_001: cr = "cr1"; break;
				case RM_REG_010: cr = "cr2"; break;
				case RM_REG_011: cr = "cr3"; break;
				case RM_REG_100: cr = "cr4"; break;
				case RM_REG_101: cr = "cr5"; break;
				case RM_REG_110: cr = "cr6"; break;
				case RM_REG_111: cr = "cr7"; break;
				default: // never
				}
			disasm_push_str(p, "mov");
			if (X86_OP_DIR(b)) {
				disasm_push_reg(p, cr);
				disasm_push_reg(p, reg);
			} else {
				disasm_push_reg(p, reg);
				disasm_push_reg(p, cr);
			}
		}
		return;
	case 0x21: // MOV REG, DR
	case 0x23: // MOV DR, REG
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File)
			disasm_push_x8(p, modrm);
		if ((modrm & RM_MOD) != RM_MOD_11) {
			disasm_err(p);
			return;
		}
		if (p.mode >= DisasmMode.File) {
			const(char) *reg = x86_modrm_reg(p, modrm << 3, X86_WIDTH_EXT);
			const(char) *dr = void;
			switch (modrm & RM_REG) {
			case RM_REG_000: dr = "dr0"; break;
			case RM_REG_001: dr = "dr1"; break;
			case RM_REG_010: dr = "dr2"; break;
			case RM_REG_011: dr = "dr3"; break;
			case RM_REG_100: dr = "dr4"; break;
			case RM_REG_101: dr = "dr5"; break;
			case RM_REG_110: dr = "dr6"; break;
			case RM_REG_111: dr = "dr7"; break;
			default: // never
			}
			disasm_push_str(p, "mov");
			if (X86_OP_DIR(b)) {
				disasm_push_reg(p, dr);
				disasm_push_reg(p, reg);
			} else {
				disasm_push_reg(p, reg);
				disasm_push_reg(p, dr);
			}
		}
		return;
	case 0x28: // MOVAPS/MOVAPD XMM, R/M
	case 0x29: // MOVAPS/MOVAPD R/M, XMM
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "movaps"; break;
		case X86_0F_66H: m = "movapd"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_OP_DIR(b));
		return;
	case 0x2A: // CVTPI2PS/CVTPI2PD/CVTSI2SD/CVTSI2SS REG, R/M
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "cvtpi2ps"; break;
		case X86_0F_66H: m = "cvtpi2pd"; break;
		case X86_0F_F2H: m = "cvtsi2sd"; break;
		case X86_0F_F3H: m = "cvtsi2ss"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0x2B: // MOVNTPS/MOVNTPD R/M, REG
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "movntps"; break;
		case X86_0F_66H: m = "movntpd"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_MEM);
		return;
	case 0x2C: // CVTTPS2PI/CVTTPD2PI/CVTTSD2SI/CVTTSS2SI
		ubyte modrm = *p.addru8;
		++p.addr;
		const(char) *m = void;
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE:
			m = "cvttps2pi";
			w = X86_WIDTH_MM;
			break;
		case X86_0F_66H:
			m = "cvttpd2pi";
			w = X86_WIDTH_MM;
			break;
		case X86_0F_F2H:
			m = "cvttsd2si";
			w = X86_WIDTH_EXT;
			break;
		case X86_0F_F3H:
			m = "cvttss2si";
			w = X86_WIDTH_EXT;
			break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File) {
			disasm_push_str(p, m);
			disasm_push_reg(p, x86_modrm_reg(p, modrm, w));
		}
		x86_modrm_rm(p, modrm, X86_WIDTH_XMM);
		return;
	case 0x2D: // CVTPS2PI/CVTPD2PI/CVTSD2SI/CVTSS2SI
		ubyte modrm = *p.addru8;
		++p.addr;
		const(char) *m = void;
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE:
			m = "cvtps2pi";
			w = X86_WIDTH_MM;
			break;
		case X86_0F_66H:
			m = "cvtpd2pi";
			w = X86_WIDTH_MM;
			break;
		case X86_0F_F2H:
			m = "cvtsd2si";
			w = X86_WIDTH_EXT;
			break;
		case X86_0F_F3H:
			m = "cvtss2si";
			w = X86_WIDTH_EXT;
			break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File) {
			disasm_push_str(p, m);
			disasm_push_reg(p, x86_modrm_reg(p, modrm, w));
		}
		x86_modrm_rm(p, modrm, X86_WIDTH_XMM);
		return;
	case 0x2E: // UCOMISS/UCOMISD
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "ucomiss"; break;
		case X86_0F_66H: m = "ucomisd"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0x2F: // COMISS/COMISD
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "comiss"; break;
		case X86_0F_66H: m = "comisd"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0x30: // WRMSR
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "wrmsr");
		return;
	case 0x31: // RDTSC
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "rdtsc");
		return;
	case 0x32: // RDMSR
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "rdmsr");
		return;
	case 0x33: // RDPMC
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "rdpmc");
		return;
	case 0x34: // SYSENTER
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "sysenter");
		return;
	case 0x35: // SYSEXIT
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "sysexit");
		return;
	case 0x37: // GETSEC
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "getsec");
		return;
	case 0x38: // 3-byte opcode
		x86_0f38(p);
		return;
	case 0x3A: // 3-byte-opcode
		x86_0f3a(p);
		return;
	case 0x40: // CMOVO
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "cmovo");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0x41: // CMOVNO
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "cmovno");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0x42: // CMOVB
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "cmovb");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0x43: // CMOVAE
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "cmovae");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0x44: // CMOVE
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "cmove");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0x45: // CMOVNE
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "cmovne");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0x46: // CMOVBE
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "cmovbe");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0x47: // CMOVA
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "cmova");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0x48: // CMOVS
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "cmovs");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0x49: // CMOVNS
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "cmovns");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0x4A: // CMOVP
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "cmovp");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0x4B: // CMOVNP
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "cmovnp");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0x4C: // CMOVL
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "cmovl");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0x4D: // CMOVNL
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "cmovnl");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0x4E: // CMOVLE
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "cmovle");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0x4F: // CMOVNLE
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "cmovnle");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0x50: // MOVMSKPS/MOVMSKPD
		const(char) *m = void;
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
		return;
	case 0x51: // SQRTPS/SQRTPD/SQRTSD/SQRTSS
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "sqrtps"; break;
		case X86_0F_66H: m = "sqrtpd"; break;
		case X86_0F_F2H: m = "sqrtsd"; break;
		case X86_0F_F3H: m = "sqrtss"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0x52: // RSQRTPS/RSQRTSS
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "rsqrtps"; break;
		case X86_0F_F3H: m = "rsqrtss"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0x53: // RCPPS/RCPSS
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "rcpps"; break;
		case X86_0F_F3H: m = "rcpss"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0x54: // ANDPS/ANDPD
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "andps"; break;
		case X86_0F_66H: m = "andpd"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0x55: // ANDNPS/ANDNPD
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "andnps"; break;
		case X86_0F_66H: m = "andnpd"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0x56: // ORPS/ORPD
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "orps"; break;
		case X86_0F_66H: m = "orpd"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0x57: // XORPS/XORPD
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "xorps"; break;
		case X86_0F_66H: m = "xorpd"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0x58: // ADDPS/ADDPD/ADDSD/ADDSS
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "addps"; break;
		case X86_0F_66H: m = "addpd"; break;
		case X86_0F_F2H: m = "addsd"; break;
		case X86_0F_F3H: m = "addss"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0x59: // MULPS/MULPD/MULSD/MULSS
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "mulps"; break;
		case X86_0F_66H: m = "mulpd"; break;
		case X86_0F_F2H: m = "mulsd"; break;
		case X86_0F_F3H: m = "mulss"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0x5A: // CVTPS2PD/CVTPD2PS/CVTSD2SS/CVTSS2SD
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "cvtps2pd"; break;
		case X86_0F_66H: m = "cvtpd2ps"; break;
		case X86_0F_F2H: m = "cvtsd2ss"; break;
		case X86_0F_F3H: m = "cvtss2sd"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0x5B: // CVTDQ2PS/CVTPS2DQ/CVTTPS2DQ
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "cvtdq2ps"; break;
		case X86_0F_66H: m = "cvtps2dq"; break;
		case X86_0F_F3H: m = "cvttps2dq"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0x5C: // SUBPS/SUBPD/SUBSD/SUBSS
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "subps"; break;
		case X86_0F_66H: m = "subpd"; break;
		case X86_0F_F2H: m = "subsd"; break;
		case X86_0F_F3H: m = "subss"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0x5D: // MINPS/MINPD/MINSD/MINSS
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "minps"; break;
		case X86_0F_66H: m = "minpd"; break;
		case X86_0F_F2H: m = "minsd"; break;
		case X86_0F_F3H: m = "minss"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0x5E: // DIVPS/DIVPD/DIVSD/DIVSS
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "divps"; break;
		case X86_0F_66H: m = "divpd"; break;
		case X86_0F_F2H: m = "divsd"; break;
		case X86_0F_F3H: m = "divss"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0x5F: // MAXPS/MAXPD/MAXSS/MAXSD
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "maxps"; break;
		case X86_0F_66H: m = "maxpd"; break;
		case X86_0F_F2H: m = "maxss"; break;
		case X86_0F_F3H: m = "maxsd"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0x60: // PUNPCKLBW
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "punpcklbw");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0x61: // PUNPCKLWD
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "punpcklwd");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0x62: // PUNPCKLDQ
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "punpckldq");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0x63: // PACKSSWB
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "packsswb");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0x64: // PCMPGTB
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "pcmpgtb");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0x65: // PCMPGTW
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "pcmpgtw");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0x66: // PCMPGTD
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "pcmpgtd");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0x67: // PACKUSWB
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "packuswb");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0x68: // PUNPCKHBW
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "punpckhbw");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0x69: // PUNPCKHWD
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "punpckhwd");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0x6A: // PUNPCKHDQ
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "punpckhdq");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0x6B: // PACKSSDW
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "packssdw");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0x6C: // PUNPCKLQDQ
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "punpcklqdq");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0x6D: // PUNPCKHQDQ
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "punpckhqdq");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0x6E: // MOVD
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "movd");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0x6F: // MOVQ/MOVDQA/MOVDQU
		const(char) *m = void;
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
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0x70: // PSHUFW/PSHUFD/PSHUFLW/PSHUFHW
		const(char) *m = void;
		int w = void;
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
		ubyte modrm = *p.addru8;
		++p.addrv;
		if ((modrm & RM_MOD) != RM_MOD_11) {
			disasm_err(p);
			return;
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
		return;
	case 0x71: // GRP12
		ubyte modrm = *p.addru8;
		if ((modrm & RM_MOD) != RM_MOD_11) {
			disasm_err(p);
			return;
		}
		const(char) *m = void;
		int w = void;
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
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0x72: // GRP13
		ubyte modrm = *p.addru8;
		if ((modrm & RM_MOD) != RM_MOD_11) {
			disasm_err(p);
			return;
		}
		const(char) *m = void;
		int w = void;
		switch (modrm & RM_REG) {
		case RM_REG_010:
			m = "psrld";
			switch (x86_0f_select(p)) {
			case X86_0F_NONE: w = X86_WIDTH_MM; break;
			case X86_0F_66H: w = X86_WIDTH_XMM; break;
			default: disasm_err(p); return;
			}
			break;
		case RM_REG_100:
			m = "psrad";
			switch (x86_0f_select(p)) {
			case X86_0F_NONE: w = X86_WIDTH_MM; break;
			case X86_0F_66H: w = X86_WIDTH_XMM; break;
			default: disasm_err(p); return;
			}
			break;
		case RM_REG_110:
			m = "pslld";
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
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0x73: // GRP14
		ubyte modrm = *p.addru8;
		if ((modrm & RM_MOD) != RM_MOD_11) {
			disasm_err(p);
			break;
		}
		const(char) *m = void;
		int w = void;
		switch (modrm & RM_REG) {
		case RM_REG_010:
			m = "psrlq";
			switch (x86_0f_select(p)) {
			case X86_0F_NONE: w = X86_WIDTH_MM; break;
			case X86_0F_66H: w = X86_WIDTH_XMM; break;
			default: disasm_err(p); return;
			}
			break;
		case RM_REG_011:
			m = "psrldq";
			switch (x86_0f_select(p)) {
			case X86_0F_66H: w = X86_WIDTH_XMM; break;
			default: disasm_err(p); return;
			}
			break;
		case RM_REG_110:
			m = "psllq";
			switch (x86_0f_select(p)) {
			case X86_0F_NONE: w = X86_WIDTH_MM; break;
			case X86_0F_66H: w = X86_WIDTH_XMM; break;
			default: disasm_err(p); return;
			}
			break;
		case RM_REG_111:
			m = "pslldq";
			switch (x86_0f_select(p)) {
			case X86_0F_66H: w = X86_WIDTH_XMM; break;
			default: disasm_err(p); return;
			}
			break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0x74: // PCMPEQB
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "pcmpeqb");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0x75: // PCMPEQW
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "pcmpeqw");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0x76: // PCMPEQD
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "pcmpeqd");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0x77: // EMMS
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "emms");
		return;
	case 0x78: // VMREAD
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "vmread");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_MEM);
		return;
	case 0x79: // VMWRITE
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "vmwrite");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0x7C: // HADDPD/HADDPS
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_66H: m = "haddpd"; break;
		case X86_0F_F2H: m = "haddps"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0x7D: // HSUBPD/HSUBPS
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_66H: m = "hsubpd"; break;
		case X86_0F_F2H: m = "hsubps"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0x7E: // MOVD/MOVQ
		int d = void, w = void;
		const(char) *m = void;
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
		x86_modrm(p, w, d);
		return;
	case 0x7F: // movq/movdqa/movdqu
		int w = void;
		const(char) *m = void;
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
		x86_modrm(p, w, X86_DIR_MEM);
		return;
	case 0x80: // JO IMM32
		int m = *p.addru32;
		p.addrv += 4;
		if (p.mode >= DisasmMode.File) {
			disasm_push_x32(p, m);
			disasm_push_str(p, "jo");
			disasm_push_imm(p, m);
		}
		return;
	case 0x81: // JNO IMM32
		int m = *p.addru32;
		p.addrv += 4;
		if (p.mode >= DisasmMode.File) {
			disasm_push_x32(p, m);
			disasm_push_str(p, "jno");
			disasm_push_imm(p, m);
		}
		return;
	case 0x82: // JB IMM32
		int m = *p.addru32;
		p.addrv += 4;
		if (p.mode >= DisasmMode.File) {
			disasm_push_x32(p, m);
			disasm_push_str(p, "jb");
			disasm_push_imm(p, m);
		}
		return;
	case 0x83: // JAE IMM32
		int m = *p.addru32;
		p.addrv += 4;
		if (p.mode >= DisasmMode.File) {
			disasm_push_x32(p, m);
			disasm_push_str(p, "jae");
			disasm_push_imm(p, m);
		}
		return;
	case 0x84: // JE IMM32
		int m = *p.addru32;
		p.addrv += 4;
		if (p.mode >= DisasmMode.File) {
			disasm_push_x32(p, m);
			disasm_push_str(p, "je");
			disasm_push_imm(p, m);
		}
		return;
	case 0x85: // JNE IMM32
		int m = *p.addru32;
		p.addrv += 4;
		if (p.mode >= DisasmMode.File) {
			disasm_push_x32(p, m);
			disasm_push_str(p, "jne");
			disasm_push_imm(p, m);
		}
		return;
	case 0x86: // JBE IMM32
		int m = *p.addru32;
		p.addrv += 4;
		if (p.mode >= DisasmMode.File) {
			disasm_push_x32(p, m);
			disasm_push_str(p, "jbe");
			disasm_push_imm(p, m);
		}
		return;
	case 0x87: // JA IMM32
		int m = *p.addru32;
		p.addrv += 4;
		if (p.mode >= DisasmMode.File) {
			disasm_push_x32(p, m);
			disasm_push_str(p, "ja");
			disasm_push_imm(p, m);
		}
		return;
	case 0x88: // JS IMM32
		int m = *p.addru32;
		p.addrv += 4;
		if (p.mode >= DisasmMode.File) {
			disasm_push_x32(p, m);
			disasm_push_str(p, "js");
			disasm_push_imm(p, m);
		}
		return;
	case 0x89: // JNS IMM32
		int m = *p.addru32;
		p.addrv += 4;
		if (p.mode >= DisasmMode.File) {
			disasm_push_x32(p, m);
			disasm_push_str(p, "jns");
			disasm_push_imm(p, m);
		}
		return;
	case 0x8A: // JP IMM32
		int m = *p.addru32;
		p.addrv += 4;
		if (p.mode >= DisasmMode.File) {
			disasm_push_x32(p, m);
			disasm_push_str(p, "jp");
			disasm_push_imm(p, m);
		}
		return;
	case 0x8B: // JNP IMM32
		int m = *p.addru32;
		p.addrv += 4;
		if (p.mode >= DisasmMode.File) {
			disasm_push_x32(p, m);
			disasm_push_str(p, "jnp");
			disasm_push_imm(p, m);
		}
		return;
	case 0x8C: // JL IMM32
		int m = *p.addru32;
		p.addrv += 4;
		if (p.mode >= DisasmMode.File) {
			disasm_push_x32(p, m);
			disasm_push_str(p, "jl");
			disasm_push_imm(p, m);
		}
		return;
	case 0x8D: // JNL IMM32
		int m = *p.addru32;
		p.addrv += 4;
		if (p.mode >= DisasmMode.File) {
			disasm_push_x32(p, m);
			disasm_push_str(p, "jnl");
			disasm_push_imm(p, m);
		}
		return;
	case 0x8E: // JLE IMM32
		int m = *p.addru32;
		p.addrv += 4;
		if (p.mode >= DisasmMode.File) {
			disasm_push_x32(p, m);
			disasm_push_str(p, "jle");
			disasm_push_imm(p, m);
		}
		return;
	case 0x8F: // JNLE IMM32
		int m = *p.addru32;
		p.addrv += 4;
		if (p.mode >= DisasmMode.File) {
			disasm_push_x32(p, m);
			disasm_push_str(p, "jnle");
			disasm_push_imm(p, m);
		}
		return;
	case 0x90: // SETO MEM8 (REG field ignored)
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "seto");
		x86_modrm_rm(p, modrm, X86_WIDTH_BYTE);
		return;
	case 0x91: // SETNO MEM8
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "setno");
		x86_modrm_rm(p, modrm, X86_WIDTH_BYTE);
		return;
	case 0x92: // SETB MEM8
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "setb");
		x86_modrm_rm(p, modrm, X86_WIDTH_BYTE);
		return;
	case 0x93: // SETAE MEM8
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "setae");
		x86_modrm_rm(p, modrm, X86_WIDTH_BYTE);
		return;
	case 0x94: // SETE MEM8
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "sete");
		x86_modrm_rm(p, modrm, X86_WIDTH_BYTE);
		return;
	case 0x95: // SETNE MEM8
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "setne");
		x86_modrm_rm(p, modrm, X86_WIDTH_BYTE);
		return;
	case 0x96: // SETBE MEM8
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "setbe");
		x86_modrm_rm(p, modrm, X86_WIDTH_BYTE);
		return;
	case 0x97: // SETA MEM8
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "seta");
		x86_modrm_rm(p, modrm, X86_WIDTH_BYTE);
		return;
	case 0x98: // SETS MEM8
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "sets");
		x86_modrm_rm(p, modrm, X86_WIDTH_BYTE);
		return;
	case 0x99: // SETNS MEM8
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "setns");
		x86_modrm_rm(p, modrm, X86_WIDTH_BYTE);
		return;
	case 0x9A: // SETP MEM8
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "setp");
		x86_modrm_rm(p, modrm, X86_WIDTH_BYTE);
		return;
	case 0x9B: // SETNP MEM8
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "setnp");
		x86_modrm_rm(p, modrm, X86_WIDTH_BYTE);
		return;
	case 0x9C: // SETL MEM8
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "setl");
		x86_modrm_rm(p, modrm, X86_WIDTH_BYTE);
		return;
	case 0x9D: // SETNL MEM8
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "setnl");
		x86_modrm_rm(p, modrm, X86_WIDTH_BYTE);
		return;
	case 0x9E: // SETLE MEM8
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "setle");
		x86_modrm_rm(p, modrm, X86_WIDTH_BYTE);
		return;
	case 0x9F: // SETNLE MEM8
		ubyte modrm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "setnle");
		x86_modrm_rm(p, modrm, X86_WIDTH_BYTE);
		return;
	case 0xA0: // PUSH FS
		if (p.mode >= DisasmMode.File) {
			disasm_push_str(p, "push");
			disasm_push_reg(p, "fs");
		}
		return;
	case 0xA1: // POP FS
		if (p.mode >= DisasmMode.File) {
			disasm_push_str(p, "pop");
			disasm_push_reg(p, "fs");
		}
		return;
	case 0xA2: // CPUID
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "cpuid");
		return;
	case 0xA3: // BT RM, REG
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "bt");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_MEM);
		return;
	case 0xA4: // SHLD RM32, REG32, IMM8
	case 0xA5: // SHLD RM32, REG32, CL
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "shld");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_MEM);
		if (X86_OP_WIDE(b)) {
			if (p.mode >= DisasmMode.File)
				disasm_push_reg(p, "cl");
		} else {
			ubyte m = *p.addru8;
			++p.addrv;
			if (p.mode >= DisasmMode.File) {
				disasm_push_x8(p, m);
				disasm_push_imm(p, m);
			}
		}
		return;
	case 0xA8: // PUSH GS
		if (p.mode >= DisasmMode.File) {
			disasm_push_str(p, "push");
			disasm_push_reg(p, "gs");
		}
		return;
	case 0xA9: // POP GS
		if (p.mode >= DisasmMode.File) {
			disasm_push_str(p, "pop");
			disasm_push_reg(p, "gs");
		}
		return;
	case 0xAA: // RSM
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "rsm");
		return;
	case 0xAB: // BTS RM, REG
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "bts");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_MEM);
		return;
	case 0xAC: // SHRD RM32, REG32, IMM8
	case 0xAD: // SHRD RM32, REG32, CL
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "shld");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_MEM);
		if (X86_OP_WIDE(b)) {
			if (p.mode >= DisasmMode.File)
				disasm_push_reg(p, "cl");
		} else {
			ubyte m = *p.addru8;
			++p.addrv;
			if (p.mode >= DisasmMode.File) {
				disasm_push_x8(p, m);
				disasm_push_imm(p, m);
			}
		}
		return;
	case 0xAE: // GRP15
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
		return;
	case 0xAF: // IMUL 
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "imul");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0xB0: // CMPXCHG RM8, REG8
	case 0xB1: // CMPXCHG RM32, REG32
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "cmpxchg");
		x86_modrm(p, X86_OP_WIDE(b), X86_DIR_MEM);
		return;
	case 0xB2: // LSS REG32, RM32
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "lss");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0xB3: // BTR RM32, REG32
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "btr");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_MEM);
		return;
	case 0xB4: // LFS REG32, RM32
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "lfs");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0xB5: // LGS REG32, RM32
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "lgs");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0xB6: // MOVZX REG32, RM8
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "movzx");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0xB7: // MOVZX REG32, RM16
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "movzx");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0xB8: // JMPE (reserved)/POPCNT
		switch (x86_0f_select(p)) {
		case X86_0F_F3H:
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, "popcnt");
			x86_modrm(p, X86_WIDTH_EXT, X86_DIR_MEM);
			return;
		default: disasm_err(p);
		}
		return;
	case 0xB9: // UD1
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "ud1");
		return;
	case 0xBA: // GRP8 REG32, IMM8
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
		ubyte imm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File) {
			disasm_push_x8(p, modrm);
			disasm_push_x8(p, imm);
			disasm_push_str(p, m);
			disasm_push_reg(p, x86_modrm_reg(p, modrm << 3, X86_WIDTH_EXT));
			disasm_push_imm(p, imm);
		}
		return;
	case 0xBB: // BTC RM32, REG32
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "btc");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_MEM);
		return;
	case 0xBC: // BSF/TZCNT REG32, RM32
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "bsf"; break;
		case X86_0F_F3H: m = "tzcnt"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0xBD: // BSR/LZCNT REG32, RM32
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: m = "bsr"; break;
		case X86_0F_F3H: m = "lzcnt"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0xBE: // MOVSX REG32, RM8
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "movsx");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0xBF: // MOVSX REG32, RM16
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "movsx");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_REG);
		return;
	case 0xC0: // XADD RM8, REG8
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "xadd");
		x86_modrm(p, X86_WIDTH_BYTE, X86_DIR_MEM);
		return;
	case 0xC1: // XADD RM32, REG32
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "xadd");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_MEM);
		return;
	case 0xC2: // CMPPS/CMPPD/CMPSD/CMPSS
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
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		ubyte imm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File) {
			disasm_push_x8(p, imm);
			disasm_push_imm(p, imm);
		}
		return;
	case 0xC3: // MOVNTI RM32, REG32
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "movnti");
		x86_modrm(p, X86_WIDTH_EXT, X86_DIR_MEM);
		return;
	case 0xC4: // PINSRW REG64/128, RM, IMM8
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "pinsrw");
		x86_modrm(p, w, X86_DIR_REG);
		ubyte imm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File) {
			disasm_push_x8(p, imm);
			disasm_push_imm(p, imm);
		}
		return;
	case 0xC5: // PEXTRW REG32, REG64/128, IMM8
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
		ubyte imm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File) {
			disasm_push_x8(p, modrm);
			disasm_push_x8(p, imm);
			disasm_push_str(p, "pextrw");
			disasm_push_reg(p, x86_modrm_reg(p, modrm, X86_WIDTH_EXT));
			disasm_push_reg(p, x86_modrm_reg(p, modrm << 3, w));
			disasm_push_imm(p, imm);
		}
		return;
	case 0xC6: // SHUFPS/SHUFPD
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
		ubyte imm = *p.addru8;
		++p.addrv;
		if (p.mode >= DisasmMode.File) {
			disasm_push_x8(p, modrm);
			disasm_push_x8(p, imm);
			disasm_push_str(p, m);
			disasm_push_reg(p, x86_modrm_reg(p, modrm, X86_WIDTH_XMM));
			disasm_push_reg(p, x86_modrm_reg(p, modrm << 3, X86_WIDTH_XMM));
			disasm_push_imm(p, imm);
		}
		return;
	case 0xC7: // GRP9
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
				disasm_push_reg(p, x86_modrm_reg(p, modrm >> 3, X86_WIDTH_EXT));
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
		return;
	case 0xC8: // BSWAP EAX
		if (p.mode >= DisasmMode.File) {
			disasm_push_str(p, "bswap");
			disasm_push_reg(p, "eax");
		}
		return;
	case 0xC9: // BSWAP ECX
		if (p.mode >= DisasmMode.File) {
			disasm_push_str(p, "bswap");
			disasm_push_reg(p, "ecx");
		}
		return;
	case 0xCA: // BSWAP EDX
		if (p.mode >= DisasmMode.File) {
			disasm_push_str(p, "bswap");
			disasm_push_reg(p, "edx");
		}
		return;
	case 0xCB: // BSWAP EBX
		if (p.mode >= DisasmMode.File) {
			disasm_push_str(p, "bswap");
			disasm_push_reg(p, "ebx");
		}
		return;
	case 0xCC: // BSWAP ESP
		if (p.mode >= DisasmMode.File) {
			disasm_push_str(p, "bswap");
			disasm_push_reg(p, "esp");
		}
		return;
	case 0xCD: // BSWAP EBP
		if (p.mode >= DisasmMode.File) {
			disasm_push_str(p, "bswap");
			disasm_push_reg(p, "ebp");
		}
		return;
	case 0xCE: // BSWAP ESI
		if (p.mode >= DisasmMode.File) {
			disasm_push_str(p, "bswap");
			disasm_push_reg(p, "esi");
		}
		return;
	case 0xCF: // BSWAP EDI
		if (p.mode >= DisasmMode.File) {
			disasm_push_str(p, "bswap");
			disasm_push_reg(p, "edi");
		}
		return;
	case 0xD0: // ADDSUBPD/ADDSUBPS REG128, RM128
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_66H: m = "addsubpd"; break;
		case X86_0F_F2H: m = "addsubps"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0xD1: // PSRLW REG64/128, RM64/128
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "psrlw");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xD2: // PSRLD REG64/128, RM64/128
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "psrld");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xD3: // PSRLQ REG64/128, RM64/128
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "psrlq");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xD4: // PADDQ REG64/128, RM64/128
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "paddq");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xD5: // PMULLW REG64/128, RM64/128
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "pmullw");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xD6: // MOVQ/MOVDQ2Q/MOVQ2DQ
		switch (x86_0f_select(p)) {
		case X86_0F_66H:
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, "movq");
			x86_modrm(p, X86_WIDTH_XMM, X86_DIR_MEM);
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
				disasm_push_reg(p, x86_modrm_reg(p, modrm, X86_WIDTH_MM));
				disasm_push_reg(p, x86_modrm_reg(p, modrm << 3, X86_WIDTH_XMM));
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
				disasm_push_reg(p, x86_modrm_reg(p, modrm, X86_WIDTH_XMM));
				disasm_push_reg(p, x86_modrm_reg(p, modrm << 3, X86_WIDTH_MM));
			}
			return;
		default: disasm_err(p); return;
		}
	case 0xD7: // PMOVMSKB REG32, REG64/128
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
			disasm_push_reg(p, x86_modrm_reg(p, modrm, X86_WIDTH_EXT));
			disasm_push_reg(p, x86_modrm_reg(p, modrm << 3, w));
		}
		return;
	case 0xD8: // PSUBUSB
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "psubusb");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xD9: // PSUBUSW
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "psubusw");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xDA: // PMINUB
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "pminub");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xDB: // PAND
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "pand");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xDC: // PADDUSB
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "paddusb");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xDD: // PADDUSW
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "paddusw");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xDE: // PMAXUB
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "pmaxub");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xDF: // PANDN
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "pandn");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xE0: // PAVGB REG64/128, RM64/128
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "pavgb");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xE1: // PSRAW REG64/128, RM64/128
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "psraw");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xE2: // PSRAD REG64/128, RM64/128
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "psrad");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xE3: // PAVGW REG64/128, RM64/128
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "pavgw");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xE4: // PMULHUW REG64/128, RM64/128
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "pmulhuw");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xE5: // PMULHW REG64/128, RM64/128
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "pmulhw");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xE6: // CVTTPD2DQ/CVTPD2DQ/CVTDQ2PD REG128, RM128/128/64
		const(char) *m = void;
		switch (x86_0f_select(p)) {
		case X86_0F_66H: m = "cvttpd2dq"; break;
		case X86_0F_F2H: m = "cvtpd2dq"; break;
		case X86_0F_F3H: m = "cvtdq2pd"; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, m);
		x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
		return;
	case 0xE7: // MOVNTQ/MOVNTDQ RM64/128, RM64/128
		int w = void;
		const(char) *m = void;
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
		x86_modrm(p, w, X86_DIR_MEM);
		return;
	case 0xE8: // PSUBSB
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "psubsb");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xE9: // PSUBSW
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "psubsw");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xEA: // PMINSW
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "pminsw");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xEB: // POR
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "por");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xEC: // PADDSB
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "paddsb");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xED: // PADDSW
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "paddsw");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xEE: // PMAXSW
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "pmaxsw");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xEF: // PXOR
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "pxor");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xF0: // LLDQU
		switch (x86_0f_select(p)) {
		case X86_0F_F2H:
			if (p.mode >= DisasmMode.File)
				disasm_push_str(p, "lldqu");
			x86_modrm(p, X86_WIDTH_XMM, X86_DIR_REG);
			return;
		default: disasm_err(p); return;
		}
	case 0xF1: // PSLLW
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "psllw");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xF2: // PSLLD
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "pslld");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xF3: // PSLLQ
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "psllq");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xF4: // PMULUDQ
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "pmuludq");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xF5: // PMADDWD
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "pmaddwd");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xF6: // PSADBW
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "psadbw");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xF7: // MASKMOVQ/MASKMOVDQU REG64/128, REG64/128
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
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xF8: // PSUBB
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "psubb");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xF9: // PSUBW
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "psubw");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xFA: // PSUBD
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "psubd");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xFB: // PSUBQ
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "psubq");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xFC: // PADDB
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "paddb");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xFD: // PADDW
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "paddw");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xFE: // PADDD
		int w = void;
		switch (x86_0f_select(p)) {
		case X86_0F_NONE: w = X86_WIDTH_MM; break;
		case X86_0F_66H: w = X86_WIDTH_XMM; break;
		default: disasm_err(p); return;
		}
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "paddd");
		x86_modrm(p, w, X86_DIR_REG);
		return;
	case 0xFF: // UD0
		// NOTE: Some older processors decode without ModR/M. Instead,
		// an opcode exception is thrown (instead of a fault).
		if (p.mode >= DisasmMode.File)
			disasm_push_str(p, "ud0");
		return;
	default: // ANCHOR End of instructions
		disasm_err(p);
	}
}

void x86_0f38(ref disasm_params_t params) {
	
}

void x86_0f3a(ref disasm_params_t params) {
	
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
	X86_WIDTH_BYTE,	/// 8-bit registers (8086)
	X86_WIDTH_EXT,	/// 32/64-bit extended registers (i386/amd64)
	X86_WIDTH_WIDE,	/// 16-bit registers (8086)
	X86_WIDTH_MM,	/// 64-bit MM registers (MMX)
	X86_WIDTH_XMM,	/// 128-bit XMM registers (SSE)
	X86_WIDTH_YMM,	/// 256-bit YMM registers (AVX)
	X86_WIDTH_ZMM,	/// 512-bit ZMM registers (AVX-512)
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

void x86_u8imm(ref disasm_params_t p) {
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
void x86_u32imm(ref disasm_params_t p) {
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
void x86_immmem(ref disasm_params_t p) {
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
int x86_0f_select(ref disasm_params_t p) {
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

const(char) *x87_ststr(ref disasm_params_t p, int index) {
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
/// 	width = Register width, see X86_WIDTH_* enumerations
/// 	direction = If set, the registers are the target
void x86_modrm(ref disasm_params_t p, int width, int direction) {
	// 11 111 111
	// || ||| +++- RM
	// || +++----- REG
	// ++--------- MODE
	ubyte modrm = *p.addru8;
	++p.addrv;

	if (direction) goto L_REG;

L_RM:
	// Memory regs are only general registers
	x86_modrm_rm(p, modrm, width);
	if (direction) return;

L_REG:
	if (p.mode >= DisasmMode.File)
		disasm_push_reg(p, x86_modrm_reg(p, modrm, width));
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
const(char) *x86_modrm_reg(ref disasm_params_t p, int modrm, int width) {
	// This is asking for trouble, hopefully more checks will be added later
	// The array has this order for X86_OP_WIDE
	// NOTE: ModR/M extension is x86-64 only! (REX)
	__gshared const(char) *[][]x86_regs = [
		[ "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh" ],	// BYTE
		[ "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" ],	// EXI
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
void x86_modrm_rm(ref disasm_params_t p, ubyte modrm, int width) {
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
void x86_sib(ref disasm_params_t p, ubyte modrm) {
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

	if (index == SIB_INDEX_100) {
		disasm_err(p);
		return;
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
