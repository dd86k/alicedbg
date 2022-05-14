/**
 * RISC-V RV32/RV64 decoder.
 *
 * Incomplete, about 5% done. Mostly RV32.
 *
 * Version: 1
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.disasm.arch.riscv;

//TODO: Control-flow analysis
//TODO: adbg_disasm_fetch_unite for RVC -> RV32/64G
//      Make it so two fetches into a type.. SOMEHOW

import adbg.error;
import adbg.disassembler;
import adbg.utils.bit;

extern (C):

/// Disassemble RISC-V
/// Note: So far only does risc-v-32
/// Params: p = Disassembler parameters
int adbg_disasm_riscv(adbg_disasm_t *disasm) {
	riscv_internals_t state = void;
	state.disasm = disasm;
	
	// Fetch by "halfword" (16-bit)
	int e = adbg_disasm_fetch!ushort(&state.op1, disasm, AdbgDisasmTag.opcode);
	if (e) return e;
	
	//
	// ANCHOR RVC
	//
	
	switch (state.op1 & 3) {
	case 0:
		switch (state.op1 & OP_RVC_FUNC) {
		case OP_RVC_FUNC_000: // C.ADDI4SPN -> ADDI REG,SP,IMM
			int imm = state.op1 >> 7;
			if (imm == 0)
				return adbg_oops(AdbgError.illegalInstruction);
			if (disasm.mode < AdbgDisasmMode.file)
				return 0;
			int rd = (state.op1 >> 2) & 7;
			adbg_disasm_add_mnemonic(state.disasm, RV_ADDI);
			adbg_disasm_add_register(state.disasm, adbg_disasm_rv_c_reg(rd));
			adbg_disasm_add_register(state.disasm, rvregs[Register.x2]);
			adbg_disasm_add_immediate(state.disasm, AdbgDisasmType.i32, &imm);
			return 0;
		case OP_RVC_FUNC_110: // C.SW -> SW REG1,REG2,IMM
			if (disasm.mode < AdbgDisasmMode.file)
				return 0;
			int rs1 = (state.op1 >> 7) & 7;
			int rs2 = (state.op1 >> 2) & 7;
			int imm = (state.op1 >> 9) & 7;
			if (state.op1 & BIT!(6)) imm |= 1;
			if (state.op1 & BIT!(5)) imm = -imm;
			adbg_disasm_add_mnemonic(state.disasm, RV_SW);
			adbg_disasm_add_register(state.disasm, adbg_disasm_rv_c_reg(rs1));
			adbg_disasm_add_register(state.disasm, adbg_disasm_rv_c_reg(rs2));
			adbg_disasm_add_immediate(state.disasm, AdbgDisasmType.i32, &imm);
			return 0;
		default: // Yes, 000 is illegal
			return adbg_oops(AdbgError.illegalInstruction);
		}
	case 1:
		switch (state.op1 & OP_RVC_FUNC) {
		case OP_RVC_FUNC_000:
			if (disasm.mode < AdbgDisasmMode.file)
				return 0;
			int rd = (state.op1 >> 7) & 31; /// rd/rs1 (op[11:7])
			if (rd) { // C.ADDI/C.ADDI16SP -> ADDI REG,REG,IMM
				int imm = (state.op1 >> 2) & 31;
				const(char) *rdstr = rvregs[rd];
				//TODO: C.ADDI16SP nzimm[4|6|8:7|5]
				if (state.op1 & BIT!(12)) imm = -imm;
				adbg_disasm_add_mnemonic(state.disasm, RV_ADDI);
				adbg_disasm_add_register(state.disasm, rdstr);
				adbg_disasm_add_register(state.disasm, rdstr);
				adbg_disasm_add_immediate(state.disasm, AdbgDisasmType.i32, &imm);
			} else { // C.NOP (rd == 0)
				adbg_disasm_add_mnemonic(state.disasm, RV_NOP);
			}
			return 0;
		case OP_RVC_FUNC_001: // C.JAL -> JAL IMM
			if (disasm.mode < AdbgDisasmMode.file)
				return 0;
			int imm = adbg_disasm_rv_imm_cj(state.op1);
			adbg_disasm_add_mnemonic(state.disasm, RV_JAL);
			adbg_disasm_add_immediate(state.disasm, AdbgDisasmType.i32, &imm);
			return 0;
		case OP_RVC_FUNC_100: // C.GRP1_1
			int rd = (state.op1 >> 7) & 7;
			switch (state.op1 & 0xC00) { // op[11:10]
			case 0:	// C.SRLI
			
				return adbg_oops(AdbgError.notImplemented);
			case 0x400:	// C.SRAI
			
				return adbg_oops(AdbgError.notImplemented);
			case 0x800:	// C.ANDI
			
				return adbg_oops(AdbgError.notImplemented);
			default: // 0xc00: C.GRP1_1_1
				const(char) *m = void;
				switch (state.op1 & 0x1060) { // op[12|6:5]
				case 0:	     m = RV_SUB; break;
				case 0x20:   m = RV_XOR; break;
				case 0x40:   m = RV_OR; break;
				case 0x60:   m = RV_AND; break;
				case 0x1000: m = RV_SUBW; break;
				case 0x1020: m = RV_ADDW; break;
				default: return adbg_oops(AdbgError.illegalInstruction);
				}
				if (disasm.mode < AdbgDisasmMode.file)
					return 0;
				int rs2 = (state.op1 >> 2) & 7;
				adbg_disasm_add_mnemonic(state.disasm, m);
				adbg_disasm_add_register(state.disasm, adbg_disasm_rv_c_reg(rd));
				adbg_disasm_add_register(state.disasm, adbg_disasm_rv_c_reg(rd));
				adbg_disasm_add_register(state.disasm, adbg_disasm_rv_c_reg(rs2));
				return 0;
			}
		default: return adbg_oops(AdbgError.illegalInstruction);
		}
	case 2:
		switch (state.op1 & OP_RVC_FUNC) { // C.LWSP
		case OP_RVC_FUNC_010:
			int rd = (state.op1 >> 7) & 31;
			if (rd == 0)
				return adbg_oops(AdbgError.illegalInstruction);
			if (disasm.mode < AdbgDisasmMode.file)
				return 0;
			int imm = (state.op1 >> 2) & 31;
			if (state.op1 & BIT!(12)) imm |= BIT!(5);
			adbg_disasm_add_mnemonic(state.disasm, RV_LW);
			adbg_disasm_add_register(disasm, rvregs[rd]);
			adbg_disasm_add_memory(state.disasm, AdbgDisasmType.i32,
				null, rvregs[Register.sp], null,
				AdbgDisasmType.i32, &imm, false, false, false);
			return 0;
		case OP_RVC_FUNC_100:
			if (disasm.mode < AdbgDisasmMode.file)
				return 0;
			int rd  = (state.op1 >> 7) & 31; // or rd
			int rs2 = (state.op1 >> 2) & 31;
			if (state.op1 & BIT!(12)) {
				if (rs2) { // C.ADD
					adbg_disasm_add_mnemonic(state.disasm, RV_ADD);
					adbg_disasm_add_register(state.disasm, adbg_disasm_rv_c_reg(rd));
					adbg_disasm_add_register(state.disasm, rvregs[rs2]);
				} else {
					if (rd) { // C.JALR
						adbg_disasm_add_mnemonic(disasm, RV_JALR);
						adbg_disasm_add_register(disasm, rvregs[rd]);
					} else { // C.EBREAK
						adbg_disasm_add_mnemonic(disasm, RV_EBREAK);
					}
				}
			} else {
				if (rs2) { // C.MV
					adbg_disasm_add_mnemonic(disasm, RV_MV);
					adbg_disasm_add_register(disasm, rvregs[rd]);
					adbg_disasm_add_register(disasm, rvregs[rs2]);
				} else { // C.JR
					if (rd == Register.ra) {
						adbg_disasm_add_mnemonic(disasm, RV_RET);
					} else {
						adbg_disasm_add_mnemonic(disasm, RV_JR);
						adbg_disasm_add_register(disasm, rvregs[rd]);
					}
				}
			}
			return 0;
		case OP_RVC_FUNC_110: // C.SWSP
			if (disasm.mode < AdbgDisasmMode.file)
				return 0;
			int rs2 = (state.op1 >> 2) & 31;
			int imm = (state.op1 >> 7) & 63;
			adbg_disasm_add_mnemonic(disasm, RV_SW);
			adbg_disasm_add_register(state.disasm, rvregs[rs2]);
			adbg_disasm_add_memory(state.disasm, AdbgDisasmType.i32,
				null, rvregs[Register.x2], null,
				AdbgDisasmType.i32, &imm,
				false, false, false);
			return 0;
		default: return adbg_oops(AdbgError.illegalInstruction);
		}
	default: // 11 >= 16b
	}
	
	//
	// ANCHOR RV32/64G
	//
	
	e = adbg_disasm_fetch!ushort(&state.op2, disasm, AdbgDisasmTag.opcode);
	if (e) return e;
	
	switch (state.op & OPCODE) {
	case 19: // (0010011) RV32I: ADDI/SLTI/SLTIU/XORI/ORI/ANDI
		const(char) *m = void;
		int imm = state.op >> 20;
		int rs1 = (state.op >> 15) & 31;
		switch (state.op & OP_FUNC) {
		case OP_FUNC_000: m = rs1 ? RV_ADDI : RV_LI; break;
		case OP_FUNC_010: m = RV_SLTI; break;
		case OP_FUNC_011: m = RV_SLTIU; break;
		case OP_FUNC_100: m = RV_XORI; break;
		case OP_FUNC_110: m = RV_ORI; break;
		case OP_FUNC_111: m = RV_ANDI; break;
		default: return adbg_oops(AdbgError.illegalInstruction);
		}
		if (disasm.mode < AdbgDisasmMode.file)
			return 0;
		int rd = (state.op >> 7) & 31;
		adbg_disasm_add_mnemonic(state.disasm, m);
		adbg_disasm_add_register(state.disasm, rvregs[rd]);
		if (rs1)
			adbg_disasm_add_register(state.disasm, rvregs[rs1]);
		adbg_disasm_add_immediate(state.disasm, AdbgDisasmType.i32, &imm);
		return 0;
	case 35: // (0100011) RV32I: SB/SH/SW
		const(char) *m = void;
		AdbgDisasmType w = void;
		switch (state.op & OP_FUNC) {
		case OP_FUNC_000: m = RV_SB; w = AdbgDisasmType.i8; break;
		case OP_FUNC_001: m = RV_SH; w = AdbgDisasmType.i16; break;
		case OP_FUNC_010: m = RV_SW; w = AdbgDisasmType.i32; break;
		default: return adbg_oops(AdbgError.illegalInstruction);
		}
		if (disasm.mode < AdbgDisasmMode.file)
			return 0;
		int imm = adbg_disasm_rv_imm_s(state.op);
		int rs1 = (state.op >> 15) & 31;
		int rs2 = (state.op >> 20) & 31;
		adbg_disasm_add_mnemonic(state.disasm, m);
		adbg_disasm_add_memory(state.disasm, w,
			null, rvregs[rs1], null,
			AdbgDisasmType.i32, &imm,
			false, false, false);
		adbg_disasm_add_register(state.disasm, rvregs[rs2]);
		return 0;
	default: return adbg_oops(AdbgError.illegalInstruction);
	}
}

private:

struct riscv_internals_t { align(1):
	adbg_disasm_t *disasm;
	union {
		uint op;
		//TODO: An array with OPCODE_LOW/HIGH constants seem better...
		version (LittleEndian)
			public struct { align(1): ushort op1, op2; }
		else
			public struct { align(1): ushort op2, op1; }
	}
}

//
// Enumerations, masks
//

enum OP_FUNC = OP_FUNC_111;	/// bit[14:12]
enum OP_FUNC_000 = 0;
enum OP_FUNC_001 = 0x1000;
enum OP_FUNC_010 = 0x2000;
enum OP_FUNC_011 = 0x3000;
enum OP_FUNC_100 = 0x4000;
enum OP_FUNC_101 = 0x5000;
enum OP_FUNC_110 = 0x6000;
enum OP_FUNC_111 = 0x7000;
enum OPCODE = 0x7F;	/// bit[6:0]
enum OP_RVC_FUNC = OP_RVC_FUNC_111;	/// bit[15:13]
enum OP_RVC_FUNC_000 = 0;
enum OP_RVC_FUNC_001 = 0x2000;
enum OP_RVC_FUNC_010 = 0x4000;
enum OP_RVC_FUNC_011 = 0x6000;
enum OP_RVC_FUNC_100 = 0x8000;
enum OP_RVC_FUNC_101 = 0xA000;
enum OP_RVC_FUNC_110 = 0xC000;
enum OP_RVC_FUNC_111 = 0xE000;

//
// Registers
//

enum Register {
	x0,  x1,  x2,  x3,  x4,  x5,  x6,  x7,
	x8,  x9,  x10, x11, x12, x13, x14, x15,
	x16, x17, x18, x19, x20, x21, x22, x23,
	x24, x25, x26, x27, x28, x29, x30, x31,
	zero	= x0,	ra	= x1,
	sp	= x2,	gp	= x3,
	tp	= x4,	t0	= x5,
	t1	= x6,	t2	= x7,
	s0	= x8,	s1	= x9,
	a0	= x10,	a1	= x11,
	a2	= x12,	a3	= x13,
	a4	= x14,	a5  	= x15,
	a6	= x16,	a7	= x17,
	s2	= x18,	s3	= x19,
	s4	= x20,	s5	= x21,
	s6	= x22,	s7  	= x23,
	s8	= x24,	s9	= x25,
	s10	= x26,	s11	= x27,
	t3	= x28,	t4	= x29,
	t5	= x30,	t6	= x31,
}

immutable const(char)*[32] rvregs = [
	"zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", // x0-x7
	"s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",   // x8-15
	"a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",   // x16-x23
	"s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6", // x24-x31
];

immutable const(char) *RV_NOP	= "nop";
immutable const(char) *RV_SB	= "sb";
immutable const(char) *RV_SH	= "sh";
immutable const(char) *RV_SW	= "sw";
immutable const(char) *RV_ADDI	= "addi";
immutable const(char) *RV_SLTI	= "slti";
immutable const(char) *RV_SLTIU	= "sltiu";
immutable const(char) *RV_XORI	= "xori";
immutable const(char) *RV_ORI	= "ori";
immutable const(char) *RV_ANDI	= "andi";
immutable const(char) *RV_J	= "j";
immutable const(char) *RV_JR	= "jr";
immutable const(char) *RV_JAL	= "jal";
immutable const(char) *RV_RET	= "ret";
immutable const(char) *RV_MV	= "mv";
immutable const(char) *RV_ADD	= "add";
immutable const(char) *RV_JALR	= "jalr";
immutable const(char) *RV_EBREAK	= "ebreak";
immutable const(char) *RV_LW	= "lw";
immutable const(char) *RV_LI	= "li";
immutable const(char) *RV_SUB	= "sub";
immutable const(char) *RV_XOR	= "xor";
immutable const(char) *RV_OR	= "or";
immutable const(char) *RV_AND	= "and";
immutable const(char) *RV_SUBW	= "subw";
immutable const(char) *RV_ADDW	= "addw";

/// Get a register (ABI) from the 3-bit field from RVC instructions.
/// Caller is responsible for masking the input value.
/// Params: s = 3-bit value
/// Returns: Register string
const(char) *adbg_disasm_rv_c_reg(int s) {
	return rvregs[s + 8];
}

int adbg_disasm_rv_imm_cj(ushort op) {	// C.J type
	// inspired by objdump 2.28 (include/opcode/riscv.h)
	return	((op & 0x38) >> 2) |
		((op & BIT!(11)) >> 7) |
		((op & BIT!(2)) << 3) |
		((op & BIT!(7)) >> 1) |
		((op & BIT!(6)) << 1) |
		((op & 0x600) >> 1) |
		((op & BIT!(8)) << 2) |
		(-(op & BIT!(12)) >> 1);
}

int adbg_disasm_rv_imm_s(uint op) {	// S type
	return	((op >> 7) & 31 |
		((op >> 20) & 4095) |
		(-((op >> 19) & 0x8_0000)));
}