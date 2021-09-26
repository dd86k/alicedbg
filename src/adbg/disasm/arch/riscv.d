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
//TODO: adbg_disasm_fetch_unify
//      Make it so two fetches into a type.. SOMEHOW

import adbg.error;
import adbg.disasm.disasm;
import adbg.utils.bit;

extern (C):

/// Disassemble RISC-V
/// Note: So far only does risc-v-32
/// Params: p = Disassembler parameters
int adbg_disasm_riscv(adbg_disasm_t *p) {
	riscv_internals_t i = void;
	i.disasm = p;
	
	switch (p.platform) with (AdbgPlatform) {
	case riscv32: i.nativeWidth = AdbgDisasmType.i32; break;
	case riscv64: i.nativeWidth = AdbgDisasmType.i64; break;
//	case riscv128: i.nativeWidth = AdbgDisasmType.i128; break;
	default: assert(0, "Invalid RISC-V platform");
	}
	
	// Fetch by "halfword" (16-bit)
	int e = adbg_disasm_fetch!ushort(p, &i.op1, AdbgDisasmTag.opcode);
	if (e) return e;
	
	//
	// RISC-V Compressed (RVC) Extension
	//
	
	switch (i.op1 & 3) {
	case 0:
		switch (i.op1 & OP_RVC_FUNC) {
		case OP_RVC_FUNC_000: // C.ADDI4SPN
			int imm = i.op1 >> 5;
			if (imm == 0) {
				return adbg_oops(AdbgError.illegalInstruction);
			}
			if (p.mode < AdbgDisasmMode.file)
				return 0;
			int rd = (i.op1 >> 2) & 7;
			adbg_disasm_add_mnemonic(i.disasm, "c.addi4spn");
			adbg_disasm_add_register(i.disasm, adbg_disasm_riscv_rvc_abi_reg(rd));
			adbg_disasm_add_immediate(i.disasm, AdbgDisasmType.i32, &imm);
			return 0;
		case OP_RVC_FUNC_110: // C.SW
			if (p.mode < AdbgDisasmMode.file)
				return 0;
			int rs1 = (i.op1 >> 7) & 7;
			int rs2 = (i.op1 >> 2) & 7;
			int imm = (i.op1 >> 9) & 7;
			if (i.op1 & BIT!(6)) imm |= 1;
			if (i.op1 & BIT!(5)) imm = -imm;
			adbg_disasm_add_mnemonic(i.disasm, "c.sw");
			adbg_disasm_add_register(i.disasm, adbg_disasm_riscv_rvc_abi_reg(rs1));
			adbg_disasm_add_register(i.disasm, adbg_disasm_riscv_rvc_abi_reg(rs2));
			adbg_disasm_add_immediate(i.disasm, AdbgDisasmType.i32, &imm);
			return 0;
		default: // Yes, 000 is illegal
			return adbg_oops(AdbgError.illegalInstruction);
		}
	case 1:
		switch (i.op1 & OP_RVC_FUNC) {
		case OP_RVC_FUNC_000:
			if (p.mode < AdbgDisasmMode.file)
				return 0;
			int rd = (i.op1 >> 7) & 31; /// rd/rs1 (op[11:7])
			if (rd) { // C.ADDI
				int imm = (i.op1 >> 2) & 31;
				if (i.op1 & BIT!(12)) imm = -imm;
				const(char) *rdstr = adbg_disasm_riscv_abi_reg(rd);
				adbg_disasm_add_mnemonic(i.disasm, rd == 2 ? "c.addi16sp" : "c.addi");
				adbg_disasm_add_register(i.disasm, rdstr);
				adbg_disasm_add_register(i.disasm, rdstr);
				adbg_disasm_add_immediate(i.disasm, AdbgDisasmType.i32, &imm);
			} else { // C.NOP (rd == 0)
				adbg_disasm_add_mnemonic(i.disasm, "c.nop");
			}
			return 0;
		case OP_RVC_FUNC_001: // C.JAL
			if (p.mode < AdbgDisasmMode.file)
				return 0;
			int imm = adbg_disasm_riscv_imm_cj(i.op1);
			adbg_disasm_add_mnemonic(i.disasm, "c.jal");
			adbg_disasm_add_immediate(i.disasm, AdbgDisasmType.i32, &imm);
			return 0;
		case OP_RVC_FUNC_100: // C.GRP1_1
			int rd = (i.op1 >> 7) & 7;
			switch (i.op1 & 0xC00) { // op[11:10]
			case 0:	// C.SRLI
			
				assert(0, "TODO");
			case 0x400:	// C.SRAI
			
				assert(0, "TODO");
			case 0x800:	// C.ANDI
			
				assert(0, "TODO");
			default: // 0xc00: C.GRP1_1_1
				const(char) *m = void;
				switch (i.op1 & 0x1060) { // op[12|6:5]
				case 0:	     m = "c.sub"; break;
				case 0x20:   m = "c.xor"; break;
				case 0x40:   m = "c.or"; break;
				case 0x60:   m = "c.and"; break;
				case 0x1000: m = "c.subw"; break;
				case 0x1020: m = "c.addw"; break;
				default: return adbg_oops(AdbgError.illegalInstruction);
				}
				if (p.mode < AdbgDisasmMode.file)
					return 0;
				int rs2 = (i.op1 >> 2) & 7;
				adbg_disasm_add_mnemonic(i.disasm, m);
				adbg_disasm_add_register(i.disasm, adbg_disasm_riscv_rvc_abi_reg(rd));
				adbg_disasm_add_register(i.disasm, adbg_disasm_riscv_rvc_abi_reg(rd));
				adbg_disasm_add_register(i.disasm, adbg_disasm_riscv_rvc_abi_reg(rs2));
				return 0;
			}
		default: return adbg_oops(AdbgError.illegalInstruction);
		}
	case 2:
		switch (i.op1 & OP_RVC_FUNC) {
		case OP_RVC_FUNC_010:
			int rd = (i.op1 >> 7) & 31;
			if (rd == 0) {
				return adbg_oops(AdbgError.illegalInstruction);
			}
			if (p.mode < AdbgDisasmMode.file)
				return 0;
			int imm = (i.op1 >> 2) & 31;
			if (i.op1 & BIT!(12)) imm |= BIT!(5);
			adbg_disasm_add_mnemonic(i.disasm, "c.lwsp");
			adbg_disasm_add_register(p, adbg_disasm_riscv_abi_reg(rd));
			adbg_disasm_add_immediate(i.disasm, AdbgDisasmType.i32, &imm);
			return 0;
		case OP_RVC_FUNC_100:
			if (p.mode < AdbgDisasmMode.file)
				return 0;
			int rd  = (i.op1 >> 7) & 31; // or rd
			int rs2 = (i.op1 >> 2) & 31;
			if (i.op1 & BIT!(12)) {
				if (rs2) {
					adbg_disasm_add_mnemonic(i.disasm, "c.add");
					adbg_disasm_add_register(i.disasm, adbg_disasm_riscv_rvc_abi_reg(rd));
					adbg_disasm_add_register(i.disasm, adbg_disasm_riscv_abi_reg(rs2));
				} else {
					if (rd) {
						adbg_disasm_add_mnemonic(p, "c.jalr");
						adbg_disasm_add_register(p, adbg_disasm_riscv_abi_reg(rd));
					} else {
						adbg_disasm_add_mnemonic(p, "c.ebreak");
					}
				}
			} else {
				if (rs2) {
					adbg_disasm_add_mnemonic(p, "c.mv");
					adbg_disasm_add_register(p, adbg_disasm_riscv_abi_reg(rd));
					adbg_disasm_add_register(p, adbg_disasm_riscv_abi_reg(rs2));
				} else {
					adbg_disasm_add_mnemonic(p, "c.jr");
					adbg_disasm_add_register(p, adbg_disasm_riscv_abi_reg(rd));
				}
			}
			return 0;
		case OP_RVC_FUNC_110:
			if (p.mode < AdbgDisasmMode.file)
				return 0;
			int rs2 = (i.op1 >> 2) & 31;
			int imm = (i.op1 >> 7) & 63;
			adbg_disasm_add_mnemonic(p, "c.swsp");
			adbg_disasm_add_memory(i.disasm, i.nativeWidth,
				null, adbg_disasm_riscv_abi_reg(rs2), null,
				AdbgDisasmType.i32, &imm,
				false, false, false);
			return 0;
		default: return adbg_oops(AdbgError.illegalInstruction);
		}
	default: // 11 >= 16b
	}
	
	//
	// RISC-V 32-bit
	//
	
	e = adbg_disasm_fetch!ushort(p, &i.op2, AdbgDisasmTag.opcode);
	if (e) return e;
	
	switch (i.op & OPCODE) {
	case 19: // (0010011) RV32I: ADDI/SLTI/SLTIU/XORI/ORI/ANDI
		const(char) *m = void;
		switch (i.op & OP_FUNC) {
		case OP_FUNC_000: m = "addi"; break;
		case OP_FUNC_010: m = "slti"; break;
		case OP_FUNC_011: m = "sltiu"; break;
		case OP_FUNC_100: m = "xori"; break;
		case OP_FUNC_110: m = "ori"; break;
		case OP_FUNC_111: m = "andi"; break;
		default: return adbg_oops(AdbgError.illegalInstruction);
		}
		if (p.mode < AdbgDisasmMode.file)
			return 0;
		int imm = i.op >> 20;
		int rs1 = (i.op >> 15) & 31;
		int rd = (i.op >> 7) & 31;
		adbg_disasm_add_mnemonic(i.disasm, m);
		adbg_disasm_add_register(i.disasm, adbg_disasm_riscv_abi_reg(rd));
		adbg_disasm_add_register(i.disasm, adbg_disasm_riscv_abi_reg(rs1));
		adbg_disasm_add_immediate(i.disasm, AdbgDisasmType.i32, &imm);
		return 0;
	case 35: // (0100011) RV32I: SB/SH/SW
		const(char) *m = void;
		AdbgDisasmType w = void;
		switch (i.op & OP_FUNC) {
		case OP_FUNC_000: m = "sb"; w = AdbgDisasmType.i8; break;
		case OP_FUNC_001: m = "sh"; w = AdbgDisasmType.i16; break;
		case OP_FUNC_010: m = "sw"; w = AdbgDisasmType.i32; break;
		default: return adbg_oops(AdbgError.illegalInstruction);
		}
		if (p.mode < AdbgDisasmMode.file)
			return 0;
		int imm = adbg_disasm_riscv_imm_s(i.op);
		int rs1 = (i.op >> 15) & 31;
		int rs2 = (i.op >> 20) & 31;
		adbg_disasm_add_mnemonic(i.disasm, m);
		adbg_disasm_add_memory(i.disasm, w,
			null, adbg_disasm_riscv_abi_reg(rs1), null,
			AdbgDisasmType.i32, &imm,
			false, false, false);
		adbg_disasm_add_register(i.disasm, adbg_disasm_riscv_abi_reg(rs2));
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
	AdbgDisasmType nativeWidth;
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

/// Get ABI register name by a 4 or 5-bit field. (e.g. sp instead of x2)
/// Only the first definition is taken (i.e. s0 over fp) to comply with objdump.
/// Caller is responsible for masking the input value.
/// Params: s = 5-bit selector
/// Returns: Register string
const(char) *adbg_disasm_riscv_abi_reg(int s) {
	__gshared const(char) *[]rv32_regs = [
		"zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", // x0-x7
		"s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",   // x8-15
		"a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",   // x16-x23
		"s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6", // x24-x31
	];
	return rv32_regs[s];
}

/// Get a register (ABI) from the 3-bit field from RVC instructions.
/// Caller is responsible for masking the input value.
/// Params: s = 3-bit value
/// Returns: Register string
const(char) *adbg_disasm_riscv_rvc_abi_reg(int s) {
	return adbg_disasm_riscv_abi_reg(s + 8);
}

//
// Helpers
//

int adbg_disasm_riscv_imm_cj(ushort op) {	// C.J type
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

int adbg_disasm_riscv_imm_s(uint op) {	// S type
	return	((op >> 7) & 31 |
		((op >> 20) & 4095) |
		(-((op >> 19) & 0x8_0000)));
}