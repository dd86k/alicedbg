/**
 * RISC-V 32-bit decoder.
 *
 * License: BSD 3-Clause
 */
module debugger.disasm.arch.rv32;

import debugger.disasm.core;
import debugger.disasm.formatter;
import utils.str, utils.bit;

extern (C):

package
struct rv32_internals_t {
	union {
		uint op;
		struct { ushort op1, op2; }
	}
}

/// Disassemble riscv-32.
/// Params: p = Disassembler parameters
void disasm_rv32(disasm_params_t *p) {
	rv32_internals_t i = void;
	p.rv32 = &i;

	// Detect RV32C first
	i.op1 = *p.addru16;
	++p.addru16;

	//
	// RVC
	//

	//TODO: Process opcodes by types (C.I, I, C.J, J, etc.)
	//      rv32_process(string, int) { switch(int) } -> push(str) + more

	switch (i.op1 & 3) {
	case 0:
		if (p.mode >= DisasmMode.File)
			disasm_push_x16(p, i.op1);
		switch (i.op1 & OP_RVC_FUNC_MASK) {
		case OP_RVC_FUNC_000: // C.ADDI4SPN
			int imm = i.op1 >> 5;
			if (imm == 0) {
				disasm_err(p);
				return;
			}
			if (p.mode < DisasmMode.File)
				return;
			int rd = (i.op1 >> 2) & 7;
			disasm_push_str(p, "c.addi4spn");
			disasm_push_reg(p, rv32_rvc_abi_reg(rd));
			disasm_push_imm(p, imm);
			return;
		case OP_RVC_FUNC_110: // C.SW
			if (p.mode < DisasmMode.File)
				return;
			int rs1 = (i.op1 >> 7) & 7;
			int rs2 = (i.op1 >> 2) & 7;
			int imm = (i.op1 >> 9) & 7;
			if (i.op1 & BIT!(6))
				imm |= 1;
			if (i.op1 & BIT!(5))
				imm = -imm;
			disasm_push_str(p, "c.sw");
			disasm_push_reg(p, rv32_rvc_abi_reg(rs1));
			disasm_push_reg(p, rv32_rvc_abi_reg(rs2));
			disasm_push_imm(p, imm);
			return;
		default: disasm_err(p); return; // Yes, 000 is illegal
		}
	case 1:
		if (p.mode >= DisasmMode.File)
			disasm_push_x16(p, i.op1);
		switch (i.op1 & OP_RVC_FUNC_MASK) {
		case OP_RVC_FUNC_000:
			if (p.mode < DisasmMode.File)
				return;
			int rd = (i.op1 >> 7) & 31; /// rd/rs1 (op[11:7])
			if (rd) { // C.ADDI
				int imm = (i.op1 >> 2) & 31;
				if (i.op1 & BIT!(12)) imm = -imm;
				const(char) *m = rd == 2 ? "c.addi16sp" : "c.addi";
				const(char) *rdstr = rv32_abi_reg(rd);
				disasm_push_str(p, m);
				disasm_push_reg(p, rdstr);
				disasm_push_reg(p, rdstr);
				disasm_push_imm(p, imm);
			} else { // C.NOP (rd == 0)
				disasm_push_str(p, "c.nop");
			}
			return;
		default: disasm_err(p); return;
		}
	case 2:
		if (p.mode >= DisasmMode.File)
			disasm_push_x16(p, i.op1);
		switch (i.op1 & OP_RVC_FUNC_MASK) {
		case OP_RVC_FUNC_010:
			int rd = (i.op1 >> 7) & 31;
			if (rd == 0) {
				disasm_err(p);
				return;
			}
			int imm = (i.op1 >> 2) & 31;
			if (i.op1 & BIT!(12))
				imm |= BIT!(5);
			disasm_push_str(p, "c.lwsp");
			disasm_push_reg(p, rv32_abi_reg(rd));
			disasm_push_imm(p, imm);
			return;
		case OP_RVC_FUNC_100:
			int rs1 = (i.op1 >> 9) & 31; // or rd
			int rs2 = (i.op1 >> 2) & 31;
			if (i.op1 & BIT!(12)) {
				if (rs2) {
					disasm_push_str(p, "c.add");
					disasm_push_reg(p, rv32_rvc_abi_reg(rs1));
					disasm_push_reg(p, rv32_abi_reg(rs2));
				} else {
					if (rs1) {
						disasm_push_str(p, "c.jalr");
						disasm_push_reg(p, rv32_abi_reg(rs1));
					} else {
						disasm_push_str(p, "c.ebreak");
					}
				}
			} else {
				if (rs2) {
					disasm_push_str(p, "c.mv");
					disasm_push_reg(p, rv32_rvc_abi_reg(rs1));
					disasm_push_reg(p, rv32_abi_reg(rs2));
				} else {
					disasm_push_str(p, "c.jr");
					disasm_push_reg(p, rv32_abi_reg(rs1));
				}
			}
			return;
		case OP_RVC_FUNC_110:
			if (p.mode < DisasmMode.File)
				return;
			int rs2 = (i.op1 >> 2) & 31;
			int imm = (i.op1 >> 7) & 63;
			disasm_push_str(p, "c.swsp");
			disasm_push_reg(p, rv32_abi_reg(rs2));
			disasm_push_imm(p, imm);
			return;
		default: disasm_err(p); return;
		}
	default: // 11 >= 16b
	}

	//
	// RV32
	//

	i.op2 = *p.addru16;
	++p.addru16;
	if (p.mode >= DisasmMode.File)
		disasm_push_x32(p, i.op);
	switch (i.op & OP_MASK) {
	case 0b0010011: // (19) RV32I: ADDI/SLTI/SLTIU/XORI/ORI/ANDI
		const(char) *m = void;
		switch (i.op & OP_FUNC_MASK) {
		case OP_FUNC_000: m = "addi"; break;
		case OP_FUNC_010: m = "slti"; break;
		case OP_FUNC_011: m = "sltiu"; break;
		case OP_FUNC_100: m = "xori"; break;
		case OP_FUNC_110: m = "ori"; break;
		case OP_FUNC_111: m = "andi"; break;
		default: disasm_err(p); return;
		}
		if (p.mode < DisasmMode.File)
			return;
		
		int imm = i.op >> 20;
		int rs1 = (i.op >> 15) & 31;
		int rd = (i.op >> 7) & 31;
		disasm_push_str(p, m);
		disasm_push_reg(p, rv32_abi_reg(rd));
		disasm_push_reg(p, rv32_abi_reg(rs1));
		disasm_push_imm(p, imm);
		return;
	/*case 0b0100011: // RV32I: SB/SH/SW
		const(char) *m = void;
		switch (opsub & OP_FUNC_MASK) {
		case OP_FUNC_000: m = "sb"; break;
		case OP_FUNC_001: m = "sh"; break;
		case OP_FUNC_010: m = "sw"; break;
		default: disasm_err(p); return;
		}
		if (p.mode < DisasmMode.File)
			return;
		disasm_push_str(p, m);
		return;*/
	default: disasm_err(p);
	}
}

private:

enum OP_FUNC_MASK = OP_FUNC_111;	/// bit[14:12]
enum OP_FUNC_000 = 0;
enum OP_FUNC_001 = 0x1000;
enum OP_FUNC_010 = 0x2000;
enum OP_FUNC_011 = 0x3000;
enum OP_FUNC_100 = 0x4000;
enum OP_FUNC_101 = 0x5000;
enum OP_FUNC_110 = 0x6000;
enum OP_FUNC_111 = 0x7000;
enum OP_MASK = 0x7F;	/// bit[6:0]
enum OP_RVC_FUNC_MASK = OP_RVC_FUNC_111;	/// bit[15:13]
enum OP_RVC_FUNC_000 = 0;
enum OP_RVC_FUNC_001 = 0x2000;
enum OP_RVC_FUNC_010 = 0x4000;
enum OP_RVC_FUNC_011 = 0x6000;
enum OP_RVC_FUNC_100 = 0x8000;
enum OP_RVC_FUNC_101 = 0xA000;
enum OP_RVC_FUNC_110 = 0xC000;
enum OP_RVC_FUNC_111 = 0xE000;

/// Get ABI register name by a 4 or 5-bit field. (e.g. sp instead of x2)
/// Only the first definition is taken (i.e. s0 over fp) to comply with objdump.
/// Params: s = 5-bit selector
/// Returns: Register string
const(char) *rv32_abi_reg(int s) {
	const(char) *m = void;
	switch (s) {
	case 0: m = "zero"; break;
	case 1: m = "ra"; break;
	case 2: m = "sp"; break;
	case 3: m = "gp"; break;
	case 4: m = "tp"; break;
	case 5: m = "t0"; break;
	case 6: m = "t1"; break;
	case 7: m = "t2"; break;
	case 8: m = "s0"; break;
	case 9: m = "s1"; break;
	case 10: m = "a0"; break;
	case 11: m = "a1"; break;
	case 12: m = "a2"; break;
	case 13: m = "a3"; break;
	case 14: m = "a4"; break;
	case 15: m = "a5"; break;
	case 16: m = "a6"; break;
	case 17: m = "a7"; break;
	case 18: m = "s2"; break;
	case 19: m = "s3"; break;
	case 20: m = "s4"; break;
	case 21: m = "s5"; break;
	case 22: m = "s6"; break;
	case 23: m = "s7"; break;
	case 24: m = "s8"; break;
	case 25: m = "s9"; break;
	case 26: m = "s10"; break;
	case 27: m = "s11"; break;
	case 28: m = "t3"; break;
	case 29: m = "t4"; break;
	case 30: m = "t5"; break;
	default: m = "t6"; break;
	}
	return m;
}

/// Get a register (ABI) from the 3-bit field from RVC instructions
/// Params: s = 3-bit value
/// Returns: Register string
const(char) *rv32_rvc_abi_reg(int s) {
	return rv32_abi_reg(s + 8);
}
