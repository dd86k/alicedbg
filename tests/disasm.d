module tests.disasm;

public import std.stdio;
public import adbg.disasm, adbg.error;
import core.stdc.string : strcmp;

struct InstructionTest {
	ubyte[] data;
	AdbgError error;
	const(char) *mnemonic;
	InstructionOperand[] operands;
}
struct InstructionOperand {
	AdbgDisasmOperand type;
	union {
		adbg_disasm_operand_imm_t imm;
		adbg_disasm_operand_reg_t reg;
		adbg_disasm_operand_mem_t mem;
	}
	this(int immediate) {
		type = AdbgDisasmOperand.immediate;
		imm.value.i32 = immediate;
	}
	this(const(char) *register) {
		type = AdbgDisasmOperand.register;
		reg.name = register;
	}
	this(AdbgDisasmType width, const(char) *base, const(char) *index, ubyte scale, int offset) {
		type = AdbgDisasmOperand.register;
		mem.base = base;
		mem.index = index;
		mem.scale = scale;
		mem.offset.i32 = offset;
		mem.hasOffset = offset != 0;
	}
}

void test(string name, adbg_disasm_t *disasm, ref immutable(InstructionTest[]) tests) {
	//TODO: Threshold?
	int statTotal, statError;
	L_OPCODE: foreach (immutable(InstructionTest) test; tests) {
		++statTotal;
		
		writef("%-10s  %(0x%02x,%): ", name, test.data);
		
		ubyte *p = cast(ubyte*)&test.data[0];
		size_t s = test.data.length;
		adbg_disasm_opcode_t op = void;
		int e = adbg_disasm_once_buffer(disasm, &op, AdbgDisasmMode.file, p, s);
		
		if (e != test.error) {
			++statError;
			writeln("Error mismatch");
			writefln("            got %s, expected %s", cast(AdbgError)e, test.error);
			continue;
		}
		
		if (strcmp(op.mnemonic, test.mnemonic)) {
			++statError;
			writeln("Mnemonic mismatch");
			printf("            got '%s', expected '%s'", op.mnemonic, test.mnemonic);
			continue;
		}
		
		size_t operandCount = test.operands.length;
		if (operandCount == 0) {
			if (operandCount != op.operandCount) {
				++statError;
				writeln("Operand count mismatch");
				writefln("            expected %u, got %s", operandCount, op.operandCount);
				continue;
			}
			
			for (size_t i; i < operandCount; ++i) {
				immutable(InstructionOperand) *op1 = &test.operands[i];
				adbg_disasm_operand_t *op2 = &op.operands[i];
				
				switch (op1.type) with (AdbgDisasmOperand) {
				case immediate:
					if (op2.type != immediate) {
						++statError;
						writeln("Operand #", i + 1, " type mismatch");
						writefln("            expected %s, got %s", op1.type, op2.type);
						continue L_OPCODE;
					}
					
					
					break;
				case register:
					if (op2.type != register) {
						++statError;
						writeln("Operand #", i + 1, " type mismatch");
						writefln("            expected %s, got %s", op1.type, op2.type);
						continue L_OPCODE;
					}
					
					
					break;
				case memory:
					if (op2.type != memory) {
						++statError;
						writeln("Operand #", i + 1, " type mismatch");
						writefln("            expected %s, got %s", op1.type, op2.type);
						continue L_OPCODE;
					}
					
				
					break;
				default: assert(0, "Unimplemented");
				}
			}
		}
		
		writeln("OK");
	}
	writef("%-10s  ", name);
	if (statError)
		writefln("%u tests out of %u failed", statError, statTotal);
	else
		writefln("all %u tests were successful", statTotal);
}
