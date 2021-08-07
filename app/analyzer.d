module analyzer;

import core.stdc.stdio;
import common;
import adbg.disasm.disasm;

__gshared const(char)*[] operandType = [
	"immediate", "register", "memory"
];
__gshared const(char)*[] widths = [
	"i8", "i16", "i32", "i64", "i128", "i256", "i512", "i1024",
	"f16", "f32", "f64", null, null, null, null, null,
];

int analyze() {
	printf("input      : (%u)", cast(uint)globals.app.inputHexSize);
	for (size_t bi; bi < globals.app.inputHexSize; ++bi)
		printf(" %02x", globals.app.inputHex[bi]);
	
	with (globals.app) {
		adbg_disasm_start_buffer(&disasm, AdbgDisasmMode.full, &inputHex, inputHexSize);
		
		adbg_disasm_opcode_t opcode = void;
		int errd = adbg_disasm(&disasm, &opcode);
		adbg_disasm_machine(&disasm, bufferMachine.ptr, BUFFER_DISASM_SIZE, &opcode);
		
		printf("\noutput     : (%u) %s\ninstruction: ", opcode.size, bufferMachine.ptr);
		
		if (errd)
			return printerror();
		
		adbg_disasm_mnemonic(&disasm, bufferMnemonic.ptr, BUFFER_DISASM_SIZE, &opcode);
		puts(bufferMnemonic.ptr);
		
		with (opcode) {
			printf("prefixes   :");
			for (size_t pi; pi < prefixCount; ++pi) {
				printf(" %s", prefixes[pi]);
			}
			printf("\nsegment    : %s\nmnemonic   : %s\noperands   :\n", segment, mnemonic);
			for (size_t ai; ai < operandCount; ++ai) {
				adbg_disasm_operand_t *operand = &operands[ai];
				const(char) *extra = void;
				switch (operand.type) with (AdbgDisasmOperand) {
				case register:  extra = operand.reg.name; break;
				case immediate: extra = widths[operand.imm.value.type]; break;
				case memory:    extra = widths[disasm.memWidth]; break;
				default:        extra = "?";
				}
				printf("\t%u. %s: %s\n", cast(uint)ai, operandType[operand.type], extra);
			}
		}
	}
	
	return 0;
}