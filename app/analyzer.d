module analyzer;

import adbg.etc.c.stdio, adbg.disasm.disasm;
import common;

private __gshared const(char)*[] operandType = [
	"immediate", "register", "memory"
];
private __gshared const(char)*[] widths = [
	"i8", "i16", "i32", "i64", "i128", "i256", "i512", "i1024",
	"f16", "f32", "f64", null, null, null, null, null,
];

int analyze() {
	with (globals.app) {
		// input bytes
		printf("input      : (%u)", cast(uint)globals.app.inputHexSize);
		for (size_t bi; bi < globals.app.inputHexSize; ++bi)
			printf(" %02x", globals.app.inputHex[bi]);
		putchar('\n');
		
		// output bytes
		adbg_disasm_opcode_t opcode = void;
		int err = adbg_disasm_once_buffer(
			&disasm, &opcode, AdbgDisasmMode.file, &inputHex, inputHexSize);
		adbg_disasm_machine(&disasm, bufferMachine.ptr, BUFFER_DISASM_SIZE, &opcode);
		printf("output     : (%u) %s\n", opcode.size, bufferMachine.ptr);
		
		if (err) return printerror();
		
		// mnemonic
		adbg_disasm_mnemonic(&disasm, bufferMnemonic.ptr, BUFFER_DISASM_SIZE, &opcode);
		printf("instruction: %s\n", bufferMnemonic.ptr);
		
		with (opcode) {
			printf("prefixes   :");
			for (size_t pi; pi < prefixCount; ++pi) {
				printf(" %s", prefixes[pi]);
			}
			if (segment == null)
				segment = "";
			printf("\nsegment    : %s\nmnemonic   : %s\noperands   :", segment, mnemonic);
			for (size_t ai; ai < operandCount; ++ai) {
				adbg_disasm_operand_t *operand = &operands[ai];
				const(char) *extra = void;
				switch (operand.type) with (AdbgDisasmOperand) {
				case register:  extra = operand.reg.name; break;
				case immediate: extra = widths[operand.imm.value.type]; break;
				case memory:    extra = widths[disasm.memWidth]; break;
				default:        extra = "?";
				}
				printf(" %s=%s", operandType[operand.type], extra);
			}
		}
	}
	
	return 0;
}