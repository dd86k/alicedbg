module analyzer;

import core.stdc.stdio;
import common;
import adbg.disasm.disasm;

__gshared const(char) *[] operandType = [
	"immediate", "register", "memory"
];

int analyze() {
	printf("input      :");
	for (size_t bi; bi < globals.app.inputHexSize; ++bi)
		printf(" %02x", globals.app.inputHex[bi]);
	printf("\ninput size : %u\n", cast(uint)globals.app.inputHexSize);
	
	with (globals.app) {
		adbg_disasm_start_buffer(&disasm, AdbgDisasmMode.full, &inputHex, inputHexSize);
		
		adbg_disasm_opcode_t opcode = void;
		int errd = adbg_disasm(&disasm, &opcode);
		adbg_disasm_machine(&disasm, bufferMachine.ptr, BUFFER_DISASM_SIZE, &opcode);
		
		printf("output     : %s\noutput size: %u\ninstruction: ",
			bufferMachine.ptr, opcode.size);
		
		if (errd)
			return printerror();
		
		adbg_disasm_mnemonic(&disasm, bufferMnemonic.ptr, BUFFER_DISASM_SIZE, &opcode);
		puts(bufferMnemonic.ptr);
		
		printf("prefixes   :");
		for (size_t pi; pi < opcode.prefixCount; ++pi) {
			printf(" %s", opcode.prefixes[pi]);
		}
		printf("\nmnemonic   : %s\noperands   :\n", opcode.mnemonic);
		for (size_t ai; ai < opcode.operandCount; ++ai) {
			adbg_disasm_operand_t *operand = &opcode.operands[ai];
			printf("\t%u. %s\n", cast(uint)ai, operandType[operand.type]);
		}
	}
	
	return 0;
}