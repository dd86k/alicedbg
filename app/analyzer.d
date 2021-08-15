module analyzer;

import adbg.etc.c.stdio, adbg.disasm.disasm;
import common;

private __gshared const(char)*[] opType = [
	"immediate", "register", "memory"
];
private __gshared const(char)*[] opWith = [
	"i8", "i16", "i32", "i64", "i128", "i256", "i512", "i1024",
	"f16", "f32", "f64", null, null, null, null, null,
];
private __gshared const(char)*[] maTags = [
	"UNKNOWN", "OPCODE", "PREFIX", "OPERAND",
	"IMMEDIATE", "DISP", "MODRM", "SIB",
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
		printf("prefixes   :");
		for (size_t pi; pi < opcode.prefixCount; ++pi) with (opcode) {
			printf(" %s", prefixes[pi]);
		}
		putchar('\n');
		if (opcode.segment)
			printf("segment    : %s\n", opcode.segment);
		with (opcode) printf("mnemonic   : %s\noperands   :", mnemonic);
		for (size_t ai; ai < opcode.operandCount; ++ai) with (opcode) {
			adbg_disasm_operand_t *operand = &operands[ai];
			const(char) *extra = void;
			switch (operand.type) with (AdbgDisasmOperand) {
			case register:  extra = operand.reg.name; break;
			case immediate: extra = opWith[operand.imm.value.type]; break;
			case memory:    extra = opWith[disasm.memWidth]; break;
			default:        extra = "?";
			}
			printf(" %s=%s", opType[operand.type], extra);
		}
		
		// segments
		puts("\n== [ SEGMENTS ] ==================");
		int z = void;
		for (size_t mi; mi < opcode.machineCount; ++mi) with (opcode) {
			adbg_disasm_machine_t *m = &machine[mi];
			ubyte *p8 = &m.u8;
			// NOTE: disasm fetch should be auto swapping these
			switch (m.type) with (AdbgDisasmType) {
			case i8:       z = 1; goto default;
			case i16:      z = 2; goto default;
			case i32, f32: z = 4; goto default;
			case i64, f64: z = 8; goto default;
			default: while (--z >= 0) printf("%02x ", p8[z]);
			}
		}
		putchar('\n');
		size_t tc = opcode.machineCount;
		for (size_t mi; mi < opcode.machineCount; ++mi) with (opcode) {
			for (size_t ti = tc; --ti;) printf(":  ");
			printf(":.. %s\n", maTags[machine[--tc].tag]);
		}
	}
	
	return 0;
}