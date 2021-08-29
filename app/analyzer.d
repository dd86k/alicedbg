module analyzer;

import adbg.etc.c.stdio, adbg.disasm.disasm;
import common;

private __gshared const(char)*[] opType = [
	"immediate", "register", "memory"
];
private __gshared const(char)*[] opWith = [
	"none", "far", "f80", null,
	null,null,null,null,
	"i8",   "i16", "i32", "i64", "i128", "i256", "i512", "i1024",
];
private __gshared const(char)*[] maTags = [
	"UNKNOWN",
	"OPCODE",
	"PREFIX",
	"OPERAND",
	"IMMEDIATE",
	"DISPLACEMENT",
	"SEGMENT",
	"MODRM",
	"SIB",
	"REX",
	"VEX",
	"EVEX",
];

int analyze() {
	with (globals.app) {
		// input bytes
		printf("input      : (%u)", cast(uint)inputHexSize);
		for (size_t bi; bi < inputHexSize; ++bi)
			printf(" %02x", inputHex[bi]);
		putchar('\n');
		
		// output bytes
		adbg_disasm_opcode_t opcode = void;
		int err = adbg_disasm_once_buffer(
			&disasm, &opcode, AdbgDisasmMode.file, &inputHex, inputHexSize);
		adbg_disasm_machine(&disasm, bufferMachine.ptr, bufferMachine.sizeof, &opcode);
		printf("output     : (%u) %s\n", opcode.size, bufferMachine.ptr);
		
		if (err) {
			printf("error      : ");
			return printerror();
		}
		
		// mnemonic
		adbg_disasm_mnemonic(&disasm, bufferMnemonic.ptr, bufferMnemonic.sizeof, &opcode);
		printf("instruction: %s\n", bufferMnemonic.ptr);
		printf("prefixes   :");
		for (size_t pi; pi < opcode.prefixCount; ++pi) with (opcode) {
			printf(" %s", prefixes[pi].name);
		}
		putchar('\n');
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
		// 9a 44 33 22 11 bb aa
		// :  :           :.. SEGMENT
		// :  :.. IMMEDIATE
		// :.. OPCODE
		puts("\n== [ SEGMENTS ] ==================");
		adbg_disasm_machine_t *m = void;
		int z = void;
		for (size_t mi; mi < opcode.machineCount; ++mi) with (opcode) {
			m = &machine[mi];
			ubyte *p8 = &m.u8;
			// NOTE: disasm fetch should be auto swapping these
			switch (m.type) with (AdbgDisasmType) {
			case i8:  z = 1; goto default;
			case i16: z = 2; goto default;
			case i32: z = 4; goto default;
			case i64: z = 8; goto default;
			default: while (--z >= 0) printf("%02x ", p8[z]);
			}
		}
		putchar('\n');
		// Machine tags
		//TODO: If last is of the same tag, make it so the same line is used
		//      dc 00
		//      :.. OPCODE
		for (size_t mi = opcode.machineCount; mi--;) with (opcode) {
			m = &machine[mi];
			if (mi) {
				int w = void;
				for (size_t mii; mii < mi; ++mii) {
					switch (machine[mii].type) with (AdbgDisasmType) {
					case i64: w = 7; break;
					case i32: w = 3; break;
					case i16: w = 1; break;
					default:  w = 0; break;
					}
					printf(":  ");
					while (w-- > 0) printf("   ");
				}
			}
			printf(":.. %s\n", maTags[m.tag]);
		}
	}
	
	return 0;
}