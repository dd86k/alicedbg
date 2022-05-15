/**
 * Instruction analyzer.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2022 dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module analyzer;

import adbg.etc.c.stdio, adbg.disassembler;
import common;

private immutable const(char)*[AdbgDisasmOperand.length] opType = [
	"immediate", "register", "memory"
];
private immutable const(char)*[AdbgDisasmType.length] opWith = [
	"none",
	"i8",  "i16", "i32", "i64", "i128", "i256", "i512", "i1024",
	"far", "f80", null, null, null, null, null,
];
private immutable const(char)*[12] maTags = [
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
		//
		// ANCHOR: input bytes
		//
		// input      : (6) 62 f1 7c ca 10 00
		//
		
		printf("input      : (%u)", cast(uint)inputHexSize);
		for (size_t bi; bi < inputHexSize; ++bi)
			printf(" %02x", inputHex[bi]);
		putchar('\n');
		
		//
		// ANCHOR: output bytes
		//
		// output     : (6) 62 f1 7c ca 10 00
		//
		
		adbg_disasm_opcode_t opcode = void;
		int err = adbg_disasm_once_buffer(
			&disasm, &opcode, AdbgDisasmMode.file, &inputHex, inputHexSize);
		adbg_disasm_machine(&disasm, bufferMachine.ptr, bufferMachine.sizeof, &opcode);
		printf("output     : (%u) %s\n", opcode.size, bufferMachine.ptr);
		
		if (err) {
			printf("error      : ");
			return printerror();
		}
		
		//
		// ANCHOR: instruction/prefixes/mnemonic/operands
		//
		// instruction: vmovups zmm0 {k2}{z}, zmmword ptr [rax]
		// prefixes   :
		// mnemonic   : vmovups
		// operands   : register=zmm0 memory=i512
		//
		
		adbg_disasm_format(&disasm, bufferMnemonic.ptr, bufferMnemonic.sizeof, &opcode);
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
		
		//
		// ANCHOR: segments
		//
		// Shamelessly inspired by Zydis
		//
		// == [ SEGMENTS ] ==================
		// 62 f1 7c ca 10 00
		// :           :  :.. MODRM
		// :           :.. OPCODE
		// :.. EVEX
		//
		
		//TODO: Properly support multi-byte opcodes (like.. anything RISC)
		//TODO: Displaying same machine tags
		//      If last is of the same tag, make it so the same line is used
		//      0f 01 00
		//      :     :.. MODRM
		//      :.. OPCODE
		
		puts("\n== [ SEGMENTS ] ==================");
		adbg_disasm_machine_t *m = void;
		int z = void;
		for (size_t mi; mi < opcode.machineCount; ++mi) with (opcode) {
			m = &machine[mi];
			ubyte *p8 = &m.u8;
			// NOTE: disasm fetch should be auto swapping these
			switch (m.type) with (AdbgDisasmType) {
			case i8:  z = 1; break;
			case i16: z = 2; break;
			case i32: z = 4; break;
			case i64: z = 8; break;
			default: continue;
			}
			while (--z >= 0) printf("%02x ", p8[z]);
		}
		putchar('\n');
		// Machine tags
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