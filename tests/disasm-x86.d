module tests.disasm_x86;

import adbg.disasm : AdbgDisasmType;
import tests.disasm;

immutable InstructionTest[] meta_x86_16 = [
	{	// add dword ptr [eax], al
		[ 0x00, 0x00 ],
		AdbgError.none,
		"add",
		[
			InstructionOperand(AdbgDisasmType.i32, "bx", "si", 0, 0),
			InstructionOperand("al"),
		]
	},
	{	// add dword ptr [eax], eax
		[ 0x01, 0x00 ],
		AdbgError.none,
		"add",
		[
			InstructionOperand(AdbgDisasmType.i32, "bx", "si", 0, 0),
			InstructionOperand("ax"),
		]
	},
];
immutable InstructionTest[] meta_x86_32 = [
	{	// add dword ptr [eax], al
		[ 0x00, 0x00 ],
		AdbgError.none,
		"add",
		[
			InstructionOperand(AdbgDisasmType.i32, "eax", null, 0, 0),
			InstructionOperand("al"),
		]
	},
	{	// add dword ptr [eax], eax
		[ 0x01, 0x00 ],
		AdbgError.none,
		"add",
		[
			InstructionOperand(AdbgDisasmType.i32, "eax", null, 0, 0),
			InstructionOperand("eax"),
		]
	},
	{	// inc eax
		[ 0x40 ],
		AdbgError.none,
		"inc",
		[
			InstructionOperand("eax")
		]
	},
	{	// inc ecx
		[ 0x41 ],
		AdbgError.none,
		"inc",
		[
			InstructionOperand("ecx")
		]
	},
	{	// int3
		[ 0xcc ],
		AdbgError.none,
		"int3",
	},
	/*{	// call dword ptr [eax]
		[ 0xff, 0x10 ],
		AdbgError.none,
		"call",
	},
	{	// call dword far ptr [eax]
		[ 0xff, 0x18 ],
		AdbgError.none,
		"call",
	}*/
];
immutable InstructionTest[] meta_x86_64 = [
];

/// 
unittest {
	adbg_disasm_t disasm = void;
	adbg_disasm_configure(&disasm, AdbgPlatform.x86_16);
	test("x86-16", &disasm, meta_x86_16);
}
/// 
unittest {
	adbg_disasm_t disasm = void;
	adbg_disasm_configure(&disasm, AdbgPlatform.x86_32);
	test("x86-32", &disasm, meta_x86_32);
}
/// 
unittest {
	adbg_disasm_t disasm = void;
	adbg_disasm_configure(&disasm, AdbgPlatform.x86_64);
	test("x86-64", &disasm, meta_x86_64);
}