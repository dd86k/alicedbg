module tests.disasm_x86;

import adbg.disasm : AdbgDisasmType;
import tests.disasm;

immutable InstructionTest[] meta_x86_16 = [
	{	// add byte ptr [bx+si], al
		[ 0x00, 0x00 ],
		AdbgError.none,
		"add",
		[
			InstructionOperand(AdbgDisasmType.i8, "bx", "si", 0, 0),
			InstructionOperand("al"),
		]
	},
	{	// add word ptr [bx+si], ax
		[ 0x01, 0x00 ],
		AdbgError.none,
		"add",
		[
			InstructionOperand(AdbgDisasmType.i16, "bx", "si", 0, 0),
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
	// SECTION ESCAPES
	{	// fadd dword ptr [eax]
		[ 0xd8, 0x00 ],
		AdbgError.none,
		"fadd",
		[
			InstructionOperand(AdbgDisasmType.i32, "eax", null, 0, 0),
		]
	},
	{	// fmul dword ptr [eax]
		[ 0xd8, 0x09 ],
		AdbgError.none,
		"fmul",
		[
			InstructionOperand(AdbgDisasmType.i32, "ecx", null, 0, 0),
		]
	},
	{	// fcom dword ptr [eax]
		[ 0xd8, 0x10 ],
		AdbgError.none,
		"fcom",
		[
			InstructionOperand(AdbgDisasmType.i32, "eax", null, 0, 0),
		]
	},
	{	// fcomp dword ptr [eax]
		[ 0xd8, 0x18 ],
		AdbgError.none,
		"fcomp",
		[
			InstructionOperand(AdbgDisasmType.i32, "eax", null, 0, 0),
		]
	},
	{	// fsub dword ptr [eax]
		[ 0xd8, 0x20 ],
		AdbgError.none,
		"fsub",
		[
			InstructionOperand(AdbgDisasmType.i32, "eax", null, 0, 0),
		]
	},
	{	// fsubr dword ptr [eax]
		[ 0xd8, 0x28 ],
		AdbgError.none,
		"fsubr",
		[
			InstructionOperand(AdbgDisasmType.i32, "eax", null, 0, 0),
		]
	},
	{	// fdiv dword ptr [eax]
		[ 0xd8, 0x30 ],
		AdbgError.none,
		"fdiv",
		[
			InstructionOperand(AdbgDisasmType.i32, "eax", null, 0, 0),
		]
	},
	{	// fdivr dword ptr [eax]
		[ 0xd8, 0x38 ],
		AdbgError.none,
		"fdivr",
		[
			InstructionOperand(AdbgDisasmType.i32, "eax", null, 0, 0),
		]
	},
	{	// fadd dword ptr [eax]
		[ 0xd8, 0xc1 ],
		AdbgError.none,
		"fadd",
		[
			InstructionOperand("st", true, 1),
		]
	},
	{	// fadd dword ptr [eax]
		[ 0xd8, 0xc9 ],
		AdbgError.none,
		"fmul",
		[
			InstructionOperand("st", true, 1),
		]
	},
	// !SECTION
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