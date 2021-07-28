module tests.disasm_x86;

import tests.disasm;

immutable InstructionTest[] meta_x86_32 = [
	{	// int3
		[ 0xcc ],
		"int3",
	},
	{	// inc eax
		[ 0x40 ],
		"inc",
	},
	{	// inc ecx
		[ 0x41 ],
		"inc",
	},
	{	// add dword ptr [eax], al
		[ 0x00, 0x00 ],
		"add",
	},
	{	// add dword ptr [eax], eax
		[ 0x01, 0x00 ],
		"add",
	},
	{	// call dword ptr [eax]
		[ 0xff, 0x10 ],
		"call",
	},
	{	// call dword far ptr [eax]
		[ 0xff, 0x18 ],
		"call",
	}
];

/// 
/*unittest {
	writeln("testing x86-16");
	adbg_disasm_t disasm = void;
	adbg_disasm_configure(&disasm, AdbgPlatform.x86_16);
	test(&disasm, x86_16instructions);
}*/
/// 
unittest {
	writeln("testing x86-32");
	adbg_disasm_t disasm = void;
	adbg_disasm_configure(&disasm, AdbgPlatform.x86_32);
	test(&disasm, meta_x86_32);
}
/// 
/*unittest {
	writeln("testing x86-32");
	adbg_disasm_t disasm = void;
	adbg_disasm_configure(&disasm, AdbgPlatform.x86_64);
	test(&disasm, x86_64instructions);
}*/