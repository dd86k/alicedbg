module tests.disasm;

import std.stdio;
import core.stdc.string : strcmp;
import adbg.disasm;
import adbg.error;

struct InstructionTest {
	ubyte[] data;
	const(char) *expectedMnemonic;
}

void test(adbg_disasm_t *disasm, ref immutable(InstructionTest[]) tests) {
	foreach (immutable(InstructionTest) test; tests) {
		writef("=> %(0x%02x,%): ", test.data);
		
		ubyte *p = cast(ubyte*)test.data.ptr;
		size_t s = test.data.length;
		adbg_disasm_start_buffer(disasm, AdbgDisasmMode.file, p, s);
		
		adbg_disasm_opcode_t op = void;
		int e = adbg_disasm(disasm, &op);
		if (e) {
			printf("E-%u\t%s\n", adbg_errno(), adbg_error_msg());
			continue;
		}
		
		if (strcmp(op.mnemonic, test.expectedMnemonic))
			fail(test, op, "Mnemonic mismatch");
		
		writeln("OK");
	}
}

void fail(ref immutable(InstructionTest) test, ref adbg_disasm_opcode_t op, string msg) {
	writeln("FAILED");
	printf("expected %s\n", test.expectedMnemonic);
	printf("got      %s\n", op.mnemonic);
	//TODO: Print test and op
	assert(0, msg);
}

immutable InstructionTest[] x86_32instructions = [
	{	// int3
		[ 0xcc ],
		"int3",
	},
	{	// inc eax
		[ 0x40 ],
		"inc",
	},
	{	// add dword ptr [eax],al
		[ 0x00, 0x00 ],
		"add",
	},
	{	// add dword ptr [eax],eax
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
	test(&disasm, x86_32instructions);
}
/// 
/*unittest {
	writeln("testing x86-32");
	adbg_disasm_t disasm = void;
	adbg_disasm_configure(&disasm, AdbgPlatform.x86_64);
	test(&disasm, x86_64instructions);
}*/
