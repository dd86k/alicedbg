module tests.disasm;

public import std.stdio;
public import adbg.disasm;
import core.stdc.string : strcmp;
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
			printf("E-%u - %s\n", adbg_errno(), adbg_error_msg());
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
	assert(0, msg);
}
