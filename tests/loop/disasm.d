module test.loop.disasm;

extern (C) int putchar(int);

import adbg.debugger.disasm;
import core.stdc.stdlib, core.stdc.time;
import std.stdio;

enum BUFSIZE = 3;
enum size_t MAX_COUNTER = 10_000;
enum size_t MAX_STAGE = 6;

/**
	An absolute simple, idiotic, crappy test to force the disasm to break
	
	Due to Windows limiting rand() between 0-32767, the 'random' part
	with 4 number inputs is XOR-hashed and shifted. 
*/
unittest {
	time_t t = void;
	uint tt = time(&t);
	srand(tt ^ tt);
	int[BUFSIZE] b = void;
	ubyte *bp = cast(ubyte*)&b;
	disasm_params_t p = void;
	p.isa = DisasmISA.x86;
	size_t counter;
	size_t stage;
L_BUF:
	for (size_t i; i < BUFSIZE; ++i)
		b[i] = ((rand ^ rand) << 16) | (rand ^ rand);
	if (++counter >= MAX_COUNTER) {
		counter = 0;
		if (++stage >= MAX_STAGE)
			return;
	}
	switch (stage) {
	case 1: bp[0] = 0xf; break;
	case 2:
		bp[0] = 0xf;
		bp[1] = 0x38;
		break;
	case 3:
		bp[0] = 0xf;
		bp[1] = 0x3a;
		break;
	case 4:
		bp[0] = 0x66;
		bp[1] = 0xf;
		bp[2] = 0x38;
		break;
	case 5:
		bp[0] = 0x66;
		bp[1] = 0xf;
		bp[2] = 0x3a;
		break;
	default:
	}
	printf("%u/%4u:", cast(uint)stage, cast(uint)counter);
	for (size_t i; i < BUFSIZE * 4; ++i)
		printf("%02X", bp[i]);
	p.addr = &b;
	adbg_dasm_line(&p, DisasmMode.Size);
//	printf(" %s\n",  &p.mnbuf);
	putchar('\n');
	goto L_BUF;
}