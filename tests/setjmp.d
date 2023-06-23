module tests.sys.setjmp;

import adbg.include.c.setjmp;

/// 
unittest {
	jmp_buf j = void;
	int e = setjmp(j);
	if (e) {
		assert(e == 0xdd, "e != 0xdd");
	} else {
		longjmp(j, 0xdd);
		assert(0, "longjmp");
	}
}