module dumper;

import core.stdc.stdio;
import core.stdc.stdlib : strtol, EXIT_SUCCESS, EXIT_FAILURE;
import core.stdc.config : c_long;
import core.stdc.stdlib : malloc;
import debugger.disasm;

extern (C):

int dump(const(char) *file, ref disasm_params_t disopt) {
	FILE *f = fopen(file, "rb");

	if (f == null) {
		puts("dump: could not open file");
		return EXIT_FAILURE;
	}

	if (fseek(f, 0, SEEK_END)) {
		puts("dump: could not seek file");
		return EXIT_FAILURE;
	}
	c_long fl = ftell(f);
	fseek(f, 0, SEEK_SET); // rewind is broken

	void *m = cast(void*)malloc(fl);
	if (fread(m, fl, 1, f) == 0) {
		puts("cli: could not read file");
		return EXIT_FAILURE;
	}

	disopt.addr = m;
	for (c_long fi; fi < fl; fi += disopt.addrv - disopt.lastaddr) {
		disasm_line(disopt, DisasmMode.File);
		printf("%08X %-30s %-30s\n",
			cast(uint)fi,
			&disopt.mcbuf, &disopt.mnbuf);
	}
	return 0;
}