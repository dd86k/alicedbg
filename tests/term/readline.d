module tests.term.readline;

import adbg.sys.term;
import core.stdc.stdio;
import core.stdc.string;

unittest {
	char[1024] buf = void;
	char* p = cast(char*)buf;
	adbg_term_init;
	adbg_term_config(TermConfig.readlineNoNewline);
	while (true) {
		printf("> ");
		uint s = cast(uint)adbg_term_readline(p, 1024);
		printf("\nr=%u l=%u s='%s'\n", s, cast(uint)strlen(p), p);
	}
}