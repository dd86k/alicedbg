module tests.readline;

import term;
import core.stdc.stdio;
import core.stdc.string;

unittest {
	puts("Press ^D to exit");
	term_init;
	term_config(TermConfig.noNewline);
	int l = void;
	while (true) {
		printf("> ");
		char* s = term_readline(&l);
		if (s == null)
			return;
		printf("\nl=%u strlen=%u s='%s'\n", l, cast(uint)strlen(s), s);
	}
}