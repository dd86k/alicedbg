module tests.term.readline;

import term;
import core.stdc.stdio;
import core.stdc.string;

unittest {
	term_init;
	term_config(TermConfig.readlineNoNewline);
	int l = void;
	while (true) {
		printf("> ");
		char* s = term_readline(&l);
		printf("\nl=%u strlen=%u s='%s'\n", l, cast(uint)strlen(s), s);
	}
}