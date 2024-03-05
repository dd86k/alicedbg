module tests.readln;

import core.stdc.stdio;
import core.stdc.ctype : isprint;
import term;

extern (C) int putchar(int);

unittest {
	while (true) {
		printf("prompt: ");
		char[] input = conrdln();
		foreach (char c; input)
			if (isprint(c))
				putchar(c);
			else
				printf("\\x%02x", c);
		putchar('\n');
		printf("buffer had %d characters\n", cast(int)input.length);
	}
}