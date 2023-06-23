module tests.utils.argv;

import adbg.utils.string;
import core.stdc.string, core.stdc.stdio;

unittest {
	immutable string[] tests = [
		null,
		"",
		"test",
		"command test",
		"readline\n",
		"readline param\n",
		"decent day, isn't it?",
		"1 2 3 4 5 6 7 8 9",
		"abc\ndef"
	];
	
	int it;
	foreach (line; tests) {
		printf("#%d '%s':\n", ++it, line.ptr);
		
		int argc = void;
		char** argv = adbg_util_expand(line.ptr, &argc);
		if (argv == null) continue;
		
		for (int i; i < argc; ++i) {
			printf("- %d  %3d '%s'\n",
				i+1, cast(int)strlen(argv[i]), argv[i]);
		}
	}
}