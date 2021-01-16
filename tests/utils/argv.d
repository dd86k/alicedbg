module tests.utils.argv;

import adbg.utils.str;
import core.stdc.string, core.stdc.stdio;

unittest {
	enum A = "command test 1 2 hello \n ";
	char[512] As = A;
	char*     Ap = cast(char*)As;
	size_t    Al = A.length;
	
	char*[8] _argv = void;
	char**   argv  = cast(char**)_argv;
	
	int argc = adbg_util_argv_expand(Ap, Al, argv);
	
	for (size_t i; i < argc; ++i) {
		printf("argv[%u] %u %s\n",
			cast(uint)i,
			cast(uint)strlen(argv[i]),
			argv[i]);
	}
}