module tests.easy;

import adbg.easy;


void enforce(bool cond, string msg,
	size_t line = __LINE__, string file = __FILE__) {
	if (cond) return;
	
	import std.string : fromStringz;
	import std.conv : text;
	
	const(char) *err = adbg_error_message();
	
	throw new Exception(
		text(msg,": ", fromStringz(err)),
		file, line);
}

unittest {
	enum SRC = "tests/easy-target.d";
	version (Windows) enum EXEC="easy-target.exe";
	else              enum EXEC="./easy-target";
	
	import std.file : exists;
	
	// 0. Check if target exists
	//    Unbothered to detect dmd/gdc/ldc and perform a compile
	//    Do that yourself
	if (exists(EXEC) == false) {
		import std.stdio : writeln;
		writeln("easy: target does not exist");
		writeln("easy: compile '", SRC, "' as '", EXEC, "'");
		writeln("easy: then re-run this test");
		return;
	}
	
	// 1. Create EZ instance
	adbg_easy_t *ez = adbg_easy_create();
	enforce(ez != null, "adbg_easy_create");
	
	// 2. Spawn executable
	enforce(adbg_easy_spawn(ez, EXEC) == 0, "adbg_easy_spawn");
}