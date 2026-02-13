module tests.easy;

import adbg.easy;
import std.stdio : writeln;

void enforce(bool cond, string func,
	size_t line = __LINE__, string file = __FILE__) {
	if (cond) return;
	
	import std.string : fromStringz;
	import std.conv : text;
	
	const(char) *aerr = adbg_error_message();
	int acode = adbg_error_code();
	int aline = adbg_error_line();
	const(char)* afunc = adbg_error_function();
	
	throw new Exception(
		text(func,": (", acode, "@", fromStringz(afunc), ":", aline, ") ", fromStringz(aerr)),
		file, line);
}

enum SRC = "tests/easy-target.d";
version (Windows) enum EXEC="easy-target.exe";
else              enum EXEC="./easy-target";
import std.file : exists;
import std.process : spawnProcess, Pid;

/// Example of spawning
unittest {
	// 0. Check if target exists
	//    Unbothered to detect dmd/gdc/ldc and perform a compile
	//    Do that yourself
	if (exists(EXEC) == false) {
		writeln("easy: target does not exist");
		writeln("easy: compile '", SRC, "' as '", EXEC, "'");
		writeln("easy: then re-run this test");
		assert(false, "Compile target and run this test again");
	}
	
	// 1. Create easy instance
	adbg_easy_t *ez = adbg_easy_create();
	enforce(ez != null, "adbg_easy_create");
	
	// 2. Spawn executable
	enforce(adbg_easy_spawn(ez, EXEC) == 0, "adbg_easy_spawn");
	
	// 3. Is it really alive?
	enforce(adbg_easy_process_is_alive(ez) > 0, "adbg_easy_process_is_alive");
	
	// Destroy! We'll know if it hangs
	adbg_easy_destroy(ez);
}

/// Example of attaching
unittest {
	// 0. Check if target exists
	//    Unbothered to detect dmd/gdc/ldc and perform a compile
	//    Do that yourself
	if (exists(EXEC) == false) {
		writeln("easy: target does not exist");
		writeln("easy: compile '", SRC, "' as '", EXEC, "'");
		writeln("easy: then re-run this test");
		assert(false, "Compile target and run this test again");
	}
	
	// 1. Create easy instance
	adbg_easy_t *ez = adbg_easy_create();
	enforce(ez != null, "adbg_easy_create");
	
	// 2. Spawn executable and attach to it
	Pid proc = spawnProcess([ EXEC, "1" ]);
	enforce(adbg_easy_attach(ez, proc.processID) == 0, "adbg_easy_attach");
	
	// 3. Is it really alive?
	enforce(adbg_easy_process_is_alive(ez) > 0, "adbg_easy_process_is_alive");
	
	// Destroy! We'll know if it hangs
	adbg_easy_destroy(ez);
}
