/**
 * Common global variables and functions so they can be used throughout the
 * entirety of the program.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module common;

import adbg.config;
import adbg.error;
import adbg.v2.disassembler;
import adbg.v2.debugger.exception;
import core.stdc.stdio : FILE;
import core.stdc.stdlib : malloc;

public:
extern (C):

/// Application error
enum AppError {
	none,
	invalidParameter	= -1,
	invalidCommand	= -2, // or action or sub-command
	unavailable	= -3,
	loadFailed	= -4,
	pauseRequired	= -5,
	alreadyLoaded	= -6,
	alicedbg	= -10,
}

// Platforms

struct setting_platform_t {
	AdbgDasmPlatform val;
	const(char)* opt, alt, desc;
}
immutable setting_platform_t[] platforms = [
	{ AdbgDasmPlatform.x86_16,	"x86_16",  "8086",  "x86 16-bit (real mode)" },
	{ AdbgDasmPlatform.x86_32,	"x86",     "i386",  "x86 32-bit (extended mode)" },
	{ AdbgDasmPlatform.x86_64,	"x86_64",  "amd64", "x86 64-bit (long mode)" },
];

// Syntaxes

struct setting_syntax_t {
	AdbgDasmSyntax val;
	const(char)* opt, desc;
}
immutable setting_syntax_t[] syntaxes = [
	{ AdbgDasmSyntax.att,   "att",   "AT&T syntax" },
	{ AdbgDasmSyntax.intel, "intel", "Intel syntax" },
];

//
// Settings
//

/// Application operating mode
enum SettingMode { debugger, dump, analyze }

/// Debugger UIs
enum SettingUI { cmd, loop, tcpserver }

/// Settings structure for the application (only!)
struct settings_t {
	/// CLI settings
	SettingMode mode;	/// Application mode
	SettingUI ui;	/// Debugger user interface
	const(char) *file;	/// Debuggee: file
	const(char) **args;	/// Debuggee: argument vector
	const(char) **env;	/// Debuggee: environement vector
	const(char) *dir;	/// Debuggee: directory
	uint pid;	/// Debuggee: PID
	uint flags;	/// Flags to pass to sub-app
	AdbgDasmSyntax syntax;	/// 
	AdbgDasmPlatform platform;	/// 
	/// App settings
	adbg_exception_t last_exception;	/// Last exception
	FILE *inputFile;	/// 
	//TODO: Should be allocated
	ubyte[32] inputHex;	/// 
	size_t inputHexSize;	/// 
	char[60] bufferMnemonic;	/// For disassembly
	char[40] bufferMachine;	/// For disassembly
}

/// Global variables. Helps keeping track of app variables.
__gshared settings_t globals;

T* alloc(T)() {
	T* t = cast(T*)malloc(T.sizeof);
	if (t == null) panic(AdbgError.crt);
	return t;
}

// Potentially dangerous since some errors require an additional component
void panic(AdbgError code = AdbgError.success, void *add = null) {
	import core.stdc.stdlib : exit;
	if (code) adbg_oops(code);
	exit(oops());
}


int oops(
	const(char)* func = cast(char*)__FUNCTION__,
	const(char)* mod = cast(char*)__MODULE__,
	int line = __LINE__) {
	import adbg.include.c.stdio : printf, puts;
	import adbg.error : adbg_error_current;
	
	const(adbg_error_t)* error = adbg_error_current;
	
	printf("ERROR-%u: ", adbg_errno);
	switch (error.code) with (AdbgError) {
	case crt:	printf("(CRT:%d) ", adbg_errno_extern); break;
	case os:	printf("(OS:"~ADBG_OS_ERROR_FORMAT~") ", adbg_errno_extern); break;
	case libCapstone:	printf("(CS:%d) ", adbg_errno_extern); break;
	default:
	}
	puts(adbg_error_msg);
	
	debug {
		printf("in %s\n", func);
		printf("  %s:%d\n", mod, line);
		printf("  %s:%d\n", error.mod, error.line);
	}
	
	return error.code;
}
