/// Common global variables and functions so they can be used throughout the
/// entirety of the program.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module common;

import core.stdc.stdio : puts;
import core.stdc.stdlib : exit;
import core.stdc.string : strerror;
import core.stdc.errno : errno;
import adbg.error;
import adbg.disassembler;
import adbg.debugger.exception;
import adbg.object.machines : AdbgMachine;
import core.stdc.stdio : FILE;
import core.stdc.stdlib : malloc;

public:
extern (C):

// Platforms

// temporary
struct setting_platform_t {
	AdbgMachine val;
	const(char)* opt, alt, desc;
}
immutable setting_platform_t[] platforms = [
	{ AdbgMachine.i8086,	"x86_16",  "8086",  "x86 16-bit (real mode)" },
	{ AdbgMachine.x86,	"x86",     "i386",  "x86 32-bit (extended mode)" },
	{ AdbgMachine.amd64,	"x86_64",  "amd64", "x86 64-bit (long mode)" },
];

// Syntaxes

struct setting_syntax_t {
	AdbgDisSyntax val;
	const(char)* opt, desc;
}
immutable setting_syntax_t[] syntaxes = [
	{ AdbgDisSyntax.att,   "att",   "AT&T syntax" },
	{ AdbgDisSyntax.intel, "intel", "Intel syntax" },
];

//
// Settings
//

/// Application operating mode
enum SettingMode { debugger, dump, analyze }

/// Debugger UIs
enum SettingUI { cmd, loop, tcpserver }

//TODO: globals should be moved to an internal app API
//      Dedicated shell/dump APIs to set global settings

/// Settings structure for the application (only!)
struct settings_t {
	/// CLI settings
	SettingMode mode;	/// Application mode
	const(char) *file;	/// Debuggee: file
	const(char) **args;	/// Debuggee: argument vector
	const(char) **env;	/// Debuggee: environement vector
	int pid;	/// Debuggee: PID
	int dump_selections;	/// Dumper selections
	int dump_options;	/// Dumper options
	long dump_base_address;	/// Dumper base address (org)
	AdbgMachine machine;	/// Disassembler: Target machine
	AdbgDisSyntax syntax;	/// Disassembler: Syntax
}

/// Global variables. Helps keeping track of app variables.
__gshared settings_t globals;

alias oops = show_error;

int show_error(
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

/// Quit program.
/// Params:
/// 	message = Quit message.
/// 	code = Exit code.
void quit(int code, const(char) *message) {
	puts(message);
	exit(code);
}

enum ErrSource {
	crt,
	adbg,
}

/// Quit due to external factor.
void quitext(ErrSource src,
	const(char)* func = cast(char*)__FUNCTION__,
	const(char)* mod = cast(char*)__MODULE__,
	int line = __LINE__) {
	switch (src) {
	case ErrSource.crt:
		int code = errno;
		puts(strerror(code));
		exit(code);
	case ErrSource.adbg:
		exit(show_error());
	default:
		puts("(Unknown source)");
		exit(1);
	}
}
