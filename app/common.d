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
import adbg.v1.debugger.exception;
import adbg.v1.disassembler;
import adbg.error;
import core.stdc.stdio : FILE;

public:
extern (C):

/// Application error
enum AppError {
	none,
	invalidParameter,
	invalidCommand, // or action or sub-command
	unavailable,
	loadFailed,
	pauseRequired,
	alreadyLoaded,
}

// Platforms

struct setting_platform_t {
	AdbgPlatform val;
	const(char)* opt, alt, desc;
}
immutable setting_platform_t[] platforms = [
	{ AdbgPlatform.x86_16,	"x86_16",  "8086",  "x86 16-bit (real mode)" },
	{ AdbgPlatform.x86_32,	"x86",     "i386",  "x86 32-bit (extended mode)" },
	{ AdbgPlatform.x86_64,	"x86_64",  "amd64", "x86 64-bit (long mode)" },
	{ AdbgPlatform.riscv32,	"riscv32", "rv32",  "RISC-V 32-bit"},
];

// Syntaxes

struct setting_syntax_t {
	AdbgSyntax val;
	const(char)* opt, desc;
}
static if (USE_CAPSTONE) {
	immutable setting_syntax_t[] syntaxes = [
		{ AdbgSyntax.att,   "att",   "AT&T syntax" },
		{ AdbgSyntax.intel, "intel", "Intel syntax" },
	];
} else {
	immutable setting_syntax_t[] syntaxes = [
		{ AdbgSyntax.att,   "att",   "AT&T syntax" },
		{ AdbgSyntax.intel, "intel", "Intel syntax" },
		{ AdbgSyntax.nasm,  "nasm",  "Netwide Assembler syntax" },
		{ AdbgSyntax.ideal, "ideal", "Borland Ideal Turbo Assembly Enhanced syntax" },
		{ AdbgSyntax.hyde,  "hyde",  "Randall Hyde High Level Assembly Language syntax" },
		{ AdbgSyntax.riscv, "riscv", "RISC-V native syntax" },
	];
}

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
	AdbgSyntax syntax;	/// 
	AdbgPlatform platform;	/// 
	/// App settings
	adbg_disasm_t dism;	/// Disassembler
	exception_t last_exception;	/// Last exception
	FILE *inputFile;	/// 
	//TODO: Should be allocated
	ubyte[32] inputHex;	/// 
	size_t inputHexSize;	/// 
	char[60] bufferMnemonic;	/// For disassembly
	char[40] bufferMachine;	/// For disassembly
}

/// Global variables. Helps keeping track of app variables.
__gshared settings_t globals;

// Potentially dangerous since some errors require an additional component
void panic(AdbgError code = AdbgError.success, void *add = null) {
	import core.stdc.stdlib : exit;
	if (code) adbg_oops(code);
	exit(oops());
}


int oops(const(char)* func = cast(char*)__FUNCTION__,
	const(char)* mod = cast(char*)__MODULE__,
	const(char)* file = cast(char*)__FILE__,
	int line = __LINE__) {
	import adbg.include.c.stdio : printf, puts;
	import adbg.error : adbg_error_current;
	
	const(adbg_error_t)* error = adbg_error_current;
	
	printf("%s: E-%u ", mod, adbg_errno);
	switch (error.code) with (AdbgError) {
	case crt:	printf("(CRT:%d) ", adbg_errno_extern); break;
	case os:	printf("(OS:"~ADBG_OS_ERROR_FORMAT~") ", adbg_errno_extern); break;
	case libCapstone:	printf("(CS:%d) ", adbg_errno_extern); break;
	default:
	}
	puts(adbg_error_msg);
	
	debug {
		printf("%s\n", func);
		printf("\t%s:%d\n", file, line);
		printf("\t%s:%d\n", error.file, error.line);
	}
	
	return error.code;
}

/// Print last library error information to stdout 
deprecated("Use oops")
int printerror(const(char)* func = cast(char*)__FUNCTION__) {
	import adbg.include.c.stdio : printf, puts;
	import adbg.error : adbg_error_current;
	
	const(adbg_error_t)* error = adbg_error_current;
	
	debug printf("[%s:%d] ", error.file, error.line);
	printf("%s: E-%u ", func, adbg_errno);
	switch (error.code) with (AdbgError) {
	case crt: printf("(CRT:%d) ", adbg_errno_extern); break;
	case os: printf("(OS:"~ADBG_OS_ERROR_FORMAT~") ", adbg_errno_extern); break;
	case libCapstone: printf("(CS:%d) ", adbg_errno_extern); break;
	default:
	}
	puts(adbg_error_msg);
	
	return error.code;
}