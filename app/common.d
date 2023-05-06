/**
 * Common global variables and functions so they can be used throughout the
 * entirety of the program.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2022 dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module common;

import adbg.dbg.exception;
import adbg.disassembler;
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
immutable setting_syntax_t[] syntaxes = [
	{ AdbgSyntax.att,   "att",   "AT&T syntax" },
	{ AdbgSyntax.intel, "intel", "Intel syntax" },
	{ AdbgSyntax.nasm,  "nasm",  "Netwide Assembler syntax" },
	{ AdbgSyntax.ideal, "ideal", "Borland Ideal Turbo Assembly Enhanced syntax" },
	{ AdbgSyntax.hyde,  "hyde",  "Randall Hyde High Level Assembly Language syntax" },
	{ AdbgSyntax.riscv, "riscv", "RISC-V native syntax" },
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
	public struct cli_settings_t {
		SettingMode mode;	/// Application mode
		SettingUI ui;	/// Debugger user interface
		const(char) *file;	/// Debuggee: file
		const(char) **args;	/// Debuggee: argument vector
		const(char) **env;	/// Debuggee: environement vector
		const(char) *dir;	/// Debuggee: directory
		uint pid;	/// Debuggee: PID
		uint flags;	/// Flags to pass to callee
		AdbgSyntax syntax;	/// 
		AdbgPlatform platform;	/// 
	} cli_settings_t cli;	/// CLI settings
	/// App settings
	public struct app_settings_t {	/// 
		adbg_disasm_t disasm;	/// Disassembler
		exception_t last_exception;	/// Last exception
		FILE *inputFile;	/// 
		ubyte[32] inputHex;	/// 
		size_t inputHexSize;	/// 
		char[60] bufferMnemonic;	/// For disassembly
		char[40] bufferMachine;	/// For disassembly
	} app_settings_t app;	/// App settings
}

/// Global variables.
///
/// This is in one big structure to avoid thinking complexity, and avoids
/// tracking other stuff. Like, "uhhh what is the variable name again?".
__gshared settings_t globals;

/// Print last library error information to stdout 
int printerror(const(char)* func = cast(char*)__FUNCTION__) {
	import adbg.etc.c.stdio : printf, puts;
	import adbg.error : error;
	import adbg.sys.err : SYS_ERR_FMT;
	
	debug printf("[%s:%d] ", error.file, error.line);
	printf("%s: E-%u ", func, adbg_errno);
	switch (error.code) with (AdbgError) {
	case crt: printf("(C runtime error %d) ", adbg_errno_extern); break;
	case os: printf("(OS error "~SYS_ERR_FMT~") ", adbg_errno_extern); break;
	default:
	}
	puts(adbg_error_msg);
	
	return error.code;
}