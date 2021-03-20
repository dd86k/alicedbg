/**
 * Common global variables and definitions so they can be used throughout the
 * entirety of the program.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: See LICENSE
 * License: BSD-3-Clause
 */
module common;

import adbg.dbg.exception;
import adbg.disasm;
import adbg.error;
import core.stdc.string : memcpy;

public:
extern (C):
__gshared:

//
// Definitions
//

/// Application error
enum AppError {
	none,
	invalidParameter,
	invalidCommand, // or action or sub-command
	unavailable,
	loadFailed,
	pauseRequired,
}

// Platforms

struct setting_platform_t {
	AdbgDisasmPlatform val;
	immutable(char)* opt, alt, desc;
}
immutable setting_platform_t[] platforms = [
	{ AdbgDisasmPlatform.x86_16, "x86_16",  "8086",  "x86 16-bit (real mode)" },
	{ AdbgDisasmPlatform.x86,    "x86",     "i386",  "x86 32-bit (extended mode)" },
	{ AdbgDisasmPlatform.x86_64, "x86_64",  "amd64", "x86 64-bit (long mode)" },
	{ AdbgDisasmPlatform.rv32,   "riscv32", "rv32",  "RISC-V 32-bit"},
];

// Syntaxes

struct setting_syntax_t {
	AdbgDisasmSyntax val;
	immutable(char)* opt, desc;
}
immutable setting_syntax_t[] syntaxes = [
	{ AdbgDisasmSyntax.att,   "att",   "AT&T syntax" },
	{ AdbgDisasmSyntax.intel, "intel", "Intel syntax" },
	{ AdbgDisasmSyntax.nasm,  "nasm",  "Netwide Assembler syntax" },
];

//
// Common globals
//

/// Common settings shared between sub-modules
settings_t common_settings;
/// Last exception
exception_t common_exception;
/// Disassembler settings
adbg_disasm_t common_disasm;

//
// Settings
//

/// Application operating mode
enum SettingMode { debugger, dump, trace }

/// Debugger UIs
enum SettingUI { cmd, loop, tui, tcpserver }

/// Settings structure for the application (only!)
struct settings_t {
	SettingMode mode;	/// Application mode
	SettingUI ui;	/// Debugger user interface
	const(char) *file;	/// Debuggee: file
	const(char) **args;	/// Debuggee: argument vector
	const(char) **env;	/// Debuggee: environement vector
	const(char) *dir;	/// Debuggee: directory
	uint pid;	/// Debuggee: PID
	uint flags;	/// Flags to pass to callee
}

/// Print last library error information to stdout 
void printerror(const(char)* f = cast(char*)__FUNCTION__)() {
	import adbg.etc.c.stdio : printf;
	debug printf("[%s:%d] ", adbg_error_file, adbg_error_line);
	printf("%s: (%s) %s\n", f, adbg_error_code, adbg_error_msg);
}