/**
 * Common global variables.
 *
 * License: BSD-3-Clause
 */
module app.common;

import adbg.debugger.exception;
import adbg.disasm;
import core.stdc.string : memcpy;

public:
extern (C):
__gshared:

//
// Common global variables
//

/// Common settings shared between sub-modules
settings_t common_settings;

/// Last exception
exception_t common_exception;

//
// Settings
//

/// 
enum SettingMode { debugger, dump, trace }

/// UI setting
enum SettingUI { cmd, loop, tui, server }

//TODO: Consider adding 'bool avoidopt' field
//      Acts as "--", to stop processing options
/// Settings structure for the application (only!)
struct settings_t {
	SettingMode mode;	/// Application mode
	SettingUI ui;	/// Debugger user interface
	adbg_disasm_t disasm;	/// Disassembler settings
	const(char) *file;	/// Debuggee: file
	const(char) **args;	/// Debuggee: argument vector
	const(char) **env;	/// Debuggee: environement vector
	const(char) *dir;	/// Debuggee: directory
	uint pid;	/// Debuggee: PID
	uint flags;	/// 
}
