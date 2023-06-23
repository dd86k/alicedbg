/**
 * Error handling module.
 *
 * This module is inspired by the way Windows deal with error codes, more or
 * less.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2022 dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module adbg.error;

import adbg.config;

// NOTE: Every thing that could go wrong should have an error code.

extern (C):

/// Self eror codes
enum AdbgError {
	/// Success!
	none	= 0,
	//
	// Generic
	//
	invalidArgument	= 1,
	nullArgument	= 2,
	allocationFailed	= 3,
	uninitiated	= 4,
	notImplemented	= 5,
	assertion	= 80,	/// Soft assert
	//
	// External
	//
	crt	= 90,
	os	= 91,
	loader	= 92,
	capstone	= 93,
	//
	// Debugger
	//
	notAttached = 100,
	//
	// Disasembler
	//
	nullAddress	= 201,
	unsupportedPlatform	= 202,
	invalidOption	= 203,
	invalidOptionValue	= 204,
	illegalInstruction	= 220,
	outOfData	= 221,
	opcodeLimit	= 222,
	//
	// Object server
	//
	unknownObjFormat	= 301,
	unsupportedObjFormat	= 302,
	invalidObjVersion	= 310,
	invalidObjMachine	= 311,
	invalidObjClass	= 312,
	invalidObjEndian	= 313,
	invalidObjType	= 314,
	invalidObjABI	= 315,
}

/// Represents an error in alicedbg.
struct adbg_error_t {
	const(char)* file;	/// File source
	int line;	/// Line source
	int code;	/// Error code
	void *res;	/// Resource
}
/// Last error in alicedbg.
__gshared adbg_error_t error;

private struct error_msg_t {
	uint code;
	const(char) *msg;
}
private immutable const(char) *defaultMsg = "Internal error.";
private immutable error_msg_t[] errors_msg = [
	//
	// Generics
	//
	{ AdbgError.invalidArgument, "Invalid parameter value." },
	{ AdbgError.nullArgument, "Parameter is null." },
	{ AdbgError.allocationFailed, "Memory allocation failed, maybe the machine is out of memory." },
	{ AdbgError.uninitiated, "Object or structure is uninitiated." },
	{ AdbgError.notImplemented, "Unimplemented." },
	{ AdbgError.assertion, "Soft assert." },
	//
	// Debugger
	//
	{ AdbgError.notAttached, "No processes are attached to debugger." },
	//
	// Disassembler
	//
	{ AdbgError.nullAddress, "Input address is null." },
	{ AdbgError.unsupportedPlatform, "Platform target not supported." },
	{ AdbgError.invalidOption, "Invalid disassembler option." },
	{ AdbgError.invalidOptionValue, "Invalid value for disassembler option." },
	{ AdbgError.illegalInstruction, "Illegal instruction." },
	{ AdbgError.outOfData, "The input buffer has been depleted in an unexpected fashion." },
	{ AdbgError.opcodeLimit, "The opcode exhausted its architectural limit." },
	//
	// Object server
	//
	{ AdbgError.unknownObjFormat, "Unknown object format." },
	{ AdbgError.unsupportedObjFormat, "Unsupported object format." },
	{ AdbgError.invalidObjVersion, "Invalid version for object." },
	{ AdbgError.invalidObjMachine, "Invalid machine/platform value for object." },
	{ AdbgError.invalidObjClass, "Invalid class/bitness value for object." },
	{ AdbgError.invalidObjEndian, "Invalid endianess value for object." },
	{ AdbgError.invalidObjType, "Invalid object type." },
	{ AdbgError.invalidObjABI, "Invalid ABI value for object." },
	//
	// Misc.
	//
	{ AdbgError.none, "No errors occured." },
];
version (Windows) {
	import core.sys.windows.windows;
	enum SYS_ERR_FMT = "%08X"; /// Error code format
} else {
	import core.stdc.errno : errno;
	import core.stdc.string : strerror;
	enum SYS_ERR_FMT = "%d"; /// Error code format
}

/// Get error message from the OS (or CRT) by providing the error code
/// Params: code = Error code number from OS
/// Returns: String
const(char) *adbg_sys_error(int code) {
	version (Windows) {
		enum ERR_BUF_SZ = 512;
		__gshared char [ERR_BUF_SZ]buffer = void;
		size_t len = FormatMessageA(
			FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_MAX_WIDTH_MASK,
			null,
			code,
			0,	// Default
			buffer.ptr,
			ERR_BUF_SZ,
			null);
		return len ? cast(char*)buffer : "Unknown error";
	} else {
		return strerror(code);
	}
}

/// Get the last error code from the OS (or CRT)
/// Returns: GetLastError from Windows, otherwise errno
int adbg_sys_errno() {
	version (Windows)
		return GetLastError;
	else
		return errno;
}

/// Print code and message to std ala perror
/// Params:
/// 	mod = module adbg.name
/// 	code = Error code
void adbg_sys_perror(string mod = null)(int code) {
	import core.stdc.stdio : printf;
	static if (mod)
		enum fmt = mod~": ("~SYS_ERR_FMT~") %s\n";
	else
		enum fmt = "("~SYS_ERR_FMT~") %s\n";
	printf(fmt, code, adbg_sys_error(code));
}

//
// ANCHOR Error setters
//

//TODO: Parameters (at least type-safe variadic strings)
//      adbg_oops(code, "param1", 2);
//      or with CS: adbg_oops(code, cs_errno(disasm.cs_handle));
/// Sets the last error code. The module path and line are automatically
/// populated.
/// Params:
/// 	e = Error code
/// 	res = External resource (handle, etc.)
/// 	m = Automatically set to `__MODULE__`
/// 	l = Automatically set to `__LINE__`
/// Returns: Error code
int adbg_oops(AdbgError e, void *res = null, string m = __MODULE__, int l = __LINE__) {
	version (Trace) trace("code=%d res=%p", e, res);
	error.file = m.ptr;
	error.line = l;
	error.res = res;
	return error.code = e;
}

//
// ANCHOR Error getters
//

int adbg_errno() {
	return error.code;
}

int adbg_errno_extern() {
	import core.stdc.errno : errno;
	static if (USE_CAPSTONE) {
		import adbg.include.capstone : cs_errno, csh;
	}
	
	with (AdbgError)
	switch (error.code) {
	case crt:	return errno;
	case os:	return adbg_sys_errno;
	case capstone:	return cs_errno(*cast(csh*)error.res);
	default:	return error.code;
	}
}

/// Returns an error message with the last error code set.
/// Returns: Error message
const(char)* adbg_error_msg(int code = error.code) {
	import core.stdc.errno : errno;
	import core.stdc.string : strerror;
	import bindbc.loader.sharedlib : errors;
	static if (USE_CAPSTONE) import adbg.include.capstone : cs_strerror;
	
	with (AdbgError)
	switch (error.code) {
	case crt: return strerror(errno);
	case os:  return adbg_sys_error(adbg_sys_errno);
	case capstone:  return cs_strerror(adbg_sys_errno);
	case loader:
		if (errors.length)
			return errors()[0].message;
		return defaultMsg;
	default:
		foreach (ref e; errors_msg)
			if (code == e.code)
				return e.msg;
		return defaultMsg;
	}
}

version (Trace) {
	import core.stdc.stdio, core.stdc.stdarg;
	private import adbg.platform : COMPILER_FEAT_PRAGMA_PRINTF;
	
	private extern (C) int putchar(int);
	
	//TODO: Eventually deprecate this for adbg_log_trace
	
	static if (COMPILER_FEAT_PRAGMA_PRINTF) {
		/// Trace application
		pragma(printf)
		void trace(string func = __FUNCTION__, int line = __LINE__)(const(char) *fmt, ...) {
			va_list va;
			va_start(va, fmt);
			printf("TRACE:%s:%u: ", func.ptr, line);
			vprintf(fmt, va);
			putchar('\n');
		}
	} else {
		/// Trace application
		void trace(string func = __FUNCTION__, int line = __LINE__)(const(char) *fmt, ...) {
			va_list va;
			va_start(va, fmt);
			printf("TRACE:%s:%u: ", func.ptr, line);
			vprintf(fmt, va);
			putchar('\n');
		}
	}
}
