/**
 * Error handling module.
 *
 * This module is inspired by the way Windows deal with error codes, more or
 * less.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © 2019-2021 dd86k
 * License: BSD-3-Clause
 */
module adbg.error;

// NOTE: Every thing that could go wrong should have an error code.

extern (C):
__gshared:

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
	softAssert	= 80,
	//
	// External
	//
	clib	= 90,
	os	= 91,
	//
	// Debugger
	//
	
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
}
/// Last error in alicedbg.
adbg_error_t error;

private struct error_msg_t {
	uint code;
	const(char) *msg;
}
private immutable const(char) *defaultMsg = "Internal error.";
private immutable error_msg_t[] errors = [
	//
	// Generics
	//
	{ AdbgError.invalidArgument, "Invalid parameter value." },
	{ AdbgError.nullArgument, "Parameter is null." },
	{ AdbgError.allocationFailed, "Memory allocation failed, maybe the machine is out of memory." },
	{ AdbgError.uninitiated, "Object or structure is uninitiated." },
	{ AdbgError.notImplemented, "Unimplemented." },
	{ AdbgError.softAssert, "Soft assert." },
	//
	// Debugger
	//
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

//
// ANCHOR Error setters
//

/// Sets the last error code. The module path and line are automatically
/// populated.
/// Params:
/// 	e = Error code
/// 	m = Automatically set to `__MODULE__`
/// 	l = Automatically set to `__LINE__`
/// Returns: Error code
int adbg_oops(AdbgError e, string m = __MODULE__, int l = __LINE__) {
	error.file = m.ptr;
	error.line = l;
	return error.code = e;
}

//
// ANCHOR Error getters
//

int adbg_errno() {
	return error.code;
}

int adbg_errno_extern() {
	import adbg.sys.err : adbg_sys_errno;
	import core.stdc.errno : errno;
	
	with (AdbgError)
	switch (error.code) {
	case clib: return errno;
	case os:   return adbg_sys_errno;
	default:   return error.code;
	}
}

/// Returns an error message with the last error code set.
/// Returns: Error message
const(char)* adbg_error_msg(int code = error.code) {
	import core.stdc.errno : errno;
	import core.stdc.string : strerror;
	import adbg.sys.err : adbg_sys_error, adbg_sys_errno;
	
	with (AdbgError)
	switch (error.code) {
	case clib: return strerror(errno);
	case os:   return adbg_sys_error(adbg_sys_errno);
	default:
		foreach (ref e; errors)
			if (code == e.code)
				return e.msg;
		return defaultMsg;
	}
}

version (Trace) {
	import core.stdc.stdio, core.stdc.stdarg;
	private import adbg.platform : COMPILER_FEAT_PRAGMA_PRINTF;
	
	private extern (C) int putchar(int);
	
	//TODO: Maybe use mixin() but ehhh
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
