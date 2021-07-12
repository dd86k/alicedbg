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

extern (C):
__gshared:

//TODO: C runtime errors

private struct error_t {
	uint code;
	const(char) *msg;
}

// Not to be confused for a sub-module
private enum AdbgErrorSource : ubyte {
	/// Comes from this library
	self,
	/// Operating system fault
	system,
	/// (Reserved) Runtime fault
	runtime,
}

/// Self eror codes
// NOTE: Every thing that could go wrong should have an error code
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

private int errcode;
private AdbgErrorSource errsource;
private int errline;
private const(char)* errfile;

private const(char) *defaultMsg = "Internal error.";
private immutable error_t[] errors = [
	//
	// Generics
	//
	{ AdbgError.invalidArgument, "Invalid parameter value." },
	{ AdbgError.nullArgument, "Parameter is null." },
	{ AdbgError.allocationFailed, "Memory allocation failed, maybe the machine is out of memory." },
	{ AdbgError.uninitiated, "Object or structure is uninitiated." },
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
	{ AdbgError.none, "Success" },
];

//
// ANCHOR Error setters
//

/// Internally used to set errors with "self" as source.
/// Params:
/// 	s = (Template) Automatically set to __FILE__
/// 	l = (Template) Automatically set to __LINE__
/// 	e = Error code
/// Returns: Error code
int adbg_error(string s = __FILE__, int l = __LINE__)(AdbgError e) {
	errline = l;
	errfile = s.ptr;
	errsource = AdbgErrorSource.self;
	return errcode = e;
}

/// Internally used to set errors with "system" as source.
/// Params:
/// 	s = (Template) Automatically set to __FILE__
/// 	l = (Template) Automatically set to __LINE__
/// Returns: System error code
int adbg_error_system(string s = __FILE__, int l = __LINE__)() {
	import adbg.sys.err : adbg_sys_errno;
	errline = l;
	errfile = s.ptr;
	errsource = AdbgErrorSource.system;
	return errcode = adbg_sys_errno;
}

/*int adbg_error_runtime() {
	
}*/

//
// ANCHOR Error getters
//

/// Get the last set error code. This can be of any source.
/// Returns: Error code
int adbg_errno() {
	return errcode;
}

/// Format the last set error code.
/// Returns: Formatted error code
const(char) *adbg_error_code() {
	import core.stdc.stdio : snprintf;
	import adbg.sys.err : SYS_ERR_FMT;
	
	enum _BL = 16; /// internall buffer length
	__gshared char[_BL] m;
	
	const(char) *fmt = void;
	with (AdbgErrorSource)
	switch (errsource) {
	case self:   fmt = "E-%u"; break;
	case system: fmt = "E-S"~SYS_ERR_FMT; break;
	default:     assert(0, "adbg_error_code: No source");
	}
	snprintf(m.ptr, _BL, fmt, errcode);
	return m.ptr;
}

/// Get the error file source.
/// Returns: Source filename
const(char)* adbg_error_file() {
	return errfile;
}

/// Get the error line source within the file.
/// Returns: Source line
int adbg_error_line() {
	return errline;
}

/// Returns an error message with the last error code set.
/// Returns: Error message
// NOTE: Every thing that could go wrong should have an error message
const(char)* adbg_error_msg() {
	import adbg.sys.err : adbg_sys_error;
	
	with (AdbgErrorSource)
	switch (errsource) {
	case self:
		uint e = errcode;
		foreach (ref err; errors)
			if (e == err.code)
				return err.msg;
		return defaultMsg;
	case system:
		return adbg_sys_error(errcode);
	default: assert(0, "adbg_error_msg");
	}
}
