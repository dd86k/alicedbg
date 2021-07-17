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

/// Self eror codes
// NOTE: Every thing that could go wrong should have an error code
//TODO: C runtime errors
//TODO: Would E-source#-error# be better?
//      Or make it only our error code and save original OS/source code?
//        e.g.  2 -> internal
//             10 -> os error (better than source enum?) -> GetLastError/errno
//             11 -> external error -> etc.
//      For example, SQLite translates codes (e.g., SQLITE_PERM)
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
	// External
	//
	system = 90,
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

/// Represents an error in alicedbg.
//TODO: Consider removing source code
//      Because we (and user app) can call errno/GetLastError in _msg
struct adbg_error_t {
	int source;	/// Original error code (OS, runtime, etc.)
	int code;	/// Error code
	const(char)* file;	/// File source
	int line;	/// Line source
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
	{ AdbgError.none, "No errors occured." },
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
int adbg_oops(string s = __FILE__, int l = __LINE__)(AdbgError e) {
	error.line = l;
	error.file = s.ptr;
	return error.code = e;
}

/// Internally used to set errors with "system" as source.
/// Params:
/// 	s = (Template) Automatically set to __FILE__
/// 	l = (Template) Automatically set to __LINE__
/// Returns: System error code
int adbg_error_system(string s = __FILE__, int l = __LINE__)() {
	import adbg.sys.err : adbg_sys_errno;
	error.line = l;
	error.file = s.ptr;
	error.source = adbg_sys_errno;
	return error.code = AdbgError.system;
}

/*int adbg_error_runtime() {
	
}*/

//
// ANCHOR Error getters
//

/// Format the last set error code.
/// Returns: Formatted error code
const(char) *adbg_error_ext_code() {
	import core.stdc.stdio : snprintf;
	import adbg.sys.err : SYS_ERR_FMT;
	
	enum _BL = 16; /// internal buffer length
	__gshared char[_BL] m;
	
	snprintf(m.ptr, _BL, "E-%u", error.code);
	return m.ptr;
}

/// Returns an error message with the last error code set.
/// Returns: Error message
// NOTE: Every thing that could go wrong should have an error message
const(char)* adbg_error_msg(int code = error.code) {
	import adbg.sys.err : adbg_sys_error;
	
	with (AdbgError)
	switch (error.code) {
	case system:
		return adbg_sys_error(error.source);
	default:
		foreach (ref e; errors)
			if (code == e.code)
				return e.msg;
		return defaultMsg;
	}
}
