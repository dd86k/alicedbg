/**
 * Error handling module.
 *
 * This module is inspired by the way Windows deal with error codes by
 * compacting them as much as possible in a 32-bit number in the
 * eventuallity that the library is using other libraries.
 *
 * License: BSD-3-Clause
 */
module adbg.error;

extern (C):
__gshared:

//TODO: C runtime errors

/// Create an errorcode.
/// Params:
/// 	mod = Module (0 being generic)
/// 	err = Error code
private template E(ubyte mod, ushort err) {
	enum E = (mod << 24) | err;
}

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
	invalidArgument	= E!(0, 1),
	//
	// Debugger
	//
	
	//
	// Disasembler
	//
	nullAddress	= E!(2, 1),
	unsupportedPlatform	= E!(2, 2),
	illegalInstruction	= E!(2, 3),
	//
	// Object server
	//
	unknownObjFormat	= E!(3, 1),
	unsupportedObjFormat	= E!(3, 2),
	invalidObjPEMachine	= E!(3, 10),
}

private int errcode;
private AdbgErrorSource errsource;
private int errline;
private const(char)* errfile;
private immutable error_t[] errors = [
	// Genrics
	{ AdbgError.invalidArgument, "Invalid parameter" },
	// Debugger
	// Disassembler
	{ AdbgError.nullAddress, "Input address is null" },
	{ AdbgError.unsupportedPlatform, "Platform target not supported" },
	{ AdbgError.illegalInstruction, "Illegal instruction" },
	// Object server
	{ AdbgError.unknownObjFormat, "Invalid object format" },
	{ AdbgError.unsupportedObjFormat, "Unsupported object format" },
	{ AdbgError.invalidObjPEMachine, "Invalid Machine value for PE32 object" },
	
	// Etc.
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
const(char) *adbg_error_format() {
	import core.stdc.stdio : snprintf;
	import adbg.sys.err : SYS_ERR_FMT;
	__gshared char[12] m;
	if (errsource == AdbgErrorSource.self)
		snprintf(m.ptr, 12, "%u.%u".ptr, errcode >> 24, cast(ushort)errcode);
	else
		snprintf(m.ptr, 12, SYS_ERR_FMT, errcode);
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
	case system:
		return adbg_sys_error(errcode);
	case self:
		uint e = errcode;
		foreach (ref err; errors) {
			if (e == err.code)
				return err.msg;
		}
		debug assert(0, "missing error message");
		else  return null;
	default: assert(0);
	}
}

//TODO: unittest all error codes have a message
