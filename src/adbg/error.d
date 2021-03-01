/**
 * License: BSD-3-Clause
 */
module adbg.error;

//TODO: Add template variables for debugging purposes
// - const(char) *f = __FILE__
// - int l = __LINE__

extern (C):
__gshared:

private enum AdbgErrorSource : ubyte {
	/// This program is the source of the error
	self,
	/// Operating system fault
	system,
	/// (Reserved) Runtime fault
	runtime,
}

/// Error code
enum AdbgError {
	/// Alas, success
	none,
	/// OS
	system,
	/// (Reserved) CRT
	runtime,
	nullArgument,
	nullAddress,
	unsupportedPlatform,
	illegalInstruction,
	unsupportedObjFormat
}

private int errcode;
private AdbgErrorSource errsource;
private int errline;
private const(char)* errfile;

//
// "Getters"
//

int adbg_errno() {
	return errcode;
}
int adbg_error_line() {
	return errline;
}
const(char)* adbg_error_file() {
	return errfile;
}
const(char)* adbg_error_msg() {
	import adbg.sys.err : adbg_sys_error;
	
	with (AdbgErrorSource)
	switch (errsource) {
	case system:
		return adbg_sys_error(errcode);
	case self:
		with (AdbgError)
		switch (errcode) {
		case nullArgument: return "Parameter is null";
		case nullAddress: return "Address is null";
		case unsupportedObjFormat: return "Unsupported object format";
		case unsupportedPlatform: return "Platforn not supported";
		case illegalInstruction: return "Illegal instruction encoding";
		case none: return "No error occured";
		default: assert(0);
		}
	default: assert(0);
	}
}

//
// "Setters"
//

int adbg_error(string s = __FILE__, int l = __LINE__)(AdbgError e) {
	errline = l;
	errfile = s.ptr;
	errsource = AdbgErrorSource.self;
	return errcode = e;
}

//public enum __FUNCTION_NAME__ = __traits(identifier, __traits(parent, {}));
private template FN(alias s)
{
	enum { FN = __traits(identifier, __traits(parent, s)) }
}

int adbg_error_system(string s = __FILE__, int l = __LINE__)() {
	import adbg.sys.err : adbg_sys_errno;
	errline = l;
	errfile = s.ptr;
	errsource = AdbgErrorSource.system;
	return errcode = adbg_sys_errno;
}

/*int adbg_error_runtime() {
	
}*/
