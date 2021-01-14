/**
 * License: BSD 3-clause
 */
module adbg.error;

extern (C):
__gshared:

// NOTE: Work in progress

private template ERR(
	ushort E,
	AdbgEModule M = AdbgEModule,
	AdbgESeverity S = AdbgESeverity.info) {
	enum ERR = (M << 24) | (S << 16) | E;
}

private enum modshift = 16;

private enum AdbgEModule : ubyte {
	Debugger,
	Disassembler,
	Object,
	Utilities,
}
private enum AdbgESeverity : ubyte {
	trace,
	debug_,
	info,
	warning,
	error,
	fatal,
}
/// Error
enum AdbgError {
	none,
	nullAddress = ERR!(1, AdbgEModule.Debugger, AdbgESeverity.error),
	unsupportedPlatform = ERR!(2, AdbgEModule.Debugger, AdbgESeverity.error),
	illegalInstruction = ERR!(3, AdbgEModule.Debugger, AdbgESeverity.error),
}

private struct adbg_error_t {
	alias syscode this;
	union {
		int syscode;
		public struct {
			AdbgEModule mod;
			ubyte meta; // severity
			ushort err;
		}
	}
	align(4) bool system;
	debug int line;
	debug const(char) *file;
}
private __gshared adbg_error_t lasterror;

//TODO: debug template with const(char) *f = __FILE__, int l = __LINE__
int adbg_error_set(AdbgError e) {
	lasterror.system = false;
	lasterror.syscode = e;
	return lasterror.syscode;
}

int adbg_error_sys() {
	import adbg.sys.err : adbg_sys_errno;
	lasterror.system = true;
	return lasterror.syscode = adbg_sys_errno;
}

const(char)* adbg_error_message() {
	import adbg.sys.err : adbg_sys_error;
	
	if (lasterror.system)
		return adbg_sys_error(lasterror.syscode);
	
	with (AdbgError)
	switch (lasterror.syscode) {
	// disassembler
	case nullAddress: return "Parameter is null";
	case unsupportedPlatform: return "Platforn not supported";
	case illegalInstruction: return "Illegal instruction encoding";
	// etc
	case none: return "no error";
	default: return "unknown error";
	}
}
