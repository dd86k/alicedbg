/**
 * License: BSD-3-Clause
 */
module adbg.error;

extern (C):
__gshared:

// NOTE: Work in progress

private enum modshift = 16;

private enum AdbgESource : ubyte {
	self,
	crt,
	system,
}

/// Error
enum AdbgError {
	none,
	nullArgument,
	nullAddress,
	unsupportedPlatform,
	illegalInstruction,
	unsupportedObjFormat
}

private struct adbg_error_t {
	union {
		int syscode;
		AdbgError code;
	}
	AdbgESource source;
//	debug int line;
//	debug const(char) *file;
}
private __gshared adbg_error_t lasterror;

int adbg_error() {
	return lasterror.syscode;
}

//TODO: debug template with const(char) *f = __FILE__, int l = __LINE__
int adbg_error_set(AdbgError e) {
	lasterror.source = AdbgESource.self;
	return lasterror.syscode = e;
}

int adbg_error_sys() {
	import adbg.sys.err : adbg_sys_errno;
	lasterror.source = AdbgESource.system;
	return lasterror.syscode = adbg_sys_errno;
}
int adbg_error_crt() {
	import adbg.sys.err : adbg_sys_errno;
	lasterror.source = AdbgESource.crt;
	return lasterror.syscode = adbg_sys_errno;
}

const(char)* adbg_error_message() {
	import adbg.sys.err : adbg_sys_error;
	
	with (AdbgESource)
	switch (lasterror.source) {
	case self:
		with (AdbgError)
		switch (lasterror.code) {
		case nullArgument: return "Parameter is null";
		case nullAddress: return "Address is null";
		case unsupportedObjFormat: return "Unsupported object format";
		case unsupportedPlatform: return "Platforn not supported";
		case illegalInstruction: return "Illegal instruction encoding";
		case none: return "no error";
		default: assert(0);
		}
	case crt, system:
		return adbg_sys_error(lasterror.syscode);
	default: assert(0);
	}
}
