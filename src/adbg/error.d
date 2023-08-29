/**
 * Error handling module.
 *
 * This module is inspired by the way Windows deal with error codes, more or
 * less.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: © dd86k <dd@dax.moe>
 * License: BSD-3-Clause
 */
module adbg.error;

version (Windows) {
	import core.sys.windows.windows;
	enum ADBG_OS_ERROR_FORMAT = "%08X"; /// Error code format
} else {
	import core.stdc.errno : errno;
	import core.stdc.string : strerror;
	enum ADBG_OS_ERROR_FORMAT = "%d"; /// Error code format
}

// NOTE: Every thing that could go wrong should have an error code.

//TODO: Consider making all codes negative values.
//      This allows positive values to be used and follows more
//      the "C way" of doing things.
//TODO: Consider prefixing errors with corresponding section (e.g., debuggerNotAttached)

extern (C):

/// Error codes.
///
/// These aren't really meant to be used directly.
enum AdbgError {
	//
	// 0-99: Generic
	//
	success	= 0,
	invalidArgument	= 1,
	nullArgument	= invalidArgument,	// Old alias for invalidArgument
	uninitiated	= 4,	// Only when user value is important like for fopen
	invalidOption	= 5,
	invalidOptionValue	= 6,
	//
	// 100-199: Debugger
	//
	debuggerUnattached = 100,
	debuggerUnpaused = 101,
	debuggerInvalidAction = 102,	/// Wrong action from creation method.
	// Old meanings
	notAttached = debuggerUnattached,	/// Old value for debuggerUnattached
	notPaused = debuggerUnpaused,	/// Old value for debuggerUnpaused
	invalidAction = debuggerInvalidAction,	/// 
	//
	// 200-299: Disasembler
	//
	disasmInvalidAddress = 201,
	disasmUnsupportedMachine = 202,
	disasmIllegalInstruction = 220,
	disasmEndOfData = 221,
	disasmOpcodeLimit = 221,
	// Old meanings
	nullAddress	= disasmInvalidAddress,
	unsupportedPlatform	= disasmUnsupportedMachine,
	illegalInstruction	= disasmIllegalInstruction,
	outOfData	= disasmEndOfData,
	opcodeLimit	= disasmOpcodeLimit,
	//
	// 300-399: Object server
	//
	objectUnknownFormat	= 301,
	objectUnsupportedFormat	= 302,
	objectInvalidVersion	= 310,
	objectInvalidMachine	= 310,
	objectInvalidClass	= 310,
	objectInvalidEndian	= 310,
	objectInvalidType	= 310,
	objectInvalidABI	= 310,
	// Old meanings
	unknownObjFormat	= objectUnknownFormat,
	unsupportedObjFormat	= objectUnsupportedFormat,
	invalidObjVersion	= objectInvalidVersion,
	invalidObjMachine	= objectInvalidMachine,
	invalidObjClass	= objectInvalidClass,
	invalidObjEndian	= objectInvalidEndian,
	invalidObjType	= objectInvalidType,
	invalidObjABI	= objectInvalidABI,
	//
	// 400-499: Debugger memory operations
	//
	scannerDataEmpty	= 400,
	//
	// 1000-1999: Misc
	//
	assertion	= 1000,	/// Soft assert
	unimplemented	= 1001,	/// Not implemented
	todo	= unimplemented,	/// Ditto
	notImplemented	= unimplemented,	/// Old alias to unimplemented
	//
	// 2000-2999: External
	//            Libraries have their own error facilities
	//
	crt	= 2001,
	os	= 2002,
	libLoader	= 2003,
	libCapstone	= 2004,
}

/// Represents an error in alicedbg.
struct adbg_error_t {
	const(char)* mod;	/// Source module
	int line;	/// Line source
	int code;	/// Error code
	void *res;	/// Resource
}
/// Last error in alicedbg.
private __gshared adbg_error_t error;

private struct adbg_error_msg_t {
	uint code;
	const(char) *msg;
}
private immutable const(char) *defaultMsg = "Internal error.";
private immutable adbg_error_msg_t[] errors_msg = [
	//
	// Generics
	//
	{ AdbgError.invalidArgument, "Invalid parameter value." },
	{ AdbgError.nullArgument, "Parameter is null." },
	{ AdbgError.uninitiated, "Object or structure is uninitiated." },
	//
	// Debugger
	//
	{ AdbgError.notAttached, "No processes are attached to debugger." },
	{ AdbgError.notPaused, "Tracee is requied to be stopped for this feature." },
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
	// Memory subsystem
	//
	// Could be a warning?
	{ AdbgError.scannerDataEmpty, "Size of data given to memory scanner is zero." },
	//
	// Misc.
	//
	{ AdbgError.unimplemented, "Feature is not implemented." },
	{ AdbgError.assertion, "A soft assert was hit." },
	{ AdbgError.success, "No errors occured." },
];

/// Get error state instance.
/// Returns: Pointer to the only error instance.
const(adbg_error_t)* adbg_error_current() {
	return &error;
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
private
int adbg_error_system() {
	version (Windows)
		return GetLastError;
	else
		return errno;
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
	error.mod = m.ptr;
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

//TODO: adbg_errno_extern_string ?

int adbg_errno_extern() {
	import core.stdc.errno : errno;
	import adbg.include.capstone : csh, cs_errno;
	
	switch (error.code) with (AdbgError) {
	case crt:	return errno;
	case os:	return adbg_error_system;
	case libCapstone:	return cs_errno(*cast(csh*)error.res);
	default:	return error.code;
	}
}

/// Returns an error message with the last error code set.
/// Returns: Error message
const(char)* adbg_error_msg(int code = error.code) {
	import core.stdc.errno : errno;
	import core.stdc.string : strerror;
	import bindbc.loader.sharedlib : errors;
	import adbg.include.capstone : csh, cs_errno, cs_strerror;
	
	switch (error.code) with (AdbgError) {
	case crt: return strerror(errno);
	case os:  return adbg_sys_error(adbg_error_system);
	case libCapstone:  return cs_strerror(cs_errno(*cast(csh*)error.res));
	case libLoader:
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
	private import adbg.include.d.config : COMPILER_FEAT_PRAGMA_PRINTF;
	
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
