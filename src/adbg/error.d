/// Error handling module.
///
/// NOTE: Every thing that could go wrong should have an error code.
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.error;

version (Windows) {
	import core.sys.windows.winbase : GetLastError, FormatMessageA,
		FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_MAX_WIDTH_MASK;
	enum ADBG_OS_ERROR_FORMAT = "%08X"; /// Error code format
} else {
	enum ADBG_OS_ERROR_FORMAT = "%d"; /// Error code format
}
import core.stdc.errno : errno;
import core.stdc.string : strerror;
import adbg.include.capstone : csh, cs_errno, cs_strerror;

//TODO: Consider making all codes values of 1000 or more.
//TODO: Make module thread-safe
//      Either via TLS and/or atomic operations
//TODO: More error should have context parameters
//      invalidArgument: string stating which argument
//TODO: adbg_error_source -> alicedbg/crt/os/capstone, etc.
//      adbg_error_is_external -> bool
//TODO: Maybe redo error code functions to reduce confusion between errno/external/system/current

extern (C):

/// Error codes.
enum AdbgError {
	//
	// 0-99: Generic
	//
	success	= 0,
	invalidArgument	= 1,
	emptyArgument	= 2,
	uninitiated	= 4,	// Only when user value is important like for fopen
	invalidOption	= 5,
	invalidOptionValue	= 6,
	nullArgument	= invalidArgument,	// Old alias for invalidArgument
	//
	// 100-199: Debugger
	//
	debuggerUnattached = 100,
	debuggerUnpaused = 101,
	debuggerInvalidAction = 102,	/// Wrong action from creation method.
	debuggerPresent = 103,	/// Debugger already present in remote process
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
	objectTooSmall	= 303,
	objectInvalidVersion	= 310,
	objectInvalidMachine	= 311,
	objectInvalidClass	= 312,
	objectInvalidEndian	= 313,
	objectInvalidType	= 314,
	objectInvalidABI	= 315,
	objectOutsideAccess	= 320,
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
	// 400-499: Symbols
	//
	symbolLibraryError	= 401,
	symbolLoadError	= 402,
	//
	// 800-899: Memory scanner
	//
	scannerDataEmpty	= 800,
	scannerDataLimit	= 801,
	//
	// 1000-1999: Misc
	//
	assertion	= 1000,	/// Soft assert
	unimplemented	= 1001,	/// Not implemented
	todo	= unimplemented,	/// Ditto
	notImplemented	= unimplemented,	/// Old alias to unimplemented
	//
	// 2000-2999: External resources
	//
	os	= 2001,
	crt	= 2002,
	//
	// 3000-3999: External libraries
	//
	libLoader	= 3001,	/// BindBC
	libCapstone	= 3002,	/// Capstone
}

/// Represents an error in alicedbg.
struct adbg_error_t {
	const(char)* mod;	/// Source module
	int line;	/// Line source
	int code;	/// Error code
	void *res;	/// External handle or code
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
	{ AdbgError.outOfData, "The input buffer has been depleted." },
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
	// Memory module
	//
	{ AdbgError.scannerDataEmpty, "Size of data given to memory scanner is empty." },
	{ AdbgError.scannerDataLimit, "Size of data given to memory scanner is too large." },
	//
	// Misc.
	//
	{ AdbgError.unimplemented, "Feature is not implemented." },
	{ AdbgError.assertion, "A soft debugging assertion was hit." },
	{ AdbgError.success, "No errors occured." },
];

/// Get error state instance.
/// Returns: Pointer to the only error instance.
//TODO: Deprecate as dangerous
//      Getting extra info such as source (string) and al. should be via functions
const(adbg_error_t)* adbg_error_current() {
	return &error;
}

/// Get error message from the OS (or CRT) by providing the error code
/// Params: code = Error code number from OS
/// Returns: String
const(char)* adbg_sys_error(int code) {
	version (Windows) {
		//TODO: Handle NTSTATUS codes
		enum ERR_BUF_SZ = 256;
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
	version (Windows) {
		return error.res ? cast(uint)error.res : GetLastError();
	} else
		return errno;
}

//
// ANCHOR Error setters
//

/// Sets the last error code. The module path and line are automatically
/// populated.
/// Params:
/// 	e = Error code
/// 	res = External resource (handle, etc.)
/// 	m = Automatically set to `__MODULE__`
/// 	l = Automatically set to `__LINE__`
/// Returns: Error code
int adbg_oops(AdbgError e, void *res = null,
	string m = __MODULE__, int l = __LINE__, const(char)* f = __FUNCTION__.ptr) {
	version (Trace) trace("code=%d res=%p caller=%s:%d", e, res, f, l);
	error.mod = m.ptr;
	error.line = l;
	error.res = res;
	return error.code = e;
}

//
// ANCHOR Error getters
//

/// Obtain the last set code.
/// Returns: Error code.
int adbg_errno() {
	return error.code;
}

/// Obtain the external error code.
/// Returns: Subsystem, library, or OS error code.
int adbg_errno_extern() {
	switch (error.code) with (AdbgError) {
	case crt:	return errno;
	case os:	return adbg_error_system;
	case libCapstone:	return cs_errno(*cast(csh*)error.res);
	default:	return error.code;
	}
}

/// Obtain an error message with the last error code set.
/// Returns: Error message
const(char)* adbg_error_msg(int code = error.code) {
	switch (error.code) with (AdbgError) {
	case crt:
		return strerror(errno);
	case os:
		return adbg_sys_error(adbg_error_system());
	case libCapstone:
		return cs_strerror(cs_errno(*cast(csh*)error.res));
	default:
		foreach (ref e; errors_msg)
			if (code == e.code)
				return e.msg;
		return defaultMsg;
	}
}

version (Trace) {
	import core.stdc.stdio, core.stdc.stdarg;
	private import adbg.include.d.config : D_FEATURE_PRAGMA_PRINTF;
	
	private extern (C) int putchar(int);
	
	static if (D_FEATURE_PRAGMA_PRINTF) {
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
