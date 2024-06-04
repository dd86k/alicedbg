/// Error handling module.
///
/// NOTE: Every thing that could go wrong should have an error code.
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
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

//TODO: Make module thread-safe
//      Either via TLS and/or atomic operations
//TODO: More error should have context parameters
//      invalidArgument: string stating which argument
//TODO: adbg_error_source -> alicedbg/crt/os/capstone, etc.
//      adbg_error_is_external -> bool
//TODO: Maybe redo error code functions to reduce confusion between errno/external/system/current
//TODO: Error utils
//      adbg_ensure_params(lvalue, "name")
//      - returns string if null found
//      - automatically set error code
//      adbg_oopsn(AdbgError)
//      - returns null

extern (C):

/// Error codes.
enum AdbgError {
	//
	// 0-99: Generic
	//
	success	= 0,
	invalidArgument	= 1,	/// Argument is null or zero
	emptyArgument	= 2,	/// Argument contains an empty dataset
	uninitiated	= 4,	/// Instance was not initiated
	invalidOption	= 5,	/// Invalid option
	invalidValue	= 6,	/// Invalid value for option
	offsetBounds	= 7,	/// File offset is outside of file size
	indexBounds	= 8,	/// Index is outside of bounds of list
	unavailable	= 9,	/// Feature or item is unavailable
	unfindable	= 10,	/// Item cannot be found in list
	partialRead	= 11,	/// Not all data could be read.
	partialWrite	= 12,	/// Not all data could be written.
	//
	// 100-199: Debugger
	//
	debuggerUnattached	= 100,
	debuggerUnpaused	= 101,
	debuggerInvalidAction	= 102,	/// Wrong action from creation method.
	debuggerPresent	= 103,	/// Debugger already present in remote process
	//
	// 200-299: Disasembler
	//
	disasmUnsupportedMachine	= 202,
	disasmIllegalInstruction	= 220,
	disasmEndOfData	= 221,
	disasmOpcodeLimit	= 221,
	//
	// 300-399: Object server
	//
	objectUnknownFormat	= 301,
	objectUnsupportedFormat	= 302,
	objectTooSmall	= 303,
	objectMalformed	= 304,
	objectItemNotFound	= 305,
	objectInvalidVersion	= 310,
	objectInvalidMachine	= 311,
	objectInvalidClass	= 312,
	objectInvalidEndian	= 313,
	objectInvalidType	= 314,
	objectInvalidABI	= 315,
	//
	// 400-499: System
	//
	systemLoadError	= 402,
	systemBindError	= 403,
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
	//
	// 2000-2999: External resources
	//
	os	= 2001,
	crt	= 2002,
	//
	// 3000-3999: External libraries
	//
	libCapstone	= 3002,	/// Capstone
}

/// Represents an error in alicedbg.
struct adbg_error_t {
	const(char)* mod;	/// Source module
	int line;	/// Line source
	int code;	/// Error code
	void *handle;	/// External handle or code
}
/// Last error in alicedbg.
private __gshared adbg_error_t error;

//TODO: Strongly consider string, provides .ptr and .length
private struct adbg_error_msg_t {
	int code;
	const(char) *msg;
}
private immutable const(char) *defaultMsg = "Unknown error occured.";
private immutable adbg_error_msg_t[] errors_msg = [
	//
	// Generics
	//
	{ AdbgError.invalidArgument,	"Invalid or missing parameter value." },
	{ AdbgError.emptyArgument,	"Parameter is empty." },
	{ AdbgError.uninitiated,	"Object or structure requires to be initialized first." },
	{ AdbgError.invalidOption,	"Option unknown." },
	{ AdbgError.invalidValue,	"Option received invalid value." },
	{ AdbgError.offsetBounds,	"File offset outside file size." },
	{ AdbgError.indexBounds,	"Index outside of list." },
	{ AdbgError.unavailable,	"Feature or item is unavailable." },
	{ AdbgError.unfindable,	"Item was not found." },
	//
	// Debugger
	//
	{ AdbgError.debuggerUnattached,	"Debugger needs to be attached for this feature." },
	{ AdbgError.debuggerUnpaused,	"Debugger needs the process to be paused for this feature." },
	{ AdbgError.debuggerInvalidAction,	"Debugger was given a wrong action for this process." },
	{ AdbgError.debuggerPresent,	"Debugger already present on remote process." },
	//
	// Disassembler
	//
	{ AdbgError.disasmUnsupportedMachine,	"Disassembler does not support this platform." },
	{ AdbgError.disasmIllegalInstruction,	"Disassembler met an illegal instruction." },
	{ AdbgError.disasmEndOfData,	"Disassembler reached end of data." },
	{ AdbgError.disasmOpcodeLimit,	"Disassembler reached architectural opcode limit." },
	//
	// Object server
	//
	{ AdbgError.objectUnknownFormat,	"Object format unknown." },
	{ AdbgError.objectUnsupportedFormat,	"Object format unsupported." },
	{ AdbgError.objectTooSmall,	"Object is too small to be valid." },
	{ AdbgError.objectMalformed,	"Object potentially corrupted." },
	{ AdbgError.objectItemNotFound,	"Object item was not found." },
	{ AdbgError.objectInvalidVersion,	"Object has invalid version." },
	{ AdbgError.objectInvalidMachine,	"Object has invalid machine or platform value." },
	{ AdbgError.objectInvalidClass,	"Object has invalid class or bitness value." },
	{ AdbgError.objectInvalidEndian,	"Object has invalid endian value." },
	{ AdbgError.objectInvalidType,	"Object type invalid." },
	{ AdbgError.objectInvalidABI,	"Object has Invalid ABI value." },
	//
	// Symbols
	//
	{ AdbgError.systemLoadError,	"Dynamic library could not be loaded." },
	{ AdbgError.systemBindError,	"Symbol could not be binded." },
	//
	// Memory module
	//
	{ AdbgError.scannerDataEmpty,	"Memory scanner received empty data." },
	{ AdbgError.scannerDataLimit,	"Memory scanner received too much data." },
	//
	// Misc.
	//
	{ AdbgError.assertion,	"A soft debug assertion was hit." },
	{ AdbgError.unimplemented,	"Feature is not implemented." },
	{ AdbgError.success,	"No errors occured." },
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

/// Get the last error code from the OS (or CRT).
/// Returns: GetLastError from Windows, otherwise errno.
private
int adbg_error_system() {
	version (Windows) {
		return error.handle ? cast(uint)error.handle : GetLastError();
	} else
		return errno;
}

//
// ANCHOR Error setters
//

/// Sets the last error code. The module path and line are automatically
/// populated.
/// Params:
/// 	e = Error code.
/// 	extra = External resource (handle, code, etc.).
/// 	m = Automatically set to `__MODULE__`.
/// 	l = Automatically set to `__LINE__`.
/// 	f = Automatically set to `__FUNCTION__`.
/// Returns: Error code
int adbg_oops(AdbgError e, void *extra = null,
	string m = __MODULE__, int l = __LINE__, const(char)* f = __FUNCTION__.ptr) {
	version (Trace) trace("code=%d res=%p caller=%s:%d", e, extra, f, l);
	error.mod = m.ptr;
	error.line = l;
	error.handle = extra;
	return error.code = e;
}

//
// ANCHOR Error getters
//

/// Obtain the last set code.
/// Returns: Error code.
export
int adbg_errno() {
	return error.code;
}

/// Obtain the external error code.
/// Returns: Subsystem, library, or OS error code.
int adbg_errno_extern() {
	switch (error.code) with (AdbgError) {
	case crt:	return errno;
	case os:	return adbg_error_system;
	case libCapstone:
		return error.handle ? cs_errno(*cast(csh*)error.handle) : 0;
	default:	return error.code;
	}
}

/// Obtain an error message with code.
/// Returns: Error message.
export
const(char)* adbg_error_msg(int code) {
	switch (code) with (AdbgError) {
	case crt:
		return strerror(errno);
	case os:
		return adbg_sys_error(adbg_error_system());
	case libCapstone:
		if (error.handle == null)
			break;
		return cs_strerror(cs_errno(*cast(csh*)error.handle));
	default:
		foreach (ref e; errors_msg)
			if (code == e.code)
				return e.msg;
	}
	return defaultMsg;
}

/// Get the last set error message.
/// Returns: Error message.
export
const(char)* adbg_error_message() {
	return adbg_error_msg(error.code);
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
