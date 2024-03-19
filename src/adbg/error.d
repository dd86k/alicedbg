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
//      adbg_errorn(AdbgError)
//      - returns null

extern (C):

/// Error codes.
enum AdbgError {
	//
	// 0-99: Generic
	//
	success	= 0,
	invalidArgument	= 1,	/// Argument is null or zero
	nullArgument	= invalidArgument,	// Old alias for invalidArgument
	emptyArgument	= 2,	/// Argument contains an empty dataset
	uninitiated	= 4,	/// Instance was not initiated
	invalidOption	= 5,	/// Invalid option
	invalidValue	= 6,	/// Invalid value for option
	invalidOptionValue	= invalidValue,
	offsetBounds	= 7,	/// File offset is outside of file size
	indexBounds	= 8,	/// Index is outside of bounds of list
	unavailable	= 9,	/// Feature or item is unavailable
	unfindable	= 10,	/// Item cannot be found in list
	//
	// 100-199: Debugger
	//
	debuggerUnattached	= 100,
	debuggerUnpaused	= 101,
	debuggerInvalidAction	= 102,	/// Wrong action from creation method.
	debuggerPresent	= 103,	/// Debugger already present in remote process
	// Old meanings
	notAttached = debuggerUnattached,	/// Old value for debuggerUnattached
	notPaused = debuggerUnpaused,	/// Old value for debuggerUnpaused
	invalidAction = debuggerInvalidAction,	/// 
	//
	// 200-299: Disasembler
	//
	disasmUnsupportedMachine	= 202,
	disasmIllegalInstruction	= 220,
	disasmEndOfData	= 221,
	disasmOpcodeLimit	= 221,
	// Old meanings
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
	objectMalformed	= 304,
	objectItemNotFound	= 305,
	objectInvalidVersion	= 310,
	objectInvalidMachine	= 311,
	objectInvalidClass	= 312,
	objectInvalidEndian	= 313,
	objectInvalidType	= 314,
	objectInvalidABI	= 315,
	objectOutsideBounds	= offsetBounds,
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
	symbolLoadError	= 402,
	symbolBindError	= 403,
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
	{ AdbgError.uninitiated,	"Object or structure is uninitiated." },
	{ AdbgError.invalidOption,	"Option unknown." },
	{ AdbgError.invalidOptionValue,	"Option received invalid value." },
	{ AdbgError.offsetBounds,	"File offset outside file size." },
	{ AdbgError.indexBounds,	"Index outside of list." },
	{ AdbgError.unavailable,	"Feature or item is unavailable." },
	{ AdbgError.unfindable,	"Index outside of list." },
	//
	// Debugger
	//
	{ AdbgError.debuggerUnattached,	"No processes are attached to debugger." },
	{ AdbgError.debuggerUnpaused,	"Process must be paused for this feature." },
	{ AdbgError.debuggerInvalidAction,	"Wrong action given to process." },
	{ AdbgError.debuggerPresent,	"Debugger already present to remote process." },
	//
	// Disassembler
	//
	{ AdbgError.disasmUnsupportedMachine,	"Platform target not supported for disassembler." },
	{ AdbgError.disasmIllegalInstruction,	"An illegal instruction was met." },
	{ AdbgError.disasmEndOfData,	"Disassembler input buffer ran out." },
	{ AdbgError.disasmOpcodeLimit,	"Architectural opcode limit reached." },
	//
	// Object server
	//
	{ AdbgError.objectUnknownFormat,	"Unknown object format." },
	{ AdbgError.objectUnsupportedFormat,	"Unsupported object format." },
	{ AdbgError.objectTooSmall,	"Object is too small to be valid." },
	{ AdbgError.objectMalformed,	"Object potentially corrupted." },
	{ AdbgError.objectItemNotFound,	"Item was not found in object." },
	{ AdbgError.objectInvalidVersion,	"Invalid version for object." },
	{ AdbgError.objectInvalidMachine,	"Invalid machine/platform value for object." },
	{ AdbgError.objectInvalidClass,	"Invalid class/bitness value for object." },
	{ AdbgError.objectInvalidEndian,	"Invalid endianess value for object." },
	{ AdbgError.objectInvalidType,	"Invalid object type." },
	{ AdbgError.objectInvalidABI,	"Invalid ABI value for object." },
	//
	// Symbols
	//
	{ AdbgError.symbolLoadError,	"Could not load any dynamic libraries." },
	{ AdbgError.symbolBindError,	"Could not bind the symbol." },
	//
	// Memory module
	//
	{ AdbgError.scannerDataEmpty,	"Size of data given to memory scanner is empty." },
	{ AdbgError.scannerDataLimit,	"Size of data given to memory scanner is too large." },
	//
	// Misc.
	//
	{ AdbgError.assertion,	"A soft debugging assertion was hit." },
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
/// 	e = Error code.
/// 	res = External resource (handle, etc.).
/// 	m = Automatically set to `__MODULE__`.
/// 	l = Automatically set to `__LINE__`.
/// 	f = Automatically set to `__FUNCTION__`.
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
	case libCapstone:
		if (error.res == null) return 0;
		return cs_errno(*cast(csh*)error.res);
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
		if (error.res == null)
			break;
		return cs_strerror(cs_errno(*cast(csh*)error.res));
	default:
		foreach (ref e; errors_msg)
			if (code == e.code)
				return e.msg;
	}
	return defaultMsg;
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
