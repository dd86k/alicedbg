/**
 * OS error module.
 *
 * License: BSD 3-Clause
 */
module os.err;

version (Windows) {
	import core.sys.windows.windows;
	/// Error code format
	enum F_ERR = "0x%08X";
} else {
	import core.stdc.errno : errno;
	import core.stdc.string : strerror;
	/// Error code format
	enum F_ERR = "%d";
}

/// Get error message from the OS (or CRT) by providing the error code
/// Params:
/// 	code = Error code number from OS
/// Returns: String
const(char) *adbg_err_osmsg(int code) {
	version (Windows) {
		__gshared char [512]buffer = void;
		size_t len = FormatMessageA(
			FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_MAX_WIDTH_MASK,
			null,
			code,
			0,	// Default
			cast(char*)buffer,
			512,
			null);
		return len ? cast(char*)buffer : "(err)";
	} else {
		return strerror(code);
	}
}

/// Get the last error code from the OS (or CRT)
/// Returns: GetLastError from Windows, otherwise errno
int adbg_err_oscode() {
	version (Windows)
		return GetLastError;
	else
		return errno;
}

/// Print code and message to std ala perror
/// Params:
/// 	mod = Module name
/// 	code = Error code
void adbg_err_osprint(const(char) *mod, int code) {
	import core.stdc.stdio : printf;
	printf("%s: ("~F_ERR~") %s\n", mod, code, adbg_err_osmsg(code));
}