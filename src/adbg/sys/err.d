/**
 * OS error module.
 *
 * License: BSD 3-clause
 */
module adbg.sys.err;

version (Windows) {
	import core.sys.windows.windows;
	import core.stdc.string : strerror;
	enum ERR_FMT = "0x%08X"; /// Error code format
	private enum ERR_BUF_SZ = 512;
} else {
	import core.stdc.errno : errno;
	import core.stdc.string : strerror;
	enum ERR_FMT = "%d"; /// Error code format
}

extern (C):

/// Get error message from the OS (or CRT) by providing the error code
/// Params:
/// 	code = Error code number from OS
/// Returns: String
const(char) *adbg_sys_error(int code) {
	version (Windows) {
		__gshared char [ERR_BUF_SZ]buffer = void;
		size_t len = FormatMessageA(
			FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_MAX_WIDTH_MASK,
			null,
			code,
			0,	// Default
			cast(char*)buffer,
			ERR_BUF_SZ,
			null);
		return len ? cast(char*)buffer : "Unknown error";
	} else {
		return strerror(code);
	}
}

/// Get the last error code from the OS (or CRT)
/// Returns: GetLastError from Windows, otherwise errno
int adbg_sys_errno() {
	version (Windows)
		return GetLastError;
	else
		return errno;
}

/// Print code and message to std ala perror
/// Params:
/// 	mod = module adbg.name
/// 	code = Error code
void adbg_sys_perror(string mod = null)(int code) {
	import core.stdc.stdio : printf;
	static if (mod == null)
		enum fmt = "("~ERR_FMT~") %s\n";
	else
		enum fmt = mod~": ("~ERR_FMT~") %s\n";
	printf(fmt, code, adbg_sys_error(code));
}