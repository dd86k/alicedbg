/**
 * OS error module.
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: See LICENSE
 * License: BSD-3-Clause
 */
module adbg.sys.err;

version (Windows) {
	import core.sys.windows.windows;
	enum SYS_ERR_FMT = "W%08X"; /// Error code format
	private enum ERR_BUF_SZ = 512;
} else {
	import core.stdc.errno : errno;
	import core.stdc.string : strerror;
	enum SYS_ERR_FMT = "L%d"; /// Error code format
}

extern (C):

/// Get error message from the OS (or CRT) by providing the error code
/// Params: code = Error code number from OS
/// Returns: String
const(char) *adbg_sys_error(int code) {
	version (Windows) {
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
	static if (mod)
		enum fmt = mod~": ("~SYS_ERR_FMT~") %s\n";
	else
		enum fmt = "("~SYS_ERR_FMT~") %s\n";
	printf(fmt, code, adbg_sys_error(code));
}