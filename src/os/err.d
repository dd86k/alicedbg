/// OS error module.
module os.err;

version (Windows) {
	/// Error code format
	enum F_ERR = "0x%08X";
	import core.sys.windows.windows;
	import core.sys.windows.winnls;

	private enum LOCALE_NAME_USER_DEFAULT = null;
	private enum LOCALE_ALL = 0;

	extern (Windows)
	private
	int GetLocaleInfoEx(
		LPCWSTR lpLocaleName,
		LCTYPE LCType,
		LPWSTR lpLCData,
		int cchData
	);
} else {
	import core.stdc.errno : errno;
	import core.stdc.string : strerror;
	/// Error code format
	enum F_ERR = "%d";
}

/// Get error message from the OS (or crt) by providing the error code
const(char) *err_msg(int code) {
	version (Windows) {
		__gshared char [512]buffer = void;
		int l = GetLocaleInfoEx( // Recommended over MAKELANGID
			LOCALE_NAME_USER_DEFAULT,
			LOCALE_ALL,
			null,
			0);
		size_t fl = FormatMessageA(
			FORMAT_MESSAGE_FROM_SYSTEM,
			null,
			code,
			l,
			cast(char*)buffer,
			512,
			null);
		// Remove newline
		if (buffer[fl - 2] == '\n')
			buffer[fl - 2] = 0;
		return cast(char*)buffer;
	} else {
		return strerror(code);
	}
}

/// Get the last error code from the OS (or crt)
/// Returns: GetLastError from Windows, otherwise errno
int err_lastcode() {
	version (Windows)
		return GetLastError;
	else
		return errno;
}