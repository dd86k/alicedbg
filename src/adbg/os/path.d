/// OS path handling.
///
/// No user code should be using this directly, as it is used internally.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.os.path;

version (Windows) {
	import core.sys.windows.windef : FALSE;
	import core.sys.windows.winbase : GetCurrentDirectoryA, SetCurrentDirectoryA;
} else version (Posix) {
	import core.sys.posix.unistd : chdir, getcwd;
}

import adbg.error;

// Returns: null on error.
const(char)* adbg_os_pwd(char *buffer, uint bsize) {
version (Windows) {
	if (GetCurrentDirectoryA(bsize, buffer) == 0) {
		adbg_oops(AdbgError.os);
		return null;
	}
	return buffer;
} else version (Posix) {
	const(char) *p = getcwd(buffer, bsize); // includes null
	if (p == null) adbg_oops(AdbgError.crt);
	return p;
} else {
	adbg_oops(AdbgError.unimplemented);
	return null;
}
}

int adbg_os_chdir(const(char) *path) {
version (Windows) {
	if (SetCurrentDirectoryA(path) == FALSE)
		return adbg_oops(AdbgError.os);
	return 0;
} else version (Posix) {
	if (chdir(path) < 0)
		return adbg_oops(AdbgError.os);
	return 0;
} else {
	return adbg_oops(AdbgError.unimplemented);
}
}