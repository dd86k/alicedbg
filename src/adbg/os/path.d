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

/// Build a new path that replaces the extension on `base`
/// with `newext` (must include leading dot, e.g. ".pdb").
/// Returns: heap-allocated string or null on failure.
char *adbg_os_replace_ext(const(char) *base, const(char) *newext) {
	if (base == null || newext == null)
		return null;
	
	import core.stdc.stdlib : malloc;
	import core.stdc.string : memcpy, strlen;
	size_t baselen = strlen(base);
	// Find last '.' after the last '/' or '\\'
	ptrdiff_t dot = -1;
	for (ptrdiff_t i = cast(ptrdiff_t)baselen - 1; i >= 0; --i) {
		char c = base[i];
		if (c == '/' || c == '\\') break;
		if (c == '.') { dot = i; break; }
	}
	size_t stem = dot >= 0 ? cast(size_t)dot : baselen;
	size_t extlen = strlen(newext);
	char *out_ = cast(char*)malloc(stem + extlen + 1);
	if (out_ == null) return null;
	memcpy(out_, base, stem);
	memcpy(out_ + stem, newext, extlen + 1);
	return out_;
}
