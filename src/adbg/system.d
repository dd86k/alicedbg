/// System interface.
///
/// So far contains a dynamic library loader.
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.system;

version (Windows) {
	import core.sys.windows.winbase; // LoadLibraryA, FreeLibrary, GetLastError
} else version (Posix) {
	import core.sys.posix.dlfcn; // dlopen, dlclose, dlsym, dladdr, dlinfo, dlerror
}

import adbg.symbols;
import adbg.error;
import core.stdc.stdlib : calloc, free;
import core.stdc.string : strncpy;

// NOTE: Calling dlerror(3) clears the last error

//TODO: Consider versioning support
//      Some libraries, like Capstone, can be found in various versions
//      depending on the distrobution.
//      Can try loading version-attached shared libraries and fallback to a default
//      where maybe a callback can be checked against for a specific major version?
//TODO: Format requested symbol into new structure buffer.
//      Should be same size of missing symbols' entry buffer.

extern (C):

//
// Dynamic library loader.
//
// Shared libraries are often known as Dynamic-Link Library (DLL) on Windows
// and Shared Objects (SO) on POSIX platforms.
// 
// This is an enhancement made to fix some annoying BindBC issues.
// The structure is kept under 4 KiB per instance with static buffers.
//
// Issue 1: Assertion usage.
// On error, debug builds stop the whole program on an assertion performed
// against user data. Unoptimal for optional features.
// 
// Issue 2: Error handling.
// On error, errorCount or SharedLib both need to be checked. Creates pitfalls.
// This also allocates memory using malloc which is never freed.
//

private enum SYMBOL_BUFSIZE  = 128;
private enum SYMBOL_BUFCOUNT = 10;

struct adbg_system_library_t {
	void *handle;
	
	size_t missingcnt;
	union {
		char[SYMBOL_BUFSIZE][SYMBOL_BUFCOUNT] missing;
	}
}

/// Load a shared library into memory using OS functions.
///
/// The list is tried in the given order. Returns on the first library loaded.
/// Params: libraries = List of dynamic system libraries to try loading.
/// Returns: Loaded library, or null on error.
adbg_system_library_t* adbg_system_library_load(const(char)*[] libraries...) {
	if (libraries.length == 0) {
		adbg_oops(AdbgError.emptyArgument);
		return null;
	}
	
	// Allocate necessary and clear all fields
	adbg_system_library_t *lib = cast(adbg_system_library_t*)
		calloc(1, adbg_system_library_t.sizeof);
	if (lib == null) {
		adbg_oops(AdbgError.crt);
		return null;
	}
	
	// Try to load libraries.
	// First one to successfully load is returned
	foreach (libname; libraries) {
		version (Windows)
			lib.handle = LoadLibraryA(libname);
		else version (Posix)
			lib.handle = dlopen(libname, RTLD_LAZY);
		else
			static assert(0, "Implement adbg_os_dynload");
		
		if (lib.handle)
			return lib;
	}
	
	// No libraries could be loaded
	free(lib);
	adbg_oops(AdbgError.systemLoadError);
	return null;
}

/// Bind a symbol from the shared library.
/// Params:
/// 	lib = Shared library instance.
/// 	proc = Function pointer instance.
/// 	symbol = Name of the function to bind.
/// 	mangling = Symbol mangling (TODO).
/// Returns: Error code.
int adbg_system_library_bind(adbg_system_library_t *lib, void** proc, const(char) *symbol,
	AdbgSymbolMangling mangling = AdbgSymbolMangling.exact) {
	if (lib == null || lib.handle == null || proc == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	*proc = null;
	version (Windows) {
		*proc = GetProcAddress(lib.handle, symbol);
	} else version (Posix) {
		*proc = dlsym(lib.handle, symbol);
	}
	if (*proc == null) {
		// Add symbol to count of missed symbols.
		adbg_system_library_addmissing(lib, symbol);
		return adbg_oops(AdbgError.systemBindError);
	}
	
	return 0;
}
private
void adbg_system_library_addmissing(adbg_system_library_t *lib, const(char) *symbol) {
	// Check if we can fit more into the buffer.
	if (lib.missingcnt >= SYMBOL_BUFCOUNT)
		return;
	
	strncpy(cast(char*)&lib.missing[lib.missingcnt++], symbol, SYMBOL_BUFSIZE);
}

/// Returns the missing symbol count.
/// Params: lib = Library instance.
/// Returns: Missed symbol count.
size_t adbg_system_library_missingcnt(adbg_system_library_t *lib) {
	if (lib == null) return 0;
	return lib.missingcnt;
}
/// Get missing symbol name by index.
/// Params:
/// 	lib = Library instance.
/// 	index = Index.
/// Returns: Missing symbol.
const(char)* adbg_system_library_missing(adbg_system_library_t *lib, size_t index) {
	if (lib == null || index >= lib.missingcnt) return null;
	return cast(const(char)*)&lib.missing[index];
}
extern (D) unittest {
	adbg_system_library_t lib;
	adbg_system_library_addmissing(&lib, "test");
	adbg_system_library_addmissing(&lib, "some_long_name_that_should_fit_the_buffer_anyway");
	
	assert(adbg_system_library_missing(&lib, 0));
	assert(adbg_system_library_missing(&lib, 1));
	assert(adbg_system_library_missing(&lib, 2) == null);
	assert(adbg_system_library_missing(null, 2) == null);
}

void adbg_system_library_close(adbg_system_library_t *lib) {
	if (lib == null) return;
	
	if (lib.handle) {
		version (Windows)
			FreeLibrary(lib.handle);
		else version (Posix)
			dlclose(lib.handle);
		else
			static assert(0, "Implement adbg_os_dynunload");
		lib.handle = null;
	}
	
	free(lib);
}