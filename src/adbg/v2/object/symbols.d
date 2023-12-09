/// Dynamic library loader.
///
/// Shared libraries are often known as Dynamic-Link Library (DLL) on Windows
/// and Shared Objects (SO) on POSIX platforms.
/// 
/// This is an enhancement made to fix some annoying BindBC issues.
/// The structure is kept under 4 KiB per instance with static buffers.
///
/// Issue 1: Assertion usage.
/// On error, debug builds stop the whole program on an assertion performed
/// against user data. Unoptimal for optional features.
/// 
/// Issue 2: Error handling.
/// On error, errorCount or SharedLib both need to be checked. Creates pitfalls.
/// This also allocates memory using malloc which is never freed.
/// 
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.v2.object.symbols;

//TODO: Option to load via object server.

// NOTE: Calling dlerror(3) clears the last error

version (Windows) {
	import core.sys.windows.winbase; // LoadLibraryA, FreeLibrary, GetLastError
} else version (Posix) {
	import core.sys.posix.dlfcn; // dlopen, dlclose, dlsym, dladdr, dlinfo, dlerror
}

import adbg.error;
import core.stdc.stdlib : malloc, calloc, free;
import core.stdc.string : memset, strncpy;

extern (C):

private enum SYMBOL_BUFSIZE  = 128;
private enum SYMBOL_BUFCOUNT = 10;

/// Symbol mangling.
///
/// Name mangling regards the ABI of a programming language.
/// Some programming languages, like D, have a particular way
/// to mangle the names of symbols, this in turn, allows for function
/// overloading.
enum AdbgSymbolMangling {
	/// Unknown or no mangling name selected.
	unknown,
	/// Exact mangled symbol name, as given.
	exact,
	/// C mangled name.
	cdecl = exact,
	/// Windows Standard Call mangled name.
	stdcall,
	// C++ mangled name, GCC rules.
	//gnucpp,
	// D mangled name.
	//d,
}
// NOTE: adbg_shared_lib_t should be under a page size.
struct adbg_shared_lib_t {
	void *handle;
	
	size_t missingcnt;
	union {
		char[SYMBOL_BUFSIZE][SYMBOL_BUFCOUNT] missing;
	}
}

/// Load a shared library into memory using OS functions.
/// Params: libraries = List of 
adbg_shared_lib_t* adbg_symbols_load(const(char)*[] libraries...) {
	if (libraries.length == 0) {
		adbg_oops(AdbgError.emptyArgument);
		return null;
	}
	
	// Allocate necessary and clear all fields
	adbg_shared_lib_t *lib = cast(adbg_shared_lib_t*)calloc(1, adbg_shared_lib_t.sizeof);
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
	adbg_oops(AdbgError.symbolLibraryError);
	return null;
}

/// Bind a symbol from the shared library.
/// Params:
/// 	lib = Shared library instance.
/// 	proc = Function pointer instance.
/// 	symbol = Name of the function to bind.
/// Returns: Error code.
int adbg_symbols_bind(adbg_shared_lib_t *lib, void** proc, const(char) *symbol,
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
		// Add symbol to count of missed
		if (lib.missingcnt < SYMBOL_BUFCOUNT) {
			strncpy(cast(char*)&lib.missing[lib.missingcnt++], symbol, SYMBOL_BUFSIZE);
		}
		
		return adbg_oops(AdbgError.symbolLoadError);
	}
	
	return 0;
}

/// Returns the missing symbol count.
/// Returns: Missed symbol count.
size_t adbg_symbols_missingcnt(adbg_shared_lib_t *lib) {
	if (lib == null) return 0;
	return lib.missingcnt;
}
/// Get missing
const(char)* adbg_symbols_missing(adbg_shared_lib_t *lib, size_t index) {
	if (lib == null || index >= lib.missingcnt) return null;
	return cast(const(char)*)&lib.missing[index];
}

void adbg_symbols_close(adbg_shared_lib_t *lib) {
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
