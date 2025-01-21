/// Symbol facility.
/// 
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.symbols;

import adbg.error;
import adbg.machines : AdbgMachine;
import adbg.utils.list;
import core.stdc.stdlib : calloc, free;

// Sources:
// - https://itanium-cxx-abi.github.io/cxx-abi/abi.html#mangling

// NOTE: Support notes
//       | Language | Description       |
//       |----------|-------------------|
//       | C        | Varies.           |
//       | C++      | Varies.           |
//       | D        | Uses `_D` prefix. |
//       | Zig      | Uses C names.     |
//       | Rust     | Uses `_R` prefix. |

extern (C):

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
	/// C mangled name. (Most 32-bit targets)
	/// Example: int g(int) -> _g (Windows, 32 and 64 bit targets)
	cdecl,
	/// Windows Standard Call mangled name. (32-bit targets)
	/// Example: (C) int g(int) -> _g@4
	/// Example: (C++) int g(int) -> ?g@@YGHH@Z
	stdcall,
	/// Pascal fastcall mangled name. (32-bit targets)
	/// Example: (C) int g(int) -> @g@4
	/// Example: (C++) int g(int) -> ?g@@YIHH@Z
	fastcall,
	/// C++ mangled name for GCC/Clang.
	/// Example: (C++) int g(int) -> _Z1gi
	gnucpp,
	// C++ mangled name for old GCC (2.9x)
	//oldgnucpp,
	// C++ mangled name for DigitalMars C++.
	//dmcpp,
	// C++ mangled name for Watcom C++ 10.6.
	//watcpp,
	// Objective-C mangled name.
	//objc,
	// Objective-C++ mangled name.
	//objcpp,
	// D mangled name.
	//d,
}

enum AdbgSymbolType {
	unknown, // unused
	label,
}

struct adbg_symbol_t {
	AdbgSymbolType type;
	ulong start;
	//ulong end;
	char[64] name;
}

const(char)* adbg_symbol_name(adbg_symbol_t *sym) {
	if (sym == null)
		return cast(const(char)*)adbg_oops_null(AdbgError.invalidArgument);
	return sym.name.ptr;
}

struct adbg_symbol_list_t {
	list_t *syms;
}

// Used internally for now
// type = Symbol type.
// name = Name string pointer.
// buff = If unset, set to internal buffer size. If set, maximum symbol name length.
// addr = Base address of module, untranslated.
package
adbg_symbol_t adbg_symbol_init(AdbgSymbolType type, char *name, size_t buff, ulong addr) {
	assert(type);
	assert(name);
	
	adbg_symbol_t sym = void;
	sym.type = type;
	sym.start = addr;
	
	if (buff == 0) buff = adbg_symbol_t.name.sizeof;
	size_t i;
	for (; i < buff && name[i] != 0; ++i) {
		sym.name[i] = name[i];
	}
	sym.name[i] = 0;
	
	return sym;
}

// Create a new list of symbols with an identifiable name,
// such as of a module or section.
adbg_symbol_list_t* adbg_symbol_list_create() {
	adbg_symbol_list_t *list = cast(adbg_symbol_list_t*)calloc(1, adbg_symbol_list_t.sizeof);
	if (list == null)
		return cast(adbg_symbol_list_t*)adbg_oops_null(AdbgError.crt);
	
	list.syms = adbg_list_new(adbg_symbol_t.sizeof, 32);
	if (list.syms == null) // Error already set
		return null;
	return list;
}

// Sub modules need to populate entries using this function
int adbg_symbol_list_add(adbg_symbol_list_t *list, adbg_symbol_t *symbol) {
	if (list == null || symbol == null)
		return adbg_oops(AdbgError.invalidArgument);
	
	list.syms = adbg_list_add(list.syms, symbol);
	return list.syms == null ? adbg_error_code() : 0;
}

// Get symbol at location, only debugger needs to translate this address
// Address can be zero, as some symbols can point at the very start of sections
adbg_symbol_t* adbg_symbol_list_at(adbg_symbol_list_t *list, ulong address) {
	if (list == null)
		return cast(adbg_symbol_t*)adbg_oops_null(AdbgError.invalidArgument);
	
	adbg_symbol_t *sym = void;
	for (size_t i; (sym = cast(adbg_symbol_t*)adbg_list_get(list.syms, i)) != null; ++i) {
		if (sym.start == address)
			return sym;
	}
	
	return cast(adbg_symbol_t*)adbg_oops_null(AdbgError.unfindable);
}

// Close symbol list
void adbg_symbol_list_close(adbg_symbol_list_t *list) {
	if (list == null) return;
	adbg_list_close(list.syms);
	free(list);
}

// NOTE: On error, copy string as-is.
/*
size_t adbg_symbol_demangle_guess(char* buffer, size_t bufsize, const(char)* symbol) {
	size_t bi;	/// Buffer index
	size_t si;	/// Symbol index
	if (buffer == null || bufsize == 0 || symbol == null) {
		adbg_oops(AdbgError.invalidArgument);
		return bi;
	}

	enum MBUFSZ = 8; // Tiny buffer to hold numbers
	char[MBUFSZ] mbuf = void;
	char c = void;
	switch (symbol[si++]) {
	case '_': // C, C++, D
		switch (symbol[si++]) {
		case 'Z': // GNU C++
			// Namespace
			bool hasnamespace = symbol[si++] == 'N';
			if (hasnamespace) {
				size_t mi;
				while (isdigit(c = symbol[si]) && mi < MBUFSZ-1) {
					mbuf[mi++] = c;
					si++;
				}
				mbuf[mi] = 0;
				int l = atoi(mbuf.ptr);
				for (int d; (c = symbol[si]) != 0 && d < l && bi < bufsize; ++d) {
					buffer[bi++] = symbol[si++];
				}
				buffer[bi++] = ':';
				buffer[bi++] = ':';
			}
			
			// Class
			bool hasclass = isdigit(c = symbol[si++]) != 0;
			if (hasclass) {
				size_t mi;
				mbuf[mi++] = c;
				while (isdigit(c = symbol[si]) && mi < MBUFSZ-1) {
					mbuf[mi++] = c;
					si++;
				}
				mbuf[mi] = 0;
				int l = atoi(mbuf.ptr);
				for (int d; (c = symbol[si]) != 0 && d < l && bi < bufsize; ++d, ++si) {
					buffer[bi++] = symbol[si];
				}
				buffer[bi++] = ':';
				buffer[bi++] = ':';
			}
			
			// Function signature
			switch (
			
			// Function parameters
			break;
		//case 'D': // D
		//	break;
		case 0:
			goto Lcopyall;
		default: // (C?) Copy past underscore
			for (si = 1; (c = symbol[si++]) != 0 && bi < bufsize; ++bi) {
				buffer[bi] = c;
			}
			break;
		}
		break;
	//case '@':
	//	break;
	case 0:
		adbg_oops(AdbgError.emptyArgument);
		return bi;
	default: // No idea, copy as-is.
	Lcopyall:
		for (si = 0; (c = symbol[si++]) != 0 && bi < bufsize; ++bi) {
			buffer[bi] = c;
		}
	}
	buffer[bi] = 0;
	return bi;
}
extern (D) unittest {
	import core.stdc.string : strncmp;
	import std.stdio : stderr, writefln;
	struct symtest {
		AdbgSymbolMangling type;
		string entry;
		string expected;
	}
	static immutable(symtest)[] symtests = [
		{ AdbgSymbolMangling.exact,
			"example",
			"example" },
		{ AdbgSymbolMangling.cdecl, // 32-bit targets
			"_example",
			"example" },
		{ AdbgSymbolMangling.gnucpp,
			"_ZN11RealSenseID7PreviewC1ERKNS_13PreviewConfigE",
			"RealSenseID::Preview::Preview(RealSenseID::PreviewConfig const&)" },
	];
	char[512] buf = void;
	foreach (ref immutable(symtest) test; symtests) {
		size_t l = adbg_symbol_demangle_guess(buf.ptr, 512, test.entry.ptr);
		if (l == 0 || strncmp(buf.ptr, test.expected.ptr, 512)) {
			stderr.writeln("Demangling error");
			stderr.writeln("  Input   : '", test.entry, "'");
			stderr.writeln("  Expected: '", test.expected, "'");
			stderr.writeln("  Got     : '", buf[0..l], "'");
			assert(false);
		}
	}
}
*/