/// Symbol facility.
/// 
/// Authors: dd86k <dd@dax.moe>
/// Copyright: © dd86k <dd@dax.moe>
/// License: BSD-3-Clause-Clear
module adbg.symbols;

import adbg.error;
import adbg.machines : AdbgMachine;
import core.stdc.ctype : isdigit;
import core.stdc.string : strcmp, strncpy;
import core.stdc.stdlib : atoi;

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
unittest {
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