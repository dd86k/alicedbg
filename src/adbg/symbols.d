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
/// License: BSD-3-Clause-Clear
module adbg.symbols;

//TODO: Symbol mangling guesser (low priority)

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
	/// C mangled name.
	cdecl = exact,
	/// Windows Standard Call mangled name.
	stdcall,
	// C++ mangled name for GCC/Clang.
	//gnucpp,
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


