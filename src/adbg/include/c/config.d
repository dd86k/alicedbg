/// Missing definitions in core.stdc.config.
///
/// Authors: dd86k <dd@dax.moe>
/// Copyright: dd86k <dd@dax.moe>
/// License: BSD-3-Clause
module adbg.include.c.config;

public import core.stdc.config;

/// Maps to a C "long int" type.
alias c_longint = c_long;
/// Maps to a C "unsigned long int" type.
alias c_ulongint = c_ulong;

// This is a thing because D compilers come with an older MSVCRT version,
// and they are not compatible with the z prefix.
// NOTE: pragma(printf) does not recognize I specifier
version (CRuntime_Microsoft) { // MSVC v13.0 and earlier (VS2015)
	/// Unsigned integer printf specifier for size_t
	enum PRIzu = "Iu";
	/// Hexadecimal integer printf specifier for size_t
	enum PRIzx = "Ix";
} else {
	/// Ditto
	enum PRIzu = "zu";
	/// Ditto
	enum PRIzx = "zx";
}