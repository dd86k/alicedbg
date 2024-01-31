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
/// Maps to a C "short int" type.
alias c_short_int = short;
/// Maps to a C "unsigned short int" type.
alias c_ushort_int = ushort;

// This is a thing because D compilers come with an older MSVCRT version,
// and they are not compatible with the z prefix.
// NOTE: pragma(printf) does not recognize the "I" specifier
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

version (CRuntime_Glibc)
	extern (C) const(char) *gnu_get_libc_version();
