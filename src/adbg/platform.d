/**
 * Compile constants
 *
 * Authors: dd86k <dd@dax.moe>
 * Copyright: See LICENSE
 * License: BSD-3-Clause
 */
module adbg.platform;

// Other interesting versions:
// - DRuntime_Use_Libunwind
// - LDC_LLVM_ (LLVM version, e.g., 1100 for 11.0)

extern (C):

//
// ANCHOR Compile settings
//

/// Amount of pointers to allocate
enum ADBG_CLI_ARGV_ARRAY_COUNT	= 16;
/// Length of array for argv parsing
enum ADBG_CLI_ARGV_ARRAY_LENGTH	= ADBG_CLI_ARGV_ARRAY_COUNT * size_t.sizeof;
/// The maximum amount of breakpoints that the debugger can have.
enum ADBG_MAX_BREAKPOINTS	= 4;
/// Child stack size if USE_CLONE is specified.
enum ADBG_CHILD_STACK_SIZE	= 1024 * 1024 * 8;

//
// Constants
//

/// Library and application version
enum ADBG_VERSION = "0.0.1";

debug enum __BUILDTYPE__ = "debug";	/// Build type
else  enum __BUILDTYPE__ = "release";	/// Build type

/// Target information structure
struct adbg_info_t {
	const(char) *adbgver = ADBG_VERSION;	/// Library/app version
	const(char) *build   = __BUILDTYPE__;	/// "debug" or "release"
	const(char) *arch    = TARGET_PLATFORM;	/// ISA
	const(char) *os      = TARGET_OS;	/// Operating system
	const(char) *crt     = TARGET_CRT;	/// C runtime
	const(char) *cpprt   = TARGET_CPPRT;	/// C++ runtime
	const(char) *env     = TARGET_ENV;	/// Target environment
	const(char) *objfmt  = TARGET_OBJFMT;	/// Object format (e.g., coff)
	const(char) *fltabi  = TARGET_FLTABI;	/// Float ABI (hard or soft)
}

//
// ANCHOR ABI string
//

version (X86) {
	enum TARGET_PLATFORM = "x86";	/// Platform ABI string
	public alias opcode_t = ubyte;
} else version (X86_64) {
	enum TARGET_PLATFORM = "x86_64";	/// Platform ABI string
	public alias opcode_t = ubyte;
} else version (ARM_Thumb) {
	enum TARGET_PLATFORM = "arm_t32";	/// Platform ABI string
	public alias opcode_t = ushort;
} else version (ARM) {
	enum TARGET_PLATFORM = "arm_a32";	/// Platform ABI string
	public alias opcode_t = uint;
} else version (AArch64) {
	enum TARGET_PLATFORM = "arm_a64";	/// Platform ABI string
	public alias opcode_t = uint;
}
else
	static assert(0, "Platform not supported.");

//
// ANCHOR CRT string
//

version (CRuntime_Bionic)
	enum TARGET_CRT = "Bionic";	/// Platform CRT string
else version (CRuntime_DigitalMars)
	enum TARGET_CRT = "DigitalMars";	/// Platform CRT string
else version (CRuntime_Glibc)
	enum TARGET_CRT = "Glibc";	/// Platform CRT string
else version (CRuntime_Microsoft)
	enum TARGET_CRT = "Microsoft";	/// Platform CRT string
else version (CRuntime_Musl)
	enum TARGET_CRT = "Musl";	/// Platform CRT string
else version (CRuntime_Newlib) // Cygwin
	enum TARGET_CRT = "Newlib";	/// Platform CRT string
else version (CRuntime_UClibc)
	enum TARGET_CRT = "UClibc";	/// Platform CRT string
else version (CRuntime_WASI) // WebAssembly
	enum TARGET_CRT = "WASI";	/// Platform CRT string
else
	enum TARGET_CRT = "Unknown";	/// Platform CRT string

//
// ANCHOR OS string
//

version (Win64)
	enum TARGET_OS = "Win64";	/// Platform OS string
else version (Win32)
	enum TARGET_OS = "Win32";	/// Platform OS string
else version (linux)
	enum TARGET_OS = "Linux";	/// Platform OS string
else version (OSX)
	enum TARGET_OS = "macOS";	/// Platform OS string
else version (FreeBSD)
	enum TARGET_OS = "FreeBSD";	/// Platform OS string
else version (OpenBSD)
	enum TARGET_OS = "OpenBSD";	/// Platform OS string
else version (NetBSD)
	enum TARGET_OS = "NetBSD";	/// Platform OS string
else version (DragonflyBSD)
	enum TARGET_OS = "DragonflyBSD";	/// Platform OS string
else version (BSD)
	enum TARGET_OS = "BSD";	/// Platform OS string
else version (Solaris)
	enum TARGET_OS = "Solaris";	/// Platform OS string
else version (AIX)
	enum TARGET_OS = "AIX";	/// Platform OS string
else version (SkyOS)
	enum TARGET_OS = "SkyOS";	/// Platform OS string
else version (SysV3)
	enum TARGET_OS = "SysV3";	/// Platform OS string
else version (SysV4)
	enum TARGET_OS = "SysV4";	/// Platform OS string
else version (Hurd)
	enum TARGET_OS = "GNU Hurd";	/// Platform OS string
else version (Android)
	enum TARGET_OS = "Android";	/// Platform OS string
else version (Emscripten)
	enum TARGET_OS = "Emscripten";	/// Platform OS string
else version (PlayStation)
	enum TARGET_OS = "PlayStation";	/// Platform OS string
else version (PlayStation3)
	enum TARGET_OS = "PlayStation3";	/// Platform OS string
else
	enum TARGET_OS = "Unknown";	/// Platform OS string

//
// ANCHOR Additional Target Information
//

private enum VERSION_TARGET_INFO = 2083;

version (DigitalMars) {
	static if (__VERSION__ >= VERSION_TARGET_INFO)
		private enum FEATURE_TARGETINFO = true;
	else
		private enum FEATURE_TARGETINFO = false;
} else version (LDC) {
	static if (__VERSION__ >= VERSION_TARGET_INFO)
		private enum FEATURE_TARGETINFO = true;
	else
		private enum FEATURE_TARGETINFO = false;
} else
	private enum FEATURE_TARGETINFO = false;

static if (FEATURE_TARGETINFO) {
	/// Target object format string
	enum TARGET_OBJFMT = __traits(getTargetInfo, "objectFormat");
	/// Target float ABI string
	enum TARGET_FLTABI  = __traits(getTargetInfo, "floatAbi");
	// Likely to happen on non-Windows platforms
	private enum __tinfo = __traits(getTargetInfo, "cppRuntimeLibrary");
	static if (__tinfo == null)
		enum TARGET_CPPRT = "none"; /// Target C++ Runtime string
	else
		enum TARGET_CPPRT = __tinfo; /// Target C++ Runtime string
} else {
	/// Target object format string
	enum TARGET_OBJFMT = "unknown";
	/// Target float ABI string
	enum TARGET_FLTABI  = "unknown";
	version (CppRuntime_Gcc)
		enum TARGET_CPPRT = "libstdc++"; /// Target C++ Runtime string
	else version (CppRuntime_Microsoft)
		enum TARGET_CPPRT = "libcmt"; /// Target C++ Runtime string
	else version (CppRuntime_Clang)
		enum TARGET_CPPRT = "clang"; /// Target C++ Runtime string
	else version (CppRuntime_DigitalMars)
		enum TARGET_CPPRT = "dmc++"; /// Target C++ Runtime string
	else version (CppRuntime_Sun)
		enum TARGET_CPPRT = "sun"; /// Target C++ Runtime string
	else // assuming none
		enum TARGET_CPPRT = "none"; /// Target C++ Runtime string
}

//
// ANCHOR Environement string
//        Typically the C library, otherwise system wrappers.
//

version (MinGW) {
	enum TARGET_ENV = "MinGW";	/// Target environment
} else version (Cygwin) {
	enum TARGET_ENV = "Cygwin";	/// Target environment
} else version (CRuntime_Microsoft) {
	enum TARGET_ENV = "MSVC";	/// Target environment
} else version (CRuntime_Glibc) {
	enum TARGET_ENV = "GNU";	/// Target environment
} else version (CRuntime_Musl) {
	enum TARGET_ENV = "Musl";	/// Target environment
} else version (FreeStanding) { // now that would surprise me
	enum TARGET_ENV = "FreeStanding";	/// Target environment
} else {
	enum TARGET_ENV = "Unknown";	/// Target environment
}

version (PrintTargetInfo) {
	pragma(msg, "ADBG_VERSION     ", ADBG_VERSION);
	pragma(msg, "__BUILDTYPE__    ", __BUILDTYPE__);
	pragma(msg, "TARGET_PLATFORM  ", TARGET_PLATFORM);
	pragma(msg, "TARGET_OS        ", TARGET_OS);
	pragma(msg, "TARGET_CRT       ", TARGET_CRT);
	pragma(msg, "TARGET_CPPRT     ", TARGET_CPPRT);
	pragma(msg, "TARGET_ENV       ", TARGET_ENV);
	pragma(msg, "TARGET_OBJFMT    ", TARGET_OBJFMT);
	pragma(msg, "TARGET_FLTABI    ", TARGET_FLTABI);
}

//
// ANCHOR External functions
//

/**
 * Get compilation information structure.
 * Returns: AdbgInfo structure pointer
 */
immutable(adbg_info_t)* adbg_info() {
	immutable static adbg_info_t info;
	return &info;
}
