/**
 * Compile constants
 *
 * License: BSD 3-clause
 */
module adbg.platform;

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

/// Application version
enum ADBG_VERSION = "0.0.0";

debug enum __BUILDTYPE__ = "debug";	/// Build type
else  enum __BUILDTYPE__ = "release";	/// Build type

private enum VERSION_TARGET_INFO = 2083;

//
// ABI string
//

version (X86) {
	enum TARGET_PLATFORM = "x86";	/// Platform ABI string
	public alias opcode_t = ubyte;
} else version (X86_64) {
	enum TARGET_PLATFORM = "x86-64";	/// Platform ABI string
	public alias opcode_t = ubyte;
} else version (ARM_Thumb) {
	enum TARGET_PLATFORM = "arm-t32";	/// Platform ABI string
	public alias opcode_t = ushort;
} else version (ARM) {
	enum TARGET_PLATFORM = "arm-a32";	/// Platform ABI string
	public alias opcode_t = uint;
} else version (AArch64) {
	enum TARGET_PLATFORM = "arm-a64";	/// Platform ABI string
	public alias opcode_t = uint;
}
else
	static assert(0, "Platform not supported.");

//
// CRT string
//

version (CRuntime_Microsoft)
	enum TARGET_CRT = "Microsoft";	/// Platform CRT string
else version (CRuntime_Bionic)
	enum TARGET_CRT = "Bionic";	/// Platform CRT string
else version (CRuntime_DigitalMars)
	enum TARGET_CRT = "DigitalMars";	/// Platform CRT string
else version (CRuntime_Glibc)
	enum TARGET_CRT = "Glibc";	/// Platform CRT string
else version (CRuntime_Musl)
	enum TARGET_CRT = "Musl";	/// Platform CRT string
else version (CRuntime_UClibc)
	enum TARGET_CRT = "UClibc";	/// Platform CRT string
else version (CRuntime_WASI) // WebAssembly
	enum TARGET_CRT = "WASI";	/// Platform CRT string
else
	enum TARGET_CRT = "Unknown";	/// Platform CRT string

//
// OS string
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
// ANCHOR Additional Feature Versions
//

version (DigitalMars) {
	version (D_InlineAsm_X86) {
		version = DMD_ASM_X86;
		version = DMD_ASM_X86_ANY;
	} else version (D_InlineAsm_X86_64) {
		version = DMD_ASM_X86_64;
		version = DMD_ASM_X86_ANY;
	}
} else
version (LDC) {
	version (D_InlineAsm_X86) {
		version = LDC_ASM_X86;
		version = LDC_ASM_X86_ANY;
	} else version (D_InlineAsm_X86_64) {
		version = LDC_ASM_X86_64;
		version = LDC_ASM_X86_ANY;
	}
}
version (GNU_Inline) {
	version (X86) {
		version = GDC_ASM_X86;
		version = GDC_ASM_X86_ANY;
	} else version (X86_64) {
		version = GDC_ASM_X86_64;
		version = GDC_ASM_X86_ANY;
	}
}

//
// ANCHOR External functions
//

/**
 * Get library version string
 * Returns: version-buildtype-platform string
 */
const(char) *adbg_info_version() {
	return ADBG_VERSION ~ "-" ~ __BUILDTYPE__ ~ "-" ~ TARGET_PLATFORM;
}
/**
 * Get library compilation platform
 * Returns: TARGET_PLATFORM string
 */
const(char) *adbg_info_platform() {
	return TARGET_PLATFORM;
}
/**
 * Get library compilation crt
 * Returns: TARGET_CRT string
 */
const(char) *adbg_info_crt() {
	return TARGET_CRT;
}
/**
 * Get library compilation os
 * Returns: TARGET_OS string
 */
const(char) *adbg_info_os() {
	return TARGET_OS;
}
