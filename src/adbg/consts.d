/**
 * Compile constants
 *
 * License: BSD 3-clause
 */
module adbg.consts;

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
enum APP_VERSION = "0.0.0";

debug enum __BUILDTYPE__ = "debug";	/// Build type
else  enum __BUILDTYPE__ = "release";	/// Build type

//
// ABI string
//

version (X86) {
	enum __PLATFORM__ = "x86";	/// Platform ABI string
	public alias ubyte opcode_t;
} else version (X86_64) {
	enum __PLATFORM__ = "x86_64";	/// Platform ABI string
	public alias ubyte opcode_t;
/*} else version (ARM_Thumb) {
	enum __PLATFORM__ = "arm_t32";	/// Platform ABI string
	public alias ushort opcode_t;
} else version (ARM) {
	enum __PLATFORM__ = "arm_a32";	/// Platform ABI string
	public alias uint opcode_t;
} else version (X86_64) {
	enum __PLATFORM__ = "arm_a64";	/// Platform ABI string
	public alias uint opcode_t;*/
} else
	static assert(0, "Platform not supported");

pragma(msg, "* isa: ", __PLATFORM__);

//
// CRT string
//

version (CRuntime_Microsoft)
	enum __CRT__ = "Microsoft";	/// Platform CRT string
else version (CRuntime_Bionic)
	enum __CRT__ = "Bionic";	/// Platform CRT string
else version (CRuntime_DigitalMars)
	enum __CRT__ = "DigitalMars";	/// Platform CRT string
else version (CRuntime_Glibc)
	enum __CRT__ = "Glibc";	/// Platform CRT string
else version (CRuntime_Musl)
	enum __CRT__ = "Musl";	/// Platform CRT string
else version (CRuntime_UClibc)
	enum __CRT__ = "UClibc";	/// Platform CRT string
else version (CRuntime_WASI)
	enum __CRT__ = "WASI";	/// Platform CRT string
else
	enum __CRT__ = "Unknown";	/// Platform CRT string

pragma(msg, "* crt: ", __CRT__);

//
// OS string
//

version (Win64)
	enum __OS__ = "Win64";	/// Platform OS string
else version (Win32)
	enum __OS__ = "Win32";	/// Platform OS string
else version (linux)
	enum __OS__ = "Linux";	/// Platform OS string
else version (OSX)
	enum __OS__ = "macOS";	/// Platform OS string
else version (FreeBSD)
	enum __OS__ = "FreeBSD";	/// Platform OS string
else version (OpenBSD)
	enum __OS__ = "OpenBSD";	/// Platform OS string
else version (NetBSD)
	enum __OS__ = "NetBSD";	/// Platform OS string
else version (DragonflyBSD)
	enum __OS__ = "DragonflyBSD";	/// Platform OS string
else version (BSD)
	enum __OS__ = "BSD";	/// Platform OS string
else version (Solaris)
	enum __OS__ = "Solaris";	/// Platform OS string
else version (AIX)
	enum __OS__ = "AIX";	/// Platform OS string
else version (SkyOS)
	enum __OS__ = "SkyOS";	/// Platform OS string
else version (SysV3)
	enum __OS__ = "SysV3";	/// Platform OS string
else version (SysV4)
	enum __OS__ = "SysV4";	/// Platform OS string
else version (Hurd)
	enum __OS__ = "GNU Hurd";	/// Platform OS string
else version (Android)
	enum __OS__ = "Android";	/// Platform OS string
else version (Emscripten)
	enum __OS__ = "Emscripten";	/// Platform OS string
else version (PlayStation)
	enum __OS__ = "PlayStation";	/// Platform OS string
else version (PlayStation3)
	enum __OS__ = "PlayStation3";	/// Platform OS string
else
	enum __OS__ = "Unknown";	/// Platform OS string

pragma(msg, "* os: ", __OS__);

//
// ANCHOR Additional Target Information
//

version (DigitalMars) {
	version = COMPILER_TARGETINFO;
} else
version (LDC) {
	version = COMPILER_TARGETINFO;
	version = COMPILER_TARGETINFO_CPU;
}

version (COMPILER_TARGETINFO) {
	/// Target object format string
	enum __TARGET_OBJ_FORMAT__ = __traits(getTargetInfo, "objectFormat");
	/// Target float ABI string
	enum __TARGET_FLOAT_ABI__  = __traits(getTargetInfo, "floatAbi");
	// Likely to happen on non-Windows platforms
	static if (__traits(getTargetInfo, "cppRuntimeLibrary") != null)
		/// Target C++ Runtime string
		enum __TARGET_CPP_RT__ = __traits(getTargetInfo, "cppRuntimeLibrary");
	else
		/// Target C++ Runtime string
		enum __TARGET_CPP_RT__ = "none"; // assuming none since empty
} else {
	/// Target object format string
	enum __TARGET_OBJ_FORMAT__ = "unknown";
	/// Target float ABI string
	enum __TARGET_FLOAT_ABI__  = "unknown";
	version (CppRuntime_Gcc)
		enum __TARGET_CPP_RT__ = "libstdc++"; /// Target C++ Runtime string
	else version (CppRuntime_Microsoft)
		enum __TARGET_CPP_RT__ = "libcmt"; /// Target C++ Runtime string
	else version (CppRuntime_Clang)
		enum __TARGET_CPP_RT__ = "clang"; /// Target C++ Runtime string
	else version (CppRuntime_DigitalMars)
		enum __TARGET_CPP_RT__ = "dmc++"; /// Target C++ Runtime string
	else version (CppRuntime_Sun)
		enum __TARGET_CPP_RT__ = "sun"; /// Target C++ Runtime string
	else // assuming none
		enum __TARGET_CPP_RT__ = "none"; /// Target C++ Runtime string
}

version (COMPILER_TARGETINFO_CPU) {
	enum __TARGET_CPU__ = __traits(targetCPU); /// Target CPU string (LDC-only)
} else {
	enum __TARGET_CPU__ = __PLATFORM__; /// Target CPU string (LDC-only)
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

extern (C):

/**
 * Get library version string
 * Returns: version-buildtype-platform string
 */
const(char) *adbg_info_version() {
	return APP_VERSION ~ "-" ~ __BUILDTYPE__ ~ "-" ~ __PLATFORM__;
}
/**
 * Get library compilation platform
 * Returns: __PLATFORM__ string
 */
const(char) *adbg_info_platform() {
	return __PLATFORM__;
}
/**
 * Get library compilation crt
 * Returns: __CRT__ string
 */
const(char) *adbg_info_crt() {
	return __CRT__;
}
/**
 * Get library compilation os
 * Returns: __OS__ string
 */
const(char) *adbg_info_os() {
	return __OS__;
}
