/**
 * Compile constants
 *
 * License: BSD 3-Clause
 */
module adbg.consts;

extern (C):

const(char) *adbg_info_version() {
	return PROJECT_VERSION ~ "-" ~ __BUILDTYPE__;
}
const(char) *adbg_info_platform() {
	return __PLATFORM__;
}
const(char) *adbg_info_crt() {
	return __CRT__;
}
const(char) *adbg_info_os() {
	return __OS__;
}

/// Project version
enum PROJECT_VERSION = "0.0.0";

debug enum __BUILDTYPE__ = "debug";	/// Build type
else  enum __BUILDTYPE__ = "release";	/// Build type

//
// ABI string
//

version (D_LP64)
	version = ABI64;
else
	version = ABI32;

version (X86) {
	enum __PLATFORM__ = "x86";	/// Platform ABI string
	version = X86_ANY;
} else
version (X86_64) {
	enum __PLATFORM__ = "x86-64";	/// Platform ABI string
	version = X86_ANY;
} else {
	static assert(0,
		"Platform not supported");
}

pragma(msg, "* isa: ", __PLATFORM__);

//
// CRT string
//

version (CRuntime_Microsoft)
	enum __CRT__ = "Microsoft";	/// Platform CRT string
else
version (CRuntime_Bionic)
	enum __CRT__ = "Bionic";	/// Platform CRT string
else
version (CRuntime_DigitalMars)
	enum __CRT__ = "DigitalMars";	/// Platform CRT string
else
version (CRuntime_Glibc)
	enum __CRT__ = "Glibc";	/// Platform CRT string
else
version (CRuntime_Musl)
	enum __CRT__ = "Musl";	/// Platform CRT string
else
version (CRuntime_UClibc)
	enum __CRT__ = "UClibc";	/// Platform CRT string
else
	enum __CRT__ = "Unknown";	/// Platform CRT string

pragma(msg, "* crt: ", __CRT__);

//
// OS string
//

version (Win64)
	enum __OS__ = "Win64";	/// Platform OS string
else
version (Win32)
	enum __OS__ = "Win32";	/// Platform OS string
else
version (linux)
	enum __OS__ = "Linux";	/// Platform OS string
else
version (OSX)
	enum __OS__ = "macOS";	/// Platform OS string
else
version (FreeBSD)
	enum __OS__ = "FreeBSD";	/// Platform OS string
else
version (OpenBSD)
	enum __OS__ = "OpenBSD";	/// Platform OS string
else
version (NetBSD)
	enum __OS__ = "NetBSD";	/// Platform OS string
else
version (DragonflyBSD)
	enum __OS__ = "DragonflyBSD";	/// Platform OS string
else
version (BSD)
	enum __OS__ = "BSD";	/// Platform OS string
else
version (Solaris)
	enum __OS__ = "Solaris";	/// Platform OS string
else
version (AIX)
	enum __OS__ = "AIX";	/// Platform OS string
else
version (SkyOS)
	enum __OS__ = "SkyOS";	/// Platform OS string
else
version (SysV3)
	enum __OS__ = "SysV3";	/// Platform OS string
else
version (SysV4)
	enum __OS__ = "SysV4";	/// Platform OS string
else
version (Hurd)
	enum __OS__ = "GNU Hurd";	/// Platform OS string
else
version (Android)
	enum __OS__ = "Android";	/// Platform OS string
else
version (Emscripten)
	enum __OS__ = "Emscripten";	/// Platform OS string
else
version (PlayStation)
	enum __OS__ = "PlayStation";	/// Platform OS string
else
version (PlayStation3)
	enum __OS__ = "PlayStation3";	/// Platform OS string
else
	enum __OS__ = "Unknown";	/// Platform OS string

pragma(msg, "* os: ", __OS__);

//
// Target additional information strings
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
		/// Target C++ Runtime string
		enum __TARGET_CPP_RT__ = "gcc";
	else
	version (CppRuntime_Microsoft)
		/// Target C++ Runtime string
		enum __TARGET_CPP_RT__ = "microsoft";
	else
		/// Target C++ Runtime string
		enum __TARGET_CPP_RT__ = "none"; // assuming none
}

version (COMPILER_TARGETINFO_CPU) {
	/// Target CPU string (LDC-only)
	enum __TARGET_CPU__ = __traits(targetCPU);
} else {
	/// Target CPU string (LDC-only)
	enum __TARGET_CPU__ = __PLATFORM__;
}